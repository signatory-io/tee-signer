use super::error::Error;
use blake2::digest::generic_array::GenericArray;
use blake2::digest::typenum::U32;
use blake2::digest::KeyInit;
use blake2::{Blake2b, Blake2bMac, Digest};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key as ChaCha20Poly1305Key, Nonce,
};
use zeroize::ZeroizeOnDrop;

use super::{
    CHACHA20_KEY_SIZE, MAX_MESSAGE_SIZE, PACKET_GRANULARITY, POLY1305_TAG_SIZE, TAG_LEN,
    TAG_PAYLOAD,
};

#[derive(Debug, ZeroizeOnDrop)]
pub struct Session {
    rd_length_key: ChaCha20Poly1305Key,
    rd_payload_key: ChaCha20Poly1305Key,
    wr_length_key: ChaCha20Poly1305Key,
    wr_payload_key: ChaCha20Poly1305Key,
    read_nonce: u64,
    write_nonce: u64,
    initialized: bool,
}

impl Session {
    pub fn new() -> Self {
        Self {
            rd_length_key: ChaCha20Poly1305Key::default(),
            rd_payload_key: ChaCha20Poly1305Key::default(),
            wr_length_key: ChaCha20Poly1305Key::default(),
            wr_payload_key: ChaCha20Poly1305Key::default(),
            read_nonce: 0,
            write_nonce: 0,
            initialized: false,
        }
    }

    pub fn derive_keys(
        &mut self,
        shared_secret: &[u8],
        local_eph_pubkey: &[u8],
        remote_eph_pubkey: &[u8],
    ) -> Result<(), Error> {
        if local_eph_pubkey.len() != CHACHA20_KEY_SIZE
            || remote_eph_pubkey.len() != CHACHA20_KEY_SIZE
        {
            return Err(Error::EncryptionFailed);
        }

        let r_bytes = Self::compute_direction_info(local_eph_pubkey, remote_eph_pubkey)?;
        let w_bytes = Self::compute_direction_info(remote_eph_pubkey, local_eph_pubkey)?;

        let mut hasher = Blake2b::<U32>::new();
        hasher.update(shared_secret);
        let prk = hasher.finalize();

        self.rd_length_key
            .copy_from_slice(&Self::blake2b_derive(&prk, &r_bytes, TAG_LEN));
        self.rd_payload_key =
            *ChaCha20Poly1305Key::from_slice(&Self::blake2b_derive(&prk, &r_bytes, TAG_PAYLOAD));

        self.wr_length_key
            .copy_from_slice(&Self::blake2b_derive(&prk, &w_bytes, TAG_LEN));
        self.wr_payload_key =
            *ChaCha20Poly1305Key::from_slice(&Self::blake2b_derive(&prk, &w_bytes, TAG_PAYLOAD));

        self.read_nonce = 0;
        self.write_nonce = 0;
        self.initialized = true;

        Ok(())
    }

    fn compute_direction_info(dest: &[u8], src: &[u8]) -> Result<[u8; CHACHA20_KEY_SIZE], Error> {
        if dest.len() != src.len() {
            return Err(Error::InvalidKeyLength);
        }

        let mut info = [0u8; CHACHA20_KEY_SIZE];
        let mut borrow = 0i16;
        for i in (0..CHACHA20_KEY_SIZE).rev() {
            let diff = (dest[i] as i16) - (src[i] as i16) - borrow;
            info[i] = (diff & 0xFF) as u8;
            borrow = (diff < 0) as i16;
        }

        Ok(info)
    }

    fn blake2b_derive(prk: &GenericArray<u8, U32>, info: &[u8], tag: &[u8]) -> [u8; 32] {
        use blake2::digest::Mac as _;
        let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(prk)
            .expect("blake2b key length should always be valid");
        mac.update(tag);
        mac.update(info);
        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        output
    }

    pub fn write_packet(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::InvalidPacketLength);
        }

        let total_unpadded = 4 + 4 + data.len() + POLY1305_TAG_SIZE; // length + unpadded_len + data + tag
        let padded_len =
            ((total_unpadded + PACKET_GRANULARITY - 1) / PACKET_GRANULARITY) * PACKET_GRANULARITY;
        let payload_len = padded_len - 4; // Exclude encrypted length field

        let nonce = Self::make_nonce(self.write_nonce);

        let length_bytes = (payload_len as u32).to_be_bytes();
        let mut encrypted_length = length_bytes;
        let mut length_cipher = ChaCha20::new(&self.wr_length_key.into(), &nonce.into());
        length_cipher.apply_keystream(&mut encrypted_length);

        let data_len_bytes = (data.len() as u32).to_be_bytes();
        let mut plaintext = Vec::with_capacity(payload_len - POLY1305_TAG_SIZE);
        plaintext.extend_from_slice(&data_len_bytes);
        plaintext.extend_from_slice(data);

        let padding_len = (payload_len - POLY1305_TAG_SIZE) - 4 - data.len();
        if padding_len > 0 {
            use rand_core::{OsRng, RngCore};
            let mut padding = vec![0u8; padding_len];
            OsRng.fill_bytes(&mut padding);
            plaintext.extend_from_slice(&padding);
        }

        let cipher = ChaCha20Poly1305::new(&self.wr_payload_key);
        let payload = Payload {
            msg: &plaintext,
            aad: &encrypted_length,
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| Error::EncryptionFailed)?;

        let mut packet = Vec::with_capacity(padded_len);
        packet.extend_from_slice(&encrypted_length);
        packet.extend_from_slice(&ciphertext);

        if self.write_nonce == u64::MAX {
            return Err(Error::NonceExhausted);
        }

        self.write_nonce += 1;
        Ok(packet)
    }

    pub fn read_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }

        if packet.len() < 4 {
            return Err(Error::InvalidPacketLength);
        }

        let nonce = Self::make_nonce(self.read_nonce);

        let mut encrypted_length = [0u8; 4];
        encrypted_length.copy_from_slice(&packet[0..4]);
        let mut length_cipher = ChaCha20::new(&self.rd_length_key.into(), &nonce.into());
        length_cipher.apply_keystream(&mut encrypted_length);
        let payload_len = u32::from_be_bytes(encrypted_length) as usize;

        if payload_len < POLY1305_TAG_SIZE + 4 {
            return Err(Error::InvalidPacketLength);
        }

        if packet.len() < 4 + payload_len {
            return Err(Error::InvalidPacketLength);
        }

        let cipher = ChaCha20Poly1305::new(&self.rd_payload_key);
        let payload = Payload {
            msg: &packet[4..4 + payload_len],
            aad: &packet[0..4],
        };
        let plaintext = cipher
            .decrypt(&nonce, payload)
            .map_err(|_| Error::DecryptionFailed)?;

        if plaintext.len() < 4 {
            return Err(Error::InvalidPacketLength);
        }

        let unpadded_len = u32::from_be_bytes(plaintext[0..4].try_into().unwrap()) as usize;
        if unpadded_len > plaintext.len() - 4 {
            return Err(Error::InvalidPacketLength);
        }

        let data = plaintext[0..4 + unpadded_len].to_vec();

        self.read_nonce += 1;
        Ok(data)
    }

    #[inline]
    fn make_nonce(counter: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        // Match Go client: counter at start (bytes 0-7), zeros at end (bytes 8-11)
        nonce[0..8].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&nonce)
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub(super) fn decrypt_length(&self, encrypted_length: &[u8; 4]) -> Result<usize, Error> {
        if !self.initialized {
            return Err(Error::NotInitialized);
        }

        let nonce = Self::make_nonce(self.read_nonce);

        let mut length_buf = *encrypted_length;
        let mut length_cipher = ChaCha20::new(&self.rd_length_key.into(), &nonce.into());
        length_cipher.apply_keystream(&mut length_buf);
        let payload_len = u32::from_be_bytes(length_buf) as usize;

        if payload_len < POLY1305_TAG_SIZE + 4 {
            return Err(Error::InvalidPacketLength);
        }

        if payload_len > MAX_MESSAGE_SIZE {
            return Err(Error::InvalidPacketLength);
        }

        Ok(payload_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_derive_keys() {
        let mut session = Session::new();
        let secret = [1u8; 32];
        let local = [2u8; 32];
        let remote = [3u8; 32];

        assert!(session.derive_keys(&secret, &local, &remote).is_ok());
        assert!(session.is_initialized());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut session1 = Session::new();
        let mut session2 = Session::new();

        let secret = [1u8; 32];
        let local = [2u8; 32];
        let remote = [3u8; 32];

        session1.derive_keys(&secret, &local, &remote).unwrap();
        session2.derive_keys(&secret, &remote, &local).unwrap();

        let plaintext = b"Hello, World!";
        let packet = session1.write_packet(plaintext).unwrap();
        let decrypted = session2.read_packet(&packet).unwrap();

        assert_eq!(decrypted.len(), 4 + plaintext.len());
        let length = u32::from_be_bytes(decrypted[0..4].try_into().unwrap()) as usize;
        assert_eq!(length, plaintext.len());
        assert_eq!(plaintext, &decrypted[4..]);
    }

    #[test]
    fn test_multiple_messages() {
        let mut session1 = Session::new();
        let mut session2 = Session::new();

        let secret = [5u8; 32];
        let local = [6u8; 32];
        let remote = [7u8; 32];

        session1.derive_keys(&secret, &local, &remote).unwrap();
        session2.derive_keys(&secret, &remote, &local).unwrap();

        for i in 0..10 {
            let msg = format!("Message {}", i);
            let packet = session1.write_packet(msg.as_bytes()).unwrap();
            let decrypted = session2.read_packet(&packet).unwrap();
            // Skip 4-byte length prefix
            assert_eq!(msg.as_bytes(), &decrypted[4..]);
        }
    }

    #[test]
    fn test_tampered_packet() {
        let mut session1 = Session::new();
        let mut session2 = Session::new();

        let secret = [8u8; 32];
        let local = [9u8; 32];
        let remote = [10u8; 32];

        session1.derive_keys(&secret, &local, &remote).unwrap();
        session2.derive_keys(&secret, &remote, &local).unwrap();

        let plaintext = b"Secret message";
        let mut packet = session1.write_packet(plaintext).unwrap();

        // Tamper with packet
        packet[10] ^= 0xFF;

        assert!(session2.read_packet(&packet).is_err());
    }

    #[test]
    fn test_not_initialized() {
        let mut session = Session::new();
        assert!(session.write_packet(b"test").is_err());
        assert!(session.read_packet(&[0u8; 64]).is_err());
    }
}
