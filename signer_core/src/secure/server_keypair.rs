use super::error::Error;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use zeroize::ZeroizeOnDrop;

use super::{ED25519_KEY_SIZE, ED25519_SIGNATURE_SIZE};

#[derive(ZeroizeOnDrop)]
pub struct ServerKeypair {
    signing_key: SigningKey,
    #[zeroize(skip)]
    verifying_key: VerifyingKey,
}

impl ServerKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 64 {
            return Err(Error::InvalidKeyLength);
        }

        let signing_key = SigningKey::from_bytes(
            bytes[0..32]
                .try_into()
                .map_err(|_| Error::InvalidKeyLength)?,
        );
        let verifying_key = signing_key.verifying_key();

        let provided_pubkey = &bytes[32..64];
        if verifying_key.as_bytes() != provided_pubkey {
            return Err(Error::InvalidKeyLength);
        }

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    pub fn public_key(&self) -> &[u8; ED25519_KEY_SIZE] {
        self.verifying_key.as_bytes()
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let (priv_part, pub_part) = bytes.split_at_mut(32);
        priv_part.copy_from_slice(&self.signing_key.to_bytes());
        pub_part.copy_from_slice(self.verifying_key.as_bytes());
        bytes
    }

    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_SIZE] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if public_key.len() != ED25519_KEY_SIZE {
            return Err(Error::InvalidKeyLength);
        }
        let verifying_key =
            VerifyingKey::from_bytes(public_key.try_into().map_err(|_| Error::InvalidKeyLength)?)?;
        let signature = Signature::from_slice(signature)?;
        verifying_key.verify(message, &signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = ServerKeypair::generate();
        assert_eq!(keypair.public_key().len(), ED25519_KEY_SIZE);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = ServerKeypair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);

        assert!(ServerKeypair::verify(keypair.public_key(), message, &signature).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair = ServerKeypair::generate();
        let message = b"test message";
        let wrong_signature = vec![0u8; 64];

        assert!(ServerKeypair::verify(keypair.public_key(), message, &wrong_signature).is_err());
    }

    #[test]
    fn test_to_from_bytes() {
        let keypair1 = ServerKeypair::generate();
        let bytes = keypair1.to_bytes();
        let keypair2 = ServerKeypair::from_bytes(&bytes).unwrap();

        assert_eq!(keypair1.public_key(), keypair2.public_key());

        let message = b"test";
        let sig1 = keypair1.sign(message);
        let sig2 = keypair2.sign(message);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        let result = ServerKeypair::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
    }
}
