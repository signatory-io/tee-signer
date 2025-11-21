use super::error::Error;
use blake2::digest::typenum::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use super::{
    AuthorizedKeys, ServerKeypair, Session, ED25519_KEY_SIZE, MAX_MESSAGE_SIZE, TAG_AUTH,
    TAG_EPH_KEYS, TAG_SECRET, TAG_SUITE, X25519_KEY_SIZE,
};

#[derive(Serialize, Deserialize)]
struct HelloMessage(ByteBuf, ByteBuf);

#[derive(Serialize, Deserialize)]
struct AuthMessage((ByteBuf,));

#[derive(Debug)]
pub struct ConnectionState {
    pub session: Session,
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            session: Session::new(),
        }
    }
}

pub async fn perform_handshake<T>(
    stream: &mut T,
    server_keypair: &ServerKeypair,
    authorized_keys: &AuthorizedKeys,
) -> Result<ConnectionState, Error>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    let hello_out = HelloMessage(
        ByteBuf::from(ephemeral_public.as_bytes().as_slice()),
        ByteBuf::from(server_keypair.public_key().as_slice()),
    );

    write_cbor_message(stream, &hello_out).await?;

    let hello_in: HelloMessage = read_cbor_message(stream).await?;

    if hello_in.0.len() != X25519_KEY_SIZE {
        return Err(Error::InvalidHandshake);
    }
    if hello_in.1.len() != ED25519_KEY_SIZE {
        return Err(Error::InvalidHandshake);
    }

    if !authorized_keys.is_authorized(&hello_in.1) {
        return Err(Error::Unauthorized);
    }

    let client_ephemeral_public = X25519PublicKey::from(
        <[u8; X25519_KEY_SIZE]>::try_from(&hello_in.0[..]).map_err(|_| Error::InvalidHandshake)?,
    );
    let shared_secret = ephemeral_secret.diffie_hellman(&client_ephemeral_public);

    let challenge = derive_challenge(
        ephemeral_public.as_bytes(),
        &hello_in.0.as_ref(),
        server_keypair.public_key(),
        &hello_in.1.as_ref(),
        shared_secret.as_bytes(),
    );

    let signature = server_keypair.sign(&challenge);
    let auth_out = AuthMessage((ByteBuf::from(signature),));

    write_cbor_message(stream, &auth_out).await?;

    let auth_in: AuthMessage = read_cbor_message(stream).await?;

    ServerKeypair::verify(&hello_in.1.as_ref(), &challenge, &auth_in.0 .0.as_ref())
        .map_err(|_| Error::SignatureVerification)?;

    let mut session = Session::new();
    session
        .derive_keys(
            shared_secret.as_bytes(),
            ephemeral_public.as_bytes(),
            &hello_in.0.as_ref(),
        )
        .map_err(|_| Error::KeyDerivation)?;

    Ok(ConnectionState { session })
}

async fn read_cbor_message<T, S>(stream: &mut S) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(Error::InvalidHandshake);
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(ciborium::de::from_reader(&buf[..])?)
}

async fn write_cbor_message<T, S>(stream: &mut S, message: &T) -> Result<(), Error>
where
    T: Serialize,
    S: AsyncWriteExt + Unpin,
{
    let mut buf = Vec::new();
    ciborium::ser::into_writer(message, &mut buf)?;
    let len = (buf.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&buf).await?;
    Ok(())
}

fn derive_challenge(
    local_eph: &[u8],
    remote_eph: &[u8],
    local_auth: &[u8],
    remote_auth: &[u8],
    secret: &[u8],
) -> Vec<u8> {
    let mut eph_combined = [0u8; X25519_KEY_SIZE];
    let mut auth_combined = [0u8; ED25519_KEY_SIZE];

    for i in 0..X25519_KEY_SIZE {
        eph_combined[i] = local_eph[i] ^ remote_eph[i];
    }
    for i in 0..ED25519_KEY_SIZE {
        auth_combined[i] = local_auth[i] ^ remote_auth[i];
    }

    // BLAKE2b-256(TAG_SUITE || TAG_EPH_KEYS || eph_combined || TAG_AUTH || auth_combined || TAG_SECRET || secret)
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(TAG_SUITE);
    hasher.update(TAG_EPH_KEYS);
    hasher.update(&eph_combined);
    hasher.update(TAG_AUTH);
    hasher.update(&auth_combined);
    hasher.update(TAG_SECRET);
    hasher.update(secret);

    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_handshake_success() {
        let (mut server_stream, mut client_stream) = UnixStream::pair().unwrap();

        let server_keypair = ServerKeypair::generate();
        let client_keypair = ServerKeypair::generate();

        // Server accepts client
        let mut authorized_keys_content = String::from("ed25519 ");
        authorized_keys_content
            .push_str(&general_purpose::STANDARD.encode(client_keypair.public_key()));
        let authorized_keys = AuthorizedKeys::parse(&authorized_keys_content).unwrap();

        let server_task = tokio::spawn(async move {
            perform_handshake(&mut server_stream, &server_keypair, &authorized_keys).await
        });

        let client_task = tokio::spawn(async move {
            perform_handshake(
                &mut client_stream,
                &client_keypair,
                &AuthorizedKeys::new_accept_all(),
            )
            .await
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        assert!(server_result.unwrap().is_ok());
        assert!(client_result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_handshake_unauthorized() {
        let (mut server_stream, mut client_stream) = UnixStream::pair().unwrap();

        let server_keypair = ServerKeypair::generate();
        let client_keypair = ServerKeypair::generate();
        let other_keypair = ServerKeypair::generate();

        // Server only accepts other_keypair
        let mut authorized_keys_content = String::from("ed25519 ");
        authorized_keys_content
            .push_str(&general_purpose::STANDARD.encode(other_keypair.public_key()));
        let authorized_keys = AuthorizedKeys::parse(&authorized_keys_content).unwrap();

        let server_task = tokio::spawn(async move {
            perform_handshake(&mut server_stream, &server_keypair, &authorized_keys).await
        });

        let client_task = tokio::spawn(async move {
            perform_handshake(
                &mut client_stream,
                &client_keypair,
                &AuthorizedKeys::new_accept_all(),
            )
            .await
        });

        let (server_result, _) = tokio::join!(server_task, client_task);

        let err = server_result.unwrap().unwrap_err();
        assert!(matches!(err, Error::Unauthorized));
    }

    #[test]
    fn test_derive_challenge() {
        let local_eph = [1u8; 32];
        let remote_eph = [2u8; 32];
        let local_auth = [3u8; 32];
        let remote_auth = [4u8; 32];
        let secret = [5u8; 32];

        let challenge =
            derive_challenge(&local_eph, &remote_eph, &local_auth, &remote_auth, &secret);
        assert_eq!(challenge.len(), 32);

        // Same inputs should produce same challenge
        let challenge2 =
            derive_challenge(&local_eph, &remote_eph, &local_auth, &remote_auth, &secret);
        assert_eq!(challenge, challenge2);

        // Different inputs should produce different challenge
        let different_secret = [6u8; 32];
        let challenge3 = derive_challenge(
            &local_eph,
            &remote_eph,
            &local_auth,
            &remote_auth,
            &different_secret,
        );
        assert_ne!(challenge, challenge3);
    }
}
