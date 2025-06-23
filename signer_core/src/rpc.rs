use crate::{
    crypto::{KeyType, PrivateKey},
    serde_helper::bytes,
};
pub use crate::{GenerateAndImportResult, GenerateResult, ImportResult};
use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request<C> {
    Initialize(C),
    Import(#[serde(with = "bytes")] Vec<u8>),
    ImportUnencrypted(PrivateKey),
    Generate(KeyType),
    GenerateAndImport(KeyType),
    Sign {
        handle: usize,
        #[serde(with = "bytes")]
        message: Vec<u8>,
    },
    SignWith {
        #[serde(with = "bytes")]
        encrypted_private_key: Vec<u8>,
        #[serde(with = "bytes")]
        message: Vec<u8>,
    },
    PublicKey(usize),
    PublicKeyFrom(#[serde(with = "bytes")] Vec<u8>),
    ProvePossession(usize),
}

/// Wire-compatible error object
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Error {
    pub message: String,
    pub source: Option<Box<Error>>,
}

impl<T: std::error::Error> From<T> for Error {
    fn from(value: T) -> Self {
        Error {
            message: value.to_string(),
            source: match value.source() {
                Some(s) => Some(Box::new(Self::from(s))),
                None => None,
            },
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(src) => write!(f, "{}: {}", &self.message, src),
            None => f.write_str(&self.message),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use crate::crypto::{Blake2b256, KeyType, PublicKey, Signature};
    use crate::rpc::{
        client::{Client, Error as ClientError},
        server::Server,
        Error,
    };
    use crate::tests::{DummyCredentials, Passthrough, PassthroughFactory};
    use crate::{macros::unwrap_as, EncryptedSigner};
    use blake2::Digest;
    use signature::{DigestVerifier, Verifier};
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn rpc_sign_with_secp256k1() {
        let (srv_sock, client_sock) = UnixStream::pair().unwrap();
        let mut server: Server<PassthroughFactory, EncryptedSigner<Passthrough>, rand_core::OsRng> =
            Server::new(PassthroughFactory, rand_core::OsRng);

        let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

        futures::join!(
            async move {
                server.serve_connection(srv_sock).await.unwrap();
            },
            async move {
                client.initialize(DummyCredentials {}).await.unwrap();
                let res = client.generate(KeyType::Secp256k1).await.unwrap();

                let data = b"text";
                let sig = unwrap_as!(
                    client
                        .try_sign_with(&res.encrypted_private_key, data)
                        .await
                        .unwrap(),
                    Signature::Secp256k1
                );
                let pub_key = unwrap_as!(res.public_key, PublicKey::Secp256k1);
                let mut digest = Blake2b256::new();
                digest.update(data);
                pub_key.verify_digest(digest, &*sig).unwrap();
            }
        );
    }

    #[tokio::test]
    async fn rpc_uninitialized() {
        let (srv_sock, client_sock) = UnixStream::pair().unwrap();
        let mut server: Server<PassthroughFactory, EncryptedSigner<Passthrough>, rand_core::OsRng> =
            Server::new(PassthroughFactory, rand_core::OsRng);

        let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

        futures::join!(
            async move {
                server.serve_connection(srv_sock).await.unwrap();
            },
            async move {
                let err = client.generate(KeyType::Secp256k1).await.unwrap_err();
                assert_eq!(
                    unwrap_as!(err, ClientError::RPC),
                    Error {
                        message: "uninitialized".into(),
                        source: None
                    }
                );
            }
        );
    }

    #[tokio::test]
    async fn rpc_proof_of_possession() {
        let (srv_sock, client_sock) = UnixStream::pair().unwrap();
        let mut server: Server<PassthroughFactory, EncryptedSigner<Passthrough>, rand_core::OsRng> =
            Server::new(PassthroughFactory, rand_core::OsRng);

        let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

        futures::join!(
            async move {
                server.serve_connection(srv_sock).await.unwrap();
            },
            async move {
                client.initialize(DummyCredentials {}).await.unwrap();
                let res = client.generate_and_import(KeyType::Bls).await.unwrap();

                let proof = unwrap_as!(
                    client.proof_of_possession(res.handle).await.unwrap(),
                    Signature::Bls
                );

                let pub_key = unwrap_as!(res.public_key, PublicKey::Bls);
                pub_key.verify(&pub_key.to_bytes(), &proof).unwrap();
            }
        );
    }
}
