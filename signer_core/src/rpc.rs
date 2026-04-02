use crate::{
    crypto::{KeyType, PrivateKey, SigningVersion},
    serde_helper::bytes,
};
pub use crate::{GenerateAndImportResult, GenerateResult, ImportResult};
use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;

pub const MAX_MESSAGE_SIZE: u32 = 2 * 1024 * 1024;

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
        version: SigningVersion,
    },
    SignWith {
        #[serde(with = "bytes")]
        encrypted_private_key: Vec<u8>,
        #[serde(with = "bytes")]
        message: Vec<u8>,
        version: SigningVersion,
    },
    SignDigest {
        handle: usize,
        #[serde(with = "bytes")]
        digest: Vec<u8>,
    },
    SignDigestWith {
        #[serde(with = "bytes")]
        encrypted_private_key: Vec<u8>,
        #[serde(with = "bytes")]
        digest: Vec<u8>,
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
            source: value.source().map(|s| Box::new(Self::from(s))),
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
    use crate::crypto::{Blake2b256, KeyType, PrivateKey, PublicKey, Signature, SigningVersion};
    use crate::rpc::{
        client::{Client, Error as ClientError},
        server::Server,
        Error,
    };
    use crate::tests::{DummyCredentials, Passthrough, PassthroughFactory};
    use crate::{macros::unwrap_as, EncryptedSigner};
    use blake2::Digest;
    use signature::DigestVerifier;
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
                        .try_sign_with(&res.encrypted_private_key, data, SigningVersion::Latest)
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
    async fn rpc_sign_digest_with_secp256k1() {
        use signature::hazmat::PrehashVerifier;
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

                let digest = Blake2b256::digest(b"text");
                let sig = unwrap_as!(
                    client
                        .try_sign_digest_with(&res.encrypted_private_key, &digest)
                        .await
                        .unwrap(),
                    Signature::Secp256k1
                );
                let pub_key = unwrap_as!(res.public_key, PublicKey::Secp256k1);
                pub_key.verify_prehash(&digest, &*sig).unwrap();
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
    async fn rpc_generate_and_import_ed25519() {
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
                let res = client.generate_and_import(KeyType::Ed25519).await.unwrap();

                let data = b"test message";
                let sig = unwrap_as!(
                    client
                        .try_sign(res.handle, data, SigningVersion::Latest)
                        .await
                        .unwrap(),
                    Signature::Ed25519
                );

                let pub_key = unwrap_as!(res.public_key, PublicKey::Ed25519);
                let digest = Blake2b256::digest(data);
                use signature::Verifier;
                pub_key.verify(&digest, &sig).unwrap();
            }
        );
    }

    #[tokio::test]
    async fn rpc_import_ed25519() {
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

                let gen_res = client.generate(KeyType::Ed25519).await.unwrap();
                let res = client.import(&gen_res.encrypted_private_key).await.unwrap();

                let data = b"test message";
                let sig = unwrap_as!(
                    client
                        .try_sign(res.handle, data, SigningVersion::Latest)
                        .await
                        .unwrap(),
                    Signature::Ed25519
                );

                let pub_key = unwrap_as!(res.public_key, PublicKey::Ed25519);
                let digest = Blake2b256::digest(data);
                use signature::Verifier;
                pub_key.verify(&digest, &sig).unwrap();
            }
        );
    }

    #[tokio::test]
    async fn rpc_import_unencrypted_ed25519() {
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

                let key = PrivateKey::generate(KeyType::Ed25519, &mut rand_core::OsRng).unwrap();
                let res = client.import_unencrypted(&key).await.unwrap();

                let data = b"test message";
                let sig = unwrap_as!(
                    client
                        .try_sign(res.handle, data, SigningVersion::Latest)
                        .await
                        .unwrap(),
                    Signature::Ed25519
                );

                let pub_key = unwrap_as!(res.public_key, PublicKey::Ed25519);
                let digest = Blake2b256::digest(data);
                use signature::Verifier;
                pub_key.verify(&digest, &sig).unwrap();
            }
        );
    }

    #[tokio::test]
    async fn rpc_public_key_operations() {
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
                let res = client.generate_and_import(KeyType::NistP256).await.unwrap();

                // Test public_key
                let pk = client.public_key(res.handle).await.unwrap();
                assert!(matches!(pk, PublicKey::NistP256(_)));

                // Test public_key_from
                let pk_from = client
                    .public_key_from(&res.encrypted_private_key)
                    .await
                    .unwrap();
                assert!(matches!(pk_from, PublicKey::NistP256(_)));
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
                use crate::crypto::{ProofOfPossession, ProofVerifier};

                client.initialize(DummyCredentials {}).await.unwrap();
                let res = client.generate_and_import(KeyType::Bls).await.unwrap();

                let proof = client.proof_of_possession(res.handle).await.unwrap();
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&proof, &mut buf).unwrap();
                let pop = ciborium::de::from_reader(&buf[..]).unwrap();
                let bls_pop = unwrap_as!(pop, ProofOfPossession::Bls);

                // Verify proof
                let pk = unwrap_as!(res.public_key, PublicKey::Bls);
                pk.verify_pop(&bls_pop).unwrap();
            }
        );
    }

    #[tokio::test]
    async fn rpc_sign_with_bls_invalid_version() {
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
                let res = client.generate(KeyType::Bls).await.unwrap();

                let version = unsafe { std::mem::transmute::<u8, SigningVersion>(0) };

                let data = b"text";
                let sig = client
                    .try_sign_with(&res.encrypted_private_key, data, version)
                    .await;
                assert!(sig.is_err());
            }
        );
    }
}
