use crate::{
    crypto::{KeyType, PrivateKey},
    serde_helper::bytes,
};
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
        msg: Vec<u8>,
    },
    SignWith {
        #[serde(with = "bytes")]
        key_data: Vec<u8>,
        msg: Vec<u8>,
    },
    PublicKey(usize),
    PublicKeyFrom(#[serde(with = "bytes")] Vec<u8>),
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
    mod synchronous {
        use crate::crypto::{Blake2b256, KeyType, PublicKey, Signature};
        use crate::rpc::{
            client::{Client, Error as ClientError},
            server::Server,
            Error, Request,
        };
        use crate::tests::{DummyCredentials, Passthrough, PassthroughFactory};
        use crate::{macros::unwrap_as, EncryptedSigner};
        use blake2::Digest;
        use signature::{DigestVerifier, Verifier};
        use std::os::unix::net::UnixStream;
        use std::thread;

        #[test]
        fn serde() {
            let req = Request::Initialize(DummyCredentials {});
            let mut serialized: Vec<u8> = Vec::new();
            ciborium::into_writer(&req, &mut serialized).unwrap();
            // a1, 6a, 49, 6e, 69, 74, 69, 61, 6c, 69, 7a, 65, a0
            let _: Request<DummyCredentials> = ciborium::from_reader(&serialized[..]).unwrap();
        }

        #[test]
        fn rpc_sign_with_secp256k1() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                client.initialize(DummyCredentials {}).unwrap();
                let (enc_pk, pub_key) = client.generate(KeyType::Secp256k1).unwrap();

                let data = b"text";
                let sig = unwrap_as!(
                    client.try_sign_with(&enc_pk, data).unwrap(),
                    Signature::Secp256k1
                );
                let pub_key = unwrap_as!(pub_key, PublicKey::Secp256k1);
                let mut digest = Blake2b256::new();
                digest.update(data);
                pub_key.verify_digest(digest, &*sig).unwrap();
            }
            jh.join().unwrap();
        }

        #[test]
        fn rpc_sign_with_ed25519() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                client.initialize(DummyCredentials {}).unwrap();
                let (enc_pk, pub_key) = client.generate(KeyType::Ed25519).unwrap();

                let data = b"text";
                let sig = unwrap_as!(
                    client.try_sign_with(&enc_pk, data).unwrap(),
                    Signature::Ed25519
                );
                let pub_key = unwrap_as!(pub_key, PublicKey::Ed25519);
                let digest = Blake2b256::digest(data);
                pub_key.verify(&digest, &sig).unwrap();
            }
            jh.join().unwrap();
        }

        #[test]
        fn rpc_sign_with_bls() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                client.initialize(DummyCredentials {}).unwrap();
                let (enc_pk, pub_key) = client.generate(KeyType::Bls).unwrap();

                let data = b"text";
                let sig = unwrap_as!(client.try_sign_with(&enc_pk, data).unwrap(), Signature::Bls);
                let pub_key = unwrap_as!(pub_key, PublicKey::Bls);
                pub_key.verify(data, &sig).unwrap();
            }
            jh.join().unwrap();
        }

        #[test]
        fn rpc_generate_and_import_secp256k1() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                client.initialize(DummyCredentials {}).unwrap();
                let (_, pub_key, handle) = client.generate_and_import(KeyType::Secp256k1).unwrap();

                let data = b"text";
                let sig = unwrap_as!(client.try_sign(handle, data).unwrap(), Signature::Secp256k1);
                let pub_key = unwrap_as!(pub_key, PublicKey::Secp256k1);
                let mut digest = Blake2b256::new();
                digest.update(data);
                pub_key.verify_digest(digest, &*sig).unwrap();
            }
            jh.join().unwrap();
        }

        #[test]
        fn rpc_generate_and_import_ed25519() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                client.initialize(DummyCredentials {}).unwrap();
                let (_, pub_key, handle) = client.generate_and_import(KeyType::Ed25519).unwrap();

                let data = b"text";
                let sig = unwrap_as!(client.try_sign(handle, data).unwrap(), Signature::Ed25519);
                let pub_key = unwrap_as!(pub_key, PublicKey::Ed25519);
                let digest = Blake2b256::digest(data);
                pub_key.verify(&digest, &sig).unwrap();
            }
            jh.join().unwrap();
        }

        #[test]
        fn rpc_generate_and_import_bls() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                client.initialize(DummyCredentials {}).unwrap();
                let (_, pub_key, handle) = client.generate_and_import(KeyType::Bls).unwrap();

                let data = b"text";
                let sig = unwrap_as!(client.try_sign(handle, data).unwrap(), Signature::Bls);
                let pub_key = unwrap_as!(pub_key, PublicKey::Bls);
                pub_key.verify(data, &sig).unwrap();
            }
            jh.join().unwrap();
        }

        #[test]
        fn rpc_uninitialized() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                EncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            {
                let mut client: Client<UnixStream, DummyCredentials> = Client::new(client_sock);

                let err = client.generate(KeyType::Secp256k1).unwrap_err();
                assert_eq!(
                    unwrap_as!(err, ClientError::RPC),
                    Error {
                        message: "uninitialized".into(),
                        source: None
                    }
                );
            }
            jh.join().unwrap();
        }
    }

    mod asynchronous {
        use crate::crypto::{Blake2b256, KeyType, PublicKey, Signature};
        use crate::rpc::{
            client::{AsyncClient, Error as ClientError},
            server::Server,
            Error,
        };
        use crate::tests::{DummyCredentials, Passthrough, PassthroughFactory};
        use crate::{macros::unwrap_as, AsyncEncryptedSigner};
        use blake2::Digest;
        use signature::DigestVerifier;
        use tokio::net::UnixStream;

        #[tokio::test]
        async fn rpc_sign_with_secp256k1() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                AsyncEncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);

            let mut client: AsyncClient<UnixStream, DummyCredentials> =
                AsyncClient::new(client_sock);

            futures::join!(
                async move {
                    server.serve_connection(srv_sock).await.unwrap();
                },
                async move {
                    client.initialize(DummyCredentials {}).await.unwrap();
                    let (enc_pk, pub_key) = client.generate(KeyType::Secp256k1).await.unwrap();

                    let data = b"text";
                    let sig = unwrap_as!(
                        client.try_sign_with(&enc_pk, data).await.unwrap(),
                        Signature::Secp256k1
                    );
                    let pub_key = unwrap_as!(pub_key, PublicKey::Secp256k1);
                    let mut digest = Blake2b256::new();
                    digest.update(data);
                    pub_key.verify_digest(digest, &*sig).unwrap();
                }
            );
        }

        #[tokio::test]
        async fn rpc_uninitialized() {
            let (srv_sock, client_sock) = UnixStream::pair().unwrap();
            let mut server: Server<
                PassthroughFactory,
                AsyncEncryptedSigner<Passthrough>,
                rand_core::OsRng,
            > = Server::new(PassthroughFactory, rand_core::OsRng);

            let mut client: AsyncClient<UnixStream, DummyCredentials> =
                AsyncClient::new(client_sock);

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
    }
}
