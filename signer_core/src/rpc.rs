use crate::crypto::KeyType;
use serde::{Deserialize, Serialize};

pub mod client;
pub mod net;
pub mod server;

#[derive(Debug, Serialize, Deserialize)]
enum Request<C> {
    Initialize(C),
    Import(Vec<u8>),
    Generate(KeyType),
    GenerateAndImport(KeyType),
    Sign { handle: usize, msg: Vec<u8> },
    SignWith { key_data: Vec<u8>, msg: Vec<u8> },
    PublicKey(usize),
    PublicKeyFrom(Vec<u8>),
    Terminate,
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
            Error,
        };
        use crate::tests::{DummyCredentials, Passthrough};
        use crate::{macros::unwrap_as, Sealant};
        use blake2::Digest;
        use signature::{DigestVerifier, Verifier};
        use std::os::unix::net::UnixDatagram;
        use std::thread;

        #[test]
        fn rpc_sign_with_secp256k1() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            client.initialize(DummyCredentials).unwrap();
            let (sealed_pk, pub_key) = client.generate(KeyType::Secp256k1).unwrap();

            let data = b"text";
            let sig = unwrap_as!(
                client.try_sign_with(&sealed_pk, data).unwrap(),
                Signature::Secp256k1
            );
            let pub_key = unwrap_as!(pub_key, PublicKey::Secp256k1);
            let mut digest = Blake2b256::new();
            digest.update(data);
            pub_key.verify_digest(digest, &sig).unwrap();

            client.terminate().unwrap();
            jh.join().unwrap();
        }

        #[test]
        fn rpc_sign_with_ed25519() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            client.initialize(DummyCredentials).unwrap();
            let (sealed_pk, pub_key) = client.generate(KeyType::Ed25519).unwrap();

            let data = b"text";
            let sig = unwrap_as!(
                client.try_sign_with(&sealed_pk, data).unwrap(),
                Signature::Ed25519
            );
            let pub_key = unwrap_as!(pub_key, PublicKey::Ed25519);
            let digest = Blake2b256::digest(data);
            pub_key.verify(&digest, &sig).unwrap();

            client.terminate().unwrap();
            jh.join().unwrap();
        }

        #[test]
        fn rpc_sign_with_bls() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            client.initialize(DummyCredentials).unwrap();
            let (sealed_pk, pub_key) = client.generate(KeyType::BLS).unwrap();

            let data = b"text";
            let sig = unwrap_as!(
                client.try_sign_with(&sealed_pk, data).unwrap(),
                Signature::BLS
            );
            let pub_key = unwrap_as!(pub_key, PublicKey::BLS);
            pub_key.verify(data, &sig).unwrap();

            client.terminate().unwrap();
            jh.join().unwrap();
        }

        #[test]
        fn rpc_generate_and_import_secp256k1() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            client.initialize(DummyCredentials).unwrap();
            let (_, pub_key, handle) = client.generate_and_import(KeyType::Secp256k1).unwrap();

            let data = b"text";
            let sig = unwrap_as!(client.try_sign(handle, data).unwrap(), Signature::Secp256k1);
            let pub_key = unwrap_as!(pub_key, PublicKey::Secp256k1);
            let mut digest = Blake2b256::new();
            digest.update(data);
            pub_key.verify_digest(digest, &sig).unwrap();

            client.terminate().unwrap();
            jh.join().unwrap();
        }

        #[test]
        fn rpc_generate_and_import_ed25519() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            client.initialize(DummyCredentials).unwrap();
            let (_, pub_key, handle) = client.generate_and_import(KeyType::Ed25519).unwrap();

            let data = b"text";
            let sig = unwrap_as!(client.try_sign(handle, data).unwrap(), Signature::Ed25519);
            let pub_key = unwrap_as!(pub_key, PublicKey::Ed25519);
            let digest = Blake2b256::digest(data);
            pub_key.verify(&digest, &sig).unwrap();

            client.terminate().unwrap();
            jh.join().unwrap();
        }

        #[test]
        fn rpc_generate_and_import_bls() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            client.initialize(DummyCredentials).unwrap();
            let (_, pub_key, handle) = client.generate_and_import(KeyType::BLS).unwrap();

            let data = b"text";
            let sig = unwrap_as!(client.try_sign(handle, data).unwrap(), Signature::BLS);
            let pub_key = unwrap_as!(pub_key, PublicKey::BLS);
            pub_key.verify(data, &sig).unwrap();

            client.terminate().unwrap();
            jh.join().unwrap();
        }

        #[test]
        fn rpc_uninitialized() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: Server<Passthrough, rand_core::OsRng> = Server::new(rand_core::OsRng);
            let jh = thread::spawn(move || server.serve_connection(srv_sock).unwrap());

            let client: Client<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                Client::new(client_sock);

            let err = client.generate(KeyType::Secp256k1).unwrap_err();
            assert_eq!(
                unwrap_as!(err, ClientError::RPC),
                Error {
                    message: "uninitialized".into(),
                    source: None
                }
            );

            client.terminate().unwrap();
            jh.join().unwrap();
        }
    }

    mod asynchronous {
        use crate::crypto::{Blake2b256, KeyType, PublicKey, Signature};
        use crate::rpc::{client::AsyncClient, server::AsyncServer};
        use crate::tests::{DummyCredentials, Passthrough};
        use crate::{macros::unwrap_as, Sealant};
        use blake2::Digest;
        use signature::DigestVerifier;
        use tokio::net::UnixDatagram;

        #[tokio::test]
        async fn rpc_sign_with_secp256k1() {
            let (srv_sock, client_sock) = UnixDatagram::pair().unwrap();
            let server: AsyncServer<Passthrough, rand_core::OsRng> =
                AsyncServer::new(rand_core::OsRng);

            let client: AsyncClient<UnixDatagram, <Passthrough as Sealant>::Credentials> =
                AsyncClient::new(client_sock);

            futures::join!(
                async {
                    server.serve_connection(srv_sock).await.unwrap();
                },
                async {
                    client.initialize(DummyCredentials).await.unwrap();
                    let (sealed_pk, pub_key) = client.generate(KeyType::Secp256k1).await.unwrap();

                    let data = b"text";
                    let sig = unwrap_as!(
                        client.try_sign_with(&sealed_pk, data).await.unwrap(),
                        Signature::Secp256k1
                    );
                    let pub_key = unwrap_as!(pub_key, PublicKey::Secp256k1);
                    let mut digest = Blake2b256::new();
                    digest.update(data);
                    pub_key.verify_digest(digest, &sig).unwrap();

                    client.terminate().await.unwrap();
                }
            );
        }
    }
}
