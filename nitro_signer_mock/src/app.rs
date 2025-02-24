use nitro_signer::{
    rand_core,
    signer_core::{rpc::server::Server, EncryptionBackend, EncryptionBackendFactory},
    tokio,
};
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, io, net::SocketAddr};

pub struct App {}

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Error::IO(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IO(error) => write!(f, "IO error: {}", error),
        }
    }
}

#[derive(Debug)]
struct Passthrough;

impl EncryptionBackend for Passthrough {
    type Error = Infallible;

    async fn encrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::from(src))
    }

    async fn decrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::from(src))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct DummyCredentials {} // serialized as empty object instead of null for unity

struct PassthroughFactory;

impl EncryptionBackendFactory for PassthroughFactory {
    type Output = Passthrough;
    type Credentials = DummyCredentials;
    fn try_new(&self, _cred: Self::Credentials) -> Result<Self::Output, Infallible> {
        Ok(Passthrough)
    }
}

impl App {
    pub async fn run(addr: &SocketAddr) -> Result<(), Error> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        loop {
            let (conn, _) = listener.accept().await?;
            tokio::spawn(async move {
                let mut srv = Server::new(PassthroughFactory, rand_core::OsRng);

                if let Err(err) = srv.serve_connection(conn).await {
                    eprintln!("{}", err);
                }
            });
        }
    }
}
