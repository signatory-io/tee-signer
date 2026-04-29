use nitro_signer::{rand_core, tokio};
use signer_core::{mock::PassthroughFactory, rpc::server::Server};
use std::{io, net::SocketAddr};

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
            Error::IO(error) => write!(f, "IO error: {error}"),
        }
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
                    eprintln!("{err}");
                }
            });
        }
    }
}
