use confidential_signer::{Server, kms_client::ClientFactory, rand_core, tokio};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub struct App {
    conf: Config,
    rng: rand_core::OsRng,
}

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

impl std::error::Error for Error {}

pub const DEFAULT_TCP_PORT: u32 = 2000;

#[derive(Debug)]
pub struct Config {
    pub listen_port: Option<u32>,
}

impl App {
    pub fn init(conf: Config) -> Result<Self, Error> {
        let rng = rand_core::OsRng;
        Ok(Self { conf, rng })
    }

    pub async fn run(self) -> Result<(), Error> {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            self.conf.listen_port.unwrap_or(DEFAULT_TCP_PORT) as u16,
        );

        let listener = tokio::net::TcpListener::bind(addr).await?;
        println!("Listening on {}", addr);
        loop {
            let (conn, addr) = listener.accept().await?;
            println!("incoming connection from {}", addr);

            tokio::spawn(async move {
                let cf = ClientFactory::new();
                let mut srv = Server::new(cf, self.rng);

                if let Err(err) = srv.serve_connection(conn).await {
                    eprintln!("{}", err);
                }
            });
        }
    }
}
