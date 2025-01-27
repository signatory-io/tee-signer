use clap::Parser;
use nitro_signer::tokio;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

mod app;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value_t = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 6543))]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), app::Error> {
    let cli = Cli::parse();
    app::App::run(&cli.listen).await
}
