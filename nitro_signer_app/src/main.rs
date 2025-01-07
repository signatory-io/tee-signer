pub mod app;
pub mod nsm;

use clap::Parser;
use nitro_signer::{
    kms_client::{self, EncryptionAlgorithmSpec},
    tokio,
};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    algorithm_spec: Option<EncryptionAlgorithmSpec>,

    #[arg(long)]
    key_id: Option<String>,

    #[arg(long, default_value_t = kms_client::DEFAULT_VSOCK_PROXY_PORT)]
    proxy_port: u32,

    #[arg(long, default_value_t = kms_client::DEFAULT_VSOCK_PROXY_CID)]
    proxy_cid: u32,

    #[arg(long)]
    region: String,

    #[arg(long)]
    endpoint: Option<String>,

    #[arg(long, default_value_t = app::DEFAULT_VSOCK_PORT)]
    listen_port: u32,
}

#[tokio::main]
async fn main() -> Result<(), app::Error> {
    let cli = Cli::parse();
    let conf = app::Config {
        algorithm_spec: cli.algorithm_spec,
        key_id: cli.key_id,
        proxy_port: Some(cli.proxy_port),
        proxy_cid: Some(cli.proxy_cid),
        region: cli.region,
        endpoint: cli.endpoint,
        listen_port: Some(cli.listen_port),
    };

    let app = app::App::init(conf)?;
    app.run().await
}
