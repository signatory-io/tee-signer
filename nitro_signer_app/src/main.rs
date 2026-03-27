pub mod app;
pub mod nsm;

use nitro_signer::tokio;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conf = app::Config {
        proxy_port: env::var("PROXY_PORT").ok().and_then(|s| s.parse().ok()),
        proxy_cid: env::var("PROXY_CID").ok().and_then(|s| s.parse().ok()),
        endpoint: env::var("ENDPOINT").ok(),
        listen_port: env::var("LISTEN_PORT").ok().and_then(|s| s.parse().ok()),
    };

    let app = app::App::init(conf)?;
    app.run().await.map_err(Into::into)
}
