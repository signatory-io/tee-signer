pub mod app;

use confidential_signer::tokio;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conf = app::Config {
        listen_port: env::var("LISTEN_PORT")
            .ok()
            .map(|s| s.parse().ok())
            .flatten(),
    };

    let app = app::App::init(conf)?;
    app.run().await.map_err(Into::into)
}
