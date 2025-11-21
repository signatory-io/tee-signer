pub mod app;
pub mod nsm;

use nitro_signer::{
    log::LevelFilter, log4rs, log4rs::append::console::ConsoleAppender, log4rs::config::Appender,
    log4rs::config::Config, log4rs::config::Root, tokio,
};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = ConsoleAppender::builder().build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        .unwrap();
    log4rs::init_config(config).unwrap();

    let conf = app::Config {
        proxy_port: env::var("PROXY_PORT")
            .ok()
            .map(|s| s.parse().ok())
            .flatten(),
        proxy_cid: env::var("PROXY_CID").ok().map(|s| s.parse().ok()).flatten(),
        endpoint: env::var("ENDPOINT").ok(),
        listen_port: env::var("LISTEN_PORT")
            .ok()
            .map(|s| s.parse().ok())
            .flatten(),
    };

    let app = app::App::init(conf)?;
    app.run().await.map_err(Into::into)
}
