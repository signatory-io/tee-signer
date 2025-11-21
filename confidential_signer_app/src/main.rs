pub mod app;

use confidential_signer::{
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
        listen_port: env::var("LISTEN_PORT")
            .ok()
            .map(|s| s.parse().ok())
            .flatten(),
        server_keypair: env::var("SERVER_KEYPAIR").ok(),
        authorized_keys: env::var("AUTHORIZED_KEYS").ok(),
    };

    let app = app::App::init(conf)?;
    app.run().await.map_err(Into::into)
}
