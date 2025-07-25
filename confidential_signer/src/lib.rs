pub mod error;
pub mod kms_client;
pub use rand_core;
pub use signer_core;
use signer_core::EncryptedSigner;

pub use tokio;

pub type Server<R> = signer_core::rpc::server::Server<
    kms_client::ClientFactory,
    EncryptedSigner<kms_client::Client>,
    R,
>;

pub type Client = signer_core::rpc::client::Client<tokio::net::TcpStream, kms_client::Credentials>;
