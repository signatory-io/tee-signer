pub use aws_config;
pub use rand_core;
pub use rsa;
pub use signer_core;
use signer_core::EncryptedSigner;
pub use tokio;
pub use vsock;

pub mod kms_client;

pub type Server<R> = signer_core::rpc::server::Server<
    kms_client::ClientFactory,
    EncryptedSigner<kms_client::Client>,
    R,
>;

pub type Client = signer_core::rpc::client::Client<vsock::Stream, kms_client::Credentials>;
