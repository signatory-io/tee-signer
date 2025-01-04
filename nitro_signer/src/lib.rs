pub use aws_config;
use signer_core::AsyncSealedSigner;

pub mod kms_client;

pub type Server = signer_core::rpc::server::Server<
    kms_client::ClientFactory,
    AsyncSealedSigner<kms_client::Client>,
    rand_core::OsRng,
>;

pub type Client = signer_core::rpc::client::Client<vsock::Stream, kms_client::Credentials>;
