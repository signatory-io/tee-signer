mod vsock_proxy_client;

use aws_sdk_kms::{
    client::Client as KMSClient,
    config::{Credentials as AWSCredentials, Region, SharedCredentialsProvider},
};
use serde::{Deserialize, Serialize};
use signer_core::{AsyncSealant, Sealant, SealantFactory};
use vsock::SocketAddr as VSockAddr;

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub region: String,
}

pub struct Config {
    pub proxy_port: Option<u32>,
    pub proxy_cid: Option<u32>,
}

pub const DEFAULT_VSOCK_PROXY_PORT: u32 = 8000;
pub const VSOCK_PROXY_CID: u32 = 3;

pub struct ClientFactory {
    aws_config: aws_config::SdkConfig,
    config: Config,
}

impl ClientFactory {
    pub async fn new(config: Config) -> Self {
        Self {
            aws_config: aws_config::from_env().load().await,
            config,
        }
    }
}

impl SealantFactory for ClientFactory {
    type Output = Client;
    type Credentials = Credentials;

    fn try_new(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Self::Output, <Client as Sealant>::Error> {
        let cred = AWSCredentials::new(
            &credentials.access_key_id,
            &credentials.secret_access_key,
            None,
            None,
            "RPC",
        );

        let conf = self
            .aws_config
            .to_builder()
            .region(Region::new(credentials.region.clone()))
            .credentials_provider(SharedCredentialsProvider::new(cred))
            .http_client(vsock_proxy_client::build(VSockAddr::new(
                self.config.proxy_cid.unwrap_or(VSOCK_PROXY_CID),
                self.config.proxy_port.unwrap_or(DEFAULT_VSOCK_PROXY_PORT),
            )))
            .build();

        Ok(Client {
            client: KMSClient::new(&conf),
        })
    }
}

pub struct Client {
    client: KMSClient,
}

impl Sealant for Client {
    type Error = aws_sdk_kms::Error;
}

impl AsyncSealant for Client {
    async fn seal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }

    async fn unseal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}
