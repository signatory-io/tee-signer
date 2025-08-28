use google_cloud_kms_v1::client::KeyManagementService;
use google_cloud_auth::credentials::external_account;
use serde::{Deserialize, Serialize};
use signer_core::{EncryptionBackend, EncryptionBackendFactory};

use crate::error;
use strfmt::strfmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub confidential_file: String,
}

#[derive(Deserialize)]
pub struct Credentials {
    pub wip_provider_path: String,
    pub encryption_key_path: String,
}

pub struct ClientFactory {}

impl ClientFactory {
    pub fn new() -> Self {
        Self {}
    }
}

const CONFIDENTIAL_CONFIG_STR: &'static str = r#"{{
    "type": "external_account",
    "audience": "//iam.googleapis.com/{wip_provider_path}",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {{
        "file": "/run/container_launcher/attestation_verifier_claims_token"
    }}
}}"#;

pub struct Client {
    client: KeyManagementService,
    encryption_key_path: String,
}

impl EncryptionBackend for Client {
    type Error = error::Error;

    async fn encrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .client
            .encrypt()
            .set_name(self.encryption_key_path.clone())
            .set_plaintext(tonic::codegen::Bytes::from(src.to_vec()))
            .send()
            .await
            .map_err(|e| error::Error::Encryption(e))?;
        Ok(response.ciphertext.into())
    }

    async fn decrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let response = self
            .client
            .decrypt()
            .set_name(self.encryption_key_path.clone())
            .set_ciphertext(tonic::codegen::Bytes::from(src.to_vec()))
            .send()
            .await
            .map_err(|e| error::Error::Decryption(e))?;
        Ok(response.plaintext.into())
    }
}

impl EncryptionBackendFactory for ClientFactory {
    type Output = Client;
    type Credentials = Credentials;

    async fn try_new(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Self::Output, <Self::Output as EncryptionBackend>::Error> {
        // prepare credentials file
        let credentials_json_str =
            strfmt!(CONFIDENTIAL_CONFIG_STR, wip_provider_path => credentials.wip_provider_path).unwrap();
        let credentials_json = serde_json::from_str(&credentials_json_str).unwrap();
        let client = KeyManagementService::builder()
            .with_credentials(external_account::Builder::new(credentials_json).build()?)
            .build()
            .await?;

        Ok(Client {
            client,
            encryption_key_path: credentials.encryption_key_path,
        })
    }
}
