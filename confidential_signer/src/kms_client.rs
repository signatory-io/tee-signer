use google_cloud_auth::credentials::external_account;
use google_cloud_kms_v1::client::KeyManagementService;
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

#[derive(Default)]
pub struct ClientFactory {}

impl ClientFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

const CONFIDENTIAL_CONFIG_STR: &str = r#"{{
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
            .map_err(error::Error::Encryption)?;
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
            .map_err(error::Error::Decryption)?;
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
        let credentials_json_str =
            strfmt!(CONFIDENTIAL_CONFIG_STR, wip_provider_path => credentials.wip_provider_path)
                .map_err(|e| error::Error::CredentialFormat(e.to_string()))?;
        let credentials_json = serde_json::from_str(&credentials_json_str)
            .map_err(|e| error::Error::CredentialFormat(e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialize() {
        let config = Config {
            confidential_file: "/path/to/file".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(json, r#"{"confidential_file":"/path/to/file"}"#);
    }

    #[test]
    fn test_config_deserialize() {
        let json = r#"{"confidential_file":"/test/path"}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.confidential_file, "/test/path");
    }

    #[test]
    fn test_credentials_deserialize() {
        let json = r#"{
            "wip_provider_path": "projects/123/locations/global/workloadIdentityPools/pool",
            "encryption_key_path": "projects/123/locations/us/keyRings/ring/cryptoKeys/key"
        }"#;
        let creds: Credentials = serde_json::from_str(json).unwrap();
        assert_eq!(
            creds.wip_provider_path,
            "projects/123/locations/global/workloadIdentityPools/pool"
        );
        assert_eq!(
            creds.encryption_key_path,
            "projects/123/locations/us/keyRings/ring/cryptoKeys/key"
        );
    }

    #[test]
    fn test_credentials_missing_field() {
        let json = r#"{"wip_provider_path": "path1"}"#;
        let result: Result<Credentials, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_factory_new() {
        let _factory = ClientFactory::new();
    }

    #[test]
    fn test_confidential_config_str_is_valid_json_template() {
        let formatted = strfmt!(
            CONFIDENTIAL_CONFIG_STR,
            wip_provider_path => "test-path"
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(parsed["type"], "external_account");
        assert_eq!(parsed["audience"], "//iam.googleapis.com/test-path");
        assert_eq!(
            parsed["subject_token_type"],
            "urn:ietf:params:oauth:token-type:jwt"
        );
        assert_eq!(parsed["token_url"], "https://sts.googleapis.com/v1/token");
        assert_eq!(
            parsed["credential_source"]["file"],
            "/run/container_launcher/attestation_verifier_claims_token"
        );
    }

    #[test]
    fn test_client_factory_debug() {
        let factory = ClientFactory::new();
        let debug_str = format!("{:?}", factory);
        assert!(debug_str.contains("ClientFactory"));
    }
}
