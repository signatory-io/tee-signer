use crate::{EncryptionBackend, EncryptionBackendFactory};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

#[derive(Debug)]
pub struct Passthrough;

impl EncryptionBackend for Passthrough {
    type Error = Infallible;

    async fn encrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::from(src))
    }

    async fn decrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(Vec::from(src))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DummyCredentials {} // serialized as empty object instead of null for unity

pub struct PassthroughFactory;

impl EncryptionBackendFactory for PassthroughFactory {
    type Output = Passthrough;
    type Credentials = DummyCredentials;
    async fn try_new(&self, _cred: Self::Credentials) -> Result<Self::Output, Infallible> {
        Ok(Passthrough)
    }
}
