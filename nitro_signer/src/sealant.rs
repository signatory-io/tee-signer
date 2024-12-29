use aws_sdk_kms as kms;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KMSCredentials {}

pub struct KMSSealant {
    rt: tokio::runtime::Runtime,
    client: kms::Client,
}
