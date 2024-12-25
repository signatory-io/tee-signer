use crate::crypto::KeyType;
use serde::{Deserialize, Serialize};

pub mod client;
pub mod net;
pub mod server;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Request<C> {
    Initialize(C),
    Import(Vec<u8>),
    Generate(KeyType),
    GenerateAndImport(KeyType),
    Sign { handle: usize, msg: Vec<u8> },
    SignWith { key_data: Vec<u8>, msg: Vec<u8> },
    PublicKey(usize),
    PublicKeyFrom(Vec<u8>),
}

/// Wire-compatible error object
#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    pub message: String,
    pub source: Option<Box<Error>>,
}

impl<T: std::error::Error> From<T> for Error {
    fn from(value: T) -> Self {
        Error {
            message: value.to_string(),
            source: match value.source() {
                Some(s) => Some(Box::new(Self::from(s))),
                None => None,
            },
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(src) => write!(f, "{}: {}", &self.message, src),
            None => f.write_str(&self.message),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
