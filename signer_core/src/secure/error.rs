#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    Serialization(ciborium::ser::Error<std::io::Error>),
    Deserialization(ciborium::de::Error<std::io::Error>),
    Base64Decode(base64::DecodeError),
    SignatureError(ed25519_dalek::SignatureError),
    InvalidHandshake,
    Unauthorized,
    InvalidKeyLength,
    InvalidKeyType,
    NotInitialized,
    EncryptionFailed,
    DecryptionFailed,
    NonceExhausted,
    InvalidPacketLength,
    SignatureVerification,
    KeyDerivation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IO(e) => write!(f, "IO error: {}", e),
            Error::Serialization(e) => write!(f, "Serialization error: {}", e),
            Error::Deserialization(e) => write!(f, "Deserialization error: {}", e),
            Error::Base64Decode(e) => write!(f, "Base64 decode error: {}", e),
            Error::SignatureError(e) => write!(f, "Signature error: {}", e),
            Error::InvalidHandshake => write!(f, "Invalid handshake message"),
            Error::Unauthorized => write!(f, "Client not authorized"),
            Error::InvalidKeyLength => write!(f, "Invalid Ed25519 key length"),
            Error::InvalidKeyType => write!(f, "Invalid key type"),
            Error::NotInitialized => write!(f, "Session not initialized"),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
            Error::NonceExhausted => write!(f, "Nonce exhausted"),
            Error::InvalidPacketLength => write!(f, "Invalid packet length"),
            Error::SignatureVerification => write!(f, "Signature verification failed"),
            Error::KeyDerivation => write!(f, "Key derivation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO(e) => Some(e),
            Error::Serialization(e) => Some(e),
            Error::Deserialization(e) => Some(e),
            Error::Base64Decode(e) => Some(e),
            Error::SignatureError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Error::SignatureError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO(e)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for Error {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Serialization(e)
    }
}

impl From<ciborium::de::Error<std::io::Error>> for Error {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Error::Deserialization(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64Decode(e)
    }
}
