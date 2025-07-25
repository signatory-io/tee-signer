#[derive(Debug)]
pub enum Error {
    Credentials(google_cloud_auth::build_errors::Error),
    Auth(google_cloud_gax::client_builder::Error),
    Encryption(google_cloud_gax::error::Error),
    Decryption(google_cloud_gax::error::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Credentials(e) => write!(f, "Credentials error: {}", e),
            Error::Auth(e) => write!(f, "Auth error: {}", e),
            Error::Encryption(e) => write!(f, "Encryption error: {}", e),
            Error::Decryption(e) => write!(f, "Decryption error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Credentials(e) => Some(e),
            Error::Auth(e) => Some(e),
            Error::Encryption(e) => Some(e),
            Error::Decryption(e) => Some(e),
        }
    }
}

impl From<google_cloud_auth::build_errors::Error> for Error {
    fn from(e: google_cloud_auth::build_errors::Error) -> Self {
        Error::Credentials(e)
    }
}

impl From<google_cloud_gax::client_builder::Error> for Error {
    fn from(e: google_cloud_gax::client_builder::Error) -> Self {
        Error::Auth(e)
    }
}
