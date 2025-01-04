use crate::nsm;

pub struct App {
    secm: nsm::NSM,
    priv_key: rsa::RsaPrivateKey,
    pub_key: rsa::RsaPublicKey,
    attestation_doc: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    NSM(nsm::Error),
    RSA(rsa::Error),
}

impl From<nsm::Error> for Error {
    fn from(value: nsm::Error) -> Self {
        Error::NSM(value)
    }
}

impl From<rsa::Error> for Error {
    fn from(value: rsa::Error) -> Self {
        Error::RSA(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NSM(error) => write!(f, "NSM error: {}", error),
            Error::RSA(error) => write!(f, "RSA error: {}", error),
        }
    }
}

const RSA_BITS: usize = 2048;

impl App {
    pub fn init() -> Result<Self, Error> {
        let secm = nsm::NSM::open()?;
        nsm::seed_rng(&secm, nsm::DEFAULT_ENTROPY_BYTE_SZ)?;

        let priv_key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, RSA_BITS)?;
        let pub_key = priv_key.to_public_key();

        let attestation_doc = secm.attest(None, None, Some(&pub_key))?;

        Ok(Self {
            secm,
            priv_key,
            pub_key,
            attestation_doc,
        })
    }
}
