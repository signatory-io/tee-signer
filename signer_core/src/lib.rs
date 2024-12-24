use rand_core::CryptoRngCore;
use serde::{de::DeserializeOwned, Serialize};
use signer::{KeyPair, KeyType, Keychain, PrivateKey, PublicKey, Signature};

pub mod rpc;
pub mod signer;

trait TryIntoCBOR {
    type Error;
    fn try_into_cbor(&self) -> Result<Vec<u8>, Self::Error>;
}

impl<T> TryIntoCBOR for T
where
    T: Serialize,
{
    type Error = ciborium::ser::Error<std::io::Error>;

    fn try_into_cbor(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buf: Vec<u8> = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }
}

trait TryFromCBOR: Sized {
    type Error;
    fn try_from_cbor(src: &[u8]) -> Result<Self, Self::Error>;
}

impl<T> TryFromCBOR for T
where
    T: DeserializeOwned,
{
    type Error = ciborium::de::Error<std::io::Error>;

    fn try_from_cbor(src: &[u8]) -> Result<Self, Self::Error> {
        ciborium::from_reader(src)
    }
}

pub trait Sealant: std::fmt::Debug + Sized {
    type Credentials;
    type Error: std::error::Error + 'static;

    fn try_new(cred: Self::Credentials) -> Result<Self, Self::Error>;
    fn seal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn unseal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub enum Error<S: Sealant> {
    Sealant(S::Error),
    Signer(signer::Error),
    Serialize(ciborium::ser::Error<std::io::Error>),
    Deserialize(ciborium::de::Error<std::io::Error>),
}

impl<S: Sealant> std::fmt::Display for Error<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sealant(_) => f.write_str("sealant error"),
            Error::Signer(_) => f.write_str("signer error"),
            Error::Serialize(_) => f.write_str("serialization error"),
            Error::Deserialize(_) => f.write_str("deserialization error"),
        }
    }
}

impl<S: Sealant> std::error::Error for Error<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Sealant(val) => Some(val),
            Error::Signer(val) => Some(val),
            Error::Serialize(val) => Some(val),
            Error::Deserialize(val) => Some(val),
        }
    }
}

impl<S: Sealant> From<ciborium::de::Error<std::io::Error>> for Error<S> {
    fn from(value: ciborium::de::Error<std::io::Error>) -> Self {
        Error::Deserialize(value)
    }
}

impl<S: Sealant> From<ciborium::ser::Error<std::io::Error>> for Error<S> {
    fn from(value: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Serialize(value)
    }
}

impl<S: Sealant> From<signer::Error> for Error<S> {
    fn from(value: signer::Error) -> Self {
        Error::Signer(value)
    }
}

#[derive(Debug)]
pub struct SealedSigner<S> {
    keychain: Keychain,
    sealant: S,
}

impl<S: Sealant> SealedSigner<S> {
    pub fn try_new(cred: S::Credentials) -> Result<Self, Error<S>> {
        Ok(SealedSigner {
            keychain: Keychain::new(),
            sealant: match S::try_new(cred) {
                Ok(v) => v,
                Err(err) => return Err(Error::Sealant(err)),
            },
        })
    }

    fn unseal(&self, src: &[u8]) -> Result<PrivateKey, Error<S>> {
        match self.sealant.unseal(src) {
            Ok(unsealed) => Ok(PrivateKey::try_from_cbor(&unsealed[..])?),
            Err(err) => return Err(Error::Sealant(err)),
        }
    }

    fn seal(&self, pk: &PrivateKey) -> Result<Vec<u8>, Error<S>> {
        let buf = pk.try_into_cbor()?;
        match self.sealant.seal(&buf) {
            Ok(value) => Ok(value),
            Err(err) => Err(Error::Sealant(err)),
        }
    }

    pub fn import(&mut self, key_data: &[u8]) -> Result<(PublicKey, usize), Error<S>> {
        let pk = self.unseal(key_data)?;
        let p = pk.public_key();
        Ok((p, self.keychain.import(pk)))
    }

    pub fn generate<R: CryptoRngCore>(
        &self,
        t: KeyType,
        r: &mut R,
    ) -> Result<(Vec<u8>, PublicKey), Error<S>> {
        let pk = PrivateKey::generate(t, r)?;
        let p = pk.public_key();
        let sealed = self.seal(&pk)?;
        Ok((sealed, p))
    }

    pub fn generate_and_import<R: CryptoRngCore>(
        &mut self,
        t: KeyType,
        r: &mut R,
    ) -> Result<(Vec<u8>, PublicKey, usize), Error<S>> {
        let pk = PrivateKey::generate(t, r)?;
        let p = pk.public_key();
        let sealed = self.seal(&pk)?;
        Ok((sealed, p, self.keychain.import(pk)))
    }

    pub fn try_sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, Error<S>> {
        Ok(self.keychain.try_sign(handle, msg)?)
    }

    pub fn try_sign_with(&self, key_data: &[u8], msg: &[u8]) -> Result<Signature, Error<S>> {
        Ok(self.unseal(key_data)?.try_sign(msg)?)
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error<S>> {
        Ok(self.keychain.public_key(handle)?)
    }

    pub fn public_key_from(&self, key_data: &[u8]) -> Result<PublicKey, Error<S>> {
        Ok(self.unseal(key_data)?.public_key())
    }
}
