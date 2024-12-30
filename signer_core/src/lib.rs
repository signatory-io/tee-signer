use crypto::{KeyPair, KeyType, Keychain, PrivateKey, PublicKey, Signature};
use rand_core::CryptoRngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::future::Future;

pub mod crypto;
pub mod rpc;

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
}

pub trait SyncSealant: Sealant {
    fn try_new(cred: Self::Credentials) -> Result<Self, Self::Error>;
    fn seal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn unseal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait AsyncSealant: Sealant {
    fn try_new(cred: Self::Credentials) -> impl Future<Output = Result<Self, Self::Error>> + Send;
    fn seal(&self, src: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
    fn unseal(&self, src: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
}

#[derive(Debug)]
pub enum Error<S: Sealant> {
    Sealant(S::Error),
    Signer(crypto::Error),
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

impl<S: Sealant> From<crypto::Error> for Error<S> {
    fn from(value: crypto::Error) -> Self {
        Error::Signer(value)
    }
}

#[derive(Debug)]
struct SealedSignerInner<S> {
    keychain: Keychain,
    sealant: S,
}

impl<S: Sealant> SealedSignerInner<S> {
    pub fn try_sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, Error<S>> {
        Ok(self.keychain.try_sign(handle, msg)?)
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error<S>> {
        Ok(self.keychain.public_key(handle)?)
    }
}

#[derive(Debug)]
pub struct SealedSigner<S>(SealedSignerInner<S>);

impl<S: SyncSealant> SealedSigner<S> {
    pub fn try_new(cred: S::Credentials) -> Result<Self, Error<S>> {
        Ok(SealedSigner(SealedSignerInner {
            keychain: Keychain::new(),
            sealant: match S::try_new(cred) {
                Ok(v) => v,
                Err(err) => return Err(Error::Sealant(err)),
            },
        }))
    }

    pub fn try_sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, Error<S>> {
        self.0.try_sign(handle, msg)
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error<S>> {
        self.0.public_key(handle)
    }

    fn unseal(&self, src: &[u8]) -> Result<PrivateKey, Error<S>> {
        match self.0.sealant.unseal(src) {
            Ok(unsealed) => Ok(PrivateKey::try_from_cbor(&unsealed[..])?),
            Err(err) => return Err(Error::Sealant(err)),
        }
    }

    fn seal(&self, pk: &PrivateKey) -> Result<Vec<u8>, Error<S>> {
        let buf = pk.try_into_cbor()?;
        match self.0.sealant.seal(&buf) {
            Ok(value) => Ok(value),
            Err(err) => Err(Error::Sealant(err)),
        }
    }

    pub fn import(&mut self, key_data: &[u8]) -> Result<(PublicKey, usize), Error<S>> {
        let pk = self.unseal(key_data)?;
        let p = pk.public_key();
        Ok((p, self.0.keychain.import(pk)))
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
        Ok((sealed, p, self.0.keychain.import(pk)))
    }

    pub fn try_sign_with(&self, key_data: &[u8], msg: &[u8]) -> Result<Signature, Error<S>> {
        Ok(self.unseal(key_data)?.try_sign(msg)?)
    }

    pub fn public_key_from(&self, key_data: &[u8]) -> Result<PublicKey, Error<S>> {
        Ok(self.unseal(key_data)?.public_key())
    }
}

#[derive(Debug)]
pub struct AsyncSealedSigner<S>(SealedSignerInner<S>);

impl<S: AsyncSealant> AsyncSealedSigner<S> {
    pub async fn try_new(cred: S::Credentials) -> Result<Self, Error<S>> {
        Ok(AsyncSealedSigner(SealedSignerInner {
            keychain: Keychain::new(),
            sealant: match S::try_new(cred).await {
                Ok(v) => v,
                Err(err) => return Err(Error::Sealant(err)),
            },
        }))
    }

    pub fn try_sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, Error<S>> {
        self.0.try_sign(handle, msg)
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error<S>> {
        self.0.public_key(handle)
    }

    async fn unseal(&self, src: &[u8]) -> Result<PrivateKey, Error<S>> {
        match self.0.sealant.unseal(src).await {
            Ok(unsealed) => Ok(PrivateKey::try_from_cbor(&unsealed[..])?),
            Err(err) => return Err(Error::Sealant(err)),
        }
    }

    async fn seal(&self, pk: &PrivateKey) -> Result<Vec<u8>, Error<S>> {
        let buf = pk.try_into_cbor()?;
        match self.0.sealant.seal(&buf).await {
            Ok(value) => Ok(value),
            Err(err) => Err(Error::Sealant(err)),
        }
    }

    pub async fn import(&mut self, key_data: &[u8]) -> Result<(PublicKey, usize), Error<S>> {
        let pk = self.unseal(key_data).await?;
        let p = pk.public_key();
        Ok((p, self.0.keychain.import(pk)))
    }

    pub async fn generate<R: CryptoRngCore>(
        &self,
        t: KeyType,
        r: &mut R,
    ) -> Result<(Vec<u8>, PublicKey), Error<S>> {
        let pk = PrivateKey::generate(t, r)?;
        let p = pk.public_key();
        let sealed = self.seal(&pk).await?;
        Ok((sealed, p))
    }

    pub async fn generate_and_import<R: CryptoRngCore>(
        &mut self,
        t: KeyType,
        r: &mut R,
    ) -> Result<(Vec<u8>, PublicKey, usize), Error<S>> {
        let pk = PrivateKey::generate(t, r)?;
        let p = pk.public_key();
        let sealed = self.seal(&pk).await?;
        Ok((sealed, p, self.0.keychain.import(pk)))
    }

    pub async fn try_sign_with(&self, key_data: &[u8], msg: &[u8]) -> Result<Signature, Error<S>> {
        Ok(self.unseal(key_data).await?.try_sign(msg)?)
    }

    pub async fn public_key_from(&self, key_data: &[u8]) -> Result<PublicKey, Error<S>> {
        Ok(self.unseal(key_data).await?.public_key())
    }
}

#[cfg(test)]
pub(crate) mod macros {
    macro_rules! unwrap_as {
        ($target: expr, $pat: path) => {
            match $target {
                $pat(a) => a,
                _ => {
                    panic!(
                        "{} doesn't match the pattern {}",
                        stringify!($target),
                        stringify!($pat)
                    );
                }
            }
        };
    }
    pub(crate) use unwrap_as;
}

#[cfg(test)]
mod tests {
    use super::{KeyType, Sealant, SealedSigner};
    use crate::crypto::{Blake2b256, PublicKey, Signature};
    use crate::macros::unwrap_as;
    use crate::{AsyncSealant, SyncSealant};
    use blake2::Digest;
    use serde::{Deserialize, Serialize};
    use signature::{DigestVerifier, Verifier};

    #[derive(Debug)]
    pub(crate) struct Passthrough;
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct DummyCredentials;
    #[derive(Debug)]
    pub(crate) struct DummyErr;

    impl std::fmt::Display for DummyErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("dummy")
        }
    }

    impl std::error::Error for DummyErr {}

    impl Sealant for Passthrough {
        type Credentials = DummyCredentials;
        type Error = DummyErr;
    }

    impl SyncSealant for Passthrough {
        fn try_new(_cred: Self::Credentials) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        fn seal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::from(src))
        }

        fn unseal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::from(src))
        }
    }

    impl AsyncSealant for Passthrough {
        async fn try_new(_cred: Self::Credentials) -> Result<Self, Self::Error> {
            Ok(Self)
        }

        async fn seal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::from(src))
        }

        async fn unseal(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::from(src))
        }
    }

    #[test]
    fn signer_secp256k1() {
        let signer: SealedSigner<Passthrough> = SealedSigner::try_new(DummyCredentials).unwrap();
        let (pk_bytes, pub_key) = signer
            .generate(KeyType::Secp256k1, &mut rand_core::OsRng)
            .unwrap();

        let data = b"text";
        let sig = unwrap_as!(
            signer.try_sign_with(&pk_bytes, data).unwrap(),
            Signature::Secp256k1
        );

        let mut digest = Blake2b256::new();
        digest.update(data);

        unwrap_as!(pub_key, PublicKey::Secp256k1)
            .verify_digest(digest, &sig)
            .unwrap();
    }

    #[test]
    fn signer_nist_p256() {
        let signer: SealedSigner<Passthrough> = SealedSigner::try_new(DummyCredentials).unwrap();
        let (pk_bytes, pub_key) = signer
            .generate(KeyType::NistP256, &mut rand_core::OsRng)
            .unwrap();

        let data = b"text";
        let sig = unwrap_as!(
            signer.try_sign_with(&pk_bytes, data).unwrap(),
            Signature::NistP256
        );

        let mut digest = Blake2b256::new();
        digest.update(data);

        unwrap_as!(pub_key, PublicKey::NistP256)
            .verify_digest(digest, &sig)
            .unwrap();
    }

    #[test]
    fn signer_ed25519() {
        let signer: SealedSigner<Passthrough> = SealedSigner::try_new(DummyCredentials).unwrap();
        let (pk_bytes, pub_key) = signer
            .generate(KeyType::Ed25519, &mut rand_core::OsRng)
            .unwrap();

        let data = b"text";
        let sig = unwrap_as!(
            signer.try_sign_with(&pk_bytes, data).unwrap(),
            Signature::Ed25519
        );

        let digest = Blake2b256::digest(data);

        unwrap_as!(pub_key, PublicKey::Ed25519)
            .verify(&digest, &sig)
            .unwrap();
    }
}
