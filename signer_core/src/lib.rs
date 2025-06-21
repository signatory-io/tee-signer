use crypto::{KeyPair, KeyType, Keychain, PrivateKey, PublicKey, Signature};
use rand_core::CryptoRngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::future::Future;

pub mod crypto;
pub mod rpc;
pub(crate) mod serde_helper;

use serde_helper::bytes;

trait TryIntoCBOR {
    type Error;
    fn try_into_cbor(&self) -> Result<Vec<u8>, Self::Error>;
    fn try_into_writer<W: std::io::Write>(&self, w: W) -> Result<(), Self::Error>;
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

    fn try_into_writer<W: std::io::Write>(&self, w: W) -> Result<(), Self::Error> {
        ciborium::into_writer(self, w)
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
pub trait EncryptionBackendFactory {
    type Output: EncryptionBackend;
    type Credentials;

    fn try_new(
        &self,
        cred: Self::Credentials,
    ) -> Result<Self::Output, <Self::Output as EncryptionBackend>::Error>;
}

pub trait EncryptionBackend: Sized {
    type Error: std::error::Error + 'static;

    fn encrypt(&self, src: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
    fn decrypt(&self, src: &[u8]) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
}

#[derive(Debug)]
pub enum Error<S: std::error::Error> {
    Encryption(S),
    Signer(crypto::Error),
    Serialize(ciborium::ser::Error<std::io::Error>),
    Deserialize(ciborium::de::Error<std::io::Error>),
}

impl<S: std::error::Error> std::fmt::Display for Error<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encryption(_) => f.write_str("encryption error"),
            Error::Signer(_) => f.write_str("signer error"),
            Error::Serialize(_) => f.write_str("serialization error"),
            Error::Deserialize(_) => f.write_str("deserialization error"),
        }
    }
}

impl<S: std::error::Error + 'static> std::error::Error for Error<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Encryption(val) => Some(val),
            Error::Signer(val) => Some(val),
            Error::Serialize(val) => Some(val),
            Error::Deserialize(val) => Some(val),
        }
    }
}

impl<S: std::error::Error> From<ciborium::de::Error<std::io::Error>> for Error<S> {
    fn from(value: ciborium::de::Error<std::io::Error>) -> Self {
        Error::Deserialize(value)
    }
}

impl<S: std::error::Error> From<ciborium::ser::Error<std::io::Error>> for Error<S> {
    fn from(value: ciborium::ser::Error<std::io::Error>) -> Self {
        Error::Serialize(value)
    }
}

impl<S: std::error::Error> From<crypto::Error> for Error<S> {
    fn from(value: crypto::Error) -> Self {
        Error::Signer(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub public_key: PublicKey,
    pub handle: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateResult {
    #[serde(with = "bytes")]
    pub encrypted_private_key: Vec<u8>,
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateAndImportResult {
    #[serde(with = "bytes")]
    pub encrypted_private_key: Vec<u8>,
    pub public_key: PublicKey,
    pub handle: usize,
}

pub struct EncryptedSigner<E> {
    keychain: Keychain,
    enc: E,
}

impl<E: EncryptionBackend> EncryptedSigner<E> {
    pub fn new(enc: E) -> Self {
        Self {
            keychain: Keychain::new(),
            enc,
        }
    }

    pub fn try_sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, Error<E::Error>> {
        Ok(self.keychain.try_sign(handle, msg)?)
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error<E::Error>> {
        Ok(self.keychain.public_key(handle)?)
    }

    pub fn try_prove(&self, handle: usize) -> Result<Signature, Error<E::Error>> {
        Ok(self.keychain.try_prove(handle)?)
    }

    async fn decrypt(&self, src: &[u8]) -> Result<PrivateKey, Error<E::Error>> {
        match self.enc.decrypt(src).await {
            Ok(decrypted) => Ok(PrivateKey::try_from_cbor(&decrypted[..])?),
            Err(err) => return Err(Error::Encryption(err)),
        }
    }

    async fn encrypt(&self, pk: &PrivateKey) -> Result<Vec<u8>, Error<E::Error>> {
        let buf = pk.try_into_cbor()?;
        match self.enc.encrypt(&buf).await {
            Ok(value) => Ok(value),
            Err(err) => Err(Error::Encryption(err)),
        }
    }

    pub async fn import(&mut self, key_data: &[u8]) -> Result<ImportResult, Error<E::Error>> {
        let pk = self.decrypt(key_data).await?;
        let p = pk.public_key();
        Ok(ImportResult {
            public_key: p,
            handle: self.keychain.import(pk),
        })
    }

    pub async fn import_unencrypted(
        &mut self,
        pk: PrivateKey,
    ) -> Result<GenerateAndImportResult, Error<E::Error>> {
        let p = pk.public_key();
        let encrypted = self.encrypt(&pk).await?;
        Ok(GenerateAndImportResult {
            encrypted_private_key: encrypted,
            public_key: p,
            handle: self.keychain.import(pk),
        })
    }

    pub async fn generate<R: CryptoRngCore>(
        &self,
        t: KeyType,
        r: &mut R,
    ) -> Result<GenerateResult, Error<E::Error>> {
        let pk = PrivateKey::generate(t, r)?;
        let p = pk.public_key();
        let encrypted = self.encrypt(&pk).await?;
        Ok(GenerateResult {
            encrypted_private_key: encrypted,
            public_key: p,
        })
    }

    pub async fn generate_and_import<R: CryptoRngCore>(
        &mut self,
        t: KeyType,
        r: &mut R,
    ) -> Result<GenerateAndImportResult, Error<E::Error>> {
        let pk = PrivateKey::generate(t, r)?;
        let p = pk.public_key();
        let encrypted = self.encrypt(&pk).await?;
        Ok(GenerateAndImportResult {
            encrypted_private_key: encrypted,
            public_key: p,
            handle: self.keychain.import(pk),
        })
    }

    pub async fn try_sign_with(
        &self,
        key_data: &[u8],
        msg: &[u8],
    ) -> Result<Signature, Error<E::Error>> {
        Ok(self.decrypt(key_data).await?.try_sign(msg)?)
    }

    pub async fn public_key_from(&self, key_data: &[u8]) -> Result<PublicKey, Error<E::Error>> {
        Ok(self.decrypt(key_data).await?.public_key())
    }
}

impl<E> From<E> for EncryptedSigner<E>
where
    E: EncryptionBackend,
{
    fn from(value: E) -> Self {
        Self::new(value)
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
    use crate::crypto::{Blake2b256, PublicKey, Signature};
    use crate::macros::unwrap_as;
    use crate::{EncryptedSigner, EncryptionBackend, EncryptionBackendFactory, KeyType};
    use blake2::Digest;
    use serde::{Deserialize, Serialize};
    use signature::{DigestVerifier, Verifier};

    pub(crate) struct PassthroughFactory;

    impl EncryptionBackendFactory for PassthroughFactory {
        type Output = Passthrough;
        type Credentials = DummyCredentials;
        fn try_new(&self, _cred: Self::Credentials) -> Result<Self::Output, DummyErr> {
            Ok(Passthrough)
        }
    }

    #[derive(Debug)]
    pub(crate) struct Passthrough;
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct DummyCredentials {}
    #[derive(Debug)]
    pub(crate) struct DummyErr;

    impl std::fmt::Display for DummyErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("dummy")
        }
    }

    impl std::error::Error for DummyErr {}

    impl EncryptionBackend for Passthrough {
        type Error = DummyErr;

        async fn encrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::from(src))
        }

        async fn decrypt(&self, src: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::from(src))
        }
    }

    #[tokio::test]
    async fn signer_secp256k1() {
        let signer = EncryptedSigner::new(Passthrough);
        let res = signer
            .generate(KeyType::Secp256k1, &mut rand_core::OsRng)
            .await
            .unwrap();

        let data = b"text";
        let sig = unwrap_as!(
            signer
                .try_sign_with(&res.encrypted_private_key, data)
                .await
                .unwrap(),
            Signature::Secp256k1
        );

        let mut digest = Blake2b256::new();
        digest.update(data);

        unwrap_as!(res.public_key, PublicKey::Secp256k1)
            .verify_digest(digest, &*sig)
            .unwrap();
    }

    #[tokio::test]
    async fn signer_nist_p256() {
        let signer = EncryptedSigner::new(Passthrough);
        let res = signer
            .generate(KeyType::NistP256, &mut rand_core::OsRng)
            .await
            .unwrap();

        let data = b"text";
        let sig = unwrap_as!(
            signer
                .try_sign_with(&res.encrypted_private_key, data)
                .await
                .unwrap(),
            Signature::NistP256
        );

        let mut digest = Blake2b256::new();
        digest.update(data);

        unwrap_as!(res.public_key, PublicKey::NistP256)
            .verify_digest(digest, &*sig)
            .unwrap();
    }

    #[tokio::test]
    async fn signer_ed25519() {
        let signer = EncryptedSigner::new(Passthrough);
        let res = signer
            .generate(KeyType::Ed25519, &mut rand_core::OsRng)
            .await
            .unwrap();

        let data = b"text";
        let sig = unwrap_as!(
            signer
                .try_sign_with(&res.encrypted_private_key, data)
                .await
                .unwrap(),
            Signature::Ed25519
        );

        let digest = Blake2b256::digest(data);

        unwrap_as!(res.public_key, PublicKey::Ed25519)
            .verify(&digest, &sig)
            .unwrap();
    }
}
