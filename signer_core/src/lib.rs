use crypto::{
    KeyPair, KeyType, Keychain, PrivateKey, ProofOfPossession, PublicKey, Signature, SigningVersion,
};
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
    ) -> impl Future<Output = Result<Self::Output, <Self::Output as EncryptionBackend>::Error>>;
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

    pub fn try_sign(
        &self,
        handle: usize,
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Signature, Error<E::Error>> {
        Ok(self.keychain.try_sign(handle, msg, version)?)
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error<E::Error>> {
        Ok(self.keychain.public_key(handle)?)
    }

    pub fn try_prove(&self, handle: usize) -> Result<ProofOfPossession, Error<E::Error>> {
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
        version: SigningVersion,
    ) -> Result<Signature, Error<E::Error>> {
        Ok(self.decrypt(key_data).await?.try_sign(msg, version)?)
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
                #[allow(unreachable_patterns)]
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
    use crate::crypto::{Blake2b256, PublicKey, Signature, SigningVersion};
    use crate::macros::unwrap_as;
    use crate::{EncryptedSigner, EncryptionBackend, EncryptionBackendFactory, KeyType};
    use blake2::Digest;
    use serde::{Deserialize, Serialize};
    use signature::{DigestVerifier, Verifier};

    pub(crate) struct PassthroughFactory;

    impl EncryptionBackendFactory for PassthroughFactory {
        type Output = Passthrough;
        type Credentials = DummyCredentials;
        fn try_new(
            &self,
            _cred: Self::Credentials,
        ) -> impl std::future::Future<Output = Result<Self::Output, DummyErr>> {
            async { Ok(Passthrough) }
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
                .try_sign_with(&res.encrypted_private_key, data, SigningVersion::Latest)
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
                .try_sign_with(&res.encrypted_private_key, data, SigningVersion::Latest)
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
                .try_sign_with(&res.encrypted_private_key, data, SigningVersion::Latest)
                .await
                .unwrap(),
            Signature::Ed25519
        );

        let digest = Blake2b256::digest(data);

        unwrap_as!(res.public_key, PublicKey::Ed25519)
            .verify(&digest, &sig)
            .unwrap();
    }

    #[tokio::test]
    async fn signer_bls() {
        use crate::crypto::Verifier;

        let signer = EncryptedSigner::new(Passthrough);
        let res: crate::GenerateResult = signer
            .generate(KeyType::Bls, &mut rand_core::OsRng)
            .await
            .unwrap();

        let data = b"test";
        {
            let sig = unwrap_as!(
                signer
                    .try_sign_with(&res.encrypted_private_key, data, SigningVersion::V2)
                    .await
                    .unwrap(),
                Signature::Bls
            );

            let pk = unwrap_as!(&res.public_key, PublicKey::Bls);
            assert!(pk.verify(data, &sig, SigningVersion::V2).is_ok());
        }
        {
            let sig = unwrap_as!(
                signer
                    .try_sign_with(&res.encrypted_private_key, data, SigningVersion::V1)
                    .await
                    .unwrap(),
                Signature::Bls
            );

            let pk = unwrap_as!(&res.public_key, PublicKey::Bls);
            assert!(pk.verify(data, &sig, SigningVersion::V1).is_ok());
        }
    }

    #[tokio::test]
    async fn signer_import_encrypted() {
        let mut signer = EncryptedSigner::new(Passthrough);

        // First generate a key
        let gen_res = signer
            .generate(KeyType::Secp256k1, &mut rand_core::OsRng)
            .await
            .unwrap();

        // Import it
        let import_res = signer.import(&gen_res.encrypted_private_key).await.unwrap();

        // Sign with the imported handle
        let data = b"test";
        let sig = unwrap_as!(
            signer
                .try_sign(import_res.handle, data, SigningVersion::Latest)
                .unwrap(),
            Signature::Secp256k1
        );

        // Verify
        let mut digest = Blake2b256::new();
        digest.update(data);
        unwrap_as!(import_res.public_key, PublicKey::Secp256k1)
            .verify_digest(digest, &*sig)
            .unwrap();
    }

    #[tokio::test]
    async fn signer_import_unencrypted() {
        use crate::crypto::{KeyPair, PrivateKey};

        let mut signer = EncryptedSigner::new(Passthrough);

        let key = PrivateKey::generate(KeyType::NistP256, &mut rand_core::OsRng).unwrap();
        let expected_pk = key.public_key();

        let res = signer.import_unencrypted(key).await.unwrap();

        // Verify we can sign
        let data = b"message";
        let sig = unwrap_as!(
            signer
                .try_sign(res.handle, data, SigningVersion::Latest)
                .unwrap(),
            Signature::NistP256
        );

        let mut digest = Blake2b256::new();
        digest.update(data);
        unwrap_as!(expected_pk, PublicKey::NistP256)
            .verify_digest(digest, &*sig)
            .unwrap();
    }

    #[tokio::test]
    async fn signer_generate_and_import() {
        let mut signer = EncryptedSigner::new(Passthrough);

        let res = signer
            .generate_and_import(KeyType::Ed25519, &mut rand_core::OsRng)
            .await
            .unwrap();

        // Sign using handle
        let data = b"data";
        let sig = unwrap_as!(
            signer
                .try_sign(res.handle, data, SigningVersion::Latest)
                .unwrap(),
            Signature::Ed25519
        );

        // Verify
        let digest = Blake2b256::digest(data);
        unwrap_as!(res.public_key, PublicKey::Ed25519)
            .verify(&digest, &sig)
            .unwrap();
    }

    #[tokio::test]
    async fn signer_public_key_operations() {
        let mut signer = EncryptedSigner::new(Passthrough);

        let res = signer
            .generate_and_import(KeyType::Secp256k1, &mut rand_core::OsRng)
            .await
            .unwrap();

        // Test public_key by handle
        let pk = signer.public_key(res.handle).unwrap();
        assert!(matches!(pk, PublicKey::Secp256k1(_)));

        // Test public_key_from encrypted key
        let pk_from = signer
            .public_key_from(&res.encrypted_private_key)
            .await
            .unwrap();
        assert!(matches!(pk_from, PublicKey::Secp256k1(_)));
    }

    #[tokio::test]
    async fn signer_proof_of_possession() {
        use crate::crypto::{ProofOfPossession, ProofVerifier};

        let mut signer = EncryptedSigner::new(Passthrough);

        let res = signer
            .generate_and_import(KeyType::Bls, &mut rand_core::OsRng)
            .await
            .unwrap();

        // Generate proof
        let proof = signer.try_prove(res.handle).unwrap();
        let pop = unwrap_as!(proof, ProofOfPossession::Bls);

        // Verify proof
        let pk = unwrap_as!(res.public_key, PublicKey::Bls);
        pk.verify_pop(&pop).unwrap();
    }

    #[tokio::test]
    async fn signer_invalid_handle() {
        let signer = EncryptedSigner::new(Passthrough);

        // Try to use non-existent handle
        let result = signer.try_sign(999, b"data", SigningVersion::Latest);
        assert!(result.is_err());

        let result = signer.public_key(999);
        assert!(result.is_err());

        let result = signer.try_prove(999);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signer_multiple_keys() {
        let mut signer = EncryptedSigner::new(Passthrough);

        // Import multiple keys
        let res1 = signer
            .generate_and_import(KeyType::Secp256k1, &mut rand_core::OsRng)
            .await
            .unwrap();

        let res2 = signer
            .generate_and_import(KeyType::Ed25519, &mut rand_core::OsRng)
            .await
            .unwrap();

        let res3 = signer
            .generate_and_import(KeyType::Bls, &mut rand_core::OsRng)
            .await
            .unwrap();

        // Verify all handles work independently
        let data = b"test";

        let sig1 = signer
            .try_sign(res1.handle, data, SigningVersion::Latest)
            .unwrap();
        assert!(matches!(sig1, Signature::Secp256k1(_)));

        let sig2 = signer
            .try_sign(res2.handle, data, SigningVersion::Latest)
            .unwrap();
        assert!(matches!(sig2, Signature::Ed25519(_)));

        let sig3 = signer
            .try_sign(res3.handle, data, SigningVersion::V2)
            .unwrap();
        assert!(matches!(sig3, Signature::Bls(_)));
    }
}
