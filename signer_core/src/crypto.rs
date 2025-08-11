use blake2::{digest, Blake2b, Digest};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
pub use signature::Error as SignatureError;
use signature::{DigestSigner, Signer};
use std::fmt::Debug;

pub mod bls;
pub mod ecdsa;

use ecdsa::NistP256;
use ecdsa::Secp256k1;

pub trait KeyPair {
    type PublicKey;
    type Signature;
    type Error;

    fn public_key(&self) -> Self::PublicKey;
    fn try_sign(&self, msg: &[u8], version: SigningVersion)
        -> Result<Self::Signature, Self::Error>;
}

pub trait Random: Sized {
    type Error;

    fn random<R: CryptoRngCore>(rng: &mut R) -> Result<Self, Self::Error>;
}

pub trait PossessionProver {
    type Proof;
    type Error;

    fn try_prove(&self) -> Result<Self::Proof, Self::Error>;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KeyType {
    Secp256k1,
    NistP256,
    Ed25519,
    Bls,
}

#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum SigningVersion {
    /// Version 1: Standard signing algorithms
    V0 = 0,
    /// Version 1: Enhanced signing with additional security features
    V1,
    /// Version 2: Latest signing algorithms with improved performance
    V2,
    /// Latest version
    Latest = 255,
}

// impl TryFrom<u8> for SigningVersion {
//     type Error = Error;
//     fn try_from(version: u8) -> Result<Self, Self::Error> {
//         match version {
//             0 => Ok(SigningVersion::V0),
//             1 => Ok(SigningVersion::V1),
//             2 => Ok(SigningVersion::V2),
//             _ => Err(Error::InvalidSigningVersion),
//         }
//     }
// }

// impl TryFrom<Option<u8>> for SigningVersion {
//     type Error = Error;
//     fn try_from(version: Option<u8>) -> Result<Self, Self::Error> {
//         match version {
//             Some(0) => Ok(SigningVersion::V0),
//             Some(1) => Ok(SigningVersion::V1),
//             Some(2) => Ok(SigningVersion::V2),
//             None => Ok(SigningVersion::Latest),
//             _ => Err(Error::InvalidSigningVersion),
//         }
//     }
// }

// impl From<SigningVersion> for u8 {
//     fn from(version: SigningVersion) -> Self {
//         match version {
//             SigningVersion::V0 => 0,
//             SigningVersion::V1 => 1,
//             SigningVersion::V2 => 2,
//             SigningVersion::Latest => 2,
//         }
//     }
// }

impl Default for SigningVersion {
    fn default() -> Self {
        SigningVersion::Latest
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Signature {
    Secp256k1(ecdsa::Signature<Secp256k1>),
    NistP256(ecdsa::Signature<NistP256>),
    Ed25519(ed25519::Signature),
    Bls(bls::Signature),
}

impl From<ecdsa::Signature<Secp256k1>> for Signature {
    fn from(value: ecdsa::Signature<Secp256k1>) -> Self {
        Signature::Secp256k1(value)
    }
}

impl From<ecdsa::Signature<NistP256>> for Signature {
    fn from(value: ecdsa::Signature<NistP256>) -> Self {
        Signature::NistP256(value)
    }
}

impl From<ed25519::Signature> for Signature {
    fn from(value: ed25519::Signature) -> Self {
        Signature::Ed25519(value)
    }
}

impl From<bls::Signature> for Signature {
    fn from(value: bls::Signature) -> Self {
        Signature::Bls(value)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofOfPossession {
    Bls(bls::ProofOfPossession),
}

impl From<bls::ProofOfPossession> for ProofOfPossession {
    fn from(value: bls::ProofOfPossession) -> Self {
        ProofOfPossession::Bls(value)
    }
}

pub trait Verifier<S> {
    fn verify(&self, msg: &[u8], signature: &S, version: SigningVersion) -> Result<(), Error>;
}

pub trait ProofVerifier<S> {
    fn verify_pop(&self, proof: &S) -> Result<(), Error>;
}

pub(crate) type Blake2b256 = Blake2b<digest::consts::U32>;

impl KeyPair for ed25519_dalek::SigningKey {
    type PublicKey = ed25519_dalek::VerifyingKey;
    type Signature = ed25519::Signature;
    type Error = ed25519::signature::Error;

    fn public_key(&self) -> Self::PublicKey {
        self.verifying_key().clone()
    }
    fn try_sign(
        &self,
        msg: &[u8],
        _version: SigningVersion,
    ) -> Result<Self::Signature, Self::Error> {
        // Tezos uses Blake2b pre-hashing in conjunction with regular Ed25519/SHA512
        let d = Blake2b256::digest(msg);
        Ok(Signer::try_sign(self, &d)?)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PrivateKey {
    Secp256k1(ecdsa::SigningKey<Secp256k1>),
    NistP256(ecdsa::SigningKey<NistP256>),
    Ed25519(ed25519_dalek::SigningKey),
    Bls(bls::SigningKey),
}

impl PrivateKey {
    pub fn generate<R: rand_core::CryptoRngCore>(t: KeyType, r: &mut R) -> Result<Self, Error> {
        match t {
            KeyType::Secp256k1 => Ok(ecdsa::SigningKey::<Secp256k1>::random(r).unwrap().into()),
            KeyType::NistP256 => Ok(ecdsa::SigningKey::<NistP256>::random(r).unwrap().into()),
            KeyType::Ed25519 => Ok(ed25519_dalek::SigningKey::generate(r).into()),
            KeyType::Bls => bls::SigningKey::random(r)
                .map(Into::into)
                .map_err(Into::into),
        }
    }
}

impl From<ecdsa::SigningKey<Secp256k1>> for PrivateKey {
    fn from(value: ecdsa::SigningKey<Secp256k1>) -> Self {
        PrivateKey::Secp256k1(value)
    }
}

impl From<ecdsa::SigningKey<NistP256>> for PrivateKey {
    fn from(value: ecdsa::SigningKey<NistP256>) -> Self {
        PrivateKey::NistP256(value)
    }
}

impl From<ed25519_dalek::SigningKey> for PrivateKey {
    fn from(value: ed25519_dalek::SigningKey) -> Self {
        PrivateKey::Ed25519(value)
    }
}

impl From<bls::SigningKey> for PrivateKey {
    fn from(value: bls::SigningKey) -> Self {
        PrivateKey::Bls(value)
    }
}

impl KeyPair for PrivateKey {
    type PublicKey = PublicKey;
    type Signature = Signature;
    type Error = Error;

    fn try_sign(
        &self,
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Self::Signature, Self::Error> {
        match self {
            PrivateKey::Secp256k1(val) => val
                .try_sign(msg, version)
                .map(Into::into)
                .map_err(Into::into),
            PrivateKey::NistP256(val) => val
                .try_sign(msg, version)
                .map(Into::into)
                .map_err(Into::into),
            PrivateKey::Ed25519(val) => KeyPair::try_sign(val, msg, version)
                .map(Into::into)
                .map_err(Into::into),
            PrivateKey::Bls(val) => Ok(val.try_sign(msg, version).unwrap().into()),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            PrivateKey::Secp256k1(val) => val.public_key().into(),
            PrivateKey::NistP256(val) => val.public_key().into(),
            PrivateKey::Ed25519(val) => val.public_key().into(),
            PrivateKey::Bls(val) => val.public_key().into(),
        }
    }
}

impl PossessionProver for PrivateKey {
    type Proof = ProofOfPossession;
    type Error = Error;

    fn try_prove(&self) -> Result<Self::Proof, Self::Error> {
        match self {
            PrivateKey::Bls(val) => Ok(val.try_prove().unwrap().into()),
            _ => Err(Error::PopUnsupported),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PublicKey {
    Secp256k1(ecdsa::VerifyingKey<Secp256k1>),
    NistP256(ecdsa::VerifyingKey<NistP256>),
    Ed25519(ed25519_dalek::VerifyingKey),
    Bls(bls::PublicKey),
}

impl From<ecdsa::VerifyingKey<Secp256k1>> for PublicKey {
    fn from(value: ecdsa::VerifyingKey<Secp256k1>) -> Self {
        PublicKey::Secp256k1(value)
    }
}

impl From<ecdsa::VerifyingKey<NistP256>> for PublicKey {
    fn from(value: ecdsa::VerifyingKey<NistP256>) -> Self {
        PublicKey::NistP256(value)
    }
}

impl From<ed25519_dalek::VerifyingKey> for PublicKey {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        PublicKey::Ed25519(value)
    }
}

impl From<bls::PublicKey> for PublicKey {
    fn from(value: bls::PublicKey) -> Self {
        PublicKey::Bls(value)
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidHandle,
    Signature(SignatureError),
    Bls(bls::Error),
    PopUnsupported,
    InvalidSigningVersion,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidHandle => f.write_str("invalid handle"),
            Error::Signature(_) => f.write_str("signature error"),
            Error::Bls(_) => f.write_str("BLST error"),
            Error::PopUnsupported => f.write_str("Proof of possession is not supported"),
            Error::InvalidSigningVersion => f.write_str("Invalid signing     version"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Signature(e) => e.source(),
            Error::Bls(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SignatureError> for Error {
    fn from(value: SignatureError) -> Self {
        Error::Signature(value)
    }
}

impl From<bls::Error> for Error {
    fn from(value: bls::Error) -> Self {
        Error::Bls(value)
    }
}

pub struct Keychain {
    keys: Vec<PrivateKey>,
}

impl Keychain {
    pub fn new() -> Self {
        Keychain { keys: Vec::new() }
    }

    pub fn import(&mut self, src: PrivateKey) -> usize {
        self.keys.push(src);
        self.keys.len() - 1
    }

    pub fn try_sign(
        &self,
        handle: usize,
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Signature, Error> {
        match self.keys.get(handle) {
            Some(k) => Ok(k.try_sign(msg, version)?),
            None => Err(Error::InvalidHandle),
        }
    }

    pub fn try_prove(&self, handle: usize) -> Result<ProofOfPossession, Error> {
        match self.keys.get(handle) {
            Some(k) => Ok(k.try_prove()?),
            None => Err(Error::InvalidHandle),
        }
    }

    pub fn public_key(&self, handle: usize) -> Result<PublicKey, Error> {
        match self.keys.get(handle) {
            Some(k) => Ok(k.public_key()),
            None => Err(Error::InvalidHandle),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Blake2b256, Digest, KeyType, Keychain, PrivateKey, PublicKey, Signature, SigningVersion,
    };
    use crate::{
        crypto::{KeyPair, ProofOfPossession, ProofVerifier, Verifier},
        macros::unwrap_as,
        TryFromCBOR, TryIntoCBOR,
    };
    use signature::{DigestVerifier, Verifier as SigVerifier};

    macro_rules! impl_pk_serde_test {
        ($name:ident, $ty:tt) => {
            #[test]
            fn $name() {
                let pk = PrivateKey::generate(KeyType::$ty, &mut rand_core::OsRng).unwrap();
                let ser_pk = pk.try_into_cbor().unwrap();
                let de_pk = PrivateKey::try_from_cbor(&ser_pk).unwrap();
                assert!(matches!(de_pk, PrivateKey::$ty(_)));
            }
        };
    }

    impl_pk_serde_test!(serde_pk_nist_p256, NistP256);
    impl_pk_serde_test!(serde_pk_secp256k1, Secp256k1);
    impl_pk_serde_test!(serde_pk_ed25519, Ed25519);
    impl_pk_serde_test!(serde_pk_bls, Bls);

    macro_rules! impl_pubkey_serde_test {
        ($name:ident, $ty:tt) => {
            #[test]
            fn $name() {
                let pubkey = PrivateKey::generate(KeyType::$ty, &mut rand_core::OsRng)
                    .unwrap()
                    .public_key();
                let ser_pubkey = pubkey.try_into_cbor().unwrap();
                let de_pubkey = PublicKey::try_from_cbor(&ser_pubkey).unwrap();
                assert!(matches!(de_pubkey, PublicKey::$ty(_)));
            }
        };
    }

    impl_pubkey_serde_test!(serde_pubkey_nist_p256, NistP256);
    impl_pubkey_serde_test!(serde_pubkey_secp256k1, Secp256k1);
    impl_pubkey_serde_test!(serde_pubkey_ed25519, Ed25519);
    impl_pubkey_serde_test!(serde_pubkey_bls, Bls);

    macro_rules! impl_sig_serde_test {
        ($name:ident, $ty:tt) => {
            #[test]
            fn $name() {
                let pk = PrivateKey::generate(KeyType::$ty, &mut rand_core::OsRng).unwrap();
                let data = b"text";
                let sig = pk.try_sign(data, SigningVersion::Latest).unwrap();
                let ser_sig = sig.try_into_cbor().unwrap();
                let de_sig = Signature::try_from_cbor(&ser_sig).unwrap();
                assert!(matches!(de_sig, Signature::$ty(_)));
            }
        };
    }

    impl_sig_serde_test!(serde_sig_nist_p256, NistP256);
    impl_sig_serde_test!(serde_sig_secp256k1, Secp256k1);
    impl_sig_serde_test!(serde_sig_ed25519, Ed25519);
    impl_sig_serde_test!(serde_sig_bls, Bls);

    #[test]
    fn keychain_secp256k1() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Secp256k1, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(
            keychain
                .try_sign(handle, data, SigningVersion::Latest)
                .unwrap(),
            Signature::Secp256k1
        );

        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Secp256k1);

        let mut digest = Blake2b256::new();
        digest.update(data);
        pub_key.verify_digest(digest, &*sig).unwrap();
    }

    #[test]
    fn keychain_nist_p256() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::NistP256, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(
            keychain
                .try_sign(handle, data, SigningVersion::Latest)
                .unwrap(),
            Signature::NistP256
        );

        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::NistP256);

        let mut digest = Blake2b256::new();
        digest.update(data);
        pub_key.verify_digest(digest, &*sig).unwrap();
    }

    #[test]
    fn keychain_ed25519() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Ed25519, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(
            keychain
                .try_sign(handle, data, SigningVersion::Latest)
                .unwrap(),
            Signature::Ed25519
        );
        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Ed25519);

        let digest = Blake2b256::digest(data);
        pub_key.verify(&digest, &sig).unwrap();
    }

    #[test]
    fn keychain_bls_v1() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Bls, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(
            keychain.try_sign(handle, data, SigningVersion::V1).unwrap(),
            Signature::Bls
        );
        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Bls);

        pub_key.verify(data, &sig, SigningVersion::V1).unwrap();
    }

    #[test]
    fn keychain_bls_v2() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Bls, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(
            keychain.try_sign(handle, data, SigningVersion::V2).unwrap(),
            Signature::Bls
        );
        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Bls);

        pub_key.verify(data, &sig, SigningVersion::V2).unwrap();
    }

    #[test]
    fn keychain_bls_pop() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Bls, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Bls);
        let sig = unwrap_as!(keychain.try_prove(handle).unwrap(), ProofOfPossession::Bls);

        pub_key.verify_pop(&sig).unwrap();
    }
}
