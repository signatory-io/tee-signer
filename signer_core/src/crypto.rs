use blake2::{digest, Blake2b, Digest};
use k256::Secp256k1;
use p256::NistP256;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
pub use signature::Error as SignatureError;
use signature::{DigestSigner, Signer, Verifier};
use std::fmt::Debug;

pub mod bls;
pub mod ecdsa;

pub trait KeyPair: Debug {
    fn public_key(&self) -> PublicKey;
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}

pub trait Random: Sized {
    type Error;
    fn random<R: CryptoRngCore>(rng: &mut R) -> Result<Self, Self::Error>;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KeyType {
    Secp256k1,
    NistP256,
    Ed25519,
    Bls,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Signature {
    Secp256k1(::ecdsa::Signature<Secp256k1>),
    NistP256(::ecdsa::Signature<NistP256>),
    Ed25519(ed25519::Signature),
    Bls(bls::Signature),
}

pub(crate) type Blake2b256 = Blake2b<digest::consts::U32>;

impl KeyPair for ed25519_dalek::SigningKey {
    fn public_key(&self) -> PublicKey {
        PublicKey::Ed25519(self.verifying_key().clone())
    }
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        // Tezos uses Blake2b pre-hashing in conjunction with regular Ed25519/SHA512
        let d = Blake2b256::digest(msg);
        Ok(Signature::Ed25519(Signer::try_sign(self, &d)?))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PrivateKey {
    Secp256k1(ecdsa::SigningKey<::ecdsa::SigningKey<Secp256k1>>),
    NistP256(ecdsa::SigningKey<::ecdsa::SigningKey<NistP256>>),
    Ed25519(ed25519_dalek::SigningKey),
    Bls(bls::SigningKey),
}

impl PrivateKey {
    pub fn generate<R: rand_core::CryptoRngCore>(t: KeyType, r: &mut R) -> Result<Self, Error> {
        match t {
            KeyType::Secp256k1 => Ok(PrivateKey::Secp256k1(ecdsa::SigningKey::random(r).unwrap())),
            KeyType::NistP256 => Ok(PrivateKey::NistP256(ecdsa::SigningKey::random(r).unwrap())),
            KeyType::Ed25519 => Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(r))),
            KeyType::Bls => Ok(PrivateKey::Bls(bls::SigningKey::random(r)?)),
        }
    }
}

impl KeyPair for PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        match self {
            PrivateKey::Secp256k1(val) => val.try_sign(msg),
            PrivateKey::NistP256(val) => val.try_sign(msg),
            PrivateKey::Ed25519(val) => KeyPair::try_sign(val, msg),
            PrivateKey::Bls(val) => val.try_sign(msg),
        }
    }

    fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Secp256k1(val) => val.public_key(),
            PrivateKey::NistP256(val) => val.public_key(),
            PrivateKey::Ed25519(val) => val.public_key(),
            PrivateKey::Bls(val) => val.public_key(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PublicKey {
    Secp256k1(::ecdsa::VerifyingKey<Secp256k1>),
    NistP256(::ecdsa::VerifyingKey<NistP256>),
    Ed25519(ed25519_dalek::VerifyingKey),
    Bls(bls::PublicKey),
}

#[derive(Debug)]
pub enum Error {
    InvalidHandle,
    Signature(SignatureError),
    Bls(bls::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidHandle => f.write_str("invalid handle"),
            Error::Signature(_) => f.write_str("signature error"),
            Error::Bls(_) => f.write_str("BLST error"),
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

#[derive(Debug)]
pub struct Keychain {
    keys: Vec<Box<dyn KeyPair + Send>>,
}

impl Keychain {
    pub fn new() -> Self {
        Keychain { keys: Vec::new() }
    }

    pub fn import(&mut self, src: PrivateKey) -> usize {
        let signer: Box<dyn KeyPair + Send> = match src {
            PrivateKey::Secp256k1(val) => Box::new(val),
            PrivateKey::NistP256(val) => Box::new(val),
            PrivateKey::Ed25519(val) => Box::new(val),
            PrivateKey::Bls(val) => Box::new(val),
        };
        self.keys.push(signer);
        self.keys.len() - 1
    }

    pub fn try_sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, Error> {
        match self.keys.get(handle) {
            Some(k) => Ok(k.try_sign(msg)?),
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
    use super::{Blake2b256, Digest, KeyType, Keychain, PrivateKey, PublicKey, Signature};
    use crate::{crypto::KeyPair, macros::unwrap_as, TryFromCBOR, TryIntoCBOR};
    use signature::{DigestVerifier, Verifier};

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
                let sig = pk.try_sign(data).unwrap();
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
            keychain.try_sign(handle, data).unwrap(),
            Signature::Secp256k1
        );

        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Secp256k1);

        let mut digest = Blake2b256::new();
        digest.update(data);
        pub_key.verify_digest(digest, &sig).unwrap();
    }

    #[test]
    fn keychain_nist_p256() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::NistP256, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(
            keychain.try_sign(handle, data).unwrap(),
            Signature::NistP256
        );

        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::NistP256);

        let mut digest = Blake2b256::new();
        digest.update(data);
        pub_key.verify_digest(digest, &sig).unwrap();
    }

    #[test]
    fn keychain_ed25519() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Ed25519, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(keychain.try_sign(handle, data).unwrap(), Signature::Ed25519);
        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Ed25519);

        let digest = Blake2b256::digest(data);
        pub_key.verify(&digest, &sig).unwrap();
    }

    #[test]
    fn keychain_bls() {
        let mut keychain = Keychain::new();
        let pk = PrivateKey::generate(KeyType::Bls, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(keychain.try_sign(handle, data).unwrap(), Signature::Bls);
        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::Bls);

        pub_key.verify(data, &sig).unwrap();
    }
}
