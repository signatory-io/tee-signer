use blake2::{digest, Blake2b, Digest};
use blst::min_pk;
use ecdsa::hazmat::SignPrimitive;
use elliptic_curve::{generic_array, scalar::Scalar, CurveArithmetic, FieldBytes, PrimeCurve};
use k256::Secp256k1;
use p256::NistP256;
use serde::{Deserialize, Serialize};
use signature::{DigestSigner, Signer, Verifier};
use std::fmt::Debug;
use zeroize::ZeroizeOnDrop;

#[derive(Serialize, Deserialize, Debug)]
pub enum KeyType {
    Secp256k1,
    NistP256,
    Ed25519,
    BLS,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Signature {
    Secp256k1(ecdsa::Signature<Secp256k1>),
    NistP256(ecdsa::Signature<NistP256>),
    Ed25519(ed25519::Signature),
    BLS(BLSSignature),
}

#[derive(Debug)]
pub struct BLSSignature(min_pk::Signature);

impl core::ops::Deref for BLSSignature {
    type Target = min_pk::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// use compressed form for serialization
impl Serialize for BLSSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.compress(), serializer)
    }
}

impl<'de> Deserialize<'de> for BLSSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes: [u8; 48] = [0; 48];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        match min_pk::Signature::uncompress(&bytes) {
            Ok(val) => Ok(BLSSignature(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

pub trait KeyPair: Debug {
    fn public_key(&self) -> PublicKey;
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error>;
}

#[derive(Debug, ZeroizeOnDrop)]
pub struct ECDSASigningKey<C>(ecdsa::SigningKey<C>)
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<Scalar<C>>> + SignPrimitive<C>,
    ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>;

impl<C> Serialize for ECDSASigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<Scalar<C>>> + SignPrimitive<C>,
    ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.to_bytes(), serializer)
    }
}

impl<'de, C> Deserialize<'de> for ECDSASigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<Scalar<C>>> + SignPrimitive<C>,
    ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes = FieldBytes::<C>::default();
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        match ecdsa::SigningKey::from_bytes(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl<C> core::ops::Deref for ECDSASigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<Scalar<C>>> + SignPrimitive<C>,
    ecdsa::SignatureSize<C>: generic_array::ArrayLength<u8>,
{
    type Target = ecdsa::SigningKey<C>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) type Blake2b256 = Blake2b<digest::consts::U32>;

const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";

#[derive(Debug)]
pub struct BLSPublicKey(min_pk::PublicKey);

impl Verifier<BLSSignature> for BLSPublicKey {
    fn verify(&self, msg: &[u8], signature: &BLSSignature) -> Result<(), signature::Error> {
        let aug = self.to_bytes();
        match signature.0.verify(true, msg, BLS_DST, &aug, self, true) {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => {
                let b: Box<dyn std::error::Error + Send + Sync> = Box::new(Error::BLS(err));
                Err(b.into())
            }
        }
    }
}

impl core::ops::Deref for BLSPublicKey {
    type Target = min_pk::PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// use compressed form for serialization
impl Serialize for BLSPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.compress(), serializer)
    }
}

impl<'de> Deserialize<'de> for BLSPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes: [u8; 48] = [0; 48];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        match min_pk::PublicKey::uncompress(&bytes) {
            Ok(val) => Ok(BLSPublicKey(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

impl KeyPair for ECDSASigningKey<Secp256k1> {
    fn public_key(&self) -> PublicKey {
        PublicKey::Secp256k1(self.verifying_key().clone())
    }
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(Signature::Secp256k1(self.0.try_sign_digest(d)?))
    }
}

impl KeyPair for ECDSASigningKey<NistP256> {
    fn public_key(&self) -> PublicKey {
        PublicKey::NistP256(self.verifying_key().clone())
    }
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(Signature::NistP256(self.0.try_sign_digest(d)?))
    }
}

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

impl KeyPair for min_pk::SecretKey {
    fn public_key(&self) -> PublicKey {
        PublicKey::BLS(BLSPublicKey(self.sk_to_pk()))
    }
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let aug = self.sk_to_pk().to_bytes();
        Ok(Signature::BLS(BLSSignature(self.sign(msg, BLS_DST, &aug))))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PrivateKey {
    Secp256k1(ECDSASigningKey<Secp256k1>),
    NistP256(ECDSASigningKey<NistP256>),
    Ed25519(ed25519_dalek::SigningKey),
    BLS(min_pk::SecretKey),
}

impl PrivateKey {
    pub fn generate<R: rand_core::CryptoRngCore>(t: KeyType, r: &mut R) -> Result<Self, Error> {
        match t {
            KeyType::Secp256k1 => Ok(PrivateKey::Secp256k1(ECDSASigningKey(
                ecdsa::SigningKey::random(r),
            ))),
            KeyType::NistP256 => Ok(PrivateKey::NistP256(ECDSASigningKey(
                ecdsa::SigningKey::random(r),
            ))),
            KeyType::Ed25519 => Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(r))),
            KeyType::BLS => {
                let mut ikm: [u8; 32] = [0; 32];
                r.fill_bytes(&mut ikm);
                Ok(PrivateKey::BLS(min_pk::SecretKey::key_gen(&ikm, &[])?))
            }
        }
    }
}

impl KeyPair for PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        match self {
            PrivateKey::Secp256k1(val) => val.try_sign(msg),
            PrivateKey::NistP256(val) => val.try_sign(msg),
            PrivateKey::Ed25519(val) => KeyPair::try_sign(val, msg),
            PrivateKey::BLS(val) => val.try_sign(msg),
        }
    }

    fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Secp256k1(val) => val.public_key(),
            PrivateKey::NistP256(val) => val.public_key(),
            PrivateKey::Ed25519(val) => val.public_key(),
            PrivateKey::BLS(val) => val.public_key(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PublicKey {
    Secp256k1(ecdsa::VerifyingKey<Secp256k1>),
    NistP256(ecdsa::VerifyingKey<NistP256>),
    Ed25519(ed25519_dalek::VerifyingKey),
    BLS(BLSPublicKey),
}

#[derive(Debug)]
pub enum Error {
    InvalidHandle,
    Signature(signature::Error),
    BLS(blst::BLST_ERROR),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidHandle => f.write_str("invalid handle"),
            Error::Signature(_) => f.write_str("signature error"),
            Error::BLS(v) => write!(f, "BLST error: {}", *v as u8),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Signature(e) => e.source(),
            _ => None,
        }
    }
}

impl From<signature::Error> for Error {
    fn from(value: signature::Error) -> Self {
        Error::Signature(value)
    }
}

impl From<blst::BLST_ERROR> for Error {
    fn from(value: blst::BLST_ERROR) -> Self {
        Error::BLS(value)
    }
}

#[derive(Debug)]
pub struct Keychain {
    keys: Vec<Box<dyn KeyPair>>,
}

impl Keychain {
    pub fn new() -> Self {
        Keychain { keys: Vec::new() }
    }

    pub fn import(&mut self, src: PrivateKey) -> usize {
        let signer: Box<dyn KeyPair> = match src {
            PrivateKey::Secp256k1(val) => Box::new(val),
            PrivateKey::NistP256(val) => Box::new(val),
            PrivateKey::Ed25519(val) => Box::new(val),
            PrivateKey::BLS(val) => Box::new(val),
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
    use crate::macros::unwrap_as;
    use signature::{DigestVerifier, Verifier};

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
        let pk = PrivateKey::generate(KeyType::BLS, &mut rand_core::OsRng).unwrap();
        let handle = keychain.import(pk);

        let data = b"text";
        let sig = unwrap_as!(keychain.try_sign(handle, data).unwrap(), Signature::BLS);
        let pub_key = unwrap_as!(keychain.public_key(handle).unwrap(), PublicKey::BLS);

        pub_key.verify(data, &sig).unwrap();
    }
}
