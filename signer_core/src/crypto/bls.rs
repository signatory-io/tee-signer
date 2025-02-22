use crate::crypto::{helper, CryptoRngCore, Deserialize, KeyPair, Random, Serialize, Verifier};
use blst::min_pk;
pub use blst::BLST_ERROR;
use std::convert::Infallible;

const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";

#[derive(Debug, Clone)]
pub struct Signature(min_pk::Signature);

impl core::ops::Deref for Signature {
    type Target = min_pk::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// use compressed form for serialization
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.compress())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<96>::new())?;
        match min_pk::Signature::uncompress(&bytes) {
            Ok(val) => Ok(Signature(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug)]
pub struct PublicKey(min_pk::PublicKey);

impl core::ops::Deref for PublicKey {
    type Target = min_pk::PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Verifier<Signature> for PublicKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let aug = self.to_bytes();
        match signature.0.verify(true, msg, BLS_DST, &aug, self, true) {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => {
                let b: Box<dyn std::error::Error + Send + Sync> = Box::new(Error::from(err));
                Err(b.into())
            }
        }
    }
}

// use compressed form for serialization
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.compress())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<48>::new())?;
        match min_pk::PublicKey::uncompress(&bytes) {
            Ok(val) => Ok(PublicKey(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningKey(pub(crate) min_pk::SecretKey);

impl core::ops::Deref for SigningKey {
    type Target = min_pk::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Random for SigningKey {
    type Error = Error;
    fn random<R: CryptoRngCore>(r: &mut R) -> Result<Self, Error> {
        let mut ikm: [u8; 32] = [0; 32];
        r.fill_bytes(&mut ikm);
        Ok(SigningKey(min_pk::SecretKey::key_gen(&ikm, &[])?))
    }
}

impl KeyPair for SigningKey {
    type PublicKey = PublicKey;
    type Error = Infallible;
    type Signature = Signature;

    fn public_key(&self) -> Self::PublicKey {
        PublicKey(self.sk_to_pk())
    }

    fn try_sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
        let aug = self.sk_to_pk().to_bytes();
        Ok(Signature(self.sign(msg, BLS_DST, &aug)))
    }
}

impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.serialize())
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<32>::new())?;
        match min_pk::SecretKey::deserialize(&bytes) {
            Ok(val) => Ok(SigningKey(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug)]
pub struct Error(pub BLST_ERROR);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            BLST_ERROR::BLST_SUCCESS => f.write_str("Success"),
            BLST_ERROR::BLST_BAD_ENCODING => f.write_str("Bad encoding"),
            BLST_ERROR::BLST_POINT_NOT_ON_CURVE => f.write_str("Point not on curve"),
            BLST_ERROR::BLST_POINT_NOT_IN_GROUP => f.write_str("Point not in group"),
            BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => f.write_str("Aggregate type mismatch"),
            BLST_ERROR::BLST_VERIFY_FAIL => f.write_str("Verify fail"),
            BLST_ERROR::BLST_PK_IS_INFINITY => f.write_str("PK is infinity"),
            BLST_ERROR::BLST_BAD_SCALAR => f.write_str("Bad scalar"),
        }
    }
}

impl From<BLST_ERROR> for Error {
    fn from(value: BLST_ERROR) -> Self {
        Error(value)
    }
}

impl std::error::Error for Error {}
