use crate::crypto::{
    helper, Blake2b256, CryptoRngCore, Deserialize, Digest, DigestSigner, Error as CryptoError,
    KeyPair, NistP256, PublicKey as CryptoPublicKey, Random, Secp256k1, Serialize,
    Signature as CryptoSignature,
};
use generic_array::typenum::Unsigned;

#[derive(Debug, Clone)]
pub struct Signature<C>(C);

impl<C> core::ops::Deref for Signature<C> {
    type Target = C;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for Signature<ecdsa::Signature<Secp256k1>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl Serialize for Signature<ecdsa::Signature<NistP256>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Signature<ecdsa::Signature<Secp256k1>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<
            { ecdsa::SignatureSize::<Secp256k1>::USIZE },
        >::new())?;
        match ecdsa::Signature::from_bytes(&bytes.into()) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl<'de> Deserialize<'de> for Signature<ecdsa::Signature<NistP256>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<
            { ecdsa::SignatureSize::<NistP256>::USIZE },
        >::new())?;
        match ecdsa::Signature::from_bytes(&bytes.into()) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl From<ecdsa::Signature<Secp256k1>> for Signature<ecdsa::Signature<Secp256k1>> {
    fn from(value: ecdsa::Signature<Secp256k1>) -> Self {
        Signature(value)
    }
}

impl From<ecdsa::Signature<NistP256>> for Signature<ecdsa::Signature<NistP256>> {
    fn from(value: ecdsa::Signature<NistP256>) -> Self {
        Signature(value)
    }
}

#[derive(Debug, Clone)]
pub struct SigningKey<C>(pub(crate) C);

impl Random for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    type Error = ();
    fn random<R: CryptoRngCore>(r: &mut R) -> Result<Self, Self::Error> {
        Ok(SigningKey(ecdsa::SigningKey::random(r)))
    }
}

impl Random for SigningKey<ecdsa::SigningKey<NistP256>> {
    type Error = ();
    fn random<R: CryptoRngCore>(r: &mut R) -> Result<Self, Self::Error> {
        Ok(SigningKey(ecdsa::SigningKey::random(r)))
    }
}

impl From<ecdsa::SigningKey<Secp256k1>> for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    fn from(value: ecdsa::SigningKey<Secp256k1>) -> Self {
        SigningKey(value)
    }
}

impl From<ecdsa::SigningKey<NistP256>> for SigningKey<ecdsa::SigningKey<NistP256>> {
    fn from(value: ecdsa::SigningKey<NistP256>) -> Self {
        SigningKey(value)
    }
}

impl<C> core::ops::Deref for SigningKey<C> {
    type Target = C;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl Serialize for SigningKey<ecdsa::SigningKey<NistP256>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> Deserialize<'de> for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<
            { elliptic_curve::FieldBytesSize::<Secp256k1>::USIZE },
        >::new())?;
        match ecdsa::SigningKey::from_bytes(&bytes.into()) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl<'de> Deserialize<'de> for SigningKey<ecdsa::SigningKey<NistP256>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<
            { elliptic_curve::FieldBytesSize::<NistP256>::USIZE },
        >::new())?;
        match ecdsa::SigningKey::from_bytes(&bytes.into()) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl KeyPair for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    fn public_key(&self) -> CryptoPublicKey {
        CryptoPublicKey::Secp256k1(VerifyingKey(self.verifying_key().clone()))
    }
    fn try_sign(&self, msg: &[u8]) -> Result<CryptoSignature, CryptoError> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(CryptoSignature::Secp256k1(Signature(
            self.0.try_sign_digest(d)?,
        )))
    }
}

impl KeyPair for SigningKey<ecdsa::SigningKey<NistP256>> {
    fn public_key(&self) -> CryptoPublicKey {
        CryptoPublicKey::NistP256(VerifyingKey(self.verifying_key().clone()))
    }
    fn try_sign(&self, msg: &[u8]) -> Result<CryptoSignature, CryptoError> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(CryptoSignature::NistP256(Signature(
            self.0.try_sign_digest(d)?,
        )))
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKey<C>(pub(crate) C);

impl<C> core::ops::Deref for VerifyingKey<C> {
    type Target = C;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for VerifyingKey<ecdsa::VerifyingKey<Secp256k1>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_sec1_bytes())
    }
}

impl Serialize for VerifyingKey<ecdsa::VerifyingKey<NistP256>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_sec1_bytes())
    }
}

impl<'de> Deserialize<'de> for VerifyingKey<ecdsa::VerifyingKey<Secp256k1>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<
            { elliptic_curve::sec1::CompressedPointSize::<Secp256k1>::USIZE },
        >::new())?;
        match ecdsa::VerifyingKey::from_sec1_bytes(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl<'de> Deserialize<'de> for VerifyingKey<ecdsa::VerifyingKey<NistP256>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(helper::ByteArrayVisitor::<
            { elliptic_curve::sec1::CompressedPointSize::<NistP256>::USIZE },
        >::new())?;
        match ecdsa::VerifyingKey::from_sec1_bytes(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl From<ecdsa::VerifyingKey<Secp256k1>> for VerifyingKey<ecdsa::VerifyingKey<Secp256k1>> {
    fn from(value: ecdsa::VerifyingKey<Secp256k1>) -> Self {
        VerifyingKey(value)
    }
}

impl From<ecdsa::VerifyingKey<NistP256>> for VerifyingKey<ecdsa::VerifyingKey<NistP256>> {
    fn from(value: ecdsa::VerifyingKey<NistP256>) -> Self {
        VerifyingKey(value)
    }
}
