use crate::crypto::{
    Blake2b256, CryptoRngCore, Deserialize, Digest, DigestSigner, Error as CryptoError, KeyPair,
    NistP256, PublicKey as CryptoPublicKey, Random, Secp256k1, Serialize,
    Signature as CryptoSignature,
};
use elliptic_curve::FieldBytes;

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
        serdect::array::serialize_hex_upper_or_bin(&self.0.to_bytes(), serializer)
    }
}

impl Serialize for SigningKey<ecdsa::SigningKey<NistP256>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut bytes = FieldBytes::<Secp256k1>::default();
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        match ecdsa::SigningKey::from_bytes(&bytes) {
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
        let mut bytes = FieldBytes::<NistP256>::default();
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        match ecdsa::SigningKey::from_bytes(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl KeyPair for SigningKey<ecdsa::SigningKey<Secp256k1>> {
    fn public_key(&self) -> CryptoPublicKey {
        CryptoPublicKey::Secp256k1(self.verifying_key().clone())
    }
    fn try_sign(&self, msg: &[u8]) -> Result<CryptoSignature, CryptoError> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(CryptoSignature::Secp256k1(self.0.try_sign_digest(d)?))
    }
}

impl KeyPair for SigningKey<ecdsa::SigningKey<NistP256>> {
    fn public_key(&self) -> CryptoPublicKey {
        CryptoPublicKey::NistP256(self.verifying_key().clone())
    }
    fn try_sign(&self, msg: &[u8]) -> Result<CryptoSignature, CryptoError> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(CryptoSignature::NistP256(self.0.try_sign_digest(d)?))
    }
}
