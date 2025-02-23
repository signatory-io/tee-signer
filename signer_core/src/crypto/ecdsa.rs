use crate::{
    crypto::{
        Blake2b256, CryptoRngCore, Deserialize, Digest, DigestSigner, KeyPair, Random, Serialize,
    },
    serde_helper,
};
use ecdsa::{hazmat::SignPrimitive, SignatureSize};
use elliptic_curve::{
    ops::Invert,
    point::PointCompression,
    sec1::{CompressedPointSize, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, Scalar,
};
use generic_array::{typenum::Unsigned, ArrayLength};
pub use k256::Secp256k1;
pub use p256::NistP256;
use std::convert::Infallible;
use subtle::CtOption;

#[derive(Debug, Clone)]
pub struct Signature<C>(ecdsa::Signature<C>)
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>;

impl<C> core::ops::Deref for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Target = ecdsa::Signature<C>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> Serialize for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de, C> Deserialize<'de> for Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer
            .deserialize_bytes(serde_helper::BytesVisitor::new(SignatureSize::<C>::USIZE))?;
        match ecdsa::Signature::from_slice(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningKey<C>(pub(crate) ecdsa::SigningKey<C>)
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>;

impl<C> Random for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Infallible;
    fn random<R: CryptoRngCore>(r: &mut R) -> Result<Self, Self::Error> {
        Ok(SigningKey(ecdsa::SigningKey::random(r)))
    }
}

impl<C> core::ops::Deref for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Target = ecdsa::SigningKey<C>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> Serialize for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de, C> Deserialize<'de> for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer
            .deserialize_bytes(serde_helper::BytesVisitor::new(FieldBytesSize::<C>::USIZE))?;
        match ecdsa::SigningKey::from_slice(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}

impl<C> KeyPair for SigningKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    ecdsa::SigningKey<C>: DigestSigner<Blake2b256, ecdsa::Signature<C>>,
{
    type PublicKey = VerifyingKey<C>;
    type Signature = Signature<C>;
    type Error = signature::Error;

    fn public_key(&self) -> Self::PublicKey {
        VerifyingKey(self.verifying_key().clone())
    }
    fn try_sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
        let mut d = Blake2b256::new();
        d.update(msg);
        Ok(Signature(self.0.try_sign_digest(d)?))
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKey<C>(pub(crate) ecdsa::VerifyingKey<C>)
where
    C: PrimeCurve + CurveArithmetic;

impl<C> core::ops::Deref for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
{
    type Target = ecdsa::VerifyingKey<C>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C> Serialize for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic + PointCompression,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_encoded_point(true).as_bytes())
    }
}

impl<'de, C> Deserialize<'de> for VerifyingKey<C>
where
    C: PrimeCurve + CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(serde_helper::BytesVisitor::new(
            CompressedPointSize::<C>::USIZE,
        ))?;
        match ecdsa::VerifyingKey::from_sec1_bytes(&bytes) {
            Ok(val) => Ok(Self(val)),
            Err(err) => Err(serde::de::Error::custom(err)),
        }
    }
}
