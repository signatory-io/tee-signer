use crate::{
    crypto::{
        self, CryptoRngCore, Deserialize, KeyPair, PossessionProver, ProofVerifier, Random,
        Serialize, SigningVersion, Verifier,
    },
    serde_helper,
};
use blst::min_pk;
pub use blst::BLST_ERROR;
use format_bytes::{format_bytes, DisplayBytes};
use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum Scheme {
    Basic,
    MessageAugmentation,
    ProofOfPossession,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scheme::Basic => "NUL",
            Scheme::MessageAugmentation => "AUG",
            Scheme::ProofOfPossession => "POP",
        })
    }
}

impl DisplayBytes for Scheme {
    fn display_bytes(&self, output: &mut dyn std::io::Write) -> std::io::Result<()> {
        output
            .write(match self {
                Scheme::Basic => b"NUL",
                Scheme::MessageAugmentation => b"AUG",
                Scheme::ProofOfPossession => b"POP",
            })
            .and(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub enum CipherSuite {
    Signature(u8, Scheme),
    ProofOfPossession(u8, Scheme),
}

impl From<CipherSuite> for Vec<u8> {
    fn from(val: CipherSuite) -> Self {
        match val {
            CipherSuite::Signature(g, scheme) => {
                format_bytes!(b"BLS_SIG_BLS12381G{}_XMD:SHA-256_SSWU_RO_{}_", g, scheme)
            }
            CipherSuite::ProofOfPossession(g, scheme) => {
                format_bytes!(b"BLS_POP_BLS12381G{}_XMD:SHA-256_SSWU_RO_{}_", g, scheme)
            }
        }
    }
}

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
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<96>::new())?;
        match min_pk::Signature::uncompress(&bytes) {
            Ok(val) => Ok(Signature(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofOfPossession(min_pk::Signature);

impl core::ops::Deref for ProofOfPossession {
    type Target = min_pk::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// use compressed form for serialization
impl Serialize for ProofOfPossession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.compress())
    }
}

impl<'de> Deserialize<'de> for ProofOfPossession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<96>::new())?;
        match min_pk::Signature::uncompress(&bytes) {
            Ok(val) => Ok(ProofOfPossession(val)),
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
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
        version: SigningVersion,
    ) -> Result<(), crypto::Error> {
        let blst_error = match version {
            SigningVersion::V1 => {
                let aug = self.to_bytes();
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::MessageAugmentation).into();
                Ok(signature
                    .0
                    .verify(true, msg, &cipher_suite, &aug, self, true))
            }
            SigningVersion::V2 | SigningVersion::Latest => {
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::ProofOfPossession).into();
                Ok(signature
                    .0
                    .verify(true, msg, &cipher_suite, &[], self, true))
            }
            _ => Err(crypto::Error::InvalidSigningVersion),
        }?;
        match blst_error {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => Err(Error::from(err).into()),
        }
    }
}

impl ProofVerifier<ProofOfPossession> for PublicKey {
    fn verify_pop(&self, proof: &ProofOfPossession) -> Result<(), crypto::Error> {
        let cipher_suite: Vec<u8> =
            CipherSuite::ProofOfPossession(2, Scheme::ProofOfPossession).into();
        match proof
            .0
            .verify(true, &self.to_bytes(), &cipher_suite, &[], self, true)
        {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => Err(Error::from(err).into()),
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
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<48>::new())?;
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
    type Error = crypto::Error;
    type Signature = Signature;

    fn public_key(&self) -> Self::PublicKey {
        PublicKey(self.sk_to_pk())
    }

    fn try_sign(
        &self,
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Self::Signature, Self::Error> {
        match version {
            SigningVersion::V1 => {
                let aug = self.sk_to_pk().to_bytes();
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::MessageAugmentation).into();
                Ok(Signature(self.sign(msg, &cipher_suite, &aug)))
            }
            SigningVersion::V2 | SigningVersion::Latest => {
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::ProofOfPossession).into();
                Ok(Signature(self.sign(msg, &cipher_suite, &[])))
            }
            _ => Err(crypto::Error::InvalidSigningVersion),
        }
    }

    fn try_sign_digest(&self, _digest: &[u8]) -> Result<Self::Signature, Self::Error> {
        Err(crypto::Error::DigestSigningUnsupported)
    }
}

impl PossessionProver for SigningKey {
    type Proof = ProofOfPossession;
    type Error = crypto::Error;

    fn try_prove(&self) -> Result<Self::Proof, Self::Error> {
        let pk = self.sk_to_pk().to_bytes();
        let cipher_suite: Vec<u8> =
            CipherSuite::ProofOfPossession(2, Scheme::ProofOfPossession).into();
        Ok(ProofOfPossession(self.sign(&pk, &cipher_suite, &[])))
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
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<32>::new())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, PossessionProver, ProofVerifier, Random, Verifier};
    use rand_core::OsRng;

    #[test]
    fn test_key_generation() {
        let sk = SigningKey::random(&mut OsRng).unwrap();
        let pk = sk.public_key();

        // Verify we can generate multiple different keys
        let sk2 = SigningKey::random(&mut OsRng).unwrap();
        let pk2 = sk2.public_key();

        assert_ne!(pk.compress(), pk2.compress());
    }

    macro_rules! test_sign_and_verify {
        ($name:ident, $version:expr) => {
            #[test]
            fn $name() {
                let sk = SigningKey::random(&mut OsRng).unwrap();
                let pk = sk.public_key();
                let msg = b"test message";

                let sig = sk.try_sign(msg, $version).unwrap();
                assert!(pk.verify(msg, &sig, $version).is_ok());
            }
        };
    }

    test_sign_and_verify!(test_sign_and_verify_v1, SigningVersion::V1);
    test_sign_and_verify!(test_sign_and_verify_v2, SigningVersion::V2);
    test_sign_and_verify!(test_sign_and_verify_latest, SigningVersion::Latest);

    #[test]
    fn test_verify_wrong_message() {
        let sk = SigningKey::random(&mut OsRng).expect("key generation failed");
        let pk = sk.public_key();

        let sig = sk
            .try_sign(b"correct message", SigningVersion::V2)
            .expect("signing failed");
        let result = pk.verify(b"wrong message", &sig, SigningVersion::V2);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let sk1 = SigningKey::random(&mut OsRng).expect("key generation failed");
        let sk2 = SigningKey::random(&mut OsRng).expect("key generation failed");
        let pk2 = sk2.public_key();
        let msg = b"test message";

        let sig = sk1
            .try_sign(msg, SigningVersion::V2)
            .expect("signing failed");
        let result = pk2.verify(msg, &sig, SigningVersion::V2);

        assert!(result.is_err());
    }

    #[test]
    fn test_proof_of_possession_wrong_key() {
        let sk1 = SigningKey::random(&mut OsRng).expect("key generation failed");
        let sk2 = SigningKey::random(&mut OsRng).expect("key generation failed");
        let pk2 = sk2.public_key();

        let proof = sk1.try_prove().expect("proof generation failed");
        let result = pk2.verify_pop(&proof);

        assert!(result.is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let sk = SigningKey::random(&mut OsRng).expect("key generation failed");
        let msg = b"test message";
        let sig = sk
            .try_sign(msg, SigningVersion::V2)
            .expect("signing failed");

        let mut serialized = Vec::new();
        ciborium::into_writer(&sig, &mut serialized).expect("serialization failed");
        let deserialized: Signature =
            ciborium::from_reader(&serialized[..]).expect("deserialization failed");

        assert_eq!(sig.compress(), deserialized.compress());
    }

    #[test]
    fn test_public_key_serialization() {
        let sk = SigningKey::random(&mut OsRng).expect("key generation failed");
        let pk = sk.public_key();

        let mut serialized = Vec::new();
        ciborium::into_writer(&pk, &mut serialized).expect("serialization failed");
        let deserialized: PublicKey =
            ciborium::from_reader(&serialized[..]).expect("deserialization failed");

        assert_eq!(pk.compress(), deserialized.compress());
    }

    #[test]
    fn test_signing_key_serialization() {
        let sk = SigningKey::random(&mut OsRng).expect("key generation failed");
        let msg = b"test message";

        let mut serialized = Vec::new();
        ciborium::into_writer(&sk, &mut serialized).expect("serialization failed");
        let deserialized: SigningKey =
            ciborium::from_reader(&serialized[..]).expect("deserialization failed");

        let sig1 = sk
            .try_sign(msg, SigningVersion::V2)
            .expect("signing failed");
        let sig2 = deserialized
            .try_sign(msg, SigningVersion::V2)
            .expect("signing failed");

        assert_eq!(sig1.compress(), sig2.compress());
    }

    #[test]
    fn test_proof_serialization() {
        let sk = SigningKey::random(&mut OsRng).expect("key generation failed");
        let proof = sk.try_prove().expect("proof generation failed");

        let mut serialized = Vec::new();
        ciborium::into_writer(&proof, &mut serialized).expect("serialization failed");
        let deserialized: ProofOfPossession =
            ciborium::from_reader(&serialized[..]).expect("deserialization failed");

        assert_eq!(proof.compress(), deserialized.compress());
    }
}
