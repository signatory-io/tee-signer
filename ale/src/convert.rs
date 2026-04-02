use crate::{Error, Stream, ASN1_INTEGER, ASN1_OBJECT};
use const_oid::ObjectIdentifier;

pub trait TryFromBytes: Sized {
    type Error;
    fn try_from_bytes(src: &[u8]) -> Result<Self, Self::Error>;
}

pub trait Tagged: TryFromBytes {
    const TAG: u32;
}

impl TryFromBytes for ObjectIdentifier {
    type Error = const_oid::Error;

    fn try_from_bytes(src: &[u8]) -> Result<Self, Self::Error> {
        ObjectIdentifier::try_from(src)
    }
}

impl Tagged for ObjectIdentifier {
    const TAG: u32 = ASN1_OBJECT;
}

macro_rules! impl_uint {
    ($t:ty) => {
        impl Tagged for $t {
            const TAG: u32 = ASN1_INTEGER;
        }

        impl TryFromBytes for $t {
            type Error = Error;
            #[inline]
            fn try_from_bytes(src: &[u8]) -> Result<Self, Self::Error> {
                let val = Stream::new(src).get_unsigned(src.len())?;
                <$t>::try_from(val).or(Err(Error::Overflow))
            }
        }
    };
}

impl_uint!(u64);
impl_uint!(u32);
impl_uint!(u16);
impl_uint!(u8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_types_try_from_bytes() {
        // u8
        assert_eq!(u8::try_from_bytes(&[0x2a]).unwrap(), 42);
        assert!(u8::try_from_bytes(&[0x01, 0x00]).is_err()); // overflow

        // u16
        assert_eq!(u16::try_from_bytes(&[0x01, 0x00]).unwrap(), 256);
        assert!(u16::try_from_bytes(&[0x01, 0x00, 0x00]).is_err()); // overflow

        // u32
        assert_eq!(
            u32::try_from_bytes(&[0x00, 0x01, 0x00, 0x00]).unwrap(),
            65536
        );

        // u64
        assert_eq!(
            u64::try_from_bytes(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
            0x01020304
        );
    }

    #[test]
    fn test_object_identifier() {
        // Valid OID
        let oid = ObjectIdentifier::try_from_bytes(&[0x2a, 0x86, 0x48]).unwrap();
        assert_eq!(oid.to_string(), "1.2.840");

        // Invalid OID
        assert!(ObjectIdentifier::try_from_bytes(&[0xff]).is_err());
    }
}
