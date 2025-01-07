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
