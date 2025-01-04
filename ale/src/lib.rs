pub use const_oid::{self as oid, ObjectIdentifier};

pub const ASN1_TAG_SHIFT: usize = 24;
pub const ASN1_TAG_NUMBER_MASK: u32 = (1_u32 << (5 + ASN1_TAG_SHIFT)) - 1;

pub const ASN1_CLASS_MASK: u32 = 0xc0 << ASN1_TAG_SHIFT;
pub const ASN1_CONSTRUCTED: u32 = 0x20 << ASN1_TAG_SHIFT;

pub const ASN1_UNIVERSAL: u32 = 0;
pub const ASN1_APPLICATION: u32 = 0x40 << ASN1_TAG_SHIFT;
pub const ASN1_CONTEXT_SPECIFIC: u32 = 0x80 << ASN1_TAG_SHIFT;
pub const ASN1_PRIVATE: u32 = 0xc0 << ASN1_TAG_SHIFT;

pub const ASN1_BOOLEAN: u32 = 0x1;
pub const ASN1_INTEGER: u32 = 0x2;
pub const ASN1_BITSTRING: u32 = 0x3;
pub const ASN1_OCTETSTRING: u32 = 0x4;
pub const ASN1_NULL: u32 = 0x5;
pub const ASN1_OBJECT: u32 = 0x6;
pub const ASN1_ENUMERATED: u32 = 0xa;
pub const ASN1_UTF8STRING: u32 = 0xc;
pub const ASN1_SEQUENCE: u32 = 0x10 | ASN1_CONSTRUCTED;
pub const ASN1_SET: u32 = 0x11 | ASN1_CONSTRUCTED;
pub const ASN1_NUMERICSTRING: u32 = 0x12;
pub const ASN1_PRINTABLESTRING: u32 = 0x13;
pub const ASN1_T61STRING: u32 = 0x14;
pub const ASN1_VIDEOTEXSTRING: u32 = 0x15;
pub const ASN1_IA5STRING: u32 = 0x16;
pub const ASN1_UTCTIME: u32 = 0x17;
pub const ASN1_GENERALIZEDTIME: u32 = 0x18;
pub const ASN1_GRAPHICSTRING: u32 = 0x19;
pub const ASN1_VISIBLESTRING: u32 = 0x1a;
pub const ASN1_GENERALSTRING: u32 = 0x1b;
pub const ASN1_UNIVERSALSTRING: u32 = 0x1c;
pub const ASN1_BMPSTRING: u32 = 0x1e;

#[derive(Debug)]
pub struct Elem<'a> {
    pub tag: u32,
    pub value: &'a [u8],
}

impl<'a> Elem<'a> {
    pub fn contents(&self) -> Bytes<'a> {
        Bytes::new(self.value)
    }
}

#[derive(Debug)]
pub struct Bytes<'a> {
    inner: &'a [u8],
}

impl<'a> Bytes<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self { inner: src }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.inner.len() < len {
            Err(Error::EOF)
        } else {
            let (out, rest) = (&self.inner[..len], &self.inner[len..]);
            self.inner = rest;
            Ok(out)
        }
    }

    #[inline]
    pub fn get_u8(&mut self) -> Result<u8, Error> {
        if self.inner.len() < 1 {
            Err(Error::EOF)
        } else {
            let v = self.inner[0];
            self.inner = &self.inner[1..];
            Ok(v)
        }
    }

    pub fn get_base128(&mut self) -> Result<u64, Error> {
        let mut v = 0_u64;
        loop {
            let b = self.get_u8()? as u64;
            if (v >> (64 - 7)) != 0 {
                // The value is too large.
                return Err(Error::ValueTooLarge);
            }
            if v == 0 && b == 0x80 {
                // The value must be minimally encoded.
                return Err(Error::Encoding);
            }
            v = (v << 7) | (b & 0x7f);
            // Values end at an octet with the high bit cleared.
            if b & 0x80 == 0 {
                break;
            }
        }
        Ok(v)
    }

    pub fn get_tag(&mut self) -> Result<u32, Error> {
        let tag_byte = self.get_u8()? as u32;

        let mut tag = (tag_byte & 0xe0) << ASN1_TAG_SHIFT;
        let mut tag_number = tag_byte & 0x1f;

        if tag_number == 0x1f {
            let v = self.get_base128()?;
            if v > ASN1_TAG_NUMBER_MASK as u64 || v < 0x1f {
                return Err(Error::Encoding);
            }
            tag_number = v as u32;
        }
        tag |= tag_number;
        if tag & !ASN1_CONSTRUCTED == 0 {
            Err(Error::Encoding)
        } else {
            Ok(tag)
        }
    }

    /// Returns None if tag doesn't match
    pub fn peek_tag(&self, expect_tag: Option<u32>) -> Result<Option<u32>, Error> {
        let mut bytes = Bytes::new(self.inner);
        let tag = bytes.get_tag()?;
        match expect_tag {
            Some(val) => {
                if tag == val {
                    Ok(Some(tag))
                } else {
                    Ok(None)
                }
            }
            None => Ok(Some(tag)),
        }
    }

    #[inline]
    pub fn get_optional_elem(&mut self, expect_tag: u32) -> Result<Option<Elem<'a>>, Error> {
        match self.peek_tag(Some(expect_tag))? {
            Some(_) => Ok(Some(self.get_elem(Some(expect_tag))?)),
            None => Ok(None),
        }
    }

    #[inline]
    pub fn get_unsigned(&mut self, len: usize) -> Result<u64, Error> {
        let data = self.get_bytes(len)?;
        let mut result = 0_u64;
        for x in data {
            result <<= 8;
            result |= *x as u64;
        }
        Ok(result)
    }

    pub fn get_elem(&mut self, expect_tag: Option<u32>) -> Result<Elem<'a>, Error> {
        let tag = self.get_tag()?;
        if let Some(expect) = expect_tag {
            if tag != expect {
                return Err(Error::Tag(tag));
            }
        }

        let length_byte = self.get_u8()?;

        let len = if length_byte & 0x80 == 0 {
            // Short form length.
            length_byte as usize
        } else {
            // The high bit indicate that this is the long form, while the next 7 bits
            // encode the number of subsequent octets used to encode the length (ITU-T
            // X.690 clause 8.1.3.5.b).
            let num_bytes = length_byte as usize & 0x7f;
            if tag & ASN1_CONSTRUCTED != 0 && num_bytes == 0 {
                self.len()
            } else {
                // ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
                // used as the first byte of the length. If this parser encounters that
                // value, num_bytes will be parsed as 127, which will fail this check.
                if num_bytes == 0 || num_bytes > 4 {
                    return Err(Error::Encoding);
                }
                self.get_unsigned(num_bytes)? as usize
            }
        };

        Ok(Elem {
            tag,
            value: self.get_bytes(len)?,
        })
    }

    #[inline]
    pub fn is_eoc(&self) -> bool {
        self.inner.len() >= 2 && self.inner[0] == 0 && self.inner[1] == 0
    }

    #[inline]
    pub fn get<T: TryFromBER<'a>>(&mut self) -> Result<T, T::Error> {
        T::try_from_ber(self)
    }
}

impl<'a> From<Elem<'a>> for Bytes<'a> {
    #[inline]
    fn from(elem: Elem<'a>) -> Self {
        elem.contents()
    }
}

pub trait TryFromBER<'a>: Sized {
    type Error;
    fn try_from_ber(src: &mut Bytes<'a>) -> Result<Self, Self::Error>;
    fn try_from_ber_bytes(src: &'a [u8]) -> Result<Self, Self::Error> {
        let mut bytes = Bytes::new(src);
        Self::try_from_ber(&mut bytes)
    }
}

impl<'a> TryFromBER<'a> for Elem<'a> {
    type Error = Error;
    fn try_from_ber(src: &mut Bytes<'a>) -> Result<Self, Self::Error> {
        src.get_elem(None)
    }
}

impl<'a> TryFromBER<'a> for ObjectIdentifier {
    type Error = Error;

    fn try_from_ber(src: &mut Bytes<'a>) -> Result<Self, Self::Error> {
        match src.get_elem(Some(ASN1_OBJECT)) {
            Ok(el) => match ObjectIdentifier::from_bytes(el.value) {
                Ok(v) => Ok(v),
                Err(err) => Err(Error::OID(err)),
            },
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    EOF,
    ValueTooLarge,
    Encoding,
    Tag(u32),
    OID(oid::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EOF => f.write_str("EOF"),
            Error::ValueTooLarge => f.write_str("value is too large"),
            Error::Encoding => f.write_str("invalid error"),
            Error::Tag(tag) => write!(f, "unexpected tag: {}", tag),
            Error::OID(error) => write!(f, "OID decoding error: {}", error),
        }
    }
}

impl std::error::Error for Error {}
