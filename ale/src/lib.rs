pub use const_oid::{self as oid, ObjectIdentifier};

mod convert;
pub use convert::{Tagged, TryFromBytes};

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
pub struct Stream<'a> {
    inner: &'a [u8],
}

impl<'a> Stream<'a> {
    #[inline]
    pub fn new(src: &'a [u8]) -> Self {
        Self { inner: src }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    fn get_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.inner.len() < len {
            Err(Error::EOS)
        } else {
            let (out, rest) = (&self.inner[..len], &self.inner[len..]);
            self.inner = rest;
            Ok(out)
        }
    }

    #[inline]
    fn get_u8(&mut self) -> Result<u8, Error> {
        if self.inner.len() < 1 {
            Err(Error::EOS)
        } else {
            let v = self.inner[0];
            self.inner = &self.inner[1..];
            Ok(v)
        }
    }

    fn get_base128(&mut self) -> Result<u64, Error> {
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

    #[inline]
    fn get_eoc(&mut self) -> bool {
        if self.inner.len() >= 2 && self.inner[0] == 0 && self.inner[1] == 0 {
            self.inner = &self.inner[2..];
            true
        } else {
            false
        }
    }

    fn get_tag(&mut self) -> Result<u32, Error> {
        let tag_byte = self.get_u8()? as u32;

        let mut tag = (tag_byte & 0xe0) << ASN1_TAG_SHIFT;
        let mut tag_number = tag_byte & 0x1f;

        if tag_number == 0x1f {
            let v = self.get_base128()?;
            if v > ASN1_TAG_NUMBER_MASK as u64 || v < 0x1f {
                return Err(Error::Overflow);
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

    #[inline]
    fn peek_tag(&self) -> Result<u32, Error> {
        Stream::new(self.inner).get_tag()
    }

    fn get_unsigned(&mut self, len: usize) -> Result<u64, Error> {
        let data = self.get_bytes(len)?;
        let mut result = 0_u64;
        for x in data {
            if result & !(u64::MAX >> 8) != 0 {
                return Err(Error::Overflow);
            }
            result <<= 8;
            result |= *x as u64;
        }
        Ok(result)
    }

    #[inline]
    fn advance(&mut self, n: usize) -> Result<(), Error> {
        if self.inner.len() < n {
            Err(Error::EOS)
        } else {
            self.inner = &self.inner[n..];
            Ok(())
        }
    }
}

pub fn new_document(stream: &mut Stream, expect: Option<u32>) -> Result<Option<Elem>, Error> {
    Elem::new(stream).get_elem(stream, expect)
}

pub trait ExpectSome<T, E> {
    fn expect_some(self) -> Result<T, E>;
}

impl<T> ExpectSome<T, Error> for Result<Option<T>, Error> {
    #[inline]
    fn expect_some(self) -> Result<T, Error> {
        match self {
            Ok(opt) => match opt {
                Some(val) => Ok(val),
                None => Err(Error::EOS),
            },
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug)]
pub struct Elem {
    pub tag: u32,
    len: Option<usize>,
    start: usize,
}

impl Elem {
    fn new(stream: &Stream) -> Self {
        Elem {
            tag: 0,
            len: Some(stream.len()),
            start: stream.len(),
        }
    }

    pub fn get_bytes<'a>(&self, stream: &mut Stream<'a>) -> Result<&'a [u8], Error> {
        match self.len {
            Some(len) => stream.get_bytes(len),
            None => Err(Error::Infinite),
        }
    }

    #[inline]
    pub fn consumed(&self, stream: &Stream) -> usize {
        self.start - stream.len()
    }

    #[inline]
    pub fn available(&self, stream: &Stream) -> Option<usize> {
        match self.len {
            Some(len) => Some(len - self.consumed(stream)),
            None => None,
        }
    }

    pub fn get_elem(
        &self,
        stream: &mut Stream,
        expect: Option<u32>,
    ) -> Result<Option<Elem>, Error> {
        if let Some(available) = self.available(stream) {
            if available == 0 {
                return Ok(None);
            }
        } else if stream.get_eoc() {
            return Ok(None);
        }

        let tag = stream.get_tag()?;
        if let Some(ex) = expect {
            if tag != ex {
                return Err(Error::Tag(tag));
            }
        }

        let length_byte = stream.get_u8()?;
        let len = if length_byte & 0x80 == 0 {
            // Short form length.
            Some(length_byte as usize)
        } else {
            // The high bit indicate that this is the long form, while the next 7 bits
            // encode the number of subsequent octets used to encode the length (ITU-T
            // X.690 clause 8.1.3.5.b).
            let num_bytes = length_byte as usize & 0x7f;
            if tag & ASN1_CONSTRUCTED != 0 && num_bytes == 0 {
                None
            } else {
                // ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
                // used as the first byte of the length. If this parser encounters that
                // value, num_bytes will be parsed as 127, which will fail this check.
                if num_bytes == 0 || num_bytes > 4 {
                    return Err(Error::Encoding);
                }
                Some(stream.get_unsigned(num_bytes)? as usize)
            }
        };

        Ok(Some(Elem {
            tag,
            len,
            start: stream.len(),
        }))
    }

    pub fn get_optional(&self, stream: &mut Stream, expect: u32) -> Result<Option<Elem>, Error> {
        if let Some(available) = self.available(stream) {
            if available == 0 {
                return Ok(None);
            }
        } else if stream.get_eoc() {
            return Ok(None);
        }

        if stream.peek_tag()? == expect {
            self.get_elem(stream, None)
        } else {
            return Ok(None);
        }
    }

    pub fn get_tagged<'a, T>(&self, stream: &mut Stream<'a>) -> Result<Option<T>, Error>
    where
        T: Tagged,
        T::Error: std::error::Error + Send + Sync + 'static,
    {
        self.get(stream, Some(T::TAG))
    }

    pub fn get<'a, T>(&self, stream: &mut Stream<'a>, tag: Option<u32>) -> Result<Option<T>, Error>
    where
        T: TryFromBytes,
        T::Error: std::error::Error + Send + Sync + 'static,
    {
        match self.get_elem(stream, tag)? {
            Some(el) => {
                let b = el.get_bytes(stream)?;
                match T::try_from_bytes(b) {
                    Ok(value) => Ok(Some(value)),
                    Err(err) => Err(Error::Convert(Box::new(err))),
                }
            }
            None => Ok(None),
        }
    }

    pub fn consume<'a>(&self, stream: &mut Stream<'a>) -> Result<(), Error> {
        match self.available(stream) {
            Some(val) => stream.advance(val),
            None => {
                while let Some(el) = self.get_elem(stream, None)? {
                    el.consume(stream)?
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    EOS,
    ValueTooLarge,
    Encoding,
    Tag(u32),
    Length(usize),
    OID(oid::Error),
    Infinite,
    Convert(Box<dyn std::error::Error + Send + Sync>),
    Overflow,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EOS => f.write_str("unexpected end of stream"),
            Error::ValueTooLarge => f.write_str("value is too large"),
            Error::Encoding => f.write_str("invalid error"),
            Error::Tag(tag) => write!(f, "unexpected tag: {:x}", tag),
            Error::OID(error) => write!(f, "OID decoding error: {}", error),
            Error::Infinite => f.write_str("infinite length"),
            Error::Convert(err) => write!(f, "convert error: {}", err),
            Error::Length(len) => write!(f, "invalid length: {}", len),
            Error::Overflow => f.write_str("overflow"),
        }
    }
}

impl std::error::Error for Error {}
