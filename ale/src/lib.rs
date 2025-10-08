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
                return Err(Error::ValueTooLarge);
            }
            if v == 0 && b == 0x80 {
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
            Error::Infinite => f.write_str("infinite length"),
            Error::Convert(err) => write!(f, "convert error: {}", err),
            Error::Length(len) => write!(f, "invalid length: {}", len),
            Error::Overflow => f.write_str("overflow"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_operations() {
        let data = [0x42, 0x43, 0x44];
        let mut stream = Stream::new(&data);
        assert_eq!(stream.get_u8().unwrap(), 0x42);
        assert_eq!(stream.len(), 2);
        let bytes = stream.get_bytes(2).unwrap();
        assert_eq!(bytes, &[0x43, 0x44]);
    }

    #[test]
    fn test_stream_eos_errors() {
        let mut stream = Stream::new(&[]);
        assert!(matches!(stream.get_u8(), Err(Error::EOS)));
        assert!(matches!(stream.get_bytes(1), Err(Error::EOS)));
        assert!(matches!(stream.advance(1), Err(Error::EOS)));
    }

    #[test]
    fn test_stream_get_base128_single_byte() {
        let data = [0x7f];
        let mut stream = Stream::new(&data);
        assert_eq!(stream.get_base128().unwrap(), 127);
    }

    #[test]
    fn test_stream_get_base128_multi_byte() {
        let data = [0x81, 0x00];
        let mut stream = Stream::new(&data);
        assert_eq!(stream.get_base128().unwrap(), 128);
    }

    #[test]
    fn test_stream_get_base128_invalid_encoding() {
        let data = [0x80];
        let mut stream = Stream::new(&data);
        assert!(matches!(stream.get_base128(), Err(Error::Encoding)));
    }

    #[test]
    fn test_stream_get_base128_overflow() {
        // Value that would overflow u64
        let data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        let mut stream = Stream::new(&data);
        assert!(matches!(stream.get_base128(), Err(Error::ValueTooLarge)));
    }

    #[test]
    fn test_stream_get_eoc_present() {
        let data = [0x00, 0x00, 0x42];
        let mut stream = Stream::new(&data);
        assert!(stream.get_eoc());
        assert_eq!(stream.len(), 1);
    }

    #[test]
    fn test_stream_get_eoc_absent() {
        let data = [0x00, 0x01];
        let mut stream = Stream::new(&data);
        assert!(!stream.get_eoc());
        assert_eq!(stream.len(), 2);
    }

    #[test]
    fn test_stream_get_tag() {
        // Simple tag
        assert_eq!(Stream::new(&[0x02]).get_tag().unwrap(), ASN1_INTEGER);
        // Constructed tag
        assert_eq!(Stream::new(&[0x30]).get_tag().unwrap(), ASN1_SEQUENCE);
        // Long form tag
        assert_eq!(Stream::new(&[0x1f, 0x20]).get_tag().unwrap(), 32);
        // Context-specific
        let tag = Stream::new(&[0xa0]).get_tag().unwrap();
        assert_eq!(tag & ASN1_CONTEXT_SPECIFIC, ASN1_CONTEXT_SPECIFIC);
    }

    #[test]
    fn test_stream_get_tag_errors() {
        assert!(matches!(
            Stream::new(&[0x00]).get_tag(),
            Err(Error::Encoding)
        ));
        assert!(matches!(
            Stream::new(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).get_tag(),
            Err(Error::Overflow)
        ));
    }

    #[test]
    fn test_stream_get_unsigned() {
        let data = [0x01, 0x02, 0x03];
        let mut stream = Stream::new(&data);
        assert_eq!(stream.get_unsigned(3).unwrap(), 0x010203);
    }

    #[test]
    fn test_stream_get_unsigned_overflow() {
        let data = [0xff; 9]; // 9 bytes will overflow u64
        let mut stream = Stream::new(&data);
        assert!(matches!(stream.get_unsigned(9), Err(Error::Overflow)));
    }

    #[test]
    fn test_elem_get_bytes() {
        let mut stream = Stream::new(&[0x01, 0x02, 0x03]);
        let elem = Elem {
            tag: 0,
            len: Some(2),
            start: 3,
        };
        assert_eq!(elem.get_bytes(&mut stream).unwrap(), &[0x01, 0x02]);

        // Infinite length error
        let mut stream2 = Stream::new(&[0x01, 0x02]);
        let elem2 = Elem {
            tag: ASN1_SEQUENCE,
            len: None,
            start: 2,
        };
        assert!(matches!(
            elem2.get_bytes(&mut stream2),
            Err(Error::Infinite)
        ));
    }

    #[test]
    fn test_parse_integer() {
        let mut stream = Stream::new(&[0x02, 0x01, 0x2a]); // INTEGER 42
        let doc = Elem::new(&stream);
        let val: u8 = doc.get_tagged(&mut stream).unwrap().unwrap();
        assert_eq!(val, 42);

        // Integer overflow
        let mut stream2 = Stream::new(&[0x02, 0x02, 0x01, 0x00]); // 256, too large for u8
        let doc2 = Elem::new(&stream2);
        assert!(doc2.get_tagged::<u8>(&mut stream2).is_err());
    }

    #[test]
    fn test_parse_sequence() {
        // Short length: SEQUENCE { INTEGER 5 }
        let mut stream = Stream::new(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        let seq = new_document(&mut stream, Some(ASN1_SEQUENCE))
            .unwrap()
            .unwrap();
        assert_eq!(seq.tag, ASN1_SEQUENCE);
        assert_eq!(seq.len, Some(3));

        // Long form length
        let mut stream2 = Stream::new(&[0x30, 0x81, 0x05, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x2b]);
        let seq2 = new_document(&mut stream2, Some(ASN1_SEQUENCE))
            .unwrap()
            .unwrap();
        assert_eq!(seq2.len, Some(5));

        // Nested sequences
        let mut stream3 = Stream::new(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]);
        let outer = new_document(&mut stream3, Some(ASN1_SEQUENCE))
            .unwrap()
            .unwrap();
        let inner = outer
            .get_elem(&mut stream3, Some(ASN1_SEQUENCE))
            .unwrap()
            .unwrap();
        let val: u8 = inner.get_tagged(&mut stream3).unwrap().unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn test_elem_get_optional() {
        // Present
        let mut stream = Stream::new(&[0x02, 0x01, 0x05]);
        assert!(Elem::new(&stream)
            .get_optional(&mut stream, ASN1_INTEGER)
            .unwrap()
            .is_some());

        // Absent - empty stream
        let mut stream2 = Stream::new(&[]);
        assert!(Elem::new(&stream2)
            .get_optional(&mut stream2, ASN1_INTEGER)
            .unwrap()
            .is_none());

        // Absent - wrong tag
        let mut stream3 = Stream::new(&[0x04, 0x01, 0x05]);
        assert!(Elem::new(&stream3)
            .get_optional(&mut stream3, ASN1_INTEGER)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_elem_consume() {
        // Definite length
        let mut stream = Stream::new(&[0x02, 0x01, 0x05, 0x99]);
        let elem = new_document(&mut stream, Some(ASN1_INTEGER))
            .unwrap()
            .unwrap();
        elem.consume(&mut stream).unwrap();
        assert_eq!(stream.len(), 1);

        // Indefinite length
        let mut stream2 = Stream::new(&[0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0x99]);
        let seq = new_document(&mut stream2, Some(ASN1_SEQUENCE))
            .unwrap()
            .unwrap();
        seq.consume(&mut stream2).unwrap();
        assert_eq!(stream2.len(), 1);
    }

    #[test]
    fn test_expect_some() {
        assert_eq!(Ok(Some(42)).expect_some().unwrap(), 42);
        assert!(matches!(
            Ok::<Option<u32>, Error>(None).expect_some(),
            Err(Error::EOS)
        ));
    }

    #[test]
    fn test_parsing_errors() {
        // Tag mismatch
        assert!(matches!(
            new_document(&mut Stream::new(&[0x04, 0x01, 0x05]), Some(ASN1_INTEGER)),
            Err(Error::Tag(_))
        ));

        // Invalid length encoding
        assert!(matches!(
            new_document(&mut Stream::new(&[0x02, 0x80]), Some(ASN1_INTEGER)),
            Err(Error::Encoding)
        ));

        // Length field too long (5 octets)
        assert!(matches!(
            new_document(
                &mut Stream::new(&[0x02, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05]),
                None
            ),
            Err(Error::Encoding)
        ));
    }

    #[test]
    fn test_parse_object_identifier() {
        let mut stream = Stream::new(&[0x06, 0x03, 0x2a, 0x86, 0x48]); // OID 1.2.840
        let oid: ObjectIdentifier = Elem::new(&stream).get_tagged(&mut stream).unwrap().unwrap();
        assert_eq!(oid.to_string(), "1.2.840");
    }

    #[test]
    fn test_empty_document() {
        assert!(new_document(&mut Stream::new(&[]), None).unwrap().is_none());
    }

    #[test]
    fn test_indefinite_length() {
        let mut stream = Stream::new(&[0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]);
        let seq = new_document(&mut stream, Some(ASN1_SEQUENCE))
            .unwrap()
            .unwrap();
        assert_eq!(seq.len, None);
    }
}
