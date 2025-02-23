use serde::de::{self, SeqAccess, Visitor};
use std::marker::PhantomData;

pub mod bytes;

pub struct ByteArrayVisitor<const T: usize> {
    _p: PhantomData<[u8; T]>,
}

impl<const T: usize> ByteArrayVisitor<T> {
    pub fn new() -> Self {
        Self { _p: PhantomData }
    }
}

impl<'a, const T: usize> Visitor<'a> for ByteArrayVisitor<T> {
    type Value = [u8; T];

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a byte array of size {}", T)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() == T {
            let mut value: [u8; T] = [0; T];
            value.copy_from_slice(v);
            Ok(value)
        } else {
            Err(de::Error::invalid_length(v.len(), &Self::new()))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'a>,
    {
        let mut values: [u8; T] = [0; T];
        let mut i = 0;
        while let Some(v) = seq.next_element()? {
            if i < T {
                values[i] = v;
            }
            i += 1;
        }

        if i != T {
            Err(de::Error::invalid_length(i, &self))
        } else {
            Ok(values)
        }
    }
}

pub struct BytesVisitor(usize);

impl BytesVisitor {
    pub fn new(sz: usize) -> Self {
        BytesVisitor(sz)
    }
}

impl<'a> Visitor<'a> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a byte array of size {}", self.0)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() == self.0 {
            Ok(v.into())
        } else {
            Err(de::Error::invalid_length(v.len(), &self))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'a>,
    {
        let mut values: Vec<u8> = match seq.size_hint() {
            Some(sz) => Vec::with_capacity(sz),
            None => Vec::new(),
        };

        while let Some(v) = seq.next_element()? {
            values.push(v);
        }

        if values.len() != self.0 {
            Err(de::Error::invalid_length(values.len(), &self))
        } else {
            Ok(values)
        }
    }
}
