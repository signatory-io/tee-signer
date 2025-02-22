use serde::de::{self, Visitor};
use std::marker::PhantomData;

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
}
