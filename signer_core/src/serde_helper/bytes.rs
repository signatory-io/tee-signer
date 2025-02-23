use std::marker::PhantomData;

use serde::{
    de::{SeqAccess, Visitor},
    Deserializer, Serializer,
};

pub fn serialize<T, S>(value: T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_bytes(value.as_ref())
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    for<'a> T: From<&'a [u8]>,
    D: Deserializer<'de>,
{
    struct BytesVisitor<T> {
        _p: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for BytesVisitor<T>
    where
        for<'a> T: From<&'a [u8]>,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte array")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(T::from(v))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values: Vec<u8> = match seq.size_hint() {
                Some(sz) => Vec::with_capacity(sz),
                None => Vec::new(),
            };
            while let Some(v) = seq.next_element()? {
                values.push(v);
            }
            Ok(T::from(&values))
        }
    }

    deserializer.deserialize_bytes(BytesVisitor { _p: PhantomData })
}
