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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize};

    #[test]
    fn test_byte_array_visitor_new() {
        let _visitor = ByteArrayVisitor::<32>::new();
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(deserialize_with = "deserialize_array")]
        #[serde(serialize_with = "serialize_array")]
        data: [u8; 4],
    }

    fn deserialize_array<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ByteArrayVisitor::<4>::new())
    }

    fn serialize_array<S>(data: &[u8; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(data)
    }

    #[test]
    fn test_byte_array_visitor_with_wrong_length() {
        // Create CBOR data with wrong length array [1,2,3] instead of [1,2,3,4]
        let wrong_data = [0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x43, 0x01, 0x02, 0x03];
        let result: Result<TestStruct, _> = ciborium::de::from_reader(&wrong_data[..]);
        assert!(result.is_err());
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestStructVec {
        #[serde(deserialize_with = "deserialize_vec")]
        #[serde(serialize_with = "serialize_vec")]
        data: Vec<u8>,
    }

    fn deserialize_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BytesVisitor::new(3))
    }

    fn serialize_vec<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(data)
    }

    #[test]
    fn test_bytes_visitor_with_valid_bytes() {
        let test = TestStructVec {
            data: vec![5, 6, 7],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&test, &mut buf).unwrap();
        let result: Result<TestStructVec, _> = ciborium::de::from_reader(&buf[..]);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, vec![5, 6, 7]);
    }

    #[test]
    fn test_bytes_visitor_with_wrong_length() {
        // Create CBOR data with wrong length [5,6] instead of [5,6,7]
        let wrong_data = [0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x42, 0x05, 0x06];
        let result: Result<TestStructVec, _> = ciborium::de::from_reader(&wrong_data[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_visitor_with_too_many_bytes() {
        // Create CBOR data with wrong length [5,6,7,8] instead of [5,6,7]
        let wrong_data = [
            0xa1, 0x64, 0x64, 0x61, 0x74, 0x61, 0x44, 0x05, 0x06, 0x07, 0x08,
        ];
        let result: Result<TestStructVec, _> = ciborium::de::from_reader(&wrong_data[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_array() {
        let test = TestStruct { data: [1, 2, 3, 4] };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&test, &mut buf).unwrap();
        let result: Result<TestStruct, _> = ciborium::de::from_reader(&buf[..]);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, [1, 2, 3, 4]);
    }

    #[test]
    fn test_byte_array_visitor_visit_seq() {
        // Use JSON which will trigger visit_seq instead of visit_bytes
        let json_data = r#"{"data":[10,20,30,40]}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(json_data);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, [10, 20, 30, 40]);
    }

    #[test]
    fn test_byte_array_visitor_visit_seq_wrong_length() {
        {
            // JSON with wrong length - too few elements
            let json_data = r#"{"data":[10,20,30]}"#;
            let result: Result<TestStruct, _> = serde_json::from_str(json_data);
            assert!(result.is_err());
        }
        {
            // JSON with wrong length - too many elements
            let json_data = r#"{"data":[10,20,30,40,50]}"#;
            let result: Result<TestStruct, _> = serde_json::from_str(json_data);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_bytes_visitor_visit_seq() {
        // Use JSON which will trigger visit_seq instead of visit_bytes
        let json_data = r#"{"data":[5,6,7]}"#;
        let result: Result<TestStructVec, _> = serde_json::from_str(json_data);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, vec![5, 6, 7]);
    }

    #[test]
    fn test_bytes_visitor_visit_seq_wrong_length() {
        // JSON with wrong length
        let json_data = r#"{"data":[5,6]}"#;
        let result: Result<TestStructVec, _> = serde_json::from_str(json_data);
        assert!(result.is_err());
    }
}
