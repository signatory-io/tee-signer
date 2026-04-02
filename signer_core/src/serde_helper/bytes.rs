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

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        #[serde(with = "super")]
        data: Vec<u8>,
    }

    #[test]
    fn test_serialize_vec() {
        let test = TestStruct {
            data: vec![1, 2, 3, 4, 5],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&test, &mut buf).unwrap();

        let deserialized: TestStruct = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(test, deserialized);
    }

    #[test]
    fn test_serialize_empty_vec() {
        let test = TestStruct { data: vec![] };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&test, &mut buf).unwrap();

        let deserialized: TestStruct = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(test, deserialized);
    }

    #[test]
    fn test_deserialize_from_bytes() {
        let test = TestStruct {
            data: vec![0xFF, 0xAA, 0x55],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&test, &mut buf).unwrap();

        let deserialized: TestStruct = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(test.data, deserialized.data);
    }

    #[test]
    fn test_visit_seq() {
        // Use JSON which will trigger visit_seq instead of visit_bytes
        let json_data = r#"{"data":[10,20,30,40,50]}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(json_data);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_visit_seq_empty() {
        // Test empty sequence
        let json_data = r#"{"data":[]}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(json_data);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, Vec::<u8>::new());
    }

    #[test]
    fn test_visit_seq_with_size_hint() {
        // JSON provides size hint for sequences
        let json_data = r#"{"data":[1,2,3]}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(json_data);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_expecting_message() {
        // Test the expecting method by triggering a type error
        // Trying to deserialize a number into our byte array should fail
        let json_data = r#"{"data":123}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(json_data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("byte array") || err_msg.contains("invalid type"));
    }
}
