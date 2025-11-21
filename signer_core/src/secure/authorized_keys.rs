use std::collections::HashSet;

use crate::secure::Ed25519PublicKey;

use super::error::Error;
use super::ED25519_KEY_SIZE;
use base64::{engine::general_purpose, Engine as _};
use log::{info, warn};

#[derive(Debug, Clone)]
pub struct AuthorizedKeys {
    keys: HashSet<Ed25519PublicKey>,
}

impl AuthorizedKeys {
    pub fn new_accept_all() -> Self {
        Self {
            keys: HashSet::new(),
        }
    }

    /// Parse authorized keys from semicolon-separated string
    /// Format: "ed25519 <base64-key> [comment];ed25519 <base64-key> [comment]"
    pub fn parse(content: &str) -> Result<Self, Error> {
        let mut keys = HashSet::new();

        for line in content.split(';') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match Self::parse_entry(line) {
                Ok(entry) => {
                    keys.insert(entry);
                }
                Err(e) => {
                    warn!("Skipping invalid key entry '{}': {}", line, e);
                }
            }
        }

        info!("Loaded {} authorized keys", keys.len());
        Ok(Self { keys })
    }

    fn parse_entry(line: &str) -> Result<Ed25519PublicKey, Error> {
        let mut parts = line.split_whitespace();

        let key_type = parts.next().ok_or(Error::InvalidKeyType)?;
        if key_type != "ed25519" {
            warn!(
                "Unsupported key type '{}', only 'ed25519' supported",
                key_type
            );
            return Err(Error::InvalidKeyType);
        }

        let key_str = parts.next().ok_or(Error::InvalidKeyLength)?;
        let key_bytes = general_purpose::STANDARD.decode(key_str)?;

        let public_key =
            <Ed25519PublicKey>::try_from(&key_bytes[..]).map_err(|_| Error::InvalidKeyLength)?;

        Ok(public_key)
    }

    pub fn is_authorized(&self, pubkey: &[u8]) -> bool {
        // Accept all if no keys configured
        if self.keys.is_empty() {
            return true;
        }

        if pubkey.len() != ED25519_KEY_SIZE {
            return false;
        }

        let pubkey: Ed25519PublicKey = pubkey.try_into().unwrap();
        self.keys.contains(&pubkey)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_key() {
        let key_base64 = general_purpose::STANDARD.encode(&[0u8; 32]);
        let content = format!("ed25519 {} test-comment", key_base64);

        let keys = AuthorizedKeys::parse(&content).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.is_authorized(&[0u8; 32]));
    }

    #[test]
    fn test_parse_multiple_keys() {
        let key1 = general_purpose::STANDARD.encode(&[1u8; 32]);
        let key2 = general_purpose::STANDARD.encode(&[2u8; 32]);
        let content = format!("ed25519 {} client1;ed25519 {} client2", key1, key2);

        let keys = AuthorizedKeys::parse(&content).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.is_authorized(&[1u8; 32]));
        assert!(keys.is_authorized(&[2u8; 32]));
        assert!(!keys.is_authorized(&[3u8; 32]));
    }

    #[test]
    fn test_parse_with_comments() {
        let key_base64 = general_purpose::STANDARD.encode(&[5u8; 32]);
        let content = format!("ed25519 {} user@host with spaces", key_base64);

        let keys = AuthorizedKeys::parse(&content).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_parse_empty_string() {
        let keys = AuthorizedKeys::parse("").unwrap();
        assert_eq!(keys.len(), 0);
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_skip_invalid() {
        let valid_key = general_purpose::STANDARD.encode(&[1u8; 32]);
        let content = format!("ed25519 {};invalid line;ed25519 INVALID", valid_key);

        let keys = AuthorizedKeys::parse(&content).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_accept_all_mode() {
        let keys = AuthorizedKeys::new_accept_all();
        assert!(keys.is_empty());
        assert!(keys.is_authorized(&[0u8; 32]));
        assert!(keys.is_authorized(&[1u8; 32]));
    }

    #[test]
    fn test_is_authorized_wrong_length() {
        let key_base64 = general_purpose::STANDARD.encode(&[0u8; 32]);
        let content = format!("ed25519 {}", key_base64);
        let keys = AuthorizedKeys::parse(&content).unwrap();

        assert!(!keys.is_authorized(&[0u8; 16]));
    }

    #[test]
    fn test_duplicate_keys() {
        let key_base64 = general_purpose::STANDARD.encode(&[0u8; 32]);
        let content = format!("ed25519 {};ed25519 {}", key_base64, key_base64);
        let keys = AuthorizedKeys::parse(&content).unwrap();

        // HashSet deduplicates automatically
        assert_eq!(keys.len(), 1);
    }
}
