mod authorized_keys;
mod error;
mod handshake;
mod server_keypair;
mod session;
mod stream;

pub use authorized_keys::AuthorizedKeys;
pub use error::Error;
pub use handshake::{perform_handshake, ConnectionState};
pub use server_keypair::ServerKeypair;
pub use session::Session;
pub use stream::EncryptedStream;

// Constants matching Intel SGX implementation
pub const ED25519_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const X25519_KEY_SIZE: usize = 32;
pub const PACKET_GRANULARITY: usize = 64;
pub const MAX_MESSAGE_SIZE: usize = 65536; // 64KB

// Tags for key derivation
pub const TAG_LEN: &[u8] = b"SIGNATORY_SECURE_CONNECTION_LENGTH_KEY";
pub const TAG_PAYLOAD: &[u8] = b"SIGNATORY_SECURE_CONNECTION_PAYLOAD_KEY";
pub const TAG_SUITE: &[u8] = b"SIGNATORY_SECURE_CONNECTION_X25519_ED25519";
pub const TAG_SECRET: &[u8] = b"DH_SECRET";
pub const TAG_EPH_KEYS: &[u8] = b"EPHEMERAL_PUBLIC_KEYS_XOR_COMBINED";
pub const TAG_AUTH: &[u8] = b"AUTHENTICATION_PUBLIC_KEYS_XOR_COMBINED";

pub const CHACHA20_KEY_SIZE: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;

pub type Ed25519PublicKey = [u8; ED25519_KEY_SIZE];
