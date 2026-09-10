//! Cryptographic interfaces and shared wire-format types for encrypted vault
//! records.
//!
//! This crate currently exposes the public contracts used by higher-level vault
//! code. `PlaceholderCryptoCore` can generate random keys, but record
//! encryption and decryption deliberately return `CryptoError::NotImplemented`
//! until the project selects and documents concrete primitives.

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Number of bytes in a symmetric vault or record key.
pub const KEY_BYTES: usize = 32;

/// Number of bytes in a record encryption nonce.
pub const NONCE_BYTES: usize = 24;

/// Initial crypto format version for encrypted vault records.
pub const CRYPTO_VERSION_V1: u8 = 1;

/// Secret byte material that redacts itself in debug output.
///
/// This type does not zeroize memory on drop yet. Callers must avoid cloning it
/// unnecessarily and must never log or serialize values unless the surrounding
/// format is explicitly designed to store protected key material.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps raw secret bytes.
    ///
    /// The bytes are stored as provided and are not validated for length or
    /// origin. Use `CryptoCore::generate_random_key` when a fresh key is needed.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the underlying secret bytes.
    ///
    /// Exposing the bytes is intentionally explicit because the result may
    /// contain key material. Do not include the returned slice in logs, panic
    /// messages, telemetry, or general-purpose AI prompts.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(**redacted**)")
    }
}

/// Serialized encrypted form of one vault record.
///
/// The structure is safe for cloud storage because it contains ciphertext and
/// wrapping metadata, not plaintext account fields. `crypto_version` identifies
/// the algorithm suite and migration behavior used to produce the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecord {
    /// Authenticated ciphertext for the protected record payload.
    pub ciphertext: Vec<u8>,

    /// Per-record data key wrapped by a vault-level key.
    pub wrapped_record_key: Vec<u8>,

    /// Nonce used for record encryption.
    pub nonce: [u8; NONCE_BYTES],

    /// Version of the crypto format that produced this record.
    pub crypto_version: u8,
}

/// Errors returned by cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A provided key does not match the length required by the active format.
    #[error("invalid key length")]
    InvalidKeyLength,

    /// The operation has not been implemented for the selected crypto backend.
    #[error("operation is not implemented yet")]
    NotImplemented,
}

/// Common interface for record encryption, decryption, and key generation.
///
/// Implementations must use cryptographically secure randomness for generated
/// keys and authenticated encryption for records. Implementations must not log
/// plaintext, master keys, record keys, nonces paired with plaintext, or
/// decrypted record contents.
pub trait CryptoCore {
    /// Generates a fresh symmetric key with `KEY_BYTES` bytes of entropy.
    fn generate_random_key(&self) -> SecretBytes;

    /// Encrypts one plaintext vault record using the provided master key.
    ///
    /// Implementations should generate a per-record data key, encrypt the
    /// plaintext with authenticated encryption, and wrap the data key with the
    /// master key. The returned `EncryptedRecord` must include all metadata
    /// required for later decryption.
    fn encrypt_record(
        &self,
        _master_key: &SecretBytes,
        _plaintext: &[u8],
    ) -> Result<EncryptedRecord, CryptoError>;

    /// Decrypts one encrypted vault record using the provided master key.
    ///
    /// Implementations must fail if authentication, key unwrapping, nonce
    /// validation, or crypto-version validation fails. Returned plaintext may
    /// contain secrets and must be handled under the project's logging rules.
    fn decrypt_record(
        &self,
        _master_key: &SecretBytes,
        _record: &EncryptedRecord,
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Temporary crypto backend used before record encryption is implemented.
///
/// This backend is suitable only for tests that need random key generation. It
/// must not be used as a production vault encryption provider because
/// `encrypt_record` and `decrypt_record` always fail.
///
/// # Example
///
/// ```
/// use crypto_core::{CryptoCore, KEY_BYTES, PlaceholderCryptoCore};
///
/// let crypto = PlaceholderCryptoCore;
/// let key = crypto.generate_random_key();
///
/// assert_eq!(key.expose().len(), KEY_BYTES);
/// ```
#[derive(Debug, Default)]
pub struct PlaceholderCryptoCore;

impl CryptoCore for PlaceholderCryptoCore {
    fn generate_random_key(&self) -> SecretBytes {
        let mut bytes = vec![0_u8; KEY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        SecretBytes::new(bytes)
    }

    fn encrypt_record(
        &self,
        _master_key: &SecretBytes,
        _plaintext: &[u8],
    ) -> Result<EncryptedRecord, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn decrypt_record(
        &self,
        _master_key: &SecretBytes,
        _record: &EncryptedRecord,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoCore, KEY_BYTES, PlaceholderCryptoCore};

    #[test]
    fn generated_keys_have_expected_size() {
        let crypto = PlaceholderCryptoCore;
        let key = crypto.generate_random_key();
        assert_eq!(key.expose().len(), KEY_BYTES);
    }

    #[test]
    fn generated_keys_are_probabilistically_unique() {
        let crypto = PlaceholderCryptoCore;
        let key_a = crypto.generate_random_key();
        let key_b = crypto.generate_random_key();
        assert_ne!(key_a.expose(), key_b.expose());
    }
}
