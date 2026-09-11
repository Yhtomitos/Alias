//! Cryptographic interfaces and shared wire-format types for encrypted vault
//! records.
//!
//! This crate exposes the public contracts used by higher-level vault code and
//! a concrete local authenticated-encryption backend for protected records.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
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

    /// Nonce used to wrap the per-record data key.
    pub key_wrapping_nonce: [u8; NONCE_BYTES],

    /// Version of the crypto format that produced this record.
    pub crypto_version: u8,
}

/// Errors returned by cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A provided key does not match the length required by the active format.
    #[error("invalid key length")]
    InvalidKeyLength,

    /// The encrypted record was produced by an unsupported crypto format.
    #[error("unsupported crypto version")]
    UnsupportedCryptoVersion,

    /// Authentication failed while decrypting ciphertext or unwrapping a key.
    #[error("authentication failed")]
    AuthenticationFailed,
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

/// Local crypto backend for encrypted vault records.
///
/// Version 1 uses XChaCha20-Poly1305 for record encryption and for wrapping the
/// fresh per-record data key under the vault master key. It authenticates the
/// crypto version as associated data so version metadata cannot be changed
/// without causing decryption to fail.
///
/// # Example
///
/// ```
/// use crypto_core::{CryptoCore, KEY_BYTES, LocalCryptoCore};
///
/// let crypto = LocalCryptoCore;
/// let key = crypto.generate_random_key();
///
/// assert_eq!(key.expose().len(), KEY_BYTES);
/// ```
#[derive(Debug, Default)]
pub struct LocalCryptoCore;

impl CryptoCore for LocalCryptoCore {
    fn generate_random_key(&self) -> SecretBytes {
        let mut bytes = vec![0_u8; KEY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        SecretBytes::new(bytes)
    }

    fn encrypt_record(
        &self,
        master_key: &SecretBytes,
        plaintext: &[u8],
    ) -> Result<EncryptedRecord, CryptoError> {
        let master_cipher = cipher_from_key(master_key)?;
        let record_key = self.generate_random_key();
        let record_cipher = cipher_from_key(&record_key)?;

        let nonce = random_nonce();
        let key_wrapping_nonce = random_nonce();
        let aad = aad_for_version(CRYPTO_VERSION_V1);

        let ciphertext = record_cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let wrapped_record_key = master_cipher
            .encrypt(
                XNonce::from_slice(&key_wrapping_nonce),
                Payload {
                    msg: record_key.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(EncryptedRecord {
            ciphertext,
            wrapped_record_key,
            nonce,
            key_wrapping_nonce,
            crypto_version: CRYPTO_VERSION_V1,
        })
    }

    fn decrypt_record(
        &self,
        master_key: &SecretBytes,
        record: &EncryptedRecord,
    ) -> Result<Vec<u8>, CryptoError> {
        if record.crypto_version != CRYPTO_VERSION_V1 {
            return Err(CryptoError::UnsupportedCryptoVersion);
        }

        let master_cipher = cipher_from_key(master_key)?;
        let aad = aad_for_version(record.crypto_version);

        let record_key_bytes = master_cipher
            .decrypt(
                XNonce::from_slice(&record.key_wrapping_nonce),
                Payload {
                    msg: record.wrapped_record_key.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let record_key = SecretBytes::new(record_key_bytes);
        let record_cipher = cipher_from_key(&record_key)?;

        record_cipher
            .decrypt(
                XNonce::from_slice(&record.nonce),
                Payload {
                    msg: record.ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

/// Backward-compatible alias for code that still imports the initial backend
/// name from early prototypes.
pub type PlaceholderCryptoCore = LocalCryptoCore;

fn cipher_from_key(key: &SecretBytes) -> Result<XChaCha20Poly1305, CryptoError> {
    if key.expose().len() != KEY_BYTES {
        return Err(CryptoError::InvalidKeyLength);
    }

    Ok(XChaCha20Poly1305::new(Key::from_slice(key.expose())))
}

fn random_nonce() -> [u8; NONCE_BYTES] {
    let mut nonce = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn aad_for_version(version: u8) -> [u8; 1] {
    [version]
}

#[cfg(test)]
mod tests {
    use super::{
        CRYPTO_VERSION_V1, CryptoCore, CryptoError, KEY_BYTES, LocalCryptoCore, SecretBytes,
    };

    #[test]
    fn generated_keys_have_expected_size() {
        let crypto = LocalCryptoCore;
        let key = crypto.generate_random_key();
        assert_eq!(key.expose().len(), KEY_BYTES);
    }

    #[test]
    fn generated_keys_are_probabilistically_unique() {
        let crypto = LocalCryptoCore;
        let key_a = crypto.generate_random_key();
        let key_b = crypto.generate_random_key();
        assert_ne!(key_a.expose(), key_b.expose());
    }

    #[test]
    fn encrypt_decrypt_roundtrip_restores_plaintext() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let plaintext = br#"{"service":"GitHub","username":"dev_tim23"}"#;

        let encrypted = crypto
            .encrypt_record(&master_key, plaintext)
            .expect("record should encrypt");
        let decrypted = crypto
            .decrypt_record(&master_key, &encrypted)
            .expect("record should decrypt");

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted.ciphertext, plaintext);
        assert_eq!(encrypted.crypto_version, CRYPTO_VERSION_V1);
    }

    #[test]
    fn decrypt_rejects_wrong_master_key() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let wrong_key = crypto.generate_random_key();
        let encrypted = crypto
            .encrypt_record(&master_key, b"protected record")
            .expect("record should encrypt");

        let result = crypto.decrypt_record(&wrong_key, &encrypted);

        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn decrypt_rejects_modified_ciphertext() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut encrypted = crypto
            .encrypt_record(&master_key, b"protected record")
            .expect("record should encrypt");
        encrypted.ciphertext[0] ^= 0x01;

        let result = crypto.decrypt_record(&master_key, &encrypted);

        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn decrypt_rejects_modified_nonce() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut encrypted = crypto
            .encrypt_record(&master_key, b"protected record")
            .expect("record should encrypt");
        encrypted.nonce[0] ^= 0x01;

        let result = crypto.decrypt_record(&master_key, &encrypted);

        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn decrypt_rejects_corrupted_wrapped_key() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut encrypted = crypto
            .encrypt_record(&master_key, b"protected record")
            .expect("record should encrypt");
        encrypted.wrapped_record_key[0] ^= 0x01;

        let result = crypto.decrypt_record(&master_key, &encrypted);

        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn decrypt_rejects_unsupported_crypto_version() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut encrypted = crypto
            .encrypt_record(&master_key, b"protected record")
            .expect("record should encrypt");
        encrypted.crypto_version = CRYPTO_VERSION_V1 + 1;

        let result = crypto.decrypt_record(&master_key, &encrypted);

        assert_eq!(result, Err(CryptoError::UnsupportedCryptoVersion));
    }

    #[test]
    fn encrypt_rejects_invalid_master_key_length() {
        let crypto = LocalCryptoCore;
        let short_key = SecretBytes::new(vec![0_u8; KEY_BYTES - 1]);

        let result = crypto.encrypt_record(&short_key, b"protected record");

        assert_eq!(result, Err(CryptoError::InvalidKeyLength));
    }
}
