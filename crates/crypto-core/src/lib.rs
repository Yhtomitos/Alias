use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const CRYPTO_VERSION_V1: u8 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(**redacted**)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRecord {
    pub ciphertext: Vec<u8>,
    pub wrapped_record_key: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub crypto_version: u8,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("operation is not implemented yet")]
    NotImplemented,
}

pub trait CryptoCore {
    fn generate_random_key(&self) -> SecretBytes;
    fn encrypt_record(&self, _master_key: &SecretBytes, _plaintext: &[u8]) -> Result<EncryptedRecord, CryptoError>;
    fn decrypt_record(&self, _master_key: &SecretBytes, _record: &EncryptedRecord) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Debug, Default)]
pub struct PlaceholderCryptoCore;

impl CryptoCore for PlaceholderCryptoCore {
    fn generate_random_key(&self) -> SecretBytes {
        let mut bytes = vec![0_u8; KEY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        SecretBytes::new(bytes)
    }

    fn encrypt_record(&self, _master_key: &SecretBytes, _plaintext: &[u8]) -> Result<EncryptedRecord, CryptoError> {
        Err(CryptoError::NotImplemented)
    }

    fn decrypt_record(&self, _master_key: &SecretBytes, _record: &EncryptedRecord) -> Result<Vec<u8>, CryptoError> {
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
