# Crypto Format

Alias uses client-side envelope encryption for vault records. Sensitive fields
must be serialized into the plaintext record payload locally before encryption;
cloud storage and synchronization should only receive `EncryptedRecord` values.

## Version 1

Version 1 uses XChaCha20-Poly1305 authenticated encryption from RustCrypto.

- `ciphertext`: encrypted plaintext record payload.
- `wrapped_record_key`: fresh per-record data key encrypted under the vault
  master key.
- `nonce`: 24-byte XChaCha20-Poly1305 nonce for the record payload.
- `key_wrapping_nonce`: 24-byte XChaCha20-Poly1305 nonce for record-key
  wrapping.
- `crypto_version`: `1`.

The crypto version is authenticated as associated data for both the payload
ciphertext and wrapped record key. Decryption must fail when authentication
fails, when the master key length is invalid, or when the crypto version is not
supported.
