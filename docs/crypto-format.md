# Crypto Format

The initial local vault format uses client-side envelope encryption. Each
`VaultRecord` is serialized as JSON and encrypted before it enters the local
encrypted record store.

## Version 1

Version 1 uses:

- XChaCha20-Poly1305 for authenticated record encryption.
- A fresh random 32-byte data key for each record.
- XChaCha20-Poly1305 to wrap each record data key with the vault master key.
- A 24-byte record encryption nonce.
- A separate 24-byte key-wrapping nonce.
- The one-byte crypto version as associated data for both encryption steps.

The serialized encrypted record contains only:

- ciphertext
- wrapped record key
- record nonce
- key-wrapping nonce
- crypto version

Plaintext service names, usernames, emails, passwords, notes, custom secret
fields, and relationship metadata are part of the protected payload and must not
be stored beside the encrypted record.

## Security Assumptions

Callers must provide a 32-byte master vault key generated from cryptographically
secure randomness or a future documented key-derivation workflow. The current
prototype keeps the master key in process memory while the encrypted vault
service exists; OS secure storage and key derivation are still future work.

Decryption fails when ciphertext, nonces, wrapped keys, or crypto version
metadata are modified. Unsupported crypto versions are rejected rather than
silently downgraded.
