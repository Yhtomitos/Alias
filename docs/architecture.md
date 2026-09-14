# Architecture

This repository uses a Rust workspace with focused crates for crypto, vault domain logic, identity graph operations, and agent orchestration.

## Local Vault

`crypto-core` provides the local authenticated-encryption backend for protected
record payloads. `vault-core` defines plaintext `VaultRecord` values and now
includes `LocalEncryptedVaultService`, which serializes records, encrypts them
through `crypto-core`, and stores only encrypted records outside its unlocked
plaintext cache.

The encrypted service starts locked. While unlocked it supports create, get,
list, update, and delete through the shared `VaultService` trait. Locking clears
the plaintext cache; unlocking decrypts the encrypted store and rejects tampered
or unsupported records.
