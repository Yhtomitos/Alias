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

## Identity Graph

`identity-graph` stores local graph metadata for personas, email identities,
username identities, and directed account relationships. Account records stay in
`vault-core`; the graph uses opaque account UUIDs so graph queries can reason
about identity boundaries, recovery dependencies, SSO dependencies, and
critical accounts without accessing credential fields.
