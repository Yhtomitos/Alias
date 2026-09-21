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

## Local Agent Policy

`agent-core` defines local analysis agents and a `PolicyEngine` boundary. The
engine checks an agent's declared field permissions against both configured
policy and available context, redacts undeclared fields before invocation, and
validates each recommendation returned by the agent.

Policy decisions separate informational recommendations from changes requiring
user approval. Persona assignment, record merging, recovery-method changes, and
MFA changes always require approval even if an agent incorrectly marks them as
safe. The policy engine does not execute actions; downstream command boundaries
must independently authorize side effects.

## Local Username Model

The custom username model is trained offline with scikit-learn from synthetic
pairs and exported to versioned JSON plus ONNX. `agent-core` embeds and validates
the JSON logistic coefficients, extracts the same four documented similarity
features, and performs local inference without network access or a native model
runtime. The ONNX artifact provides a portable representation for future
runtime integration and cross-implementation verification.
