# Encrypted Synchronization Protocol

`sync-core` defines the ciphertext-only protocol boundary used by future AWS and
self-hosted adapters. The current implementation is an in-memory reference
store; it does not provision or contact AWS.

## Trust Boundary

Transport adapters must derive the opaque `owner_id` from verified
authentication claims. They must never accept an owner ID from a request body,
query parameter, or client-selected partition key. Every read and conditional
write must be scoped to that authenticated owner.

The synchronization service may receive only:

- opaque owner and record UUIDs
- encrypted record bytes and key-wrapping metadata
- cryptographic format version and nonces
- record revision, tombstone state, and incremental cursor metadata

It must not receive decrypted `VaultRecord` fields. Authentication permits a
user to access an encrypted partition; it does not provide a vault decryption
key.

## Mutations and Revisions

The serialized `SyncMutation` format uses a tagged `operation` field:

```json
{
  "operation": "upsert",
  "expected_revision": 4,
  "encrypted_record": {
    "ciphertext": [1, 2, 3],
    "wrapped_record_key": [4, 5, 6],
    "nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    "key_wrapping_nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    "crypto_version": 1
  }
}
```

First creation uses `expected_revision: null`. Every subsequent upsert or
delete supplies the exact current revision. Accepted mutations increment the
record revision by one. A mismatch returns `SyncError::Conflict` with the
current revision and leaves state unchanged. This rejects stale device writes
and straightforward replay of an already accepted mutation.

Deletion writes a tombstone with a new revision, `deleted: true`, and no
encrypted payload. Recreating a deleted record requires the tombstone revision,
so an old create request cannot silently resurrect it.

AWS adapters should implement the comparison and mutation as one DynamoDB
conditional write. A suggested key layout remains:

```text
PK = USER#<opaque authenticated owner UUID>
SK = RECORD#<opaque record UUID>
```

## Incremental Download

Each owner has an independent monotonically increasing `server_sequence`.
`changes_since` returns changes after a `SyncCursor`, ordered by sequence, plus
the next cursor and `has_more`. Cursors are owner-scoped metadata, not bearer
credentials. A cursor ahead of the owner's current sequence is rejected.

Pages contain between 1 and 100 changes. Encrypted payload plus wrapped record
key is limited to 1 MiB per record. Transport adapters may impose a smaller
request limit.

Downloaded `SyncRecord` values must pass `validate` before use. Validation
rejects zero revisions or sequences and inconsistent active/tombstone payloads.
Clients must still authenticate ciphertext locally during decryption.

## Security Limits

Optimistic revisions protect against normal concurrent edits and stale-client
replay while the synchronization service is trusted to enforce conditional
writes. In version 1, record revisions and server sequences are not
cryptographically bound to ciphertext. A compromised service could replay an
older valid ciphertext and matching metadata.

Defending against a malicious-server rollback requires a future cryptographic
protocol, such as authenticating record ID and revision as associated data and
maintaining a device-verifiable signed or MACed state commitment. The current
API must not be represented as solving that threat.

The reference store also omits timestamps, durability, authentication, request
rate limiting, and retention/compaction of historical changes. Those belong to
the AWS adapter and infrastructure slices.
