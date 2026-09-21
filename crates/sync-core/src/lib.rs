//! Ciphertext-only synchronization contracts and conflict handling.
//!
//! This crate models the boundary an authenticated AWS adapter will expose. It
//! stores opaque owner and record IDs, encrypted record payloads, revisions,
//! tombstones, and per-owner cursors. It never decrypts vault records.

use crypto_core::EncryptedRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Maximum encrypted payload accepted for one synchronized record.
pub const MAX_ENCRYPTED_RECORD_BYTES: usize = 1024 * 1024;

/// Maximum number of changes returned in one incremental page.
pub const MAX_SYNC_PAGE_SIZE: usize = 100;

/// Opaque synchronization cursor scoped to one authenticated owner.
///
/// Cursors are monotonically increasing server sequence numbers. They are not
/// valid across owners and must not be used as authorization credentials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCursor {
    /// Last server sequence observed by the client.
    pub sequence: u64,
}

/// Ciphertext-only record version returned by synchronization APIs.
///
/// Active records contain `encrypted_record`; tombstones set it to `None`.
/// `revision` increases for every accepted mutation of one record, while
/// `server_sequence` increases for every accepted mutation owned by one user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRecord {
    /// Opaque vault record identifier.
    pub record_id: Uuid,

    /// Monotonic per-record revision, starting at one.
    pub revision: u64,

    /// Monotonic per-owner sequence used for incremental synchronization.
    pub server_sequence: u64,

    /// Encrypted vault record, omitted for deletion tombstones.
    pub encrypted_record: Option<EncryptedRecord>,

    /// Whether this version represents deletion of the record.
    pub deleted: bool,
}

impl SyncRecord {
    /// Validates revision and tombstone invariants after deserialization.
    ///
    /// Transport and database adapters must call this before returning records
    /// loaded from an untrusted or remotely mutable store.
    pub fn validate(&self) -> Result<(), SyncError> {
        let valid_payload_shape = if self.deleted {
            self.encrypted_record.is_none()
        } else {
            self.encrypted_record.is_some()
        };
        if self.revision == 0 || self.server_sequence == 0 || !valid_payload_shape {
            return Err(SyncError::MalformedRecord);
        }
        Ok(())
    }
}

/// Client mutation submitted against an expected server revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum SyncMutation {
    /// Creates or replaces an encrypted record.
    Upsert {
        /// Expected current revision. Use `None` only for first creation.
        expected_revision: Option<u64>,

        /// Ciphertext and cryptographic metadata produced on the client.
        encrypted_record: EncryptedRecord,
    },

    /// Creates a tombstone for an existing record.
    Delete {
        /// Expected current revision.
        expected_revision: u64,
    },
}

/// Incremental page of changes for one authenticated owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPage {
    /// Changes ordered by ascending server sequence.
    pub changes: Vec<SyncRecord>,

    /// Cursor to use for the next request.
    pub next_cursor: SyncCursor,

    /// Whether more changes currently exist after `next_cursor`.
    pub has_more: bool,
}

/// Errors returned by synchronization stores.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyncError {
    /// The expected revision does not match the current record revision.
    #[error("sync conflict; current revision is {current_revision:?}")]
    Conflict {
        /// Current revision, or `None` when the record has never existed.
        current_revision: Option<u64>,
    },

    /// A revision or per-owner sequence cannot be incremented safely.
    #[error("sync revision overflow")]
    RevisionOverflow,

    /// Incremental page size must be greater than zero.
    #[error("sync page size must be between 1 and {MAX_SYNC_PAGE_SIZE}")]
    InvalidPageSize,

    /// The encrypted record exceeds the protocol payload limit.
    #[error("encrypted sync record exceeds {MAX_ENCRYPTED_RECORD_BYTES} bytes")]
    PayloadTooLarge,

    /// The cursor is ahead of the owner's latest server sequence.
    #[error("sync cursor is ahead of the server")]
    InvalidCursor,

    /// A downloaded record violates revision or tombstone invariants.
    #[error("malformed synchronized record")]
    MalformedRecord,
}

/// Storage contract for encrypted per-owner synchronization.
///
/// `owner_id` must come from verified authentication claims in a transport
/// adapter, never from an untrusted request body. Implementations must enforce
/// owner isolation and compare revisions atomically with writes.
pub trait SyncStore {
    /// Applies one encrypted mutation using optimistic concurrency.
    ///
    /// First creation requires `expected_revision: None`. Every later upsert or
    /// deletion must provide the exact current revision. Stale or replayed
    /// mutations return `SyncError::Conflict` without changing stored state.
    fn apply_mutation(
        &mut self,
        owner_id: Uuid,
        record_id: Uuid,
        mutation: SyncMutation,
    ) -> Result<SyncRecord, SyncError>;

    /// Returns changes after an owner-scoped cursor.
    ///
    /// `limit` must be nonzero. A cursor ahead of the owner's current sequence
    /// is rejected instead of silently skipping future events.
    fn changes_since(
        &self,
        owner_id: Uuid,
        cursor: SyncCursor,
        limit: usize,
    ) -> Result<SyncPage, SyncError>;

    /// Returns the current encrypted version of one record for an owner.
    fn current_record(&self, owner_id: Uuid, record_id: Uuid) -> Option<SyncRecord>;
}

#[derive(Debug, Default)]
struct OwnerState {
    records: HashMap<Uuid, SyncRecord>,
    changes: Vec<SyncRecord>,
    latest_sequence: u64,
}

/// In-memory reference implementation of `SyncStore`.
///
/// This store exists for protocol tests and local integration. It models the
/// conditional-write and owner-partition behavior expected from DynamoDB, but
/// it is not durable and does not perform authentication itself.
#[derive(Debug, Default)]
pub struct InMemorySyncStore {
    owners: HashMap<Uuid, OwnerState>,
}

impl InMemorySyncStore {
    /// Creates an empty synchronization store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SyncStore for InMemorySyncStore {
    fn apply_mutation(
        &mut self,
        owner_id: Uuid,
        record_id: Uuid,
        mutation: SyncMutation,
    ) -> Result<SyncRecord, SyncError> {
        if let SyncMutation::Upsert {
            encrypted_record, ..
        } = &mutation
        {
            let payload_size = encrypted_record
                .ciphertext
                .len()
                .checked_add(encrypted_record.wrapped_record_key.len())
                .ok_or(SyncError::PayloadTooLarge)?;
            if payload_size > MAX_ENCRYPTED_RECORD_BYTES {
                return Err(SyncError::PayloadTooLarge);
            }
        }

        let owner = self.owners.entry(owner_id).or_default();
        let current_revision = owner.records.get(&record_id).map(|record| record.revision);
        let expected_revision = match &mutation {
            SyncMutation::Upsert {
                expected_revision, ..
            } => *expected_revision,
            SyncMutation::Delete { expected_revision } => Some(*expected_revision),
        };

        if expected_revision != current_revision {
            return Err(SyncError::Conflict { current_revision });
        }

        let revision = current_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SyncError::RevisionOverflow)?;
        let server_sequence = owner
            .latest_sequence
            .checked_add(1)
            .ok_or(SyncError::RevisionOverflow)?;
        let (encrypted_record, deleted) = match mutation {
            SyncMutation::Upsert {
                encrypted_record, ..
            } => (Some(encrypted_record), false),
            SyncMutation::Delete { .. } => (None, true),
        };
        let record = SyncRecord {
            record_id,
            revision,
            server_sequence,
            encrypted_record,
            deleted,
        };

        owner.latest_sequence = server_sequence;
        owner.records.insert(record_id, record.clone());
        owner.changes.push(record.clone());
        Ok(record)
    }

    fn changes_since(
        &self,
        owner_id: Uuid,
        cursor: SyncCursor,
        limit: usize,
    ) -> Result<SyncPage, SyncError> {
        if limit == 0 || limit > MAX_SYNC_PAGE_SIZE {
            return Err(SyncError::InvalidPageSize);
        }

        let Some(owner) = self.owners.get(&owner_id) else {
            if cursor.sequence > 0 {
                return Err(SyncError::InvalidCursor);
            }
            return Ok(SyncPage {
                changes: Vec::new(),
                next_cursor: cursor,
                has_more: false,
            });
        };
        if cursor.sequence > owner.latest_sequence {
            return Err(SyncError::InvalidCursor);
        }

        let mut pending = owner
            .changes
            .iter()
            .filter(|record| record.server_sequence > cursor.sequence);
        let changes: Vec<SyncRecord> = pending.by_ref().take(limit).cloned().collect();
        let has_more = pending.next().is_some();
        let next_cursor = changes
            .last()
            .map(|record| SyncCursor {
                sequence: record.server_sequence,
            })
            .unwrap_or(cursor);

        Ok(SyncPage {
            changes,
            next_cursor,
            has_more,
        })
    }

    fn current_record(&self, owner_id: Uuid, record_id: Uuid) -> Option<SyncRecord> {
        self.owners.get(&owner_id)?.records.get(&record_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InMemorySyncStore, MAX_ENCRYPTED_RECORD_BYTES, MAX_SYNC_PAGE_SIZE, SyncCursor, SyncError,
        SyncMutation, SyncStore,
    };
    use crypto_core::{CryptoCore, LocalCryptoCore};
    use uuid::Uuid;

    fn encrypted_record(plaintext: &[u8]) -> crypto_core::EncryptedRecord {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        crypto
            .encrypt_record(&master_key, plaintext)
            .expect("fixture should encrypt")
    }

    #[test]
    fn upload_stores_only_ciphertext_and_sync_metadata() {
        let owner_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();

        let stored = store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: None,
                    encrypted_record: encrypted_record(b"private username and password"),
                },
            )
            .expect("first upload should succeed");

        let serialized = serde_json::to_string(&stored).expect("sync record should serialize");
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.server_sequence, 1);
        assert!(!stored.deleted);
        assert!(!serialized.contains("private username and password"));
    }

    #[test]
    fn mutation_wire_format_is_tagged_and_has_no_owner_field() {
        let mutation = SyncMutation::Upsert {
            expected_revision: None,
            encrypted_record: encrypted_record(b"record"),
        };

        let serialized = serde_json::to_value(mutation).expect("mutation should serialize");
        assert_eq!(serialized["operation"], "upsert");
        assert!(serialized.get("expected_revision").is_some());
        assert!(serialized.get("encrypted_record").is_some());
        assert!(serialized.get("owner_id").is_none());
    }

    #[test]
    fn stale_and_replayed_mutations_are_rejected() {
        let owner_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();
        store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: None,
                    encrypted_record: encrypted_record(b"version one"),
                },
            )
            .expect("create should succeed");
        store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: Some(1),
                    encrypted_record: encrypted_record(b"version two"),
                },
            )
            .expect("update should succeed");

        let replay = store.apply_mutation(
            owner_id,
            record_id,
            SyncMutation::Upsert {
                expected_revision: Some(1),
                encrypted_record: encrypted_record(b"replayed version"),
            },
        );

        assert_eq!(
            replay,
            Err(SyncError::Conflict {
                current_revision: Some(2)
            })
        );
        assert_eq!(
            store
                .current_record(owner_id, record_id)
                .expect("record should remain")
                .revision,
            2
        );
    }

    #[test]
    fn deletion_creates_revisioned_tombstone() {
        let owner_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();
        store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: None,
                    encrypted_record: encrypted_record(b"record"),
                },
            )
            .expect("create should succeed");

        let tombstone = store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Delete {
                    expected_revision: 1,
                },
            )
            .expect("delete should succeed");

        assert_eq!(tombstone.revision, 2);
        assert!(tombstone.deleted);
        assert!(tombstone.encrypted_record.is_none());
    }

    #[test]
    fn tombstone_revision_is_required_to_recreate_record() {
        let owner_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();
        store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: None,
                    encrypted_record: encrypted_record(b"record"),
                },
            )
            .expect("create should succeed");
        store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Delete {
                    expected_revision: 1,
                },
            )
            .expect("delete should succeed");

        let stale_create = store.apply_mutation(
            owner_id,
            record_id,
            SyncMutation::Upsert {
                expected_revision: None,
                encrypted_record: encrypted_record(b"stale recreation"),
            },
        );
        assert_eq!(
            stale_create,
            Err(SyncError::Conflict {
                current_revision: Some(2)
            })
        );

        let recreated = store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: Some(2),
                    encrypted_record: encrypted_record(b"approved recreation"),
                },
            )
            .expect("current tombstone revision should permit recreation");
        assert_eq!(recreated.revision, 3);
        assert!(!recreated.deleted);
    }

    #[test]
    fn owners_are_isolated_even_when_record_ids_match() {
        let first_owner = Uuid::new_v4();
        let second_owner = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();

        for owner_id in [first_owner, second_owner] {
            store
                .apply_mutation(
                    owner_id,
                    record_id,
                    SyncMutation::Upsert {
                        expected_revision: None,
                        encrypted_record: encrypted_record(owner_id.as_bytes()),
                    },
                )
                .expect("independent owner record should be created");
        }

        let first_page = store
            .changes_since(first_owner, SyncCursor::default(), 10)
            .expect("first owner should sync");
        let second_page = store
            .changes_since(second_owner, SyncCursor::default(), 10)
            .expect("second owner should sync");
        assert_eq!(first_page.changes.len(), 1);
        assert_eq!(second_page.changes.len(), 1);
        assert_ne!(
            first_page.changes[0].encrypted_record,
            second_page.changes[0].encrypted_record
        );
    }

    #[test]
    fn incremental_pages_advance_owner_scoped_cursor() {
        let owner_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();
        for value in 0..3 {
            store
                .apply_mutation(
                    owner_id,
                    Uuid::new_v4(),
                    SyncMutation::Upsert {
                        expected_revision: None,
                        encrypted_record: encrypted_record(&[value]),
                    },
                )
                .expect("upload should succeed");
        }

        let first = store
            .changes_since(owner_id, SyncCursor::default(), 2)
            .expect("first page should load");
        assert_eq!(first.changes.len(), 2);
        assert!(first.has_more);
        assert_eq!(first.next_cursor.sequence, 2);

        let second = store
            .changes_since(owner_id, first.next_cursor, 2)
            .expect("second page should load");
        assert_eq!(second.changes.len(), 1);
        assert!(!second.has_more);
        assert_eq!(second.next_cursor.sequence, 3);
    }

    #[test]
    fn invalid_cursor_and_page_size_are_rejected() {
        let store = InMemorySyncStore::new();
        let owner_id = Uuid::new_v4();

        assert_eq!(
            store.changes_since(owner_id, SyncCursor::default(), 0),
            Err(SyncError::InvalidPageSize)
        );
        assert_eq!(
            store.changes_since(owner_id, SyncCursor::default(), MAX_SYNC_PAGE_SIZE + 1),
            Err(SyncError::InvalidPageSize)
        );
        assert_eq!(
            store.changes_since(owner_id, SyncCursor { sequence: 1 }, 10),
            Err(SyncError::InvalidCursor)
        );
    }

    #[test]
    fn oversized_encrypted_payload_is_rejected_without_state_change() {
        let owner_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut encrypted = encrypted_record(b"small fixture");
        encrypted.ciphertext = vec![0; MAX_ENCRYPTED_RECORD_BYTES + 1];
        let mut store = InMemorySyncStore::new();

        assert_eq!(
            store.apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: None,
                    encrypted_record: encrypted,
                },
            ),
            Err(SyncError::PayloadTooLarge)
        );
        assert!(store.current_record(owner_id, record_id).is_none());
    }

    #[test]
    fn downloaded_record_validation_rejects_malformed_tombstones() {
        let owner_id = Uuid::new_v4();
        let record_id = Uuid::new_v4();
        let mut store = InMemorySyncStore::new();
        let mut record = store
            .apply_mutation(
                owner_id,
                record_id,
                SyncMutation::Upsert {
                    expected_revision: None,
                    encrypted_record: encrypted_record(b"record"),
                },
            )
            .expect("record should be created");

        assert_eq!(record.validate(), Ok(()));
        record.deleted = true;
        assert_eq!(record.validate(), Err(SyncError::MalformedRecord));
        record.encrypted_record = None;
        record.revision = 0;
        assert_eq!(record.validate(), Err(SyncError::MalformedRecord));
    }
}
