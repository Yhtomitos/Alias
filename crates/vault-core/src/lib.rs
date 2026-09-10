//! Core vault data model and service contracts.
//!
//! The types in this crate describe plaintext account records after a vault has
//! been unlocked. Storage implementations must keep these values local or
//! encrypted before persistence or synchronization. Debug output for explicit
//! secret fields is redacted, but ordinary identity and metadata fields may
//! still contain user-sensitive information.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Secret text that redacts itself in debug output.
///
/// This wrapper is intended for passwords, TOTP seeds, recovery codes, security
/// answers, and custom secret values. It does not zeroize memory on drop yet, so
/// callers should avoid unnecessary clones and should keep values out of logs,
/// telemetry, crash reports, and general-purpose AI prompts.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a plaintext secret string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying plaintext secret.
    ///
    /// Exposing the value is intentionally explicit because the result may
    /// contain credentials. Callers must not log or display it unless the user
    /// has specifically requested that secret.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(**redacted**)")
    }
}

/// Plaintext representation of one account or digital identity record.
///
/// A `VaultRecord` is the logical payload that should be serialized and
/// encrypted as a single protected unit before leaving the local process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRecord {
    /// Random opaque identifier used for local references and sync metadata.
    pub id: Uuid,

    /// User-facing account identity fields.
    pub identity: IdentityFields,

    /// Secret credential fields associated with the account.
    pub credentials: CredentialFields,

    /// Optional non-credential metadata.
    pub metadata: RecordMetadata,

    /// Local graph references from this record to personas or other accounts.
    pub relationships: RecordRelationships,

    /// Additional user-defined secret fields.
    pub custom_fields: Vec<CustomField>,
}

/// User-facing account identity fields.
///
/// These fields are not wrapped in `SecretString`, but they can still identify a
/// person. Cloud backends must not receive them in plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityFields {
    /// Service, site, or application name for the account.
    pub service: String,

    /// Optional username or handle.
    pub username: Option<String>,

    /// Optional email identity used with the account.
    pub email: Option<String>,

    /// Optional profile or display name.
    pub display_name: Option<String>,
}

/// Secret credential fields for a vault record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialFields {
    /// Optional password or passphrase.
    pub password: Option<SecretString>,

    /// Optional TOTP seed or equivalent MFA shared secret.
    pub totp_secret: Option<SecretString>,

    /// Stored recovery codes for the account.
    pub recovery_codes: Vec<SecretString>,
}

/// Non-secret metadata used to organize a record.
///
/// Notes may still contain sensitive user-entered text. Treat the whole
/// `VaultRecord` as protected plaintext even when explicit credential fields are
/// empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecordMetadata {
    /// Optional broad category such as development, finance, or gaming.
    pub category: Option<String>,

    /// User-assigned labels for filtering and agent recommendations.
    pub tags: Vec<String>,

    /// Whether the record should be highlighted in ordinary vault views.
    pub favorite: bool,

    /// Optional free-form notes.
    pub notes: Option<String>,
}

/// Graph references stored directly on a vault record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecordRelationships {
    /// Persona assigned to this account, if any.
    pub persona_id: Option<Uuid>,

    /// Accounts that can recover or regain access to this account.
    pub recovery_account_ids: Vec<Uuid>,

    /// Account used as an SSO provider for this account, if any.
    pub sso_provider_account_id: Option<Uuid>,
}

/// User-defined secret field attached to a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    /// User-facing label for the field.
    pub name: String,

    /// Secret value for the field.
    pub value: SecretString,
}

impl VaultRecord {
    /// Creates a new record with a random ID and empty optional fields.
    ///
    /// # Example
    ///
    /// ```
    /// use vault_core::{SecretString, VaultRecord};
    ///
    /// let mut record = VaultRecord::new("GitHub");
    /// record.identity.username = Some("example-user".to_string());
    /// record.credentials.password = Some(SecretString::new("fake-password"));
    ///
    /// assert_eq!(record.identity.service, "GitHub");
    /// ```
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            identity: IdentityFields {
                service: service.into(),
                username: None,
                email: None,
                display_name: None,
            },
            credentials: CredentialFields::default(),
            metadata: RecordMetadata::default(),
            relationships: RecordRelationships::default(),
            custom_fields: Vec::new(),
        }
    }
}

/// Errors returned by vault service operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    /// The vault is locked and cannot expose or modify plaintext records.
    #[error("vault is locked")]
    Locked,

    /// The requested record ID is not present.
    #[error("record not found")]
    RecordNotFound,

    /// A record with the same ID already exists.
    #[error("record already exists")]
    RecordAlreadyExists,

    /// The vault is already unlocked.
    #[error("vault is already unlocked")]
    AlreadyUnlocked,

    /// The vault is already locked.
    #[error("vault is already locked")]
    AlreadyLocked,
}

/// Interface for local vault record storage.
///
/// Implementations must enforce lock state before exposing plaintext records.
/// Persistent or synchronized implementations must encrypt records before
/// writing them outside the unlocked local vault boundary.
pub trait VaultService {
    /// Inserts a new record.
    ///
    /// Fails with `VaultError::Locked` when the vault is locked and
    /// `VaultError::RecordAlreadyExists` when the record ID is already present.
    fn create_record(&mut self, record: VaultRecord) -> Result<(), VaultError>;

    /// Returns a copy of one record by ID.
    ///
    /// Fails with `VaultError::Locked` when the vault is locked and
    /// `VaultError::RecordNotFound` when the ID is unknown.
    fn get_record(&self, id: Uuid) -> Result<VaultRecord, VaultError>;

    /// Returns all records currently available in the vault.
    ///
    /// Ordering is implementation-defined. Fails with `VaultError::Locked` when
    /// the vault is locked.
    fn list_records(&self) -> Result<Vec<VaultRecord>, VaultError>;

    /// Replaces an existing record with the same ID.
    ///
    /// Fails with `VaultError::Locked` when the vault is locked and
    /// `VaultError::RecordNotFound` when the record has not been created.
    fn update_record(&mut self, record: VaultRecord) -> Result<(), VaultError>;

    /// Deletes a record by ID.
    ///
    /// Fails with `VaultError::Locked` when the vault is locked and
    /// `VaultError::RecordNotFound` when the ID is unknown. User-facing callers
    /// must require confirmation before invoking this for destructive actions.
    fn delete_record(&mut self, id: Uuid) -> Result<(), VaultError>;

    /// Locks the vault and prevents plaintext access.
    fn lock(&mut self) -> Result<(), VaultError>;

    /// Unlocks the vault for plaintext access.
    fn unlock(&mut self) -> Result<(), VaultError>;
}

/// Non-persistent vault service used for tests and local prototypes.
///
/// Records are stored in process memory only. Locking gates access through the
/// service API, but it does not encrypt or erase the in-memory map.
#[derive(Debug, Default)]
pub struct InMemoryVaultService {
    records: HashMap<Uuid, VaultRecord>,
    locked: bool,
}

impl InMemoryVaultService {
    /// Creates a new locked in-memory vault.
    ///
    /// # Example
    ///
    /// ```
    /// use vault_core::{InMemoryVaultService, VaultRecord, VaultService};
    ///
    /// let mut vault = InMemoryVaultService::new();
    /// vault.unlock().expect("vault should unlock");
    /// vault
    ///     .create_record(VaultRecord::new("Example Service"))
    ///     .expect("record should be created");
    ///
    /// assert_eq!(vault.list_records().expect("vault is unlocked").len(), 1);
    /// ```
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            locked: true,
        }
    }

    fn ensure_unlocked(&self) -> Result<(), VaultError> {
        if self.locked {
            return Err(VaultError::Locked);
        }
        Ok(())
    }
}

impl VaultService for InMemoryVaultService {
    fn create_record(&mut self, record: VaultRecord) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        if self.records.contains_key(&record.id) {
            return Err(VaultError::RecordAlreadyExists);
        }
        self.records.insert(record.id, record);
        Ok(())
    }

    fn get_record(&self, id: Uuid) -> Result<VaultRecord, VaultError> {
        self.ensure_unlocked()?;
        self.records
            .get(&id)
            .cloned()
            .ok_or(VaultError::RecordNotFound)
    }

    fn list_records(&self) -> Result<Vec<VaultRecord>, VaultError> {
        self.ensure_unlocked()?;
        Ok(self.records.values().cloned().collect())
    }

    fn update_record(&mut self, record: VaultRecord) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        if !self.records.contains_key(&record.id) {
            return Err(VaultError::RecordNotFound);
        }
        self.records.insert(record.id, record);
        Ok(())
    }

    fn delete_record(&mut self, id: Uuid) -> Result<(), VaultError> {
        self.ensure_unlocked()?;
        self.records
            .remove(&id)
            .map(|_| ())
            .ok_or(VaultError::RecordNotFound)
    }

    fn lock(&mut self) -> Result<(), VaultError> {
        if self.locked {
            return Err(VaultError::AlreadyLocked);
        }
        self.locked = true;
        Ok(())
    }

    fn unlock(&mut self) -> Result<(), VaultError> {
        if !self.locked {
            return Err(VaultError::AlreadyUnlocked);
        }
        self.locked = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryVaultService, SecretString, VaultRecord, VaultService};

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretString::new("super-secret");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn vault_record_round_trip_serialization() {
        let mut record = VaultRecord::new("GitHub");
        record.identity.username = Some("dev_tim23".to_string());
        record.credentials.password = Some(SecretString::new("p@ssw0rd"));

        let serialized = serde_json::to_string(&record).expect("record should serialize");
        let restored: VaultRecord =
            serde_json::from_str(&serialized).expect("record should deserialize");

        assert_eq!(record, restored);
    }

    #[test]
    fn in_memory_vault_crud_and_locking() {
        let mut service = InMemoryVaultService::new();
        service.unlock().expect("vault should unlock");

        let record = VaultRecord::new("Discord");
        let id = record.id;
        service
            .create_record(record)
            .expect("record should be inserted");
        assert!(service.get_record(id).is_ok());

        service.lock().expect("vault should lock");
        assert!(service.list_records().is_err());
    }
}
