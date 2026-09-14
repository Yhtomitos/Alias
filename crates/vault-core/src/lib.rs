//! Core vault data model and service contracts.
//!
//! The types in this crate describe plaintext account records after a vault has
//! been unlocked. Storage implementations must keep these values local or
//! encrypted before persistence or synchronization. Debug output for explicit
//! secret fields is redacted, but ordinary identity and metadata fields may
//! still contain user-sensitive information.

use crypto_core::{CryptoCore, CryptoError, EncryptedRecord, SecretBytes};
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

    /// A record could not be serialized before encryption or parsed after decryption.
    #[error("record serialization failed")]
    SerializationFailed,

    /// Encryption, decryption, key wrapping, or authentication failed.
    #[error("cryptographic operation failed")]
    CryptoOperationFailed,
}

impl From<CryptoError> for VaultError {
    fn from(_error: CryptoError) -> Self {
        Self::CryptoOperationFailed
    }
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

/// Local vault service that keeps its durable record store encrypted.
///
/// Records are serialized as JSON and encrypted through `crypto-core` before
/// they enter the backing map. While unlocked, the service keeps a plaintext
/// cache so callers can use ordinary CRUD operations. Locking clears that cache
/// and gates all plaintext access; unlocking decrypts every stored record with
/// the configured master key. This prototype keeps the master key in process
/// memory until OS secure storage integration exists.
#[derive(Debug)]
pub struct LocalEncryptedVaultService<C> {
    crypto: C,
    master_key: SecretBytes,
    encrypted_records: HashMap<Uuid, EncryptedRecord>,
    unlocked_records: Option<HashMap<Uuid, VaultRecord>>,
}

impl<C> LocalEncryptedVaultService<C>
where
    C: CryptoCore,
{
    /// Creates a locked encrypted vault service using the provided crypto
    /// backend and master key.
    ///
    /// The service starts with an empty encrypted store. Call `unlock` before
    /// creating, reading, updating, or deleting plaintext records.
    pub fn new(crypto: C, master_key: SecretBytes) -> Self {
        Self {
            crypto,
            master_key,
            encrypted_records: HashMap::new(),
            unlocked_records: None,
        }
    }

    /// Creates a locked encrypted vault service from an existing encrypted
    /// record store.
    ///
    /// The provided records are not decrypted until `unlock` is called. This is
    /// the handoff point for future file, database, or sync adapters that load
    /// encrypted records from disk or another opaque storage backend.
    pub fn from_encrypted_records(
        crypto: C,
        master_key: SecretBytes,
        encrypted_records: HashMap<Uuid, EncryptedRecord>,
    ) -> Self {
        Self {
            crypto,
            master_key,
            encrypted_records,
            unlocked_records: None,
        }
    }

    /// Returns the encrypted records currently held by the local backing store.
    ///
    /// This exposes ciphertext and metadata only. It is intended for persistence
    /// adapters, sync adapters, and tests that need to verify that plaintext
    /// records are not stored outside the unlocked cache.
    pub fn encrypted_records(&self) -> &HashMap<Uuid, EncryptedRecord> {
        &self.encrypted_records
    }

    fn ensure_unlocked_records(&self) -> Result<&HashMap<Uuid, VaultRecord>, VaultError> {
        self.unlocked_records.as_ref().ok_or(VaultError::Locked)
    }

    fn ensure_unlocked_records_mut(
        &mut self,
    ) -> Result<&mut HashMap<Uuid, VaultRecord>, VaultError> {
        self.unlocked_records.as_mut().ok_or(VaultError::Locked)
    }

    fn encrypt_for_storage(&self, record: &VaultRecord) -> Result<EncryptedRecord, VaultError> {
        let plaintext = serde_json::to_vec(record).map_err(|_| VaultError::SerializationFailed)?;
        self.crypto
            .encrypt_record(&self.master_key, &plaintext)
            .map_err(VaultError::from)
    }

    fn decrypt_from_storage(&self, record: &EncryptedRecord) -> Result<VaultRecord, VaultError> {
        let plaintext = self.crypto.decrypt_record(&self.master_key, record)?;
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::SerializationFailed)
    }
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

impl<C> VaultService for LocalEncryptedVaultService<C>
where
    C: CryptoCore,
{
    fn create_record(&mut self, record: VaultRecord) -> Result<(), VaultError> {
        let records = self.ensure_unlocked_records()?;
        if records.contains_key(&record.id) {
            return Err(VaultError::RecordAlreadyExists);
        }

        let encrypted = self.encrypt_for_storage(&record)?;
        self.encrypted_records.insert(record.id, encrypted);
        self.ensure_unlocked_records_mut()?
            .insert(record.id, record);
        Ok(())
    }

    fn get_record(&self, id: Uuid) -> Result<VaultRecord, VaultError> {
        self.ensure_unlocked_records()?
            .get(&id)
            .cloned()
            .ok_or(VaultError::RecordNotFound)
    }

    fn list_records(&self) -> Result<Vec<VaultRecord>, VaultError> {
        Ok(self.ensure_unlocked_records()?.values().cloned().collect())
    }

    fn update_record(&mut self, record: VaultRecord) -> Result<(), VaultError> {
        let records = self.ensure_unlocked_records()?;
        if !records.contains_key(&record.id) {
            return Err(VaultError::RecordNotFound);
        }

        let encrypted = self.encrypt_for_storage(&record)?;
        self.encrypted_records.insert(record.id, encrypted);
        self.ensure_unlocked_records_mut()?
            .insert(record.id, record);
        Ok(())
    }

    fn delete_record(&mut self, id: Uuid) -> Result<(), VaultError> {
        let records = self.ensure_unlocked_records()?;
        if !records.contains_key(&id) {
            return Err(VaultError::RecordNotFound);
        }

        self.encrypted_records.remove(&id);
        self.ensure_unlocked_records_mut()?.remove(&id);
        Ok(())
    }

    fn lock(&mut self) -> Result<(), VaultError> {
        if self.unlocked_records.is_none() {
            return Err(VaultError::AlreadyLocked);
        }

        self.unlocked_records = None;
        Ok(())
    }

    fn unlock(&mut self) -> Result<(), VaultError> {
        if self.unlocked_records.is_some() {
            return Err(VaultError::AlreadyUnlocked);
        }

        let mut records = HashMap::new();
        for (id, encrypted) in &self.encrypted_records {
            let record = self.decrypt_from_storage(encrypted)?;
            if record.id != *id {
                return Err(VaultError::SerializationFailed);
            }
            records.insert(*id, record);
        }

        self.unlocked_records = Some(records);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InMemoryVaultService, LocalEncryptedVaultService, SecretString, VaultError, VaultRecord,
        VaultService,
    };
    use crypto_core::{CryptoCore, LocalCryptoCore};
    use uuid::Uuid;

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

    #[test]
    fn local_encrypted_vault_crud_persists_ciphertext_only() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut service = LocalEncryptedVaultService::new(crypto, master_key);
        service.unlock().expect("vault should unlock");

        let mut record = VaultRecord::new("GitHub");
        record.identity.username = Some("dev_tim23".to_string());
        record.credentials.password = Some(SecretString::new("fake-password"));
        let id = record.id;

        service
            .create_record(record)
            .expect("record should be created");

        let stored_json =
            serde_json::to_string(service.encrypted_records()).expect("store should serialize");
        assert!(!stored_json.contains("GitHub"));
        assert!(!stored_json.contains("dev_tim23"));
        assert!(!stored_json.contains("fake-password"));

        let mut updated = service.get_record(id).expect("record should be readable");
        updated.metadata.favorite = true;
        service
            .update_record(updated)
            .expect("record should be updated");
        assert!(
            service
                .get_record(id)
                .expect("record should exist")
                .metadata
                .favorite
        );

        service
            .delete_record(id)
            .expect("record should be deleted from both stores");
        assert_eq!(service.list_records().expect("vault is unlocked").len(), 0);
        assert!(!service.encrypted_records().contains_key(&id));
    }

    #[test]
    fn local_encrypted_vault_lock_unlock_restores_records() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut service = LocalEncryptedVaultService::new(crypto, master_key);
        service.unlock().expect("vault should unlock");

        let record = VaultRecord::new("Discord");
        let id = record.id;
        service
            .create_record(record)
            .expect("record should be stored encrypted");

        service.lock().expect("vault should lock");
        assert_eq!(service.get_record(id), Err(VaultError::Locked));

        service
            .unlock()
            .expect("vault should decrypt stored records");
        assert_eq!(
            service
                .get_record(id)
                .expect("record should decrypt after unlock")
                .identity
                .service,
            "Discord"
        );
    }

    #[test]
    fn local_encrypted_vault_can_start_from_existing_encrypted_records() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut service = LocalEncryptedVaultService::new(crypto, master_key.clone());
        service.unlock().expect("vault should unlock");

        let record = VaultRecord::new("Notion");
        let id = record.id;
        service
            .create_record(record)
            .expect("record should be stored encrypted");
        let encrypted_records = service.encrypted_records().clone();

        let mut restored = LocalEncryptedVaultService::from_encrypted_records(
            LocalCryptoCore,
            master_key,
            encrypted_records,
        );
        restored.unlock().expect("records should decrypt");

        assert_eq!(
            restored
                .get_record(id)
                .expect("record should exist")
                .identity
                .service,
            "Notion"
        );
    }

    #[test]
    fn local_encrypted_vault_rejects_tampered_ciphertext_on_unlock() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut service = LocalEncryptedVaultService::new(crypto, master_key);
        service.unlock().expect("vault should unlock");

        let record = VaultRecord::new("Example");
        let id = record.id;
        service
            .create_record(record)
            .expect("record should be stored encrypted");
        service.lock().expect("vault should lock");

        service
            .encrypted_records
            .get_mut(&id)
            .expect("encrypted record should exist")
            .ciphertext[0] ^= 0x01;

        assert_eq!(service.unlock(), Err(VaultError::CryptoOperationFailed));
    }

    #[test]
    fn local_encrypted_vault_reports_missing_records() {
        let crypto = LocalCryptoCore;
        let master_key = crypto.generate_random_key();
        let mut service = LocalEncryptedVaultService::new(crypto, master_key);
        service.unlock().expect("vault should unlock");

        let missing_id = Uuid::new_v4();
        assert_eq!(
            service.delete_record(missing_id),
            Err(VaultError::RecordNotFound)
        );
        assert_eq!(
            service.update_record(VaultRecord::new("Missing")),
            Err(VaultError::RecordNotFound)
        );
    }
}
