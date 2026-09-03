use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(**redacted**)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRecord {
    pub id: Uuid,
    pub identity: IdentityFields,
    pub credentials: CredentialFields,
    pub metadata: RecordMetadata,
    pub relationships: RecordRelationships,
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityFields {
    pub service: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CredentialFields {
    pub password: Option<SecretString>,
    pub totp_secret: Option<SecretString>,
    pub recovery_codes: Vec<SecretString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecordMetadata {
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RecordRelationships {
    pub persona_id: Option<Uuid>,
    pub recovery_account_ids: Vec<Uuid>,
    pub sso_provider_account_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: SecretString,
}

impl VaultRecord {
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("record not found")]
    RecordNotFound,
    #[error("record already exists")]
    RecordAlreadyExists,
    #[error("vault is already unlocked")]
    AlreadyUnlocked,
    #[error("vault is already locked")]
    AlreadyLocked,
}

pub trait VaultService {
    fn create_record(&mut self, record: VaultRecord) -> Result<(), VaultError>;
    fn get_record(&self, id: Uuid) -> Result<VaultRecord, VaultError>;
    fn list_records(&self) -> Result<Vec<VaultRecord>, VaultError>;
    fn update_record(&mut self, record: VaultRecord) -> Result<(), VaultError>;
    fn delete_record(&mut self, id: Uuid) -> Result<(), VaultError>;
    fn lock(&mut self) -> Result<(), VaultError>;
    fn unlock(&mut self) -> Result<(), VaultError>;
}

#[derive(Debug, Default)]
pub struct InMemoryVaultService {
    records: HashMap<Uuid, VaultRecord>,
    locked: bool,
}

impl InMemoryVaultService {
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
        self.records.get(&id).cloned().ok_or(VaultError::RecordNotFound)
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
        self.records.remove(&id).map(|_| ()).ok_or(VaultError::RecordNotFound)
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
        let restored: VaultRecord = serde_json::from_str(&serialized).expect("record should deserialize");

        assert_eq!(record, restored);
    }

    #[test]
    fn in_memory_vault_crud_and_locking() {
        let mut service = InMemoryVaultService::new();
        service.unlock().expect("vault should unlock");

        let record = VaultRecord::new("Discord");
        let id = record.id;
        service.create_record(record).expect("record should be inserted");
        assert!(service.get_record(id).is_ok());

        service.lock().expect("vault should lock");
        assert!(service.list_records().is_err());
    }
}
