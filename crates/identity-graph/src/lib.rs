//! Identity graph primitives for personas and account relationships.
//!
//! The graph models how accounts relate to personas and to each other so local
//! agents can reason about dependencies, recovery paths, duplicates, and
//! linkability. Account IDs are opaque UUIDs owned by vault records; this crate
//! does not store plaintext credentials.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;
use uuid::Uuid;

/// A user-defined identity grouping for accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persona {
    /// Random opaque identifier for the persona.
    pub id: Uuid,

    /// User-facing name such as "Professional" or "Gaming".
    pub name: String,

    /// Optional user-facing description of the persona boundary.
    pub description: Option<String>,

    /// User-assigned labels for filtering or agent context.
    pub tags: Vec<String>,
}

impl Persona {
    /// Creates a persona with a random ID and no description or tags.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            tags: Vec::new(),
        }
    }
}

/// Meaning assigned to a directed relationship between two accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipType {
    /// The target account is used as a recovery email for the source account.
    RecoveryEmail,

    /// The target account is used as a single sign-on provider.
    SsoProvider,

    /// The accounts are believed to belong to the same persona.
    SamePersona,

    /// The accounts use usernames that appear related.
    RelatedUsername,

    /// The source account depends on the target account in a general way.
    Dependency,

    /// The accounts may be duplicates and should be reviewed by the user.
    DuplicateCandidate,
}

/// Directed relationship from one account to another.
///
/// Relationship semantics depend on `relationship_type`. Traversal methods
/// treat relationships as directed edges from `source_account_id` to
/// `target_account_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRelationship {
    /// Random opaque identifier for the relationship.
    pub id: Uuid,

    /// Account where the relationship begins.
    pub source_account_id: Uuid,

    /// Account reached by the relationship.
    pub target_account_id: Uuid,

    /// Meaning of the directed edge.
    pub relationship_type: RelationshipType,
}

impl AccountRelationship {
    /// Creates a directed account relationship with a random relationship ID.
    pub fn new(
        source_account_id: Uuid,
        target_account_id: Uuid,
        relationship_type: RelationshipType,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_account_id,
            target_account_id,
            relationship_type,
        }
    }
}

/// Errors returned by graph mutation operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GraphError {
    /// The requested persona ID does not exist in the graph.
    #[error("persona not found")]
    PersonaNotFound,
}

/// In-memory identity graph for account personas and dependencies.
///
/// The graph stores account IDs, persona records, and directed account
/// relationships. It does not validate that account IDs exist in an external
/// vault, so callers must keep vault records and graph edges consistent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityGraph {
    personas: HashMap<Uuid, Persona>,
    account_personas: HashMap<Uuid, Uuid>,
    relationships: Vec<AccountRelationship>,
}

impl IdentityGraph {
    /// Adds or replaces a persona by ID.
    pub fn add_persona(&mut self, persona: Persona) {
        self.personas.insert(persona.id, persona);
    }

    /// Assigns an account to an existing persona.
    ///
    /// Returns `GraphError::PersonaNotFound` if `persona_id` has not been added
    /// to the graph. Reassigning an account replaces the previous persona.
    ///
    /// # Example
    ///
    /// ```
    /// use identity_graph::{IdentityGraph, Persona};
    /// use uuid::Uuid;
    ///
    /// let mut graph = IdentityGraph::default();
    /// let persona = Persona::new("Professional");
    /// let persona_id = persona.id;
    /// let account_id = Uuid::new_v4();
    ///
    /// graph.add_persona(persona);
    /// graph
    ///     .assign_account_to_persona(account_id, persona_id)
    ///     .expect("persona exists");
    ///
    /// assert_eq!(graph.persona_for_account(account_id).unwrap().name, "Professional");
    /// ```
    pub fn assign_account_to_persona(
        &mut self,
        account_id: Uuid,
        persona_id: Uuid,
    ) -> Result<(), GraphError> {
        if !self.personas.contains_key(&persona_id) {
            return Err(GraphError::PersonaNotFound);
        }
        self.account_personas.insert(account_id, persona_id);
        Ok(())
    }

    /// Returns the persona assigned to an account, if one exists.
    pub fn persona_for_account(&self, account_id: Uuid) -> Option<&Persona> {
        let persona_id = self.account_personas.get(&account_id)?;
        self.personas.get(persona_id)
    }

    /// Returns account IDs assigned to a persona.
    ///
    /// Ordering is implementation-defined.
    pub fn accounts_for_persona(&self, persona_id: Uuid) -> Vec<Uuid> {
        self.account_personas
            .iter()
            .filter_map(|(account_id, assigned_persona)| {
                if *assigned_persona == persona_id {
                    Some(*account_id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Adds a directed relationship to the graph.
    ///
    /// This method does not deduplicate relationships or verify that account IDs
    /// exist in a vault.
    pub fn add_relationship(&mut self, relationship: AccountRelationship) {
        self.relationships.push(relationship);
    }

    /// Returns relationships whose source account matches `account_id`.
    ///
    /// References are returned in insertion order.
    pub fn relationships_from(&self, account_id: Uuid) -> Vec<&AccountRelationship> {
        self.relationships
            .iter()
            .filter(|relationship| relationship.source_account_id == account_id)
            .collect()
    }

    /// Finds all accounts reachable from `root_account_id` by following
    /// directed relationships.
    ///
    /// The root account is not included in the result. Cycles are handled by
    /// tracking visited accounts, and ordering is implementation-defined.
    ///
    /// # Example
    ///
    /// ```
    /// use identity_graph::{AccountRelationship, IdentityGraph, RelationshipType};
    /// use uuid::Uuid;
    ///
    /// let mut graph = IdentityGraph::default();
    /// let recovery_email = Uuid::new_v4();
    /// let account = Uuid::new_v4();
    ///
    /// graph.add_relationship(AccountRelationship::new(
    ///     recovery_email,
    ///     account,
    ///     RelationshipType::RecoveryEmail,
    /// ));
    ///
    /// assert_eq!(graph.dependent_accounts(recovery_email), vec![account]);
    /// ```
    pub fn dependent_accounts(&self, root_account_id: Uuid) -> Vec<Uuid> {
        let mut queue = VecDeque::from([root_account_id]);
        let mut visited = HashSet::new();
        visited.insert(root_account_id);

        while let Some(current) = queue.pop_front() {
            for relationship in self.relationships_from(current) {
                if visited.insert(relationship.target_account_id) {
                    queue.push_back(relationship.target_account_id);
                }
            }
        }

        visited.remove(&root_account_id);
        visited.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountRelationship, IdentityGraph, Persona, RelationshipType};
    use uuid::Uuid;

    #[test]
    fn account_persona_assignment_is_queryable() {
        let mut graph = IdentityGraph::default();
        let persona = Persona::new("Professional");
        let persona_id = persona.id;
        graph.add_persona(persona);

        let account_id = Uuid::new_v4();
        graph
            .assign_account_to_persona(account_id, persona_id)
            .expect("persona should exist");

        assert_eq!(graph.accounts_for_persona(persona_id), vec![account_id]);
    }

    #[test]
    fn dependency_traversal_finds_transitive_dependents() {
        let mut graph = IdentityGraph::default();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        graph.add_relationship(AccountRelationship::new(a, b, RelationshipType::Dependency));
        graph.add_relationship(AccountRelationship::new(
            b,
            c,
            RelationshipType::RecoveryEmail,
        ));

        let dependents = graph.dependent_accounts(a);
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&b));
        assert!(dependents.contains(&c));
    }
}
