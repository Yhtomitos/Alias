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

/// Email address identity that can be shared by one or more accounts.
///
/// Email values are sensitive identity data. They may be useful for local graph
/// reasoning, but they must be encrypted whenever the graph is persisted outside
/// the unlocked local vault boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailIdentity {
    /// Random opaque identifier for the email identity.
    pub id: Uuid,

    /// Email address value associated with accounts.
    pub email: String,

    /// Optional user-facing label such as "Primary personal email".
    pub label: Option<String>,
}

impl EmailIdentity {
    /// Creates an email identity with a random ID and no label.
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            email: email.into(),
            label: None,
        }
    }
}

/// Username or handle identity that can appear across multiple accounts.
///
/// Username identities support local linkability and persona reasoning without
/// requiring agents to inspect passwords or other credential fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsernameIdentity {
    /// Random opaque identifier for the username identity.
    pub id: Uuid,

    /// Username or handle value.
    pub username: String,

    /// Optional service or context where the username is commonly used.
    pub service_hint: Option<String>,
}

impl UsernameIdentity {
    /// Creates a username identity with a random ID and no service hint.
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            username: username.into(),
            service_hint: None,
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

impl RelationshipType {
    fn is_dependency_edge(&self) -> bool {
        matches!(
            self,
            Self::RecoveryEmail | Self::SsoProvider | Self::Dependency
        )
    }
}

/// Coarse dependency criticality based on reachable account count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CriticalityLevel {
    /// No known accounts depend on this account.
    None,

    /// One or two known accounts depend on this account.
    Low,

    /// Three to seven known accounts depend on this account.
    Medium,

    /// Eight or more known accounts depend on this account.
    High,
}

/// Dependency summary for one account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCriticality {
    /// Account being evaluated.
    pub account_id: Uuid,

    /// Accounts that directly depend on this account through recovery, SSO, or
    /// explicit dependency edges.
    pub direct_dependents: Vec<Uuid>,

    /// Accounts reachable by following dependency edges transitively.
    pub transitive_dependents: Vec<Uuid>,

    /// Coarse criticality level derived from `transitive_dependents`.
    pub level: CriticalityLevel,
}

/// Search result returned by `IdentityGraph::search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphSearchResult {
    /// A matching persona.
    Persona(Uuid),

    /// A matching email identity.
    EmailIdentity(Uuid),

    /// A matching username identity.
    UsernameIdentity(Uuid),
}

/// Directed relationship from one account to another.
///
/// Relationship semantics depend on `relationship_type`. For dependency-like
/// edges, `source_account_id` is the account that depends on or refers to
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

    /// The requested email identity ID does not exist in the graph.
    #[error("email identity not found")]
    EmailIdentityNotFound,

    /// The requested username identity ID does not exist in the graph.
    #[error("username identity not found")]
    UsernameIdentityNotFound,
}

/// In-memory identity graph for account personas and dependencies.
///
/// The graph stores account IDs, persona records, and directed account
/// relationships. It does not validate that account IDs exist in an external
/// vault, so callers must keep vault records and graph edges consistent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityGraph {
    personas: HashMap<Uuid, Persona>,
    email_identities: HashMap<Uuid, EmailIdentity>,
    username_identities: HashMap<Uuid, UsernameIdentity>,
    account_personas: HashMap<Uuid, Uuid>,
    account_email_identities: HashMap<Uuid, Vec<Uuid>>,
    account_username_identities: HashMap<Uuid, Vec<Uuid>>,
    relationships: Vec<AccountRelationship>,
}

impl IdentityGraph {
    /// Adds or replaces a persona by ID.
    pub fn add_persona(&mut self, persona: Persona) {
        self.personas.insert(persona.id, persona);
    }

    /// Returns a persona by ID.
    pub fn persona(&self, persona_id: Uuid) -> Option<&Persona> {
        self.personas.get(&persona_id)
    }

    /// Returns all personas currently stored in the graph.
    ///
    /// Ordering is implementation-defined.
    pub fn personas(&self) -> Vec<&Persona> {
        self.personas.values().collect()
    }

    /// Adds or replaces an email identity by ID.
    pub fn add_email_identity(&mut self, email_identity: EmailIdentity) {
        self.email_identities
            .insert(email_identity.id, email_identity);
    }

    /// Returns an email identity by ID.
    pub fn email_identity(&self, email_identity_id: Uuid) -> Option<&EmailIdentity> {
        self.email_identities.get(&email_identity_id)
    }

    /// Returns all email identities currently stored in the graph.
    ///
    /// Ordering is implementation-defined.
    pub fn email_identities(&self) -> Vec<&EmailIdentity> {
        self.email_identities.values().collect()
    }

    /// Adds or replaces a username identity by ID.
    pub fn add_username_identity(&mut self, username_identity: UsernameIdentity) {
        self.username_identities
            .insert(username_identity.id, username_identity);
    }

    /// Returns a username identity by ID.
    pub fn username_identity(&self, username_identity_id: Uuid) -> Option<&UsernameIdentity> {
        self.username_identities.get(&username_identity_id)
    }

    /// Returns all username identities currently stored in the graph.
    ///
    /// Ordering is implementation-defined.
    pub fn username_identities(&self) -> Vec<&UsernameIdentity> {
        self.username_identities.values().collect()
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

    /// Links an account to an existing email identity.
    ///
    /// Returns `GraphError::EmailIdentityNotFound` if `email_identity_id` has
    /// not been added to the graph. Linking the same account and email identity
    /// more than once is idempotent.
    pub fn link_account_to_email_identity(
        &mut self,
        account_id: Uuid,
        email_identity_id: Uuid,
    ) -> Result<(), GraphError> {
        if !self.email_identities.contains_key(&email_identity_id) {
            return Err(GraphError::EmailIdentityNotFound);
        }

        push_unique(
            self.account_email_identities.entry(account_id).or_default(),
            email_identity_id,
        );
        Ok(())
    }

    /// Links an account to an existing username identity.
    ///
    /// Returns `GraphError::UsernameIdentityNotFound` if `username_identity_id`
    /// has not been added to the graph. Linking the same account and username
    /// identity more than once is idempotent.
    pub fn link_account_to_username_identity(
        &mut self,
        account_id: Uuid,
        username_identity_id: Uuid,
    ) -> Result<(), GraphError> {
        if !self.username_identities.contains_key(&username_identity_id) {
            return Err(GraphError::UsernameIdentityNotFound);
        }

        push_unique(
            self.account_username_identities
                .entry(account_id)
                .or_default(),
            username_identity_id,
        );
        Ok(())
    }

    /// Returns email identities linked to an account.
    ///
    /// Missing identity references are ignored so callers can recover from
    /// partially migrated graph data.
    pub fn email_identities_for_account(&self, account_id: Uuid) -> Vec<&EmailIdentity> {
        self.account_email_identities
            .get(&account_id)
            .into_iter()
            .flatten()
            .filter_map(|email_identity_id| self.email_identities.get(email_identity_id))
            .collect()
    }

    /// Returns username identities linked to an account.
    ///
    /// Missing identity references are ignored so callers can recover from
    /// partially migrated graph data.
    pub fn username_identities_for_account(&self, account_id: Uuid) -> Vec<&UsernameIdentity> {
        self.account_username_identities
            .get(&account_id)
            .into_iter()
            .flatten()
            .filter_map(|username_identity_id| self.username_identities.get(username_identity_id))
            .collect()
    }

    /// Returns accounts linked to an email identity.
    ///
    /// Ordering is implementation-defined.
    pub fn accounts_for_email_identity(&self, email_identity_id: Uuid) -> Vec<Uuid> {
        accounts_for_identity(&self.account_email_identities, email_identity_id)
    }

    /// Returns accounts linked to a username identity.
    ///
    /// Ordering is implementation-defined.
    pub fn accounts_for_username_identity(&self, username_identity_id: Uuid) -> Vec<Uuid> {
        accounts_for_identity(&self.account_username_identities, username_identity_id)
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

    /// Returns relationships whose target account matches `account_id`.
    ///
    /// References are returned in insertion order.
    pub fn relationships_to(&self, account_id: Uuid) -> Vec<&AccountRelationship> {
        self.relationships
            .iter()
            .filter(|relationship| relationship.target_account_id == account_id)
            .collect()
    }

    /// Finds accounts that point at `root_account_id` through any relationship
    /// type, then continues transitively through incoming relationships.
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
    /// let account = Uuid::new_v4();
    /// let recovery_email = Uuid::new_v4();
    ///
    /// graph.add_relationship(AccountRelationship::new(
    ///     account,
    ///     recovery_email,
    ///     RelationshipType::RecoveryEmail,
    /// ));
    ///
    /// assert_eq!(graph.dependent_accounts(recovery_email), vec![account]);
    /// ```
    pub fn dependent_accounts(&self, root_account_id: Uuid) -> Vec<Uuid> {
        self.reachable_accounts(root_account_id, |_| true)
    }

    /// Finds accounts that depend on `root_account_id` through recovery, SSO,
    /// or explicit dependency edges.
    ///
    /// The graph convention is `source_account_id` depends on
    /// `target_account_id`. This method walks incoming dependency edges so a
    /// caller can ask, for example, which accounts depend on a particular email
    /// or SSO provider account.
    pub fn dependency_dependents(&self, root_account_id: Uuid) -> Vec<Uuid> {
        self.reachable_accounts(root_account_id, RelationshipType::is_dependency_edge)
    }

    /// Calculates direct and transitive dependency criticality for an account.
    pub fn account_criticality(&self, account_id: Uuid) -> AccountCriticality {
        let direct_dependents = self
            .relationships_to(account_id)
            .into_iter()
            .filter(|relationship| relationship.relationship_type.is_dependency_edge())
            .map(|relationship| relationship.source_account_id)
            .collect();
        let transitive_dependents = self.dependency_dependents(account_id);
        let level = CriticalityLevel::from_dependent_count(transitive_dependents.len());

        AccountCriticality {
            account_id,
            direct_dependents,
            transitive_dependents,
            level,
        }
    }

    /// Searches personas, email identities, and username identities.
    ///
    /// Search is case-insensitive and matches persona names, descriptions, tags,
    /// email values, email labels, username values, and username service hints.
    /// Account IDs are not searched because account display data lives in the
    /// vault record payload.
    pub fn search(&self, query: &str) -> Vec<GraphSearchResult> {
        let normalized_query = normalize_search_text(query);
        if normalized_query.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();

        for persona in self.personas.values() {
            if matches_any(
                &normalized_query,
                [
                    Some(persona.name.as_str()),
                    persona.description.as_deref(),
                    tags_as_search_text(&persona.tags).as_deref(),
                ],
            ) {
                results.push(GraphSearchResult::Persona(persona.id));
            }
        }

        for email_identity in self.email_identities.values() {
            if matches_any(
                &normalized_query,
                [
                    Some(email_identity.email.as_str()),
                    email_identity.label.as_deref(),
                    None,
                ],
            ) {
                results.push(GraphSearchResult::EmailIdentity(email_identity.id));
            }
        }

        for username_identity in self.username_identities.values() {
            if matches_any(
                &normalized_query,
                [
                    Some(username_identity.username.as_str()),
                    username_identity.service_hint.as_deref(),
                    None,
                ],
            ) {
                results.push(GraphSearchResult::UsernameIdentity(username_identity.id));
            }
        }

        results
    }

    fn reachable_accounts<F>(&self, root_account_id: Uuid, include_edge: F) -> Vec<Uuid>
    where
        F: Fn(&RelationshipType) -> bool,
    {
        let mut queue = VecDeque::from([root_account_id]);
        let mut visited = HashSet::new();
        visited.insert(root_account_id);

        while let Some(current) = queue.pop_front() {
            for relationship in self.relationships_to(current) {
                if include_edge(&relationship.relationship_type)
                    && visited.insert(relationship.source_account_id)
                {
                    queue.push_back(relationship.source_account_id);
                }
            }
        }

        visited.remove(&root_account_id);
        visited.into_iter().collect()
    }
}

impl CriticalityLevel {
    fn from_dependent_count(count: usize) -> Self {
        match count {
            0 => Self::None,
            1..=2 => Self::Low,
            3..=7 => Self::Medium,
            _ => Self::High,
        }
    }
}

fn push_unique(values: &mut Vec<Uuid>, value: Uuid) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn accounts_for_identity(
    account_identities: &HashMap<Uuid, Vec<Uuid>>,
    identity_id: Uuid,
) -> Vec<Uuid> {
    account_identities
        .iter()
        .filter_map(|(account_id, identity_ids)| {
            if identity_ids.contains(&identity_id) {
                Some(*account_id)
            } else {
                None
            }
        })
        .collect()
}

fn normalize_search_text(value: &str) -> String {
    value.trim().to_lowercase()
}

fn matches_any<const N: usize>(normalized_query: &str, candidates: [Option<&str>; N]) -> bool {
    candidates
        .into_iter()
        .flatten()
        .any(|candidate| normalize_search_text(candidate).contains(normalized_query))
}

fn tags_as_search_text(tags: &[String]) -> Option<String> {
    if tags.is_empty() {
        None
    } else {
        Some(tags.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountRelationship, CriticalityLevel, EmailIdentity, GraphError, GraphSearchResult,
        IdentityGraph, Persona, RelationshipType, UsernameIdentity,
    };
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

        let dependents = graph.dependent_accounts(c);
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&a));
        assert!(dependents.contains(&b));
    }

    #[test]
    fn email_and_username_identities_link_accounts() {
        let mut graph = IdentityGraph::default();
        let account_id = Uuid::new_v4();
        let email_identity = EmailIdentity::new("example@example.com");
        let email_identity_id = email_identity.id;
        let username_identity = UsernameIdentity::new("dev_tim23");
        let username_identity_id = username_identity.id;

        graph.add_email_identity(email_identity);
        graph.add_username_identity(username_identity);

        graph
            .link_account_to_email_identity(account_id, email_identity_id)
            .expect("email identity should exist");
        graph
            .link_account_to_email_identity(account_id, email_identity_id)
            .expect("linking again should be idempotent");
        graph
            .link_account_to_username_identity(account_id, username_identity_id)
            .expect("username identity should exist");

        assert_eq!(
            graph.accounts_for_email_identity(email_identity_id),
            vec![account_id]
        );
        assert_eq!(
            graph
                .email_identities_for_account(account_id)
                .first()
                .expect("email identity should be linked")
                .email,
            "example@example.com"
        );
        assert_eq!(
            graph
                .username_identities_for_account(account_id)
                .first()
                .expect("username identity should be linked")
                .username,
            "dev_tim23"
        );
    }

    #[test]
    fn linking_unknown_identities_fails() {
        let mut graph = IdentityGraph::default();
        let account_id = Uuid::new_v4();

        assert_eq!(
            graph.link_account_to_email_identity(account_id, Uuid::new_v4()),
            Err(GraphError::EmailIdentityNotFound)
        );
        assert_eq!(
            graph.link_account_to_username_identity(account_id, Uuid::new_v4()),
            Err(GraphError::UsernameIdentityNotFound)
        );
    }

    #[test]
    fn dependency_dependents_ignore_non_dependency_edges() {
        let mut graph = IdentityGraph::default();
        let provider = Uuid::new_v4();
        let sso_account = Uuid::new_v4();
        let duplicate_candidate = Uuid::new_v4();

        graph.add_relationship(AccountRelationship::new(
            sso_account,
            provider,
            RelationshipType::SsoProvider,
        ));
        graph.add_relationship(AccountRelationship::new(
            duplicate_candidate,
            provider,
            RelationshipType::DuplicateCandidate,
        ));

        let dependency_dependents = graph.dependency_dependents(provider);

        assert_eq!(dependency_dependents, vec![sso_account]);
        assert!(
            graph
                .dependent_accounts(provider)
                .contains(&duplicate_candidate)
        );
    }

    #[test]
    fn account_criticality_counts_transitive_dependency_edges() {
        let mut graph = IdentityGraph::default();
        let provider = Uuid::new_v4();
        let direct = Uuid::new_v4();
        let indirect = Uuid::new_v4();

        graph.add_relationship(AccountRelationship::new(
            direct,
            provider,
            RelationshipType::SsoProvider,
        ));
        graph.add_relationship(AccountRelationship::new(
            indirect,
            direct,
            RelationshipType::RecoveryEmail,
        ));

        let criticality = graph.account_criticality(provider);

        assert_eq!(criticality.account_id, provider);
        assert_eq!(criticality.direct_dependents, vec![direct]);
        assert_eq!(criticality.transitive_dependents.len(), 2);
        assert!(criticality.transitive_dependents.contains(&direct));
        assert!(criticality.transitive_dependents.contains(&indirect));
        assert_eq!(criticality.level, CriticalityLevel::Low);
    }

    #[test]
    fn search_matches_personas_email_identities_and_username_identities() {
        let mut graph = IdentityGraph::default();
        let mut persona = Persona::new("Professional");
        persona.tags.push("work".to_string());
        let persona_id = persona.id;
        let mut email_identity = EmailIdentity::new("primary@example.com");
        email_identity.label = Some("Personal recovery".to_string());
        let email_identity_id = email_identity.id;
        let mut username_identity = UsernameIdentity::new("dragonTim");
        username_identity.service_hint = Some("Steam".to_string());
        let username_identity_id = username_identity.id;

        graph.add_persona(persona);
        graph.add_email_identity(email_identity);
        graph.add_username_identity(username_identity);

        assert!(
            graph
                .search("WORK")
                .contains(&GraphSearchResult::Persona(persona_id))
        );
        assert!(
            graph
                .search("recovery")
                .contains(&GraphSearchResult::EmailIdentity(email_identity_id))
        );
        assert!(
            graph
                .search("steam")
                .contains(&GraphSearchResult::UsernameIdentity(username_identity_id))
        );
    }
}
