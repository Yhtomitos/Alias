use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persona {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

impl Persona {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            description: None,
            tags: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipType {
    RecoveryEmail,
    SsoProvider,
    SamePersona,
    RelatedUsername,
    Dependency,
    DuplicateCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRelationship {
    pub id: Uuid,
    pub source_account_id: Uuid,
    pub target_account_id: Uuid,
    pub relationship_type: RelationshipType,
}

impl AccountRelationship {
    pub fn new(source_account_id: Uuid, target_account_id: Uuid, relationship_type: RelationshipType) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_account_id,
            target_account_id,
            relationship_type,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GraphError {
    #[error("persona not found")]
    PersonaNotFound,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityGraph {
    personas: HashMap<Uuid, Persona>,
    account_personas: HashMap<Uuid, Uuid>,
    relationships: Vec<AccountRelationship>,
}

impl IdentityGraph {
    pub fn add_persona(&mut self, persona: Persona) {
        self.personas.insert(persona.id, persona);
    }

    pub fn assign_account_to_persona(&mut self, account_id: Uuid, persona_id: Uuid) -> Result<(), GraphError> {
        if !self.personas.contains_key(&persona_id) {
            return Err(GraphError::PersonaNotFound);
        }
        self.account_personas.insert(account_id, persona_id);
        Ok(())
    }

    pub fn persona_for_account(&self, account_id: Uuid) -> Option<&Persona> {
        let persona_id = self.account_personas.get(&account_id)?;
        self.personas.get(persona_id)
    }

    pub fn accounts_for_persona(&self, persona_id: Uuid) -> Vec<Uuid> {
        self.account_personas
            .iter()
            .filter_map(|(account_id, assigned_persona)| if *assigned_persona == persona_id { Some(*account_id) } else { None })
            .collect()
    }

    pub fn add_relationship(&mut self, relationship: AccountRelationship) {
        self.relationships.push(relationship);
    }

    pub fn relationships_from(&self, account_id: Uuid) -> Vec<&AccountRelationship> {
        self.relationships
            .iter()
            .filter(|relationship| relationship.source_account_id == account_id)
            .collect()
    }

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
        graph.add_relationship(AccountRelationship::new(b, c, RelationshipType::RecoveryEmail));

        let dependents = graph.dependent_accounts(a);
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&b));
        assert!(dependents.contains(&c));
    }
}
