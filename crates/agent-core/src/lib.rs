use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use uuid::Uuid;

pub trait Agent {
    fn id(&self) -> &'static str;
    fn required_permissions(&self) -> AgentPermissions;
    fn analyze(&self, context: &AgentContext) -> Result<Vec<Recommendation>, AgentError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentPermissions {
    pub service: bool,
    pub username: bool,
    pub email: bool,
    pub persona: bool,
    pub tags: bool,
    pub relationships: bool,
    pub password: bool,
    pub totp_secret: bool,
    pub recovery_codes: bool,
}

impl AgentPermissions {
    pub fn username_persona_defaults() -> Self {
        Self {
            service: true,
            username: true,
            persona: true,
            tags: true,
            relationships: true,
            ..Self::default()
        }
    }

    pub fn allows(&self, required: &AgentPermissions) -> bool {
        (!required.service || self.service)
            && (!required.username || self.username)
            && (!required.email || self.email)
            && (!required.persona || self.persona)
            && (!required.tags || self.tags)
            && (!required.relationships || self.relationships)
            && (!required.password || self.password)
            && (!required.totp_secret || self.totp_secret)
            && (!required.recovery_codes || self.recovery_codes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    pub record_id: Uuid,
    pub service: String,
    pub username: Option<String>,
    pub persona: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentContext {
    pub permissions: AgentPermissions,
    pub accounts: Vec<AccountView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub agent_id: String,
    pub title: String,
    pub description: String,
    pub confidence: f32,
    pub reasons: Vec<String>,
    pub affected_record_ids: Vec<Uuid>,
    pub action: RecommendedAction,
    pub requires_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    AssignPersona,
    MergeRecords,
    AddRecoveryMethod,
    ReviewIdentityLinkability,
    EnableMfa,
    ReviewAccount,
    NoAction,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AgentError {
    #[error("agent does not have required permissions")]
    PermissionDenied,
}

pub fn normalize_username(username: &str) -> String {
    username
        .trim()
        .to_lowercase()
        .chars()
        .filter(|char| !char.is_whitespace() && !matches!(char, '_' | '-' | '.'))
        .collect()
}

pub fn normalized_edit_similarity(lhs: &str, rhs: &str) -> f32 {
    let lhs = normalize_username(lhs);
    let rhs = normalize_username(rhs);

    if lhs == rhs {
        return 1.0;
    }
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }

    let distance = strsim::levenshtein(&lhs, &rhs) as f32;
    let longest = lhs.len().max(rhs.len()) as f32;
    1.0 - (distance / longest)
}

pub fn jaro_winkler_similarity(lhs: &str, rhs: &str) -> f32 {
    strsim::jaro_winkler(&normalize_username(lhs), &normalize_username(rhs)) as f32
}

pub fn ngram_similarity(lhs: &str, rhs: &str, n: usize) -> f32 {
    let lhs = normalize_username(lhs);
    let rhs = normalize_username(rhs);

    if lhs.is_empty() || rhs.is_empty() || n == 0 {
        return 0.0;
    }

    let lhs_ngrams = ngrams(&lhs, n);
    let rhs_ngrams = ngrams(&rhs, n);

    if lhs_ngrams.is_empty() || rhs_ngrams.is_empty() {
        return 0.0;
    }

    let intersection = lhs_ngrams.intersection(&rhs_ngrams).count() as f32;
    let union = lhs_ngrams.union(&rhs_ngrams).count() as f32;
    intersection / union
}

fn ngrams(value: &str, n: usize) -> HashSet<String> {
    let characters: Vec<char> = value.chars().collect();
    if characters.len() < n {
        return HashSet::new();
    }

    (0..=characters.len() - n)
        .map(|index| characters[index..index + n].iter().collect())
        .collect()
}

pub fn numeric_suffix_similarity(lhs: &str, rhs: &str) -> f32 {
    match (numeric_suffix(&normalize_username(lhs)), numeric_suffix(&normalize_username(rhs))) {
        (Some(lhs), Some(rhs)) if lhs == rhs => 1.0,
        (Some(_), Some(_)) => 0.0,
        (None, None) => 1.0,
        _ => 0.0,
    }
}

fn numeric_suffix(value: &str) -> Option<&str> {
    let split_at = value
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_ascii_digit())
        .map_or(0, |(index, character)| index + character.len_utf8());

    if split_at >= value.len() {
        return None;
    }

    Some(&value[split_at..])
}

pub fn combined_username_score(lhs: &str, rhs: &str) -> f32 {
    let edit = normalized_edit_similarity(lhs, rhs);
    let jaro = jaro_winkler_similarity(lhs, rhs);
    let ngram = ngram_similarity(lhs, rhs, 2);
    let numeric = numeric_suffix_similarity(lhs, rhs);

    (edit * 0.35) + (jaro * 0.35) + (ngram * 0.20) + (numeric * 0.10)
}

#[derive(Debug, Clone)]
pub struct UsernamePersonaAgent {
    threshold: f32,
}

impl Default for UsernamePersonaAgent {
    fn default() -> Self {
        Self { threshold: 0.85 }
    }
}

impl UsernamePersonaAgent {
    pub fn new(threshold: f32) -> Self {
        Self { threshold }
    }
}

impl Agent for UsernamePersonaAgent {
    fn id(&self) -> &'static str {
        "username_persona"
    }

    fn required_permissions(&self) -> AgentPermissions {
        AgentPermissions::username_persona_defaults()
    }

    fn analyze(&self, context: &AgentContext) -> Result<Vec<Recommendation>, AgentError> {
        let required = self.required_permissions();
        if !context.permissions.allows(&required) {
            return Err(AgentError::PermissionDenied);
        }

        let mut recommendations = Vec::new();
        for (idx, lhs_account) in context.accounts.iter().enumerate() {
            for rhs_account in context.accounts.iter().skip(idx + 1) {
                let (Some(lhs_username), Some(rhs_username)) = (&lhs_account.username, &rhs_account.username) else {
                    continue;
                };

                let score = combined_username_score(lhs_username, rhs_username);
                if score < self.threshold {
                    continue;
                }

                let normalized_match = normalize_username(lhs_username) == normalize_username(rhs_username);
                let matching_suffix = numeric_suffix_similarity(lhs_username, rhs_username) == 1.0;

                let mut reasons = vec![format!(
                    "combined username similarity score is {:.0}%",
                    score * 100.0
                )];
                if normalized_match {
                    reasons.push("same normalized base username".to_string());
                }
                if matching_suffix {
                    reasons.push("matching numeric suffix".to_string());
                }

                recommendations.push(Recommendation {
                    id: format!("{}:{}:{}", self.id(), lhs_account.record_id, rhs_account.record_id),
                    agent_id: self.id().to_string(),
                    title: format!(
                        "Potential persona relationship: {} and {}",
                        lhs_account.service, rhs_account.service
                    ),
                    description: format!(
                        "{} ({}) and {} ({}) likely belong to the same persona",
                        lhs_account.service, lhs_username, rhs_account.service, rhs_username
                    ),
                    confidence: score,
                    reasons,
                    affected_record_ids: vec![lhs_account.record_id, rhs_account.record_id],
                    action: RecommendedAction::AssignPersona,
                    requires_confirmation: true,
                });
            }
        }

        Ok(recommendations)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountView, Agent, AgentContext, AgentError, AgentPermissions, UsernamePersonaAgent, combined_username_score,
        normalize_username,
    };
    use uuid::Uuid;

    #[test]
    fn username_normalization_removes_separators() {
        assert_eq!(normalize_username("Timothy_So"), "timothyso");
        assert_eq!(normalize_username("timothy.so"), "timothyso");
        assert_eq!(normalize_username("  Timothy-So  "), "timothyso");
    }

    #[test]
    fn combined_similarity_is_high_for_minor_variants() {
        let score = combined_username_score("dev_tim23", "devtim23");
        assert!(score >= 0.9);
    }

    #[test]
    fn agent_requires_permissions() {
        let agent = UsernamePersonaAgent::default();
        let context = AgentContext {
            permissions: AgentPermissions::default(),
            accounts: vec![],
        };

        let result = agent.analyze(&context);
        assert_eq!(result, Err(AgentError::PermissionDenied));
    }

    #[test]
    fn recommendation_threshold_is_respected() {
        let agent = UsernamePersonaAgent::new(0.9);
        let context = AgentContext {
            permissions: AgentPermissions::username_persona_defaults(),
            accounts: vec![
                AccountView {
                    record_id: Uuid::new_v4(),
                    service: "GitHub".to_string(),
                    username: Some("dev_tim23".to_string()),
                    persona: None,
                    tags: vec![],
                },
                AccountView {
                    record_id: Uuid::new_v4(),
                    service: "Reddit".to_string(),
                    username: Some("devtim23".to_string()),
                    persona: None,
                    tags: vec![],
                },
            ],
        };

        let recommendations = agent.analyze(&context).expect("analysis should succeed");
        assert_eq!(recommendations.len(), 1);
        assert!(recommendations[0].confidence >= 0.9);
    }
}
