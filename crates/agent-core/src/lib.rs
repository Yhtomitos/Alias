//! Local agent interfaces and username-persona heuristics.
//!
//! Agents analyze limited vault views and return user-reviewable
//! recommendations. Permission checks are part of the public contract: agents
//! must declare required fields and refuse analysis when the provided context
//! does not grant those fields.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use uuid::Uuid;

/// Local analysis unit that produces recommendations from permitted context.
pub trait Agent {
    /// Stable identifier used in recommendation metadata and permission logs.
    fn id(&self) -> &'static str;

    /// Vault fields required by this agent.
    fn required_permissions(&self) -> AgentPermissions;

    /// Analyzes the provided context and returns recommendations for review.
    ///
    /// Implementations must return `AgentError::PermissionDenied` instead of
    /// inspecting fields that are not granted by `context.permissions`.
    fn analyze(&self, context: &AgentContext) -> Result<Vec<Recommendation>, AgentError>;
}

/// Field-level permission grant for local agents.
///
/// A value of `true` allows the corresponding field family to be present in an
/// `AgentContext`. Secret-bearing permissions such as `password`, `totp_secret`,
/// and `recovery_codes` should remain false unless a specialized local agent has
/// a documented need for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentPermissions {
    /// Allows service names.
    pub service: bool,

    /// Allows usernames and handles.
    pub username: bool,

    /// Allows email identity fields.
    pub email: bool,

    /// Allows persona assignments or persona names.
    pub persona: bool,

    /// Allows user-assigned tags.
    pub tags: bool,

    /// Allows account relationship metadata.
    pub relationships: bool,

    /// Allows plaintext passwords.
    pub password: bool,

    /// Allows TOTP seeds or equivalent MFA shared secrets.
    pub totp_secret: bool,

    /// Allows recovery codes.
    pub recovery_codes: bool,
}

impl AgentPermissions {
    /// Returns the minimum field grant for username-persona analysis.
    ///
    /// This profile deliberately excludes email and credential secrets.
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

    /// Returns whether this grant satisfies all requested permissions.
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

/// Minimal account projection exposed to recommendation agents.
///
/// This view intentionally omits passwords, TOTP secrets, recovery codes, email
/// addresses, and notes. Agents that need additional fields should define a
/// separate context shape and permission profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    /// Opaque vault record ID.
    pub record_id: Uuid,

    /// Service, site, or application name.
    pub service: String,

    /// Username or handle, if the user has stored one.
    pub username: Option<String>,

    /// Persona label available to the agent, if any.
    pub persona: Option<String>,

    /// User-assigned tags available to the agent.
    pub tags: Vec<String>,
}

/// Input data and permission grant for an agent run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentContext {
    /// Permissions granted to the agent for this analysis run.
    pub permissions: AgentPermissions,

    /// Account projections available to the agent.
    pub accounts: Vec<AccountView>,
}

/// User-reviewable result produced by an agent.
///
/// Recommendations are advisory. Any action that changes vault state,
/// relationships, credentials, or security settings must still be confirmed by
/// the user or a higher-level policy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    /// Stable recommendation ID for feedback and deduplication.
    pub id: String,

    /// ID of the agent that produced the recommendation.
    pub agent_id: String,

    /// Short user-facing summary.
    pub title: String,

    /// Longer user-facing explanation of the suggested action.
    pub description: String,

    /// Confidence score in the inclusive range `0.0..=1.0`.
    pub confidence: f32,

    /// Human-readable evidence supporting the recommendation.
    pub reasons: Vec<String>,

    /// Vault record IDs affected by the recommendation.
    pub affected_record_ids: Vec<Uuid>,

    /// Suggested action category.
    pub action: RecommendedAction,

    /// Whether applying the recommendation requires explicit confirmation.
    pub requires_confirmation: bool,
}

/// Category of action recommended by an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// Assign or review persona membership for one or more records.
    AssignPersona,

    /// Merge records after user review.
    MergeRecords,

    /// Add or review a recovery method.
    AddRecoveryMethod,

    /// Review whether accounts are too linkable across personas.
    ReviewIdentityLinkability,

    /// Enable or review multi-factor authentication.
    EnableMfa,

    /// Review an account without a more specific action.
    ReviewAccount,

    /// No state-changing action is recommended.
    NoAction,
}

/// Errors returned by agent analysis.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AgentError {
    /// The supplied context does not grant all permissions required by the agent.
    #[error("agent does not have required permissions")]
    PermissionDenied,
}

/// Normalizes a username for similarity checks.
///
/// Normalization trims surrounding whitespace, lowercases, removes whitespace,
/// and removes `_`, `-`, and `.` separators. The function does not perform
/// Unicode confusable detection or locale-specific normalization.
pub fn normalize_username(username: &str) -> String {
    username
        .trim()
        .to_lowercase()
        .chars()
        .filter(|char| !char.is_whitespace() && !matches!(char, '_' | '-' | '.'))
        .collect()
}

/// Computes normalized Levenshtein similarity for two usernames.
///
/// Inputs are normalized with `normalize_username` first. The return value is in
/// the inclusive range `0.0..=1.0`, where `1.0` means the normalized usernames
/// are identical.
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

/// Computes Jaro-Winkler similarity after username normalization.
///
/// The return value is in the inclusive range `0.0..=1.0`.
pub fn jaro_winkler_similarity(lhs: &str, rhs: &str) -> f32 {
    strsim::jaro_winkler(&normalize_username(lhs), &normalize_username(rhs)) as f32
}

/// Computes Jaccard similarity over character n-grams.
///
/// Inputs are normalized first. Returns `0.0` if either username is empty,
/// `n == 0`, or no n-grams can be produced.
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

/// Compares trailing numeric suffixes after username normalization.
///
/// Returns `1.0` when both usernames have the same numeric suffix or when
/// neither has a numeric suffix. Returns `0.0` when only one side has a suffix
/// or the suffixes differ.
pub fn numeric_suffix_similarity(lhs: &str, rhs: &str) -> f32 {
    match (
        numeric_suffix(&normalize_username(lhs)),
        numeric_suffix(&normalize_username(rhs)),
    ) {
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

/// Combines username similarity signals into a single heuristic score.
///
/// The score is a weighted blend of normalized edit similarity, Jaro-Winkler
/// similarity, bigram Jaccard similarity, and numeric suffix agreement. It is a
/// heuristic for local recommendations, not an identity proof.
///
/// # Example
///
/// ```
/// use agent_core::combined_username_score;
///
/// let score = combined_username_score("dev_tim23", "devtim23");
/// assert!(score > 0.9);
/// ```
pub fn combined_username_score(lhs: &str, rhs: &str) -> f32 {
    let edit = normalized_edit_similarity(lhs, rhs);
    let jaro = jaro_winkler_similarity(lhs, rhs);
    let ngram = ngram_similarity(lhs, rhs, 2);
    let numeric = numeric_suffix_similarity(lhs, rhs);

    (edit * 0.35) + (jaro * 0.35) + (ngram * 0.20) + (numeric * 0.10)
}

/// Agent that recommends persona review for accounts with similar usernames.
///
/// The agent reads only the `AccountView` fields allowed by
/// `AgentPermissions::username_persona_defaults`. Recommendations always require
/// confirmation because persona assignment changes the user's identity graph.
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
    /// Creates an agent with a custom recommendation threshold.
    ///
    /// `threshold` is compared against `combined_username_score`. Values outside
    /// `0.0..=1.0` are accepted as provided; callers should clamp user-provided
    /// configuration before constructing the agent.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_core::{AccountView, Agent, AgentContext, AgentPermissions, UsernamePersonaAgent};
    /// use uuid::Uuid;
    ///
    /// let agent = UsernamePersonaAgent::new(0.85);
    /// let context = AgentContext {
    ///     permissions: AgentPermissions::username_persona_defaults(),
    ///     accounts: vec![
    ///         AccountView {
    ///             record_id: Uuid::new_v4(),
    ///             service: "GitHub".to_string(),
    ///             username: Some("dev_tim23".to_string()),
    ///             persona: None,
    ///             tags: vec![],
    ///         },
    ///         AccountView {
    ///             record_id: Uuid::new_v4(),
    ///             service: "Reddit".to_string(),
    ///             username: Some("devtim23".to_string()),
    ///             persona: None,
    ///             tags: vec![],
    ///         },
    ///     ],
    /// };
    ///
    /// assert_eq!(agent.analyze(&context).unwrap().len(), 1);
    /// ```
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
                let (Some(lhs_username), Some(rhs_username)) =
                    (&lhs_account.username, &rhs_account.username)
                else {
                    continue;
                };

                let score = combined_username_score(lhs_username, rhs_username);
                if score < self.threshold {
                    continue;
                }

                let normalized_match =
                    normalize_username(lhs_username) == normalize_username(rhs_username);
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
                    id: format!(
                        "{}:{}:{}",
                        self.id(),
                        lhs_account.record_id,
                        rhs_account.record_id
                    ),
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
        AccountView, Agent, AgentContext, AgentError, AgentPermissions, UsernamePersonaAgent,
        combined_username_score, normalize_username,
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
