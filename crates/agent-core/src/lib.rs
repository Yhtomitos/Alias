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

impl AgentContext {
    fn scoped_to(&self, permissions: &AgentPermissions) -> Self {
        Self {
            permissions: permissions.clone(),
            accounts: self
                .accounts
                .iter()
                .map(|account| AccountView {
                    record_id: account.record_id,
                    service: if permissions.service {
                        account.service.clone()
                    } else {
                        String::new()
                    },
                    username: permissions
                        .username
                        .then(|| account.username.clone())
                        .flatten(),
                    persona: permissions
                        .persona
                        .then(|| account.persona.clone())
                        .flatten(),
                    tags: if permissions.tags {
                        account.tags.clone()
                    } else {
                        Vec::new()
                    },
                })
                .collect(),
        }
    }
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

impl RecommendedAction {
    fn requires_approval(&self) -> bool {
        match self {
            Self::AssignPersona
            | Self::MergeRecords
            | Self::AddRecoveryMethod
            | Self::EnableMfa => true,
            Self::ReviewIdentityLinkability | Self::ReviewAccount | Self::NoAction => false,
        }
    }
}

/// Errors returned by agent analysis.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AgentError {
    /// The supplied context does not grant all permissions required by the agent.
    #[error("agent does not have required permissions")]
    PermissionDenied,
}

/// Policy decision attached to a validated agent recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// The recommendation is informational and may be shown without approval.
    Allow,

    /// Applying the recommendation could change user data or security settings.
    RequireApproval,
}

/// Recommendation validated and classified by the policy engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    /// Validated recommendation returned by the agent.
    pub recommendation: Recommendation,

    /// Independently computed handling decision.
    pub decision: PolicyDecision,
}

/// Errors raised while enforcing agent policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Either the policy or source context does not grant required fields.
    #[error("agent '{agent_id}' is not permitted to access its required fields")]
    PermissionDenied {
        /// Stable ID of the denied agent.
        agent_id: String,
    },

    /// The agent rejected the policy-scoped context.
    #[error("agent analysis failed: {0}")]
    Agent(#[from] AgentError),

    /// A recommendation claimed a different producing agent.
    #[error("recommendation '{recommendation_id}' has an invalid agent ID")]
    AgentIdentityMismatch {
        /// ID of the invalid recommendation.
        recommendation_id: String,
    },

    /// A recommendation confidence was non-finite or outside `0.0..=1.0`.
    #[error("recommendation '{recommendation_id}' has invalid confidence")]
    InvalidConfidence {
        /// ID of the invalid recommendation.
        recommendation_id: String,
    },

    /// A recommendation did not provide explainable evidence.
    #[error("recommendation '{recommendation_id}' has no reasons")]
    MissingReasons {
        /// ID of the invalid recommendation.
        recommendation_id: String,
    },
}

/// Enforces field access and approval policy around local agent execution.
///
/// The engine checks both its configured maximum grant and the permissions on
/// the source context. It then creates a context containing only fields the
/// agent declared as required. Returned recommendations are validated before
/// they can enter a recommendation queue or user interface.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    granted_permissions: AgentPermissions,
}

impl PolicyEngine {
    /// Creates an engine with the maximum fields agents may access.
    pub fn new(granted_permissions: AgentPermissions) -> Self {
        Self {
            granted_permissions,
        }
    }

    /// Runs an agent against a least-privilege projection of `context`.
    ///
    /// Returns `PolicyError::PermissionDenied` without invoking the agent when
    /// either the engine policy or source context lacks a required field.
    /// Recommendations with invalid identity, confidence, or explainability
    /// metadata are rejected. State-changing actions always require approval,
    /// regardless of the recommendation's own confirmation flag.
    pub fn run(
        &self,
        agent: &dyn Agent,
        context: &AgentContext,
    ) -> Result<Vec<PolicyEvaluation>, PolicyError> {
        let required = agent.required_permissions();
        if !self.granted_permissions.allows(&required) || !context.permissions.allows(&required) {
            return Err(PolicyError::PermissionDenied {
                agent_id: agent.id().to_string(),
            });
        }

        let scoped_context = context.scoped_to(&required);
        agent
            .analyze(&scoped_context)?
            .into_iter()
            .map(|recommendation| self.evaluate(agent.id(), recommendation))
            .collect()
    }

    fn evaluate(
        &self,
        agent_id: &str,
        mut recommendation: Recommendation,
    ) -> Result<PolicyEvaluation, PolicyError> {
        if recommendation.agent_id != agent_id {
            return Err(PolicyError::AgentIdentityMismatch {
                recommendation_id: recommendation.id,
            });
        }
        if !recommendation.confidence.is_finite()
            || !(0.0..=1.0).contains(&recommendation.confidence)
        {
            return Err(PolicyError::InvalidConfidence {
                recommendation_id: recommendation.id,
            });
        }
        if recommendation.reasons.is_empty()
            || recommendation
                .reasons
                .iter()
                .all(|reason| reason.trim().is_empty())
        {
            return Err(PolicyError::MissingReasons {
                recommendation_id: recommendation.id,
            });
        }

        let decision =
            if recommendation.requires_confirmation || recommendation.action.requires_approval() {
                PolicyDecision::RequireApproval
            } else {
                PolicyDecision::Allow
            };
        recommendation.requires_confirmation = decision == PolicyDecision::RequireApproval;

        Ok(PolicyEvaluation {
            recommendation,
            decision,
        })
    }
}

/// Explainable component scores for a pair of usernames.
///
/// Every score is in the inclusive range `0.0..=1.0`. The assessment contains
/// no copies of the input usernames, which lets callers retain only the result
/// without duplicating identity data. A score is evidence of textual
/// similarity, not proof that two accounts belong to the same person.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UsernameSimilarity {
    /// Normalized Levenshtein similarity.
    pub normalized_edit: f32,

    /// Jaro-Winkler similarity after normalization.
    pub jaro_winkler: f32,

    /// Jaccard similarity over normalized character bigrams.
    pub bigram: f32,

    /// Agreement between trailing numeric suffixes.
    pub numeric_suffix: f32,

    /// Weighted aggregate used by the initial username heuristic.
    pub score: f32,
}

const USERNAME_MODEL_FORMAT_VERSION: u32 = 1;
const USERNAME_MODEL_FEATURE_NAMES: [&str; 4] = [
    "normalized_edit",
    "jaro_winkler",
    "bigram",
    "numeric_suffix",
];

/// Errors returned while loading a username similarity model.
#[derive(Debug, Error)]
pub enum UsernameModelError {
    /// The model artifact is not valid JSON.
    #[error("username model is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The artifact uses a format version this client does not understand.
    #[error("unsupported username model format version: {0}")]
    UnsupportedFormat(u32),

    /// The model name is empty.
    #[error("username model name must not be empty")]
    EmptyModelName,

    /// Feature names or ordering do not match the Rust extraction contract.
    #[error("username model feature schema does not match this client")]
    FeatureSchemaMismatch,

    /// A coefficient is missing, non-finite, or otherwise unusable.
    #[error("username model coefficients are invalid")]
    InvalidCoefficients,

    /// The classification threshold is non-finite or outside `0.0..=1.0`.
    #[error("username model threshold is invalid")]
    InvalidThreshold,
}

#[derive(Debug, Deserialize)]
struct SerializedUsernameModel {
    format_version: u32,
    model_name: String,
    feature_names: Vec<String>,
    weights: Vec<f32>,
    bias: f32,
    threshold: f32,
}

/// Validated local logistic-regression model for username pairs.
///
/// The model consumes the same four non-secret similarity signals as the
/// heuristic. It does not retain input usernames or perform network access.
#[derive(Debug, Clone)]
pub struct UsernameSimilarityModel {
    name: String,
    weights: [f32; 4],
    bias: f32,
    threshold: f32,
}

impl UsernameSimilarityModel {
    /// Loads a model from the versioned JSON coefficient format.
    ///
    /// Feature names and order must exactly match `username_model_features`.
    /// All coefficients must be finite, and the threshold must be in
    /// `0.0..=1.0`.
    pub fn from_json(json: &str) -> Result<Self, UsernameModelError> {
        let serialized: SerializedUsernameModel = serde_json::from_str(json)?;
        if serialized.format_version != USERNAME_MODEL_FORMAT_VERSION {
            return Err(UsernameModelError::UnsupportedFormat(
                serialized.format_version,
            ));
        }
        if serialized.model_name.trim().is_empty() {
            return Err(UsernameModelError::EmptyModelName);
        }
        if serialized.feature_names != USERNAME_MODEL_FEATURE_NAMES {
            return Err(UsernameModelError::FeatureSchemaMismatch);
        }

        let weights: [f32; 4] = serialized
            .weights
            .try_into()
            .map_err(|_| UsernameModelError::InvalidCoefficients)?;
        if !serialized.bias.is_finite() || weights.iter().any(|weight| !weight.is_finite()) {
            return Err(UsernameModelError::InvalidCoefficients);
        }
        if !serialized.threshold.is_finite() || !(0.0..=1.0).contains(&serialized.threshold) {
            return Err(UsernameModelError::InvalidThreshold);
        }

        Ok(Self {
            name: serialized.model_name,
            weights,
            bias: serialized.bias,
            threshold: serialized.threshold,
        })
    }

    /// Loads the synthetic logistic baseline embedded in `agent-core`.
    pub fn embedded() -> Result<Self, UsernameModelError> {
        Self::from_json(include_str!(
            "../../../models/username-similarity/model.json"
        ))
    }

    /// Returns the stable model name recorded in recommendations.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the model's classification threshold.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Runs local inference for a username pair.
    ///
    /// The returned explanations describe model inputs and contributions, not
    /// proof that the accounts share an owner. No input usernames are retained
    /// in the prediction.
    pub fn predict(&self, lhs: &str, rhs: &str) -> UsernameModelPrediction {
        let features = username_model_features(lhs, rhs);
        let feature_contributions =
            std::array::from_fn(|index| features[index] * self.weights[index]);
        let logit = self.bias + feature_contributions.iter().sum::<f32>();
        let likelihood = stable_sigmoid(logit);

        let mut ranked_contributions: Vec<(&str, f32)> = USERNAME_MODEL_FEATURE_NAMES
            .iter()
            .copied()
            .zip(feature_contributions)
            .filter(|(_, contribution)| *contribution > 0.0)
            .collect();
        ranked_contributions.sort_by(|lhs, rhs| rhs.1.total_cmp(&lhs.1));
        let mut reasons: Vec<String> = ranked_contributions
            .into_iter()
            .take(2)
            .map(|(feature, contribution)| {
                format!(
                    "{} contributed {:.2} to the model score",
                    feature.replace('_', " "),
                    contribution
                )
            })
            .collect();
        if reasons.is_empty() {
            reasons.push("no positive username similarity signals".to_string());
        }

        UsernameModelPrediction {
            model_name: self.name.clone(),
            likelihood,
            same_persona: likelihood >= self.threshold,
            feature_contributions,
            reasons,
        }
    }
}

/// Result of local inference with the username similarity model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsernameModelPrediction {
    /// Stable name of the model artifact used for inference.
    pub model_name: String,

    /// Model likelihood in the inclusive range `0.0..=1.0`.
    pub likelihood: f32,

    /// Whether likelihood meets the model's stored threshold.
    pub same_persona: bool,

    /// Per-feature weighted contributions in the versioned feature order.
    pub feature_contributions: [f32; 4],

    /// Human-readable descriptions of the strongest positive signals.
    pub reasons: Vec<String>,
}

/// Extracts the versioned feature vector consumed by the username model.
///
/// Feature order is normalized edit, Jaro-Winkler, character bigram overlap,
/// and numeric suffix agreement. Changing this order requires a new model
/// format version and retraining.
pub fn username_model_features(lhs: &str, rhs: &str) -> [f32; 4] {
    let similarity = username_similarity(lhs, rhs);
    [
        similarity.normalized_edit,
        similarity.jaro_winkler,
        similarity.bigram,
        similarity.numeric_suffix,
    ]
}

fn stable_sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exponential = value.exp();
        exponential / (1.0 + exponential)
    }
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
    let longest = lhs.chars().count().max(rhs.chars().count()) as f32;
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

/// Computes an explainable username similarity assessment.
///
/// Inputs are normalized locally and are not retained in the returned value.
/// If either normalized username is empty, every component score is `0.0`.
/// The aggregate is a weighted blend of normalized edit similarity (35%),
/// Jaro-Winkler similarity (35%), bigram Jaccard similarity (20%), and numeric
/// suffix agreement (10%).
///
/// This heuristic does not account for Unicode confusables, transliteration,
/// language-specific rules, or whether two accounts are actually controlled by
/// the same person.
///
/// # Example
///
/// ```
/// use agent_core::username_similarity;
///
/// let assessment = username_similarity("dev_tim23", "devtim23");
/// assert!(assessment.score > 0.9);
/// assert_eq!(assessment.numeric_suffix, 1.0);
/// ```
pub fn username_similarity(lhs: &str, rhs: &str) -> UsernameSimilarity {
    if normalize_username(lhs).is_empty() || normalize_username(rhs).is_empty() {
        return UsernameSimilarity {
            normalized_edit: 0.0,
            jaro_winkler: 0.0,
            bigram: 0.0,
            numeric_suffix: 0.0,
            score: 0.0,
        };
    }

    let normalized_edit = normalized_edit_similarity(lhs, rhs);
    let jaro_winkler = jaro_winkler_similarity(lhs, rhs);
    let bigram = ngram_similarity(lhs, rhs, 2);
    let numeric_suffix = numeric_suffix_similarity(lhs, rhs);
    let score = (normalized_edit * 0.35)
        + (jaro_winkler * 0.35)
        + (bigram * 0.20)
        + (numeric_suffix * 0.10);

    UsernameSimilarity {
        normalized_edit,
        jaro_winkler,
        bigram,
        numeric_suffix,
        score: score.clamp(0.0, 1.0),
    }
}

/// Combines username similarity signals into a single heuristic score.
///
/// This convenience API returns the aggregate from `username_similarity`. It is
/// a heuristic for local recommendations, not an identity proof. Empty or
/// separator-only inputs score `0.0`.
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
    username_similarity(lhs, rhs).score
}

/// Agent that recommends persona review for accounts with similar usernames.
///
/// The agent reads only the `AccountView` fields allowed by
/// `AgentPermissions::username_persona_defaults`. Recommendations always require
/// confirmation because persona assignment changes the user's identity graph.
#[derive(Debug, Clone)]
pub struct UsernamePersonaAgent {
    threshold: f32,
    model: Option<UsernameSimilarityModel>,
}

impl Default for UsernamePersonaAgent {
    fn default() -> Self {
        Self {
            threshold: 0.85,
            model: None,
        }
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
        Self {
            threshold,
            model: None,
        }
    }

    /// Creates an agent backed by a validated local model.
    ///
    /// The model's stored threshold controls whether the agent emits a
    /// recommendation. Policy-engine approval requirements are unchanged.
    pub fn with_model(model: UsernameSimilarityModel) -> Self {
        Self {
            threshold: model.threshold(),
            model: Some(model),
        }
    }

    /// Creates an agent using the model embedded in `agent-core`.
    pub fn with_embedded_model() -> Result<Self, UsernameModelError> {
        UsernameSimilarityModel::embedded().map(Self::with_model)
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

                let similarity = username_similarity(lhs_username, rhs_username);
                let (score, mut reasons) = if let Some(model) = &self.model {
                    let prediction = model.predict(lhs_username, rhs_username);
                    let mut reasons = vec![format!(
                        "{} model likelihood is {:.0}%",
                        prediction.model_name,
                        prediction.likelihood * 100.0
                    )];
                    reasons.extend(prediction.reasons);
                    (prediction.likelihood, reasons)
                } else {
                    (
                        similarity.score,
                        vec![format!(
                            "combined username similarity score is {:.0}%",
                            similarity.score * 100.0
                        )],
                    )
                };
                if score < self.threshold {
                    continue;
                }

                let normalized_match =
                    normalize_username(lhs_username) == normalize_username(rhs_username);
                let matching_suffix = similarity.numeric_suffix == 1.0;

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
        AccountView, Agent, AgentContext, AgentError, AgentPermissions, PolicyDecision,
        PolicyEngine, PolicyError, Recommendation, RecommendedAction, UsernameModelError,
        UsernamePersonaAgent, UsernameSimilarityModel, combined_username_score, normalize_username,
        normalized_edit_similarity, username_model_features, username_similarity,
    };
    use uuid::Uuid;

    struct DeniedAgent;

    impl Agent for DeniedAgent {
        fn id(&self) -> &'static str {
            "denied"
        }

        fn required_permissions(&self) -> AgentPermissions {
            AgentPermissions {
                username: true,
                ..AgentPermissions::default()
            }
        }

        fn analyze(&self, _context: &AgentContext) -> Result<Vec<Recommendation>, AgentError> {
            panic!("denied agents must not be invoked")
        }
    }

    struct ServiceOnlyAgent;

    impl Agent for ServiceOnlyAgent {
        fn id(&self) -> &'static str {
            "service_only"
        }

        fn required_permissions(&self) -> AgentPermissions {
            AgentPermissions {
                service: true,
                ..AgentPermissions::default()
            }
        }

        fn analyze(&self, context: &AgentContext) -> Result<Vec<Recommendation>, AgentError> {
            assert!(context.permissions.service);
            assert!(!context.permissions.username);
            assert_eq!(context.accounts[0].service, "Example");
            assert_eq!(context.accounts[0].username, None);
            assert_eq!(context.accounts[0].persona, None);
            assert!(context.accounts[0].tags.is_empty());

            Ok(vec![test_recommendation(
                self.id(),
                RecommendedAction::NoAction,
                false,
            )])
        }
    }

    struct StaticRecommendationAgent {
        recommendation: Recommendation,
    }

    impl Agent for StaticRecommendationAgent {
        fn id(&self) -> &'static str {
            "static"
        }

        fn required_permissions(&self) -> AgentPermissions {
            AgentPermissions::default()
        }

        fn analyze(&self, _context: &AgentContext) -> Result<Vec<Recommendation>, AgentError> {
            Ok(vec![self.recommendation.clone()])
        }
    }

    fn test_recommendation(
        agent_id: &str,
        action: RecommendedAction,
        requires_confirmation: bool,
    ) -> Recommendation {
        Recommendation {
            id: "recommendation-1".to_string(),
            agent_id: agent_id.to_string(),
            title: "Review account".to_string(),
            description: "Review the suggested account change".to_string(),
            confidence: 0.9,
            reasons: vec!["test evidence".to_string()],
            affected_record_ids: vec![Uuid::new_v4()],
            action,
            requires_confirmation,
        }
    }

    fn account_context(permissions: AgentPermissions) -> AgentContext {
        AgentContext {
            permissions,
            accounts: vec![AccountView {
                record_id: Uuid::new_v4(),
                service: "Example".to_string(),
                username: Some("private_handle".to_string()),
                persona: Some("Private".to_string()),
                tags: vec!["sensitive".to_string()],
            }],
        }
    }

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
    fn similarity_assessment_exposes_component_scores() {
        let assessment = username_similarity("dev_tim23", "devtim23");

        assert_eq!(assessment.normalized_edit, 1.0);
        assert_eq!(assessment.jaro_winkler, 1.0);
        assert_eq!(assessment.bigram, 1.0);
        assert_eq!(assessment.numeric_suffix, 1.0);
        assert_eq!(assessment.score, 1.0);
    }

    #[test]
    fn empty_and_separator_only_usernames_score_zero() {
        assert_eq!(username_similarity("", "").score, 0.0);
        assert_eq!(username_similarity("_-.", "name").score, 0.0);
    }

    #[test]
    fn edit_similarity_counts_unicode_characters() {
        assert_eq!(normalized_edit_similarity("é", "a"), 0.0);
        assert_eq!(normalized_edit_similarity("éx", "éy"), 0.5);
    }

    #[test]
    fn similarity_is_symmetric_and_bounded() {
        let forward = username_similarity("alpha_42", "alfa42");
        let reverse = username_similarity("alfa42", "alpha_42");

        assert_eq!(forward, reverse);
        assert!((0.0..=1.0).contains(&forward.score));
    }

    #[test]
    fn username_model_feature_order_matches_contract() {
        assert_eq!(
            username_model_features("dev_tim23", "DevTim23"),
            [1.0, 1.0, 1.0, 1.0]
        );

        let fixture = username_model_features("martha", "marhta");
        let expected = [2.0 / 3.0, 0.961_111_1, 0.25, 1.0];
        for (actual, expected) in fixture.into_iter().zip(expected) {
            assert!((actual - expected).abs() < 0.000_001);
        }
    }

    #[test]
    fn embedded_model_scores_related_usernames_above_unrelated_usernames() {
        let model = UsernameSimilarityModel::embedded().expect("embedded model should be valid");

        let related = model.predict("dev_tim23", "DevTim23");
        let unrelated = model.predict("orbit_cedar", "plasmaquill");

        assert_eq!(model.name(), "username-similarity-logistic-v1");
        assert!(related.likelihood > unrelated.likelihood);
        assert!(related.same_persona);
        assert!(!unrelated.same_persona);
        assert!(!related.reasons.is_empty());
    }

    #[test]
    fn username_model_rejects_feature_schema_mismatch() {
        let invalid = r#"{
            "format_version": 1,
            "model_name": "invalid",
            "feature_names": ["bigram", "jaro_winkler", "normalized_edit", "numeric_suffix"],
            "weights": [1.0, 1.0, 1.0, 1.0],
            "bias": 0.0,
            "threshold": 0.5
        }"#;

        assert!(matches!(
            UsernameSimilarityModel::from_json(invalid),
            Err(UsernameModelError::FeatureSchemaMismatch)
        ));
    }

    #[test]
    fn username_model_rejects_unsupported_versions_and_thresholds() {
        let unsupported = include_str!("../../../models/username-similarity/model.json").replacen(
            "\"format_version\": 1",
            "\"format_version\": 2",
            1,
        );
        assert!(matches!(
            UsernameSimilarityModel::from_json(&unsupported),
            Err(UsernameModelError::UnsupportedFormat(2))
        ));

        let invalid_threshold = include_str!("../../../models/username-similarity/model.json")
            .replacen("\"threshold\": 0.5", "\"threshold\": 1.5", 1);
        assert!(matches!(
            UsernameSimilarityModel::from_json(&invalid_threshold),
            Err(UsernameModelError::InvalidThreshold)
        ));
    }

    #[test]
    fn model_backed_agent_emits_model_explanation() {
        let agent = UsernamePersonaAgent::with_embedded_model()
            .expect("embedded model should construct an agent");
        let permissions = AgentPermissions::username_persona_defaults();
        let context = AgentContext {
            permissions: permissions.clone(),
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
                    username: Some("DevTim23".to_string()),
                    persona: None,
                    tags: vec![],
                },
            ],
        };
        let engine = PolicyEngine::new(permissions);

        let evaluations = engine
            .run(&agent, &context)
            .expect("model-backed agent should pass policy");

        assert_eq!(evaluations.len(), 1);
        assert!(
            evaluations[0].recommendation.reasons[0].contains("username-similarity-logistic-v1")
        );
        assert_eq!(evaluations[0].decision, PolicyDecision::RequireApproval);
    }

    #[test]
    fn policy_denies_missing_permissions_before_agent_execution() {
        let engine = PolicyEngine::new(AgentPermissions::default());
        let context = account_context(AgentPermissions::username_persona_defaults());

        assert_eq!(
            engine.run(&DeniedAgent, &context),
            Err(PolicyError::PermissionDenied {
                agent_id: "denied".to_string(),
            })
        );
    }

    #[test]
    fn policy_scopes_context_to_declared_permissions() {
        let available = AgentPermissions {
            service: true,
            username: true,
            persona: true,
            tags: true,
            ..AgentPermissions::default()
        };
        let engine = PolicyEngine::new(available.clone());
        let context = account_context(available);

        let evaluations = engine
            .run(&ServiceOnlyAgent, &context)
            .expect("service-only analysis should be permitted");

        assert_eq!(evaluations[0].decision, PolicyDecision::Allow);
    }

    #[test]
    fn policy_requires_approval_for_state_changes_even_when_agent_does_not() {
        let recommendation = test_recommendation("static", RecommendedAction::AssignPersona, false);
        let agent = StaticRecommendationAgent { recommendation };
        let engine = PolicyEngine::new(AgentPermissions::default());

        let evaluations = engine
            .run(&agent, &AgentContext::default())
            .expect("valid recommendation should pass policy");

        assert_eq!(evaluations[0].decision, PolicyDecision::RequireApproval);
        assert!(evaluations[0].recommendation.requires_confirmation);
    }

    #[test]
    fn policy_preserves_stricter_agent_confirmation_request() {
        let recommendation = test_recommendation("static", RecommendedAction::NoAction, true);
        let agent = StaticRecommendationAgent { recommendation };
        let engine = PolicyEngine::new(AgentPermissions::default());

        let evaluations = engine
            .run(&agent, &AgentContext::default())
            .expect("valid recommendation should pass policy");

        assert_eq!(evaluations[0].decision, PolicyDecision::RequireApproval);
    }

    #[test]
    fn policy_rejects_invalid_recommendation_metadata() {
        let mut recommendation = test_recommendation("static", RecommendedAction::NoAction, false);
        recommendation.confidence = f32::NAN;
        let agent = StaticRecommendationAgent { recommendation };
        let engine = PolicyEngine::new(AgentPermissions::default());

        assert_eq!(
            engine.run(&agent, &AgentContext::default()),
            Err(PolicyError::InvalidConfidence {
                recommendation_id: "recommendation-1".to_string(),
            })
        );
    }

    #[test]
    fn policy_rejects_blank_explanations() {
        let mut recommendation = test_recommendation("static", RecommendedAction::NoAction, false);
        recommendation.reasons = vec!["   ".to_string()];
        let agent = StaticRecommendationAgent { recommendation };
        let engine = PolicyEngine::new(AgentPermissions::default());

        assert_eq!(
            engine.run(&agent, &AgentContext::default()),
            Err(PolicyError::MissingReasons {
                recommendation_id: "recommendation-1".to_string(),
            })
        );
    }

    #[test]
    fn username_persona_agent_runs_through_policy_boundary() {
        let permissions = AgentPermissions::username_persona_defaults();
        let engine = PolicyEngine::new(permissions.clone());
        let context = AgentContext {
            permissions,
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

        let evaluations = engine
            .run(&UsernamePersonaAgent::default(), &context)
            .expect("username persona analysis should pass policy");

        assert_eq!(evaluations.len(), 1);
        assert_eq!(evaluations[0].decision, PolicyDecision::RequireApproval);
        assert_eq!(
            evaluations[0].recommendation.action,
            RecommendedAction::AssignPersona
        );
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
