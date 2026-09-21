# Username Similarity Heuristic

The initial username similarity heuristic runs locally in `agent-core`. It
compares two usernames after trimming, lowercasing, removing whitespace, and
removing `_`, `-`, and `.` separators.

The public `username_similarity` API returns an explainable assessment made of:

- normalized Levenshtein similarity, weighted 35%
- Jaro-Winkler similarity, weighted 35%
- character-bigram Jaccard similarity, weighted 20%
- trailing numeric-suffix agreement, weighted 10%

The component values and aggregate score are bounded to `0.0..=1.0`. Empty or
separator-only inputs receive a zero assessment. The result does not retain the
input strings, so callers can store an assessment without creating another copy
of username identity data.

## Safety and Interpretation

The score measures textual similarity only. It is not a probability, identity
proof, or authorization signal. Similar usernames may belong to unrelated
people, while usernames owned by one person may be intentionally dissimilar.
The heuristic does not currently detect Unicode confusables, transliterations,
or language-specific similarities.

Usernames remain identity data. Analysis should stay local, raw inputs should
not be logged, and persona or graph changes based on a score require user
review.

## Learned Baseline

`agent-core` also embeds `username-similarity-logistic-v1`, a logistic-regression
baseline trained on deterministic synthetic username pairs. It consumes the
same four signals as the heuristic and returns a local same-persona likelihood,
threshold decision, weighted feature contributions, and human-readable reasons.
`UsernamePersonaAgent::with_embedded_model` opts into model scoring; the default
agent continues to use the original heuristic.

The model is exported as both a versioned JSON coefficient artifact and ONNX.
Rust currently evaluates the audited JSON coefficients directly, avoiding a
native inference-runtime dependency. Loading rejects unsupported versions,
changed feature ordering, non-finite coefficients, and invalid thresholds.

Training compares logistic regression with a small random forest and records
holdout precision and recall in `model.json`. Current measurements use only an
easy synthetic dataset and validate the pipeline rather than real-world
accuracy, fairness, or calibration. See
[`models/username-similarity/README.md`](../models/username-similarity/README.md)
for reproduction instructions and data constraints.

Model output remains advisory. It cannot authorize graph changes, and the
policy engine always requires user approval for persona assignment.
