# Threat Model

Initial scope includes:

- stolen encrypted cloud data
- compromised cloud components
- prompt injection from untrusted web content
- accidental secret leakage in logs
- compromised or substituted local model artifacts
- model-training dependency supply-chain compromise
- stale or replayed synchronization mutations
- cross-user encrypted-record access
- malicious synchronization-service rollback

## Local Model Controls

The username model is built from synthetic data and does not require vault
exports. Python training dependencies are pinned, the random seed and feature
order are fixed, and generated metrics are stored with the model artifact.

Rust embeds the reviewed JSON artifact at compile time and rejects unsupported
format versions, feature schema changes, non-finite coefficients, and invalid
thresholds. These checks detect malformed or incompatible artifacts, but they
do not prove model provenance. Changes to training dependencies, scripts, or
generated artifacts require code review and regeneration from a trusted build
environment. Model output is advisory and remains subject to policy-engine user
approval.

## Synchronization Controls

Authenticated transport adapters must derive opaque owner IDs from verified
claims and scope every read and write to that owner. Record revisions use
atomic compare-and-set semantics: stale or replayed mutations fail without
changing server state. Deletions remain visible as revisioned tombstones, and
incremental cursors are scoped independently per owner.

These controls assume the service correctly enforces revisions. Current crypto
authenticates ciphertext and the crypto version, but does not bind record ID,
sync revision, or server cursor as associated data. A malicious cloud service
could therefore return an older valid ciphertext and matching metadata. This
rollback threat remains open until a later protocol adds client-verifiable
state commitments or authenticated revision metadata. Clients must not treat
server revision checks as cryptographic freshness proof.
