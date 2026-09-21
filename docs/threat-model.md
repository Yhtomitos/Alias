# Threat Model

Initial scope includes:

- stolen encrypted cloud data
- compromised cloud components
- prompt injection from untrusted web content
- accidental secret leakage in logs
- compromised or substituted local model artifacts
- model-training dependency supply-chain compromise

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
