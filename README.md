# Alias

A privacy-first digital identity agent that understands how your online accounts relate to each other and helps you securely organize, protect, and maintain them.

## Current milestone

Offline Rust workspace foundation with:

- `crypto-core` (authenticated local record encryption)
- `vault-core` (vault data model, in-memory service, encrypted local CRUD service)
- `identity-graph` (personas, email/username identities, dependency queries)
- `agent-core` (explainable username similarity heuristic + agent interfaces)

The username heuristic exposes bounded component scores for local analysis; see
[`docs/username-similarity.md`](docs/username-similarity.md) for its behavior
and limitations.
