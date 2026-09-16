# Identity Graph

The identity graph stores local identity metadata that helps the application
reason about accounts without flattening everything into a password list.

## Stored Entities

The current graph model includes:

- personas, such as `Professional`, `Personal`, or `Gaming`
- email identities, such as a recovery or login email address
- username identities, such as handles reused across services
- directed account relationships, such as recovery, SSO, dependency, related
  username, same-persona, and duplicate-candidate links

Account records remain owned by `vault-core`. The graph stores opaque account
UUIDs and does not validate whether those IDs exist in a vault service.

Email addresses and usernames are identity data. They are not credentials, but
they can still identify a person and must be protected when serialized or
persisted outside the unlocked local vault boundary.

## Relationship Direction

Directed account relationships use this convention:

```text
source account -> target account
```

For dependency-like relationships, the source account depends on or refers to
the target account. For example:

```text
GitHub account -> Primary email account   RecoveryEmail
Notion account -> Google account          SsoProvider
```

This lets callers ask, "Which accounts depend on this email or SSO provider?"
by walking incoming dependency edges from the target account.

## Supported Queries

`IdentityGraph` supports:

- assigning accounts to personas
- linking accounts to email identities
- linking accounts to username identities
- listing accounts for a persona, email identity, or username identity
- finding incoming dependency dependents for recovery, SSO, and dependency edges
- calculating coarse account criticality from direct and transitive dependents
- case-insensitive search over personas, email identities, and username
  identities

Criticality is intentionally simple for this slice:

- `None`: no known dependent accounts
- `Low`: one or two dependent accounts
- `Medium`: three to seven dependent accounts
- `High`: eight or more dependent accounts

These thresholds are local heuristics and can be refined when the dependency
agent and user-facing review workflow arrive.
