# Agent Security

Agents use explicit field-level permissions and return recommendations with
explainable reasons and confidence scores. Agent output is advisory and must
pass through `PolicyEngine` before reaching an execution workflow.

## Permission Enforcement

An agent declares the fields it needs through `required_permissions`. Before
invoking the agent, `PolicyEngine` verifies that both of these sources grant all
required fields:

- the engine's configured maximum permission grant
- the permissions describing fields available in the source `AgentContext`

If either check fails, the engine returns `PolicyError::PermissionDenied` and
does not invoke the agent. A successful check produces a least-privilege context
containing only the fields the agent declared. Undeclared optional fields are
removed, tags are emptied, and an undeclared service name becomes an empty
string because `AccountView::service` is currently required by the type.

The current `AccountView` intentionally cannot carry passwords, TOTP secrets,
recovery codes, email addresses, or notes. Adding any of those fields requires a
new security review, explicit permission handling, redaction tests, and updated
documentation.

## Recommendation Validation

The policy engine rejects recommendations when:

- the recommendation's agent ID does not match the invoked agent
- confidence is not finite or is outside `0.0..=1.0`
- no explanatory reasons are present

The `requires_confirmation` value produced by an agent is not trusted to waive
approval. The engine independently requires approval for persona assignment,
record merging, recovery-method changes, and MFA changes. An agent may request
stricter handling for an otherwise informational action.

`Allow` means a recommendation may be displayed as informational output. It
does not authorize an external side effect. Any later command or tool boundary
must perform its own authorization and validate explicit user intent.

## Logging

Do not log source contexts, raw identity fields, or complete recommendation
descriptions. Operational logs may contain an agent ID, recommendation ID,
policy decision, and non-sensitive error category when needed for diagnostics.
