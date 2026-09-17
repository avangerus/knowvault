# ADR-0052: Workspace-managed confirmation authority contract

Status: accepted.

`WORKSPACE_MANAGED` access requires an explicit authority confirmation outside
both reusable source-scope configuration and canonical workspace configuration.
The confirmation is an immutable sidecar relation exact-bound to organization,
workspace ID and revision, workspace configuration hash, stable binding ID,
source-scope ID and immutable revision, scope-configuration hash, and access
mode. Confirming or revoking it does not create or rewrite a WorkspaceRevision.
A live-binding view may join the resulting confirmation ID server-side; stored
scope or workspace canonical bytes never contain it, and no mutable confirmation
pointer is installed on either aggregate.

Workspace ownership and organization administration are insufficient authority.
At `confirmed_at` the actor must exact-match one workspace-scoped immutable
authorization grant by `grant_id`, revision and canonical `grant_hash`. The grant
must name the actor, permission `workspace.source.confirm`, workspace and policy
revision, and satisfy
`granted_at <= valid_from <= confirmed_at < valid_until`. Authority timestamps
use canonical UTC RFC 3339 second precision `YYYY-MM-DDTHH:MM:SSZ`; offsets,
fractional seconds and non-round-tripping forms are rejected. Repeating the
same actor, workspace and permission without the exact grant identity is denied.

The actor grant primary identity is `(organization_id, grant_id, revision)` and
its exact-hash tuple is unique. Confirmation identity is
`(organization_id, confirmation_id)` with a unique exact confirmation hash.
Actor-grant and confirmation revocations each have their own tenant-scoped
revocation primary ID; additionally there is at most one grant revocation per
exact `(grant_id, revision)` and at most one confirmation revocation per
`confirmation_id`. Both revocation records persist their own canonical hash.

Canonical `policy_revision` remains an opaque immutable external ID. It is not
derived by formatting the existing numeric organization counter. Persistence
must introduce an append-only organization policy-revision registry that binds
the monotonic safe-integer ordinal, opaque ID and policy hash. Authority rows
store both ordinal and ID and exact-reference that registry tuple; decreasing
the organization counter or reusing an ID/hash is forbidden. This closes the
database-to-JCS bridge without changing the existing Answer Manifest contract.

The warning acknowledgement is also authority data rather than a UI boolean.
Every confirmation binds the server-owned warning version, canonical warning
contract hash and the closed acknowledgement code
`WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL`. Those fields and the
exact target tuple enter both the idempotent command request hash and immutable
confirmation hash. The warning contract is a protected registry JCS object with
fixed access mode and sorted closed risk codes; a client cannot provide its own
warning body. Localized presentation text is not authoritative.

Confirmation, actor grant and their hashes are append-only. Individual access
reduction creates one immutable confirmation revocation. Revoking an actor grant
is a separate append-only kill-switch for every confirmation that references
that exact grant. No row changes from `CONFIRMED` to `REVOKED`; effective
`CONFIRMED`, `REVOKED` or `STALE` state is derived from the confirmation,
revocations, current policy and warning contracts, and the current exact enabled
workspace binding. Grant expiry prevents a new confirmation but does not rewrite
historical confirmation provenance.

For one exact current organization/workspace/revision/configuration-hash,
binding, scope-revision/scope-hash, policy and warning tuple, at most one
unrevoked derived-live confirmation may exist. A deferred validator computes
that set with both revocation relations while the command holds the workspace
row lock, so two grants cannot create an ambiguous live join. A revoked confirmation may
be replaced only by a new command and confirmation ID. Revoking one
confirmation does not affect another unless both deliberately reference the
same actor grant and that grant itself is revoked.

Any new WorkspaceRevision makes an earlier confirmation stale, even when the
binding was carried unchanged. Carry-forward is never implicit. A later feature
may create new explicitly audited confirmations for unchanged bindings, but it
cannot reuse the historical confirmation as authority. Advancing a source
scope's mutable `latest_revision` alone does not substitute for the immutable
revision selected by the workspace; changing the selected scope revision creates
a new WorkspaceRevision and requires a new confirmation. Revocation remains
allowed for a stale confirmation because access reduction must not depend on a
fresh optimistic configuration precondition.

`SOURCE_ENFORCED` can never reference this confirmation. A confirmation alone
does not activate a source connection or scope and does not authorize a
connector job or event, ingestion, catalog/evidence creation, retrieval, search,
or a question. Those later gates must independently exact-match the live
confirmation as one necessary input and must still prove connector trust,
activation and all other access invariants.

The runtime command checkpoint must use an authority-specific idempotency receipt
rather than treating confirmation as a workspace-configuration mutation. It
must serialize with workspace source commands at the workspace row, bind the
exact actor grant, policy and warning contracts, emit a content-free append-only
audit event, and make confirmation/revocation insertion impossible without the
fresh successful receipt in the same transaction.

This architectural contract adds no dependency or license. Persistence and
runtime authority remain deferred until a migration and repository checkpoint
implement every invariant above together.
