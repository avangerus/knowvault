# ADR-0027: PostgreSQL runtime command proof gate

Status: accepted.

`knowvault_app` may write the workspace aggregate only through a transaction
that also seals one fresh `workspace_command_receipt`. Deferred PostgreSQL
constraint triggers prove at commit that the workspace revision, canonical
revision snapshot, membership transitions and append-only audit event belong to
that receipt's immutable command intent. This is an integrity gate, not a SQL
implementation of workspace business policy.

A successful receipt is unique for its exact workspace revision and an audit
event can be consumed by only one receipt. The validator checks the audit actor,
action, resource, outcome and error code, then verifies the operation-specific
domain effect. Workspace and membership shape guards require revision `+1`,
append-only revisions, immutable membership fields and close-only membership
updates. Every gated row must resolve to a `SUCCESS` receipt, revision and
snapshot created in the current database transaction; an old receipt therefore
cannot authorize a later write.

Validators are `SECURITY DEFINER` assertion functions with `EXECUTE` revoked
from `PUBLIC` and the application role. This is required for a legitimate
self-removal: at deferred-trigger time the actor no longer passes snapshot RLS.
The gate recognizes the direct login role through
`session_user = 'knowvault_app'`; the production pool must authenticate directly
as that role and must not use role switching. Migration-owner bootstrap remains
outside the runtime gate.

The database cannot distinguish correct application SQL from a deliberately
fabricated, internally consistent complete command proof. It does guarantee
that the runtime role cannot accidentally commit a workspace mutation without
the fresh receipt, exact snapshot and uniquely linked audit evidence required
by the architecture.
