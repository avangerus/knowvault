# ADR-0022: Workspace control-plane repository

Status: accepted.

`internal/workspace/repository` is the only Stage 1 persistence adapter for
workspace creation and current metadata reads. It accepts a validated,
server-derived `database.AccessContext`; a transport request neither supplies
an organization filter nor an actor ID. Before mutation it resolves the
organization, principal and active organization roles from PostgreSQL under
RLS, then asks the pure default-deny policy layer.

Creating a workspace requires an active Organization `OWNER` or `ADMIN`. One
bounded write transaction inserts the workspace, its revision-one canonical
configuration hash, exactly one owner membership and a `workspace.created`
audit event. A known actor denied by policy receives a content-free denied
result and the denied attempt is appended to the same tenant audit chain.

Current reads rebuild the complete direct-member snapshot and recompute the
canonical configuration hash `workspace-configuration-v1`; it must
exact-match the hash stored on the current `workspace_revision`. A mismatch
fails closed. Metadata reads use the same pure workspace policy; a missing
direct membership maps to the same external `NOT_FOUND` result as an absent
workspace, preventing enumeration.
Organization administration alone never grants workspace metadata or content
access.

This ADR deliberately excludes update, archive, membership mutation, owner
transfer, source bindings and HTTP routes. Those mutations must advance a
new revision and use the same hash-and-audit transaction.
