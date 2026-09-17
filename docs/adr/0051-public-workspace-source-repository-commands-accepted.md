# ADR-0051: Public workspace source repository commands

Status: accepted.

`Store.AddSource` and `Store.RemoveSource` are the only public repository
commands in this checkpoint that may change a workspace source projection.
Both use the canonical `workspace-command-v2` envelope and reserve the one
actor-scoped `workspace_command_receipt` extended by migration `000009`.
The request hash, receipt target, base workspace revision and configuration
hash, scope revision, scope configuration hash, access mode, and stable
binding identity must all match exactly on first execution and replay.

The binding ID is server-derived, never client-selected for ADD. It is the
first 128 bits of SHA-256 over the domain-separated tuple
`organization_id + workspace_id + source_scope_id`, encoded as one canonical
26-character Crockford Base32 value with two leading zero pad bits and the
fixed `binding_` prefix. The organization component prevents cross-tenant
aliasing; the workspace and scope components make the lineage independent of
an actor or idempotency key. REMOVE must present that exact ID. Disable keeps
the lineage row, and a later ADD re-enables the same ID rather than inserting
a second lineage.

Every first execution reserves the receipt before target authorization. The
source mutation then crosses a row-lock barrier, reloads the fresh canonical
workspace snapshot and exact relational source projection, and evaluates the
current post-lock membership through the source-specific
`workspace.manage_sources` policy operation. Only a current `OWNER` or
`MANAGER` in an `ACTIVE` workspace is allowed. Missing and hidden workspaces
resolve to the same terminal NOT_FOUND shape; unauthorized visible targets
resolve to DENIED. This post-lock decision and content-free terminal audit
prevent stale membership and target-existence oracles. If membership was
removed after reservation, the command and any later replay return NOT_FOUND.
A successful replay requires current workspace metadata visibility; it does
not reuse historical manage authority and does not require that a still-visible
caller retain the old management role merely to read the immutable result.

ADD accepts only an exact immutable source-scope revision whose scope remains
`DRAFT` and whose `active_revision` is `NULL`. REMOVE accepts only the exact
currently enabled projection. The commands preserve all non-target workspace
metadata, memberships, status, clocks, and source bindings. PostgreSQL's
workspace row lock plus the exact expected revision/hash makes simultaneous
different commands serialize to one success and one terminal stale result;
the same actor and idempotency key replay the one terminal result.

This checkpoint is configuration provenance only. It does not confirm
`WORKSPACE_MANAGED` access, activate a connection or scope, create a grant,
schedule a connector job, ingest content, create catalog/evidence rows, or
authorize retrieval or a question. Connection and scope authority remain
`DRAFT`; the binding is inert until later, separately audited gates exist.

No dependency, module, service, model, component, or license is introduced.
The implementation uses only the existing Go standard library and already
accepted PostgreSQL, audit, workspace, and policy boundaries.
