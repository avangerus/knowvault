# ADR-0049: Inert workspace source snapshot checkpoint

Status: accepted.

Migration `000008` records source-binding lineage and the immutable source set
of one exact workspace revision. It is a storage checkpoint only. It does not
confirm a workspace-managed grant, activate a connection or scope, start a
connector job, accept an event, ingest content, populate a catalog, or make any
data queryable.

`workspace_source` gives one generated binding identity to one workspace and
one source-scope lineage. `workspace_revision_source` binds that identity to an
exact workspace revision and configuration hash and to one exact immutable
source-scope revision, scope-configuration hash, and access mode. A mutable
`latest_revision`, a display label, or a caller-supplied access mode is never
authority.

The relational snapshot and the canonical `workspace-configuration-v1` bytes
must describe exactly the same source set. A deferred validator compares the
complete arrays in both directions and rejects missing, extra, duplicated, or
mismatched scope IDs, revisions, hashes, and enabled flags. It runs for changes
to either the binding rows or the workspace revision snapshot; an empty row set
therefore cannot hide non-empty canonical bindings.

The checkpoint deliberately contains no `workspace_managed_grant_confirmation`.
That confirmation belongs to a later audited and idempotent command checkpoint
because workspace ownership alone must not grant source data. The later command
must bind the exact organization, workspace revision, binding identity, source
scope revision and hash, actor, policy revision, and warning version. A
`SOURCE_ENFORCED` binding must never have such a confirmation.

All new rows are append-only, tenant-isolated with forced RLS, visible only to
current workspace members, and read-only to the shared application role. Hard deletion is restricted to tenant deletion and
must follow forward foreign-key order. The source connection and scope remain
in their existing DRAFT state with null active revisions, so a valid binding
snapshot still confers no retrieval or ingestion authority.

No dependency or license is introduced by this decision.
