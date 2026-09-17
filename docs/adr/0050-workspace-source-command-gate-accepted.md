# ADR-0050: Workspace source command and projection gate

Status: accepted.

Migration `000009` extends the single actor-scoped
`workspace_command_receipt` with `WORKSPACE_SOURCE_ADD` and
`WORKSPACE_SOURCE_REMOVE`. The receipt binds the exact base workspace revision
and configuration hash, generated `workspace_source` identity, source-scope
identity and immutable revision, scope-configuration hash, and access mode.
The terminal result remains one fresh immutable workspace revision. Reusing a
successful revision or audit event is still forbidden by the stage-1 unique
proof constraints.

`workspace_source` is stable lineage. A first ADD may insert it; REMOVE retains
it; a later ADD re-enables the same identity. Every workspace revision has a
complete immutable `workspace_revision_source` projection. An ordinary
workspace command must carry every row forward exactly. ADD changes exactly
one absent or disabled declared binding to enabled. REMOVE changes exactly one
enabled declared binding to disabled. Missing, extra, substituted, or otherwise
changed rows reject the whole transaction at the deferred terminal gate.
The base workspace must be `ACTIVE`. The new canonical snapshot may differ
only in its revision number and declared source bindings. The mutable workspace
row must install that exact result revision, metadata, owner, retention policy,
status, and transaction timestamp; omitting or substituting the pointer update
rejects the command.

The runtime role receives INSERT, but not UPDATE or DELETE, on the two source
projection tables. A lineage INSERT requires the fresh exact successful ADD
receipt in the same transaction. Each projection INSERT requires the one fresh
successful receipt for its exact workspace revision. Existing RLS, append-only
guards, canonical-snapshot equality, source-scope tuple foreign keys, and
tenant hard-delete ordering remain authoritative.

Only a current workspace `OWNER` or `MANAGER` may insert source-configuration
lineage or projection rows. The sole transition exception is a manager removing
themself: that actor may carry the unchanged source projection into the exact
membership-closing revision, then has no INSERT authority on any later
revision. `MEMBER`, `VIEWER`, and `AUDITOR` never receive source-configuration
write authority.

Source mutation audit uses the closed `WORKSPACE_SOURCE` resource and
`workspace.source_added` / `workspace.source_removed` actions. Its metadata is
exactly the seven content-free target fields; it contains no policy decision,
evidence, title, path, or source content. Terminal DENIED, NOT_FOUND, and
PRECONDITION_FAILED receipts retain the stage-1 idempotency behavior, bind an
exact failure audit event, and cannot create a result revision. `SUCCESS`
requires the exact non-null workspace reference. A denied or failed attempt
may keep `workspace_id` null when the target is missing or hidden, preventing
the audit foreign key from becoming an existence oracle.

The runtime keeps no EXECUTE privilege on the older caller-prefix ID validator.
The one legacy writable CHECK is replaced by a closed validator that accepts
only fixed `binding` and `scope` prefixes; any other prefix returns false.

This checkpoint is configuration provenance, not a data grant. In particular,
`WORKSPACE_MANAGED` has no confirmation or authority here. Connection, scope,
and activation remain DRAFT; there is no activation, connector job/event,
ingestion, catalog object, retrieval, or query path. The exact
workspace-managed warning and policy confirmation is deferred to migration
`0010`.

No dependency or license is introduced by this decision.
