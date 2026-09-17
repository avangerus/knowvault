# ADR-0023: Workspace revision mutations

Status: accepted.

Metadata update, member addition and archive are implemented through one
workspace mutation path. It locks the current workspace/revision and active
memberships, rebuilds and verifies the current canonical configuration hash,
then evaluates `workspace.manage` using the current direct membership. Only an
active workspace `OWNER` or `MANAGER` proceeds; an archived workspace cannot
be managed again through this path.

Every successful mutation constructs a new pure snapshot with revision `n+1`,
calculates its canonical hash, conditionally advances `workspace.current_revision`,
inserts exactly one immutable `workspace_revision` row and appends the matching
audit event in the same transaction. The conditional revision update converts a
concurrent stale writer into a safe failure rather than overwriting a newer
configuration.

Adding a member requires an existing ACTIVE principal in the same organization
and rejects a second owner. It creates a new `workspace_member` row beginning
at the new revision; it does not rewrite historical membership. Ownership
transfer, removal and role change remain separate future commands because they
must close historical membership ranges before creating their replacements.

Archive changes only the lifecycle state to `ARCHIVED`; it does not delete any
workspace, revision or audit row. Metadata reads remain possible to existing
members under the pure policy, while management is denied.
