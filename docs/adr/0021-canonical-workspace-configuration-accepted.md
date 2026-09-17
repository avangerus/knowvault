# ADR-0021: Canonical workspace configuration

Status: accepted.

`internal/workspace` owns one pure `workspace-configuration-v1` snapshot. It
contains organization, workspace ID, revision, name, description, status,
owner, optional retention policy, current direct memberships and source bindings.
It opens neither a database nor an HTTP request and cannot decide
whether a caller may mutate a workspace.

Before a snapshot is persisted or hashed, all text fields use the accepted
`text-v1` NFC normalization; member and source-binding lists are sorted by
their stable IDs and copied. A JSON Canonicalization Scheme representation is
then SHA-256 hashed as `sha256:<lowercase-hex>`. Caller-owned slices, Go map
iteration and NFD/NFC spelling cannot change the hash.

The snapshot requires exactly one `OWNER` membership and its principal must
equal `owner_principal_id`. The existing deferred PostgreSQL constraint remains
the authoritative persistence backstop. Source bindings are part of the
canonical shape from the first version, although Stage 1 stores none; a future
SourceScope cannot be added without advancing and hashing a new workspace
revision.

This decision does not introduce Workspace CRUD, membership mutation, source
binding persistence or transport routes. Those layers must reconstruct and
validate the same snapshot inside their authorized transaction before they
advance `workspace.current_revision`.
