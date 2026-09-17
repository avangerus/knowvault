# ADR-0025: Workspace optimistic concurrency

Status: accepted.

Every workspace mutation except initial creation requires the exact canonical
configuration hash observed by its caller. The repository validates the
`sha256:` representation, locks and verifies the current workspace snapshot,
authorizes the actor and compares the expected hash with the persisted current
revision hash before constructing revision `n+1`.

A mismatch returns `WORKSPACE_REVISION_CONFLICT`; it never retries against the
newer configuration and never applies a partial domain change. The failed
attempt is appended as a content-free FAILED audit event in the same database
transaction. This protects metadata, archive, membership, role and ownership
commands from lost updates when two interfaces operate on stale views.

The precondition is enforced inside `workspace/repository`, not only by a
future HTTP `If-Match` header. Web, internal API and any later transport must
therefore use the same rule. Initial workspace creation remains blocked from a
public mutating route until a durable body-sensitive idempotency ledger is
implemented; an in-memory or transport-only idempotency key is insufficient.

The PostgreSQL acceptance test performs a stale overwrite after a newer
revision exists, verifies `WORKSPACE_REVISION_CONFLICT`, confirms the current
revision is unchanged and checks the matching FAILED audit event.
