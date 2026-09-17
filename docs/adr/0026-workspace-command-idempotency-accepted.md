# ADR-0026: Durable workspace command idempotency

Status: accepted.

Every mutating workspace repository request carries a canonical 256-bit
base64url Idempotency-Key. The raw key is never persisted or audited. The
repository stores its SHA-256 hash in an actor-scoped receipt whose unique
namespace is `(organization_id, actor_principal_id, idempotency_key_hash)`.
The typed `workspace-command-v1` JCS request hash covers the operation, target,
expected configuration hash and normalized command fields. Reusing a key for a
different operation or body returns `WORKSPACE_IDEMPOTENCY_CONFLICT` without
executing a second mutation.

A new command reserves a PENDING receipt inside the same `database.Write`
transaction that evaluates policy, changes the workspace, appends audit and
stores the terminal result. A deferred database constraint rejects commit while
the receipt remains PENDING. PostgreSQL unique-key locking makes concurrent
identical requests wait for the first transaction: commit produces exact
replay; rollback lets one waiter become the only author.

Successful commands persist exact JCS `workspace-configuration-v1` bytes in
append-only `workspace_revision_snapshot` and the receipt references their
workspace, revision and configuration hash through composite foreign keys.
Replay parses those immutable bytes and recomputes the hash; it never substitutes
the current workspace revision. Policy denials and optimistic-precondition
failures are terminal receipts with their single audit event. Invalid requests
and rolled-back infrastructure failures do not consume a key.

The receipt is not an authorization grant. Before returning an old successful
result the repository checks the current active identity and current workspace
metadata permission. RLS additionally scopes receipts to the authenticated
actor and revision snapshots to a current workspace member. A removed or
deprovisioned actor therefore cannot disclose the stored historical snapshot.

Runtime roles cannot update or delete revision snapshots, cannot mutate a
terminal receipt and cannot commit PENDING. Integration tests cover exact
replay after later revisions, body conflict, access loss, actor-scoped RLS,
terminal immutability and eight concurrent creates producing one workspace,
revision, snapshot, receipt and audit event.

The receipt also carries a non-content `gate_version=1` command intent: target
workspace, optional membership target and exact audit resource. Server-generated
workspace and membership IDs are derived deterministically from the tenant,
actor, operation and stored idempotency-key hash, so an exact retry reconstructs
the same intent without persisting the raw key.
