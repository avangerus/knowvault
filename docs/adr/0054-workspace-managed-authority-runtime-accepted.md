# ADR-0054: Workspace-managed authority runtime persistence

Status: accepted.

ADR-0052 fixed the workspace-managed confirmation authority data contract and
migration `000010` shipped it as inert persistence: the runtime role could read
the four authority relations but could not insert a single row. ADR-0053 then
froze the runtime command boundary before any code existed. This decision
implements the persistence half of that boundary — migration `000011` and the
authority audit contract — and opens the first, exactly gated write path into
those four relations. It does not revise ADR-0052 or ADR-0053; where this
document restates them it is a summary, and the earlier decisions remain
authoritative.

This checkpoint is deliberately partial. It introduces no Go repository or
store method, no policy evaluation, no production canonicalizer, and no HTTP,
API, UI, MCP, outbox, activation, job, ingestion or retrieval surface. The four
operations and the `WORKSPACE_AUTHORITY_` error namespace remain forbidden in
every one of those surfaces, and the architecture checker still proves their
absence there. What changes is that the negative "migration `000011` must not
exist" assertion retires, replaced by a positive gate that proves each
invariant by presence rather than by absence.

## The receipt family is separate

`workspace_managed_authority_command_receipt` is a new relation, not an
extension of `workspace_command_receipt`. An authority command never creates a
WorkspaceRevision, so the two receipt families address two different result
contracts and two different namespaces; the same raw Idempotency-Key in each is
two independent commands. The authority namespace is
`(organization_id, actor_principal_id, idempotency_key_hash)`, where
`organization_id` is always the trusted `AccessContext.OrganizationID`.

Request `organization_id` is stored, as `request_organization_id`, purely as
the canonical projection of the request body. Nothing in the schema ever
selects a tenant, an RLS context or a namespace from it.

It is inert on failure and only on failure: a cross-tenant command legitimately
terminates `NOT_FOUND` with a trusted-tenant receipt whose request names a
foreign organization, so no general equality with `organization_id` can be
required. Success is the opposite case — a command that succeeded acted inside
the trusted tenant — so a `SUCCESS` receipt must have
`request_organization_id = organization_id`. Without that, a receipt could bind
hash-verified canonical bytes claiming one tenant to a row created in another,
which is precisely the divergence the audit binding exists to prevent.

The operation-specific request projection is closed by one exhaustive CHECK per
operation: each operation pins its own exact non-null field set and forces
every field of every other operation to NULL. There is no generic intent JSON
column and no unconstrained nullable union, so one idempotency key can never be
reused for a different operation shape.

## The upgrade fails closed

Every authority row that exists when `000011` runs predates the receipt
boundary by construction, because `000010` granted the runtime role SELECT
only. There is no receipt such a row could be bound to and no honest way to
invent one. The migration therefore counts the four relations first and aborts
the whole transaction if any row exists. It does not backfill, does not
synthesize a receipt, and does not declare the rows trusted.

## The canonicalization boundary

Go is the sole authority for exact RFC 8785 canonicality: it builds the
canonical bytes and derives the hash. PostgreSQL never re-derives canonical
bytes from typed fields, and this migration is not a second JCS engine — a byte
string that is semantically equivalent but not canonical is rejected at the Go
boundary, not here.

What PostgreSQL proves independently, about what Go actually stored, is three
complementary facts: the stored hash equals SHA-256 of exactly the stored
bytes; the stored JSON's field set and types are exactly the closed contract;
and every JSON field exact-matches its relational column. Typed accessors make
the second and third checks strict — a string `"7"` can never satisfy an
integer projection, and a number can never satisfy a string projection.

## Authority rows exist only behind a receipt

Each of the four relations gains `command_id`, the stored canonical result
bytes, a unique `(organization_id, command_id)` key, a foreign key to the
receipt, and a CHECK that its existing hash column equals SHA-256 of exactly
those bytes. A BEFORE INSERT gate then resolves the one receipt the INSERT may
rely on and proves it is exact and fresh: same tenant, same actor, same
`command_id`, same operation, still `PENDING`, and exact-matching the
operation-specific request projection. A terminal receipt, another actor's
receipt, another tenant's receipt, or a receipt of a different operation can
never authorize an authority row.

Deferred constraint triggers close the loop at commit: a `SUCCESS` receipt must
bind exactly one authority row of its own operation with the exact result ID
and hash, and any other terminal status must bind zero.

## The audit contract

This is the later migration ADR-0053 anticipated: it adds
`WORKSPACE_AUTHORITY_COMMAND` to the resource-type enum and the four actions to
the registry. `audit.resource_id` is always `receipt.command_id`, on every
terminal outcome; created and parent authority IDs appear only inside metadata,
and only on `SUCCESS`.

Receipt status maps to audit outcome and error code exhaustively, and the
binding is proved in both directions. A terminal receipt must name one audit
event whose action, outcome, error code, actor and workspace ID agree exactly
with it; and an authority audit event must be claimed by exactly one terminal
receipt, which is what makes "no audit event for `PENDING`, an invalid request,
an idempotency conflict or a replay" enforceable rather than merely intended.

A `SUCCESS` event must additionally project the row that was actually
persisted. Proving the metadata key set is necessary but not sufficient:
without a value comparison a command could persist one grant and audit a
structurally perfect projection of another, which is a forged audit record that
every shape check accepts. So on `SUCCESS` the database loads the authority row
by `(organization_id, command_id)` for the receipt's own operation and compares
every metadata value against it and against the parent projection — created ID
and hash, parent identity, reason code, policy revision, and for a confirmation
the whole 17-field tuple. The comparison reads the trusted persisted row, not
the request, so what the audit trail claims and what the tenant holds cannot
diverge.

Server-owned timestamps are derived rather than accepted: `granted_at`,
`confirmed_at` and `revoked_at` must equal the command's single PostgreSQL
transaction-second, so a client clock can neither backdate a grant nor stretch
its own TTL. The grant-issue request is optimistic, and its
`expected_workspace_revision` and `expected_workspace_configuration_hash` are
applied against the workspace's current revision under a share lock rather than
merely stored as projection.

The Go validator in `internal/audit` and these database gates are deliberate
mirrors: both encode the same closed action/resource pairing, the same
outcome-to-error-code mapping, the same `workspace_id` rule and the same
per-action metadata sets. Migration `000009` had reserved part of the
workspace-source metadata vocabulary to its own two actions;
`WORKSPACE_MANAGED_CONFIRM` legitimately shares four of those keys, so the
reserved-vocabulary branch is narrowed to exempt authority events rather than
the vocabulary being duplicated. `enabled` remains exclusive to the
workspace-source projection.

## Commit-time protection

`000010`'s current-policy guard runs BEFORE INSERT only, so it proves the
policy was current when the row was written, not when the transaction
committed. ADR-0053 requires that a policy or warning advance between
reservation and commit roll back and fail closed, so deferred gates re-read
both projections at commit. They only ever roll the whole transaction back;
they never switch an already-chosen terminal branch to a different status.

The policy head is a row, so its deferred gate locks it with `FOR SHARE`. The
warning head is not: the registry is global and append-only, so the head is
`max(revision)` and no row lock can block the INSERT of a new revision, which
is exactly how the head moves. `000010` already re-read the warning head at
commit, and a re-read alone leaves a window — an advance that lands between the
check and the commit still lets the confirmation commit. This decision closes
that window with `LOCK TABLE ... IN SHARE MODE`: SHARE is the minimal mode that
conflicts with an INSERT's ROW EXCLUSIVE, and it is self-compatible, so
concurrent confirmations — including across tenants, which is the only place
this global lock could couple them — never block each other.

A lock is not sufficient on its own, and this is the one place the two gates
differ in kind. A table lock serializes the writer but does not advance the
locking transaction's snapshot, so under REPEATABLE READ or SERIALIZABLE the
re-read would see the pre-advance snapshot and pass — the gate would degrade
into exactly the silent no-op the policy gate avoids. The policy gate is safe
there for free: it locks a row, and a locked row updated by a committed
transaction raises a serialization failure. The warning gate has no row to
lock and so gets no such signal. Rather than assume the isolation level, it
asserts it: a command running at anything other than READ COMMITTED fails
closed. The runtime pins READ COMMITTED today, so this is a guard against a
future change silently removing a property, not a live defect.

The lock is insurance rather than today's load-bearing defence. The warning
registry has exactly one permissible writer: `000010` seeds revision 1 and then
refuses every INSERT, UPDATE and DELETE unconditionally, from any role
including the table owner, so a v2 contract requires a migration that drops
that guard explicitly. While the guard stands the head cannot move and there is
no runtime race to win. The gate is what keeps the invariant true for the
migration that does drop it, and the concurrency tests prove it by dropping the
guard themselves — the only state in which the race is reachable at all.

## Visibility and privileges

The receipt is actor-scoped: readable only by the exact actor who owns it,
inside the trusted tenant, so it never becomes an existence oracle for another
actor's command. FORCE ROW LEVEL SECURITY is preserved on all four authority
relations and enabled on the receipt.

Authority-metadata visibility widens beyond plain workspace membership exactly
as far as ADR-0053 allows and no further: existing membership, Organization
`OWNER`/`ADMIN`, and the exact self principal.

"Self" here means precisely whom ADR-0053 gives a self-revoke right to, because
a principal who may revoke a row must be able to see it. That is the grant
principal for a grant (ADR-0053: revocation is open to the Workspace `OWNER`
and "to the exact grant principal as self-revoke") and the historical
`confirmed_by` for a confirmation (ADR-0053: "to the original `confirmed_by`
principal as self-revoke"). It is deliberately not "whoever issued the row":
`granted_by` and `revoked_by` have no self-revoke right in ADR-0053 and so get
no disjunct — they reach authority metadata through their current organization
role, and a personal disjunct would let someone who lost that role still
distinguish `DENIED` from `NOT_FOUND`.

That `confirmed_by` happens to also be a confirmation's issuer is incidental;
it is included because ADR-0053 gives it self-revoke, not because it issued the
row. The residual consequence is deliberate and worth naming: a principal who
confirmed a source keeps a narrow existence oracle on that confirmation, and on
its revocation, after losing membership and their organization role — which is
the unavoidable price of the self-revoke right ADR-0053 grants them.

This predicate appears only in the four authority policies; it grants no
source-content, evidence or retrieval access.

This widening is a replacement, not an addition: each relation's `000010`
tenant-isolation policy is dropped and two policies take its place, one for
reads and one for the receipt-gated INSERT. The `000010` suite pins the
policies that migration shipped, against the `000010` schema, so nothing there
covers the replacements; they are proved at head instead, by their own tests —
cross-tenant denial, Organization `OWNER`/`ADMIN` without membership, exact
self-visibility surviving loss of membership, and `granted_by` conferring
nothing.

The database-side gates read the receipt and count authority rows through
SECURITY DEFINER functions, which assumes the migration owner is not itself
subject to FORCE ROW LEVEL SECURITY. An owner without that property would
silently see fewer rows: the gates would weaken rather than fail loudly, and a
deployment could believe it had a boundary it does not have. A deployment
contract stated only in prose cannot prevent that, so the migration checks it
instead — it refuses to install unless its owner is `SUPERUSER` or `BYPASSRLS`.
A weaker owner gets a failed upgrade, not a weaker boundary.

That check is install-time only, and deliberately so: a role attribute is not
something the schema can hold. `ALTER ROLE ... NOBYPASSRLS` after the fact
would still weaken every SECURITY DEFINER gate here with nothing to catch it,
so the owner's attributes remain part of the deployment contract. What the gate
removes is the failure mode where a deployment never had the property at all
and never learned.

Receipts are append-only to the runtime role twice over: the role holds no
DELETE privilege at all, and the guard refuses the delete regardless of role
while the tenant is live. A receipt is the evidence that a command happened, so
nothing in normal operation may erase it. Tenant hard-delete is the one
exception, because a receipt that could never be deleted would pin the tenant's
rows forever and make erasure impossible: the guard opens only while the
organization is `DELETING` or `DELETED`, and only for a non-runtime role. It
stays child-first — the authority row's foreign key means its receipt cannot be
deleted out from under it — so erasure can never leave a grant naming a receipt
that is gone.

The runtime role receives INSERT and nothing else on the authority relations —
no UPDATE, no DELETE, and no policy that would permit either. A CHECK
constraint is evaluated as the inserting role, so the pure validators reachable
from a CHECK are granted EXECUTE; the trigger guards are SECURITY DEFINER and
their helpers, including the receipt resolver, stay revoked. Every SECURITY
DEFINER function introduced here is a closed assertion that returns a verdict
and mutates nothing: there is no generic mutating SECURITY DEFINER tool.

## Testing the boundary at two points in history

Migration `000011` is chartered to replace exactly the inert boundary that
`000010` shipped, so the `000010` suite's assertions — SELECT-only privileges,
no INSERT path, no receipt — are false at head by design rather than by
regression. Rewriting those assertions into the new contract, or deleting them,
would silently drop the proof that the inert step was ever correct and that a
deployment stopped mid-upgrade at `000010` is safe.

The suites are therefore split by the schema state they pin. The `000010` suite
rebuilds the database through `000010` and keeps testing the contract it was
written against; the `000011` suite rebuilds through head and proves the
receipt-gated contract, including that the runtime role can execute a whole
authority command end to end. Both replay the same migration files against an
empty schema; neither restores a dump.

## What remains deferred

The Go repository, the policy evaluation matrix, the production canonicalizer
and its golden-vector parity, the replay and idempotency-conflict paths,
concurrency and TOCTOU behaviour above the database, and every transport
surface remain deferred to their own checkpoint, together with the anti-drift
gates that will prove the repository stays uncomposed. This decision adds no
dependency, module, service, model, component or license.
