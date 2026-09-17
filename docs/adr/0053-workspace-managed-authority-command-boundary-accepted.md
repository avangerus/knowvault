# ADR-0053: Workspace-managed authority command boundary

Status: accepted.

ADR-0052 fixed the workspace-managed confirmation authority data contract and
migration `000010` shipped its inert persistence: the runtime role can read the
four authority relations but cannot insert a single row. This decision freezes
the runtime command boundary before any repository code exists, so that issuing
and revoking confirmation authority is a reviewed contract instead of a
privilege invented inside an implementation checkpoint. This checkpoint is
contract-only: it introduces no migration `000011`, no Go repository or store
method, no policy or audit runtime constant, and no HTTP, API, UI, MCP, outbox,
activation, job, ingestion or retrieval surface.

The command surface is closed to exactly four operations:
`WORKSPACE_CONFIRMATION_GRANT_ISSUE`, `WORKSPACE_CONFIRMATION_GRANT_REVOKE`,
`WORKSPACE_MANAGED_CONFIRM` and `WORKSPACE_MANAGED_CONFIRM_REVOKE`. No other
authority operation exists in this contract, and an unknown operation is a
request-shape error, never a soft no-op.

Every command is one canonical JSON envelope
`{"schema_version": "workspace-managed-authority-command-v1", "operation":
"...", "request": {...}}`. The envelope and each request are closed objects:
unknown or extra fields are rejected on every level, no field is nullable and
no missing-field alias exists, every integer is a safe integer bounded by
`9007199254740991`, and no free-form metadata or map field exists anywhere.
Canonical bytes are exact RFC 8785 JCS of the envelope, and the request hash is
`sha256:` over exactly those bytes. The raw Idempotency-Key never enters the
canonical envelope and is never persisted; only its SHA-256 hash participates
in the receipt namespace. `docs/CANONICALIZATION.md` carries the byte-level
envelope contract and `architecture/contracts/workspace-managed-authority-command.schema.json`
is its reviewed schema with golden JCS vectors under `tests/contracts`.

`WORKSPACE_CONFIRMATION_GRANT_ISSUE` requests exactly `organization_id`,
`workspace_id`, `expected_workspace_revision`,
`expected_workspace_configuration_hash`, `target_principal_id`, `ttl_seconds`
and `expected_policy_revision`, with `ttl_seconds` an integer between 60 and
86400 inclusive. The server later derives, from one PostgreSQL
transaction-second inside the command transaction: the grant ID, revision `1`,
the fixed permission `workspace.source.confirm`, `granted_by`, `granted_at`,
`valid_from` equal to `granted_at`, `valid_until` equal to `granted_at` plus
`ttl_seconds`, and the canonical grant hash. A client cannot supply any of
those server-owned fields; a request carrying a result ID, hash, timestamp,
permission or reason code is invalid.

`WORKSPACE_CONFIRMATION_GRANT_REVOKE` requests exactly `organization_id`,
`workspace_id`, `grant_id`, `grant_revision`, `grant_hash` and
`expected_policy_revision`. The server owns the revocation ID, `revoked_by`,
`revoked_at`, the fixed reason code `AUTHORITY_REVOKED` and the canonical
revocation hash. The request deliberately carries no expected
WorkspaceRevision: a stale grant must remain revocable, so access reduction
never depends on a fresh optimistic configuration precondition.

`WORKSPACE_MANAGED_CONFIRM` requests exactly the target tuple
`organization_id`, `workspace_id`, `workspace_revision`,
`workspace_configuration_hash`, `workspace_source_id`, `source_scope_id`,
`source_scope_revision`, `scope_config_hash`, the fixed `access_mode`
`WORKSPACE_MANAGED`, the exact grant identity `confirmation_actor_grant_id`,
`confirmation_actor_grant_revision`, `confirmation_actor_grant_hash`, the
warning binding `warning_version`, `warning_contract_hash`,
`acknowledgement_code`, and `expected_policy_revision`. The server owns the
confirmation ID, `confirmed_by`, `confirmed_at` and the canonical confirmation
hash. A warning body, `risk_codes`, localized warning text or any
acknowledgement other than the closed registry code is rejected.

`WORKSPACE_MANAGED_CONFIRM_REVOKE` requests exactly `organization_id`,
`workspace_id`, `confirmation_id`, `confirmation_hash` and
`expected_policy_revision`. The server owns the revocation ID, `revoked_by`,
`revoked_at`, the fixed reason code `ACCESS_REVOKED` and the canonical
revocation hash. There is no current-WorkspaceRevision precondition; the exact
historical parent ID and hash are the required precondition instead.

In every request `expected_policy_revision` is the opaque immutable
`policy_revision_id` from the organization policy-revision registry. A numeric
policy ordinal, a formatted counter string or a policy hash in its place is
invalid; the registry tuple stays the only bridge between the ordinal and the
opaque ID.

Every request also carries `organization_id`. It is canonical: it enters the
request bytes and the request hash exactly like any other field, and altering
it changes the hash. It is never, by itself, tenant authority. Before any
tenant-scoped access the server exact-matches request `organization_id`
against the trusted `AccessContext.OrganizationID`; only that trusted value
ever selects a tenant. The tenant for `database.Write`, the
`SET LOCAL app.organization_id` session variable, the row-level-security
context, `receipt.organization_id`, `audit.organization_id`, and the
actor-scoped idempotency namespace all come exclusively from the trusted
`AccessContext.OrganizationID` — never from the request body, on either
initial execution or replay. A mismatch between request `organization_id` and
`AccessContext.OrganizationID` terminates `WORKSPACE_AUTHORITY_NOT_FOUND`
before any workspace, target principal, grant, confirmation, binding, policy
or warning lookup runs. The transaction that reserves the receipt opens only
under the trusted tenant, so the receipt and its `command_id` are themselves
always trusted-tenant rows; exactly one receipt and one audit event are
produced under the accepted receipt-status-to-audit-outcome mapping for
`NOT_FOUND`; no authority row is ever created; and `AuditEvent.workspace_id`
is null, matching the existing `NOT_FOUND` rule rather than a special case.
Replay resolves the receipt only inside the trusted `AccessContext.OrganizationID`
namespace; request `organization_id` can exact-match that namespace but can
never select it, so a cross-tenant replay is exactly as indistinguishable
from a missing receipt as a first-time cross-tenant command, and neither ever
becomes an existence oracle.

The authority policy matrix is fixed now, before code. Issuing a grant is
allowed only to an active Organization `OWNER` or `ADMIN`. The target must be
an active `HUMAN` principal of the same tenant, must currently be an effective
Workspace `OWNER` or `MANAGER` of the target workspace, and must be an exact
principal — never a group, service or agent principal. The issuer does not
need workspace membership, because the grant is authority metadata rather than
content access. Self-grant is allowed only when the issuer is simultaneously
Organization `OWNER`/`ADMIN` and themselves an eligible target Workspace
`OWNER`/`MANAGER`. There is no four-eyes workflow in 1.0 and none may appear
implicitly. `CONNECTOR_ADMIN`, `SECURITY_AUDITOR` and ordinary members cannot
issue a grant. The workspace must be `ACTIVE`.

Confirming requires all of the following at once: the actor is an active
`HUMAN` principal, is a current effective Workspace `OWNER` or `MANAGER`, and
is the exact principal of a current unrevoked actor grant whose workspace,
permission, policy revision and validity window exact-match the command.
Organization role alone never authorizes a confirmation, and workspace
ownership or management without that exact unrevoked actor grant is
insufficient. The command must reference the current policy revision, the
current warning version and contract hash, and the exact current enabled
`WORKSPACE_MANAGED` binding of the referenced WorkspaceRevision.

Revoking a grant is allowed to an active Organization `OWNER` or `ADMIN`, to
the current Workspace `OWNER`, and to the exact grant principal as self-revoke.
A Workspace `MANAGER` may revoke only their own grant through self-revoke.
Revoking a confirmation is allowed to an Organization `OWNER` or `ADMIN`, to a
current Workspace `OWNER` or `MANAGER`, and to the original `confirmed_by`
principal as self-revoke. Grant revocation does not require a current
WorkspaceRevision and may revoke a stale parent; confirmation revocation
likewise carries no current-WorkspaceRevision precondition but must exact-match
the historical parent ID and hash. Both revocations are accepted while the
workspace is `ACTIVE`, `READ_ONLY` or `ARCHIVED`; issue and confirm require
`ACTIVE`. `SECURITY_AUDITOR` remains read-only everywhere.

Initial execution and replay use different visibility rules, and the bare
term "workspace visibility" is never used without one of the following four
operation-specific definitions. For `WORKSPACE_CONFIRMATION_GRANT_ISSUE`, both
initial execution and a later replay of a stored result are available only to
a currently active Organization `OWNER` or `ADMIN`; the issuer needs no
workspace membership at either stage. If the actor has lost that organization
role, the terminal outcome is `WORKSPACE_AUTHORITY_DENIED` when they still
hold ordinary metadata visibility of the workspace, and
`WORKSPACE_AUTHORITY_NOT_FOUND` otherwise. Replay never re-requires that the
target still be Workspace `OWNER` or `MANAGER`: that condition gated the
original execution, not the historical receipt.

For `WORKSPACE_MANAGED_CONFIRM`, initial execution requires a current
Workspace `OWNER` or `MANAGER` acting under a live exact actor grant, exactly
as the policy matrix above states. Replay of a stored result requires only a
current effective Workspace `OWNER` or `MANAGER`; it does not re-require that
the historical actor grant remain live or that policy or warning still match
what the original command bound. If workspace membership visibility itself is
lost, replay terminates `WORKSPACE_AUTHORITY_NOT_FOUND`; if the workspace is
visible but the current role is insufficient, replay terminates
`WORKSPACE_AUTHORITY_DENIED`.

For `WORKSPACE_CONFIRMATION_GRANT_REVOKE`, both initial execution and replay
are available to a current Organization `OWNER` or `ADMIN`, to the current
Workspace `OWNER`, or to the exact grant principal acting as self-revoke; a
Workspace `MANAGER` has this access only for their own grant. The exact grant
principal may self-revoke and later replay their own receipt after being
removed from the workspace: self-revoke visibility never requires current
workspace membership.

For `WORKSPACE_MANAGED_CONFIRM_REVOKE`, both initial execution and replay are
available to a current Organization `OWNER` or `ADMIN`, to a current Workspace
`OWNER` or `MANAGER`, or to the exact historical `confirmed_by` principal
acting as self-revoke. The original confirmer may self-revoke and later
replay their own receipt after being removed from the workspace, on the same
terms as grant self-revoke.

Four rules are common to all four operations. A cross-tenant reference is
always `WORKSPACE_AUTHORITY_NOT_FOUND`, never `WORKSPACE_AUTHORITY_DENIED`. An
inactive or deprovisioned actor never receives a stored result, on either
initial execution or replay. Historical replay is permitted while the
workspace is `ACTIVE`, `READ_ONLY` or `ARCHIVED`, and replay never repeats the
execution-time preconditions — live grant, current warning, current policy —
that gated the original command; it repeats only current identity and current
visibility, and it never rewrites the receipt. Authority-metadata visibility
never grants source content or evidence access; a later checkpoint that widens
Organization Admin or self-revoke visibility over authority metadata does so
only for that metadata, never for source-content row-level security.

The public error surface is closed to
`WORKSPACE_AUTHORITY_REQUEST_INVALID`,
`WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT`, `WORKSPACE_AUTHORITY_DENIED`,
`WORKSPACE_AUTHORITY_NOT_FOUND`, `WORKSPACE_AUTHORITY_PRECONDITION_FAILED` and
`WORKSPACE_AUTHORITY_PERSISTENCE_FAILED`. A cross-tenant reference, a hidden
workspace, and a missing or invisible parent grant or confirmation all
terminate as `WORKSPACE_AUTHORITY_NOT_FOUND`; a visible workspace with an
insufficient role terminates as `WORKSPACE_AUTHORITY_DENIED`; a stale expected
revision, configuration hash, grant or confirmation hash, policy revision or
warning contract terminates as `WORKSPACE_AUTHORITY_PRECONDITION_FAILED`; the
same idempotency key with a different request hash terminates as
`WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT`. Database and internal causes never
leave the boundary except as `WORKSPACE_AUTHORITY_PERSISTENCE_FAILED` without
detail. Replay re-verifies current identity and the operation-specific
visibility defined above before returning anything, never the execution-time
preconditions that gated the original command; a revocation command never
becomes an existence oracle for a hidden workspace. An invalid request and an
idempotency conflict create no receipt and no audit event. Business terminal
outcomes (`SUCCESS`, `DENIED`, `NOT_FOUND`, `PRECONDITION_FAILED`) create
exactly one receipt and one content-free audit event. An infrastructure
failure rolls the transaction back and leaves no terminal receipt.

The future idempotency relation is named
`workspace_managed_authority_command_receipt`. This is a separate receipt
family: the checkpoint must not extend `workspace_command_receipt`, because the
authority sidecar never creates a WorkspaceRevision. The receipt namespace is
`(organization_id, actor_principal_id, idempotency_key_hash)`, where
`organization_id` is always the trusted `AccessContext.OrganizationID` from
the tenant fence above, never request `organization_id`; the same raw key
in the workspace receipt family and the authority receipt family addresses two
different namespaces, while inside the authority family one key can never be
reused for a different operation. Receipt statuses are closed to `PENDING`,
`SUCCESS`, `DENIED`, `NOT_FOUND` and `PRECONDITION_FAILED`. A `PENDING` receipt
cannot commit; a terminal receipt is immutable; the canonical request bytes and
request hash are immutable; `command_id`, result IDs, result hashes and server
timestamps are stored exactly once; replay returns the original immutable
result; one audit event belongs to exactly one receipt; the operation-specific
projection is closed by an exhaustive CHECK per operation; a generic intent
JSON column and an unconstrained nullable union are forbidden; and no request
ID, raw Idempotency-Key, credential, warning text or source content is ever
stored. Migration `000011` must fail closed if it finds authority rows created
before this receipt boundary: declaring them trusted automatically or
silently backfilling receipts is forbidden.

Every authority command additionally reserves a `command_id` at receipt
creation, before any authorization decision is evaluated. `command_id` is
server-generated at reservation time, immutable, unique within the tenant,
and never enters the request canonical bytes or request hash — it identifies
the receipt, not the request. Every business terminal outcome — `SUCCESS`,
`DENIED`, `NOT_FOUND` and `PRECONDITION_FAILED` alike — has a `command_id`,
because reservation happens before visibility or authorization is evaluated
and therefore before a business failure can even be known. `command_id` is
the audit resource ID for all four operations; it exists precisely because
`DENIED`, `NOT_FOUND` and `PRECONDITION_FAILED` outcomes have no created
grant, confirmation or revocation row to name instead, and a created or
parent authority ID must never be required as an audit resource on a path
where that row was never read or never came to exist.

The future command transaction runs one common decision phase before any
terminal branch is chosen, and no branch may be entered until that phase
completes. The phase is, in order: syntactic shape validation and
canonicalization; the trusted tenant fence defined above; opening
`database.Write` under the trusted `AccessContext.OrganizationID`;
reservation of the actor-scoped authority receipt and its `command_id`,
itself a trusted-tenant row; the workspace serialization row lock, taken only
once the tenant fence has passed; reloading current identity and evaluating
the operation-specific visibility defined above; authorization; and finally
loading, locking and exact-matching every business projection the specific
operation needs — current workspace state, revision and configuration;
current policy; current warning; the exact parent grant or confirmation; the
exact enabled binding and scope tuple; actor-grant validity and revocation;
and every other precondition already fixed above. Only after every one of
those checks completes does the transaction settle on exactly one terminal
decision — `SUCCESS`, `DENIED`, `NOT_FOUND` or `PRECONDITION_FAILED` — and
only then does it enter the matching branch below. A precondition mismatch
discovered during this phase is `PRECONDITION_FAILED` regardless of which
branch looked likely going in: the branch choice follows the decision, the
decision never follows the branch.

The order inside the decision phase is itself a safety invariant. A tenant
mismatch, a hidden workspace and an invisible parent grant or confirmation
each resolve — as `NOT_FOUND` — strictly before any later check that could
otherwise leak their existence, so a caller can never distinguish "wrong
tenant" from "hidden workspace" from "missing parent" by which later check
happened to run.

The business-failure branch is entered only once the decision phase has
settled on `DENIED`, `NOT_FOUND` or `PRECONDITION_FAILED`, never before. It
creates no result or revocation ID, no authority timestamp, no result JCS or
hash, and performs no authority-table INSERT. It appends exactly one
content-free command audit event, terminalizes the receipt with that status,
and commits. Nothing about a failed command is ever partially persisted.

The success branch is entered only once the decision phase has settled on
`SUCCESS`; it can never be the branch that first discovers an ordinary
business `PRECONDITION_FAILED` — that outcome belongs entirely to the
decision phase above. Once entered, the success branch performs only:
obtaining one PostgreSQL transaction-second; deriving the server-owned result
ID, or the revocation ID for the two revoke operations, and every other
server-owned field; building the canonical result JCS and its hash; inserting
exactly one authority relation row; appending the content-free command audit
event in the same transaction; terminalizing the receipt as `SUCCESS`; and
commit.

Database-side final gates may re-check the same projections the decision
phase already loaded, purely to defend against a time-of-check-to-time-of-use
race between the decision phase and commit. Drift they catch fails the whole
transaction closed and rolls it back; it never switches an already-chosen
branch to a different terminal status. Any infrastructure, database, JCS or
audit failure at any stage of either branch rolls back the entire transaction
— receipt, authority row and audit event together — and leaves no terminal
receipt. Revocation locks the parent workspace row for serialization but does
not require a current WorkspaceRevision. Replay never re-enters the decision
phase or either branch: it returns the stored terminal result and creates no
new authority row, receipt or audit event.

Migration `000011` also owes the database-side JCS gate: canonical bytes stored
next to each of the four authority records; the hash equal to SHA-256 of
exactly those bytes; every JSON field exact-matching its relational projection;
no unconditional raw INSERT for the application role; a receipt/actor/operation
gate on every authority table; receipt, authority row and audit event bound to
one transaction; FORCE ROW LEVEL SECURITY preserved; no generic mutating
SECURITY DEFINER tool; no second hand-written PostgreSQL JCS engine — Go JCS
validation and database projection/hash checks complement each other; and a
policy or warning advance between reservation and commit must roll back and
fail closed.

The audit contract is fixed but not yet wired into runtime enums. Future
actions are
`workspace.source_confirmation_grant_issued`,
`workspace.source_confirmation_grant_revoked`, `workspace.source_confirmed`
and `workspace.source_confirmation_revoked`. All four share one resource
type, `WORKSPACE_AUTHORITY_COMMAND`, and one resource-ID rule:
`audit.resource_id = receipt.command_id`, always, on every terminal outcome.
Grant, confirmation and revocation IDs never serve as the audit resource ID;
they appear only inside metadata, and only on `SUCCESS`.

Receipt status maps to audit outcome and error code exhaustively and without
exception. `SUCCESS` maps to audit outcome `SUCCESS` with a null error code.
`DENIED` maps to audit outcome `DENIED` with error code
`WORKSPACE_AUTHORITY_DENIED`. `NOT_FOUND` maps to audit outcome `DENIED` — the
audit outcome enum has no `NOT_FOUND` value, and collapsing it onto `DENIED`
at the outcome level keeps a hidden workspace indistinguishable from an
insufficient role in the audit trail itself — with error code
`WORKSPACE_AUTHORITY_NOT_FOUND` carrying the finer distinction.
`PRECONDITION_FAILED` maps to audit outcome `FAILED` with error code
`WORKSPACE_AUTHORITY_PRECONDITION_FAILED`. `PENDING` is never terminal and
never produces an audit event. An invalid request and an idempotency conflict
create neither a receipt nor an audit event, and neither does an ordinary
replay of a matching key. A persistence failure rolls back the receipt, the
audit event and any authority row together.

Every audit event for these four actions sets `actor_type` to `HUMAN`,
`actor_principal_id` to the exact access actor, `on_behalf_of_principal_id` to
null, and `policy_decision_id` to null in this checkpoint.
`referenced_evidence_ids` is always the empty set. `request_id` is populated
only from the trusted AccessContext, never from the request body. Metadata
never contains the request canonical bytes, the request hash or the
idempotency-key hash.

Audit metadata for `DENIED`, `NOT_FOUND` and `PRECONDITION_FAILED` contains
exactly one key, `authority_operation`, and nothing else: no request-supplied
target ID, no parent ID or hash, no warning tuple and no expected policy
revision, because none of those were proven current at the point of failure.

`SUCCESS` metadata is closed per operation to trusted, persisted result and
parent projections — never to the unverified request. For
`WORKSPACE_CONFIRMATION_GRANT_ISSUE` it is exactly `authority_operation`,
`authority_result_id` (the created `grant_id`), `authority_result_hash` (the
created `grant_hash`), `target_principal_id` and `policy_revision`. For
`WORKSPACE_CONFIRMATION_GRANT_REVOKE` it is exactly `authority_operation`,
`authority_parent_id` (the revoked `grant_id`), `authority_parent_hash` (the
revoked `grant_hash`), `authority_revocation_id`, `authority_revocation_hash`,
`authority_reason_code` fixed to `AUTHORITY_REVOKED`, and `policy_revision`.
For `WORKSPACE_MANAGED_CONFIRM` it is exactly `authority_operation`,
`authority_result_id` (the created `confirmation_id`), `authority_result_hash`
(the created `confirmation_hash`), `workspace_revision`,
`workspace_configuration_hash`, `workspace_source_id`, `source_scope_id`,
`source_scope_revision`, `scope_config_hash`, `access_mode` fixed to
`WORKSPACE_MANAGED`, `confirmation_actor_grant_id`,
`confirmation_actor_grant_revision`, `confirmation_actor_grant_hash`,
`warning_version`, `warning_contract_hash`, `acknowledgement_code` and
`policy_revision`. For `WORKSPACE_MANAGED_CONFIRM_REVOKE` it is exactly
`authority_operation`, `authority_parent_id` (the revoked `confirmation_id`),
`authority_parent_hash` (the revoked `confirmation_hash`),
`authority_revocation_id`, `authority_revocation_hash`,
`authority_reason_code` fixed to `ACCESS_REVOKED`, and `policy_revision`.
Titles, paths, content, warning text, credentials, prompts, answers,
evidence, arbitrary metadata and the raw Idempotency-Key remain forbidden on
every outcome.

The main `AuditEvent.workspace_id` follows its own exhaustive rule, distinct
from `resource_id`. On `SUCCESS` it is the exact workspace ID. On `NOT_FOUND`
it is always null — a hidden or cross-tenant workspace must never leak its own
ID through the one path a caller cannot avoid seeing. On
`PRECONDITION_FAILED` it is the exact workspace ID, because reaching a
precondition check already proved same-tenant visibility. On `DENIED` it is
the exact workspace ID only if same-tenant workspace visibility was already
established before the role check failed, and null otherwise.

A later migration adds `WORKSPACE_AUTHORITY_COMMAND` to the resource-type
enum and these four actions to the action registry; runtime audit enums stay
unchanged in this checkpoint.

The architecture checker enforces this boundary with mutation-tested gates: the
contract schema, its golden JCS vectors and the request-shape fixtures are
protected; the schema is registered in the official contract fixture suite,
not validated ad hoc; the four operations and the `WORKSPACE_AUTHORITY_` error
namespace must not appear in runtime code, migrations, API, UI or deployment
surfaces before the `000011` checkpoint; and the normative sentences of this
decision are anchored so that weakening the policy matrix, collapsing initial
and replay visibility into one undefined "visibility" concept, reusing
`workspace_command_receipt`, adding client-owned server fields, requiring a
WorkspaceRevision for revocation, persisting the raw Idempotency-Key, using a
created grant or confirmation ID as the audit resource on a failure path,
dropping `command_id`, or weakening the exact receipt-status-to-audit-outcome
mapping or the exact per-operation metadata sets is a checker failure, not a
review debate. The checker also proves the schema's structural shape
directly: the exact property set of each of the four request definitions, the
exact one-to-one `operation`-to-request-definition mapping in the closed
`oneOf`, and that the schema's operation enum and per-operation field sets
match the Go validator's inventory exactly, field for field. The same
mutation-tested anchoring covers the tenant fence and the decision phase:
letting request `organization_id` govern `database.Write`, the RLS context,
`receipt.organization_id`, `audit.organization_id` or the idempotency
namespace instead of the trusted `AccessContext.OrganizationID`, dropping the
`AuditEvent.workspace_id` null rule on tenant mismatch, running a workspace,
target, grant, confirmation or binding lookup before the tenant fence,
choosing a terminal branch before the decision phase's business-precondition
evaluation completes, or letting the success branch reload policy, warning,
parent or binding projections it should already hold from the decision
phase, is a checker failure, not a review debate.

This architectural contract adds no dependency, module, service, model,
component or license. Persistence and runtime authority remain deferred until
the migration `000011` and repository checkpoint implement every invariant
above together with ADR-0052.
