# ADR-0079: Enterprise Question Run access through live UI, versioned API and read-only MCP

Status: accepted design.

Date: 2026-08-27.

Owners: product architect, identity/security owner, Question Run owner, product
surface owner.

Related: ADR-0003, ADR-0014, ADR-0053, ADR-0054, ADR-0058, ADR-0059,
ADR-0067, ADR-0073, ADR-0076, ADR-0078,
`PRODUCT_CONSTITUTION.md`, `docs/DATA_MODEL.md` §§2, 6–7,
`docs/CANONICALIZATION.md`, `docs/TRUST_BOUNDARY.md`, `api/openapi.yaml` and
`architecture/guardrails.yaml`.

## Context and current prohibition

An enterprise installation needs three ways to ask the same workspace-scoped
question: the live browser UI, a stable versioned HTTP API used by another
system, and an MCP server used by an authenticated user or service principal.
Those surfaces must produce the same immutable Question Run, policy decisions,
answer manifest and Evidence links. A transport-specific search implementation
would let policy, retrieval or citation behavior drift and is therefore not an
acceptable design.

The capability is **forbidden by the current accepted baseline**:

1. `PRODUCT_CONSTITUTION.md` §7 explicitly forbids both MCP and a public
   developer API in 1.0. Section 9 requires a proposed ADR, acceptance tests,
   explicit architecture-owner approval and only then code changes.
2. `architecture/guardrails.yaml` lists `mcp` in
   `forbidden_product_modules` and `/mcp` in
   `forbidden_api_path_fragments`. It also protects the Constitution,
   guardrails, OpenAPI-adjacent contracts, data model, trust boundary, tests and
   accepted ADR history.
3. `api/openapi.yaml` describes an internal, non-public API and explicitly says
   that a described handler is not necessarily composed into the running
   server. Its current version and routes do not constitute an external
   Question Run contract.
4. ADR-0053 and ADR-0054 keep the four workspace-managed authority operations
   and their error namespace out of every API/UI/MCP surface at their accepted
   checkpoints. This proposal does not expose those commands through MCP and
   does not use them as an implicit question-time grant.
5. ADR-0062 and ADR-0063 explicitly add no chat/agent/MCP capability. Their
   parser workers remain hostile data-plane components and cannot become MCP
   servers or obtain principal, policy, retrieval or source authority.

This accepted design records a future protected-baseline change. Creating
this file, reviewing it, or accepting its design does not amend any prohibition,
create an endpoint, select an MCP dependency, or activate a public service.

## Decision

### 1. One authority, three adapters

There will be one application authority for a Question Run. It owns, in order:

```text
authenticated AccessContext
  -> exact current workspace authorization
  -> immutable Question Run creation/idempotency
  -> corpus capture + retrieval + post-authorization
  -> generation/verification or extractive projection
  -> atomic terminal manifest commit
  -> current-access-checked result and Evidence disclosure
```

The browser handler, versioned HTTP handler and MCP handler are adapters around
that authority. They may parse their own wire envelopes and render their own
wire responses, but they may not own or copy policy evaluation, workspace
filtering, retrieval, model invocation, answer validation, citation resolution,
Evidence decryption, idempotency, rate accounting or audit decisions. They
invoke the same typed commands/queries with the same trusted `AccessContext` and
receive the same typed result projection.

No adapter calls another adapter over loopback HTTP, and no adapter reads
Question/Evidence tables directly. The shared application package depends on
the existing policy, Question Run and Evidence owners; it is not a second
facade-owned implementation. An architecture dependency gate and mutation test
must fail if an HTTP or MCP package imports OpenSearch, the model gateway,
source credentials, raw database repositories, or Evidence artifact decryption
instead of the shared authority.

The UI is live only when its production build calls the versioned question
surface and every displayed answer, status, source-health marker and link is a
projection of persisted system state. Static demo data, generated fixtures,
client-side policy, fabricated progress and fallback answers are forbidden in
production composition.

### 2. Versioned HTTP surface

The first external contract is a strict `/api/v1` Question Run surface. Exact
path spelling and schemas land in the later protected OpenAPI package, but the
semantic operations are fixed here:

| Operation | Semantic result |
| --- | --- |
| submit one question in one workspace | create or idempotently replay one immutable Question Run and return `202` with its opaque ID and status link |
| read one Question Run status | return its persisted status, corpus status and content-free typed failure only |
| read one terminal result | return the immutable answer projection, manifest identity and server-minted citation links after current-access recheck |
| read one cited Evidence fragment | resolve the exact fragment/version/extraction/anchor through the existing Evidence read gate after current-access recheck |
| observe bounded status events | return only monotonic persisted status projections and a final terminal marker; never partial answer text |

Every path includes the exact `workspace_id`; the server never infers a global
workspace, accepts a workspace filter array or searches multiple workspaces.
`organization_id`, actor ID, workspace revision, policy revision and principal
set are server-derived and cannot appear as caller-authoritative fields.

Request JSON schemas are closed and bounded; unknown members, duplicate JSON
members, ambiguous Unicode, invalid content types, unsupported answer modes and
oversize inputs are rejected before enqueue. Response schemas are versioned and
carry an explicit schema version. Source-native identifiers, credentials, raw
SQL, connector locators and model prompts are not request fields.

The browser may use an OIDC-backed browser session plus the existing CSRF
boundary. A non-browser API client uses the exact external authentication
profile selected by the later identity delivery decision; it never reuses a
browser cookie or a shared API key. Both become the same `AccessContext` before
the shared authority is called.

### 3. Actor-neutral principal and workspace authority

The current baseline is not sufficient for service-principal delivery.
`database.AccessContext` currently carries only organization/principal/request
IDs, the product identity/session model is human-OIDC-shaped, and existing audit
callers can hard-code `HUMAN`. This ADR proposes an actor-neutral contract but
does not pretend it already exists. A protected schema/data-model/canonicalization
amendment and migration are mandatory before any external API or MCP code.

The canonical `AccessContext` must represent exactly one authenticated actor and
contain at least this trusted, server-created tuple:

```text
organization_id
actor_kind = HUMAN | SERVICE
actor_principal_id
credential_id
credential_revision
authentication_revision
principal_set_snapshot_id + principal_set_snapshot_hash
access_authority_revision
access_snapshot_id + access_snapshot_hash
resolved_grant_id + grant_revision + grant_hash (or HUMAN_NONE)
resolved_grant_revocation_id + grant_revocation_hash (or NO_EFFECTIVE_REVOCATION)
access_authority_epoch_id + access_authority_epoch_hash
authenticated_at + expires_at
request_id
```

For a human, the credential/authentication revisions bind the exact OIDC
provider/session revisions and the principal-set snapshot binds current human
and group expansion. For a service actor they bind the exact service credential
revision and an actor-only principal set; a service credential never inherits a
human group, browser session or caller-supplied subject. The data model must add
canonical immutable records equivalent to:

```text
service_principal
  organization_id, principal_id, status(ACTIVE|REVOKED),
  authority_revision, created_at, revoked_at

service_principal_credential
  organization_id, principal_id, credential_id, credential_revision,
  authentication_binding_hash, issued_at, not_before, expires_at,
  status(ACTIVE|REVOKED|EXPIRED), revoked_at,
  issued_access_authority_epoch_id, issued_access_authority_revision,
  issued_access_authority_epoch_hash

service_principal_workspace_grant
  organization_id, grant_id, grant_revision, grant_hash,
  principal_id, workspace_id,
  operation(question.run.create|question.run.read|question.evidence.read),
  valid_from_workspace_revision, valid_to_workspace_revision,
  valid_from, valid_until, policy_revision, issued_by, issued_at,
  issued_access_authority_epoch_id, issued_access_authority_revision,
  issued_access_authority_epoch_hash

service_principal_workspace_grant_revocation
  organization_id, revocation_id, revocation_hash,
  grant_id, grant_revision, grant_hash,
  effective_workspace_revision, effective_at,
  revoke_command_digest, revoked_by, revoked_at,
  effective_access_authority_epoch_id,
  effective_access_authority_revision,
  effective_access_authority_epoch_hash

access_authority_epoch
  organization_id, epoch_id, access_authority_revision, epoch_hash,
  event_kind, event_subject_digest, previous_epoch_hash, committed_at
```

Credentials are stored only as an issuer/key/secret-provider-bound digest or
opaque reference, never raw secret/token bytes. Rotation creates a new immutable
credential revision; revoke/expiry is monotonic and advances both principal
`authority_revision` and the authentication/cache revision. Each grant row
authorizes exactly one operation, one workspace and one bounded revision/time
interval. A grant is never updated or deleted: a changed grant is a new
immutable row and the old row is revoked. The
`service_principal_workspace_grant_revocation` relation is append-only and
contains an exact immutable foreign-key reference to
`(organization_id, grant_id, grant_revision)`. Its `grant_hash` must equal the
referenced row's canonical `grant_hash`. A composite foreign key on
`(organization_id, effective_access_authority_epoch_id,
effective_access_authority_revision)` must reference the single atomically
committed `access_authority_epoch` row, and `effective_access_authority_epoch_hash`
must equal that row's canonical `epoch_hash`; the referenced grant and epoch
cannot be updated or deleted. A unique constraint on
`(organization_id, grant_id, grant_revision)` permits at most one revocation;
`revocation_hash` is the canonical digest of the exact relation (including its
grant and epoch bindings), and the canonical `revoke_command_digest` makes the
same revoke command idempotent and returns that row, while a different command
for the same grant is a typed conflict. No direct status flag or cache
invalidation substitutes for this relation.

A service-grant revoke is immediate-only: its `effective_at` is exactly the
revocation transaction's commit time and its `effective_workspace_revision` is
exactly the current workspace revision atomically observed by that transaction.
The transaction obtains the exclusive grant and workspace lineages before that
observation, writes those exact values and the new authority epoch, and commits
them together. A caller cannot supply a future `effective_at` or future
workspace revision, and a scheduled-revocation row, queue, job or state is
forbidden. Exact replay of the same canonical revoke command returns the one
committed revocation row without advancing authority; a semantically different
second revoke for that already-revoked grant is terminal `already-revoked` /
typed conflict and can never restore authority. Thus an urgent revoke is never
queued behind an earlier schedule, because schedules do not exist.

The service-authority owner is the sole writer for credential, grant,
revocation and access-authority-epoch state. Credential issue/rotation/revoke,
grant issue and grant revoke each acquire the conflicting exclusive
`DisclosureFence` lineages, increment `access_authority_revision` exactly once,
append the epoch event and the immutable subject row/revocation in one atomic
transaction, and commit them together. The transaction records the previous
epoch binding and the new epoch ID/revision/hash; a retry either commits the
whole transaction once or returns the existing idempotent result. There is no
out-of-band grant revoke, credential revoke or epoch advance.

For a service actor, the current grant predicate is exact and is never a
cached ALLOW:

```text
CurrentServiceGrant(ctx, g, workspace_id, operation, now,
                    workspace_revision, policy_revision) iff
  g is the exact immutable row for
    (ctx.organization_id, ctx.actor_principal_id, workspace_id, operation)
  and g.grant_hash is the digest of that exact row
  and g.valid_from <= now < g.valid_until
  and g.valid_from_workspace_revision <= workspace_revision
      <= g.valid_to_workspace_revision
  and g.policy_revision (the canonical organization/workspace policy-revision
      tuple used by this grant) exactly matches the current revisions used by
      the current-access gate
  and no committed revocation row r exists for the exact immutable
      (ctx.organization_id, g.grant_id, g.grant_revision)
  and the current organization access-authority epoch is exactly
      ctx.access_authority_revision, ctx.access_authority_epoch_id and
      ctx.access_authority_epoch_hash
```

An effective revocation is the one atomically committed immediate revoke for
that exact immutable grant revision; it is permanent across all later
access-authority epoch advances, even when unrelated credentials or grants
change. Its bound `effective_access_authority_revision`/epoch is historical
commit-chain evidence, not a filter limiting the absence predicate. If ancestry
is consulted, the owner proves that historical revocation epoch belongs to the
immutable chain leading to the current epoch; the absence predicate itself
never drops an older revoke. An absent row is represented by the canonical
`NO_EFFECTIVE_REVOCATION` marker. The gate also requires the exact active
credential revision and principal status. There is no `>=` epoch check, stale
snapshot acceptance or grant-ID-only shortcut: `AccessContext` separately
exact-matches the latest current `access_authority_revision` and epoch, while
`PolicyDecision` captures those current values after the live check. Grant,
revocation and epoch IDs/hashes are resolved from the owner tables, not from a
token or caller field.

Grant change/revoke is immutable/audited, advances `access_authority_revision`,
and cannot be replaced by an organization role. The same exact resolved grant,
revocation (or no-effective-revocation marker) and access-authority epoch
lineage is carried by the persisted `PolicyDecision`, Question Run provenance,
signed manifest, audit event and idempotency actor scope. For human decisions,
the grant fields use a typed `HUMAN_NONE` marker; a denial caused by an
effective revoke records the exact revocation ID/hash without disclosing its
content.

The exact actor must pass the operation matrix below through the one policy
layer:

| Operation | Human authority | Service authority |
| --- | --- | --- |
| `question.run.create` | active exact OIDC/session revision plus current workspace membership role permitting create | active exact service credential revision plus one current `service_principal_workspace_grant` row for this workspace/operation/revision/time |
| `question.run.read` | active exact OIDC/session revision plus current workspace membership role permitting read; run ownership is insufficient | active exact service credential revision plus one current exact read grant; run ownership or ID possession is insufficient |
| `question.evidence.read` | active exact OIDC/session revision plus current workspace membership permission and complete current Evidence grant path | active exact service credential revision plus one current exact evidence-read grant and complete permitted `WORKSPACE_MANAGED` Evidence path |

Organization OWNER/ADMIN, connector administration and service-principal
registration give **no data permission**. One actor may have different grants in
different workspaces, and no organization-wide question grant or cross-workspace
result join exists. A token workspace/scope claim is an input hint at most, never
the grant relation.

The immutable access snapshot canonically binds actor kind/ID, credential
ID/revision, authentication revision, principal-set snapshot ID/hash, exact
workspace operation grant/member revision and policy revision; its content hash
excludes wall-clock observation fields while `captured_at`/`expires_at` remain
separately exact-checked freshness metadata. `AccessContext` access-snapshot
ID/hash, actor kind/ID, credential ID/revision,
`access_authority_revision`, access-authority epoch ID/hash and the resolved
grant/revocation IDs/hashes must exact-match every persisted `PolicyDecision`.
The same complete actor-authority lineage is bound into Question Run provenance
and signed manifest, audit actor fields and the idempotency actor scope.
Consequently a credential rotation or grant-authority revision is a new
idempotency actor epoch; it cannot replay work authorized under the old
credential merely by reusing its raw key. The idempotency row also retains the
originating access snapshot ID/hash and every resolved grant/revocation/epoch
ID/hash, while content disclosure still performs the current live checks in
§§6 and 6.1.

A client name, MCP `clientInfo`, request header, email, API-key label, upstream
system user string or caller-supplied `on_behalf_of` value is not identity
authority. This capability has no impersonation, token exchange or delegation
chain. An integration needing per-user results authenticates as that exact human;
otherwise audit and policy identify the exact service principal.

For `WORKSPACE_MANAGED`, a service principal may use only its explicit current
workspace operation grant plus the existing exact workspace/source confirmation.
For `SOURCE_ENFORCED`, a service principal is unconditionally denied until a
separate ADR accepts and a later delivery implements a cryptographically bound
source-native service identity, fresh group/ACL mapping and revocation contract.
The service credential itself, a matching display name or the human user's
source ACL can never be treated as that mapping. Wire authentication remains
deferred under §11.

### 4. One-shot immutable Question Run and cross-surface idempotency

Submission always means one independent question. There is no conversation ID,
message history, previous-answer context, follow-up tool state or hidden MCP
session context. A rerun is another Question Run and is never an update of the
old run.

`Idempotency-Key` is mandatory for UI, API and MCP submission. The shared
idempotency owner, not an adapter, enforces the actor-neutral scope
`(organization_id, actor_kind, actor_principal_id, credential_revision,
access_authority_revision, access_authority_epoch_id,
access_authority_epoch_hash, resolved_grant_id, grant_revision,
resolved_grant_hash, resolved_grant_revocation_id,
resolved_grant_revocation_hash, access_snapshot_hash,
idempotency_key_digest)` proposed in §3 and persists the exact originating
access-snapshot ID/hash. `HUMAN_NONE` and `NO_EFFECTIVE_REVOCATION` are typed
scope values, not omitted columns. This intentionally requires a protected
amendment to the current human-shaped idempotency relation. Its
canonical request hash covers the exact workspace ID, canonical question bytes,
answer mode and every caller-selected result-affecting option. The workspace
revision is captured once in the created Question Run; it is not recomputed into
the replay hash, so an exact retry within the same actor authority epoch after a
later workspace revision still returns the original run. Transport name, HTTP
request ID and MCP request ID do not affect the hash, so an exact retry by the
same actor authority through another adapter returns the same run. A new
credential/grant authority epoch does not inherit the old key scope. The same
key in the same epoch with a different canonical request returns the one typed
idempotency conflict. Raw keys are not logged or stored.

An accepted request durably creates the Question Run and queue work before the
adapter returns. Disconnecting the UI, API stream or MCP call neither loses nor
cancels it. There is no MCP or public-API mutation for editing, cancelling,
amending or deleting a run in this capability. Terminal status, answer, claims,
citations, context snapshot and manifest remain protected by the existing
immutable completion gate.

### 5. Asynchronous status and bounded streaming

Question execution is asynchronous. Submission returns the durable handle; all
clients can poll status. The product must not hold a model call open as the only
way to recover a result.

The optional API/UI status stream is request-scoped and bounded by maximum wall
time, event count, event bytes, heartbeat count and per-principal concurrent
streams. It contains a closed sequence derived from persisted transitions such
as `QUEUED`, `RUNNING` and one terminal status. It contains no retrieval hits,
prompt, model tokens, draft claims, answer text, excerpts or source metadata.
The complete answer becomes visible only after the atomic terminal transaction;
there is no token-streamed answer that could later disagree with the signed
manifest.

Every stream authenticates and authorizes before opening. Immediately before
**each** event, heartbeat, terminal marker or any other write (including an
initial response write, flush and close-detail write), it performs a fresh
current-access authorization, derives the relevant exhaustive `DisclosureFence`
set from that gate, materializes only that bounded emission into a private
buffer, acquires every shared key and exact-revalidates all current revisions
and epochs. The shared fence is held through the trusted edge's last byte of
that emission, then the private buffer is destroyed and the fence is released.
The bounded cadence is only a scheduling/resource limit; it never caches or
reuses an `ALLOW`. No event, heartbeat or write may use an authorization result
from an earlier emission.

For every event, heartbeat and write, the post-fence revalidation also computes
the earliest temporal/revision boundary of every predicate mechanically
registered by `CurrentAccessReadGate`: credential/session/token or access
snapshot expiry, grant `valid_until`, policy/ACL/membership validity,
retention, Evidence/source/extraction validity, and every other registered
validity boundary. Its write deadline plus a fixed safety margin must be
strictly before that earliest boundary. If there is no sufficient interval, the
emission commits zero event bytes and follows the uniform deny/close path. A
fence does not freeze wall clock: while holding it, the writer checks the clock
before each chunk/flush and aborts, discards uncommitted bytes and releases the
fence before a boundary can be crossed. No write is permitted at or after a
boundary.

If a revoke commits before an emission obtains and revalidates its shared fence,
that emission writes zero bytes. If the emission acquired the fence first, the
conflicting revoke waits until its last byte, and that emission is the one
linearized before the revoke. After the revoke commit there is no subsequent
event, heartbeat, terminal marker or close-detail byte. The stream then ends
with the same generic transport close used for a missing/unauthorized resource:
no reason, resource ID, status/detail variation, retry hint, ETag,
content-length, cache header, cache entry or resource-specific timing metadata
is allowed. At equivalent lifecycle points the close has the same bounded
external timing class as missing/unauthorized handling.

A reconnect does a normal status read with the same per-emission rules;
delivery correctness never depends on an unbounded buffer, sticky server,
hidden session or client replay cursor. Slow consumers are disconnected at the
byte/time bound rather than accumulating memory, and a disconnect/cancel/write
failure/deadline stops all subsequent writes, destroys the private emission
buffer and releases its fence before any revocation owner can commit.

MCP uses durable start-and-poll semantics. Any protocol-level streaming,
subscription or task extension remains outside this ADR; MCP transport choices
cannot weaken the application bounds above. The same fresh-gated status/poll
surface and barrier requirements apply to its equivalent status projection.

### 6. Result, citation and Evidence disclosure

A terminal result returns only the persisted deterministic rendering and typed
structured representation of the same signed manifest. It does not ask a model
to re-render for API or MCP. Citation numbers, Evidence IDs and links are
server-built from persisted citation rows, never parsed from model Markdown.

Each citation carries opaque, versioned links for:

- the Question Run result;
- its exact citation projection; and
- the exact Evidence fragment/version/extraction/anchor viewer.

Links are locators, not bearer capabilities and not public shares. Opening a
result, citation or Evidence resource re-authenticates the caller and performs
the current live access check described by `docs/DATA_MODEL.md` and
`docs/CANONICALIZATION.md`. A saved response, cached MCP resource, valid
signature or possession of an ID never overrides membership removal, source
revocation, stale ACL, retention purge or extraction state. Revoked content is
not returned with an advisory warning: its disclosure is denied, while the
allowed tombstone/status projection stays content-free.

HTTP and MCP evidence reads call the existing Evidence resolver. Neither may
reconstruct an excerpt from OpenSearch, raw source data, a model artifact or the
stored answer. Exact anchor failure, chain mismatch or access failure is the
same denial.

### 6.1 Last-byte authorization linearization

An authorization check followed by an ordinary streamed write has a revocation
race: access can be revoked after the check while bytes are still leaving the
server. Every content-bearing UI, API and MCP result, citation and Evidence
read, and every content-free status/poll emission, therefore uses one shared
`DisclosureFence` owned below all adapters. The ADR fixes the fence semantics;
it does not select its storage primitive.

There is one canonical `CurrentAccessReadGate` for all of those reads and
emissions. For a particular response or emission `e`, the gate returns its
current authorization decision and the complete set of mutable predicates and
stable lineages on which that decision and projection depend, plus the complete
set of their temporal/revision validity boundaries. The fence set is
the exhaustive mechanically generated projection

```text
DisclosureFenceSet(e) = sort_unique(
  (organization_id, lineage_kind, stable_lineage_id)
  for every mutable predicate/lineage evaluated by CurrentAccessReadGate(e)
)
```

`stable_lineage_id` is the identity of the authority lineage, never a revision
or epoch value. A revision/epoch change therefore conflicts on the same stable
key; revisions and epochs are exact values revalidated after the shared fence
has been acquired. This is not a hand-maintained finite revoke list. The
mechanically generated projection must include, at minimum, organization and
workspace policy revisions; the `service_principal_workspace_grant` lineage,
its exact grant-revocation relation and `access_authority_revision`/epoch;
organization/workspace and workspace lifecycle; credential, principal and
signing-key revocation; group and principal-set snapshots; workspace
membership; workspace-source bindings and confirmations; source ACL grants;
source object/version; active extraction; Evidence chain and retention; and
Question Run/result/citation/manifest lifecycle and retention. It also includes
source-connection trust and scope activation whenever the current-read
predicate uses either. Adding a predicate to the gate automatically adds its
stable lineage; it cannot be silently omitted because it is absent from this
minimum list.

A closed `DisclosureFenceOwnerRegistry` is generated from and mechanically
checked against the predicate-owner declarations of `CurrentAccessReadGate`.
Each generated entry names the predicate, stable-lineage extractor, exact
revision/epoch revalidator, shared-key builder and every transaction owner
that can mutate it, together with that owner's exclusive-key builder. The
registry and the gate/mutation dependency graph are checked in both directions:
an unregistered gate predicate, a predicate without a shared stable key, or a
mutation owner without a conflicting exclusive stable key turns the
dependency/mutation test **RED**. An owner/key not backed by a registered gate
predicate is also an error, and wildcard/catch-all entries are forbidden. This
closed check is what makes the projection exhaustive as the gate evolves; a
new current-read predicate cannot land without its shared and exclusive
lineage proof.

The exact read/emission sequence is:

```text
authenticate canonical AccessContext
  -> invoke the one CurrentAccessReadGate and capture exact live
     authority/revision/epoch tuple plus its predicate lineages
  -> materialize the complete bounded response into a private server buffer
  -> derive DisclosureFenceSet(e), acquire every shared key, and exact-match
     revalidate every current revision/epoch, resolved grant/revocation, and
     every registered temporal/revision boundary; compute a deadline whose
     safety margin is strictly before the earliest boundary
  -> first content byte
  -> before every chunk/write/flush, recheck clock versus deadline/boundary;
     abort before a crossing
  -> last content byte or writer cancellation/connection termination
  -> destroy private buffer and release shared response fence
```

Materialization exposes no byte and creates no externally readable cache. Fence
acquisition and the second exact-match validation are one repository operation;
a mismatch destroys the buffer and returns the uniform denial before response
headers or content bytes are committed. A multi-citation answer or status
emission acquires its entire generated set or none; it never acquires a
manually selected prefix.

The same deadline rule applies to every content response, including a one-byte
or buffered response: its planned trusted-edge completion plus safety margin is
strictly before the earliest registered boundary. The implementation may not
estimate past a boundary or treat a prior check as a clock freeze. If the clock
reaches the deadline/boundary before the final trusted-edge byte, it stops
without another write, discards every not-yet-emitted byte, releases the fence,
and uses the uniform denial/close behavior.

Every KnowVault transaction that can change **any** predicate in
`CurrentAccessReadGate`—positive grant/activation as well as revoke,
credential, principal, group snapshot, organization/workspace policy revision,
workspace lifecycle, membership, binding, workspace-managed confirmation,
source connection trust/scope activation, source ACL, source object/version,
active extraction, signing-key state, Evidence, Question Run/result/citation or
retention—must derive the same stable-lineage projection, acquire all
conflicting **exclusive** fence keys in the canonical order before changing
authority, and hold them through commit. Every writer is behind its registered
owner; there is no direct table update, cache invalidation or revocation path
outside that owner. In particular, no current-read predicate revision, epoch,
validity boundary or revocation binding may change except inside a transaction
that has acquired its registered exclusive lineage fence and holds it through
commit.

The fence primitive must be cross-instance: all application instances use the
same shared/exclusive namespace and a holder crash, connection loss or owner
termination releases (or safely invalidates) its keys. A later delivery may
choose database advisory locks, database row locks or another proven primitive,
but it must explicitly prove the selected primitive's cross-instance
visibility, shared/exclusive conflict, holder identity, transaction/session
lifetime, crash release and ability to hold a read fence through the trusted
edge's last byte. A process-local mutex is never sufficient, and the ADR does
not preselect PostgreSQL, a lock table or a session/transaction arrangement.

All shared and exclusive sets use the same canonical byte representation,
organization namespace, stable lineage identity, de-duplication and total
deterministic ordering. Deadlock/lock-timeout handling is bounded: a read
emission with a partial or failed acquisition emits no bytes, and a mutating
transaction retries its entire transaction (never a partially applied write)
only within an owner-defined finite attempt/time budget. Exhausting that bound
returns a uniform fail-closed result; there is no unlocked fallback, stale
`ALLOW` or unbounded retry. The delivery proof must cover these semantics for
every selected DB advisory/row-lock mode and every runtime instance.

The linearization rule is exact:

- if revoke commits before the read obtains and revalidates its shared fence,
  the read emits **zero content bytes**;
- if the read obtains the shared fence first, the conflicting revoke transaction
  waits and cannot commit until the read writes its last byte or aborts and
  releases the fence.

The same two cases apply independently to each status event, heartbeat,
terminal marker or other emission. A status emission that loses the fresh gate
or shared-fence acquisition emits zero bytes; a revoke cannot commit through a
shared emission fence and no later emission is permitted after that commit.

No registered temporal/revision boundary can occur inside a response or
emission: the deadline plus safety margin must be strictly earlier than the
earliest boundary, otherwise the server refuses before the first byte. This
includes credential, session, token and access-snapshot expiry, grant validity,
policy/ACL/membership validity, retention and Evidence/source/extraction
validity, plus every future gate predicate. Cancellation, client disconnect,
write error or deadline first stops the writer, prevents all further writes,
discards every trusted-edge buffer and only then releases the fence. Bytes
already written belong to the read linearized before revoke; no byte may be
emitted after release. Content endpoints terminate TLS at the trusted edge and
forbid CDN/proxy/cache buffering that could continue disclosure after the
application fence is released. “Last byte” means the trusted edge has completed
the final bounded write/flush; it never means merely that a handler queued bytes
to an asynchronous downstream buffer.

The status stream in §5 remains deliberately content-free, but it is a fenced
read **for each emission**. It may reveal only the already defined non-oracular
status class and never a final answer, citation, Evidence excerpt, source name
or content-derived count. Any future addition of a content-bearing status event
would require another accepted decision and the same exhaustive gate.

### 7. MCP is a read/query facade, not an agent or source connector

The proposed MCP capability is a thin server adapter inside the existing
`knowvault-server` composition. It exposes a closed, statically reviewed
inventory equivalent to:

| MCP capability | Allowed meaning |
| --- | --- |
| `knowvault.question_start` tool | submit exactly one bounded, workspace-scoped read/query and return its durable Question Run handle |
| `knowvault.question_get` tool | read authorized persisted status |
| `knowvault.answer_get` tool | read the authorized terminal result |
| `knowvault.evidence_get` tool | read one exact authorized cited Evidence fragment |
| versioned Question Run/Evidence resource URI templates | alternate read-only projections of the same `*_get` authority |

"Read-only" here means the MCP client cannot change a workspace, source,
external system or published result. `question_start` necessarily records a new
immutable query execution for reproducibility and audit, but has no control-plane
or source-side effect. It is the only permitted create-like operation.

The server exposes no workspace/source/member/credential management, ingestion
trigger, arbitrary search endpoint, prompt catalog, write action, cancellation,
answer amendment, SQL, connector call or generic URL/file fetch. It exposes no
raw query output and no global resource listing. `resources/list`, if required
by the exact selected protocol, returns only static non-sensitive templates or
an empty instance list; it never enumerates workspace, run or Evidence IDs.

The internal embedding/reranking/generation/verifier models still receive **no
tools**, MCP client metadata or source credentials, preserving Constitution §6
and `MOD-001`. An external MCP host may choose to let its own model call the
KnowVault facade, but that host is outside the trusted Question Run model
boundary and gains only the exact authenticated principal's grants. Tool output
cannot cause KnowVault's model to invoke another tool.

Tool names, descriptions and JSON schemas are server-owned immutable assets.
Questions, source text, email, documents, Git content, SQL-derived Evidence,
model output and MCP client metadata are untrusted data and are never promoted
to a tool name, description, schema, URI authority, policy operation, header or
follow-up instruction. Content-bearing fields are structurally separated and
marked untrusted in the common result schema. The renderer never creates a link,
tool call or resource URI from model/source prose, never auto-fetches a cited or
embedded URL, and never reflects source content into protocol errors.

Input/output schemas have bounded byte size, depth, array cardinality and
validation time; remote `$ref`, schema-driven network fetch and recursive schema
expansion are forbidden. Unknown tool/resource names and prompt/tool-injection
attempts receive content-free errors. MCP roots, sampling, elicitation, logging,
prompts and client-provided tools are not capabilities of this server.

### 8. Resource, concurrency and abuse bounds

Bounds are enforced in the shared authority and, where cheaper, again at each
edge. Immutable configuration sets maximum question UTF-8 bytes, JSON depth,
request bytes, active runs per principal/workspace/organization, submissions per
time window, queued work, model attempts, retrieval candidates/context bytes,
execution time, status polls, streams, response bytes and Evidence bytes.
Counting occurs before large allocation and before enqueue where applicable.

Rate and concurrency keys use authenticated organization/principal and trusted
workspace identity, never only IP address or a caller-supplied tenant. A bounded
global overload gate also exists so many valid tenants cannot exhaust the
installation. Fair scheduling prevents one workspace from monopolizing model or
retrieval capacity. Retries are bounded and reuse the same run/idempotency row;
they do not multiply work silently.

Rate rejection is a typed, content-free result with bounded retry metadata. A
queue-full, timeout, model failure or resource cap cannot fall back to an
unverified answer or a smaller hidden corpus. Accepted runs persist an explicit
terminal failure or corpus status according to the existing Question Run
contract.

### 9. Tenant/workspace non-oracle and error contract

After authentication, an absent organization/workspace/run/Evidence ID, a real
object in another tenant/workspace, an object outside the principal's grants and
a mismatched parent/child tuple all produce the same external not-found class,
body schema, cache policy and bounded timing class. The application performs the
tenant/workspace predicate in the owning database query; adapters do not fetch
then filter.

No list, count, status, ETag, rate bucket, stream behavior, citation number,
error detail, MCP discovery response or cache metadata reveals the existence,
name, freshness or size of an unauthorized workspace/corpus/run/resource.
Authentication failure may remain a distinct protocol-level class before any
resource lookup. Authorization challenge metadata is server configuration, not
resource-specific disclosure.

Request correlation IDs are server-generated or syntax-validated opaque values.
Client metadata is never copied into an error. Database, OpenSearch, model,
connector and policy errors are mapped to a closed, content-free namespace.

### 10. Audit and observability

The owning transaction records content-free audit events for accepted Question
Run creation/idempotent replay, terminal completion/failure, result disclosure,
Evidence disclosure, access denial, principal/service-principal revocation and
rate/resource rejection. High-frequency status polling may be represented by a
bounded aggregated security counter plus sampled request telemetry, but every
content disclosure and every policy decision remains attributable to the exact
principal, workspace, request and Question Run.

Audit identifies adapter kind (`UI`, `API`, `MCP`) as non-authoritative metadata
and carries internal IDs, policy-decision ID, outcome, typed code, counts and
durations only. It contains no question text, answer, excerpt, source value,
prompt, token, Authorization header, cookie, raw idempotency key, MCP arguments,
client-provided identity, SQL or source credentials. Metrics use bounded labels
and never organization/workspace names or content-derived values.

MCP/client protocol logs cannot bypass the audit/logging policy. Wire body
logging is disabled; debug modes that log payloads, weaken header/content-type
checks, accept protocol downgrade or expose SDK internals are forbidden in the
production profile.

### 11. MCP protocol, transport, authorization and dependency are deferred

This ADR deliberately does **not** select or activate an MCP protocol revision,
transport, authorization profile, endpoint path, extension set, SDK or package
version. Those are supply-chain and trust-boundary choices that require a
separate exact owner decision and atomic protected delivery package.

The official MCP project published revision `2026-07-28` as GA with a stateless
per-request core, `server/discover`, request-scoped Streamable HTTP behavior and
authorization hardening. It also deprecated Roots, Sampling and Logging. These
facts make `2026-07-28` the only current production candidate for the later
decision, not a dependency selection made by this proposal. See the official
[release announcement](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[revision changelog](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx),
[Streamable HTTP specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx)
and [official Go SDK releases](https://github.com/modelcontextprotocol/go-sdk/releases).

Before any MCP code lands, the later decision must exact-pin all of:

1. the final official protocol revision and immutable specification reference;
2. the one production transport and endpoint/origin/header/content-type rules;
3. the authorization-server discovery, issuer/audience/resource/scope,
   human/service-principal and credential-revocation profile;
4. the exact official SDK version, module checksum, transitive dependency set,
   license/NOTICE, SBOM, vulnerability review and offline artifact provenance;
5. the exact capability/extension inventory and conformance-suite version.

If that decision selects `2026-07-28`, production must pin only that revision,
reject negotiation/downgrade to legacy revisions, use its stateless request
semantics, and omit deprecated Roots, Sampling and Logging as well as all
unselected extensions. Legacy HTTP+SSE, stateful sessions, stdio deployment,
Tasks, MCP Apps, Enterprise Managed Authorization or backwards compatibility
would each need explicit security analysis; none is implicitly allowed here.
SDK support or protocol conformance never substitutes for KnowVault policy,
current-access checks, non-oracle behavior or the gates in this ADR.

### 12. API compatibility and revocation

The OpenAPI document is the normative HTTP wire contract. Input schemas remain
closed within a major version. Backwards-compatible additions are optional
response fields with defined defaults; a breaking request/meaning/error/security
change creates a parallel major path and migration window. A server never
silently interprets a v1 request as v2 or negotiates a weaker security profile.
Every response carries the selected API/schema version and build identity.

MCP tool/resource schemas are generated or mechanically compared against the
same typed application schemas. Their names and meanings are versioned; a new
tool version cannot silently change the canonical Question Run request. Protocol
compatibility and product-schema compatibility are separate and both must pass.

Credential, principal, group, workspace membership, policy, source grant and
signing-key revocation are checked on every new request. No adapter caches an
ALLOW across calls. Long status streams recheck as specified in §5; result and
Evidence reads always recheck and hold the shared last-byte fence of §6.1.
Every local revocation owner participates in its conflicting exclusive fence;
"invalidate cache after commit" is not a substitute. Tool/result caching, if the
later MCP decision permits it, must be private to the exact authenticated actor
authority and have zero authorization lifetime for content: a cache is a client
convenience, not disclosure authority.

Client registrations and service-principal credentials have explicit revision,
expiry, rotation and revoke paths. Token passthrough to a model, connector,
OpenSearch or downstream source is forbidden. Revocation tests must prove that a
previously valid API/MCP credential, cached result link and open stream cannot
disclose content after the revocation commit.

## Reserved invariant and proof inventory

These proposed proof IDs remain reservations. They become guardrail/test
identifiers only in a later accepted atomic delivery package; their appearance
here is not a delivery claim.

| Reserved invariant | Required proof IDs |
| --- | --- |
| `SURF-001` UI/API/MCP use one Question Run authority | `architecture.surface.single-question-authority`, `mutation.surface.adapter-direct-retrieval` |
| `SURF-002` actor-neutral context binds exact human/service credential revision, access snapshot and current per-workspace operation grant, with immediate-only permanent service-grant revoke | `contract.surface.actor-neutral-access-context`, `acceptance.surface.exact-principal`, `mutation.surface.caller-supplied-actor`, `acceptance.surface.service-principal-grant-revoke`, `acceptance.surface.service-grant-revoke-no-schedule`, `acceptance.surface.service-grant-revoke-permanent-across-epochs`, `mutation.surface.grant-revoke-current-epoch-filter`, `acceptance.surface.service-source-enforced-deny` |
| `SURF-003` no cross-workspace or cross-tenant oracle exists | `acceptance.surface.workspace-isolation-matrix`, `mutation.surface.fetch-then-filter`, `acceptance.surface.uniform-not-found` |
| `SURF-004` submission is one-shot, immutable and cross-surface idempotent | `contract.surface.question-one-shot`, `acceptance.surface.cross-adapter-idempotency`, `mutation.surface.terminal-update` |
| `SURF-005` asynchronous status and streams are persisted, bounded, freshly authorized, temporally bounded and disclose no draft content or post-revoke oracle | `acceptance.surface.async-recovery`, `acceptance.surface.slow-consumer-bound`, `acceptance.surface.status-between-events-revoke`, `acceptance.surface.status-heartbeat-write-revoke`, `acceptance.surface.status-expiry-fence-barriers`, `acceptance.surface.status-reset-cancel-revoke`, `contract.surface.status-uniform-close`, `mutation.surface.partial-answer-stream`, `mutation.surface.status-cadence-cache-allow` |
| `SURF-006` every content response is authorization-linearized and temporally bounded through its last byte against every revocation owner and the exhaustive fence registry | `acceptance.surface.saved-answer-revocation`, `acceptance.surface.evidence-link-revocation`, `acceptance.surface.last-byte-fence-ui-api-mcp`, `acceptance.surface.content-expiry-fence-barriers`, `acceptance.surface.disconnect-fence-release`, `contract.surface.disclosure-fence-owner-registry`, `mutation.surface.cached-allow`, `mutation.surface.missing-revoke-fence`, `mutation.surface.missing-fence-owner` |
| `SURF-007` MCP inventory is read/query-only and cannot expose source credentials, SQL, global search or writes | `contract.mcp.closed-capabilities`, `mutation.mcp.execute-sql`, `mutation.mcp.management-tool`, `acceptance.mcp.secret-absence` |
| `SURF-008` source/prompt/tool injection remains data and cannot create authority or tool calls | `acceptance.surface.prompt-tool-injection`, `mutation.mcp.model-controlled-schema`, `acceptance.surface.external-ref-disabled` |
| `SURF-009` rate, allocation, queue, retrieval, model and stream work are bounded | `acceptance.surface.resource-cap-plus-one`, `acceptance.surface.fair-concurrency`, `mutation.surface.unbounded-retry` |
| `SURF-010` every disclosure and state transition is attributable without content leakage | `contract.surface.audit-attribution`, `acceptance.surface.audit-secret-content-canary`, `mutation.surface.wire-body-logging` |
| `SURF-011` API/MCP schema compatibility cannot weaken security or fork semantics | `contract.surface.schema-equivalence`, `acceptance.surface.api-major-version`, `mutation.mcp.protocol-downgrade` |
| `SURF-012` protocol and dependency activation is impossible while the exact MCP gate is deferred | `architecture.mcp.deferred-dependency`, `architecture.mcp.no-endpoint-before-gate`, `mutation.mcp.unlocked-sdk` |
| `SURF-013` implementation is impossible before predecessor acceptances and an owner-approved roadmap/phase amendment | `architecture.surface.phase-charter-authority`, `architecture.surface.no-predecessor-artifacts`, `mutation.surface.p7-new-feature` |

## Explicit non-goals

- No mock, fake, stub, seed-only or in-memory implementation counts as delivery
  evidence or production fallback.
- No chat, thread memory, follow-up context, autonomous agent, model tool use,
  prompt library or user-defined tool.
- No cross-workspace/global search or implicit organization-admin data access.
- No MCP or public-API workspace/member/source/credential management, ingestion
  control, answer amendment, cancellation or external write action.
- No raw SQL, natural-language-to-SQL, database execution, raw source row,
  source credential or arbitrary URL/file fetch.
- No public/bearer result link, offline Evidence export or authorization cache
  that survives revocation.
- No direct MCP-to-OpenSearch/model/source path and no MCP server in a parser,
  connector or model runtime.
- No protocol version, transport, auth profile, SDK or dependency activation by
  accepting this design record.

## Alternatives considered

| Alternative | Why not selected |
| --- | --- |
| Implement separate UI, REST and MCP search stacks | Policy, retrieval ranking, idempotency, audit and citation semantics would drift and create bypasses. |
| Make MCP call the public HTTP API internally | Adds a network trust hop and duplicate wire authentication without proving a single application authority. |
| Expose a synchronous `ask` call that waits for the model | Disconnects lose recoverability, resource use is unbounded and partial streaming conflicts with immutable terminal results. |
| Give one integration service account organization-wide access | Hides the asking identity and defeats workspace isolation and least privilege. |
| Pass an upstream user ID in a trusted-looking header | It is impersonation without a cryptographically bound, revocable identity flow. |
| Expose generic search, SQL or source tools | Bypasses the immutable Question Run/Evidence path and expands prompt injection into execution authority. |
| Return signed or pre-authorized Evidence URLs | A saved capability cannot enforce current membership, ACL, retention and revocation. |
| Select an SDK/protocol in this surface ADR | Protocol, transport, authorization and supply-chain locks require their own exact official-spec decision and proof package. |

## Governance: design acceptance is not delivery activation

There are six distinct gates:

1. **Design acceptance.** Architecture and security owners may accept this ADR.
   That records the intended boundary only. Current Constitution and guardrail
   prohibitions remain effective and no implementation work is authorized.
2. **Predecessor and phase-charter authority.** All required P2, P3, P4, P5 and
   P6 phase-end protocols and external acceptance records must exist in their
   normative order. Separately, the architecture owner must approve an exact
   amendment to `docs/IMPLEMENTATION_PLAN.md` that assigns this new capability
   to an authorized feature phase and its acceptance charter. The current P7
   charter is release/pilot stabilization **without new functions, schemas,
   connectors or feature flags**, so this capability cannot be implemented in
   P7. This ADR does not invent a parallel phase or choose how the owner will
   amend the P0–P7 roadmap.
3. **Protected-baseline amendment.** A later owner-approved atomic change must
   amend the Constitution, remove only the exact `mcp`/`/mcp` prohibitions,
   establish the public API scope, update the actor-neutral AccessContext,
   OpenAPI/data model/trust/disclosure-fence boundaries, reserve `SURF-*`, and
   preserve all chat/agent/action/global-search/SQL guards.
4. **Protocol/dependency decision.** A separate exact owner decision must close
   every deferred item in §11. It is necessary but does not authorize code,
   imports or composition by itself.
5. **Implementation package.** Only after gates 1–4 may the application,
   adapters, migrations, version/license locks and tests land as one reviewable
   capability in the owner-authorized phase. Partial adapters, an unlocked SDK
   or a feature hidden behind a disabled flag are still implementation and are
   forbidden before that point.
6. **Delivery activation.** Runtime routing/readiness and any delivery-state
   advance occur only after all real-environment gates below pass and the
   delivery owner records activation. Merge, acceptance and activation are not
   aliases.

Until **both** all applicable predecessor acceptances through P6 and the
owner-approved `IMPLEMENTATION_PLAN.md`/phase-charter amendment exist, the tree
must contain no API/MCP implementation code, migration, dependency or import,
wire/schema contract, runtime route/listener, deployment manifest, SDK lock,
composition hook or feature flag for this capability. Architecture tests must
recognize each forbidden artifact class. Design acceptance, a protocol decision,
a dependency review, local tests or this ADR alone never authorize one of those
artifacts. Documentation of the proposed boundary is the only permitted result
before phase authority.

Accepted ADR history is not edited to claim the new capability. The later
baseline amendment explicitly composes or supersedes only the affected current
clauses and keeps the immutable/no-tools/no-actions properties intact.

## Concrete delivery gates

The later delivery package must satisfy all of the following. This accepted
design satisfies none of them:

1. Preflight exact-matches accepted predecessor records for every required phase
   P2 through P6 and the owner-approved `IMPLEMENTATION_PLAN.md` feature-phase
   amendment. Before both exist, an architecture absence gate rejects every
   implementation artifact class enumerated in Governance. Only then are
   protected documents, actor-neutral schema, OpenAPI, policy inventory,
   migrations, owner packages, architecture checker, `SURF-*` guardrails,
   version/license locks and runtime readiness updated atomically. Removing the
   `mcp` prohibition without the closed replacement inventory fails.
2. A code-ownership/dependency proof shows UI, API and MCP enter one typed
   Question Run service and one Evidence read service. Mutations introducing
   adapter-owned policy, OpenSearch/model/source access, direct SQL or copied
   citation resolution turn the architecture gate red. The closed
   `DisclosureFenceOwnerRegistry` is generated/checked against the one
   current-access gate and its mutation owners; tests deliberately remove a
   shared key or exclusive owner and must turn **RED**.
3. A real multi-workspace E2E installation uses the production PostgreSQL,
   OpenSearch, model gateway/runtimes, OIDC provider and live source connectors,
   with no mock/fake/stub/seed fallback. At minimum, workspace A and B contain
   distinct canary information and grants; an overlapping human, an A-only
   human, a B-only service principal and an ungranted principal prove exact
   results through UI, API and MCP. Documents, mail, Git and accepted
   PostgreSQL-query Evidence participate through the normal ingestion path.
4. The operational scenario asks a time-sensitive question such as “How much
   waste was removed today?”, obtains a terminal answer whose material number,
   date and unit pass deterministic validation, follows every citation to an
   exact current Evidence anchor, and obtains byte/manifest-equivalent structured
   results through all three adapters.
5. Actor-authority tests use real signed credentials from the selected provider
   and prove the protected actor-neutral `AccessContext`, immutable service
   principal/credential revisions, per-workspace/per-operation/time/revision
   grant relation, access snapshot, policy decision, Question Run/manifest,
   audit and idempotency actor epoch all exact-match. They cover human/service
   principal, wrong issuer/audience/resource/scope, expiry, rotation,
   deprovision, group/grant change, client revoke and token replay.
   Organization-admin-only and caller-supplied actor/on-behalf-of/client metadata
   grant no data. Every service principal is denied on `SOURCE_ENFORCED` until
   the separately accepted source-native service identity capability exists.
6. Isolation tests permute organization, workspace, run, citation and Evidence
   IDs across every endpoint/tool/resource. Missing and unauthorized cases have
   identical external class/body/cache behavior and no forbidden canary appears
   in timing buckets, lists, counts, status, logs or metrics.
7. Idempotency/concurrency/crash tests submit the same key through different
   adapters, change each hashed field, race many submissions, disconnect after
   durable accept and restart every runtime phase. Exactly one run exists for an
   exact replay; conflicts never enqueue; the terminal aggregate is immutable.
8. Content-free status-stream and general resource-bound tests exercise cap+1
   bytes/events/time/connections, slow readers, disconnect, overload, queue
   exhaustion and retry storms. No answer/citation/Evidence/source-derived count
   is emitted on status, memory remains bounded, fair scheduling holds and
   polling recovers the durable terminal result. Real socket/TLS barrier tests
   cover the UI, API and MCP-equivalent status surface: pause after event N and
   before event N+1, at each heartbeat and immediately before every write,
   commit a real credential/principal/grant/membership/policy/workspace/source
   revoke at each barrier, and prove that no post-commit event, heartbeat,
   terminal or close-detail byte is emitted. The same barriers exercise client
   reset, server cancel, write failure and deadline; each must stop subsequent
   writes, release the shared fence and then let revoke commit. A cadence-only
   or cached `ALLOW`, resource-specific close reason, timing/cache metadata or
   protocol distinction from missing/unauthorized must turn the suite red.
   Deterministic fake-clock tests coupled to real shared/exclusive fence
   barriers advance each registered expiry/validity boundary immediately before
   fence acquisition, between acquisition and first byte, and between stream
   events and heartbeat writes. They prove zero bytes for an already-expired
   emission and no write at/after a boundary; clock advance at every barrier
   must make the writer abort before a crossing rather than relying on the
   fence to freeze time.
9. Real socket/TLS E2E barriers and production-owner failpoints exercise every
   content-bearing result/citation/Evidence read through UI, API and the pinned
   MCP transport, using the exhaustive generated `DisclosureFenceOwnerRegistry`.
   For each organization/workspace policy revision, service-principal grant and
   grant revocation, access-authority epoch, workspace lifecycle, credential,
   principal, group/access snapshot, membership, binding, confirmation/ACL,
   source-connection trust/scope activation when used by the gate, signing-key,
   source object/version, extraction, Evidence and Question-retention
   revocation class they pause (a) after materialization but
   before shared-fence acquisition, commit revoke and prove exactly zero content
   bytes, and (b) after shared-fence acquisition/first byte but before last byte
   and prove the exclusive revoke commit remains blocked until the final trusted
   edge flush and fence release. Cancellation, deadline, write failure and client
   connection reset at that barrier must stop all subsequent writes, discard
   buffers, release the fence and then allow revoke to commit. Mutations removing
   the shared fence from any adapter, the post-fence exact revalidation, the
   last-byte hold, trusted-edge no-buffer rule, or the exclusive fence from each
   revocation owner must turn the suite red. Already-sent pre-revoke bytes are
   accounted as the read linearized before revoke; no post-release byte is
   accepted by the instrumented edge. Reopening a previously cached result/link
   after revoke repeats the fenced server read and discloses no cached content.
   The same real fake-clock/barrier harness advances every registered temporal
   boundary immediately before fence acquisition, between fence acquisition and
   the first byte, and between chunks including immediately before the last
   byte. It verifies a deadline plus safety margin strictly precedes the
   earliest boundary, zero content bytes when no sufficient interval exists,
   and abort/discard before any post-boundary write. Service-grant scenarios
   race an immediate revoke against a read, reject an attempted future-time or
   future-workspace-revision revoke, accept only an exact replay, reject a
   semantically different second revoke as already-revoked/conflict, and prove
   an urgent revoke is never blocked by a prior schedule because no schedule
   can be stored or executed. A real UI/API/MCP E2E sequence revokes one exact
   grant, repeatedly advances the authority epoch through unrelated
   credential/grant issue, rotation and revoke transactions, restarts every
   runtime, and proves that old grant remains denied on all three surfaces. A
   mutation that filters a grant revocation by the current epoch rather than its
   immutable `(organization_id, grant_id, grant_revision)` identity turns
   **RED**.
10. Injection corpus places tool instructions, fake MCP resource URIs, Markdown
    links, JSON/XML/HTML control text, SQL, prompt delimiters and oversize schemas
    in question and every live source family. None changes tool inventory,
    policy, retrieval scope, link targets or model tools; no external URI is
    dereferenced.
11. The selected official MCP conformance suite and at least two compatible real
    MCP clients pass the exact pinned protocol/auth/transport profile. All other
    versions, legacy downgrade, unselected methods/extensions, malformed
    header/body pairs, payload/content-type drift and unauthenticated discovery
    behavior fail as specified without an oracle.
12. Supply-chain evidence records exact SDK/module hashes, transitive SBOM,
    license/NOTICE, vulnerability review, reproducible/offline build, upgrade and
    rollback. A version range, pre-release substituted for the accepted lock,
    debug compatibility switch or untracked transitive package fails release.
13. Audit/content-leak canaries prove exact principal/workspace/run attribution
    for creation, terminal transition and disclosure while question, answer,
    Evidence, credentials, SQL, source values and wire bodies are absent from
    audit, logs, traces, metrics, errors, jobs and dead letters.
14. Load/soak/failure tests exercise organization/principal/workspace fairness,
    real model latency, OpenSearch/PostgreSQL interruption, restart, dependency
    timeout and audit degradation. Readiness fails closed when a required
    authority is unavailable; there is no mock answer or transport-specific
    fallback.

The architecture checker must anchor the single application authority, exact
actor-neutral credential/access-snapshot conversion, current policy/evidence
recheck, shared/exclusive last-byte fence on every read/revocation owner,
one-shot idempotency, terminal-only answer disclosure, content-free bounded
status stream, closed MCP inventory, model-no-tools boundary, non-oracle
repository predicates, content-free audit, strict API/schema versioning,
predecessor/phase-charter absence gate and deferred MCP protocol/dependency
gate. Each load-bearing anchor requires a mutation self-test that proves its
removal is detected.

## Consequences

The design gives browser users, enterprise integrations and MCP clients the same
workspace-isolated, evidence-backed product rather than three products with
similar names. Durable asynchronous runs favor correctness, recovery and
revocation over token-by-token immediacy. Exact service-principal grants require
more identity administration, but preserve attribution and tenant boundaries.
The intentionally small MCP inventory is less flexible than a generic agent
server; that limitation prevents source credentials, SQL and write authority
from entering an untrusted model/tool loop.

## Delivery status

The enterprise API/MCP surface is reserved by this accepted design only. No current
prohibition is removed; no public API, `/mcp` route, tool, resource, auth profile,
SDK, dependency, migration or runtime composition is authorized or claimed
delivered. Design acceptance may approve this boundary while the capability
remains inert. Until the required P2–P6 acceptances and owner-approved roadmap/
phase-charter amendment exist, even implementation artifacts and disabled
feature flags are forbidden; P7 cannot absorb this new feature. Only that phase
authority, the separate protected amendment, exact MCP decision, fully
implemented real-environment proof package and recorded activation decision may
make it available to users.
