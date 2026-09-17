# ADR-0078: Live external PostgreSQL named-query source

Status: accepted.

Acceptance scope: design authorization only; runtime capability remains inert.

Date: 2026-08-27.

Owners: product architect, source/ingestion owner, security owner.

Owner decision: accepted on 2026-08-27 under explicit product-owner authority.
This decision accepts the boundary below, not an implementation, delivery
coordinate advance, runtime activation or release verdict.

Related: ADR-0047 through ADR-0061, ADR-0074,
`docs/SOURCE_CONTRACTS.md`, `docs/DATA_MODEL.md` §§3–6 and
`architecture/guardrails.yaml`.

## Context

KnowVault needs a live, non-mock source for operational PostgreSQL data: an
administrator connects a customer database, registers several entity
projections, binds them to a workspace, and users ask questions over their
Evidence. The accepted source contract now recognizes `POSTGRESQL_QUERY` by
normative reference to this ADR. This ADR authorizes its design and reserves its
invariant IDs, but does not authorize production composition. A later delivery
package must amend the remaining protected data model, schemas, version/license
locks, product surface and implementation and satisfy every gate below
atomically; accepted ADRs remain unedited history.

This source must reuse the existing immutable connection/scope revisions,
workspace-managed confirmation, durable `SOURCE_SCOPE_SYNC` jobs, catalog,
immutable versions, Evidence, retention, retrieval authorization and Question
Run boundaries. It must not introduce a second catalog or a shortcut from an
external row to a model prompt.

## Decision

### 1. Source and authority shape

The accepted source type is `POSTGRESQL_QUERY`. One connection names one exact
external PostgreSQL database and one dedicated login identity. One immutable
scope revision contains an ordered, bounded set of named projection revisions.
Changing the endpoint trust tuple, credential reference, projection set,
projection contract, fields, identity, limits, schedule or empty-snapshot policy
creates a new immutable revision and uses the ADR-0061 full-scan cutover; a
mutable label or `latest_revision` never grants authority.

The connection trust tuple includes an immutable, DBA-attested database identity:
`cluster_system_identifier`, `database_oid`, `database_name` and a customer-
assigned `database_identity` UUID. The DBA obtains the system identifier through
a narrowly installed attestation helper, signs canonical
`postgresql-database-attestation-v1` bytes, and the encrypted trust profile stores
those bytes, signer/key reference and signature. Their digest enters the
connection-revision hash, trust-profile hash and every dependent projection/scope
hash. On every physical connection, before any projection catalog lookup or
application SELECT, the connector calls only that fingerprint-pinned attestation
helper and exact-matches all four values and the signature. A valid certificate
and DNS name that lead to a different cluster, database OID/name or database UUID
therefore fail pre-scan; restore, clone, failover or database replacement requires
an explicit new connection revision and revalidation, never silent continuity.

The same attestation carries a customer-DBA-managed monotonic `security_epoch`.
Its exact value and attestation digest are bound into the connection revision and
trust hash. Every reviewed change to role membership, ownership, database/schema/
relation/column/routine ACL or PUBLIC grant, RLS enable/force/policy, routine
definition/volatility/security mode/configuration, or a projection dependency
must advance the epoch in the same external PostgreSQL transaction as that
change. Reuse, decrement or wrap is forbidden. This epoch is the non-lockable
security-catalog fence; relation locks alone cannot fence GRANT, role, routine or
RLS catalog changes.

V1 supports `WORKSPACE_MANAGED` only. The external login represents the
connector, not the asking user, and PostgreSQL row-level permissions evaluated
for that shared identity cannot be treated as a user ACL. `SOURCE_ENFORCED`, an
ACL snapshot synthesized from database roles, and fallback from one access mode
to the other are refused.

### 2. Named parameterless SELECT projections; no arbitrary SQL

A named projection is a structured contract over one administrator-created
PostgreSQL view or materialized view. A server-generated stable
`projection_lineage_id` belongs to the projection parent and never changes across
its revisions only while the complete content contract is byte-identical. That
contract is the ordered IDENTITY and EVIDENCE column inventory, names, ordinals,
PostgreSQL/type fingerprints, roles, nullable rules and every
`postgresql-query-value-v1`/normalization/fragmentation semantic; TITLE and
VERSION_HINT fields are covered as well because they affect provenance. Changing,
adding, removing, retyping, reordering or re-roleing any content-contract field
creates a new stable lineage ID, never another revision. Same-lineage revisions
may change only operational limits, schedule and empty-snapshot policy and may
not widen the returned or Evidence field set. Each revision binds its revision
and contract hash to the
pinned database identity, database/schema/relation identity, a verified recursive
semantic/security fingerprint, and an ordered closed column inventory. Each column
has an exact source name, PostgreSQL type identity, logical canonical type,
ordinal and one or more closed roles: `IDENTITY`, `TITLE`, `VERSION_HINT`, or
`EVIDENCE`. At least one non-null `IDENTITY` column and one `EVIDENCE` column are
required. Unknown, duplicate, dropped or type-drifted columns fail closed.

The connector constructs the only application-data statement from that trusted
structure:

```text
SELECT <quoted declared columns>
FROM <quoted discovered schema>.<quoted discovered view>
ORDER BY <quoted identity columns>
```

It has no raw SQL input. Identifiers are selected from exact discovered catalog
objects and quoted as identifiers; they are never interpolated from a question,
model output or ordinary workspace request. There are no parameters, predicates,
expressions, joins, CTEs, subqueries, comments, multiple statements or runtime
query templates at this boundary. Complex relational logic belongs in the
source-owned view and is reviewed by the customer's database administrator.
The connector may issue fixed transaction-control, timeout, attestation and
catalog-verification statements owned by its implementation, but no caller can
alter them. Every catalog name is explicitly `pg_catalog`-qualified and every
name lookup uses OIDs obtained from the trusted discovery tuple; no unqualified
object lookup or caller-controlled `search_path` is permitted.

Registration and every sync use the same lock-and-fingerprint algorithm inside
the same external transaction that performs the SELECT. Before relation discovery
or locking, a fresh trusted attestation call exact-matches the pinned database
identity and `security_epoch`, and the effective-privilege digest exact-matches
the connection revision. It then enumerates the
candidate recursive dependency graph with fixed safe `pg_catalog` queries, locks
every lockable relation in ascending `(database_oid, relation_oid)` order with
`ACCESS SHARE`, re-enumerates and exact-matches the graph, then computes the
fingerprint while those locks remain held. Only after the fingerprint exact-
matches the immutable projection revision does it execute the generated SELECT;
all locks remain held until every projection reaches EOF and the external
transaction ends. Concurrent DDL therefore blocks or produces typed drift; it
cannot swap semantics between validation and read.

The recursive fingerprint covers relation/database/schema OIDs and names,
relation kind and persistence, owner and owner-role closure, view definition,
`security_invoker`/`security_barrier`, columns/ordinals/types/typmods/domains/
enums/collations, generated/default expressions, every recursively referenced
relation and routine, routine identity/language/volatility/security-definer flag/
configuration/ACL, RLS enable/force state and every policy command/role/
permissiveness/USING/WITH CHECK expression, relation/schema/database ACLs,
PUBLIC grants and the complete inherited/predefined-role graph. V1 refuses base
tables and foreign/temp/system relations as the registered root, unregistered
dependencies and **all user-defined routine dependencies**, regardless of
declared volatility or security mode; allowing an apparently IMMUTABLE/STABLE
customer routine would make its external side effects and mutable body part of an
unfenceable query. Built-in routine dependencies are allowlisted by exact server
version and volatility, and every `VOLATILE` dependency is refused. Drift at sync
time is a typed failure requiring a new
projection revision; it is never silently accepted under an old contract hash.
No model, Question Run, browser/API user or connector event can create, edit or
submit SQL, and an `/execute-sql` surface remains forbidden by the architecture
guard.

### 3. Read-only external database and transport boundary

The external identity is dedicated to KnowVault ingestion and has only
`CONNECT` on the exact database, `USAGE` on the required schemas, and `SELECT`
on the exact registered views. It is not a superuser, owner, replication role or
member of a write-capable role and has no `CREATE`, `TEMP`, table DML, sequence,
large-object or role-management grant. Its only user-defined routine EXECUTE is
the exact fingerprint-pinned, non-mutating database-attestation helper; it has no
generic routine execution and projection views may not depend on that helper.
The customer-side
installation check proves these grants and proves an attempted INSERT, UPDATE,
DELETE, DDL, COPY, CALL and advisory-lock mutation is denied. The role and
database also set `default_transaction_read_only=on`; every scan additionally
opens `SERIALIZABLE READ ONLY DEFERRABLE` and verifies the server reports a
read-only transaction. These layers are complementary, not substitutes.

Registration produces a canonical `postgresql-effective-privileges-v1`
attestation and every physical connection and sync recomputes it before source
access. It expands direct, nested and inherited membership, PUBLIC and predefined
roles; accounts for ownership-implied rights; enumerates effective database,
schema, relation, column, sequence, routine and large-object privileges; and
binds the exact attestation-helper EXECUTE, role/session identity and security-
relevant GUCs. The digest is part of the connection revision and trust hash.
Unexpected membership, ownership, PUBLIC privilege, routine EXECUTE, predefined
role, `BYPASSRLS`, replication, SET ROLE/SESSION AUTHORIZATION capability or GUC
drift fails before projection fingerprinting. Fixed harmless probes also prove
that SELECT on registered unprivileged canary relations, write to a canary,
temporary-object creation and role switching remain denied; a catalog claim of
least privilege without those runtime negative probes is insufficient.

TLS is fixed to PostgreSQL `verify-full`. The exact DNS server name, port,
database, approved network zone, trust-bundle reference and optional client-
certificate reference are admin-managed connection trust data. Hostname and CA
verification, SNI, connect timeout and per-address network policy are mandatory;
`sslmode=disable`, `allow`, `prefer`, `require`, `verify-ca`, certificate-ignore,
arbitrary service files, environment connection strings, Unix sockets and
redirected endpoints are rejected. A private CA is a mounted purpose-scoped
trust reference. DNS results are checked against the configured deployment
network policy on every connection.

Before the lock/fingerprint/read sequence the connector establishes and verifies
a closed session profile: exact login and session authorization, no adopted role,
`search_path=pg_catalog`, `row_security=on`, read-only transaction, bounded
`statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` and
`transaction_timeout`, bounded `work_mem` and `temp_file_limit`,
`max_parallel_workers_per_gather=0`, and `jit=off`. DBA-only limits are pinned as
role/database settings and verified with `SHOW`; caller- or DSN-supplied GUCs are
forbidden. Failure to set or verify one value is a trust failure, not a warning.

Password, client private key and any token live only behind the opaque
`credential_reference`/secret-provider capability. Secret bytes, DSNs, raw
query/view definitions and source row values are forbidden in scope plaintext,
job/outbox payloads, API responses, logs, metrics, audit, dead-letter rows and
raw model inputs. After current workspace authorization, only normalized
published Evidence fragments selected by the retrieval contract may enter a
model context; raw/full result rows, identity/title fields and unselected cells
never may. The connector receives a purpose-typed connection capability and
cannot export it.

### 4. One bounded authoritative full snapshot

V1 has no cursor, CDC, logical replication or incremental mode. A scope sync
opens one bounded external read-only transaction and scans every configured
projection to EOF inside that same PostgreSQL snapshot. The immutable scope
sets maximum projections, columns, rows per projection, rows per scope, bytes
per field, bytes per row, total decoded bytes, statement time, transaction time
and retry count. The reader counts cap+1 and byte-cap+1; exceeding any cap,
timeout, cancellation, connection loss, decode failure or failure to reach EOF
makes the whole run incomplete. Partial rows may be staged but no publication,
cutover or absence reconciliation may use them.

Bounds apply before allocation as well as after decode. The external PostgreSQL
driver/wire owner must stream rows (`Rows.Next` semantics; no whole-result
collection), cap protocol message/frame length, column count and each DataRow
field length before allocating from attacker-controlled length words, use a
bounded reusable buffer, and keep a process-level per-run memory budget. A server
frame or field claiming cap+1 bytes closes the connection and fails the run
without allocating that size. The verified server GUC profile bounds sort/hash
memory, temporary spill, locks, idle/total transaction time and statement time,
and disables parallel query and JIT. Integration includes a hostile PostgreSQL
wire peer and expensive-view cases; application row/byte caps alone are not
accepted as resource containment.

Only a successful run whose every projection passed catalog-fingerprint checks,
identity checks, bounds and EOF is `coverage_complete=true`. The run records a
content-free ordered projection/count digest and a canonical snapshot-set hash.
These hashes are provenance, not authority supplied by the worker: the final
database gate recomputes them from the staged rows under the exact job and scope
fences.

EOF is not sufficient security proof. After the locked snapshot transaction
ends and before local publication, the connector opens a fresh trusted external
check, re-attests cluster/database identity and `security_epoch`, recomputes the
complete effective-privilege digest, deterministically locks/re-fingerprints the
semantic/security dependency graph, and exact-matches all results to both the
connection/projection revisions and the pre-scan values. A changed epoch,
privilege graph or fingerprint makes the run incomplete and publishes, reconciles
and deletes nothing. The canonical pre/post proof and hashes are run-owned staging
inputs independently rechecked by the local publication gate.

An ACL/role/routine/RLS change followed by reversal (ABA) is detectable through
the mandatory monotonic epoch even if the final catalog fingerprint equals the
initial one. Performing such a change without atomically advancing the epoch is
an explicit customer deployment trust violation: runtime cannot infer an
identical historical catalog state from a snapshot. When noncompliance is
detected by an epoch/fingerprint/privilege mismatch, attestation probe or
operational audit, the run and every staged successor under that trust revision
are held non-queryable, publish/delete nothing, and the connection requires a new
DBA attestation and trust revision. The delivery readiness check must document
and mutation-test this DBA change procedure; prose-only operator intent is not a
runtime substitute.

### 5. Stable entity identity and immutable version detection

Each result row is one logical SourceObject. Its equality key is exactly
`HMAC-SHA-256(SourceDigestKey[organization,key_version], JCS(identity_tuple))`,
where `identity_tuple` contains the connection ID, pinned
`cluster_system_identifier + database_oid + database_identity`, stable
`projection_lineage_id`, and the tagged canonical values of every declared
`IDENTITY` column in declared order. The tuple deliberately excludes projection
revision, projection contract hash, scope revision and mutable view fingerprint:
those belong to membership and version provenance, so a compatible projection
revision reuses the same SourceObject. Changing the identity-column contract
requires a new projection lineage. Identity values must be non-null, supported
bounded scalars and unique within the complete projection. Raw values are stored
only in owner-bound encrypted artifacts. A null, duplicate, unsupported or non-
canonical identity fails the whole projection, rather than merging rows or
inventing an ordinal identity. Changing an identity value is semantically delete-
plus-create; customers must choose source-stable keys.

This restriction closes cross-scope revision widening. Two workspaces/scopes may
share one SourceObject/current SourceVersion through different projection
revisions only when those revisions have the byte-identical content contract, so
the shared current Evidence has identical meaning and field visibility for both.
A revision that adds an EVIDENCE column, changes a type/role/canonicalizer or
otherwise changes content receives another `projection_lineage_id`; its keyed
identity therefore resolves to distinct SourceObjects/versions/Evidence and
cannot make wider revision content visible through a narrower revision's active
membership. A projection revision number or contract hash remains provenance,
not an excuse to merge incompatible content.

The row version is always the SHA-256 hash of the complete canonical typed row
projection under `postgresql-query-value-v1`, including identity and all
Evidence values. A declared
`VERSION_HINT` such as `updated_at` is retained as provenance and may optimize a
later version, but is never sufficient to prove equality. Reordering rows does
not change identity, version or the snapshot-set hash. An identical row reuses
the existing immutable SourceVersion; any canonical value or type change creates
one new SourceVersion and Evidence set.

`postgresql-query-value-v1` is a protected, versioned canonical contract, not
driver stringification. A row is a JCS array in declared column order; every
entry contains column ordinal, exact PostgreSQL type fingerprint, logical type
tag and canonical value. NULL is a distinct tag. Booleans and signed int2/int4/
int8 use their unique lowercase/decimal forms (no leading zero or negative zero).
`numeric(p,s)` is accepted only with bounded explicit precision and scale and is
encoded with exactly `s` fractional digits; unconstrained numeric, NaN and
infinity are refused. UUID is lowercase canonical form. `date`, `timestamp(p)`
and `timestamptz(p)` preserve the declared bounded precision; timestamp without
zone is explicitly tagged local, timestamptz is UTC, and PostgreSQL `infinity`/
`-infinity`, ambiguous offset input and lossy rounding are refused.

Text is valid UTF-8, NFC and `text-v1` newline normalized, with length measured
after normalization. JSON and JSONB retain distinct type tags, reject duplicate
keys/non-finite or non-JCS-safe numbers, and encode parsed content as RFC 8785
JCS; driver-returned JSON text is never hashed verbatim. A registered domain tag
includes its schema/name/OID, base-type fingerprint, NOT NULL and ordered check-
expression hashes before the canonical base value. A registered enum tag includes
its schema/name/OID and fingerprint of the complete ordered label inventory; the
value is the exact NFC label. Text/domain/enum column fingerprints include
collation OID, provider, locale, version and deterministic flag; nondeterministic,
missing-version or drifted collation is refused, and collation ordering never
defines equality. Float types, `money`, intervals, arrays, composites, ranges,
multiranges, `bytea`, large objects and unregistered extension types are refused
in v1. Golden vectors pin all accepted values, edge precisions/scales, timestamp
zones/infinities, JSON-vs-JSONB, domain constraints, enum labels and collation
drift across the exact driver/server version lock.

Deletion is set reconciliation, never inference from a failed read. After one
authoritative full snapshot, an identity absent from that projection moves only
the exact scope-revision membership to `REMOVED`; the existing zero-active-
membership rule is the only route to `SOURCE_OBJECT_DELETED`. An empty result is
held by default as `PG_QUERY_EMPTY_SNAPSHOT_HELD`. It is authoritative only when
the immutable projection contract explicitly sets
`empty_snapshot_policy=AUTHORITATIVE`; that high-risk choice enters the scope
hash and the workspace-managed warning/confirmation reviewed for this source.
No partial, capped, timed-out, drifted, stale-lease or uncorroborated held-empty
run can remove membership or close an object.

### 6. Exact Evidence anchors and deep links

Every published result row must yield at least one non-empty normalized Evidence
fragment. NULL/empty cells yield no fragment; a row whose complete `EVIDENCE`
set yields none makes the projection incomplete with
`PG_QUERY_ROW_WITHOUT_EVIDENCE`; the run publishes and reconciles nothing. It
therefore cannot expose an empty SourceVersion or delete a previously observed
entity merely because its current evidence is empty. Every other `EVIDENCE` cell is
canonicalized into one or more immutable normalized Evidence fragments. The
accepted delivery contract reserves the anchor kind
`POSTGRESQL_QUERY_CELL` and contains the exact connection ID, projection ID and
revision, projection contract hash, keyed entity-identity digest, row-version
content hash, column ordinal and name, canonical value hash, UTF-8 byte range
and canonicalization version. A resolver exact-matches that tuple to the
immutable SourceVersion/Extraction/Evidence chain and slices the stored
normalized value; it never re-runs the live query and never falls back to a row,
view or file-level citation when a cell/range cannot be proven. Anchor and safe
metadata remain encrypted artifacts, and raw primary-key values are not placed
in an answer URL.

The v1 deep link is the existing KnowVault Evidence viewer link for the exact
fragment. Opening it repeats current workspace membership, enabled current
binding, active exact scope membership, version/extraction retention and live
workspace-managed confirmation checks, returning the same not-found shape for
missing and unauthorized evidence. PostgreSQL has no portable source-native row
URL, so source-native database deeplinks are explicitly not claimed. A citation
still exposes projection/version provenance and the exact cell anchor through
the authorized viewer.

Only those encrypted normalized fragments may flow through post-authorization
retrieval into Question Run context. The raw row, its complete canonical row
bytes, non-Evidence fields, identity values and staging representation are not a
model artifact and are never supplied to embedding, reranking, generation or
verification. This distinction makes the earlier no-raw-row rule compatible
with evidence-backed answers: authorized Evidence is allowed; raw query output
is not.

### 7. Crash, retry, idempotency and fencing

The current generic `job.payload_json` is a mutable producer-owned schema surface
and is not signed source authority, even though an individual committed job row
is immutable. It is therefore insufficient for this connector. Before
composition, a protected `postgresql-query-sync-job-v1` contract must add a
server-signed canonical bounded envelope containing the exact organization,
connection ID/revision/trust hash/pinned database-identity digest/effective-
privilege digest/`security_epoch`, scope ID/revision/config hash/access mode,
ordered complete
projection lineage ID/revision/contract-hash set, all limits, job ID, lease
binding, issued/expiry times and replay nonce. It contains no SQL, DSN,
credential or row content. The worker verifies schema, signature, expiry and
exact database projection before opening a network connection; the local
database gates exact-match the same tuple before staging and publication. A job
for projection or scope revision N can never resolve mutable `latest_revision`
or execute/publish N+1, even if N+1 becomes current while N is queued.

A claim's `lease_epoch` fences every staged write, heartbeat, publication and
completion through the ADR-0056 job CAS and the ADR-0061 scope-revision fence.
The worker periodically heartbeats while reading the remote snapshot; lease loss
cancels the remote transaction. A slow or partitioned worker with a stale epoch
may neither stage more data nor publish, reconcile deletion, move an active
extraction or mark the scope READY.

The existing folder ingestion pipeline commits and publishes per object; that
execution shape is explicitly incompatible with an authoritative relational
snapshot and must not be reused or lightly parameterized. Implementation first
introduces one atomic semantic owner, `internal/source/postgresqlquery`, and new
run-owned staging relations/functions. Only that package may hold the external
PostgreSQL driver, canonicalize rows, write its staging relations or invoke its
publish function; `internal/ingestion` may call only its closed job handler.
Architecture import/call gates and database privileges make this owner a
prerequisite, not a naming convention.

Staged row descriptors, encrypted Evidence artifacts and their content-derived
catalog intents are keyed by exact organization, sync run, job, lease epoch,
scope revision and projection revision and remain non-queryable. Raw/full rows
are not a staging table or artifact. One local PostgreSQL publication and
reconciliation transaction verifies the live lease, signed job tuple, current
`SYNCING` activation, pinned database and privilege digests, complete projection
inventory, exact pre/post `security_epoch` and semantic/security/privilege proof,
bounds, recomputed snapshot hashes and every non-empty staged Evidence
set. That one transaction inserts/reuses the generic catalog rows, activates all
new memberships/versions/extractions, performs absence reconciliation, advances
the scope revision, appends every required audit event and terminalizes the run.
No generic catalog current pointer, membership removal or Evidence read becomes
visible earlier.
A crash before commit leaves the prior published snapshot authoritative; a
crash after commit leaves the new snapshot complete. Retry uses the durable job
idempotency key plus content-derived entity/version identity and converges
without duplicate current versions or Evidence. Inert abandoned staging is
retention-cleaned only after its lease/run can no longer publish.

### 8. Authorization, audit and observable failures

The normal workspace source-add and exact live `WORKSPACE_MANAGED` confirmation
are necessary before activation, ingestion publication, retrieval or Evidence
view. Organization administration, source registration, possession of a
projection ID, or access to the external database grants no source content.
Question retrieval uses the same current authorization snapshot and citation
recheck as every other source; SQL data never bypasses post-authorization into
OpenSearch or a model.

Registration, projection revision, trust verification, activation request,
sync start/completion/failure, cutover, membership removal and object deletion
append audit in their owning local transactions. Audit metadata is closed to
tenant-safe internal IDs, revisions, hashes, counts, durations and typed error
codes. Host, database/schema/view/column names, view definition, DSN, SQL, keys,
row values, titles, Evidence and excerpts are forbidden.

The runtime error namespace is closed at least to TLS/trust mismatch, secret
unavailable, external privilege mismatch, projection drift, unsupported type,
null/duplicate identity, row/byte/column limit, statement/transaction timeout,
incomplete snapshot, held empty snapshot, stale lease, publication conflict and
audit unavailable. External PostgreSQL details are mapped to these content-free
codes; driver/server messages never cross the connector boundary.

### 9. Accepted invariant and proof inventory

These IDs are reserved by this accepted design and become executable
guardrail/test identifiers only in the later atomic delivery package; their
presence here is not a delivery claim.

| Accepted invariant | Required primary and negative/mutation proof IDs |
| --- | --- |
| `PGQ-001` exact cluster/database identity precedes source access | `contract.source.pgquery-database-identity`, `acceptance.source.pgquery-database-substitution` |
| `PGQ-002` verify-full and network policy cannot downgrade | `acceptance.source.pgquery-tls-verify-full`, `architecture.connector.pgquery-tls-downgrade` |
| `PGQ-003` effective privilege graph is exact and read-only | `acceptance.source.pgquery-privilege-graph`, `acceptance.source.pgquery-unregistered-canary`, `architecture.connector.pgquery-write-capability` |
| `PGQ-004` relation locks plus pre/post monotonic security epoch and recursive fingerprint prevent semantic/security TOCTOU and ABA | `acceptance.source.pgquery-fingerprint-lock`, `acceptance.source.pgquery-security-epoch`, `acceptance.source.pgquery-security-aba`, `contract.source.pgquery-semantic-drift` |
| `PGQ-005` only the generated parameterless projection SELECT executes | `contract.source.pgquery-no-arbitrary-sql`, `architecture.connector.pgquery-query-origin` |
| `PGQ-006` wire, memory and server work are bounded before allocation | `acceptance.source.pgquery-wire-frame-cap`, `acceptance.source.pgquery-resource-bounds`, `architecture.connector.pgquery-streaming-read` |
| `PGQ-007` identity is stable only across byte-identical content-contract revisions and versions are exact | `contract.source.pgquery-identity-lineage`, `contract.source.pgquery-content-lineage`, `contract.source.pgquery-value-v1`, `acceptance.source.pgquery-cross-scope-lineage`, `acceptance.source.pgquery-version-reconciliation` |
| `PGQ-008` only a complete authoritative snapshot can publish/delete | `acceptance.source.pgquery-completeness-delete`, `contract.source.pgquery-empty-policy` |
| `PGQ-009` signed job N exact-matches and cannot execute N+1 | `contract.job.pgquery-signed-tuple`, `acceptance.source.pgquery-job-revision-fence` |
| `PGQ-010` run-owned staging publishes/reconciles/audits atomically | `acceptance.source.pgquery-atomic-publication`, `architecture.source.pgquery-owner`, `acceptance.source.pgquery-crash-fence` |
| `PGQ-011` every published row has exact non-empty Evidence and anchor | `contract.anchor.pgquery-cell`, `acceptance.source.pgquery-evidence-nonempty`, `acceptance.source.pgquery-anchor-tamper` |
| `PGQ-012` raw rows/secrets never bypass post-authorization | `acceptance.storage.pgquery-raw-row-absence`, `acceptance.model.pgquery-post-authorized-evidence-only` |

## Explicit non-goals

- No mock, seed-only or in-memory connector is accepted as delivery evidence.
- No ad hoc SQL editor, natural-language-to-SQL, model-generated SQL, user
  parameter, stored-procedure call, write-back, action or `/execute-sql` API.
- No base-table discovery, arbitrary query text, dynamic filters, joins owned by
  KnowVault, CDC, WAL/logical replication, LISTEN/NOTIFY or incremental cursor in
  v1.
- No `SOURCE_ENFORCED` database-role mapping and no impersonation of the asking
  user at the external database.
- No source-native row deeplink, cross-database transaction, or guarantee that
  mutable customer keys preserve identity.
- No change to the existing Question Run claim/verification contract and no
  direct row-to-model path.

## Alternatives considered

| Alternative | Why not selected |
| --- | --- |
| Accept arbitrary saved SELECT text | Requires a complete SQL parser/policy, retains injection and function/side-effect ambiguity, and creates an attractive NL-to-SQL bypass. |
| Let the model generate SQL | Violates the no-tools/no-source-credentials model boundary and makes authorization, bounds and reproducibility dependent on untrusted output. |
| Mirror each source table directly | Exposes more data than a reviewed projection, couples the product to source schemas and cannot express a least-privilege business view. |
| CDC/logical replication first | Requires elevated external privileges, cursor/deletion semantics and a new durable protocol; bounded full snapshot is the smaller verifiable v1. |
| Treat PostgreSQL roles/RLS as SOURCE_ENFORCED | The connector uses one service identity and cannot prove the asking user's exact current source ACL. |

## Governance and capability delivery

Governance has three separate decisions. First, the designated architecture and
security owners may accept this ADR as design authorization; that changes its
status and reserves the contracts/invariants, but the capability remains inert
and no production code may be composed on that fact alone. Second, a later atomic
delivery package updates the protected baseline, migrations, owner package,
product surface, version/license locks and every proof below in one reviewed
change; a partial package is rejected and does not inherit authority from the
accepted design. Third, runtime activation and any `DELIVERY_STATE.md` advance
occur only after that package's real-environment evidence passes and the delivery
owner records the activation decision. Design acceptance, implementation merge
and runtime delivery are not aliases for one another.

## Concrete capability delivery gates

The later atomic delivery package must satisfy all of the following. This
accepted design satisfies none of them:

1. Protected contract/model/schema/guardrail updates add
   `POSTGRESQL_QUERY`, `postgresql-query-value-v1`, the signed job and strict
   connection/scope/projection schemas, anchor kind, staging/owner-bound artifact
   branches, closed error/action inventory, accepted `PGQ-*` gates and product
   registration/status surface. `internal/source/postgresqlquery` and its
   database privileges are installed atomically; a mutation routing the driver
   or staging/publish function through another package fails.
2. A real second PostgreSQL 18.x cluster (not KnowVault's primary, mock, fake or
   in-memory adapter) proves register -> DBA database/security-epoch attestation
   -> projection verify -> bind -> confirm -> signed enqueue -> full scan ->
   fresh post-EOF security proof -> atomic publish -> Evidence -> authorized
   viewer -> Question citation. The exact driver/server/helper versions,
   checksums, licenses and offline artifacts are pinned.
3. Database-identity tests route the same DNS name and valid certificate to a
   different cluster/database and vary system identifier, database OID/name and
   database UUID independently; every mutation fails before projection catalog
   lookup or SELECT. Restoring/cloning under an old trust hash is refused.
4. Registration, reconnect and every-sync privilege tests recompute the same
   attestation digest and cover PUBLIC, nested/inherited/predefined roles,
   ownership, BYPASSRLS/replication, database/schema/relation/column/sequence/
   large-object/routine privileges, exact helper EXECUTE, GUCs and unregistered
   read/write/temp/role canaries. Pre-lock and fresh post-EOF checks exact-match
   `security_epoch`, privilege digest and connection revision. Adding any hidden
   grant or weakening read-only changes the proof and refuses publication.
5. TLS tests refuse wrong CA, hostname mismatch, expired certificate, plaintext
   and every sslmode weaker than `verify-full`; credential/DSN canaries are
   absent from DB rows outside approved encrypted artifacts, jobs, outbox,
   audit, logs, metrics, errors, backups and model-run artifacts.
6. A real concurrent-DDL test proves preliminary graph discovery, deterministic
   recursive relation locking, re-enumeration, complete semantic/security
   fingerprinting and application SELECT happen in one external transaction
   while locks are held. Mutations of dependencies, owner/security-invoker,
   RLS/policies, ACL/PUBLIC/role graph, columns/types/collation or view definition
   block or fail as drift, never race through. GRANT/REVOKE, role/ownership, RLS
   and routine mutations must transactionally advance `security_epoch`; concurrent
   compliant change and reversal/ABA, decrement/reuse and post-EOF mismatch cases
   publish/delete nothing. A mutation removing the epoch advance from the reviewed
   DBA change procedure fails deployment readiness; a bypassed noncompliant ABA
   is recorded as the explicit deployment-trust limit in §4, and when surfaced by
   attestation/audit it holds all affected runs non-queryable. Every user-defined
   projection routine dependency is refused regardless of declared volatility.
7. Query-boundary mutations that introduce raw SQL, a second statement,
   predicate/parameter, non-view root, unsafe catalog/search_path/row_security,
   unregistered or volatile dependency, model/user query input or identifier
   interpolation fail before application execution.
8. Hostile-wire and expensive-view tests prove message/frame and DataRow lengths
   are rejected before allocation, rows stream under a process memory budget,
   and client caps plus verified `work_mem`, `temp_file_limit`, time/lock/idle
   limits, no parallelism and no JIT bound work. Row/column/field/total cap+1,
   timeout, cancellation, connection loss and partial EOF publish/delete nothing.
9. `postgresql-query-value-v1` golden/mutation vectors prove every accepted type
   and rejection: numeric precision/scale, timestamp precision/timezone/infinity,
   JSON versus JSONB and duplicates/range, domain constraint/type drift, enum
   order/label drift, collation provider/version/determinism and unsupported
   types. Driver stringification cannot substitute for canonical bytes.
10. Identity/version/reconciliation tests prove the exact organization-keyed
    connection+pinned-database+stable-lineage+typed-values identity, revision/hash
    exclusion, stable reuse across compatible revisions, row-order independence,
    exact replay, one new version per canonical change, authoritative absence,
    held/authorized empty behavior and overlapping-scope survival. A two-scope
    rev1/rev2 case proves byte-identical content contracts share the same current
    SourceObject/version semantics; adding/retyping/re-roleing an EVIDENCE field
    requires a new lineage and produces distinct objects/Evidence, with no wider
    fragment reachable through the rev1 workspace.
11. Signed-job tests mutate every tuple/hash/limit/expiry/signature field and
    prove queued N cannot resolve or execute N+1. Crash/concurrency injection at
    every staging/publication boundary proves new run-owned staging stays inert,
    one local transaction publishes/reconciles/audits, retry converges, and a
    stale epoch cannot publish, delete, reactivate or complete. A mutation that
    restores existing per-object publication fails `PGQ-010`.
12. Evidence tests prove every published row has at least one non-empty fragment;
    an empty-Evidence row makes the run incomplete. Anchor mutations alter every
    tuple member, cell hash and byte range and obtain identical not-found. A
    multi-source answer resolves the exact immutable cell, while raw/full row,
    identity/title and unselected-cell canaries never reach model artifacts;
    authorized selected Evidence does. Deeplink authority revokes immediately.
13. Audit tests prove exactly-once content-free state-change events inside the
    atomic publication transaction and typed failures; planted host/schema/view/
    column/SQL/raw-row/secret canaries appear in none of audit, diagnostics,
    jobs/outbox, dead-letter or unauthorized model storage.

The architecture checker must anchor the atomic owner package, pinned database
identity, monotonic security epoch, pre/post privilege attestation,
same-transaction dependency locks/fingerprint,
no-arbitrary-SQL rule, dedicated read-only identity, `verify-full`, wire/server
bounds, typed canonicalization, signed exact job, snapshot completeness, stable
identity, delete gate, workspace-managed-only policy, non-empty exact anchor
resolver, raw-row/model boundary and run-owned lease-fenced atomic publication.
Each anchor requires a mutation self-test that reddens when its load-bearing
clause or production call is removed.

## Consequences

The selected design gives customers many live relational entity projections
while keeping query authorship and least privilege in their database control
plane. It deliberately trades interactive SQL flexibility and incremental
freshness for a bounded, replayable snapshot whose objects, versions and
citations fit the existing evidence model. Large databases must expose smaller
reviewed views/scopes or wait for a separately accepted incremental protocol.

## Delivery status

`POSTGRESQL_QUERY` is reserved by this accepted design only. No migration, connector,
secret, endpoint, job handler, Evidence kind or runtime composition is authorized
or claimed delivered, and `DELIVERY_STATE.md` is unchanged. Owner acceptance may
authorize the design while leaving this capability inert. Only the later atomic
delivery package may implement it, and only a subsequent recorded activation
decision after all capability gates pass may compose runtime or change the
delivery coordinate.
