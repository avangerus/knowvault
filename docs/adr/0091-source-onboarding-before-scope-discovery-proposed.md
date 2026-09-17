# ADR-0091 — Source connection onboarding before PostgreSQL scope discovery

**Status:** proposed

**Date:** 2026-09-09

**Owners:** product architect, source-management owner, security owner,
PostgreSQL connector owner, worker owner

**Approval:** owner approval recorded for connection-only bootstrap, metadata
discovery before scope confirmation, and a new encrypted `SourceDiscoveryResult`
owner. This document remains `proposed` until the complete runtime capability
passes its delivery gates.

**Related:** `PRODUCT_CONSTITUTION.md`; ADR-0047, ADR-0048, ADR-0056,
ADR-0059, ADR-0078 and ADR-0087; `docs/DATA_MODEL.md`;
`docs/SOURCE_CONTRACTS.md`; `docs/ENCRYPTION.md`;
`controller/projects/knowvault-SOURCE-ONBOARDING-DECISION.md`.

## Context

PostgreSQL onboarding currently couples connection creation, scope creation and
external view contract entry. That order asks an operator to provide scope
identity and projection columns before the server has read the external
catalog. It creates a circular dependency and makes manual columns the
authority for a contract that must be derived from a prepared view.

The source control plane intentionally keeps `source_connection.status` equal
to `DRAFT` and `source_connection.active_revision` null. A DRAFT parent can
still have an immutable configured connection revision. DRAFT does not mean
that a revision is absent, and it must not be bypassed by an empty scope or a
fabricated activation.

Metadata discovery is source-management work. It may inspect bounded
PostgreSQL catalogs and native comments through the existing read-only source
connector before a scope, workspace binding or confirmation exists. It never
reads business rows. Credentials remain in the customer-controlled mounted
secret provider and are resolved only by the worker.

The current delivery coordinate is `P2/PHASE_GATE`; production release remains
ineligible. This ADR defines the prerequisite and storage boundary. It does
not claim a composed runtime, HTTP surface or release eligibility.

## Decision

### 1. Connection-only bootstrap

An organization `OWNER` may create or revise one immutable
`SourceConnectionRevision` without creating a `SourceScope`,
`SourceScopeRevision`, `SourceScopeActivation`, workspace binding or content
job. The request contains typed non-secret connector configuration and an
opaque generated credential reference. Secret bytes, DSNs, passwords and
source-native credentials never enter an API request, job payload, audit event,
log, model input or result projection.

`CONNECTOR_ADMIN` retains the separate trust-verification authority from
ADR-0087. Creating or revising a connection does not verify trust, activate a
scope or grant workspace data access. No ordinary workspace member, model or
workspace metadata reader can create or probe a connection.

The parent connection remains `DRAFT`; scope activation is a separate
authority and does not mutate that parent. The source-management read model
may derive two content-free labels:

- `CONFIGURED`: the exact connection revision, connector/build tuple,
  credential reference and trust record exist;
- `PROBEABLE`: `CONFIGURED` plus current verified trust, database identity,
  security epoch and a worker-resolvable mounted credential.

`DRAFT`, `CONFIGURED` and `PROBEABLE` are not interchangeable. Trust that is
missing, expired, revoked or unavailable is not `PROBEABLE`.

### 2. Pre-scope metadata discovery

An authorized source-management actor requests discovery for one exact
`PROBEABLE` connection revision. The server writes a durable
`source_discovery_request` and enqueues one existing PostgreSQL job in the same
transaction. The generic job payload contains only the opaque
`source_discovery_request_id`. It contains no credential reference, DSN, SQL,
catalog detail or source row.

The request binds organization, actor, connection/revision, trust profile,
security epoch, bounded catalog limits, issue time, expiry and an idempotency
digest. The expiry is at most 15 minutes. The worker derives bounded database
identity and effective-privilege digests during the read-only probe and derives
both again before result commit; it persists them only when both observations
match. The worker resolves the exact revision and mounted credential through
existing worker authority, then uses the existing PostgreSQL trust roots and
catalog-only discovery helper.

The external transaction is read-only and bounded. It may read `pg_catalog`
metadata, relation and column comments, and server-owned type/ordinal/OID
metadata. It never selects business rows, calls arbitrary routines, accepts
caller SQL or mutates the source database. Before catalog access and before
result commit, the worker rechecks the exact connection, trust, database,
privilege and security-epoch tuple.

### 3. Encrypted immutable result

`source_discovery_result.metadata_artifact_id` is a new closed encrypted
artifact owner tuple with resource type `SOURCE_DISCOVERY_RESULT`, field
`DISCOVERY_METADATA`, and trusted resource ID `source_discovery_result.id`.
`SourceScopeDisplayMetadata` is not reused because it belongs to an already
created discovered scope and has a different owner identity.

The relational result stores only server-safe authorization, expiry, recheck,
status and bounded-count metadata. The full bounded catalog representation,
including native comments, remains in the envelope-encrypted artifact. Raw
credentials, DSNs, OIDs, privilege graphs and source rows never reach the API
or Model Gateway. A bounded sanitized semantic metadata projection may be
provided to the Model Gateway only under the existing model policy. Native
comments are untrusted data, not instructions.

The result is immutable after its worker-owned terminal write. The only later
mutation is one exact binding of the artifact ID before the transaction
commits. A new probe creates a new request and result. Every read or selected
view use rechecks tenant/source-management authorization, artifact retention,
expiry, connection revision, trust, database identity, privilege digest and
security epoch. A stale or expired result cannot seed a scope and is not
renewed by a read or retry.

### 4. Server-derived view selection

The later selected-view command references a server-issued view selector bound
to the immutable result. It does not accept OIDs, hashes, roles, columns, SQL,
credentials or source-native identifiers from the caller.

The server recognizes the existing explicit `BusinessObjectContract` format.
For a prepared view it derives the ordered projection and contract hash from
trusted metadata and existing format rules. It does not infer identity,
date, status or business meaning from a noun, seed name, sample row or
ambiguous structure. A visible but incomplete, malformed or ambiguous view
returns typed `NEEDS_INTERPRETATION` metadata and creates no scope.

For a prepared selection, the source owner creates the normal discovered-scope
identity/display artifacts and a `SourceScope` draft using the server-derived
projection. Existing full-scan, activation, workspace binding, confirmation,
sync and Evidence gates remain unchanged.

### 5. Storage and implementation staging

The first storage slice uses append-only migration `000090` and the existing
PostgreSQL job queue. It adds strict request/result contracts, the new encrypted
owner tuple, request/result relations, forced tenant RLS, exact immutable
lifecycle guards, worker-only result/artifact authority functions, the
`SOURCE_DISCOVERY` job type and the sole `source_discovery_request_id` payload
key. It does not alter an earlier migration.

Implementation follows independently reviewable stages:

1. owner/AAD registry, strict request/result schemas, normative docs, migration
   storage authority and real-PostgreSQL security tests;
2. OWNER connection-only bootstrap and atomic request/enqueue command;
3. worker resolution, catalog probe, result encryption and recheck handling;
4. source-management HTTP polling and server-derived selected-view draft;
5. UI projection and user flow.

Stages after the first do not create alternate SQL authority, a second queue,
a new credential channel, a mock connection or a fake scope activation.

## Alternatives rejected

| Option | Reason |
| --- | --- |
| Require scope registration before discovery | Preserves the circular dependency and makes manual columns authoritative. |
| Create an empty scope or fake activation for probing | Confuses metadata inspection with data authorization. |
| Accept a DSN, password or token through API/UI | Creates an unapproved secret channel. |
| Let the application query the source | Bypasses worker credential and source-owner authority. |
| Add a discovery service or second queue | Adds runtime ownership without a demonstrated need. |
| Seed rows through an operator SQL script | Bypasses the source service's tenant, audit and artifact invariants. |

## Failure and security semantics

- Missing tenant, role, connection revision, trust, attestation or credential
  produces a content-free unavailable result at the caller surface.
- Trust revocation, expiry, database substitution, privilege drift or security
  epoch change invalidates queued work and old results; no fallback revision is
  selected.
- Worker crash or lease loss follows the existing bounded queue retry and
  fencing state machine.
- A terminal request/result is written once. Replay cannot create another
  result or re-register a scope.
- No source content, raw driver error, credential, DSN, SQL, OID or privilege
  graph is stored in job payloads, logs, audit, API responses or model input.
- Discovery never grants workspace content access. Only the existing scope
  activation and workspace confirmation gates can make a projection queryable.

## Evidence required before activation

- strict request/result JSON validation rejects unknown fields and over-limit
  values;
- real PostgreSQL proves forced RLS, cross-tenant isolation, worker-only
  lifecycle functions, exact source-revision binding, 15-minute expiry and
  duplicate-terminal rejection;
- a real source probe proves catalog-only reads, native comments and numeric
  type metadata without business-row reads;
- malformed, oversized, hidden or ambiguous views return typed
  `NEEDS_INTERPRETATION` without a guessed projection;
- selected-view draft creation rechecks the result and leaves parent
  `source_connection` DRAFT;
- HTTP/UI and release gates pass independently after their packages land.

## Delivery status

`DELIVERY_STATE.md` remains the sole delivery-coordinate source. This proposal
does not change it, the release flag, accepted ADRs or deployment composition.

The storage/contract slice, connection-only bootstrap and worker discovery
orchestration are implemented checkpoints. HTTP status/result projection,
selected-view registration, UI, MCP and model projection remain separate until
their own evidence and owner reviews are complete.

## Supersedes / superseded by

None. This proposal complements the accepted source revision, draft,
durable-job and PostgreSQL-source decisions.
