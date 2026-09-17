# ADR-0086: Data access modes, principals and access audit for people and agents

Status: proposed.

Date: 2026-09-06.

Owners: product architect, security owner, source/ingestion owner, Question
Run owner.

Owner sign-off: delegated owner sign-off, curator, 2026-09-05. The product
owner delegated every need-owner decision to the curator on 2026-09-05; this
ADR is authored and proposed under that delegation, not final owner
acceptance. It still requires the explicit review this document's Acceptance
tests describe before any status change to `accepted`.

Related: ADR-0067, ADR-0074, ADR-0078, ADR-0079, ADR-0082, ADR-0083,
`PRODUCT_CONSTITUTION.md` §§7, 9, `docs/DATA_MODEL.md`,
`docs/TRUST_BOUNDARY.md` and `architecture/guardrails.yaml`.

## Context

KnowVault currently gives every principal exactly one shape of data: every
source, of every type, is reduced to immutable text fragments (Evidence
cells) with a citation anchor. `POSTGRESQL_QUERY` is the only structural
source type accepted so far (ADR-0078, ADR-0083), and it still produces one
Evidence cell per rendered projection column
(`internal/source/postgresqlquery/evidence.go`); there is no path from a
source to a structural, tabular or aggregated result.

Ingestion of that source is deliberately manual and static: `Activate` and
`Sync` (`internal/source/registration/service.go`) run only on explicit
administrator call. There is no schedule and no watermark — each sync is a
full pass over the current projection contract, not an incremental one.

Nothing in the current baseline classifies a source's sensitivity or masks a
field or column on the way into Evidence. A projection or connector column
that should not be readable in full, or at all, has no declared way to say
so; whatever the connector renders becomes citable text.

`database.AccessContext` (`internal/platform/database/database.go`) carries
only a human-derived identity: organization, principal and request. ADR-0079
§3 designed an actor-neutral `actor_kind = HUMAN | SERVICE` context with
service-principal credentials, workspace grants and revocation, but that
design has not been implemented — there is no non-human principal today, and
the MCP/API surface therefore has no service caller to authorize.

A workspace has no access profile of its own: nothing records which access
modes or source types a workspace may use, what budget an agent principal
gets, which retrieval profile applies, or what freshness a workspace should
demand from its sources.

The audit log does not yet close the loop on data access. `ActionCitationOpened`
is declared in `internal/audit/audit.go` and included in every audit-action
switch, but nothing in the current code path calls it — opening a citation
leaves no event. MCP tool calls (ADR-0079 §7) have no audit event either.
There is today no way to answer "who has seen object X" or "what has
principal Y seen."

`PRODUCT_CONSTITUTION.md` §7 forbids SQL authorship or input on every
product, UI, API, operator, user and model surface, and forbids any database
connector outside the exact `POSTGRESQL_QUERY` boundary of ADR-0078. Any
decision here that touches structured data must stay inside that boundary:
declarative parameters and aggregations only, never caller-supplied or
model-generated SQL.

## Decision

### 1. One trust model, two access modes

KnowVault connects both people and agents to corporate data of any shape
through a single trust model: source → confirmation → grant → audit →
revocation. Every read, regardless of principal or transport, must resolve
through that chain or fail closed.

Data reaches a principal in exactly two modes:

- **EVIDENCE** — the current model: an immutable text fragment with a
  citation anchor, unchanged by this ADR.
- **GOVERNED_QUERY** — a structural result of a source-owner-confirmed
  projection, executed with declared parameters, filters and aggregations
  that the projection's owner — not the caller — defined when the
  projection was confirmed. Each execution is recorded as a query execution
  fact: its parameters, the exact projection version it ran against, and a
  digest of the result. That result is citable as evidence exactly as an
  Evidence fragment is; a GOVERNED_QUERY answer is never presented as
  unattributed generation.

The constitution's "answer only from evidence, fail-closed" principle holds
for both modes without exception. SQL authorship remains forbidden on every
surface: a GOVERNED_QUERY's parameters, filters and aggregations are
declarative selections against a confirmed projection contract, never a
caller- or model-composed query, and this stays strictly inside the
`POSTGRESQL_QUERY` boundary set by ADR-0078/ADR-0083 — it does not open a
second, wider database-access surface.

### 2. Principals: implement ADR-0079 §3

`SERVICE` principals become real, not only designed. A service principal
authenticates with its own credential, is granted access per
workspace/operation/revision/time interval, and is never able to impersonate
a human principal or another service principal. Every access decision and
every audit event records `actor_kind` and the exact principal responsible;
a request that cannot resolve to a granted, unexpired, unrevoked principal
is denied. A grant additionally carries a resource budget — bounded calls,
rows and time — enforced at the grant, not left to the caller's own
restraint.

### 3. Complete access audit

Every act of reading data — a fragment read (whether through the REST
surface or through MCP), a GOVERNED_QUERY execution (with its parameters,
projection version, result digest and row count), and every MCP tool
invocation — leaves exactly one audit event carrying the responsible
principal, its scope, the source and version it read, and the identifier of
the object read. The audit log must be sufficient, on its own, to answer
"who has seen object X" and "what has principal Y seen" for any object and
any principal.

### 4. Classification and masking

Every source declares a classification: a small, fixed set of sensitivity
levels, chosen when the source is registered. A projection contract and its
extraction path declare masking rules per field/column at that same point.
Masking is applied while evidence is assembled — before a fragment or a
GOVERNED_QUERY result ever reaches a principal — not as a display-time
filter. A source or field with an unknown or missing classification is
treated as forbidden, not as unrestricted: classification is fail-closed by
default, matching the existing fail-closed evidence principle.

### 5. Workspace access profile

Each workspace declares its own access profile: which access modes
(EVIDENCE, GOVERNED_QUERY) and source types it permits, the resource budgets
its agent principals receive, its retrieval profile (lexical or hybrid), and
the freshness threshold it requires from its sources. The same profile is
where a source's synchronization schedule and incremental watermark belong;
today's manual, full-pass `Activate`/`Sync` remains the default until a
workspace profile declares otherwise.

## Alternatives considered

| Alternative | Why rejected |
| --- | --- |
| Free-form SQL from chat or an agent prompt | Directly reintroduces caller-authored SQL, forbidden by `PRODUCT_CONSTITUTION.md` §7 and outside the ADR-0078 boundary; removes the confirmed-projection guarantee entirely. |
| Generative (model-composed) structural answers, without a recorded query execution | Breaks the "answer only from evidence" principle: a generated number or table has no citable, replayable execution behind it and cannot be audited as a read. |
| A separate product/surface for structured data, apart from Evidence/Question Run | Duplicates confirmation, grant, retrieval-authorization and audit authority that already exists for Evidence; risks policy and citation drift, the exact failure mode ADR-0079 §"one authority, three adapters" already rejected for transports. |

## Acceptance tests

One per decision, executed on a live stand:

1. A confirmed projection with declared parameters returns a structural
   result presented as evidence, and its execution is recorded with
   parameters, projection version and result digest.
2. An agent presenting a valid SERVICE grant receives an authorized answer
   through MCP; the same agent outside its grant (wrong workspace,
   operation, revision, time window or a revoked grant) is denied.
3. A fragment read and a GOVERNED_QUERY execution both appear in
   audit events with their responsible principal, and those events answer
   both "who has seen object X" and "what has principal Y seen."
4. A field or column declared masked never appears, in full or in part, in
   an answer or in an Evidence fragment, regardless of principal.
5. A workspace access profile that forbids a mode or source type causes a
   request using that mode/type to be denied for that workspace.

## Consequences

### Positive

- One trust model covers people and agents, and both Evidence and
  structural data, closing the gap between ADR-0078/ADR-0079's design and
  today's human-only, fragment-only runtime.
- Audit becomes complete for data access, not only for lifecycle and policy
  events, enabling access review and incident response that the current log
  cannot support.
- Classification and masking give sources a declared sensitivity boundary
  instead of relying on what a connector happens to render.

### Negative / trade-offs

- Adds a second data shape (GOVERNED_QUERY) and its own execution-recording
  and citation path alongside the existing Evidence path, increasing the
  surface that policy, retrieval and audit must all agree on.
- Service principals, budgets, classification and workspace profiles are new
  authoritative state; each needs its own owner, schema and migration before
  any of this is more than a design.

### Security and failure semantics

- A read with no resolvable principal, grant, workspace profile permission,
  or classification is denied, not degraded — fail-closed, matching the
  existing Evidence policy.
- A GOVERNED_QUERY execution with an unconfirmed or superseded projection
  version is rejected; only the exact confirmed projection revision may
  execute.
- A masked field or an unknown classification never reaches an answer or an
  Evidence/GOVERNED_QUERY result through any route, transport or recovery
  path; there is no route that bypasses classification once a source
  declares it.
- Revoking a service-principal grant takes effect immediately for every new
  request; it does not wait for a schedule and does not require a new
  workspace or organization epoch.

## Implementation and evidence

- Code/packages: extends `internal/platform/database` (actor-neutral
  `AccessContext`), `internal/source/registration` and
  `internal/source/postgresqlquery` (projection/masking contract),
  `internal/audit` (citation-open and MCP-tool-call events wired to actual
  call sites), and a new workspace-profile and service-principal-grant
  authority.
- Contracts/schemas: ADR-0079 §3 principal/grant/credential relations;
  a projection classification/masking contract; a query-execution record
  (parameters, projection version, result digest, row count); a workspace
  access-profile record.
- Negative/mutation tests: caller-supplied SQL/parameters outside the
  declared projection contract; access with an expired/revoked/wrong-scope
  service grant; a masked field surfacing through any surface; a workspace
  profile violation.
- Guardrails/versions/licenses/protected hashes: this ADR proposes no
  guardrail, dependency, or protected-file change beyond the documentation
  updates it makes; a delivery package implementing it must amend
  `architecture/guardrails.yaml` and protected schemas explicitly, under its
  own gates.
- Required CI or phase evidence: architecture, schema and full Go checks;
  a live-stand run of the Acceptance tests above.

## Delivery status

`current`: EVIDENCE-only access, human-only `AccessContext`, no
classification/masking, no data-access audit for citation reads or MCP
tool calls, no workspace access profile.

`target`: GOVERNED_QUERY alongside EVIDENCE, ADR-0079 §3 SERVICE principals
implemented, complete data-access audit, source classification and masking,
and a workspace access profile — delivered across the roadmap slices below.

`reserved`: the GOVERNED_QUERY execution-record and workspace-profile schema
names in this ADR, so a later delivery package can implement them without a
naming conflict.

`deferred`: everything under Implementation and evidence above; this ADR
authorizes design only and activates no runtime capability.

### Roadmap consequences

- **S2** — sources as a first-class product surface, plus ADR-0079 §3
  SERVICE principals.
- **S3** — GOVERNED_QUERY: confirmed projections, declarative parameters,
  execution recording.
- **S4** — classification, masking, and an access-audit report ("who saw
  X", "what did Y see").
- **S5** — larger data volumes.
- **S6** — OIDC federation and disaster recovery.

## Supersedes / superseded by

None. This ADR extends ADR-0078, ADR-0079 and ADR-0083 without replacing any
accepted decision in them.
