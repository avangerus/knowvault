# ADR-0089 — Governed model-authored SQL over operator-exposed schemas

**Status:** proposed

**Date:** 2026-09-06

**Owners:** product architect, security owner, source/ingestion owner,
model-runtime owner, Question Run owner.

**Owner sign-off:** RECORDED 2026-09-06. This ADR amends `PRODUCT_CONSTITUTION.md` §7 ("Change rule", §9, requires exactly this: `PROPOSED` status, alternatives, new acceptance tests, then "explicit confirmation of the architecture owner"). Owner decision 10 of `knowvault-DECISIONS.md` (2026-09-06, evening) directs this ADR and names the owner as its sign-off authority; owner decision 13 of the same document (2026-09-06, sign-off) records "This is the sign-off for amendments to the constitution §7 within the narrow scope of ADR-0089" — the explicit confirmation §9 requires. The narrow §7 exception (model-composed SQL, over an operator-exposed schema, executed by a dedicated database role under the bounds in §3) is therefore in force for the scope this document describes; every other §7 prohibition (no SQL input on any UI/API/operator/MCP surface, no widening beyond `POSTGRESQL_QUERY`) remains exactly as accepted. This status line records the sign-off; it is not itself a delivery or activation claim — see Delivery status below.

**Related:** `knowvault-DECISIONS.md` decisions 5, 10–12;
`PRODUCT_CONSTITUTION.md` §§7, 9; ADR-0074 §1.10; ADR-0078 (`POSTGRESQL_QUERY`
boundary, §§1–3, §7, explicit non-goals); ADR-0080 §2.6 (model data boundary,
`MOD-001`); ADR-0086 §1 (GOVERNED_QUERY access mode, declarative only);
ADR-0088 (Model Gateway generation adapter shape); `POKA_YOKE.md` `MOD-001`,
`ARC-002`–`ARC-004`; `internal/ingestion/postgresql.go`;
`internal/source/registration/service.go`; `internal/analytic/registry.go`;
`internal/planner/planner.go`; `scripts/check-architecture.go`.

## Context

Owner decision 5 (2026-09-06, evening) names the main task of the product:
"The operator provides an SQL query; the system executes it on a schedule, ingests the data, builds embeddings, and responds via an LLM... That is why the system is being built." That scheduled path already has a home: `POSTGRESQL_QUERY`
(ADR-0078), the parameterless-projection connector implemented in
`internal/source/registration/service.go` (`registerPostgreSQLQuery`) and
`internal/ingestion/postgresql.go` (`PublishPostgreSQLSnapshot`), and the
deterministic aggregation path — `internal/planner/planner.go`'s `Aggregate`
operation feeding `internal/analytic/registry.go`'s `Registry.Invoke`, which
calls a `Binding.Adapter.Aggregate` over already-authorized `Cell`s, never a
live query. The curator's note on decision 5 is explicit: "numbers must be calculated deterministically from the snapshot — reducer/planner Aggregate, — and the model formulates; the model does not write SQL, constitution §7 remains in force." That remains true
for the scheduled/projection path; this ADR does not touch it.

`PRODUCT_CONSTITUTION.md` §7 separately forbids, without the carve-out
decision 10 now creates: "SQL authorship/input on product, UI, API, operator,
user and model surfaces, model-generated SQL and any database connector
outside the exact `POSTGRESQL_QUERY` boundary of ADR-0078." ADR-0078 §2's
explicit non-goals repeat this: "No ad hoc SQL editor, natural-language-to-SQL,
model-generated SQL... `/execute-sql` API," and ADR-0080 §2.6 (`MOD-001`)
holds that models receive no tools, no source credentials and no raw SQL.
ADR-0074 §1.10 scoped its own registration surface to `FOLDER` only and
explicitly left "non-FOLDER connectors" for a later ADR — the `POSTGRESQL_QUERY`
path (ADR-0078/0083) is that later step, and this ADR is a further, narrower
one still: it does not touch registration, activation or the scheduled
snapshot at all.

Owner decision 10 (2026-09-06, late evening) creates one narrow exception to that prohibition: "Model writes SQL against an open schema" — the model may compose SQL text, but only against a subset of an external source's schema that the *operator* has explicitly exposed, executed by a dedicated, least-privilege database role under fixed transactional and resource bounds, on the SUBD's own authority, not a text parser's. Decisions 11–12 place this in the roadmap: S3-1 (scheduled `POSTGRESQL_QUERY` + row-card Evidence) precedes S3-1b — this ADR, "managed text-to-SQL" — which precedes smart chunking and the S3-2 MCP authorization slice. The product's stated aim (decision 12) is leadership among enterprise RAG/knowledge-base products; an operator who can expose a reviewed slice of their operational schema and ask an ad hoc question about it — "how many machines were on route today" without a pre-registered projection for every possible question — is the concrete feature this ADR authorizes.

**What changes:** for the exact `POSTGRESQL_QUERY` external-source boundary
only, and only over a schema the operator has explicitly and narrowly
exposed, a model may compose read-only SQL text; a dedicated database role
executes it under fixed transactional, timeout, row and cost bounds enforced
by the source PostgreSQL server itself.

**What does not change:** the model never writes SQL against KnowVault's own
PostgreSQL database (`internal/platform/database`) under any circumstance;
§7's prohibition on SQL input from a human — UI, API, operator, MCP caller —
is untouched, because the SQL here is model-composed, never accepted as
caller-supplied text; the scheduled projection path of ADR-0078 (§§1–7) and
the deterministic `Aggregate` path of `internal/analytic` are unmodified and
remain the only route to a repeatable, scheduled answer; and a query this ADR
authorizes becomes durable, scheduled Evidence only by the existing route —
an operator reviewing it and saving it as a confirmed `POSTGRESQL_QUERY`
projection (ADR-0078), never by the model's own authority.

## Decision

### 1. Operator-exposed schema: a new, narrower disclosure than a projection

The operator declares an **exposed schema** for one `POSTGRESQL_QUERY` connection: an explicit, ordered subset of the connection's discovered tables/views and, per object, an explicit subset of columns, each carrying an operator-written natural-language description and unit/type annotation (mirroring the row-card shape decision 11 asks for: "cards with column names/units/table description"). Exposure is strictly narrower than or equal to what the connection's attested privilege graph (ADR-0078 §3) already permits; it can never widen access beyond the dedicated role's grants. The exposed schema is its own immutable, versioned, hashed artifact bound to the connection's trust tuple and `security_epoch` exactly as a projection revision is (ADR-0078 §1): changing which object or column is exposed, or its description, creates a new exposed-schema revision, never a mutable edit. Every exposure change is audited (`source.exposed_schema_revised`) with the principal, connection ID and revision, never the schema text itself beyond its hash.

### 2. The model receives only the exposed schema and the question

A Question Run in `GOVERNED_QUERY` mode (extending ADR-0086 §1's two access
modes with the query-composition step that mode's own text deliberately
excludes: "declarative selections against a confirmed projection contract,
never a caller- or model-composed query" remains exactly true for
`GOVERNED_QUERY` against a *confirmed projection*; this ADR adds a distinct,
explicitly-labelled ad hoc predecessor of that path) sends the model gateway
exactly the current exposed-schema text (names, descriptions, units, types)
and the user's question — never a raw table sample, never unexposed objects,
never credentials, never prior query results from another principal. This is
additive to, not a widening of, `MOD-001`: the model still receives no tools
and no source credentials; it receives schema *metadata* as bounded evidence
text and returns SQL as its *answer* text, exactly as it returns any other
`ClaimPlan` text today (ADR-0088). The model's output is untrusted candidate
text, not a command the gateway or question service is permitted to execute
directly.

### 3. Execution is a single owner package, a dedicated database role, and a database-enforced boundary — never a text parser

A new, single, atomic owner package (working name
`internal/source/postgresqlquery/governedquery`, inside the existing
`postgresqlquery` boundary `scripts/check-architecture.go` already recognizes)
is the only code in the repository permitted to hold the dedicated governed
execution role's connection capability and to pass model-authored SQL text to
that connection. No other package — `internal/ingestion`, `internal/question`,
`internal/modelgateway`, `internal/platform/workspaceapi` — may construct or
forward that text to a database call; each calls only this package's closed
`Execute(ctx, connectionID, exposedSchemaRevision, sqlText)` entry point.

Before execution:

- A **fresh dedicated database role**, distinct from the ADR-0078 §3
  ingestion role, holds `SELECT` on exactly the objects/columns the current
  exposed-schema revision names, and nothing else — no `SELECT` on an
  unexposed table even if the connection's ingestion role could read it, no
  DML, DDL, `CREATE`, `TEMP`, sequence, large-object or role grant, no
  `BYPASSRLS`. Widening the exposed schema is the only way to widen this
  role's grants, and it happens through the same versioned-artifact path as
  §1, never a live `GRANT` issued at question time.
- The connection opens `SET TRANSACTION READ ONLY` (or, following ADR-0078
  §3's own precedent, `SERIALIZABLE READ ONLY DEFERRABLE`) and verifies the
  server reports a read-only transaction before any statement runs.
- A bounded `statement_timeout` and `idle_in_transaction_session_timeout` are
  set and verified with `SHOW`, exactly as ADR-0078 §3 already requires for
  the ingestion connection.
- A row-limit wrapper caps returned rows at cap+1 (the ADR-0078 §4 pattern:
  detect and refuse over-cap results rather than silently truncate them) and
  a total-byte cap bounds decoded response size before allocation.
- The generated statement is first run through `EXPLAIN` (no `ANALYZE`, no
  execution) and refused if its estimated cost exceeds a fixed, configured
  threshold — a resource guard, not a semantic one; a cheap but semantically
  wrong query is a model-quality failure, not a security failure, and this
  ADR does not claim `EXPLAIN` catches the latter.

**The security boundary is the database's own grants, the read-only
transaction, the timeout and the row/byte caps — not a SQL parser.** A
lightweight static check (single statement, no semicolon, no DDL/DML
keywords, no `COPY`, no multi-statement) may run as a cheap first-pass
rejection to save a round trip, but passing it is never treated as proof of
safety, and its absence or a bug in it must never be able to grant access the
role's own grants would refuse. If the model emits a write, a DDL statement,
or a reference to an unexposed object, the dedicated role's own privilege
model — not the check — is what makes PostgreSQL itself refuse it.

### 4. Full observability: request, plan, result and failure are audited; the answer to the user carries the query and result

Every attempt appends one audit event carrying the exposed-schema revision,
the exact generated SQL text, the `EXPLAIN` cost estimate, row count, a
content-free hash of the result set, elapsed time and a typed outcome
(`SUCCEEDED`, `REJECTED_STATIC`, `REJECTED_DATABASE`, `TIMEOUT`,
`ROW_LIMIT_EXCEEDED`, `COST_LIMIT_EXCEEDED`). Following `MOD-007`/`MOD-008`'s
existing content-free discipline for model-gateway attempts, row *values* are
never written to audit, logs, metrics or dead-letter storage — only the
digest. The user-facing answer, by contrast, is not content-free: the exact
SQL executed and its result are shown to the user alongside the model's
answer, exactly as an Evidence citation shows its exact fragment — this is
what makes a `GOVERNED_QUERY`-ad-hoc answer independently checkable rather
than an opaque generation, matching ADR-0086 §1's "never presented as
unattributed generation."

### 5. A promotion path to scheduled, deterministic Evidence — never model authority over what is scheduled

When an operator reviews an ad hoc query's result and finds it useful, they —
not the model, not an automatic promotion — may save that exact SQL text as
the definition of a new confirmed `POSTGRESQL_QUERY` projection (ADR-0078
§§1–2): the operator becomes the object's PostgreSQL view/materialized-view
author (ADR-0078 §2's "complex relational logic belongs in the source-owned
view and is reviewed by the customer's database administrator" is satisfied
by construction, since the operator is reviewing and authoring the object,
not the model). From that point the query is scheduled, its rows become
row-card Evidence and deterministic `Aggregate` answers exactly as decision 5
and ADR-0078/`internal/analytic` already define — this ADR's ad hoc path is
strictly the *discovery* step that precedes a projection, never a substitute
for one, and it creates no schedule, watermark or recurring job of its own.

### 6. Fail-closed at every stage; no partial or degraded disclosure

Absent an exposed schema for the connection, `GOVERNED_QUERY`-ad-hoc is
denied with a typed, content-free code before any model call — the same
"capability absent" shape ADR-0088 already uses for `GENERATIVE`. Absent the
dedicated execution role (misconfigured, revoked, or grants drifted since the
schema was last exposed — reusing ADR-0078 §3's effective-privilege
attestation to detect this before every execution, not only at exposure
time), a static-check rejection, a cost-threshold rejection, a timeout, a
row/byte-cap breach, or any database error: the run terminates with a fixed,
server-owned, content-free error and citation-free note — no query text, no
partial rows and no database error message ever reach the user, audit, logs
or model context in that failure path. This mirrors ADR-0078 §8's closed
error namespace and ADR-0088's bounded-retry/terminal-`INSUFFICIENT_EVIDENCE`
shape; there is no route that silently downgrades a failed governed query
into an ungoverned one.

### 7. Idempotency and per-principal budget

A retried request with the same `Idempotency-Key` (ADR-0073 §1.1's existing
pattern) converges on the same recorded attempt rather than re-executing
against the source database. Every principal — human or, once ADR-0086 §2's
`SERVICE` principals exist, an agent — has a bounded budget of governed
queries per interval, enforced at the grant (ADR-0086 §2's "resource budget —
bounded calls, rows and time — enforced at the grant, not left to the
caller's own restraint"), independent of and in addition to the
`EXPLAIN`/row/timeout bounds enforced per single query.

## Alternatives considered

| Alternative | Why not selected |
| --- | --- |
| Leave `PRODUCT_CONSTITUTION.md` §7 exactly as accepted (no model-authored SQL, ever) | Directly blocks owner decision 5's stated main task for any question the operator has not already anticipated with a pre-registered projection; every new business question would need a developer or DBA to write a new view first, which is the anti-SAP simplicity decision 9 explicitly rejects for every other surface. |
| A SQL parser/validator as the security boundary (accept the text if it parses as a single read-only `SELECT` with no forbidden clauses) | ADR-0078's own explicit non-goals already rejected "a complete SQL parser/policy" for the fixed-projection path because it "retains injection and function/side-effect ambiguity"; a parser can be wrong, incomplete against a specific PostgreSQL grammar version, or bypassed by a construct its author did not anticipate (a function call with a side effect, a cast to a volatile type, a comment that hides a second statement in a naive scanner). A database role's own grants cannot be argued around by a cleverer SQL string; a parser can be. |
| Execute through the existing shared read-only ingestion identity, with no separate exposed-schema role or object list | Reintroduces exactly what ADR-0078 §1 refused for `SOURCE_ENFORCED`: a single shared identity whose privileges are not a per-question ACL. Worse here, that identity's grants (ADR-0078 §3) were sized for the fixed, reviewed projection SELECT — extending its reach to arbitrary model-authored text would let a query touch any object the ingestion role can read, not the operator-reviewed subset decision 10 explicitly requires ("schema that the operator explicitly opened"). |
| A semantic layer / metrics layer (a fixed, named-metric API) instead of model-generated SQL | Is a real alternative for pre-anticipated metrics, and is in effect what the existing `Aggregate` planner path (`internal/analytic`) already is for the scheduled projection route — this ADR keeps that path unchanged. It does not, however, answer decision 5's demand for ad hoc operational questions the operator has not pre-defined a metric for ("which machines were on route today" without a pre-built "machines in transit" metric); a metrics layer alone would leave that class of question unanswerable without a developer adding a new metric, the exact dependency decision 10 removes. |

## Security and failure semantics

- **PostgreSQL grants, not application code, are the trust boundary.** The
  dedicated execution role can be proven, by the customer-side installation
  check ADR-0078 §3 already establishes for the ingestion role, to be denied
  `INSERT`/`UPDATE`/`DELETE`/DDL/`COPY`/advisory-lock mutation and `SELECT`
  on any object outside the current exposed schema.
- **No credential, DSN, or raw row ever reaches the model.** Unchanged from
  ADR-0078 §3/§6 and ADR-0080 §2.6: the model receives exposed-schema
  metadata and the question; it never receives a connection string, a
  credential reference or an unexposed object's existence.
- **Fail-closed, not degraded**, at: missing exposed schema, missing or
  drifted execution-role privileges, static-check rejection, `EXPLAIN`
  cost-threshold rejection, timeout, row/byte-cap breach, and any database
  error — each returns the same shape of content-free typed failure with no
  citation, per §6 above.
- **No route bypasses post-authorization.** A governed query result becomes
  visible to the asking principal only after the same current-workspace
  membership and confirmation checks every other Evidence and `GOVERNED_QUERY`
  read already requires (ADR-0086 §1/§3); it is not a side channel that skips
  retrieval authorization because it did not go through the ingestion
  pipeline.
- **Idempotent retry never re-executes** against the live source database;
  it returns the already-recorded attempt.
- **This ADR does not change the KnowVault-database boundary.** §7's
  prohibition on any SQL surface for KnowVault's own PostgreSQL
  (`internal/platform/database`) is untouched; the dedicated execution role
  and every mechanism in §3 exist only inside the external
  `POSTGRESQL_QUERY` connector boundary.
- **This ADR does not open a human/operator SQL-input surface.** No UI, REST,
  operator or MCP field accepts SQL text as caller input anywhere in this
  design; the only SQL text in the system under this ADR is model output,
  consumed exclusively by the one owner package in §3.

## Acceptance tests

Executed on a live stand with a real second PostgreSQL cluster, following
ADR-0078's own evidentiary discipline (no mock/fake/in-memory connector
counts):

1. A question against an object outside the current exposed schema is
   composed by the model as SQL, submitted to the dedicated role, and denied
   by PostgreSQL itself with a typed, content-free result — proving the
   boundary is the grant, not the static check (disable the static check for
   this one test and confirm the database still refuses it).
2. A generated query that would exceed the configured `EXPLAIN` cost
   threshold is refused before execution; no rows are returned or audited
   beyond the rejection event.
3. A generated query that would return more than the configured row cap is
   refused (cap+1 detection, per ADR-0078 §4's pattern), returning no partial
   result.
4. A query that runs past `statement_timeout` is refused with a timeout
   outcome and no partial rows reach the user, audit or model context.
5. Every attempt — success and every rejection kind — appends exactly one
   audit event carrying the exposed-schema revision, SQL text, cost estimate,
   row count, result digest and typed outcome; row values never appear in
   audit, logs or dead-letter storage.
6. A successful query's exact SQL and result are shown to the requesting
   user in the answer.
7. An operator saves a successful ad hoc query as a new `POSTGRESQL_QUERY`
   projection; it becomes a scheduled, versioned projection through the
   unmodified ADR-0078 registration path and its rows subsequently appear as
   deterministic `Aggregate`-path Evidence, not through this ADR's ad hoc
   path.
8. Every failure mode above returns a content-free error: planted canaries
   (a raw error string, a row value, a credential) appear in none of the
   user-visible failure note, audit, logs, metrics or dead-letter storage.
9. A retried request with the same `Idempotency-Key` returns the recorded
   attempt without a second execution against the source database.
10. A principal exceeding its governed-query budget (calls, rows or time
    within the interval) is denied before execution, independent of any
    single query's own cost/row/timeout bounds.
11. `scripts/check-architecture.go` proves no package other than the new
    owner package can hold the dedicated execution role's connection
    capability or pass SQL text to it, and that this owner package cannot
    hold or use the ADR-0078 §3 ingestion role's connection capability
    (two distinct roles stay distinct code paths).

## Implementation and evidence

- **Code/packages:** new atomic owner package (working name
  `internal/source/postgresqlquery/governedquery`) holding the dedicated
  execution role's connection capability and the sole `Execute` entry point;
  extends `internal/source/registration/service.go` with exposed-schema
  registration/revision (alongside the existing `registerPostgreSQLQuery`);
  extends `internal/question/service.go` with the `GOVERNED_QUERY`-ad-hoc
  branch (capability-gated on an exposed schema existing, following the
  ADR-0088 `EnableGeneration`-style opt-in shape); extends
  `internal/modelgateway` with a schema-composition request/response shape
  reusing `GenerateRequest`/`ClaimPlan` validation; extends `internal/audit`
  with the new attempt event and outcome vocabulary; does not modify
  `internal/ingestion/postgresql.go`'s snapshot-publication path or
  `internal/analytic/registry.go`'s `Aggregate` invocation.
- **New migration:** one new append-only migration (next in sequence after
  `000060`, e.g. `000061_stage3_postgresql_query_exposed_schema.sql`) adding
  the exposed-schema revision relation(s) and the governed-query attempt
  audit relation, following the existing append-only, hash-bound,
  `DEFERRABLE`-guard discipline of migrations 000006/000007/000059.
- **Contracts:** a new `architecture/contracts/postgresql-query-exposed-schema-v1.schema.json`
  (object/column inventory, descriptions, units, revision hash) and a new
  `architecture/contracts/postgresql-query-governed-attempt-v1.schema.json`
  (exposed-schema revision, SQL text, cost estimate, row count, result
  digest, outcome) — both following the closed-JSON-contract, no-free-form-
  metadata discipline ADR-0053/ADR-0087 §4 already establish, and both added
  to `docs/CANONICALIZATION.md`.
- **OpenAPI (`api/openapi.yaml`):** a new endpoint to register/revise an
  exposed schema (operator-only) and a new question-mode value/response shape
  carrying the executed SQL and result alongside citations for a governed
  ad hoc answer; no endpoint anywhere accepts SQL text as a request field.
- **MCP tool:** a new read-only MCP tool surfacing the same governed ad hoc
  question capability to a `SERVICE` principal, following ADR-0079/ADR-0087's
  existing authority pattern (authenticated, scoped, audited, no SQL input
  field — only a natural-language question and the target connection).
- **`scripts/check-architecture.go`:** a new anchor guard, following the
  existing `checkGoBoundaries` shape used for the pgx driver, OpenSearch and
  model-provider boundaries: only the new owner package may import the
  dedicated governed-execution role's connection type or forward
  model-authored SQL text to a database call; the existing
  `internal/source/postgresqlquery/` pgx-import allowance is not widened to
  automatically cover the new subpackage's distinct role/credential type,
  and a mutation routing SQL text through any other package fails the guard.
- **Negative/mutation tests:** unexposed-object query (database-level
  denial), over-cost query, over-row-cap query, timeout, static-check bypass
  attempt (prove the database still refuses what the parser would have
  missed), budget-exceeded principal, retried `Idempotency-Key`, and a
  canary scan across audit/logs/dead-letter for raw SQL error text, row
  values and credentials.
- **Guardrails/versions/licenses/protected hashes:** this ADR proposes no
  new dependency; `architecture/guardrails.yaml` and
  `architecture/protected-hashes.json` gain the new migration, contracts and
  `check-architecture.go` anchor under this proposal's own delivery package.
- **Required CI or phase evidence:** architecture, schema and full Go checks;
  a live-stand run of every Acceptance test above against a real second
  PostgreSQL cluster (no mock/fake connector, per ADR-0078's evidentiary
  bar).

## Delivery status

**Owner sign-off: RECORDED 2026-09-06** (owner decision 13, `knowvault-DECISIONS.md`: "This is sign-off amendments to the constitution §7 in a narrow scope ADR-0089"). Per §9's rule this is the explicit confirmation that activates the narrow §7 exception this ADR describes; every other §7 prohibition remains exactly as accepted.

`current` (V1-D slice, worktree `worktree-v1d`, migrations 000068–000069):
a first, narrower implementation exists on this branch, delivered
independently of the full ADR-0078/V1-A registration surface (not yet merged
onto this branch) and of the ADR-0086 `GOVERNED_QUERY` Question-Run mode
(also not yet merged):

- `internal/source/postgresqlquery/governedquery` is the single owner
  package holding the dedicated governed-execution role's DSN capability and
  the only code that executes model-authored SQL text: read-only
  transaction, `statement_timeout`/`idle_in_transaction_session_timeout`,
  `EXPLAIN (FORMAT JSON)` cost-threshold rejection before execution, and a
  row/byte-capped streaming reader. A lightweight static pre-check
  (`staticPrecheck`) is explicitly a cheap first pass, never the boundary —
  its own package-internal tests call the unexported executor with that
  check disabled and confirm the database still refuses an out-of-grant
  statement.
- The mounted `Config` (DSN, TLS trust bundle, connection id, resource
  limits) comes from its own administrator mount
  (`governedquery.LoadMountedConfig`, `/run/knowvault/governedquery`),
  mirroring the GEN-1/GEN-2 lab-adapter mount pattern; a wholly absent mount
  leaves the capability inert (fail-closed), a present-but-invalid mount is a
  startup failure (`StartupStageGovernedQueryMount`).
- `internal/governedask.Service` is the capability-gated orchestration
  service (`EnableGovernedQuery`, mirroring `question.Service
  .EnableGeneration`): it loads the current exposed-schema revision, sends
  it and the question to the Model Gateway (reusing the existing
  `GenerateRequest`/`ClaimPlan` evidence-bounded contract unchanged — each
  exposed table's description is one `Evidence` item, the model's SQL is the
  `text` of a single `FACT` claim), and hands the exact candidate to
  `governedquery.Execute`. It never holds the execution capability itself
  and is the one other package `scripts/check-architecture.go` allows to
  import `governedquery`.
- Migration `000068` adds `governed_query_connection` (the minimal typed
  registration this slice substitutes for the not-yet-merged V1-A surface,
  including the `live_queries_enabled` flag, default `false`) and
  `governed_query_exposed_schema` (immutable, append-only revisions,
  cross-validated against the dedicated role's own `information_schema`
  before storage — exposure can only narrow, never widen, the role's actual
  grants). Migration `000069` adds `governed_query_promotion` (the
  content-free record behind the "save as projection" hook, see below) and
  extends `app.audit_metadata_is_allowed` with the governed-query attempt
  vocabulary.
- `internal/audit`'s new `source.governed_query_attempted` action records,
  per attempt, the exposed-schema revision, a content-free SQL hash, the
  `EXPLAIN` cost estimate, row count, a content-free result digest and the
  closed outcome vocabulary — never the SQL text or a row value.
- REST (`POST /api/v1/workspaces/{id}/governed-query-connections/{id}
  :set-live-queries`, `.../exposed-schema`, `.../{id}:ask`, `.../{id}
  :promote`) and MCP (`knowvault_governed_query_ask`) surfaces exist; none
  accepts SQL, a DSN or a credential as a field.
- The "save as projection" hook (§5) is `governedquery.PromoteToProjection`
  plus `governedask.Service.Promote`: it records the operator's exact
  reviewed SQL text's hash and a typed `RECORDED_PENDING_INTEGRATION` status
  in `governed_query_promotion`; it does **not** yet call the real
  ADR-0078 `internal/source/registration.Service.Register` (that surface is
  the separate V1-A slice) — this is an honest, typed placeholder with its
  own unit test, not a fabricated integration.

`known gaps against the full Decision text above` (this slice's own
disclosed scope reduction, not a silent omission): idempotency-key dedup for
`Ask` (§7, first half) and the per-principal governed-query budget (§7,
second half) are not implemented; the DBA cluster/database-identity
attestation and monotonic `security_epoch` machinery ADR-0078 §1/§3 describe
for the *scheduled* connector are not required here because this slice's
`governed_query_connection` is its own minimal registration, not a
`source_connection` row — merging V1-A's full connection lineage onto this
branch is expected to reconcile the two; the interim reuse of the GEN-1/GEN-2
Model Gateway adapter (a single shared instance, not a §2.2-qualified
customer-perimeter peer) carries the same interim caveats ADR-0088 already
discloses for `GENERATIVE`.

`target`: unchanged from the Decision above — full ADR-0086 `GOVERNED_QUERY`
Question-Run integration, the real V1-A promotion call, idempotency/budget
enforcement, and the ADR-0078 DBA attestation reconciliation once that
connector's full lineage is merged onto this branch.

`reserved`: the migration slot 000068–000069 is now consumed by this slice
(not merely reserved); a later merge of V1-A/ADR-0086 onto the same tree must
reconcile connection identity, not invent a second one.

## Supersedes / superseded by

None. This ADR narrows an exception into `PRODUCT_CONSTITUTION.md` §7 and
extends ADR-0078's `POSTGRESQL_QUERY` boundary with a second, ad hoc,
model-authored execution path; it does not replace ADR-0078's scheduled
projection path, ADR-0086's GOVERNED_QUERY/EVIDENCE mode split, or ADR-0088's
Model Gateway generation shape.
