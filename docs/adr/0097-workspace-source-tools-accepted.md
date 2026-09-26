# ADR-0097 — Workspace source tools: tables as sources, agent-written read-only SQL

**Status:** accepted on 2026-09-24.

**Provenance:** product direction set by the owner on 2026-09-24; architecture
decision taken by the release lead under the owner's explicit delegation of the
same day (constitution §9, item 4). Verbatim statements are kept in the private
project record.

**Date:** 2026-09-24

**Related:** ADR-0078 (amends §2), ADR-0089 (amends §3), PRODUCT_CONSTITUTION
§5 and §7, and the private delivery plan.

## Context

The owner's canon (12 September 2026) says that the tool does not think and
the model interprets. KnowVault finds data, returns it whole with an address
and never returns another workspace's data.

Two rules currently contradict this for databases:
- ADR-0078 admits a PostgreSQL source only as DBA-created views with a fixed
  five-column contract. It refuses base tables. As a result a customer
  database cannot be connected without prior DBA work in that database.
- The constitution forbids model-authored SQL. So a question that needs a count over customer
  data can be answered only through a separately
  mounted connection, where a second model composes SQL over a hand-registered
  schema of at most 32 objects. That path is invisible in Sources and
  unavailable to external MCP agents as a source tool.

The base-table refusal in ADR-0078 is about keeping business logic in a
reviewed view. It is not a safety property. The safety of ingestion comes from:
- the separate read-only role;
- the single transaction-consistent snapshot;
- the recursive fingerprint check before read;
- the refusal of user-defined routines.

A base table with a primary key keeps all four.

## Decision

1. **Base tables are PostgreSQL sources.** Discovery lists ordinary and
   partitioned tables next to views.
   - A table is PREPARED only with a primary key. The key columns are IDENTITY
     and the remaining columns are EVIDENCE.
   - The administrator may exclude columns. An exclusion only narrows the
     projection, never includes a key column and changes the contract hash.
   - Foreign, temporary and system relations stay refused. User-defined
     routine dependencies stay refused. The fingerprint, the snapshot
     transaction and the drift failure from ADR-0078 apply unchanged.
   - The five-column view contract remains valid.
2. **The agent may write read-only SQL, only through the source tools:**
   - `knowvault_source_schema` returns tables, columns, types and comments of
     one PostgreSQL source enabled in the caller's workspace. It never
     returns excluded columns.
   - `knowvault_source_sql` accepts one statement from the agent (the chat
     model or an authenticated MCP/API agent) against one such source.

   UI forms, operator commands and user-facing API fields still do not
   accept SQL.
3. **The security boundary for agent SQL is the database, not the author.**
   - A separate query role, distinct from the ingestion role, has SELECT only
     on the source's selected tables. Excluded columns are REVOKEd from it,
     which registration verifies.
   - Each statement runs in a READ ONLY transaction with a single-statement
     SELECT/WITH static precheck.
   - An EXPLAIN plan walk rejects any relation outside the source.
   - Cost, time, row and byte limits apply, with at most three successful
     statements per question.
   - Every statement is audited: SQL hash, result digest, schema digest and
     actor. It is reauthorized before disclosure.
   - Functions called inside the statement run with the query role's rights;
     the operator must not grant that role EXECUTE on side-effecting
     routines.
4. **Evidence.** A statement result is a live receipt bound to the question
   run, the SQL hash, the result digest and the schema digest. A numeric
   claim must cite it. Ingested rows are ordinary addressable fragments.
5. **One path.** The separately mounted governed connection becomes an
   ordinary workspace source. `knowvault_ask_live_data` and the second-model
   SQL composition are retired from the chat after S3. The typed-intent,
   metric-definition, planner and metric-comparison paths are not extended
   and are removed after S3.

## Alternatives considered

| Option | Why it was not selected |
| --- | --- |
| Keep DBA-prepared views only | Every customer database needs DBA work before it can be discussed; contradicts the owner's requirement that a connected database is indexed and discussable. |
| Keep second-model SQL composition | The composing model does not see what the agent read (for example the data dictionary). External MCP agents cannot use it, every question pays an extra model call, and it scales only to a hand-registered 32-object schema. |
| Parse and allowlist SQL syntax as the boundary | A parser is not a security boundary. Role privileges and the read-only transaction are, and the plan walk only adds defence in depth. |
| Index everything and answer only from the index | Aggregates over thousands of rows ("how many…") cannot be read page by page. Live SQL is needed for exact numbers, and the index is needed for search and citation. |

## Consequences

### Positive

- A customer database is connected from Sources like a folder. Its rows are
  searchable and citable, and the agent can count and aggregate with exact
  receipts.
- The same tools serve the built-in chat and external MCP agents.

### Negative / risks

- Large tables create many fragments. A per-table row limit (default 50,000)
  and a row estimate in the UI are required.
- Personal data must be excluded both from the projection and from the query
  role. Registration refuses a table whose excluded columns are still
  readable by the query role.
- A customer routine with side effects could be called if the operator grants
  EXECUTE to the query role; this is an operator obligation.

### Acceptance

The owner-facing acceptance criteria live in the private delivery plan.
