# ADR-0095 — Reviewed governed-query presets for MCP

**Status:** proposed

**Date:** 2026-09-19

**Owner sign-off:** RECORDED 2026-09-19. The owner explicitly requested that an
agent recognize configured code phrases and run preset database checks, then
directed implementation to continue. This sign-off authorizes only the bounded
extension below. It does not authorize SQL input from UI, API, MCP, operator
mounts or users, and does not expand the pilot into arbitrary analytics.

**Related:** `PRODUCT_CONSTITUTION.md` §§5, 7 and 9; ADR-0078; ADR-0083;
ADR-0086; ADR-0089; `docs/release/PLAN.md` F2/F3/F5.

## Context

The first SQL customer needs a small set of repeatable operational checks. The
existing governed-query path can compose and execute a bounded read-only query,
show the exact statement and result to an operator, persist the successful
attempt, and audit its execution. Asking a model to reconstruct the same query
for every request adds latency and variation. Accepting SQL in a preset file
would be faster to implement but would violate the product constitution's
closed SQL-input boundary.

## Decision

Add two optional MCP tools:

- `knowvault_queries_list` lists reviewed presets without SQL;
- `knowvault_query_run` executes one preset by id and returns a live result and
  content-free receipt.

A preset is mounted at server startup and contains a stable id, version, user
facing name and description, exact phrases, workspace id, source governed-query
attempt id, SQL hash and exposed-schema revision. It contains no SQL or
credential. IDs and normalized phrases are unique within a workspace and
startup fails closed on an invalid catalogue.

On every list and run, the catalogue is filtered to the requested workspace.
On every run, the server authorizes the current human or SERVICE principal for
that workspace, writes the admission event, checks the workspace's live-query
opt-in, loads the current exposed schema, loads the referenced successful
attempt from the same workspace and connection, and verifies attempt id, SQL
hash and schema revision. A schema change requires a newly reviewed preset
version. Only then does the existing governed-query executor repeat the stored
statement through the dedicated role and its read-only transaction, TLS,
timeout, EXPLAIN cost, row and byte limits.

The successful outcome audit is a condition of disclosing rows. The response
is labelled `LIVE_OBSERVATION` and returns execution timestamps, attempt id,
preset hash, SQL hash and result digest. It is not Evidence and does not receive
a `kv1:` address.

The tools are advertised only while a valid non-empty preset catalogue is
mounted. Direct calls while absent are indistinguishable from an unknown method.
MCP schemas accept only workspace id, connection id and, for run, preset id;
unknown fields including `sql` are refused before the service is called.

## Alternatives

1. **SQL text in configuration:** rejected because it creates an operator SQL
   input surface forbidden by the constitution.
2. **Compose SQL with the model on every call:** already available as governed
   ask, but slower and less repeatable for known operational checks.
3. **Only prepared snapshot views:** retained evidence remains the right path
   for citations and history, but it cannot answer a current operational check
   without waiting for ingestion.
4. **Parameterized presets:** deferred. Parameter schemas, value binding,
   cardinality and audit semantics would enlarge the first slice.

## Acceptance

Focused tests must prove capability absence, SERVICE visibility parity, closed
arguments, SQL-field refusal, immutable attempt/hash/revision binding, exact
phrase uniqueness, startup refusal on malformed mounts and unchanged governed
execution limits. A customer stand additionally compares a successful result
with the source and checks admission plus outcome events before pilot use.

## Delivery status

Implementation is in `feature/governed-sql-presets`. Activation remains gated
on repository CI, a reviewed customer preset, external database grants and a
live acceptance receipt. This ADR records authorization and design; it is not
itself a production claim.
