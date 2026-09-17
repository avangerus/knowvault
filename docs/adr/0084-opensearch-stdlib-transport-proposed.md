# ADR-0084 — Bounded OpenSearch HTTPS transport

Status: Proposed  
Date: 2026-08-29  
Owner: KnowVault platform

## Context

The P3 retrieval boundary needs a tenant-bound transport before an indexer or
retrieval executor can be composed. The dependency lock still marks the
OpenSearch client library as `DEFERRED`, and the current deployment has no
qualified OpenSearch TLS/identity evidence. A transport package must therefore
be useful for contract work without silently turning retrieval on in the
production composition.

## Decision

Introduce a standard-library-only `internal/search` transport as a proposed,
inert boundary:

* production construction accepts only an HTTPS canonical DNS endpoint,
  administrator-provided purpose-specific roots, and an optional client
  certificate; system roots and proxy environment settings are not used;
* the client owns the index alias and organization binding. Callers cannot
  provide an index name, raw OpenSearch DSL, ACL filter, or another tenant;
* indexing documents contain immutable source/version/extraction/evidence
  references and hashes. Search returns only bounded lexical candidates;
  PostgreSQL authorization and current Evidence/grant checks remain mandatory
  before disclosure;
* dependency failures expose stable error codes without endpoint, response
  body, credentials, or query leakage. Generation conflicts stop stale
  writers rather than retrying against another alias;
* this package is not wired into server/worker composition until the P3 schema,
  outbox/indexer, post-authorization executor, live OpenSearch TLS proof, and
  owner phase acceptance are complete.

The standard library is deliberately used only to keep this contract slice
dependency-neutral while `go.opensearch-client` remains deferred. A future
accepted ADR may replace the wire implementation after the dependency license,
SBOM, and runtime qualification gates pass; the public boundary must remain
unchanged.

## Alternatives and consequences

1. Compose the client library now. Rejected: it would bypass the dependency
   lock and create an unqualified production capability.
2. Accept caller-supplied DSL and index names. Rejected: it would make
   cross-workspace leakage and ACL bypass possible.
3. Keep no transport contract at all. Rejected: indexer and retrieval work
   could not be tested against a stable server-owned boundary.

The trade-off is that lexical transport behavior is available for contract
tests, while relevance, indexing durability, and answer disclosure remain
explicitly unavailable until their live gates are met.

## Acceptance evidence required before promotion

* `internal/search` unit contract tests pass with malformed, cross-tenant,
  oversized, conflict, and dependency-error cases;
* a live mTLS OpenSearch environment proves alias generation fencing, bounded
  indexing/search, and response limits using the same endpoint/trust contract;
* PostgreSQL post-authorization tests prove that search candidates cannot
  disclose an Evidence fragment across workspace, grant, version, or
  generation boundaries;
* outbox/indexer replay, stale-generation, and rollback evidence is recorded in
  the signed release registry and the P3 qualification record.

Until those conditions are recorded, `architecture/versions.json`, delivery
state, and production composition must remain unchanged.
