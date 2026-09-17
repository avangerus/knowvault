# ADR-0083 — Bounded live PostgreSQL query runtime

Status: Accepted  
Date: 2026-08-29  
Owner confirmation: the product owner explicitly directed the implementation
of a real, non-mock PostgreSQL source for operational demonstrations and
deployment. This ADR records the runtime slice and does not close the wider
P2/P3/P4 release gates.

## Decision

The `POSTGRESQL_QUERY` source uses one production connector path:

* source revisions persist only a named, parameterless projection contract;
  application code generates the quoted `SELECT` and identity `ORDER BY`;
* each sync resolves its opaque `credential_reference` from the protected
  secret mount, connects with PostgreSQL `sslmode=verify-full`, and uses the
  administrator-mounted database CA bundle; system trust stores, environment
  DSNs, IP literals and caller SQL are rejected;
* the external transaction is `SERIALIZABLE READ ONLY DEFERRABLE` with the
  bounded timeout, memory, parallelism and JIT profile. Rows stream through
  the existing bounded reader and are published only after complete EOF and
  snapshot-hash verification;
* the connector remains data-plane only. Lease fencing, workspace authority,
  immutable versions, Evidence and audit stay in the existing ingestion and
  database owners;
* `knowvault-secret-manifest-v1` may carry optional `source_credentials`
  entries. References are unique across OIDC and source credentials, values
  are imported from protected files, and a worker `-keys-from` generation
  copies the verified source-credential set without exposing plaintext.

No arbitrary SQL, write operation, model prompt, cross-workspace lookup or
source credential is exposed through UI, HTTP, MCP, jobs, logs or audit. A
changed external trust/identity/security/projection contract creates a new
immutable source revision and requires the existing activation and sync gates.

## Alternatives and impact

1. Keep the connector inert and use fixtures. Rejected: it would not satisfy
   the requested live operational scenario and would hide the external DB
   boundary.
2. Accept a caller-supplied SQL string or DSN. Rejected: it bypasses the
   immutable projection and secret/trust boundaries.
3. Add a separate query service. Rejected: it would duplicate lease,
   authorization and Evidence authority.

The runtime adds no third-party dependency. It reuses the pinned pgx driver,
the existing trust-bundle and secret-mount capabilities, and the current
ingestion/job contracts. This slice is accepted as implementation scope; it is
not an assertion that OCR, the remaining connectors, model-backed generation,
signed manifests or the external phase acceptance have been completed.

## Acceptance evidence

* PostgreSQL contract, canonical-value and generated-SQL unit tests pass;
* the PostgreSQL integration suite applies migrations and exercises RLS,
  idempotency, source registration, activation and publication on live
  PostgreSQL 18;
* the external-cluster harness uses a real PostgreSQL URL when explicitly
  configured and verifies two rows/four Evidence cells through the connector
  and publisher;
* connector tests reject IP targets, malformed DNS names and construction
  without explicit administrator trust roots;
* architecture, schema and full Go checks remain required before a release
  claim. Production qualification still requires the owner-level phase and
  customer DBA attestation evidence defined by ADR-0078.
