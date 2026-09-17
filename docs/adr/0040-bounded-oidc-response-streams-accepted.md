# ADR-0040: Bounded OIDC response streams

Status: accepted.

Every OIDC discovery, JWKS and token response consumed by KnowVault passes
through one streaming response-body limiter owned by `HardenedHTTPClient`.
The limit is fixed at 4 MiB and applies to both the production transport and
the deterministic protocol-test seam. Provider response bodies are never
fully buffered by the transport boundary.

A declared `Content-Length` greater than the limit is rejected before the
first body read and the body is closed. Unknown-length and chunked responses
may yield at most 4 MiB; the wrapper probes one additional byte only to prove
overflow. Overflow closes the underlying body exactly once and returns the
fixed content-free OIDC configuration error. A response of exactly 4 MiB is
accepted only after the next read proves EOF.

The wrapper rejects nil responses, nil bodies, invalid content lengths and
zero-progress reads. Close is idempotent and delegates to the provider body.
The transport wrapper chain also preserves `CloseIdleConnections`, so normal
shutdown still releases the owned production connection pool.

This boundary prevents a malicious or broken identity provider from turning
an unbounded JSON/JWKS read in an upstream protocol library into process-memory
exhaustion. Changing the limit or bypassing the wrapper requires a new ADR and
regression tests for declared oversize, chunked overflow, exact-limit success,
close delegation and the complete discovery/JWKS/token flow.
