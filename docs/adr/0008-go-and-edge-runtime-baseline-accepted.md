# ADR-0008: Go and on-edge runtime baseline

Status: `ACCEPTED`

## Solution

- `knowvault-server`, `knowvault-worker` and remote `knowvault-connector` are written in Go and compiled into separate static binaries.
- Web UI is written in TypeScript/React and embedded as static assets in production; Node is used only during build.
- PostgreSQL stores authoritative metadata, jobs, RLS and audit; OpenSearch is the sole lexical/vector retrieval engine.
- Tika, PaddleOCR and vLLM remain isolated replaceable runtimes via typed adapters; Python is not the language of the application/control plane.
- Exact toolchains, service versions, OCI digests and npm integrity are stored in `architecture/versions.json`.
- For the accepted JCS API, all Go targets fix `GOEXPERIMENT=jsonv2` together with exact Go 1.26.5.

## Why

Go provides a single compiled language for the API, background worker, and network-installed Connector Agent client, offering a small operational surface, good concurrency/network primitives, and simple offline deployment. Java is technically permissible but adds the JVM and a heavier edge artifact. Python is convenient within the ML/OCR ecosystem but is not needed as a second language for business logic: this ecosystem is isolated in versioned sidecars.

PostgreSQL is required as the source of truth and policy boundary. OpenSearch was chosen instead of a separate vector DB so that BM25, vectors, and metadata filters operate within a single index, avoiding the introduction of an additional database with separate ACL/delete failure modes.

## Consequences

- A new application language, runtime database, or vector engine requires a separate ADR.
- The Model/OCR sidecar cannot be imported into domain packages or invoked bypassing the adapter/gateway.
- The production binary image is based on `scratch`; any added CA bundle or helper is included in the SBOM/license review.
- Until the exact Tika/PaddleOCR/vLLM/model artifacts are fixed by digest/revision/hash, the stage using them and the release gate are closed.
