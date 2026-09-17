# Testing and verification

This document describes the minimal reproducible verification cycle. Commands are run from the repository root. For production-like and RLS/mutation scenarios, a real PostgreSQL is required; mock databases are insufficient.

Go checks require a pinned toolchain and profile from `architecture/versions.json`:
`GOTOOLCHAIN=local`, `GOEXPERIMENT=jsonv2`. On CI, this is set by the runner; in the local environment, first activate such a toolchain, then execute the commands below.

## 1. Fast pre-commit cycle

```powershell
$env:GOTOOLCHAIN = 'local'
$env:GOEXPERIMENT = 'jsonv2'
go run ./scripts/check-architecture.go
go test -mod=readonly -run '^$' ./...
go test -mod=readonly -count=1 ./internal/... ./scripts/... ./tests/contracts/runner ./tests/integration/sandboxdispatch
go vet ./...
```

What is checked:

- architecture guardrails, versions, licenses, protected hashes and forbidden dependencies;
- compilation of all Go packages without modifying `go.mod`/`go.sum`;
- unit/contract/sandbox tests without cache reuse;
- static analysis of Go.

## 2. Full Go run

```powershell
go test -mod=readonly -count=1 ./...
```

If the test requires PostgreSQL, start only the local dev profile from [deploy/compose/README.md](../deploy/compose/README.md), apply migrations according to [db/README.md](../db/README.md), and use test credentials. Do not connect the customer database to the local pipeline.

Full run does not replace CI evidence: e2e, mutation corpus, and phase gates must be executed in the environment specified in the corresponding ADR and workflow.

## 3. Architecture guard

```powershell
go run ./scripts/check-architecture.go
```

Guard is mandatory when changing:

- `architecture/guardrails.yaml`, `versions.json`, `licenses.yaml`;
- protected files and `architecture/protected-hashes.json`;
- package dependency direction;
- deployment/image/mount contracts;
- canonical schemas and contract fixtures.

`-rebaseline` cannot be used as a way to hide diff. It is applied only after review of changes and explicit owner decision on a new protected baseline.

## 4. Contract fixtures

The contract suite is located in [tests/contracts/README.md](../tests/contracts/README.md).
The verification order is fixed:

1. strict I-JSON decoding;
2. JSON Schema Draft 2020-12 and local `$ref`;
3. canonicalization/hash;
4. signature/replay protection;
5. semantic validation;
6. state-machine/data-model validation.

Need to check the exact `expected_error_code`, not just the fact of an error. Upon contract change, the fixture, runner, and ADR/document explaining compatibility are updated.

## 5. PostgreSQL, RLS and mutation proof

Scenarios proving tenant isolation, optimistic concurrency, idempotency, audit atomicity, and failure upon SQL weakening must use real PostgreSQL. Minimum check:

- foreign workspace does not read or modify other people's lines;
- absence/substitution of tenant context does not become an unrestricted query;
- retry of the same command does not create a second audit/evidence result;
- stale revision receives a typed conflict;
- mutation removing a guard or predicate becomes RED.

Mutation cases and required checks are defined by the corresponding ADRs, `tests/contracts/mutation-registry.json` and CI workflow. This guide describes their shared invariants and prerequisites.

For a live business object scenario with a separate external cluster, launch a narrow acceptance proof (both URLs must point to different PostgreSQL instances):

```powershell
docker run --rm --network knowvault-test-net `
  -e KNOWVAULT_TEST_POSTGRES_URL=postgres://.../knowvault_test?sslmode=disable `
  -e KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL=postgres://.../external_business?sslmode=disable `
  -e KNOWVAULT_REQUIRE_EXTERNAL_PG=1 `
  -v "${PWD}:/src:ro" -w /src golang:1.26.5-bookworm `
  go test -mod=readonly -count=1 ./tests/integration/postgres `
  -run '^TestPostgreSQLQuery(PublisherAgainstExternalCluster|QuestionWorkspaceIsolation)$' -v
```

`TestPostgreSQLQueryQuestionWorkspaceIsolation` checks two real VIEWs, separate totals/citations and typed deny for a participant in another workspace.

## 6. UI verification

UI source is located in `web`, release artifact — in `web/dist`. Before PR that changes UI or package lock:

```powershell
Set-Location web
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm exec tsc --noEmit
```

Then use the pinned build command and ensure that the modified `web/dist` is indeed its result. Generated asset cannot be updated manually without explanation.

In the current minimal esbuild pipeline, there is no separate `build` script; the exact CI command looks like this:

```powershell
corepack pnpm exec esbuild src/main.tsx --bundle --format=esm --jsx=automatic --minify --outdir=dist/assets --target=es2025
Copy-Item src/index.html dist/index.html
```

To change the contract-shaped response, add tests for meta-symbols, invalid inputs, missing evidence, and foreign workspace, not just the happy path UI snapshot.

### OCR worker OCI reproducibility

For supply-chain verification, collect two independent no-cache OCI exports of the same OCR context with a fixed `SOURCE_DATE_EPOCH`, provenance disabled, and `rewrite-timestamp=true`, then compare the SHA-256 hashes of the archives themselves:

```powershell
$stage = Join-Path $PWD '.tmp-ocr-repro'
New-Item -ItemType Directory -Force $stage | Out-Null
docker buildx build --no-cache --provenance=false `
  --build-arg SOURCE_DATE_EPOCH=1704067200 `
  --output "type=oci,dest=$stage/a.tar,rewrite-timestamp=true" `
  -f workers/tesseract-ocr/Dockerfile workers/tesseract-ocr
docker buildx build --no-cache --provenance=false `
  --build-arg SOURCE_DATE_EPOCH=1704067200 `
  --output "type=oci,dest=$stage/b.tar,rewrite-timestamp=true" `
  -f workers/tesseract-ocr/Dockerfile workers/tesseract-ocr
Get-FileHash $stage/a.tar, $stage/b.tar -Algorithm SHA256
```

Archive matching — only deterministic-pair proof. Until release approval, offline/snapshot package source, fresh SBOM/Grype on the same image, scanned-PDF corpus, and owner acceptance are still required.

## 7. E2E and CI

E2E proof runs on a clean agent in CI. A local green test is useful for diagnostics but does not close the phase if required workflow evidence has not yet been obtained. Before merge, check:

- workflow `.github/workflows/architecture.yml`;
- clean state of the workspace tree;
- absence of unfixed generated files, logs, archives, credentials;
- compliance with protected hashes and delivery coordinate.

## 8. Diagnosis of Drop

1. First, save the exact command, commit SHA, and minimal error output.
2. Check whether the local service/container has expired and whether the test is using the incorrect database.
3. Repeat only a single narrow package with `-count=1`.
4. If the error relates to an invariant, first update the contract/ADR and negative test; do not weaken the check for a green run.
5. Remove secrets and customer data from logs before publishing in the PR.

Verification is completed only when the result is reproducible, the working tree is clean, and the delivery state asserts no more than what is proven by the test.
