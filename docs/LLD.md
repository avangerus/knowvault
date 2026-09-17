# LLD — Low-Level Design

**Status:** implementation map for the current Go modular monolith

**Release scope:** [Pilot status](PILOT-STATUS.md); a listed design boundary does not by itself establish runtime availability.

LLD explains implementation locations and contracts. Design decisions are in the [ADR index](adr/README.md); current availability and limits are in [Pilot status](PILOT-STATUS.md).

## 1. Repository layout

```text
cmd/
  server/                 HTTP server and web surface
  worker/                 durable ingestion worker
  connector/              reserved remote-agent executable scaffold
  operator/               deployment/control-plane tooling
  sandbox-dispatcher/     isolated execution broker
  purger/                 privileged retention runtime
internal/
  answer/                 answer model and repository
  artifact/               encrypted artifact repository
  audit/                  append-only audit primitives
  connector/folder/       bounded folder connector
  connector/git/          read-only HTTPS GitHub/GitLab tree connector
  identity/               identity/session domain
  ingestion/              ingestion orchestration
  jobs/                   durable job model and repository
  platform/               composition and transport adapters
  policy/                 organization/workspace authorization policy
  purge/ recovery/        lifecycle and operational boundaries
  question/               independent question runs and bounded answer tools
  modelgateway/           built-in answer profiles and provider adapters
  retrieval/ search/      candidate retrieval, fusion and search projection
  embedding/              profile-bound embedding client
  sandboxdispatch/        isolated execution broker and protocol
  source/                 source, parser, evidence and canonicalization domains
  workspace/              workspace domain and repository
architecture/             guardrails, versions, licenses, schemas, hashes
api/openapi.yaml           HTTP surface/status contract
db/                        migrations and database instructions
deploy/                    compose, images and runtime assets
tests/contracts/           schema/canonicalization acceptance fixtures
tests/integration/         database, source and sandbox integration tests
tests/e2e/                 end-to-end verification
web/                       UI source and committed production dist
scripts/                   architecture and verification tooling
```

The module path is intentionally left as `knowvault.local/verified-workspace`: this is the internal identity of the current module, not a promise of a public Go import path. It can be changed to the GitHub path only as a separate decision with verification of toolchain, imports, and release consumers.

## 2. Dependency direction

```text
transport / HTTP / CLI
        ↓
application use cases / orchestration
        ↓
domain invariants and value objects
        ↓
ports (repositories, clock, crypto, source reader, job broker)
        ↑
infrastructure adapters (PostgreSQL, filesystem, OIDC, OpenSearch, runtime)
```

Rules:

- domain does not import HTTP, SQL driver, filesystem, or a specific parser;
- transport validates and dispatches requests; repository-backed services own authoritative reads and mutations;
- repository adapter does not turn `tenant_id`, `workspace_id`, or revision into a trusted user parameter;
- server, worker, dispatcher and purger wiring live in their respective `internal/platform/*composition` packages;
- `go list ./...` and the architecture checker serve as a fast signal of boundary violation but do not replace review invariants.

## 3. Binary composition

| Binary | Role | Allowed dependencies |
| --- | --- | --- |
| `cmd/server` | browser HTTP, auth, workspace/source surface, system API, static UI | apphttp, httpauth, tenantsecurity, workspaceapi, systemapi, composition |
| `cmd/worker` | durable ingestion and evidence jobs | workercomposition, ingestion, connector/source/evidence, jobs |
| `cmd/connector` | reserved remote-agent scaffold | lifecycle only; not a qualified remote connector deployment |
| `cmd/operator` | deployment and operational commands | deployment validation, secret/recovery/rotation boundaries |
| `cmd/sandbox-dispatcher` | isolated execution broker for the configured native profile | sandboxdispatch and dispatchercomposition |
| `cmd/purger` | privileged retention processing | purge and purgercomposition |

Operator and purger have separate administrative capabilities. The implemented dispatcher is activated with the optional native-ingestion profile and external host supervisor; the worker receives a submit socket, not container-management authority. See [Native ingestion](NATIVE-INGEST.md) for provisioning and readiness.

## 4. HTTP request path

### 4.1 General pipeline

```text
listener
  → exact root dispatcher (`internal/platform/apphttp`)
  → browser/session/auth boundary
  → tenant security context and CSRF checks
  → route handler (`systemapi`, `workspaceapi`, ...)
  → application/domain operation
  → repository transaction
  → PostgreSQL RLS / authoritative state
  → contract-shaped response
```

`apphttp` matches method + exact path. Do not add prefix-based fallback, which could send a request to a broader branch. Unknown route, wrong method, missing session, foreign workspace, and invalid CSRF have different typed refusal semantics, defined by code and contracts.

### 4.2 Current route boundaries

| Area | Routes / contract | Status |
| --- | --- | --- |
| System | `/api/v1/system/health`, `/api/v1/system/build-info` | current |
| Auth | `/auth/login`, `/auth/callback`, `/auth/logout` | current boundary |
| Workspace/source | `/api/v1/workspaces/...`, `/api/v1/sources/...` | membership, source registration, validation, activation and synchronization |
| Search/evidence | workspace search, evidence, inventory and tools routes | permission-checked reads, retained addresses and source-page URLs |
| Access/audit | workspace membership, service access codes and audit journal | implemented, permission-scoped surfaces |
| MCP | authenticated HTTP MCP surface | workspace-scoped knowledge tools, closed inputs and bounded pagination |
| Questions/models | workspace questions and model-profile catalog | independent runs; configured built-in generation remains preliminary |

[OpenAPI](../api/openapi.yaml) records the exact REST/MCP routes, input fields and response contracts. [MCP tools](MCP-TOOLS.md) is the agent-facing reference. API availability is distinct from qualification of every optional operation or downstream provider.

## 5. Package ownership map

| Package | Owns | Must Not Do |
| --- | --- | --- |
| `internal/identity` | identity/session invariants | must not read HTTP cookies directly |
| `internal/identity/repository` | persistence and pre-auth boundary | must not resolve product authorization policy |
| `internal/workspace` | workspace, membership, revision commands | must not bypass transaction/audit append |
| `internal/workspace/repository` | PostgreSQL workspace operations | must not treat a supplied tenant/workspace coordinate as authorization |
| `internal/source/*` | source IDs, scope, path, format, extraction, evidence | must not publish results without scope/license checks |
| `internal/ingestion` | job orchestration and lifecycle | must not own HTTP/session concerns |
| `internal/jobs` | durable queue state, leases, retries | must not execute parser policy on its own |
| `internal/audit` | append/checkpoint chain and events | must not edit already published events |
| `internal/answer` | answer/evidence repository boundary | must not render claims without access/evidence gate |
| `internal/policy` | default-deny organization/workspace decisions | must not treat administration as implicit source-content access |
| `internal/platform/*` | adapters, composition, HTTP and runtime boundaries | must not transfer domain invariants into wiring |
| `scripts` | static checks and fixtures tooling | must not be the production data path |

## 6. Data and transaction rules

### 6.1 Authoritative state

PostgreSQL owns identity, session/revocation, workspace membership, source/revision, jobs, audit, and evidence metadata. OpenSearch and other projections are built from this state and cannot independently resolve access.

Exact entities, indexes, RLS, and migration contract are located in [DATA_MODEL.md](DATA_MODEL.md) and [db/README.md](../db/README.md). Upon changing a table invariant, both documents are updated, along with the corresponding ADR and protected-hash/evidence, if the file is registered.

### 6.2 Transaction boundary

The team changing the authoritative state must:

1. open one transaction;
2. set/verify tenant and security context;
3. read expected revision or idempotency key;
4. check invariant and object state;
5. write change and required audit event atomically;
6. commit only after successful append;
7. return typed result with new revision/checkpoint.

Repeating the command with the same idempotency key returns the same semantic result or typed conflict; re-delivery of a job must not publish immutable evidence twice.

### 6.3 RLS and tenant context

HTTP security context is created after the session/OIDC boundary. The repository receives a typed context and, within the transaction, sets the values required for PostgreSQL RLS. `workspace_id` from the URL is the request coordinate, not proof of access. The foreign workspace must be rejected by both the application and the database.

## 7. Source and ingestion implementation

```text
source registration
  → source revision / scope draft
  → explicit activation
  → durable job + fencing token
  → bounded read-only source adapter (folder, prepared SQL, or configured extension)
  → catalog / extraction
  → immutable EvidenceFragment + anchor + keyed text_hash
  → audit + ordered outbox
  → optional rebuildable projection
```

- `internal/source/pathcanon` canonicalizes and contains paths;
- `internal/source/scopeglob` applies bounded shared scope matching;
- `internal/connector/folder` performs stable, size/time-bounded reads;
- `internal/source/format`, `docparser`, `docworker`, `eml`, `html` own format
  and parser boundaries;
- `internal/source/evidence` owns immutable fragment semantics and anchors;
- `internal/ingestion` and `internal/jobs` own lifecycle, retries, lease and
  fencing;
- `internal/purge` and `internal/recovery` own explicit lifecycle/operations.

The pilot supports folders and prepared PostgreSQL snapshots. Supported DOCX and text-PDF extraction uses the provisioned native profile; OCR/VLM and Excel analysis are outside the pilot guarantee. `internal/source/postgresqlquery` owns the prepared-view boundary, while `internal/ingestion/postgresql.go` publishes and reconciles its typed entity snapshots. See [SQL snapshots](SQL-SNAPSHOTS.md), [Native ingestion](NATIVE-INGEST.md) and the [connector roadmap](CONNECTOR-ROADMAP.md).

## 8. Evidence and answer path

An evidence object carries at least the identity needed to resolve:

- source and source revision;
- document/version and fragment coordinate;
- deterministic anchor and rendered byte span;
- organization-scoped keyed content digest with `digest_key_version`;
- provenance/format metadata and disclosure state.

Answer rendering is a separate boundary from authorization:

```text
question run
  → candidate evidence
  → PostgreSQL permission re-check
  → integrity/digest/anchor validation
  → mode-specific answer assembly (extractive, generative, or bounded tool loop)
  → safe renderer
  → citations + audit checkpoint
```

The current named-profile answer path is documented in [Model profiles](MODEL-PROFILES.md). It shares authorized evidence access with search; successful transport and valid addresses do not establish model-answer completeness.

`internal/platform/workspaceapi/evidence_exact.go` builds the authenticated `source_page_url`; MCP/read responses and the UI use that URL to open the retained source in KnowVault. `internal/source/evidence` checks access and resolves the exact version/fragment. Neighbor and related-object tools supply additional authorized context where available; the product does not infer arbitrary relationships merely from a link.

Model-supplied Markdown-like text is treated as data and rendered inert where
the contract requires it. Plain SHA is not exposed as the product content
digest; the keyed digest decision is in ADR-0077.

## 9. Jobs, outbox and worker protocol

- Job rows are durable and carry the source revision/tenant coordinate needed
  for re-check.
- A worker claims work with a bounded lease and a fencing identity.
- Expired lease may be retried; an old worker must fail the fence check before
  publishing state.
- Retry policy is explicit and bounded; poison input becomes an inspectable
  failure, not an infinite loop.
- Outbox ordering is part of the contract where downstream projection or audit
  depends on event order.
- Shutdown closes intake, stops claim loops, gives bounded time to active work
  and releases resources; no unbounded goroutine is allowed to own a secret or
  mounted source handle.

Details and operational commands: [WORKER_OPERATIONS.md](WORKER_OPERATIONS.md),
[DEPLOYMENT.md](DEPLOYMENT.md), ADR-0056, ADR-0065, ADR-0069.

## 10. Crypto, secrets and external boundaries

- `internal/platform/artifactcrypto` owns artifact encryption/key wrapping;
- `internal/platform/secretmount` owns Linux mounted-secret reads;
- `internal/platform/trustbundle` owns customer-mounted trust roots;
- `internal/platform/oidc` and `oidcweb` own protocol/browser separation;
- `internal/platform/oidctransport` uses bounded response streams;
- `internal/platform/netcanon` owns canonical host/network rules;
- runtime composition in `internal/platform/composition` wires closeable owners
  and readiness gates.

Secrets are passed as purpose-typed capabilities, not arbitrary strings. They
are never committed, logged or returned in errors. For key rotation and
recovery follow [deployment secret procedure](DEPLOYMENT.md) and ADR-0070.

## 11. UI build boundary

`web/` contains UI source and package metadata. The release surface is the
committed `web/dist`; the build must be deterministic and produce the same
tracked files. esbuild is the intentionally small bundling boundary (ADR-0011).
A UI control alone does not establish a backend capability. Check the current
scope in [Pilot status](PILOT-STATUS.md).

## 12. Test and verification matrix

| Layer | Primary Check |
| --- | --- |
| Architecture | `go run ./scripts/check-architecture.go` |
| Compile | `go test -mod=readonly -run '^$' ./...` |
| Go unit/contract | `go test -mod=readonly -count=1 ./internal/... ./scripts/... ./tests/contracts/runner ./tests/integration/sandboxdispatch` |
| Static analysis | `go vet ./...` |
| JSON/schema | `tests/contracts/fixture-cases.json` and contract runner |
| PostgreSQL/RLS | integration and mutation suites against real PostgreSQL |
| UI | pinned pnpm/esbuild build; committed `web/dist` must be identical |
| E2E | isolated deployment checks for the configured workflow; a package test is not a live acceptance result |

The order and prerequisites are collected in [TESTING.md](TESTING.md).

## 13. Rules for Extension

Before adding a new package, binary, parser, queue, or datastore, you must:

1. verify that this is not a duplicate of an existing boundary;
2. describe owner, input/output contract, trust boundary, and failure semantics;
3. add or update ADR if the architectural decision changes;
4. register versions, license, and protected hashes as needed;
5. add negative/mutation test proving that bypass does not work;
6. update HLD/LLD and the public release status only after actual evidence.

Main rule: low-level implementation cannot expand the product scope with a silent fallback.
