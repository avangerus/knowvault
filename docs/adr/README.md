# Architecture Decision Records

An ADR records an architectural decision, its context, consequences, and boundaries of application. This catalog contains decisions `0001`–`0094`; new decisions receive the next number and are created using [TEMPLATE.md](TEMPLATE.md).

## How to read ADRs

- `accepted` — the solution is the current architectural baseline until it is replaced by a new ADR;
- `proposed` — the solution under discussion; it does not grant the right to include a capability in production;
- `superseded` — the old solution is retained for historical purposes; the new ADR must be applied;
- the absence of a suffix in the filename does not override `Status` within the file. For example, ADR-0077 is accepted and this is indicated in its body.

ADR explains "why" and does not replace the contract or test. If the ADR and code diverge, the change is not considered complete until both are updated and the architecture guard is passed.

## Lifecycle

1. Formulate the problem and scope.
2. Review existing ADRs and associated guardrails/contract.
3. Create a draft using the template, specifying alternatives and consequences.
4. Obtain owner/reviewer decision; for security/data/license/runtime boundary, corresponding verification is required.
5. After acceptance, update code, tests, HLD/LLD, and delivery evidence.
6. Upon decision change, create a new ADR with a reference `Supersedes`; do not rewrite the old one so that history is lost.

## Index

### Foundation and core invariants

- [ADR-0001 — Go modular monolith](0001-go-modular-monolith-accepted.md)
- [ADR-0002 — PostgreSQL + OpenSearch](0002-postgres-opensearch-accepted.md)
- [ADR-0003 — Immutable one-shot](0003-immutable-one-shot-accepted.md)
- [ADR-0004 — Derived data without source binaries](0004-derived-data-no-binaries-accepted.md)
- [ADR-0005 — PostgreSQL durable jobs](0005-postgres-jobs-accepted.md)
- [ADR-0006 — Default-deny license policy](0006-license-default-deny-accepted.md)
- [ADR-0007 — Canonical contracts](0007-canonical-contracts-accepted.md)
- [ADR-0008 — Go and edge runtime baseline](0008-go-and-edge-runtime-baseline-accepted.md)
- [ADR-0009 — Build-tool supply chain](0009-build-tool-supply-chain-accepted.md)
- [ADR-0010 — Immutable extraction](0010-immutable-extraction-accepted.md)
- [ADR-0011 — Minimal esbuild UI build](0011-minimal-esbuild-ui-build-accepted.md)

### Identity, tenancy and workspace control plane

- [ADR-0012 — Stage 1 PostgreSQL RLS gate](0012-stage1-postgresql-rls-gate-accepted.md)
- [ADR-0013 — Stage 1 audit foundation](0013-stage1-audit-foundation-accepted.md)
- [ADR-0014 — Stage 1 default-deny policy](0014-stage1-default-deny-policy-accepted.md)
- [ADR-0015 — Stage 1 OIDC dependency lock](0015-stage1-oidc-dependency-lock-accepted.md)
- [ADR-0016 — Stage 1 identity/session foundation](0016-stage1-identity-session-foundation-accepted.md)
- [ADR-0017 — Stage 1 identity persistence](0017-stage1-identity-persistence-accepted.md)
- [ADR-0018 — Atomic domain state and audit](0018-atomic-domain-audit-accepted.md)
- [ADR-0019 — Identity repository pre-auth boundary](0019-identity-repository-preauth-boundary-accepted.md)
- [ADR-0020 — Isolated OIDC protocol boundary](0020-oidc-protocol-boundary-accepted.md)
- [ADR-0021 — Canonical workspace configuration](0021-canonical-workspace-configuration-accepted.md)
- [ADR-0022 — Workspace control-plane repository](0022-workspace-control-plane-repository-accepted.md)
- [ADR-0023 — Workspace revision mutations](0023-workspace-revision-mutations-accepted.md)
- [ADR-0024 — Workspace membership lifecycle](0024-workspace-membership-lifecycle-accepted.md)
- [ADR-0025 — Workspace optimistic concurrency](0025-workspace-optimistic-concurrency-accepted.md)
- [ADR-0026 — Durable workspace command idempotency](0026-workspace-command-idempotency-accepted.md)
- [ADR-0027 — PostgreSQL runtime command proof gate](0027-workspace-runtime-command-gate-accepted.md)

### HTTP, secrets and production runtime

- [ADR-0028 — Tenant-bound HTTP session and CSRF](0028-http-session-and-csrf-boundary-accepted.md)
- [ADR-0029 — Workspace HTTP control-plane handler](0029-workspace-http-control-plane-handler-accepted.md)
- [ADR-0030 — Single-tenant security context and session cookie](0030-single-tenant-security-and-session-cookie-accepted.md)
- [ADR-0031 — AEAD-sealed OIDC browser transport](0031-oidc-sealed-browser-transport-accepted.md)
- [ADR-0032 — Pinned OIDC callback prerequisites](0032-oidc-callback-prerequisites-accepted.md)
- [ADR-0033 — OIDC browser HTTP boundary](0033-oidc-browser-http-boundary-accepted.md)
- [ADR-0034 — Exact root HTTP dispatcher](0034-exact-root-http-dispatcher-accepted.md)
- [ADR-0035 — Linux mounted-secret boundary](0035-linux-mounted-secret-boundary-accepted.md)
- [ADR-0036 — Production PostgreSQL constructor](0036-production-postgresql-constructor-accepted.md)
- [ADR-0037 — Production non-secret composition config](0037-production-nonsecret-composition-config-accepted.md)
- [ADR-0038 — Closeable runtime cryptographic owners](0038-closeable-runtime-crypto-owners-accepted.md)
- [ADR-0039 — Customer-mounted purpose-scoped trust roots](0039-customer-mounted-purpose-scoped-trust-roots-accepted.md)
- [ADR-0040 — Bounded OIDC response streams](0040-bounded-oidc-response-streams-accepted.md)
- [ADR-0041 — Purpose-typed mounted key capabilities](0041-purpose-typed-mounted-key-capabilities-accepted.md)
- [ADR-0042 — Production local readiness gates](0042-production-local-readiness-gates-accepted.md)
- [ADR-0043 — Transactional production runtime](0043-transactional-production-runtime-accepted.md)
- [ADR-0044 — Production server image and mount contract](0044-production-server-image-and-mount-contract-accepted.md)

### Sources, ingestion and evidence

- [ADR-0045 — Bounded shared source scope matcher](0045-bounded-shared-source-scope-matcher-accepted.md)
- [ADR-0046 — Encrypted artifact and ordered outbox](0046-encrypted-artifact-and-ordered-outbox-foundation-accepted.md)
- [ADR-0047 — Source control-plane revision and activation](0047-source-control-plane-revision-and-activation-boundaries-accepted.md)
- [ADR-0048 — Source discovery and scope DRAFT checkpoint](0048-source-discovery-and-scope-draft-checkpoint-accepted.md)
- [ADR-0049 — Inert workspace source snapshot](0049-inert-workspace-source-snapshot-accepted.md)
- [ADR-0050 — Workspace source command and projection gate](0050-workspace-source-command-gate-accepted.md)
- [ADR-0051 — Public workspace source repository commands](0051-public-workspace-source-repository-commands-accepted.md)
- [ADR-0052 — Workspace-managed confirmation authority contract](0052-workspace-managed-confirmation-authority-contract-accepted.md)
- [ADR-0053 — Workspace-managed authority command boundary](0053-workspace-managed-authority-command-boundary-accepted.md)
- [ADR-0054 — Workspace-managed authority runtime persistence](0054-workspace-managed-authority-runtime-accepted.md)
- [ADR-0055 — Encrypted artifact key-wrapping backend](0055-encrypted-artifact-key-wrapping-backend-accepted.md)
- [ADR-0056 — Durable ingestion job substrate](0056-durable-ingestion-job-substrate-accepted.md)
- [ADR-0057 — Safe folder connector](0057-safe-folder-connector-accepted.md)
- [ADR-0058 — Catalog, extraction and Evidence path](0058-catalog-extraction-evidence-accepted.md)
- [ADR-0059 — Source lifecycle and disclosure gate](0059-source-lifecycle-accepted.md)
- [ADR-0060 — Text/structured format extraction](0060-text-structured-format-extraction-accepted.md)
- [ADR-0061 — Source scope-revision cutover lifecycle](0061-source-scope-revision-cutover-lifecycle-accepted.md)

### Isolated workers, deployment and proof

- [ADR-0062 — Isolated document-parser worker](0062-isolated-document-parser-worker-accepted.md)
- [ADR-0063 — Isolated Tesseract OCR worker](0063-isolated-tesseract-ocr-worker-accepted.md)
- [ADR-0065 — Production worker composition](0065-worker-production-composition-accepted.md)
- [ADR-0066 — Parser runtime license decoupling](0066-parser-runtime-license-decoupling-accepted.md)
- [ADR-0067 — Extractive answer contract](0067-extractive-answer-accepted.md)
- [ADR-0068 — Pull-based sandbox dispatcher](0068-sandbox-dispatcher-accepted.md)
- [ADR-0069 — Deterministic deployment and operations](0069-deployment-operations-accepted.md)
- [ADR-0070 — Deployment secret rotation and recovery](0070-deployment-secret-rotation-accepted.md)
- [ADR-0071 — Recognized-uncovered mutation corpus policy](0071-mutation-corpus-recognition-accepted.md)

### Product surface and source boundary extension

- [ADR-0072 — Industrial on-prem perimeter for 1.0](0072-industrial-perimeter-proposed.md) — `proposed`
- [ADR-0073 — Revision activation and Evidence delivery surface](0073-product-surface-enqueue-viewer-accepted.md)
- [ADR-0074 — Source registration and activation surface](0074-source-registration-product-surface-accepted.md)
- [ADR-0075 — Session termination](0075-session-termination-accepted.md)
- [ADR-0076 — Protected answer-document amendments](0076-protected-answer-document-amendments-accepted.md)
- [ADR-0077 — Keyed Evidence content digest](0077-keyed-content-digest.md) — status is recorded in the document body
- [ADR-0078 — Live external PostgreSQL named-query source](0078-live-postgresql-query-source-accepted.md) — `accepted design`; runtime capability remains inert until its delivery gates pass
- [ADR-0079 — Enterprise Question Run access through live UI, versioned API and read-only MCP](0079-enterprise-api-mcp-access-accepted.md) — `accepted design`; MCP/API capability remains forbidden and inert pending P2–P6 acceptances, a separate owner-approved phase amendment, and protected-baseline amendments
- [ADR-0080 — Bounded production model-runtime profile](0080-bounded-model-runtime-profile-accepted.md) — `accepted design`; model/runtime capability remains `DEFERRED` and inert until its qualification and delivery gates pass
- [ADR-0082 — Authenticated HTTP/MCP question access](0082-enterprise-question-access-accepted.md) — accepted bounded read-only adapter
- [ADR-0083 — Bounded live PostgreSQL query runtime](0083-live-postgresql-query-runtime-accepted.md) — accepted implementation slice; external DBA and phase gates remain open
- [ADR-0084 — Bounded OpenSearch HTTPS transport](0084-opensearch-stdlib-transport-proposed.md) — `proposed`; transport remains inert until P3 schema, live TLS, post-authorization, and phase gates pass
- [ADR-0085 — Enterprise knowledge graph and generic question planner](0085-enterprise-knowledge-graph-generic-planner-accepted.md) — accepted product retarget; provider/model activation remains qualification-gated
- [ADR-0086 — Data access modes, principals and access audit for people and agents](0086-data-access-modes-principals-access-audit-proposed.md) — `proposed`; design only, no runtime capability activated
- [ADR-0087 — Operator-visible confirmation, trust verification and refresh of workspace-managed sources](0087-operator-visible-confirmation-trust-verification-refresh-proposed.md) — `proposed`; amends ADR-0053's surface boundary, design only, no runtime capability activated
- [ADR-0088 — Bounded interim GENERATIVE answer adapter (GEN-1/GEN-2)](0088-bounded-generative-answer-adapter-proposed.md) — `proposed`; interim adapter/verifier accepted and activated for a single test workspace only, not a claim of full ADR-0080 compliance
- [ADR-0089 — Governed model-authored SQL over operator-exposed schemas](0089-governed-model-authored-sql-over-operator-exposed-schema-proposed.md) — `proposed`; owner sign-off recorded 2026-09-06 (narrow §7 exception in force); V1-D slice delivers the owner package, mount, exposed-schema/flag registration, REST/MCP ask and audit vocabulary — see its own Delivery status for what remains
- [ADR-0090 — Runtime components of the one-compose install](0090-one-compose-install-runtime-components-proposed.md) — `proposed`; names and closes the set of infrastructure components of the installation (reverse proxy, built-in IdP) to which their records in `architecture/versions.json` (ARC-005) refer
- [ADR-0091 — Source connection onboarding before PostgreSQL scope discovery](0091-source-onboarding-before-scope-discovery-proposed.md) — `proposed`; connection-only bootstrap, metadata discovery before scope activation, and encrypted worker-owned result
- [ADR-0092 — Absence in source and final deletion](0092-source-observed-presence-accepted.md) — accepted for the owner-approved fix for file and SQL disappearance and return; verification and deployment status are recorded separately in PLAN.md
- [ADR-0093 — Migration comment translation compatibility](0093-migration-comment-translation-compatibility-accepted.md) — owner-approved compatibility for six exact legacy-to-English migration checksum pairs
- [ADR-0094 — English source publication](0094-english-source-publication-accepted.md) — English publication under Apache-2.0, private preservation of originals, and a one-time freeze of reviewed English ADRs

## What must be kept in sync

- ADR ↔ implementation/test evidence;
- ADR ↔ `architecture/guardrails.yaml`, versions, licenses and protected hashes,
  if the decision concerns these files;
- ADR ↔ [HLD](../HLD.md), [LLD](../LLD.md) and [pilot acceptance](../PILOT-ACCEPTANCE.md);
- API/JSON schemas ↔ contract fixtures and error-code ownership.

An ADR does not establish that unfinished functionality works: production composition and capability qualification require their own evidence.
