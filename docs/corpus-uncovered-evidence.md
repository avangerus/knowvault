# Evidence for acknowledged uncovered critical invariants (R1 mutation corpus)

Status: normative evidence of ADR-0070/ADR-0071 package (PROPOSED).
Audit date: 2026-08-13. Audit point: P2/R1.

This is a historical mutation-coverage assessment. Descriptions of missing
implementation refer to that audited snapshot. Current registered cases are in
`tests/contracts/mutation-registry.json`; current pilot availability is in
[Pilot status](PILOT-STATUS.md).

Summary: out of 35 critical invariants without an honest mutation corpus at the time of audit — 31 `STAGE_GATED` (enforcement not yet deployed in the product), 1 `DUAL_LAYER` (ING-006, two live independent gates, proven committed probe), 3 converted to regular corpus entries (SRC-014, FRESH-003, SRC-002). A full run of the mutation register on a real PostgreSQL is mandatory in CI and reproducible with the command `go run ./tests/contracts/mutation-runner -root .`; each RED/GREEN outcome of each entry must match the declared one.

## 1. Mutation-runner honesty contract

- One mutation = a copy of the tree in temp + `bytes.Replace` (exactly 1 anchor occurrence) +
  a run of the associated harness test; the baseline must be GREEN.
- A RED mutation must weaken enforcement of the protected semantics; GREEN must
  change executable text without changing semantics.
- Prohibited target paths: `tests/`, `docs/`, `architecture/` (exceptions:
  SCHEMA_SUITE → `architecture/contracts/`, GO_UNIT governance →
  `architecture/licenses.yaml`; the historical workflow-only exception has been retired). The prohibition is enforced
  by the architecture checker when validating mutation-registry entries
  (check-architecture.go:2696-2708: a relative product path, not `../`,
  not absolute, and not under a prohibited prefix), not by the runner code: the runner
  trusts the registry already validated by the checker.
- Consequently, enforcement that lives only in `tests/contracts/runner`
  (self-contained fixture validators without `internal/` imports) structurally
  cannot be weakened honestly: only prohibited files could be weakened.
  For semantics enforced by a normative artifact (JSON Schema,
  fixture), mutating that artifact changes the contract itself, rather than
  weakening its implementation. No honest RED exists until the semantics
  are enforced by a product gate.
- An entry is not designed only on paper: local
  BASELINE/RED/GREEN verification is mandatory; POSTGRES_INTEGRATION runs are performed
  by the main agent against real PostgreSQL (KNOWVAULT_TEST_POSTGRES_URL).

## 2. Classes of product enforcement absence

- **Class 1 (STAGE_GATED)** — enforcement only in fixture validators
  `tests/contracts/runner` and/or normative artifacts; product phase
  landing has not occurred.
- **Class 2 (DUAL_LAYER)** — two independent gates (Go + DB); single-anchored
  mutation cannot structurally flip the test. Proven by committed
  probe script `tests/contracts/mutation-probes/<id>.ps1`, which CI
  must execute (executing entity — implementation debt ADR-0071,
  registered in the archived assessment): baseline GREEN; weakening only
  layer A → GREEN; only layer B → GREEN; both → RED (both layers alive, not
  dead code).
- **Converted** — product gate existed in active phase,
  linked test created, entries added to mutation-registry, RED/GREEN
  empirically verified. Recognition (recognized) does not apply to them.

For STAGE_0A-typed CONTRACT_NEGATIVE rules, "phase not yet arrived" means the phase of semantic landing in product code (P3/P4 for retrieval/manifest semantics): the body obligation arises where the product enforcement appears.

## 3. Summary Table

| critical_id | disposition | product_stage | class |
|---|---|---|---|
| SIG-001 | STAGE_GATED | STAGE_6 | 1 |
| CAN-003 | STAGE_GATED | STAGE_5 | 1 |
| SRC-010 | STAGE_GATED | STAGE_5 | 1 |
| ACL-002 | STAGE_GATED | STAGE_3 | 1 |
| AUD-002 | STAGE_GATED | STAGE_6 | 1 |
| IMM-004 | STAGE_GATED | STAGE_6 | 1 |
| EVD-005 | STAGE_GATED | STAGE_4 | 1 |
| QRY-006 | STAGE_GATED | STAGE_4 | 1 |
| ACL-007 | STAGE_GATED | STAGE_4 | 1 |
| ACL-008 | STAGE_GATED | STAGE_4 | 1 |
| ACL-009 | STAGE_GATED | STAGE_4 | 1 |
| ACL-010 | STAGE_GATED | STAGE_4 | 1 |
| ACL-011 | STAGE_GATED | STAGE_4 | 1 |
| QRY-003 | STAGE_GATED | STAGE_4 | 1 |
| QRY-005 | STAGE_GATED | STAGE_4 | 1 |
| QRY-007 | STAGE_GATED | STAGE_4 | 1 |
| QRY-008 | STAGE_GATED | STAGE_4 | 1 |
| QRY-009 | STAGE_GATED | STAGE_4 | 1 |
| SRCH-009 | STAGE_GATED | STAGE_3 | 1 |
| SRCH-011 | STAGE_GATED | STAGE_3 | 1 |
| MOD-008 | STAGE_GATED | STAGE_4 | 1 |
| MOD-009 | STAGE_GATED | STAGE_4 | 1 |
| MOD-010 | STAGE_GATED | STAGE_4 | 1 |
| MOD-011 | STAGE_GATED | STAGE_4 | 1 |
| MOD-012 | STAGE_GATED | STAGE_4 | 1 |
| CIT-001 | STAGE_GATED | STAGE_4 | 1 |
| CIT-003 | STAGE_GATED | STAGE_4 | 1 |
| CIT-006 | STAGE_GATED | STAGE_4 | 1 |
| CIT-007 | STAGE_GATED | STAGE_4 | 1 |
| CIT-008 | STAGE_GATED | STAGE_4 | 1 |
| CIT-009 | STAGE_GATED | STAGE_4 | 1 |
| ING-006 | DUAL_LAYER | — | 2 |
| SRC-014 | converted | — | 3 |
| FRESH-003 | converted | — | 3 |
| SRC-002 | converted | — | 3 |

## 4. STAGE_GATED — proofs by ID

### SIG-001 — STAGE_6
Rules: contract.signature.multiple-active-key, revoked-key-denied,
retired-key-verifies, wrong-organization-purpose-scope, outside-validity
(invariant-test-registry:144-148). Enforcement: the fixture validator
`validateAuditCheckpoint` (tests/contracts/runner/audit.go:173,179-180,290) and
connector event signature checks (runner/connector.go:265,274,293) are
self-contained, without `knowvault.local` imports. Product: `internal/audit`
contains `ResourceSigningKey` only as a resource-type enum (:83,:483); migrations
000002/000003 have no signing-key tables; the 53 files in `internal/**/*_test.go`
have no key-lifecycle unit tests. An honest RED is impossible.

### CAN-003 — STAGE_5
Rule: contract.connector.tampered-signature-or-replay (:114). Enforcement:
runner/connector.go validateConnectorEvent (:265,274,293) +
executeConnectorReplay (contract_test.go:1781), without knowvault.local imports.
Product: grep `replay|purpose|signing` in internal/ yields: resource enums
(owner_registry), AES-GCM nonce of artifact encryption, OIDC
`SigningAlgorithms` (identity/repository/repository.go:118,252,257,317,323),
replay workspace-snapshot (workspace/repository/source_commands.go:152-155,
repository.go:205-208,645-648) and audit trigger replay (audit.go:257) — all
from other domains. There are no connector event signature and replay-nonce
checks in the product. Honest RED is impossible.

### SRC-010 — STAGE_5
Rules: contract.source.site-prefix-boundary (:127, case_ids site-prefix-boundary/encoded-separator/robots-required), acceptance.source.site-ssrf
PLANNED (:133). Enforcement: runner/source_scope.go validateSiteScope (:477-526), urlWithinPrefix (:603-619) — self-sufficient (the only runner product import is scopeglob, participates only in compile-time syntax check of patterns; results from SITE-cases do not depend on scopeglob.Match).
Product: crawler/SSRF gate deferred (archived assessment: external connectors deferred), no packages with site logic in internal/. Honest RED is impossible.

### ACL-002 — STAGE_3
Rules: contract.connector.source-enforced-acl-invalid (:29, EXECUTABLE),
acceptance.acl.stale-source-denied PLANNED (:27). Enforcement:
runner/connector.go (SOURCE_ENFORCED_ACL_* mutations :632) — self-sufficient.
Product: `acl_freshness_sla_seconds` in 000007:135-137 — CHECK scope-draft validity (:176), not retrieval freshness; `acl_snapshot` in 000014:253
"inert in S1d"; `QuarantineACLUnknown` (folder.go:182) — quarantine marker,
not a gate. The "ACL_UNKNOWN is not indexed" gate drops with indexing (Stage 3).
Honest RED is impossible.

### AUD-002 — STAGE_6
Rule: contract.audit.checkpoint-chain-mismatch (:149). Enforcement:
fixture-cases event-gap/backdated-signature in tests/contracts/runner.
Product: internal/audit/audit.go (639 lines) builds a linear chain
sequence/previous_hash/JCS-hash without checkpoint-signature and external sink;
`ResourceAuditCheckpoint` (:84) — only a constant; grep `checkpoint` on
migrations yields only comments. Periodic chain signing and external
append-only sink — Stage 6. Honest RED is impossible.

### IMM-004 — STAGE_6
Rules: contract.retention.purging-content-disclosure, contract.retention.purged-content-disclosure. Enforcement: fixture-cases of the runner. Product: `CREATE TABLE question_run` is absent (grep `question_run` for migrations — only AAD map 000005:78-81 and audit enums);
internal/purge (110 lines) — purge of source versions (000015) via SECURITY DEFINER, no disclosure gate in the chain. Question-run retention — Stage 6.
Honest RED is impossible.

### EVD-005 — STAGE_4
Rule: contract.manifest.citation-chain-mismatch. Enforcement: fixture-case of the runner. Product: `question_citation` only as a forward-declaration of AAD (000005:86-88, owner_registry.go:43-91); no executable keyed-citation-chain resolver exists in internal/. The citation chain collapses at Question Run (Stage 4). A genuine RED is impossible.

### QRY-006 — STAGE_4
Rule: contract.manifest.corpus-health-provenance. Enforcement: fixture-case of the runner. Product: grep -i `corpus` in internal/ — 0 matches; retrieval layer is not built (archived assessment: evidence callbacks no-op). Corpus-health snapshot — Stage 4. Honest RED is impossible.

### ACL-007 — STAGE_4
Rule: acceptance.answer.current-scope-citation-denied (:30, STAGE_4, DISCLOSURE_NEGATIVE). Enforcement: fixture-case state-saved-answer → validateSavedAnswerCurrentScope (runner/state.go:187-222); local run PASS. Product: no answer/question_run table; grep `material_citation|answer_read_gate` in internal/ — 0; internal/source/evidence/viewer.go — gate for a separate evidence fragment (ErrNotFound), not a gate for a saved answer; no unit tests in the package; api/openapi.yaml without answer endpoints. Honest RED is impossible.

### ACL-008 — STAGE_4
Rule: contract.manifest.stale-acl-partial-citation (:151, STAGE_0A, CONTRACT_NEGATIVE). Enforcement: fixture-case → validateAnswerManifest → validateTrustedRetrievalGrant (runner/manifest_provenance.go:794-798, RETRIEVAL_SOURCE_ACL_STALE); local run PASS. Product: grep `RETRIEVAL_SOURCE_ACL_STALE|acl_fresh` in internal/, db/, cmd/, api/, web/, workers/ — 0 outside tests/, except `acl_freshness_sla_seconds` (000007:135-137, CHECK scope-draft validity :176 — domain ACL-002, not manifest retrieval freshness); ACL in product only as cryptographic binding ACL_PRINCIPAL_SET (owner_registry.go:76, 000005:73). Product landing — retrieval (Stage 4). Honest RED is impossible.

### ACL-009 — STAGE_4
Rule: contract.manifest.stale-principal-set (:152, STAGE_0A). Enforcement:
fixture-case STALE_PRINCIPAL_SET → validateTrustedRetrievalGrant
(manifest_provenance.go:733-738, RETRIEVAL_PRINCIPAL_SET_STALE); local
run PASS. Product: grep `principal_set` — 0 outside tests/. Candidate
internal/identity/identity.go:278-315 (identity-freshness-gate of the caller's
session) is NOT enforcement of the rule: (1) the runner is isolated and does
not import internal/identity; (2) the rule protects the principal-set snapshot
of the manifest, not the session; (3) the identity gate is not registered in
any registry rule. An entry in identity.go would be dishonest redirection.
Honest RED is impossible.

### ACL-010 — STAGE_4
Rules: contract.manifest.authorization-live-projection-mismatch (:181, 7 case_ids), contract.manifest.nondeterministic-grant-path (:182). Enforcement:
fixture-cases → validateTrustedRetrievalGrant/minimalTrustedGrantPath
(RETRIEVAL_WORKSPACE_BINDING_MISMATCH :526/532/542/702,
RETRIEVAL_GRANT_NOT_MINIMAL :684/696); local runs PASS (all 7 cases).
Product: grep `grant_path|MINIMAL_GRANT` — 0 outside tests/ and docs;
internal/workspace/repository/authority_*.go — management side
(deployment/confirmation of grant), not retrieval-temporary live-projection; no SQL retrieval-grants. Honest RED is impossible.

### ACL-011 — STAGE_4
Rule: contract.manifest.zero-context-stale-principal-set (:183, STAGE_0A).
Enforcement: fixture-case → zero-context branch validateAnswerManifest (manifest.go:204-213) + PRINCIPAL_SET_SNAPSHOT_STALE (manifest_provenance.go:142);
local run PASS. Product: retrieval-conveyor is not entirely present; grep `pre-retrieval|PRINCIPAL_SET_SNAPSHOT` — 0; identity.go does not participate in
the rule proof (as ACL-009). Honest RED is impossible.

### QRY-003 — STAGE_4
Rule: contract.manifest.corpus-snapshot-set-mismatch (:88, STAGE_0A;
part of required-set TestContractRegistry, contract_test.go:78).
Enforcement: fixture-case CORPUS_SOURCE_MISSING → validateCorpusSnapshotSet
(manifest.go:883-960); local run PASS. Product: grep
`corpus_snapshot|CorpusSnapshot` — 0; UNIQUE-constraints 000008:36-37 and
persistRevisionSnapshot (idempotency.go:381-410) — management snapshot
workspace (domain SRC-016), not corpus-snapshot manifest. Honest RED is impossible.

### QRY-005 — STAGE_4
Rules: contract.manifest.empty-context-completed (:87), contract.manifest.nonempty-context-unknown-completed (:90). Enforcement: fail-sites in validator manifest.go:172-173 (EMPTY_CONTEXT_COMPLETED) and :186-187 (COMPLETED_SUPPORTED_FACT_REQUIRED); case mutators EMPTY_CONTEXT_COMPLETED (contract_test.go:1615) and NONEMPTY_CONTEXT_UNKNOWN_COMPLETED (contract_test.go:1570).
Product: grep `manifest|question|answer` in internal/**/*.go — no validation code for the answer; no question_run/answer tables (only audit enums 000002/000009/000011); answer-manifest schema only in protected-hashes (pinning, not enforcement). No legitimate product target exists. Honest RED is impossible.

### QRY-007 — STAGE_4
Rule: contract.manifest.retrieval-provenance (:164). Enforcement:
fixture-case RETRIEVAL_PROVENANCE_TAMPER → manifest_provenance.go:872,929.
Product: grep `retrieval` in internal/ — single occurrence comment
authority_command.go:13; pipeline retrieval/snapshot counts are absent.
Honest RED is impossible.

### QRY-008 — STAGE_4
Rule: contract.manifest.question-run-provenance (:165). Enforcement:
fixture-case WRONG_QUESTION_HASH → manifest_provenance.go:83. Product:
`QUESTION_RUN` in migrations — only enum audit content type and AAD type label
(000002:39,80; 000005:78-81; 000009:27; 000011:1455,1480), tables
question_run do not exist. Honest RED is impossible.

### QRY-009 — STAGE_4
Rules: contract.manifest.out-of-interval-model-run (:166), out-of-interval-authorization (:167), out-of-interval-signature (:168).
Enforcement: fixture-cases → manifest_provenance.go:746,933,983,1162,1293 + manifest.go:44. Product: no interval validation for QuestionRun (temporal checks in DB — only lease_deadline 000013/000016). Honest RED is impossible.

### SRCH-009 — STAGE_3
Rule: contract.manifest.unauthorized-candidate-count-leak (:170).
Enforcement: fixture-case + answer-manifest.schema.json. Product: grep
`candidate` from internal/ gives header-iterations (platform/httpauth/auth.go:193-195, platform/workspaceapi/workspaceapi.go:560-562), OIDC state-comparison (platform/oidctransport/codec.go:98-99), OIDC clients (platform/secretmount/provider.go:435-440), AuthorizedCandidateSet AAD (platform/artifactcrypto/owner_registry.go:39,85) and comments ingestion — retrieval-counters (authorized_candidate_count, etc.) are not present in the product.
The schema is a normative pinning of the response structure: its mutation changes the contract, not the landing (there is no product gate that this schema validates in internal/), therefore an honest RED does not exist independently of the legality of the SCHEMA_SUITE-target. An honest RED is impossible.

### SRCH-011 — STAGE_3
Rule: contract.manifest.retrieval-profile-mismatch (:175). Enforcement:
fixture-case → manifest_provenance.go:820 + answer-manifest.schema.json.
Product: grep `profile` yields only parser profile (PAR-004, different invariant)
and connector capability profile; retrieval-profile/index-mapping code is absent.
The same normative logic as for SRCH-009: only the contract can be weakened,
not its landing. Honest RED is impossible.

### MOD-008 — STAGE_4
Rules: contract.model.unrelated-embedding-run, unrelated-reranking-run, unrelated-generation-run, generation-plan-drift (:156-159). Enforcement: UNRELATED_EMBEDDING_RUN / UNRELATED_RERANKING_RUN / UNRELATED_GENERATION_RUN / GENERATION_PLAN_DRIFT case mutators (contract_test.go:1117-1134,1141-1146) + answer-manifest schema (these cases' error_code — MODEL_RUN_INPUT_PROVENANCE_MISMATCH / MODEL_GENERATION_PLAN_DRIFT in fixture-cases.json). Product: grep `model_runs|rerank|embedding` — only AAD-forward-declarations (000005:260-261, owner_registry.go) without logic; Model Gateway is absent (archived assessment: generative deferred). Schema — normative pinning (as SRCH-009): schema mutation changes the contract, there is no product gate. Honest RED is impossible.

### MOD-009 — STAGE_4
Rules: contract.model.profile-hash-mismatch (:160), prompt-template-drift (:161). Enforcement: MODEL_PROFILE_HASH_MISMATCH / PROMPT_TEMPLATE_DRIFT mutators (contract_test.go:1103-1116,1135-1140).
Product: grep `profile_hash|prompt_version` in internal/: profile_hash — only parser/extraction profile (ingestion/pipeline.go:130,189,477; handler.go:399 trust_profile_hash; canon/hash.go:119), prompt_version — 0 occurrences; no model-profile hashes in the product. Honest RED is impossible.

### MOD-010 — STAGE_4
Rule: contract.model.unknown-factual-payload (:84). Enforcement:
fixture-case MODEL_UNKNOWN_FACTUAL_PAYLOAD → validateModelPlan (runner/model.go:3,
mutator contract_test.go:627-629). Product: grep
`unknown_reason|UNKNOWN_FACTUAL_PAYLOAD` — 0; model-answer renderer is missing.
Honest RED is impossible.

### MOD-011 — STAGE_4
Rules: contract.model.reranker-incomplete-candidate-set (:184), contract.manifest.candidate-context-count-collapsed (:185). Enforcement: fixture-cases (mutators contract_test.go:1153-1160,1269-1270). Product: grep `rerank|authorized_candidate_set` — only AAD resource-type `question_authorized_candidate_set` (000005:82, owner_registry.go:85) without logic. Honest RED is impossible.

### MOD-012 — STAGE_4
Rules: contract.model.execution-plan-self-declared (:186), unplanned-attempt (:187), snapshot-profile-binding-mismatch (:188). Enforcement: fixture-cases (mutators contract_test.go:1190-1202,1271-1277). Product: grep
`execution_plan|unplanned` — only AAD resource-type
`question_model_execution_plan` (000005:83, owner_registry.go:86); execution plan of the model in code is absent. Honest RED is impossible.

### CIT-001 — STAGE_4
Rules: contract.manifest.unsupported-fact (:82), acceptance.answer.current-scope-citation-denied (:30, see ACL-007). Enforcement: fixture-cases UNSUPPORTED_FACT (mutator contract_test.go:625-626) and state-saved-answer.
Product: grep `claim|citation|answer_span|CLAIM_VERIFICATION_MISSING` — only audit event types and AAD resource types; response contour is missing (OWNER-EXTRACTIVE-ANSWER in archived assessment). Honest RED is impossible.

### CIT-003 — STAGE_4
Rules: contract.numeric.literal-mismatch, uncited-literal, derived-arithmetic,
validation-toctou (:94-97). Enforcement: fixture-cases →
validateNumericOutput (runner/numeric.go:408, mutators :564). Product: grep
`numeric|lexer|LITERAL_MISMATCH` — 0 (matches: HTML-entity handling,
idempotency-keys — other scopes). numeric-validator — with Question Run (Stage 4).
Honest RED is impossible.

### CIT-006 — STAGE_4
Rules: contract.manifest.verifier-toctou (:91), contract.verifier.output-set-mismatch (:92), output-hash-mismatch (:93).
Enforcement: fixture-cases (mutators contract_test.go:968-987,491-513) →
validateVerifierOutput (manifest.go:787). Product: grep
`claim_verification|verifier` — 0 (OIDC token verification — different circuit);
semantic verification deferred. Honest RED is impossible.

### CIT-007 — STAGE_4
Rule: contract.model.factual-section-title (:83). Enforcement: fixture-case
MODEL_SECTION_TITLE → validateModelPlan (runner/model.go:3, mutator contract_test.go:602-603). Product: grep `MODEL_SECTION_TITLE|section_title` — 0;
renderer exists only in tests/contracts/runner/renderer.go. Honest RED is impossible.

### CIT-008 — STAGE_4
Rules: contract.numeric.compound-span-split-citations (:177), compound-locale-mismatch (:178). Enforcement: fixture-cases + golden
numeric-lexer-v1 → validateNumericOutput/numeric.go (all compound logic:
scanFourDigitYear, extendCompoundDateYear, unitClass, classifyPrimary,
exactCitationNumbers — entirely in tests/). Product: grep `compound|lexer` — 0.
Honest RED is impossible.

### CIT-009 — STAGE_4
Rules: contract.numeric.inference-global-citation-leak (:179),
inference-unvalidated-support (:180), inference-citation-only-literal (:195).
Enforcement: fixture-cases → validateNumericOutput +
validateDirectSupportingNumericFact/inferenceLiteralSupportedByFact
(numeric.go:484,517). Product: grep `inference|NUMERIC_INFERENCE|claim_id` — 0.
Honest RED is impossible.

## 5. DUAL_LAYER — probe-evidence

### ING-006 — acceptance.storage.source-binary-persistence rule

The rule has an EXECUTABLE negative test
`TestFolderConnectorTransientBytesNeverReachDurableSinks`
(POSTGRES_INTEGRATION, tests/integration/postgres/folder_connector_test.go:415).
The test is protected by two independent live gates:

- **Go-gate**: `internal/jobs/jobs.go:80` — `sha256Pattern = ^sha256:[0-9a-f]{64}$`; enforcement in `Payload.Validate` for `hashPayloadKeys` (:105-109): payload-value must be `sha256:<64 hex>`, otherwise `CodeInvalid`.
- **DB-gate**: `db/migrations/000013_stage2_durable_ingestion_jobs.sql:115` — CHECK `public.job` → `app.job_payload_is_safe` → `stage2_sha256_is_valid` with the same pattern `^sha256:[0-9a-f]{64}$`.

Committed probe `tests/contracts/mutation-probes/ing-006.ps1` (pwsh,
parameterized `-Root` and env-variables PG-URL/worker-image, without hardcoded
local paths; execution in CI — implementation debt ADR-0071; file
pinned in protected-hashes.json) performs four test runs on a real
PostgreSQL and must yield exactly:

1. baseline — GREEN;
2. weakened only Go-gate (`^.*$`) — GREEN (holds DB-gate);
3. weakened only DB-gate (`CHECK (true)`) — GREEN (holds Go-gate);
4. both weakened — RED (canary reaches durable sink).

All four outcomes are confirmed by a local run on 2026-08-13 on a real PostgreSQL (kv_pg_p2); the run log is not included in the package — the run is reproduced by the command `pwsh tests/contracts/mutation-probes/ing-006.ps1 -Root <repo>` with the specified env (KNOWVAULT_TEST_POSTGRES_URL, KNOWVAULT_TEST_OFFICE_WORKER_IMAGE). Conclusion: both layers are live enforcement (not dead code); single-anchor mutation (the only format allowed by the runner contract) structurally cannot overturn the test. Publishing such an entry (known GREEN when expected=RED) would misrepresent the result; the previous entry `acceptance.storage.source-binary-persistence` has been removed from the registry on this empirical basis, and the mutation_corpus linkage has been removed from the rule. Drift, deletion, or repinning of the probe script must return the ID to corpus-debt.

## 6. Converted — ordinary corpus entries

The product gate existed in the active phase; the attached test was created (contract-first), RED/GREEN outcomes are empirically verified, entries were added to `tests/contracts/mutation-registry.json` and are covered by a full mutation-runner run.

### SRC-014 — rules contract.connector.untrusted-build-workspace-managed,
contract.connector.trust-record-mismatch,
contract.source.workspace-managed-connector-trust-mismatch (:191-193)

Conversion: the trust-gate has been extracted into a pure function `activationGate` (internal/ingestion/handler.go), with a linked GO_UNIT-test `TestResolveActivationGateRefusesUntrustedOrNonSyncingScope` (internal/ingestion/handler_test.go); entry `SRC-014-*` in the mutation-registry (WEAKENING_ACTIVATION_TRUST / PRESERVING_ACTIVATION_TRUST), rule :193 received mutation_corpus.
Verification: baseline GREEN, RED (condition `|| !trustVerified` removed) — FAILS, GREEN (condition reordering) — PASSES.

### FRESH-003 — contract.extraction.superseded-freshness rule (:101,
kind STATE_SCENARIO)

Conversion: attached POSTGRES_INTEGRATION test
`TestS1dSupersededVersionCannotResurrect`
(tests/integration/postgres/catalog_evidence_freshness_test.go) attacks
the forbidden transition SUPERSEDED→CURRENT in
`db/migrations/000014_stage2_catalog_extraction_evidence.sql` (source_version_guard
:518) and requires failure with state preservation; entry `FRESH-003-*` in
mutation-registry (SQL_LIFECYCLE_WEAKENING / SQL_SEMANTIC_PRESERVING), rule
:101 received mutation_corpus. Verification on real PostgreSQL: baseline
GREEN, RED (`'CURRENT'` added to the allowed set) — FAILS on
version resurrection, GREEN (permutation `IN`) — PASSES.

### SRC-002 — rule architecture.connector.folder-database-capability (:54)

Conversion: entry `SRC-002-*` in mutation-registry is linked to checker-native negative test `TestFolderConnectorBoundaryGuardRejectsCapabilityAndContainmentRegressions` (scripts/check_architecture_test.go:1160), whose enforcement is import-boundary guard folder-connector (internal/connector/folder/folder.go; check-architecture.go checkFolderConnectorBoundaryContents :1798-1849); rule :54 received mutation_corpus. Verification: baseline GREEN, RED (blank-import `internal/platform/database` — capability) — FAILS on «gained a non-allowlisted import», GREEN (reordering allowlisted-imports) — PASSES.
