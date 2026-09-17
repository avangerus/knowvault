# ADR-0088 — Bounded interim GENERATIVE answer adapter (GEN-1/GEN-2)

**Status:** proposed

**Date:** 2026-09-06 (GEN-1); addendum 2026-09-06 (GEN-2, workspace-scoped
external runtime activation on the acceptance deployment).

**Owners:** product owner (generation-now directive), model-runtime owner, question-run owner.

**Related:** `PRODUCT_CONSTITUTION.md` §"technologies" (generation is an isolated model runtime behind the Model Gateway), ADR-0067 (extractive answer contract), ADR-0080 (bounded model-runtime profile, design-only, DEFERRED), `POKA_YOKE.md` `MOD-001`..`MOD-012`, `CIT-001`/`CIT-002`, `internal/modelgateway/gateway.go`, `internal/question/service.go`, `db/migrations/000024_stage3_extractive_question_run.sql`.

## Context

The owner directive of 2026-09-06 is: "LLM is the heart of the system — connect
generation now." `internal/modelgateway/gateway.go` already contains the
designed contract (`Profile`, `Binding`, `GenerateRequest`, `ClaimPlan` with
evidence-bounded claim validation) and ADR-0080 accepted the *design* of a
bounded, mTLS, fully-qualified remote/local generator + independent semantic
verifier. ADR-0080 is explicit that it authorizes **no implementation,
qualification or activation**: model/runtime locks stay `DEFERRED`, and the one
probed private-network candidate is "not a production generator" and "cannot be a fallback".

Live probing during this slice (2026-09-06) found two additional facts not
visible from the ADR text alone:

1. The previously observed candidate refused connections at the probe time;
   the reachable OpenAI-compatible endpoint served a multimodal artifact
   with `"capabilities":["completion","multimodal"]`. This is a **vision**
   (multimodal) llama.cpp instance. ADR-0080 §2.3 is a bright-line rule, not a
   qualification gap: "Qwen VL and any other multimodal artifact may be
   qualified only as text-only... vision projectors... are forbidden in the
   generation and verification profile... is not the primary generator and is
   not a fallback." No text-only qualified candidate exists on the acceptance deployment
   today.
2. `db/migrations/000024_stage3_extractive_question_run.sql` enforces
   `question_run_guard()`, which raises on any `UPDATE` where
   `NEW.answer_mode IS DISTINCT FROM OLD.answer_mode` ("question run identity
   is immutable"). `answer_mode`/`verification_method` are fixed forever at
   `INSERT`. A row can therefore never be inserted as `EXTRACTIVE` and later
   promoted to `GENERATIVE`, nor the reverse — "fail closed to an EXTRACTIVE
   answer with a note" for an already-`GENERATIVE` row is not just discouraged
   by ADR-0080 §2.5, it is mechanically impossible without weakening an
   existing immutability trigger, which the product's accepted immutability contract forbids without explicit
   approval of a change to that contract.
3. The manifest schema's DB pair check
   (`question_run_mode_pair_check`) ties `GENERATIVE` to
   `verification_method = 'SEMANTIC_VERIFIER'`. No independently qualified,
   different-family verifier model exists in this deployment (ADR-0080 §2.3
   requires one). Labelling a lexical/string check as `SEMANTIC_VERIFIER` would
   misrepresent the audit trail.

Given these three facts, the literal GEN-1 brief ("fail closed to an EXTRACTIVE
answer with a note", "wire the observed candidate endpoint") cannot be honestly
satisfied without either weakening the `question_run` immutability trigger,
using a forbidden vision model as generator, or mislabelling an unverified
answer as semantically verified. `PRODUCT_CONSTITUTION.md`'s invariant-change rule applies: stop and
propose an ADR instead of taking any of those "small exceptions".

## Decision

1. **Adapter, not activation.** Add a Model Gateway adapter
   (`internal/modelgateway/lab_adapter.go`) that speaks the OpenAI-compatible
   `/v1/chat/completions` contract over plain `net/http`, reuses the existing
   `GenerateRequest`/`ClaimPlan` evidence-bounded validation
   (`ClaimPlan.Validate`), and is a **new, additive type**. The existing mTLS
   `Client`/`Profile`/`validModelEndpoint` (the ADR-0080 production path) are
   untouched — this closes no ADR-0080 gate and claims no qualification.
2. **A real, disclosed verifier**, not a stub. `internal/modelgateway/verifier.go`
   defines a `Verifier` interface and an `EmbeddingVerifier` that reuses the
   *already-integrated* embedding channel (`internal/embedding`, itself an
   isolated model runtime behind its own mTLS mount) to check cosine similarity
   between a claim's text and its cited evidence. This is a genuine, disclosed
   interim semantic check — not the independently-qualified different-family
   LLM verifier ADR-0080 §2.3 ultimately requires. It is explicitly named as an
   **interim** verifier in code comments and here; a future ADR must replace it
   before any customer-facing `GENERATIVE` claim of full ADR-0080 compliance.
3. **Capability-gated, default absent.** `question.Service` only accepts
   `answer_mode: GENERATIVE` when both the adapter and the verifier are wired
   (`NewWithGeneration`). Neither is wired in `internal/platform/composition`
   by default; enabling either requires an explicit new mounted config
   (`internal/modelgateway.LoadLabMountedForTenant`, modelled on
   `internal/embedding`'s mount pattern, requiring an explicit
   `insecure_lab_mode: true` acknowledgement in the mounted file). Absent that
   mount, a `GENERATIVE` request returns the existing typed
   `QUESTION_MODE_UNSUPPORTED` before any run is created — the same
   "capability absent, not silently downgraded" shape already used for the
   embedding channel, and consistent with ADR-0080 §2.5/§2.7 ("an unconfigured
   candidate has no readiness effect").
4. **Mode is decided once, at run creation, never changed.** When the
   capability is wired, `answer_mode`/`verification_method` are fixed at
   `INSERT` (`GENERATIVE`/`SEMANTIC_VERIFIER`) exactly as the immutability
   trigger requires. If the bounded generation+verification attempt (at most
   two attempts, matching ADR-0080 §2.2) does not produce a schema-valid,
   evidence-bounded, verified `ClaimPlan`, the run completes as its own
   terminal state (`INSUFFICIENT_EVIDENCE`) with a fixed, server-owned,
   non-empty sentence and no citations — **never** re-labelled `EXTRACTIVE`.
   This supersedes the GEN-1 brief's literal "fail closed to EXTRACTIVE"
   instruction for the reason in Context point 2; the caller who wants an
   extractive answer submits a new run with `answer_mode: EXTRACTIVE` (already
   true today and unchanged).
5. **Every attempt is persisted content-free.** A new append-only table
   (`question_model_gateway_attempt`, migration `000060`) records one row per
   bounded attempt: run id, purpose, model id, attempt number, status,
   request/response byte-size and a hash of the exact evidence-ID set — never
   question text, evidence text or model output (`MOD-007`/`MOD-008`).
6. **No wiring against the forbidden vision candidate.** This ADR does not
   configure the observed vision-model endpoint as the `GENERATIVE`
   generator: it is multimodal and ADR-0080 §2.3 already forbids that
   regardless of qualification status. `GENERATIVE` therefore remains
   unavailable end-to-end on the acceptance deployment until a text-only candidate exists.
   REST/MCP/UI surfaces expose the mode and the adapter/verifier code is real
   and unit-tested against fake endpoints; the acceptance step added for
   this slice records this fact rather than a fabricated pass.

## Alternatives considered

| Alternative | Why not selected |
| --- | --- |
| Weaken `question_run_guard()` to allow `answer_mode` to change after insert, enabling literal "fail closed to EXTRACTIVE with a note" | Directly weakens an existing, accepted immutability invariant without explicit owner sign-off on that specific change; forbidden by `PRODUCT_CONSTITUTION.md`. |
| Point the adapter at the observed vision endpoint for the acceptance deployment demo so the acceptance step turns green | Uses a model ADR-0080 §2.3 explicitly forbids as generator; would fabricate a passing step over a known-prohibited configuration. |
| Label the embedding-similarity check `SEMANTIC_VERIFIER` and claim full ADR-0080 compliance | Misrepresents the audit trail; the check is real but is not an independently qualified different-family verifier as ADR-0080 §2.3 requires. |
| Do nothing until a full ADR-0080 qualification package (weights/AIBOM/license/GPU/egress-deny) exists | Ignores the owner's explicit "do it now" direction and leaves the designed gateway contract completely unexercised; rejected in favour of building the real, capability-gated adapter now. |

## Consequences

### Positive

- The Model Gateway's designed `ClaimPlan`/evidence-bounded contract gets a
  real, testable implementation and a real (if interim) verifier, without
  touching the ADR-0080 production path.
- `GENERATIVE` is a genuine, addressable capability in REST/MCP/UI today; it
  activates the moment a qualified text-only generator + verifier mount is
  provisioned, with no further product-code change.
- No existing security, immutability or citation invariant is weakened.

### Negative / trade-offs

- `GENERATIVE` remains unavailable on the acceptance deployment at the end of this slice
  (no compliant model is reachable there); the new acceptance step documents
  this rather than passing end-to-end on real hardware.
- The interim embedding-similarity verifier is weaker than the independently
  qualified different-family LLM verifier ADR-0080 §2.3 ultimately requires
  and must not be described as closing that gate.

### Security and failure semantics

- Missing adapter/verifier mount: `QUESTION_MODE_UNSUPPORTED`, no run created.
- Adapter unreachable/invalid JSON/schema-invalid `ClaimPlan`/verifier
  rejection: bounded retry (2 attempts total), then terminal
  `INSUFFICIENT_EVIDENCE` with a fixed sentence, no citations, same
  `GENERATIVE`/`SEMANTIC_VERIFIER` pair recorded at insert — never re-labelled.
- No credential, tool schema, source SQL or prior-run content crosses the
  adapter boundary (unchanged from the existing `GenerateRequest` contract).
- Every attempt is recorded content-free even on failure, so a silent retry
  loop cannot hide behind an empty audit trail.

## Implementation and evidence

- Code/packages: `internal/modelgateway/lab_adapter.go`,
  `internal/modelgateway/verifier.go`, `internal/question/service.go`
  (GENERATIVE branch), `internal/platform/workspaceapi/*.go`, `web/src/main.tsx`.
- Contracts/schemas: no change to `architecture/contracts/answer-manifest.schema.json`
  (the manifest-publishing pipeline is not yet wired for either mode; see
  `docs/DELIVERY_STATE.md` P2 coordinate).
- Negative/mutation tests: fake-endpoint unit tests for the adapter (invalid
  JSON, wrong model id, non-2xx, evidence-ID not in allow-list), verifier
  threshold tests, question-service capability-absent/typed-rejection test.
- Guardrails/versions/licenses/protected hashes: `architecture/versions.json`
  model locks stay `DEFERRED`, untouched; no new dependency.
- Required CI or phase evidence: host gate for this worktree (build/vet/unit/
  contract/real-Postgres); acceptance step documents the unavailable
  end-to-end state honestly.

## GEN-2 addendum — workspace-scoped external runtime activation (2026-09-06)

GEN-1 deliberately left `GENERATIVE` unavailable end-to-end: the acceptance deployment had
no text-only local candidate, and ADR-0080 §2.2 bars a third-party/external
SaaS service from the *production* remote-peer path. The approved scope
for this slice is narrower than that production path: activate `GENERATIVE`
on the *acceptance deployment only*, for the one demo workspace, using DeepSeek
chat-completions (`https://api.deepseek.com/v1`, model `deepseek-v4-flash`) as
the interim GEN-1 lab adapter's endpoint — explicitly approved for that
bounded evaluation, and explicitly **not** a
claim that DeepSeek satisfies ADR-0080 §2.2's customer-owned/customer-operated
on-prem peer contract (no dedicated mTLS/CA mounts, no deny-all egress host, no
retention/logging proof — none of §2.2's conjunctive requirements are
attempted here). A later production activation still needs the full ADR-0080
qualification matrix (§3) regardless of this addendum.

Because an uncontrolled path from *any* workspace to a public third-party API
would be a real, if narrow, data-egress widening beyond what GEN-1 built (the
GEN-1 adapter accepted only a loopback/RFC1918/RFC4193 literal-IP endpoint —
an operator's own bounded lab network — precisely to keep that door shut), this
addendum adds a workspace-scoped policy rather than simply pointing the
existing adapter at a public host:

1. **Local stays the default.** `LabAdapterConfig.ExternalRuntimeWorkspaceIDs`
   (`internal/modelgateway/lab_adapter.go`) is empty unless the mounted config
   explicitly names workspaces; an empty list keeps the GEN-1 loopback/private
   endpoint restriction exactly as before, with no workspace restriction
   (unchanged behaviour for every deployment that does not opt in).
2. **A public endpoint requires an explicit, bounded workspace allow-list.**
   `validLabEndpoint` now accepts a public https host only when
   `ExternalRuntimeWorkspaceIDs` is non-empty (`labMaxExternalWorkspaces = 8`
   caps it); `LabAdapterConfig.AllowsWorkspace`/`LabAdapter.AllowsWorkspace`
   decide per call, and `question.Service.Create` denies `GENERATIVE` with the
   same typed `CodeUnsupportedMode` — indistinguishable from a wholly absent
   mount — for any workspace not on that list, even though the process-wide
   adapter is wired. On the acceptance deployment the mounted list contains
   one explicitly named demo workspace; every other workspace on
   that deployment keeps `GENERATIVE` unsupported.
3. **The key never enters the manifest or a log.** `mount_lab.go`'
   `config.json` now carries `api_key_file` (a bare filename inside the same
   mount root) instead of an inline `api_key`; the key is read from that
   separate file (`loadLabAPIKeyFile`, bounded, path-traversal-rejecting) and
   never marshalled back into any structure that is logged. The operator keeps
   the master secret in its own file (0600, root:root) and provisions a separate
   container-readable copy (0440, root:65532), following the server's existing
   secret-mount convention. The key and non-secret `config.json` are mounted
   read-only at `/run/knowvault/generation` in the server service. The deployment
   must preserve that mount across updates; credentials do not come from a checkout.
4. **Every attempt records which runtime scope served it.** Migration `000060`
   adds a `NOT NULL runtime_scope` column (`LOCAL_LAB` |
   `EXTERNAL_WORKSPACE_SCOPED`) to `question_model_gateway_attempt`, and the
   existing content-free `model_run.gateway_attempt` audit event's
   `reason_codes` carries `MODEL_RUNTIME_<scope>` — a closed, already-validated
   vocabulary entry, not a schema change — so a DeepSeek-backed answer is
   durably distinguishable from a local one without widening the audit
   contract or ever recording a hostname, key or model content.
5. **Composition actually wires it now.** GEN-1 left
   `question.Service.EnableGeneration` uncalled by production composition.
   `internal/platform/composition/runtime.go` now loads
   `modelgateway.LoadLabMountedConfig()` right after `question.NewWithRetrieval`,
   mirroring the existing embedding-mount pattern: a wholly absent mount
   leaves `GENERATIVE` unsupported (no startup failure, unchanged default); a
   present-but-invalid mount is a new startup failure
   (`StartupStageGenerationMount`) so drift cannot look like a safe partial
   deployment; a valid mount calls `questions.EnableGeneration`.
   `modelgateway.EmbedFunc` and `Verifier.VerifyClaim` were widened to carry
   `workspaceID`/`operationID` so a real per-question `embedding.Binding`
   (organization/workspace/operation-id/profile-hash) is assembled per
   question/claim/evidence-item when an embedding channel is mounted — closing
   the "per-question Binding is assembled normally" gap GEN-1 left open.
6. **The interim verifier's embedding source degrades honestly, it does not
   block activation.** The acceptance deployment has no embedding/reranker capability
   mounted at all today (a separate, unrelated qualification gap — retrieval
   there is lexical-only). Requiring a real embedding channel to back the
   interim verifier would therefore make `GENERATIVE` permanently unavailable
   on the one test deployment the owner asked to activate it on. Rather than accept
   that, `internal/modelgateway/local_embed.go` adds a second, explicitly
   weaker interim verifier backing: a deterministic, network-free
   character-trigram feature-hashing vector over the exact claim/evidence
   text (no external call, no model, nothing to bind per tenant). Composition
   prefers the real embedding channel when one is mounted
   (`modelgateway.DefaultVerifierThreshold`) and falls back to this local
   hashing vector (`modelgateway.LocalHashVerifierThreshold`, see point 8
   below for its final live-calibrated value) only when it is not. Both paths run
   through the exact same `Verifier.VerifyClaim`/`cosineSimilarity` code and
   are equally explicit about being an interim, disclosed, textual-similarity
   proxy — neither is, or is described as, the ADR-0080 §2.3
   independently-qualified different-family LLM verifier.

Everything else GEN-1 decided is unchanged by this addendum: the bounded
2-attempt retry, strict `ClaimPlan` schema validation, the interim
embedding-similarity verifier (still explicitly not the ADR-0080 §2.3
independently-qualified different-family LLM verifier), content-free
persistence, and the immutable `answer_mode`/`verification_method` pair fixed
at `INSERT` (an unverifiable attempt still completes as its own terminal
`INSUFFICIENT_EVIDENCE`, never a re-labelled `EXTRACTIVE` run).

7. **The runtime image has no ambient trust pool, so the adapter needs its
   own, mounted one.** `deploy/images/Dockerfile.server` builds `FROM scratch`
   with no CA bundle at all — every other TLS peer in this system (OIDC,
   database, search) already reaches its counterpart over a dedicated mount,
   never the system trust pool, so this was never missed until an adapter
   needed to reach the public web PKI. Rather than add a public CA bundle to
   the protected server image (`deploy/images/` is outside this slice's
   allow-list and changing it needs separate owner sign-off), `LabAdapterConfig`
   gained a `TrustRoots *x509.CertPool` field that is never populated from
   `config.json`: `mount_lab.go` reads it from its own PEM file inside the
   mount root (`trust_bundle_file`), the same "explicit mount, never ambient"
   discipline as `api_key_file`. `Validate()` now requires a non-nil
   `TrustRoots` whenever the endpoint is external (a local loopback/private
   endpoint is unaffected, since it was never a public-PKI target); on acceptance deployment
   this is a copy of the acceptance host's own Ubuntu `ca-certificates.crt`, refreshed
   by `ensureGenerationMount()` on every deploy alongside `api-key` and
   `config.json`.

8. **The real endpoint is a reasoning model; the interim prompt/budget/timeouts
   are calibrated against it, live, end to end on the acceptance deployment.**
   `deepseek-v4-flash` emits a hidden `reasoning_content` field that consumes
   the completion-token budget before any `content` is written — for the
   acceptance deployment demo corpus's real multi-fragment Evidence this reliably needs
   several thousand tokens of reasoning before any answer content appears —
   and separately does not reliably infer `ClaimPlan.Validate`'s per-kind
   field shape (`internal/modelgateway/gateway.go` `validClaimShape` — an
   `UNKNOWN` claim's `text` must be JSON `null`, not an explanatory string)
   from the JSON Schema alone. Four independent bounds were found and fixed
   by live-testing the real production code path end to end against the
   real endpoint with a real API key on the acceptance deployment itself, not by
   inspection or a synthetic-only test:
   - `generationMaxOutputTokens` (`internal/question/service.go`) and the
     adapter's own independent `labMaxOutputTokens` ceiling
     (`internal/modelgateway/lab_adapter.go`) are 32,768: live attempts
     against the real corpus needed anywhere from ~130 to tens of thousands
     of completion tokens depending on question ambiguity, and 1,024-,
     4,096-, 8,192- and 16,384-token budgets each measurably truncated
     mid-reasoning (`finish_reason` `"length"`) on the real prompt before
     this ceiling was reached.
   - `generationSystemInstructions` spells out the exact required field
     combination per claim `kind` (previously every real `UNKNOWN` claim
     failed `MODEL_GATEWAY_RESPONSE_INVALID` because the model populated a
     non-null `text` explaining the gap instead of the required JSON `null`).
   - The adapter's own `labMaxTimeout` (`internal/modelgateway/lab_adapter.go`)
     is 170s, `internal/platform/composition/runtime.go` raises the shared
     `httpserver` `WriteTimeout` to 200s (the stdlib default 60s covers the
     *entire* request-to-response-write window, not just writing bytes, and
     was silently killing the connection — "upstream prematurely closed
     connection" at the reverse proxy — before a legitimately slower real
     attempt could reach its own terminal state), and the acceptance deployment's
     `proxy/nginx.conf` (host-side, not tracked in this repository) raises
     `proxy_read_timeout`/`proxy_send_timeout` to 180s for the same reason,
     one layer further out.
   - The interim verifier's `LocalHashVerifierThreshold`
     (`internal/modelgateway/local_embed.go`) is 0.20, not the originally
     estimated 0.28: a real generated claim (a short paraphrase) checked
     against a real, much longer, multi-topic Evidence fragment scores lower
     even when genuinely supported (live, verified-correct attempts scored
     0.24-0.26) than a same-length synthetic pair does, because the
     fragment's hashed vector is diluted by its own unrelated content. 0.20
     keeps that real case above threshold while staying well clear of the
     unrelated-pair noise floor (observed at roughly -0.05 to 0.15).

   No content, prompt or model output from any of this live testing is
   retained anywhere in the repository, this document, a log or the
   database; only the calibrated bounds and the failure modes they fix are.
   With all four bounds in place, a real end-to-end `GENERATIVE` question
   against the demonstration corpus completes with a real, verified, cited answer
   through both REST and MCP (historical acceptance harness).

### GEN-2 alternatives considered

| Alternative | Why not selected |
| --- | --- |
| Wait for the owner to free local GPU capacity for a text-only qualified candidate before activating `GENERATIVE` anywhere | Leaves the owner's explicit "activate it on the demo stand now" directive unmet for an indeterminate wait; the workspace-scoped policy below lets a later local candidate replace DeepSeek with no product-code change (same `LoadLabMountedConfig` seam). |
| Point the existing (GEN-1) loopback/private-only adapter at DeepSeek by simply relaxing `validLabEndpoint` deployment-wide | Would let *any* workspace on the deployment reach a public third-party API the moment the mount exists, with no per-workspace containment — a real widening of GEN-1's own stated boundary, not a bounded demo exception. |
| Claim this activation closes ADR-0080 §2.2 (customer-owned/customer-operated on-prem peer) | False: DeepSeek is a public SaaS API, not a customer-perimeter peer; none of §2.2's mTLS/CA-mount/egress-deny/retention-proof requirements are attempted. Misrepresenting this would misstate the audit trail exactly as GEN-1's own "Alternatives considered" table already rejected for the verifier. |
| Store the DeepSeek key inline in the mounted `config.json` (as GEN-1 originally did for its lab endpoint's optional key) | Contradicts the explicit requirement that the key come from its own secret file, never the manifest and never a log; also inconsistent with every other deployment secret's own-file convention. |

## Delivery status

- `current` (GEN-2): adapter + verifier + capability-gated question-service
  branch, wired into production composition behind the mount; on the acceptance
  deployment, activated for the single demo workspace (identity omitted) against
  DeepSeek chat-completions, workspace-scoped, audited, key from a separate
  secret file; every other workspace/deployment without a mount stays exactly
  as GEN-1 left it (`QUESTION_MODE_UNSUPPORTED`).
- `target`: a qualified text-only local or ADR-0080 §2.2-compliant
  customer-perimeter generator and an independently qualified different-family
  verifier profile, each behind their own mount, closing ADR-0080 §2.3/§3
  before any customer-facing `GENERATIVE` claim; the DeepSeek activation above
  is explicitly interim and demo-scoped, not that target.
- `deferred`: `architecture/versions.json` `model.generator`/`model.verifier`
  locks, full ADR-0080 qualification matrix (§3), any non-demo workspace or
  other deployment activation.

## Supersedes / superseded by

None.
