# ADR-0071: Recognized-uncovered mutation corpus policy and stage-bound debt (R1)

Status: accepted.

R1 requires a mutation corpus for every critical invariant whose protected semantics exist in the tree, and states the phase exemption explicitly:
“An invariant whose phase has not arrived according to the current roadmap does not require a corpus and carries an explicit registration of the phase that has not arrived. Overdue evidence for current and completed phases requires a corpus: it is debt, not future work.”
The checker implements the debt half mechanically (`checkCriticalMutationCoverage`): every critical with an EXECUTABLE negative test and no covering corpus entry is an error. The 2026-08 corpus audit found 35 such criticals (docs/corpus-uncovered-evidence.md). Of those, 31 have no product enforcement at the active phase: the protected semantics live only in normative artifacts and the contract runner, so an honest RED mutation (one that weakens a product gate) has no product gate to weaken — mutating a normative artifact would change the contract, not weaken its enforcement. 1 carried dual-layer enforcement where a single-anchor mutation structurally cannot flip the product test, and 3 had product enforcement at the active phase but no binding test. This ADR creates the registration half — an explicit, machine-validated registration of the not-yet-arrived phase — and the overdue mechanism.

## 1. Decision

1. **New protected artifact.** `architecture/recognized-uncovered-critical.json`
   is the explicit registration of a not-yet-arrived phase that R1 requires.
   Schema: `{"version": 1, "entries": [{critical_id, disposition,
   product_stage?, probe?, evidence}]}`. The file is pinned in
   `architecture/protected-hashes.json` alongside the other registries and
   shall be machine-validated by the architecture check. The checker-side
   validation is an implementation obligation of this ADR and has not landed
   yet; until it lands the recognized IDs keep failing the checker with the
   corpus-debt error — the visible, honest form of the debt, not a green state.

2. **Dispositions.**
   - `STAGE_GATED`: corpus debt is suppressed while
     `rank(product_stage) > rank(activeStage)`, both computed through the
     checker's `invariantRoadmapStage` with the active stage taken from
     `DELIVERY_COORDINATE` in `docs/DELIVERY_STATE.md`. When the coordinate
     reaches `product_stage`, suppression ends and the ID returns to debt until
     a corpus entry covers it — "debt, not future work" shall be enforced by
     the gate once the checker implementation lands, not by prose. Until then
     the suppression does not exist and the checker's debt error is the
     enforcement of the "debt" half.
   - `DUAL_LAYER`: corpus debt is suppressed while the ID's committed
     dual-layer probe passes. A probe is an executable script at
     `tests/contracts/mutation-probes/<critical-id>.ps1` that the mutation-runner
     CI shall execute and require to exit 0. Runner-side probe execution is an
     implementation obligation of this ADR and has not landed yet. The probe
     runs the product test on a copied tree and must demonstrate all four
     outcomes: baseline GREEN; weakening layer A only → still GREEN (layer B
     holds); weakening layer B only → still GREEN (layer A holds); weakening
     both → RED. This proves both layers are live enforcement and that no
     single-anchor mutation can flip the product test. The probe file is pinned
     in `architecture/protected-hashes.json`; a missing or unpinned probe shall
     re-open debt once the gate lands.

3. **Honesty constraints to be enforced by the checker.**
   a. A recognized ID must exist in `architecture/guardrails.yaml` and own an
      EXECUTABLE rule in the invariant-test-registry — no recognition of unknown
      or non-executable invariants.
   b. An ID that gains a covering corpus entry in `mutation-registry.json`
      loses its recognition — recognition alongside a corpus is an error, so
      conversion is the only exit from recognition.
   c. `STAGE_GATED` requires a `product_stage` from the canonical stage set
      (`STAGE_0A`–`STAGE_6`) and is only admissible while the ID's owner rule
      has no product-harness test registration (`GO_UNIT` /
      `POSTGRES_INTEGRATION`) in the invariant-test-registry — a registration
      of product tests proves enforcement is already seated at the active phase,
      so the ID cannot be stage-gated and returns to debt. `DUAL_LAYER` requires
      the committed and pinned probe; every entry must link an evidence-doc
      anchor.
   d. Demotion of EXECUTABLE rules to PLANNED remains forbidden by the existing
      phase gate — recognition is not a demotion substitute.
   e. Changes to the recognized file go through the ADR amendment path, not a
      routine protected-hash bump.

4. **Dispositions for the audited 35.** 31 `STAGE_GATED` — 3 × `STAGE_3`
   (ACL-002, SRCH-009, SRCH-011), 23 × `STAGE_4` (ACL-007…011, CIT-001, CIT-003,
   CIT-006…009, EVD-005, MOD-008…012, QRY-003, QRY-005…009), 2 × `STAGE_5`
   (CAN-003, SRC-010), 3 × `STAGE_6` (AUD-002, IMM-004, SIG-001) — and
   1 `DUAL_LAYER` (ING-006) with the committed probe
   `tests/contracts/mutation-probes/ing-006.ps1` covering the Go-side
   `sha256Pattern` payload gate (internal/jobs/jobs.go) and the DB-side
   `app.job_payload_is_safe` CHECK (db/migrations/000013). Three criticals were
   **converted** into ordinary corpus entries instead of being recognized:
   SRC-014 (GO_UNIT entry against the scope-activation trust gate in
   internal/ingestion/handler.go), FRESH-003 (POSTGRES_INTEGRATION entry against
   the forward-only version lifecycle in db/migrations/000014) and SRC-002
   (GO_UNIT entry against the connector import boundary in
   internal/connector/folder/folder.go, executed by the checker-native negative
   test).

5. **Evidence.** `docs/corpus-uncovered-evidence.md` records, per ID, the
   enforcement location and the proof of why no honest corpus entry exists. The
   checker links recognized entries to it. The document is normative evidence,
   not prose, and is pinned in `architecture/protected-hashes.json` like the
   registries.

## 2. Consequences

At P2/R1 the corpus debt equals the 31 `STAGE_GATED` IDs plus ING-006 while its
probe passes; the three conversion cases are ordinary corpus entries.
Advancing the coordinate to P3 automatically re-opens ACL-002/SRCH-009/SRCH-011,
P4 re-opens the 23, and so on — proof obligations arrive with the phase that
makes them possible; there are no silent exemptions. The recognized file will
be self-policing once the checker implementation lands: false recognition fails
structural validation, recognition plus corpus fails the redundancy rule,
stage-gating an ID with seated product enforcement fails the admissibility
rule, and a broken, missing or unpinned dual-layer probe re-opens debt.

**Implementation debt (registered in `docs/DELIVERY_STATE.md`).** Two gate
halves of this ADR are not yet implemented: (a) the checker-side recognition
validation and suppression, and (b) the runner-side probe execution in CI.
Until they land, the 32 recognized IDs keep failing the checker with the
corpus-debt error and the probe is a pinned, parameterized executable proven
locally on real PostgreSQL but not yet executed by any CI step. This ADR
cannot be accepted without accepting this debt; closing it is a separate,
registered piece of work, not a silent part of another milestone.
