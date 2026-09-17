# ADR-0063: Isolated Tesseract OCR worker — PNG/JPEG/scanned PDF (P2/I2/S2d)

Status: accepted.

Records the owner's dependency-gate decision that closes the P2/I2
`DEPENDENCY_GATE` for OCR, replacing the STAGE_2 `oci.paddleocr` /
`model.paddleocr` gate. It composes with the accepted I1 path (ADR-0058),
lifecycle (ADR-0059), cutover (ADR-0061), the S2a extractor (ADR-0060) and the
document-parser worker (ADR-0062, which owns the deterministic PDF render feeding
scanned-PDF OCR), and reopens none of them. It adds no application runtime,
database, queue, source type, chat/agent/MCP, or write action. The OCR worker is a
data-plane component, not a KnowVault service.

Normative refs: `docs/PARSER_CONTRACTS.md` (§1 ownership matrix, §2
terminal-resolver + no-fallback, §4 PDF+OCR token contract, §6 regression gate),
`docs/SOURCE_CONTRACTS.md`, `docs/TRUST_BOUNDARY.md`, `docs/CANONICALIZATION.md`,
`architecture/versions.json`, `architecture/licenses.yaml`, and `POKA_YOKE.md`
families PAR/ING/EVD/SRC/IMM. The OCR token/box binding is a numeric-validator-v1
adjacent contract (`docs/NUMERIC_VALIDATION.md`).

## 1. Owner decision (context)

The Block D dossier (`docs/dependency-dossier-paddleocr.md`) found PaddleOCR
runtime-permissive but **capability-as-specified NO-GO for 1.0**: PaddleOCR emits
**per-text-line boxes, not per-token boxes**, so the mandatory immutable
token→box 1:1 list (PARSER_CONTRACTS §4) would require uncertifiable
post-processing; arm64 is unsupported/broken; and the PP-OCRv5 weight license is
declared only via Hugging Face cardData, not a per-weight LICENSE file.

**Owner decision:** PaddleOCR is **NO-GO for 1.0** until it provides a verifiable
1:1 canonical-OCR-token → bounding-box mapping. The primary selected candidate is
a **separate, isolated Tesseract OCR worker** — engine and `tessdata` are
Apache-2.0 at the LICENSE-file level, offline, CPU-only, amd64 **and** arm64, with
native word/character boxes.

## 2. Normative meaning of "OCR token"

An **OCR token is an element of the canonical OCR token stream — not an LLM
token.** This is fixed here to prevent any later conflation. Each element **must**
carry: page/image identity; a stable ordinal; exact normalized text; a bounding
rectangle/polygon; confidence metadata; and immutable profile/model identity. A
citation is permitted **only** for a contiguous range of such tokens
(PARSER_CONTRACTS §4: `token_start_ordinal`/`token_end_ordinal`, 0-based
half-open, `join_after ∈ {NONE,SPACE,LINE_BREAK}`, `len(boxes) == end - start`,
ordinal continuity, `end > start`). Geometry without token/text binding is invalid.

## 3. Decision — the OCR worker is a hostile data-plane component

The OCR worker carries the identical boundary set as ADR-0062 §2, enforced by
construction with negative/mutation proofs (not naming/string scans):

- **(a) Parser sandbox:** no PostgreSQL, tenant/workspace authority, source
  credentials, network, persistent storage, or audit/outbox/job authority;
  executed `--network none`, read-only root fs, wiped tmpfs scratch, non-root,
  `no-new-privileges`, with CPU/RAM/wall-clock/input/output caps.
- **(b) Protocol boundary:** invoked per-object with one transient image (or one
  deterministically rendered page) + a minimal typed request (media family,
  limits, requested OCR `parser_profile_revision`/model identity) — no
  tenant/scope/version id, no credentials, no database id. Returns a closed
  versioned result (`ocr-result-v1`, JSON Schema authored with the S2d slice)
  carrying only the immutable token list + warnings + profile/model identity. It
  cannot return database ids, lifecycle state, queryability, scope, or a current
  pointer.
- **(c) Publication boundary:** the token list is not queryable by itself; only the
  Go ingestion runtime binds it to the exact SourceVersion/content
  hash/profile+model identity and atomically publishes the Evidence set. The Go
  terminal resolver re-opens the immutable token list and re-proves the OCR-anchor
  invariants of §2 before any citation is allowed.
- **(d) Transient-content boundary:** source image, rendered pages, and worker temp
  files are destroyed after the operation and never reach PostgreSQL, object
  storage, jobs, outbox, audit, logs, crash dumps, or diagnostics; failures return
  a content-free typed code only.
- **(e) Resource boundary:** image/decompression/OCR bombs are bounded
  independently in connector, worker, and ingestion runtime; refusal is a per-object
  quarantine, never a scope-sync failure.
- **(f) Supply-chain boundary:** the OCR worker image, the Tesseract engine, and
  each `tessdata` model are distinct capabilities with their own exact locks;
  replacing the engine or a model mints a **new OCR `parser_profile_revision` +
  model identity and a new immutable Extraction**, never rewriting an old one
  (PARSER_CONTRACTS §4/§6, IMM).
- **(g) Cross-format isolation:** OCR is not a fallback for text extraction and
  vice-versa; a media/parser mismatch quarantines (§5).

## 4. Scanned PDF: deterministic render → OCR

A scanned PDF (classified per ADR-0062 §5) passes a **deterministic render → OCR**
pipeline: each page is rasterized by a pinned deterministic renderer, then OCR'd.
Both the **renderer profile and the OCR profile/model are part of the OCR
extraction identity** — a change to either mints a new immutable Extraction. The
renderer is a pinned, byte-deterministic rasterizer whose identity is recorded in
the profile; it is an OCR-profile concern, not a general PDF-parser fallback (a
scanned PDF never silently falls back to text extraction, and a text PDF never
silently falls back to OCR).

## 5. Fail-closed classes (quarantine, no fallback)

An unsupported/corrupt image, a media-signature mismatch, a decode/decompression
bomb, a render failure, or an OCR result that cannot satisfy the §2 token/box
binding (missing box, count mismatch, non-monotonic ordinal) is a **per-object
quarantine with no fallback** — no whole-image citation, no boxless text, no
"nearest region." Every such input is per-object, never a sync-run failure. The
scanned-PDF path additionally quarantines on a render/OCR determinism mismatch on
re-run.

## 6. Supply-chain activation gate

`architecture/versions.json` STAGE_2 deferred locks replace `oci.paddleocr` /
`model.paddleocr` with `oci.tesseract-ocr-worker` (OCI_IMAGE) and `model.tessdata`
(MODEL_ARTIFACT); the deterministic renderer reuses the ADR-0062 worker's pinned
PDFBox (or an explicitly locked rasterizer recorded at qualification). These stay
**deferred (gate) entries, not ACTIVE.** Before production activation each must be
proven and recorded (no fabricated digest/CVE/hash): exact version + immutable
digest (image) and exact revision + weight hash + license text + AIBOM entry
(`tessdata` model); full transitive SBOM; license + NOTICE inventory (engine +
`tessdata` = Apache-2.0 at LICENSE-file level; leptonica = BSD-2-Clause; any OS
package license concluded); vulnerability review; offline build/run; non-root,
read-only-fs, network-disabled runtime; CPU/RAM/time/input/output limits;
**platform lock = `linux/amd64` only with `linux/arm64` explicitly restricted**
(owner decision 2026-07-24, aligned with ADR-0062 §6; recorded on the ACTIVE lock
as `platforms: ["linux/amd64"]` + `platform_restriction: "arm64 deferred"` even
though Tesseract itself supports arm64 — the whole worker fleet is amd64-locked for
1.0); deterministic-rebuild evidence; upgrade/rollback procedure.
The gate is not turned ACTIVE artificially; it flips only when the S2d
qualification lands with this evidence.

## 7. Consequences

- **Supersedes** the PARSER_CONTRACTS §1 row that assigned scanned PDF/PNG/JPEG to
  "PaddleOCR token map" and the §4 "PaddleOCR" naming: the owner selects an
  isolated Tesseract OCR worker. §4's token/box contract is **unchanged** and now
  binds the Tesseract worker's Go re-validator; only the engine/model name changes.
- The `oci.paddleocr` / `model.paddleocr` STAGE_2 locks and the `paddleocr`
  leak-scan pattern are retired in `versions.json`, `check-architecture.go`, and
  `licenses.yaml` in favor of the new components; the checker's default-deny
  reconciliation is updated in lockstep.
- **Non-goals / deferred:** the `ocr-result-v1` schema, the OCR worker image, the
  Go invoker/sandbox harness, the deterministic renderer lock, the terminal OCR
  resolver, the exact digests/weight hashes/SBOM, and the synthetic image/scanned
  corpus are the S2d delivery slice — contract/test-first, real-PG + real-fs proof,
  pinned-Linux `-race`, gated behind §6.

## 8. Acceptance (of this decision record)

- The STAGE_2 dependency gate names the Tesseract OCR worker + `tessdata`
  (deferred), PaddleOCR is retired, and `check-architecture.go` reconciles the new
  closed inventory green.
- PARSER_CONTRACTS §1/§4 name the isolated Tesseract worker as the OCR owner; the
  token/box binding contract binds unchanged; "OCR token" is fixed as a canonical
  OCR-stream element (§2).
- The seven boundaries of §3 and the render→OCR identity of §4 are stated as
  enforceable contracts (each will carry a positive + deny/mutation proof when the
  OCR code lands — S2d).
- No PaddleOCR/Tesseract import, image, model, or run exists yet; activation is
  gated by §6.
