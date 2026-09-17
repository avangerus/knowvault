# ADR-0062: Isolated document-parser worker — Office (Apache POI) and text PDF (Apache PDFBox) (P2/I2/S2b–S2c)

Status: accepted.

Records the owner's dependency-gate decision that closes the P2/I2
`DEPENDENCY_GATE` for Office and text PDF, replacing the STAGE_2 `oci.apache-tika`
gate. It supersedes neither an accepted ADR nor accepted ADR history; it composes
with the accepted I1 catalog/extraction/Evidence path (ADR-0058), lifecycle
(ADR-0059) and scope-revision cutover (ADR-0061), and the S2a format-aware
extractor (ADR-0060), and reopens none of them. It does **not** add an application
runtime, database, queue, source type, chat/agent/MCP, or write action. The new
component is a data-plane parser, not a KnowVault service.

Normative refs: `docs/PARSER_CONTRACTS.md` (§1 ownership matrix, §2 parser result
+ terminal-resolver + no-fallback rule, §3 OOXML, §4 PDF, §6 regression gate),
`docs/SOURCE_CONTRACTS.md` (extension is a hint, structure is the proof; mismatch
quarantines), `docs/TRUST_BOUNDARY.md`, `docs/CANONICALIZATION.md`,
`architecture/versions.json` (STAGE_2 deferred locks), `architecture/licenses.yaml`,
and `POKA_YOKE.md` families PAR/ING/EVD/SRC/IMM.

## 1. Owner decision (context)

The Block D dossier (`docs/dependency-dossier-tika-pdfbox.md`) established that
Apache Tika is **NO-GO as the universal extraction API for 1.0**: Tika emits a
flat text/XHTML blob with only coarse structure — no OOXML element ids, no A1
cell references, no PDF page coordinates — so the platform's mandatory *exact
anchors* (PARSER_CONTRACTS §2/§3/§4) force dropping below Tika to POI/PDFBox
anyway. The dossier's proposed pure-Go stack (`excelize` + `archive/zip` +
`encoding/xml` + `ledongthuc/pdf`) was **not** adopted either: it cannot be
called a chosen solution until it independently proves, on the same adversarial
corpus, anchor accuracy, determinism and safety at least equal to POI/PDFBox.

**Owner GO:** a **separate, isolated document-parser worker** that uses
**Apache POI directly** (DOCX/PPTX/XLSX) and **Apache PDFBox directly** (text
PDF). A JVM is not forbidden merely because the primary Go images use `scratch`;
a specialized parser-worker may be a distinct, isolated data-plane component.
**Tika is not used as an abstraction layer** — structural anchors are taken
directly from POI/PDFBox. A pure-Go stack may replace POI/PDFBox later only after
it proves ≥ accuracy/determinism/safety on the same corpus; dependency-graph
simplicity does not outweigh evidential accuracy.

## 2. Decision — the worker is a hostile data-plane component

The document-parser worker is treated as a **hostile data-plane component**
(POKA_YOKE parser-sandbox). Every boundary below is enforced by construction and
proven by a negative/mutation test, not by naming or a string scan.

**(a) Parser sandbox.** The worker gets **no** PostgreSQL access, **no**
tenant/workspace authority, **no** source credentials, **no** network, **no**
persistent storage, and **no** audit/outbox/job authority. It is executed with
network disabled (`--network none`), a read-only root filesystem, a wiped
tmpfs-only scratch, a non-root uid, `no-new-privileges`, and explicit
CPU/RAM/wall-clock/input-size/output-size caps. It cannot open a socket, a durable
path, or a database handle because none is present in its capability set.

**(b) Protocol boundary.** The Go ingestion runtime invokes the worker
per-object with exactly one transient document's bytes plus a minimal typed
request (dispatched format, resource limits, expected observation profile) — and
**nothing else**: no tenant/workspace/scope id, no `source_version_id`, no
credentials, no database id. The worker returns a **closed, versioned observation
result** (`document-parser-result-v1`, JSON Schema in `architecture/contracts`)
carrying only: the format it observed, its own parser identity, ordered
**structural locators** (DOCX section path + paragraph ordinal + optional native
paragraph id; PPTX slide + shape id; XLSX sheet + single A1 cell), the bounded
**raw** Unicode text of each such node, and content-free warning codes. The worker
can **not** return database ids, lifecycle state, queryability, tenant/workspace
scope, or a current-version pointer; those keys are absent from the schema and
rejected by the Go strict decode.

**(b1) Single canonicalization owner.** The worker is a parser **observer**, never
a canonicalization authority. It cannot normalize, hash, offset, range or anchor,
because the protocol gives it no field in which to say any of those things.
`internal/source/canon` is the single owner of text-v1 normalization, canonical
bytes, the canonical object text, every text and anchor hash, the derived DOCX
paragraph identity, the Evidence byte ranges and the source-anchor JCS bytes;
`internal/source/docparser` computes all of them from `raw_text` on ingestion and
the terminal resolver recomputes them on citation. The load-bearing consequence:
**correctness does not depend on the worker's Unicode tables matching Go's.** A
worker whose Unicode version differs cannot produce a differently-canonicalized
Evidence set, because it produces no canonical bytes at all; the worst it can do
is report different *raw* text, which is a parser-observation defect that the
golden corpus detects and which fails closed (quarantine, no publication).
Cross-language canonicalization fixtures are kept as a **drift detector** for the
worker, not as the foundation of correctness. `observation_profile_revision`
versions the worker's observation semantics (which parts are opened, how a node's
text is read out, ordering) and never denotes a normalization authority; the
immutable Extraction's `parser_profile_revision` is bound by the Go runtime.

**(c) Publication boundary.** A correct parser result is **not queryable by
itself.** Only the Go ingestion runtime binds it to the exact
SourceVersion/content hash/`parser_profile_revision` and atomically publishes the
full Evidence set through the accepted `source_version_publish_extraction` path
(ADR-0058). The Go **terminal resolver** re-opens the persisted parser structure
and independently re-proves every anchor (PARSER_CONTRACTS §2): the structural
node exists, the range/cell/page/shape is admissible, the cited excerpt is the
canonical slice of that node, anchor and Evidence hashes match, and the
parser/profile identity equals the SourceExtraction. The worker's output is
evidence *to be verified*, never trusted as-published.

**(d) Transient-content boundary.** The source binary, any rendered intermediate,
and every worker temporary file are destroyed after the operation and never reach
PostgreSQL, object storage, jobs, outbox, audit, logs, crash dumps, or
diagnostics (ING/EVD content-free rule). Worker failures return a content-free
typed code only; no source bytes, text, path, or parser stack detail leave the
sandbox.

**(e) Resource boundary.** Archive, XML, PDF and image bombs are bounded
**independently** in three places — the connector (`max_file_bytes`, media gate),
the worker (POI/PDFBox open limits + the request caps in (a)), and the Go
ingestion runtime (output-size and evidence-count caps on re-validation). One
object's resource refusal is a per-object quarantine and never stops the scope
sync.

**(f) Supply-chain boundary.** The worker image, POI, and PDFBox are each a
distinct capability with its own exact lock (`architecture/versions.json`).
Replacing any version mints a **new `parser_profile_revision` and a new immutable
Extraction** — it never changes the meaning of an existing Extraction
(PARSER_CONTRACTS §6, IMM).

**(g) Cross-format isolation.** POI (Office) is not a fallback for PDFBox (PDF)
and neither is a fallback for the OCR worker (ADR-0063). A media/parser mismatch
is a quarantine — there is no "try every parser." Text-PDF vs scanned-PDF is a
**deterministic determination**, not a cascade (see §5).

## 3. Exact anchors (structure observed by the worker, anchor built by canon)

The worker supplies only the **structural position** it observed; `canon` builds the
anchor. A DOCX/PPTX Evidence unit is one structural node and its byte range is the
node's full canonical extent `[0, len(canonical text))`, **derived in Go** from the
text Go canonicalized — so a range that does not correspond to extracted text cannot
be expressed, and a worker cannot claim a wider or offset range than it produced. An
XLSX unit is one cell; the worker cannot widen it into a multi-cell A1 range. Two
units claiming the same structural position are refused. When a DOCX paragraph has no
OOXML-native id, the `derived:sha256:…` identity of `CANONICALIZATION.md` §3 is
computed by `canon` from the section path, the paragraph ordinal and the hash of the
text `canon` itself canonicalized; a worker-supplied `derived:` id is refused.

| Format | Canonical format | Anchor (built by canon from the observed structure) |
|---|---|---|
| DOCX | `DOCX` | package part + paragraph/table structural position + text range |
| PPTX | `PPTX` | slide + shape identity/order + text range |
| XLSX | `XLSX` | sheet identity + A1 cell/range |
| Text PDF | `PDF` | page + canonical text range + geometry sufficient to re-select the used text + parser/profile revision |

- **OOXML (§3 of PARSER_CONTRACTS applies unchanged):** only allowlisted parts and
  relationships are opened; path traversal / duplicate normalized entry denied;
  external relationship, attached package, OLE, macro/VBA and custom executable
  part are never loaded or executed; XML DTD / external+parameter entity /
  XInclude denied → XXE-closed. DOCX paragraph id is the POI-native id or a
  deterministic derived id per `CANONICALIZATION.md`; PPTX shape id comes from the
  exact slide shape tree, never visual order; XLSX shared strings/styles/cell refs
  resolve deterministically and a formula is stored as text + cached value but is
  **never** evaluated. Hidden sheet/row/cell status is preserved as metadata; the
  parser never silently hides it.
- **PDF:** the anchor must re-select the same text on the same page and geometry
  after restart/version lock (PARSER_CONTRACTS §4). Geometry is captured to the
  precision needed to re-highlight; if the sidecar cannot reproduce page/range,
  the Extraction is not activated.

The `canonical_format` is part of the immutable SourceExtraction profile hash and
selects the exact resolver; media sniffing confirms parser admissibility but never
by itself chooses the terminal anchor.

## 4. Fail-closed classes (quarantine, no fallback)

Macros/VBA, embedded objects/OLE, external relationships, encrypted/password
documents, zip/entity/nesting/ratio bombs, and any unsupported active content are
**fail-closed or quarantined** per this contract — never partially extracted,
never "best-effort" text. An object whose exact anchor cannot be built or
re-resolved gets `EXTRACTION_FAILED`/`QUARANTINED` and does not become
citeable/queryable. Fallback to "whole file", a guessed page, the nearest
paragraph, or a search chunk is forbidden (PARSER_CONTRACTS §2). Every such input
is a **per-object** quarantine, never a sync-run failure.

## 5. Text PDF vs scanned PDF (deterministic determination)

A PDF is classified once, deterministically: a PDF whose extractable text layer
meets the accepted profile threshold is a **text PDF** (this ADR, PDFBox, S2c). A
PDF with no/insufficient text layer is a **scanned PDF** and is handed to the OCR
worker (ADR-0063, S2d) via a deterministic render → OCR whose renderer and OCR
profiles are part of the OCR extraction identity. A PDF that is neither cleanly
text nor cleanly renderable is quarantined. The threshold and its adversarial
corpus are fixed in the S2c/S2d slices; the rule is a single deterministic
determination, not a cascade (§2g).

## 6. Supply-chain activation gate

`architecture/versions.json` STAGE_2 deferred locks are updated to reflect this
decision: the `oci.apache-tika` runtime/dependency gate is **replaced** by
`oci.document-parser-worker` (OCI_IMAGE), `maven.apache-poi` (MAVEN_ARTIFACT), and
`maven.apache-pdfbox` (MAVEN_ARTIFACT). These remain **deferred (gate) entries,
not ACTIVE** — the decision selects the components; the exact-lock qualification is
per-slice work. Per the owner supply-chain authority and `licenses.yaml`, before
**production activation** of the worker each of the following must be proven and
recorded (no fabricated digest/CVE): exact version + immutable digest; full
transitive SBOM; license + NOTICE inventory (POI, PDFBox and every transitive =
Apache-2.0 / permissive; the pinned OpenJDK base = GPL-2.0-only WITH
Classpath-exception-2.0, already conditionally allowed, scope broadened from "the
Apache Tika container" to this worker with a THIRD_PARTY_NOTICE); vulnerability
review; offline build/run; non-root, read-only-fs, network-disabled runtime;
CPU/RAM/time/input/output limits; **platform lock = `linux/amd64` only with
`linux/arm64` explicitly restricted** (owner decision 2026-07-24, permitted as an
"explicit platform restriction"; POI/PDFBox are pure-Java/architecture-neutral, so
the restriction is a property of the pinned JRE base and is recorded on the ACTIVE
lock as `platforms: ["linux/amd64"]` + `platform_restriction: "arm64 deferred"`);
deterministic-rebuild evidence; upgrade/rollback procedure. The
STAGE_2 gate is not turned "ACTIVE" artificially — it flips only when the S2b/S2c
qualification lands with this evidence, exactly as `x/net` did for S2a HTML.

## 7. Consequences

- **Supersedes** the PARSER_CONTRACTS §1 rows that assigned DOCX/PPTX/XLSX to a
  "KnowVault Go OOXML structure parser" and text PDF to a "Tika/PDFBox sidecar":
  the owner selects an isolated POI/PDFBox worker. §1/§4 are updated to name the
  worker as owner; §2/§3/§6 (result shape, OOXML safety, regression gate) are
  unchanged and now bind the worker's Go re-validator.
- The `oci.apache-tika` STAGE_2 lock and the `apache/tika` leak-scan pattern are
  retired in `versions.json`, `check-architecture.go` and `licenses.yaml` in favor
  of the new components; the checker's default-deny reconciliation is updated in
  lockstep so the closed inventory stays exact.
- **Non-goals / deferred:** the concrete `document-parser-result-v1` schema, the
  worker image + Dockerfile, the Go invoker/sandbox harness, the terminal
  resolvers, the exact digests/SBOM, and the synthetic corpus are the S2b (Office)
  and S2c (PDF) delivery slices, each contract/test-first with real-PG + real-fs
  proof and pinned-Linux `-race`, gated behind §6.

## 8. Acceptance (of this decision record)

- The STAGE_2 dependency gate names the document-parser worker + POI + PDFBox
  (deferred), Tika is retired, and `check-architecture.go` reconciles the new
  closed inventory green.
- PARSER_CONTRACTS §1/§4 name the isolated worker as the Office/PDF owner with the
  exact anchors of §3; §2/§3/§6 bind unchanged.
- The seven boundaries of §2 are stated as enforceable contracts (each will carry
  a positive + deny/mutation proof when the parser code lands — S2b/S2c).
- No POI/PDFBox/worker import, image, or run exists yet; activation is gated by §6.
