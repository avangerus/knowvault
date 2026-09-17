# Ownership of parsers and anchors 1.0

Status: `ACCEPTED`. Tika is not considered a universal proof parser. The format becomes production-ready only after the exact anchor resolver contract suite.

## 1. Ownership matrix

| Format | Owner extraction/resolver | Canonical anchor |
|---|---|---|
| TXT, Markdown, source code | Go line parser | `TEXT` line range |
| CSV | Go `encoding/csv`, headers preserved | `TEXT` line range |
| JSON | Go strict `encoding/json/jsontext` | `TEXT` line range |
| XML | Go `encoding/xml` streaming, DTD/entity/directive deny | `TEXT` line range |
| HTML file | pinned `golang.org/x/net/html` adapter | `TEXT` line range |
| Site HTML | same HTML tree adapter + canonical URL | `HTML` DOM/text range |
| EML / mail MIME | Go `net/mail`, `mime`, `multipart` | `EMAIL` message/MIME part/range |
| DOCX | Isolated document-parser worker (Apache POI, ADR-0062) | `DOCX` section/paragraph/range |
| PPTX | Isolated document-parser worker (Apache POI, ADR-0062) | `PPTX` slide/shape/range |
| XLSX | Isolated document-parser worker (Apache POI, ADR-0062) | `XLSX` sheet/cell/range |
| Text PDF | Isolated document-parser worker (Apache PDFBox, ADR-0062) | `PDF` page/range + geometry |
| Scanned PDF, PNG, JPEG | Isolated OCR worker (Tesseract + tessdata, ADR-0063) | `OCR` page/token boxes |

An isolated worker owns **only parser observation** — which parts are open, which structure was observed, and what **raw** text was read from each structural node. It does not own canonicalization: normalization, canonical bytes, canonical object text, text/anchor hashes, derived paragraph ID, byte ranges, and source-anchor bytes belong exclusively to `internal/source/canon` and are computed by Go-runtime from raw text (ADR-0062 §2b1). The worker cannot return hash, offset, range, normalization version, or ready anchor — such fields are absent from the protocol. Therefore, correctness does not depend on the matching of worker and Go Unicode tables: a worker with a different Unicode version cannot create an otherwise canonicalized Evidence set. Cross-language canonicalization fixtures remain a detector of worker drift, not a basis for correctness.

Exact `golang.org/x/net` version/checksum/license lock blocks HTML implementation until Stage 2. Office/PDF/OCR belong to isolated data-plane workers (ADR-0062 document-parser worker on Apache POI/PDFBox; ADR-0063 OCR worker on Tesseract), which replaced Tika/PaddleOCR gate entries; their exact worker images, POI/PDFBox/Tesseract artifacts, parser/OCR profiles, tessdata model and artifact hashes are STAGE_2 release blockers in `versions.json` (deferred to per-slice qualification). Tika is not used as an abstraction layer — structural anchors are taken directly from POI/PDFBox. Stdlib ownership does not permit an unbound external helper.

## 2. General parser result

Below is described the **result Go-runtime** — what binds to SourceVersion and is published. For formats with an isolated worker (Office/PDF/OCR), the worker supplies only the observation (structural locator + raw text), while the canonical text and exact anchor bytes are computed by Go. `evidence_text_hash` and organization-scoped keyed `anchor_hash` materialize only at the ingestion persistence boundary; no hash projection is accepted from the wire.

Parser returns a versioned typed result:

```text
source_version_id
canonical_format
parser_profile_hash
canonical_object_text
evidence[]
  ordinal
  canonical_text
  evidence_text_hash
  exact anchor
  anchor_hash
  structural parent IDs
warnings[]
```

`canonical_format` equals one of `TEXT|PDF|DOCX|PPTX|XLSX|EMAIL|HTML|OCR`, is part of the immutable SourceExtraction profile hash and selects the exact resolver. For source-code extensions, trusted determination uses a separate parser profile `source-code-v1` while preserving canonical `TEXT` bytes and line-range anchor; this is a provenance class, not a filename, and it is passed to the Evidence authority. MIME/media sniffing must confirm the admissibility of the parser profile during extraction, but MIME itself does not select the terminal anchor.

New TXT/Markdown/source-code/CSV/JSON/XML/HTML-file extractions add the suffix `-layout-v2` to the parser-profile revision, preserving the structural format revision and `text-v1`. They write encrypted per-fragment layout according to `CANONICALIZATION.md` §2.1, so that full reading preserves LF between fragments and at the end of the document. This creates a new extraction even with the same source bytes; old immutable fragments/addresses are retained within the retention scope. EML/Office/PDF/OCR do not transition to this TEXT-stream contract.

The terminal resolver must reopen the persisted parser structure and prove:

- structural node exists;
- range/line/cell/page/shape/MIME part is allowed;
- exact cited excerpt is the canonical slice of this node;
- anchor hash and Evidence hash match;
- parser/OCR artifact/profile is the same as SourceExtraction.

If exact anchor construction or permission is not possible, object receives `EXTRACTION_FAILED`/`QUARANTINED` and does not become citeable/queryable. Fallback to the link "entire file", guessed page, nearest paragraph, or search chunk is prohibited.

## 3. OOXML

DOCX/PPTX/XLSX are ZIP packages, but are not processed as a user-provided arbitrary archive. The Go parser opens only allowlisted OOXML parts and relationships:

- limits for compressed bytes, decoded bytes, entry count, per-entry bytes, nesting, and ratio;
- path traversal and duplicate normalized entry are prohibited;
- external relationship, attached package, OLE, macro/VBA, and custom executable part are not loaded and not executed;
- XML DTD, external/parameter entity, and XInclude are prohibited;
- DOCX paragraph ID is native or a deterministic derived ID based on `CANONICALIZATION.md`;
- PPTX shape ID is taken from the exact slide shape tree and is not replaced by visual order;
- XLSX shared strings/styles/cell references are resolved deterministically; formula is preserved as text and cached value, but never computed;
- hidden sheet/row/cell status is preserved in metadata and the policy profile decides indexing; it is not hidden by the parser on its own.

## 4. PDF and OCR

Pinned PDF sidecar profile must contract-test prove page boundaries, canonical page text order, and offsets on a synthetic PDF corpus. Optional bounding boxes are verified in the PDF coordinate contract. If the sidecar cannot reproduce the page/range after restart/version lock, Extraction is not activated.

OCR preserves the immutable token list:

```text
page
token_id
canonical token text
bounding box 0..1 top-left
reading-order ordinal
join_after = NONE | SPACE | LINE_BREAK
confidence
```

Evidence OCR anchor exact-match contains `token_start_ordinal` and `token_end_ordinal` as a 0-based half-open range within an immutable token list of a single page. The semantic resolver checks `end > start`, ordinal continuity, exact equality of `len(bounding_boxes) == end - start`, and the box of each token in the same order. Canonical evidence text is constructed as `canonical token text` plus a separator, defined by `join_after`, only between selected tokens; `join_after` of the last selected token is not included. `SPACE` provides one U+0020, `LINE_BREAK` — one LF, `NONE` — an empty string. The result must exact-match `evidence_text_hash`. Geometry without token/text binding is invalid. The new OCR profile/model/artifact hash is included in SourceExtraction. A new OCR profile creates a new Extraction, it does not overwrite the old one.

## 5. HTML, XML and EML

- HTML scripts/styles/forms/active content are removed before canonical text; URLs are not loaded by the parser.
- Site DOM path is built from the parsed tree using deterministic sibling ordinals, not from the browser-mutated DOM.
- XML directive/DTD/entity/XInclude results in quarantine; network/file resolver is absent.
- EML Message-ID is not considered a globally reliable object ID. Provider mail uses provider immutable ID; file EML anchor uses deterministic `source-object:<source_object_id>`. MIME part path is built from the exact parsed multipart tree.
- Remote images, external body references, and nested message attachments are not loaded. Nested `message/rfc822` is either a separate bounded attachment object or is not indexed according to the profile.

## 6. Regression gate

Any change to parser, worker image, POI/PDFBox/Tesseract artifact, tessdata model, deterministic renderer, normalization, OOXML rules, or HTML dependency:

1. creates a new parser profile revision;
2. runs the golden corpus of all promised anchors;
3. does not change historical Extraction;
4. builds a new staged Extraction/evidence set;
5. activates only after 100% anchor resolution on the accepted corpus;
6. passes the license/SBOM gate.
