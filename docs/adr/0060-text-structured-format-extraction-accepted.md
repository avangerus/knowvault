# ADR-0060: Text/structured format extraction (P2/I2/S2a)

Status: accepted.

Implements the first slice of the P2/I2 format matrix: turning the S1d single
`text-v1` extractor into a format-aware extractor for the stdlib-only text and
structured formats, so a connected `.csv`/`.json`/`.xml`/`.eml` (and the already
covered `.txt`/`.md`/source-code) file becomes correctly-validated, exactly
anchored Evidence. It composes with the accepted I1 catalog/extraction/Evidence
path (ADR-0058) and lifecycle (ADR-0059) and reopens neither. No new runtime, no
new dependency, no new source type.

Normative refs: `docs/PARSER_CONTRACTS.md` (the §1 ownership matrix, §2 parser
result + no-fallback rule, §5 HTML/XML/EML rules, §6 regression gate),
`docs/SOURCE_CONTRACTS.md` §"formats" (in particular the rule that the extension
does not choose the parser — media type is verified by signature/structure and a
mismatch quarantines), `docs/CANONICALIZATION.md`, and `POKA_YOKE.md` families
PAR/ING/EVD.

## 1. Scope of this slice (stdlib-only) vs. the dependency gate

`PARSER_CONTRACTS.md` §1 assigns owners per format. Exactly these are
implementable now with the Go standard library and no new dependency:

| Format | Owner (stdlib) | Canonical anchor |
|---|---|---|
| TXT, Markdown, source code | Go line parser (`text-v1`, already shipped in S1d) | `TEXT` line range |
| CSV | `encoding/csv`, headers preserved | `TEXT` line range |
| JSON | strict `encoding/json/v2` + `jsontext` | `TEXT` line range |
| XML | `encoding/xml` streaming, DTD/entity/directive denied | `TEXT` line range |
| EML / mail MIME | `net/mail`, `mime`, `mime/multipart` | `EMAIL` message/MIME-part/range |

**HTML file (delivered as the S2a straggler once its dependency gate closed — see §7):**

- **HTML file** needs `golang.org/x/net/html` (`PARSER_CONTRACTS.md` §1: "Exact
  `golang.org/x/net` version/checksum/license lock blocks HTML implementation
  until Stage 2"). That version-lock is now **accepted**: `golang.org/x/net v0.57.0`
  is an ACTIVE, license-evidenced, checksum-pinned dependency (BSD-3-Clause,
  zero new transitive modules — only the stdlib-only `x/net/html` + `html/atom`
  import subset; `html/charset` deliberately unused). HTML resolves to a `TEXT`
  line range like the other text formats; the delivered extractor and its safety
  boundary are specified in §7. It is not part of the initial S2a sub-slices (1–4)
  and its canonical text is produced by a dedicated parser, not the byte-level
  `Validate`, so it is called out separately here.

**Blocked on the owner dependency gate (NOT in this slice):**

- **DOCX/PPTX/XLSX (S2b), text PDF (S2c), scanned PDF/PNG/JPEG OCR (S2d)** need the
  gated OCI images `oci.apache-tika` / `oci.paddleocr` and `model.paddleocr`,
  which are STAGE_2 **gate** entries in `architecture/versions.json`, not accepted
  exact-digest+license entries. Per the versions.json lock rule ("No component may
  start … Selection requires an accepted version-lock change and license
  evidence") and IMPLEMENTATION_PLAN.md, format/provider implementation cannot
  begin until an owner replaces the gate with accepted exact entries. This is a
  **stop condition**, not something this executor may resolve.

## 2. Format determination (extension is a hint, structure is the proof)

The connector classifies only a coarse media family (`TEXT` for every format
above). The specific format is resolved at extraction:

1. The candidate format is derived from the object's canonical extension and
   **must** be in the scope revision's `formats[]` allowlist (already carried in
   the decrypted `scope_config`; this slice plumbs the allowlist into the resolved
   scope). An extension outside the allowlist, or none, quarantines.
2. The candidate parser then **structurally validates** the bytes: JSON must parse
   strictly, XML must parse with DTD/entities/directives denied, CSV must parse
   with a consistent field shape, EML must parse as a MIME message. A structural
   mismatch (extension says one thing, bytes are not that) quarantines
   (`SOURCE_CONTRACTS.md`: "extension does not define parser … mismatch goes to
   quarantine"). There is no fallback to "whole file", plain-text, nearest
   paragraph or search chunk (`PARSER_CONTRACTS.md` §2).

Only after a clean structural validation is the canonical text produced and
segmented into `TEXT` line-range Evidence exactly as `text-v1` does; the object's
`source_extraction.canonical_format` stays `TEXT` (all of these resolve to the
TEXT anchor), and the **`parser_profile_revision`** distinguishes them
(`text-v1`, `csv-v1`, `json-v1`, `xml-v1`), so each format is an immutable,
independently-revisable Extraction profile and a new profile forces a new
Extraction (`PARSER_CONTRACTS.md` §6). EML resolves to the `EMAIL` canonical
format and its message/MIME-part anchor, a distinct resolver added in this slice.

## 3. Security-load-bearing validation

- **XML**: `encoding/xml` is configured to reject DTDs, internal/external/
  parameter entities, and processing directives, and performs no network/file
  resolution — closing XXE and entity-expansion (`PARSER_CONTRACTS.md` §5).
- **JSON**: strict decoding (no duplicate keys, no trailing data) via the pinned
  `encoding/json/v2` experiment already in use for JCS.
- **CSV**: bounded, header-preserving parse; a ragged/oversized record
  quarantines rather than being silently coerced.
- **EML**: `net/mail`/`multipart` parse the exact tree; remote images, external
  body references and nested `message/rfc822` attachments are not loaded
  (`PARSER_CONTRACTS.md` §5). The file-EML anchor uses the deterministic
  `source-object:<source_object_id>` identity, never the Message-ID.

Every malformed or mismatched input is a per-object quarantine, never a sync-run
failure, so one bad file cannot block a scope.

## 4. Delivery plan (bounded sub-slices)

1. Plumb `formats[]` into the resolved scope; add extension→format determination
   with allowlist enforcement.
2. JSON + XML structural validators (the security-relevant pair) → `TEXT`
   Evidence, quarantine-on-malformed/mismatch, per-format `parser_profile_revision`.
3. CSV validator → `TEXT` Evidence.
4. EML validator + the `EMAIL` message/MIME-part anchor resolver.

Each sub-slice: contract/tests first, proven on real PostgreSQL + filesystem
(valid → correctly anchored Evidence whose anchor re-resolves; malformed →
quarantine; extension/structure mismatch → quarantine; XML DTD/entity → quarantine
with no resolution), full gate + pinned Linux `-race`, atomic commit.

## 5. Acceptance

- A valid `.json`/`.xml`/`.csv` in an allowing scope produces Evidence whose
  `TEXT` anchor re-resolves to the exact canonical slice, with a format-specific
  `parser_profile_revision`.
- A malformed input, or one whose bytes do not match its extension's format, is
  quarantined with no Evidence and no fallback.
- An XML DTD/entity/XInclude input is quarantined; no entity is expanded and no
  external resource is fetched.
- A valid `.eml` produces `EMAIL`-anchored Evidence keyed by
  `source-object:<id>`, with no remote/nested load.
- A valid `.html`/`.htm` produces `TEXT` line-range Evidence carrying the
  `html-v1` profile whose anchor re-resolves to the exact normalized visible
  text; active/embedded/hidden content and external URLs are dropped and never
  reach durable storage; a text-free or media-mismatched document is quarantined
  with no fallback (delivered — §7).
- Office, PDF and OCR remain unimplemented and explicitly gated (§1).

## 6. EML — as delivered (sub-slice 4)

The file-EML owner is `internal/source/eml` (stdlib `net/mail`, `mime`,
`mime/multipart`, `mime/quotedprintable`, `encoding/base64`, plus the
already-accepted `golang.org/x/text` for charset conversion — no new module).
`Parse` produces the ordered set of extractable text/plain body parts, each
decoded and canonicalized to `text-v1`; the pipeline byte-segments each part and
anchors every fragment as `EMAIL`.

Load-bearing decisions:

- **Anchor.** `canon.EmailAnchorBytes` emits `{kind:EMAIL, message_id, mime_part,
  text_start, text_end, offset_unit:UTF8_BYTE, range_semantics, normalization_version:text-v1}`
  (source-anchor.schema.json). `text_start`/`text_end` are UTF-8 byte offsets into
  that MIME part's canonical text; the resolver re-parses the immutable source
  bytes, re-derives the part and slices the range. `canonical_format` is `EMAIL`,
  `parser_profile_revision` is `eml-v1`.
- **Identity.** `message_id` is the deterministic `source-object:<source_object_id>`,
  never the RFC `Message-ID` header (PARSER_CONTRACTS.md §5); a missing or
  duplicate `Message-ID` header never affects SourceObject identity (that stays
  the file-locator digest) or the anchor.
- **MIME part path.** IMAP body-part numbering (RFC 3501 §6.4.5) computed from the
  actual parsed multipart tree (`1`, `2`, `1.1`, …), so the path is deterministic
  and re-derivable.
- **Selection.** Only inline `text/plain` body parts are extracted. `text/html` is
  gated (no accepted HTML parser dependency — §1); attachments (any
  `Content-Disposition: attachment`, or any non-`text/plain` media), nested
  `message/rfc822` and every other media type are never decoded or stored. A
  message with no extractable text part (HTML-only, attachment-only) is quarantined
  with no fallback (PARSER_CONTRACTS.md §2).
- **Transfer encoding / charset.** A closed transfer-encoding allowlist
  (`7bit`/`8bit`/`binary`/`quoted-printable`/`base64`); charset conversion only
  through the accepted `golang.org/x/text` IANA index (UTF-8/US-ASCII validated in
  place). An unknown encoding/charset, a decode error, or a result that is not
  valid UTF-8 quarantines. (Raw non-UTF-8 8-bit bodies are already quarantined
  upstream by the connector's whole-file UTF-8 gate; charset conversion therefore
  applies to transfer-encoded content.)
- **Bounded parse.** MIME nesting depth, part count, per-part decoded bytes and
  total decoded bytes are all bounded (`eml.DefaultLimits`); any breach quarantines
  — a nesting/part-count/size bomb cannot exhaust resources. The parser performs no
  network or filesystem access, so remote images, external references and links are
  never loaded.
- **Content-free failure.** Every malformed/mismatched/limit-breaching input is a
  per-object quarantine (a single bad `.eml` never fails the sync run), and the
  parser returns only a sentinel error — no source content in logs, jobs, audit or
  errors.

## 7. HTML — as delivered (S2a straggler, after the x/net gate closed)

The safe folder-HTML owner is `internal/source/html`. `Extract` parses the
transient bytes with the pinned `golang.org/x/net/html` tree builder (+ `html/atom`)
and produces the text-v1 canonical UTF-8 **visible text**, one logical line per
block; the pipeline (`plan` html-v1 branch) byte/line-segments it and anchors every
fragment as `TEXT`. `canonical_format` is `TEXT`, `parser_profile_revision` is
`html-v1`, so it is an independently-revisable immutable Extraction that composes
with the accepted I1 catalog/extraction/Evidence path (ADR-0058) and lifecycle
(ADR-0059) and reopens neither.

Load-bearing decisions:

- **Anchor.** The `TEXT` line-range anchor indexes the *normalized visible text*
  (not the raw HTML). The resolver re-parses the immutable source bytes, re-runs
  the identical deterministic extraction to reproduce the same canonical bytes, and
  slices the line range — proven by real-PG anchor replay.
- **Resolver dispatch (load-bearing).** Because for `html-v1` the canonical text is
  `html.Extract(source)` and **not** `canon.Canonicalize(source)` (unlike the other
  `TEXT` formats), any terminal `TEXT` resolver or re-extractor that re-derives
  canonical text from the source bytes **must dispatch on `parser_profile_revision`**
  (run `html.Extract` for `html-v1`), never on `canonical_format` alone. Selecting a
  plain-`Canonicalize` path by `canonical_format=TEXT` would mis-resolve an html-v1
  anchor. This is a required property of the future citation resolver (P4), pinned
  here and to be covered by a golden fixture when that resolver lands.
- **Active/embedded/hidden content dropped.** `script`/`style`/`head`/`template`/
  `iframe`/`frame`/`object`/`embed`/`applet`/`canvas`/`audio`/`video`/`svg`/`math`/
  `form` and interactive controls, and every element carrying the boolean `hidden`
  attribute, have their whole subtree dropped **before** any text is collected. The
  parser executes no script, evaluates no CSS, and opens no network/filesystem
  resource, so active content and external references (scripts, styles, forms, event
  handlers, frames, meta-refresh, images, links) are inert and their URLs never
  enter the canonical text (PARSER_CONTRACTS.md §5). HTML has no DTD/entity
  mechanism, so there is no XXE/entity-expansion surface.
- **Accepted hidden-content policy (fixture- and profile-hash-locked).** Text hidden
  by the `hidden` attribute or living in a dropped subtree is never extracted; text
  hidden only by CSS (`display:none`) IS extracted, because this profile evaluates
  no CSS. Preformatted (`<pre>`) whitespace is normalized like all flow content;
  `<br>` and block boundaries are the only line breaks. This one deterministic
  semantics is what lets a re-extraction reproduce identical bytes/hashes/anchors.
- **Bounded parse.** Input size, node count, nesting depth and produced-text size
  are all bounded (`html.DefaultLimits`); a nesting/node/markup bomb quarantines.
  The connector's per-scope `max_file_bytes` already caps the input upstream, so the
  tree the builder materializes is bounded before the walk applies its own limits.
- **Fail-closed, content-free.** A malformed, empty, text-free, oversized or
  media-signature-mismatched document is a per-object quarantine with **no fallback**
  to raw markup or file-level citation (PARSER_CONTRACTS.md §2), never a sync-run
  failure; the parser returns only a sentinel error — no source markup or text in
  logs, jobs, audit or errors.
- **Capability boundary (enforced).** The extractor's imports are a fixed closed
  allowlist (stdlib byte/text subset + `x/net/html`/`html/atom` + `canon`), and
  `golang.org/x/net` may be imported **only** by `internal/source/html` and only its
  `html`/`html/atom` subpackages — both enforced by `checkHTMLParserBoundary` and
  its mutation self-tests, so the module cannot grow a network (`http2`/`proxy`/
  `websocket`), SSRF or `html/charset` capability, and no other package can reach
  `x/net`.

### x/net dependency activation

`golang.org/x/net v0.57.0` moves from the STAGE_2 `deferred_dependency_locks` gate
to an ACTIVE, checksum-pinned `go_dependencies.x_net` entry, landed atomically with
this first use: exact `module_sum`/`go_mod_sum` verified against the offline module
cache, BSD-3-Clause license (identical profile to the ACTIVE `x/text`/`x/oauth2`/
`x/sync`), **zero new transitive modules** (module-graph pruning; only the
stdlib-only `x/net/html` + `html/atom` are imported, `html/charset` deliberately
avoided so no `x/text` pull), `govulncheck` clean, `go.sum` delta = exactly the two
`x/net` lines. Any divergence from this evidence returns the dependency to a blocked
state and forbids the parser.
