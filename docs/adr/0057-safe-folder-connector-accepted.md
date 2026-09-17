# ADR-0057: Safe folder connector (containment, bounded stable read, transient-content boundary)

Status: accepted.

Implements the P2/I1/S1c slice: the local/SMB folder connector that a durable
`SOURCE_SCOPE_SYNC` worker will drive. It introduces a typed semantic owner,
`internal/connector/folder`, and nothing else — no migration, no new dependency,
no new runtime component, no new source identity or scope model. It composes
with the already-accepted control plane (ADR-0045 shared scope-glob grammar,
ADR-0047/0048 source connection/scope draft, ADR-0056 durable job substrate) and
does not reopen any of it.

## Scope of the connector

The connector can do exactly three things: discover objects inside an exact
trusted scope, read one bounded stable snapshot of an object, and report a
diagnosable quarantine or failure. It never creates a `SourceObject`,
`SourceVersion`, `SourceExtraction` or `EvidenceFragment`, never mints a durable
identity, and never persists source bytes. Its input is a trusted, already
authorized `Scope` assembled by server-side configuration from an activated
`SourceScopeRevision` (the pre-mounted connection root, the signed platform
semantics, and the decrypted `folderConfig`); it is never assembled from a
connector event or an end-user request, and the connector cannot widen it.

The connector supports only `WORKSPACE_MANAGED`. This build implements no
item-level ACL, so a `SOURCE_ENFORCED` scope is refused at construction — the
matching fail-closed to the database capability gate that already blocks such a
scope upstream (`SOURCE_ENFORCED requires stable IDs, item ACL and ACL refresh`).
`S3_COMPATIBLE` is a distinct object transport with its own conditional-read
connector and is not a platform value here.

## Three load-bearing controls, each enforced by construction

1. **Filesystem containment (SRC-007).** Every open is resolved against a pinned
   root handle (`os.Root` via `os.OpenRoot`), which is traversal- and
   reparse-resistant on both POSIX and Windows. The root itself is re-checked for
   a TOCTOU swap (`os.Lstat` + `os.SameFile` before use, the webui asset idiom).
   Each entry is `Lstat`'d and a POSIX symlink or Windows reparse point/junction
   is quarantined `FOLDER_SYMLINK_REJECTED` and never followed; a device, socket
   or pipe is `FOLDER_NON_REGULAR`. A read additionally re-checks every ancestor
   path component with `Lstat`, so an in-root symlink (one `os.Root` would follow
   because it stays inside the root) cannot redirect a read out of the scope's
   `relative_root` or return content under a mislabelled identity. Traversal, empty/`.`/`..` segments, absolute
   and UNC substitution, backslashes and Windows special namespaces
   (`CON`/`NUL`/... , ADS colon, trailing dot/space) are rejected before any
   open. `follow_symlinks` is not a field because the connector never follows a
   link.

2. **Bounded stable read (SRC-012).** Size and media signature are checked before
   any bytes are handed forward. The read is bounded by the scope byte cap (read
   at most cap+1 so an object that grows past the cap is caught, not truncated).
   The same open descriptor is stat'd before and after the read; a mismatch in
   identity, size or mtime, or a byte count that disagrees with the pre-read
   size, is a `TORN_READ_VERSION_MISMATCH` quarantine, never a trusted result. A
   second independent read from a fresh descriptor must reproduce the same
   identity, size and content hash, closing the same-size in-place-rewrite window
   that coarse SMB/FAT mtime granularity could otherwise hide.
   Media family is classified from a bounded signature window (not the
   extension); an executable/unknown signature is `FOLDER_UNSUPPORTED_TYPE`, a
   family outside the scope allowlist is `FOLDER_MEDIA_SIGNATURE_MISMATCH`, and a
   text object with invalid UTF-8 past the window is `FOLDER_INVALID_UTF8`. The
   connector never executes source content. Signature gating is at family
   granularity only (every text subtype resolves to one text family, every OOXML
   container to one family); the connector never disambiguates DOCX/PPTX/XLSX and
   returns a coarse non-authoritative `MediaFamily`, never a `canonical_format`.
   Exact-format enforcement — rejecting an object whose resolved `canonical_format`
   is outside the scope `formats[]` — is an S1d parser obligation, listed below.

3. **Transient-content boundary (ING-006, SRC-002).** The connector returns
   bounded bytes to the next in-process extraction boundary but persists them
   nowhere. It holds no capability to do so: it imports only the standard
   library, the shared `scopeglob` grammar and text normalization. It cannot
   reach PostgreSQL, the catalog, evidence, search, the job substrate, audit or
   the model gateway. A `SOURCE_SCOPE_SYNC` job that drives it carries only a
   content-free reference payload (source bytes cannot even be encoded into a job
   payload), so the canary content of a read never appears in any durable sink.

## Diagnostics

Every hard failure and every quarantine has a content-free code safe for
structured logs and metrics; the `Error` type and the `Scope`/`Matcher` values
redact themselves. Source-native paths are sensitive and are carried only inside
the typed in-process result, never in a code and never in open telemetry.

## Enforcement (three layers)

- **Semantic owner:** the typed `internal/connector/folder` package, whose
  private fields prevent a caller from widening a validated scope or substituting
  another matcher.
- **Independent OS/package containment:** `os.Root` for the operating system,
  and the architecture checker's `checkFolderConnectorBoundary` import gate that
  enforces a closed allowlist — only the standard library, `scopeglob` and
  `x/text` — so any database/catalog/evidence/search/jobs/audit/model capability,
  or even stdlib logging that could exfiltrate bytes or a source path, is refused;
  plus the shared-grammar ban (ADR-0045) already covering `internal/connector`.
- **Negative/mutation proof:** real-filesystem acceptance tests on POSIX and
  Windows semantics (`tests/integration/postgres/folder_connector_test.go`) that
  redden if containment, the stable read or the transient-content boundary is
  weakened, plus checker self-tests
  (`architecture.connector.folder-database-capability`,
  `architecture.connector.folder-root-handle`,
  `architecture.connector.folder-stable-read`) that redden if the source drops a
  control or gains a forbidden import.

## Deferred to later slices

Resolving a `SourceScopeRevision` into a `Scope` (decrypting the scope-config
artifact, binding the connection root/platform), emitting signed connector
events, and creating `SourceObject`/`SourceVersion`/`SourceExtraction`/
`EvidenceFragment` are S1d and are deliberately out of this connector. Exact
per-format enforcement — the parser rejecting an object whose resolved
`canonical_format` falls outside the scope `formats[]` — is an S1d parser
obligation; this connector gates only at signature-family granularity. The
`-race` proof on a pinned Linux host remains an outstanding P2 phase-gate debt
(as for S1a/S1b): this host cannot run `-race` (CGO disabled), and the connector
acceptance tests use no shared mutable Go state.
