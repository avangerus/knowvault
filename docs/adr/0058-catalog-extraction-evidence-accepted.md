# ADR-0058: Catalog, extraction and Evidence for the folder-to-Evidence path

Status: accepted.

Implements the P2/I1/S1d slice: the first working path that turns one allowed
text file in a connected folder into versioned, exactly-anchored Evidence a
permitted user can open. It drives the S1c connector (ADR-0057) from a
`SOURCE_SCOPE_SYNC` worker built on the S1b job substrate (ADR-0056), stores
sensitive fields through the S1a encrypted-artifact runtime (ADR-0046/0055), and
creates the catalog/extraction/Evidence rows the connector deliberately does
not. It composes with the accepted control plane and does not reopen it. No
search, no Question Run, no OpenSearch, no LLM, no new source type, no new
office/PDF/OCR format — those remain later slices.

The normative model for every row and constraint below is `DATA_MODEL.md` §4–5,
`CANONICALIZATION.md` §1–3 and §7, `ENCRYPTION.md` §2, `SOURCE_CONTRACTS.md`
§1–2, `PARSER_CONTRACTS.md` §1–2, and the `POKA_YOKE.md` families SRC-006,
VER-001..008, EVD-001..006, PAR-001..003, ING-001..008, JOB-001..005, AUD-005.
This ADR records the decisions that turn that model into migration `000014` and
the domain packages; it introduces no new normative field and does not amend an
accepted ADR.

## 1. Ownership boundaries (who may write what)

The seven owners named in the slice charter map to code as follows.

- **Folder connector** (`internal/connector/folder`, unchanged) only discovers
  and reads. It writes no catalog, version, extraction or evidence row and mints
  no id. Reused exactly as ADR-0057 shipped it.
- **Sync worker** (`internal/ingestion`, new) orchestrates a `SOURCE_SCOPE_SYNC`
  job. It owns no identity or publication semantics: every write it makes is
  fenced by the exact current lease epoch, job identity, tenant, scope revision
  and retention fence, and it calls the catalog/extraction/evidence owners rather
  than writing their rows itself.
- **Catalog** (`internal/source/catalog`, new) is the sole owner of `SourceObject`
  identity, `source_object_scope` M:N membership, `SourceVersion`, version
  lifecycle and the current-version pointer.
- **Extraction** (`internal/source/extraction`, new) is the sole owner of the
  parser profile, extraction state, `evidence_set_hash` and terminal result.
- **Evidence** (`internal/source/evidence`, new) is the sole owner of immutable
  fragments and canonical anchors. Folder-specific detail exists only inside the
  canonical anchor payload and the encrypted metadata artifact.
- **Artifact boundary** (`internal/artifact`, unchanged) — sensitive source
  identities, locators, titles, Evidence text, anchors and metadata pass only
  through activated owner-bound encrypted-artifact branches (§6).
- **Publication boundary** — one catalog/extraction transaction makes a fully
  verified Evidence set current by moving `source_version_active_extraction`; the
  worker and connector never move the pointer directly (§5).

The load-bearing ownership boundary is enforced by the database, not by package
count: the worker-side write pipeline is one package (`internal/ingestion`, with
the catalog/version/extraction/Evidence responsibilities in separate files —
`pipeline.go`, `handler.go`), and the authorized read path is a distinct
`internal/source/evidence` package that runs on the application role. What makes
the ownership real is that (1) the `source_version_active_extraction` pointer and
`source_version` state move only through `SECURITY DEFINER` functions no runtime
role can bypass, (2) `encrypted_artifact` is reachable only through the per-branch
bind/read functions, and (3) grants split worker-writes from app-reads. A single
pipeline package is the accepted decomposition for S1d; the semantic owners above
remain distinct responsibilities within it.

## 2. Scope resolution and activation

The worker turns a trusted, activated `SourceScopeRevision` into an in-process
`folder.Scope` (`internal/source/scoperesolver`, new). It:

1. loads the exact immutable `source_scope_revision` and its
   `source_scope_activation` row and refuses anything not `SYNCING`/`READY`;
2. decrypts the `scope_config` artifact (branch `SourceScopeConfig`), JSON-Schema
   validates it against `source-scope.schema.json` `folderConfig`, and checks its
   `plaintext_hash` equals `scope_config_hash`;
3. decrypts the connection revision's trust-profile artifact (branch
   `SourceConnectionTrustConfig`), reads `platform` and the trusted
   `root_alias`/`root_identity`, and checks its hash equals `trust_profile_hash`;
4. resolves `root_alias`+`root_identity` to an absolute host path through a
   trusted in-process `folder mount registry` supplied at worker construction
   (the "pre-mounted root" of `SOURCE_CONTRACTS.md` §2 — never a request field,
   never a DB column, never derived from content);
5. builds `folder.ScopeParams` and calls `folder.NewScope`.

The mount registry is the honest home for the alias→path binding: an absolute
filesystem path is a deployment mount fact, not tenant data, and putting it in a
signed trust profile plus an injected registry keeps the connector's "never take
an absolute path from a request" contract (SRC-007). The folder trust-profile
plaintext is a new canonical object `source-folder-trust-v1`
`{"schema_version","platform","root_alias","root_identity"}`; it is connection
trust config, not a pinned wire contract, and is documented here rather than in
`architecture/contracts`.

Activation transitions are part of the sync flow, not a separate control plane.
`DATA_MODEL.md` §3 and `SOURCE_CONTRACTS.md` §1 state that opening the
`SYNCING/READY` transitions is the job of a subsequent accepted checkpoint (the
`000006`/`000007` draft migrations only pin `status='DRAFT'`); S1d is that
checkpoint. Migration `000014` widens `source_scope_activation.status` to the
`DRAFT→SYNCING→READY` / `→FAILED` / `→REVOKED` machine and lets
`source_scope.active_revision` be set, both only through guarded functions the
worker calls under its lease. Connection-trust verification (`DRAFT→VERIFIED`) is
opened as a monotonic transition, but it is **not** exposed as a worker-callable
function: no runtime role holds `UPDATE` on `source_connection_trust_projection`,
so trust is verified only by the control-plane/admin authority, and the worker
cannot satisfy its own trust precondition. The folder trust-profile plaintext is
a connection trust-config object (`source-folder-trust-v1`), documented here
rather than in `architecture/contracts` because it is deployment trust config,
not a signed wire contract (matching how other source types' trust profiles are
unschematized). A `SOURCE_SCOPE_SYNC` job for a scope revision with
a live `WORKSPACE_MANAGED` confirmation and `VERIFIED` connection trust moves the
activation to `SYNCING` at start and to `READY` on success; a failed terminal run
moves it to `FAILED`. This keeps invariant F ("connector event only for an
existing signed SYNCING|READY activation") true without inventing a second
activation authority.

`SOURCE_ENFORCED` stays refused end-to-end (schema gate, `folder.NewScope`, and a
new worker guard): S1d is `WORKSPACE_MANAGED` only, so `acl_snapshot` and its
owner branch are created inert in the schema and not activated (§6).

## 3. Stable identity and overlapping scopes (invariant A, SRC-006, VER-004/005)

A folder `SourceObject` is identified by its canonical FILE locator, not by a
raw path column. For a discovered object the worker computes the canonical
locator JCS of `CANONICALIZATION.md` §3.1
`{"connection_id","kind":"FILE","relative_path"}`, where `relative_path` is the
connector's `DiscoveredObject.RelativePath` (canonical, slash, NFC, relative to
the connection root). From it:

- `canonical_locator_digest = HMAC-SHA-256(digest_key_version, JCS(locator))`,
  organization-scoped, is the DB equality/uniqueness key;
- the raw locator JCS is stored only in the `canonical_locator_artifact`
  (branch `SourceObjectCanonicalLocator`);
- for a folder object the external object id **is** the canonical locator, so
  `external_object_id_digest = canonical_locator_digest` and the raw external id
  artifact (branch `SourceObjectExternalID`) holds the same locator JCS; the
  filename title is stored in the `title_artifact` (branch `SourceObjectTitle`).

`source_object` is unique on `(organization_id, connection_id,
digest_key_version, external_object_id_digest)`, so the same file discovered
through two overlapping scopes resolves to one row. Scope membership is a
separate M:N relation `source_object_scope` unique on `(organization_id,
source_object_id, source_scope_id, source_scope_revision)` with state
`ACTIVE|MOVED|REMOVED`; removing one membership never deletes a shared object
while another membership is `ACTIVE`. `SCOPE_MEMBERSHIP_REMOVED` changes only the
exact membership; only a proven `SOURCE_OBJECT_DELETED` (S1e) closes the object.

There is one normative path/pattern canonicalization, `internal/source/pathcanon`
(relative-root, separators, Unicode NFC, dot segments, Windows special names, ADS
colon, per-platform case, and the `scope-glob-v1` pattern grammar). The scope-glob
matcher (`scopeglob`, used by server-side validation and the connector), the
folder connector's read/relative-root path (`folder`), and the catalog object
identity (the pipeline re-validates every object's path through `pathcanon.Path`
before minting a durable SourceObject id) all route through it — there is no
second copy of the rules. Golden parity vectors cover every dimension, and a
cross-check proves the server matcher accepts a path exactly when `pathcanon`
does; the connector's closed import allowlist (checker) permits `pathcanon` and
still forbids anything else. This closes the ADR-0057 deferred drift: a durable
SourceObject identity is canonical by construction, not "equivalent by
convention".

## 4. Immutable versions and text extraction (invariants B, C; VER-001/002, PAR-001/003)

`SourceVersion` is created only from the connector's fully-read stable snapshot.
`content_hash` is `ReadResult.ContentSHA256` (SHA-256 of the exact transient
bytes). `external_version_key` is `hash:sha256:<hex>` (folder objects have no
native version id). Uniqueness on `(organization_id, source_object_id,
external_version_key)` makes a repeat of an identical version idempotent; a
changed file yields a new `content_hash`, a new key and exactly one new
immutable version. A torn read (`TORN_READ_VERSION_MISMATCH`) never produces a
version. `current_version_id` on `source_object` is a pointer, never the version
itself; at most one `CURRENT` version per object (partial unique).

Extraction is exact-match bound to one `SourceVersion` and one parser profile.
S1d ships only the `TEXT` canonical format (TXT, Markdown, source code) — the
`Go line parser` of `PARSER_CONTRACTS.md`. `canonical_format` is chosen by the
trusted media gate (connector `MediaFamily == TEXT`), never re-derived from a
mutable MIME. The parser:

1. runs `text-v1` canonicalization (`CANONICALIZATION.md` §1: decode UTF-8,
   strip one BOM, CRLF/CR→LF, NFC via the pinned `x/text/unicode/norm`, encode
   UTF-8) in one shared `internal/source/canontext` package;
2. segments the canonical text into contiguous, non-overlapping, gap-free line
   ranges in document order, each a fragment with a bounded byte budget;
3. emits one immutable `SourceExtraction` result; raw parser output is never
   persisted (`ENCRYPTION.md` §2 — only normalized Evidence text/metadata/anchor
   and the extraction profile/hashes are durable).

`profile_hash` is the JCS of `CANONICALIZATION.md` §7 (`canonical_format`,
extractor name/version/artifact_hash/parser_profile_revision,
`normalization_version:"text-v1"`, `ocr:null`). A partial unique
`(organization_id, source_version_id, profile_hash) WHERE status='SUCCEEDED'`
forbids two activatable successes of the same exact profile but allows a new run
after a terminal failure. `FAILED`/`QUARANTINED` extraction is never active;
re-extraction creates a new immutable result and never updates the old one
(VER-007).

## 5. Evidence, anchors, fencing and atomic publication (invariants D–G; EVD-*, VER-008, JOB-*)

Every `evidence_fragment` carries tenant, `source_version_id`, `extraction_id`
(one composite FK to the exact version+extraction), `ordinal`, encrypted
normalized text + `text_hash`, `token_count`, encrypted canonical anchor +
`anchor_hash`, encrypted safe metadata, and parser provenance. The anchor for a
text file is the `TEXT` anchor of `source-anchor.schema.json`
`{"kind":"TEXT","line_start","line_end}`. The byte range is not stored in the
anchor (the schema forbids extra fields); it is resolved deterministically:
`internal/source/canontext` owns the single line↔byte mapping used by both the
extractor (to slice the fragment text) and the resolver (to re-fetch it), so an
anchor resolves unambiguously through canonical relative-path identity, line
range, the derived UTF-8 byte range `[start,end)`, and the version content hash.
An anchor of another version, parser, path or hash is rejected; an anchor whose
`kind` is not `TEXT` for a `TEXT` extraction cannot be stored (schema + resolver
gate). Evidence cannot be stored without its owning encrypted-artifact rows (the
bind functions insert the artifact and set the owner column in one statement).

`evidence_set_hash` is the JCS array of `CANONICALIZATION.md` §7 sorted by
`ordinal`. Ordinals are a closed, gap-free, unique set per extraction, enforced
by a deferred check at terminal commit.

Fencing (invariant F, JOB-004, VER-008): the queryable-making writes are
lease-fenced at the database, and the rest are inert until they are. Each
per-object transaction first calls `app.lock_job_lease` (a `SELECT … FOR UPDATE`
on the job row that confirms the exact live epoch and holds the lock to commit),
and the extraction locks the version-retention row at its current fence via
`app.assert_version_writable`. The one write that makes Evidence queryable — the
active-extraction pointer move **and** the current-version cutover (supersede the
prior current, make this version current, flip object queryability) — happens
only inside the `SECURITY DEFINER` `app.source_version_publish_extraction`, which
re-checks the lease first; the worker holds no `UPDATE` on `source_version`, so it
cannot flip a version to `CURRENT` out of band, and `source_version` state is
forward-only by trigger. A stale worker's object/version/extraction/Evidence rows,
if any commit, are never current and never active, so they are not queryable: an
expired worker can neither publish nor resurrect. This reuses the ADR-0056 lease
compare-and-set and adds a version-retention CAS.

Atomic publication (invariant G): `source_version_active_extraction` may point
only at a `SUCCEEDED` extraction of the same version whose full Evidence set is
stored, ordinal set closed, `evidence_set_hash` recomputed, every artifact
owner-bound, ACL/access state permitting, and lease/fence still current. The
pointer move is one transaction; a crash between any two stages leaves either the
prior active set or a fully new one, never a half-queryable state. Re-extraction
of the same version publishes a new immutable extraction and atomically switches
the pointer without mutating old fragments.

`source_version_retention` and `source_extraction_retention` are created
`ACTIVE/queryable` with the version. S1d does not purge (that is S1e), but the
fence columns and the CAS are present so a later purge is not made impossible.

## 6. Owner-branch activations (invariant E)

S1d activates exactly the branches the text path uses, each with owning relation,
exact owner binding, same-transaction persistence via a `SECURITY DEFINER`
bind/read pair, DB containment and a negative/mutation proof:

- `source_object`: `SourceObjectCanonicalLocator`, `SourceObjectExternalID`,
  `SourceObjectTitle`;
- `evidence_fragment`: `EvidenceNormalizedText`, `EvidenceAnchor`,
  `EvidenceMetadata`.

`acl_snapshot.principal_tokens` stays inert: S1d is `WORKSPACE_MANAGED` only and
needs no source-native ACL token set. All other branches of the 26-way registry
remain inert. No new branch is added to the registry, AAD schema, SQL owner
validator or `ENCRYPTION.md`; the parity gate keeps the inventory frozen.

Because the architecture checker forbids the literal strings `encrypted_artifact`
/ `outbox_event` in `internal/**` and `cmd/**` Go, the domain packages reference
only the `app.*_bind_*` / `app.*_read_*` function names; the table stays hidden
behind them.

## 7. Authorization and transient content (invariants H, I; ING-006, AUD-003)

The Evidence viewer (`internal/source/evidence` read path) derives
tenant/workspace/principal only from a trusted `AccessContext`, confirms
workspace membership, an enabled binding of the current `WorkspaceRevision`, an
`ACTIVE` `source_object_scope` of the exact scope revision, a current
`SourceVersion` + version retention `ACTIVE/queryable` + active extraction +
extraction retention `ACTIVE/queryable`, and — for `WORKSPACE_MANAGED` — a live
confirmation. Only then does it `Fetch`/`Open` the Evidence text through the
owner-bound branch. `OrgAdmin` or knowledge of an Evidence id grants nothing;
an unauthorized viewer and `ACL_UNKNOWN` fail closed with no existence oracle
(the read returns the same not-found for cross-tenant, missing and unauthorized).

Source bytes and raw extraction output never touch PostgreSQL, job/outbox
payload, audit, logs, dead letter or backup. The connector holds bytes only
in-process; the extractor normalizes in memory and persists only encrypted
normalized Evidence. Job payloads carry only the safe `source_scope_id`
reference (and fences), never a path or content. Audit and diagnostics carry
only safe ids, status and content-free error codes. A durable-storage/backup/log
scan for a planted canary finds nothing.

## 8. Audit (AUD-005)

Every security-significant S1d state change appends a content-free audit event
inside the same `database.Write` as the change (AUD-005), through
`audit.Store.AppendInTransaction`. All are `SYSTEM`-actor events whose metadata
carries only safe ids (the sync run and the job that caused the change) — never a
path, title, locator or Evidence text, verified by a canary-absence test:

- per object, in its fenced transaction: `source.object_ingested` (on the new
  SourceObject), `source.version_created` (on the new SourceVersion) and
  `source.extraction_activated` (on the published Extraction);
- per sync, in the publication transaction: `source.scope_changed`.

The three new actions are added to the closed action registry in
`internal/audit`; they reuse the existing `SOURCE_OBJECT` resource type with the
exact object/version/extraction id as the `resource_id`, so no new
`resource_type` is introduced and the frozen `audit-event.schema.json` enum is
unchanged. The worker gets the same append-only audit privileges the app role
has (INSERT on the log, no UPDATE/DELETE; the chain-head grants the trigger
needs), and a failure to append fails the whole transaction closed
(`INGEST_AUDIT_UNAVAILABLE`) — there is no publication without its audit.

Per-view (read) access logging (`source.evidence_viewed`) is deferred: it is
access-logging, not the AUD-005 state-change invariant, and is not on the S1d
critical path.

## 9. What S1d deliberately does not do

No OpenSearch, embeddings, search UI, Question Run, LLM, office/PDF/OCR,
Git/Site/Mail, or production remote Connector Agent. Full delete / reconciliation
/ purge qualification is S1e; S1d schema and state machines keep it possible
(retention aggregates and fences exist) but do not implement it.

## 10. Head coverage parity after historical pinning

Three source control-plane suites were re-pinned to migration `000013`
(`resetPreCatalogDatabase`) because S1d opens transitions they were written to
forbid. Each keeps proving the pre-S1d contract (and that a deployment stopped
mid-upgrade at `000013` is safe), and each has an equal-or-stronger head test for
the changed invariant — no privilege, RLS, lifecycle or authority check
disappears under historical compatibility.

| Historical invariant (proved at 000013) | Why the historical test is kept | Head test proving current semantics |
|---|---|---|
| `TestSourceConnectionRevisionAndTrustAreImmutable`: trust projection is immutable, DRAFT-only | proves the pre-S1d control plane refused any trust transition; a 000013 deployment stays safe | `TestS1dHeadControlPlaneTransitions/trust projection opens DRAFT to VERIFIED` (DRAFT→VERIFIED opened, but monotonic: reversal and post-terminal transitions rejected) + `TestS1dFencingAndIsolation/worker cannot verify connection trust` (no runtime role may perform it) |
| `TestSourceConnectionCheckpointRejectsAuthorityAndUnsafeReferences/ready_projection`: a VERIFIED projection is rejected | proves VERIFIED was refused before this checkpoint | same head trust-transition test: VERIFIED is now a valid state reached only monotonically, and the connection revision it belongs to stays immutable (`…/connection and scope revisions stay immutable at head`) |
| `TestSourceScopeRowsAreImmutable`: scope + activation rows are immutable | proves the pre-S1d activation projection was inert | `TestS1dHeadControlPlaneTransitions/scope activation opens only its exact edges` (DRAFT→SYNCING opened, non-edges rejected) + the full `TestS1dFolderToEvidence` path (begin_sync/publish_ready drive the machine), while `source_scope_revision` stays immutable at head |

The privilege and fencing invariants that S1d adds are proved fresh at head:
worker cannot `UPDATE` `source_version` (state forward-only, cutover fenced),
worker cannot mutate the trust projection, stale-lease writes nothing, and RLS is
forced on every new tenant table.

## 11. Acceptance

The 18 acceptance checks of the slice charter are proven on a real filesystem and
PostgreSQL 18.4 with primary semantic enforcement, independent PostgreSQL
containment, negative/mutation proof, concurrency/failure-injection proof, and a
real end-to-end test (folder → version → extraction → Evidence → anchor
re-resolution → authorized read), not only isolated repository tests.
