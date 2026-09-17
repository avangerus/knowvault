# ADR-0059: Source lifecycle — reconciliation, deletion, retention/purge and the read-time disclosure gate

Status: accepted.

Implements the P2/I1/S1e slice: the lifecycle that closes what S1d (ADR-0058)
opened. S1d proved a folder file becoming versioned, exactly-anchored Evidence a
permitted user can open, and it already proved idempotent re-sync, a changed
file producing one new immutable version, and re-extraction switching the active
set. S1e adds what happens when a file *leaves* the source or a version must be
*forgotten*: full-scan reconciliation, proven object deletion, the
retention/purge state machine, and the read-time gate that stops disclosing a
version the moment it stops being queryable.

The normative model is `DATA_MODEL.md` §4 (the lifecycle bullets, in particular
§4 items on `source_version_retention`, the purge single-transaction fence
advance, `queryable=false` being stronger than index state, single-membership
removal preserving the `SourceObject`, and `SCOPE_MEMBERSHIP_REMOVED` versus a
proven `SOURCE_OBJECT_DELETED`) and `POKA_YOKE.md` families SRC-006, VER-005,
VER-008, IMM-004, ING-005, ING-008, FRESH-002. This ADR records the decisions
that turn that model into the S1e code and (for the purge machine) migration
`000015`; it introduces no new normative field, adds no runtime/source type, and
does not amend an accepted ADR. Search, embeddings, OpenSearch and any office/
PDF/OCR format remain later slices.

## 1. Reconciliation is authoritative per full scan, and only per synced scope

A `SOURCE_SCOPE_SYNC` in `FULL` mode observes the complete current object set of
one scope. The sync worker (`internal/ingestion`) therefore closes the
memberships of objects that the scan did not observe: after the per-object
ingest loop, in one lease-fenced write, it moves `source_object_scope`
`ACTIVE -> REMOVED` for exactly the synced `(source_scope_id,
source_scope_revision)` whose `external_object_id_digest` is not in the scanned
set.

Three decisions make this fail-safe rather than fail-open:

- **Absence closes a membership only for an authoritative, complete scan.** The
  connector reports `DiscoveryResult.Complete`, true only when it enumerated the
  entire allowed root with no directory-level gap: every allowed subtree opened,
  listed and stat'd, with no unresolved enumeration, permission or I/O error, in
  one uninterrupted lease-fenced FULL run. If the scan is PARTIAL — an unreadable
  or vanished subtree, a permission loss mid-enumeration, an I/O failure after a
  partial list, an unresolvable `relative_root` — reconciliation is skipped
  entirely: no membership is REMOVED, no `SourceObject` is DELETED, and the run
  records `INGEST_PARTIAL_COVERAGE` so sync health reflects the incomplete
  coverage honestly. A *file-level* quarantine (a symlink, an oversized or
  unsupported object, a torn read, or a single entry whose identity was observed)
  does **not** make a scan partial: that object's identity was seen and its
  exclusion was a decision, not a coverage gap. The lease fence and the exact
  scope-revision key bind the deletion to this one run, so a stale, reclaimed,
  superseded or concurrent-newer scan cannot drive a false removal, and a crash
  before commit rolls the whole closure back.
- **"Present" is every discovered path, readable or quarantined.** Within a
  complete scan, the scanned set is the digests of both the ingested objects and
  the discovery-level quarantined ones. A file that is momentarily unreadable —
  turned into a symlink, an ACL change, a transient read error surfaced as
  quarantine — is *present but not ingestable*, never *absent*. Only a path in
  neither set is treated as gone. This is SRC-006 / ING-008: temporary absence is
  not deletion.
- **Reconciliation touches only the synced scope's exact membership.** The
  update is keyed by the exact scope revision, so a shared `SourceObject` that an
  overlapping scope still holds `ACTIVE` survives untouched (VER-005,
  `DATA_MODEL.md` §4: single-membership removal does not delete the object). A
  `REMOVED` membership is forward-only by the existing `source_object_scope`
  guard; it never un-removes, and the membership of an older scope revision never
  authorizes a newer one.

A trusted explicit connector deletion event, whose object identity, scope,
version and fence are proven by the connector contract, may close a membership
independently of coverage; the folder connector has no such native feed, so its
only deletion route is the complete-scan absence above.

Two further fail-safe boundaries harden the absence rule:

- **An empty complete scan is held, never acted on.** A scan that is `Complete`
  but observed *nothing at all* (no object, no quarantine) is indistinguishable
  from a vanished or substituted mount — an unmounted volume presents an empty
  readable mountpoint. Because removing an entire scope's catalog is irreversible
  (the membership and lifecycle guards never un-remove), reconciliation is
  skipped on a zero-observation scan and the run records
  `INGEST_EMPTY_SCAN_UNCORROBORATED`; a genuinely emptied scope keeps its
  memberships until a scan again observes objects or an explicit deletion
  arrives. A partial-but-nonzero collapse toward zero is still bounded by the
  coverage gate; richer corroboration (prior-count comparison, an in-root
  sentinel) is a follow-up, tracked as a known risk.
- **The absence predicate is keyed to the exact connection and digest key
  version.** The removal joins `source_object.connection_id` and
  `digest_key_version`, mirroring the identity lookup, so a rotation of the
  organization HMAC digest key cannot make objects ingested under the prior key
  version look absent and manufacture false removals.

Known risk (out of this slice): `source_object_scope` membership is
per-scope-revision, and the object-closure "zero ACTIVE memberships" check is
revision-agnostic; if a scope re-activation left an old-revision `ACTIVE`
membership un-migrated, a genuinely gone object would not be closed. This is
fail-safe — the read-time gate keys membership on the workspace-bound scope
revision, so a stale old-revision membership never discloses — but the
scope-revision activation path should be confirmed to close superseded-revision
memberships.

The immutable rows are never rewritten by reconciliation: the `SourceVersion`,
its `SourceExtraction` and its `EvidenceFragment`s stay exactly as published. The
closure is entirely at the membership, which is where authorization reads it.

This slice lands first and needs no migration: the `ACTIVE -> REMOVED`
transition and the worker `UPDATE` grant already exist in `000014`.

## 2. Read-time disclosure gate

`app.evidence_fragment_readable` already requires an `ACTIVE` membership of the
current scope revision in its authorization join. A `REMOVED` membership
therefore denies the Evidence body immediately, and it denies with the identical
not-found the viewer returns for every other failure — no existence oracle
(FRESH-002). No viewer change is needed for the membership path; the gate is a
consequence of the S1d authorization model, and S1e proves it end to end.

The same gate must hold for a non-queryable version and for a purged version;
those are proven against the retention machine below.

## 3. Object deletion versus membership removal (delivered, no migration)

`DATA_MODEL.md` §4 distinguishes two signals and S1e keeps them distinct:

- `SCOPE_MEMBERSHIP_REMOVED` changes only the exact membership (§1 above).
- Only a proven `SOURCE_OBJECT_DELETED` closes the `SourceObject`. For a folder
  connector without a native deletion feed, the proof is *unreachability from any
  scope*: reconciliation runs the membership closure and the object closure in
  one transaction, and an object that thereby holds **zero** `ACTIVE` memberships
  is closed — `lifecycle_state ACTIVE -> DELETED`, `queryable=false`. An object an
  overlapping scope still holds `ACTIVE` fails the `NOT EXISTS` guard and stays
  open (VER-005). A single scope's scan never closes an object another scope
  still references.

The object closure is a second gate on top of the membership one:
`evidence_fragment_readable` already requires `lifecycle_state='ACTIVE'`, so a
`DELETED` object denies its Evidence even if a membership row were somehow left
`ACTIVE`. The immutable version/extraction/evidence rows are retained for a later
purge; object deletion does not forget bytes. No migration: the
`ACTIVE -> DELETED` transition, the `queryable` flag and the worker `UPDATE`
grant already exist in `000014`.

Each closure is a significant lifecycle transition, so it leaves one content-free
audit event in the same transaction (AUD-005): a new `source.object_deleted`
action on the existing `SOURCE_OBJECT` resource type — no new `resource_type`, so
the frozen `audit-event.schema.json` enum is untouched — a SYSTEM actor, the exact
object id, and the sync run and job that caused it, never a path, title or
content. The membership-only removal (an overlapping-scope object that survives)
is not itself minted as a separate action; it is covered by the sync-level
`source.scope_changed` event, matching the per-object granularity S1d shipped
(object/version/extraction, not per-membership).

## 4. Retention / purge state machine (delivered, migration 000015)

Source-derived purge is the single-transaction fence advance of `DATA_MODEL.md`
§4, delivered as three SECURITY DEFINER functions in migration `000015` and a
privileged `internal/purge` orchestrator that runs as the trusted
`knowvault_purger` role.

- **Fail-close (`app.source_version_begin_purge`)** — one transaction, CAS on the
  observed `retention_fence`: it increments the fence first, drives the version
  retention to `PURGING` with `queryable=false` and `extraction_allowed=false`,
  drives every one of the version's Extraction retentions to `PURGING`/
  `queryable=false`, and clears the active-extraction pointer. The fence advance
  is the stale-work containment: every derived write CAS-checks the unchanged
  fence in `app.assert_version_writable`, so any in-flight worker at the old fence
  rolls its whole transaction back (`DATA_MODEL.md` §4). The
  `evidence_fragment_readable` join already requires `ACTIVE queryable` version
  and extraction retention, so the Evidence body is denied the instant this
  commits — inaccessible before any byte is removed. The orchestrator appends a
  content-free `source.version_purging` audit event in the same transaction.
- **Cleanup (`app.source_version_purge_cleanup`)** — a separate, idempotent step
  that runs only after the fail-close commit. It irreversibly forgets the
  decryptable bytes of every Evidence artifact of the version (`ciphertext` and
  `wrapped_dek` nulled, `purged_at` set), keeping the nonce and hashes as
  non-decryptable provenance, and skips already-purged rows so a crashed cleanup
  is safely resumable.
- **Completion (`app.source_version_complete_purge`)** — `PURGING -> PURGED` only
  when no decryptable Evidence artifact, no active pointer and no running job of
  the version remain. It drives the version and every Extraction retention to
  `PURGED`, redacts the version's lifecycle (`REDACTED`), and — if the purged
  version was the object's current version — closes the object
  (`queryable=false`) until a safe new current is chosen; a historical purge
  leaves the current version and object untouched (`DATA_MODEL.md` §4, VER-008,
  IMM-004). The orchestrator appends a content-free `source.version_purged` event.

Purge is a privileged control-plane operation: the three functions are revoked
from `PUBLIC` and granted only to `knowvault_purger`, so neither the web/API
runtime (`knowvault_app`) nor the sync worker (`knowvault_worker`) can purge. Each
function self-fences on `app.current_organization_id()` like every peer SECURITY
DEFINER function — the definer owner bypasses RLS, so the caller-supplied
`p_organization_id` must equal the session tenant; knowledge of another tenant's
ids is never purge authority. The caller passes the exact tenant, version and
observed fence, and `begin_purge` CAS-checks the observed fence so a purge under a
retention that already moved is rejected. Job containment rests on the fence CAS
(a stale worker's derived write rolls back via `assert_version_writable`), not on
job cancellation, which `begin_purge` does not perform; the completion job gate is
forward-defense for when extraction becomes its own durable job, and blocks
completion while any running job of the version remains rather than cancelling it. Migration `000015` also fixes two latent guards that S1d
never exercised: the shared retention guard read `NEW.retention_fence` for the
extraction-retention table (which has no such column), and the active-pointer
guard denied every non-hard-delete `DELETE`; both are repaired forward with
unchanged security semantics so a purging version's pointer can be torn down.

The OpenSearch/outbox residual check remains a P3/P6 responsibility, but the
fence contract already forbids stale resurrection today.

## 5. Acceptance

- A full scan that no longer sees a file moves exactly that scope's membership to
  `REMOVED`, leaves object/version/extraction/evidence counts unchanged, and the
  read-time gate then denies the fragment with the identical not-found.
- A momentarily unreadable (quarantined) file keeps its membership `ACTIVE`.
- A PARTIAL scan (vanished/unreadable subtree, unresolvable `relative_root`)
  removes no membership and closes no object, and records
  `INGEST_PARTIAL_COVERAGE`; a file-level quarantine keeps the scan complete.
- A crash inside the reconciliation transaction rolls the whole closure back; a
  clean reclaimed re-run then converges.
- Removing one overlapping scope's membership leaves the shared object queryable,
  `ACTIVE`, and the other scope's membership `ACTIVE` (VER-005).
- An object unreachable from every scope after a full scan is closed
  (`DELETED`, non-queryable), while an overlapping-scope object is not, and the
  closure leaves one content-free `source.object_deleted` audit event.
- Purge advances the fence, fail-closes the version and every Extraction, blocks
  new extraction, clears the pointer and denies retrieval before any byte is
  removed; a stale worker at the old fence cannot reactivate; cleanup is
  idempotently resumable; `PURGED` only after no decryptable artifact/pointer/
  running job remains; a current-version purge closes the object while a
  historical purge does not; purge is denied to the web/API and worker roles and
  across tenants.

## 6. Status of delivery

All four sections are delivered and proven on real PostgreSQL 18.4 and
filesystem: reconciliation and the membership read-time gate
(`catalog_evidence_reconcile_test.go`), the authoritative-absence coverage gate
(`catalog_evidence_coverage_test.go`, with connector coverage semantics in
`internal/connector/folder/folder_test.go`), proven `SOURCE_OBJECT_DELETED`
(`catalog_evidence_reconcile_test.go`), and the retention/purge state machine
(`catalog_evidence_purge_test.go`, migration `000015`, `internal/purge`). S1e is
complete.
