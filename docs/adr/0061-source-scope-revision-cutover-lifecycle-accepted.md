# ADR-0061: Source scope-revision cutover lifecycle — authority transition, prior-revision supersession, worker fencing and scan-safety

Status: accepted.

Closes the scope-revision debt that ADR-0059 §1 recorded as a known risk: the
scope-activation path never closed superseded-revision memberships, so a scope
that moved to a new revision (a narrowed root, a changed include/exclude) left
the prior revision's `source_object_scope` memberships `ACTIVE` and its
activation authoritative. This ADR records the decisions that turn the already
normative cutover model (`DATA_MODEL.md` §3–§4, `SOURCE_CONTRACTS.md` §1/§8,
`ADR-0047`) into code and migration `000016`. It introduces no new normative
field, no runtime/source type, no dependency, and does not amend an accepted
ADR. Search, embeddings, office/PDF/OCR remain later slices.

The normative anchors are: `DATA_MODEL.md` §3 (`latest_revision` grants no data
authority; the nullable `active_revision` switches only by an explicit audited
activation after `READY`; creating a revision performs no implicit cutover) and
§4 (a prior scope revision's membership never authorizes a newer revision;
`SCOPE_MEMBERSHIP_REMOVED` changes only the exact membership while a proven
`SOURCE_OBJECT_DELETED` closes the object and all memberships); `ADR-0047`
(cutover is always an explicit audited operation after dependent scopes have
been revalidated); POKA_YOKE SRC-004, SRC-006, SRC-014, SRC-015, VER-004,
VER-005, VER-006, ING-005, ING-008.

## 1. One authoritative revision; the transition is atomic and audited

At any instant a scope lineage has at most one authoritative revision for new
sync and read authority: `source_scope.active_revision` (nullable; `NULL` before
the first activation). A worker prepares a candidate revision `N+1` under its job
lease — `begin_sync` drives that revision's activation `… -> SYNCING`, a full
scan builds revision-`N+1`-specific `source_object_scope` memberships — and the
authority transition is a single lease-fenced transaction,
`app.source_scope_activate_revision`, that:

- confirms revision `N+1`'s activation is `SYNCING` and that the scan proving it
  reached full authoritative coverage committed under this lease (§4);
- **only ever moves authority forward.** A candidate strictly older than the
  current `active_revision` — a stale worker whose job was reordered behind a
  newer revision that already became authoritative — is *refused*: it is neither
  published nor allowed to supersede the newer revision; it is held `FAILED` and
  the transition returns `HELD`. Without this guard a reordered retry of an older
  revision would `REVOKE` and mass-delete the newer authoritative one;
- advances the candidate activation `SYNCING -> READY` and
  `source_scope.active_revision -> N+1` (forward-only, already guarded by
  `source_scope_parent_guard`);
- if the candidate is a genuine forward advance over a prior authoritative
  revision, supersedes every older revision in the same transaction (§2);
- appends one content-free `source.scope_activated` audit event, plus one
  `source.object_deleted` per object the supersession closes.

Because the whole transition is one transaction: the activation is atomic; a
crash before commit leaves `active_revision` at `P` and revision `N+1` still
`SYNCING` (recoverable); a crash after commit leaves `N+1` authoritative with `P`
fully superseded, never a half-cutover. The immutable `source_scope_revision`
rows are never rewritten — authority lives only in the monotonic activation
projection and the `active_revision` pointer, exactly as `ADR-0047` requires.
`source.scope_activated` is a new action on the existing `SOURCE_SCOPE` resource
type, so the frozen `audit-event.schema.json` `resource_type` enum is untouched.

## 2. Prior-revision membership supersession and object closure

When a genuine forward cutover to `N+1` supersedes the older revisions, in the
same transaction it closes **every** revision of this scope older than the
candidate — not only the immediately-prior active one. This is load-bearing: a
partial/failed intermediate revision can leave a stray `ACTIVE` membership (its
scan wrote memberships before the coverage decision held it `FAILED`), and
because object closure counts `ACTIVE` memberships across all revisions, a single
stray membership would keep a genuinely-gone object open forever and defeat
purge. So the supersession:

- transitions every older revision's activation `READY|SYNCING -> REVOKED`
  (`REVOKED` is the terminal "no longer authoritative" projection state; the
  existing activation guard already permits `READY -> REVOKED` and
  `SYNCING -> REVOKED`). This is the fence for any still-running older-revision
  worker (§3). Newer in-flight revisions (`> N+1`) are untouched — they will cut
  over later.
- closes the older revisions' memberships: every `source_object_scope` row with
  `source_scope_revision < N+1` and `membership_state='ACTIVE'` moves to
  `REMOVED` (forward-only by the existing membership guard). An older revision's
  membership thereby stops conferring read authority (the read gate requires
  `ACTIVE`), reconciliation authority, liveness and retention hold.
- closes objects that thereby hold **zero** `ACTIVE` membership across every
  scope and revision — `lifecycle_state ACTIVE -> DELETED`, `queryable=false` —
  reusing the exact object-closure predicate S1e reconciliation uses. An object
  still present under the new revision `N+1` (its complete scan built an `ACTIVE`
  `N+1` membership) or held `ACTIVE` by an overlapping *different* scope survives
  (VER-005); a narrowed-out object, whose only authority was its `P` membership,
  closes as a proven `SOURCE_OBJECT_DELETED`.

The ordering is the safety property: the candidate revision's complete scan
builds its `ACTIVE` memberships **before** the transition closes the prior
revision's, so a still-in-scope object is never momentarily authority-less. This
is why cutover requires complete coverage (§4) — supersession without a complete
new-revision membership set would close still-present objects.

The read-time gate is already revision-precise and needs no change: it keys the
membership on the workspace-pinned `(source_scope_id, source_scope_revision)`
(via `workspace_revision_source` at the workspace's current revision) and
requires `ACTIVE`. A superseded (`REMOVED`) prior membership therefore denies
disclosure immediately, with the identical not-found every other failure returns
(FRESH-002). A workspace that still pins `P` re-pins `N+1` through its own
workspace-binding revision — a separate checkpoint; until it does, a citation
into the superseded revision is denied, which is the correct fail-safe
(ACL-007, `DATA_MODEL.md` §6: scope narrowing immediately blocks an answer whose
citation is no longer reachable through the current scope).

## 3. Worker fencing across the cutover

Fencing binds a derived write to *both* the job lease and the candidate
revision's live `SYNCING` authority. Every membership/version write the sync
worker performs re-asserts, in its own transaction,
`app.assert_scope_revision_syncing(source_scope_id, source_scope_revision)`,
which locks the activation row `FOR UPDATE` and raises unless it is `SYNCING`
(mirroring `assert_version_writable`/`lock_job_lease`). Because
`activate_revision` takes the same activation rows `FOR UPDATE` to move `P` to
`REVOKED`, a revision-`P` worker and the cutover serialize on that row:

- if cutover commits first, `P` is `REVOKED` and the `P` worker's next
  `assert_scope_revision_syncing` fails → its whole transaction rolls back. After
  cutover a revision-`P` worker can create no membership, no SourceVersion, no
  Extraction, no Evidence, delete no object, and cannot re-enter `SYNCING`
  (`REVOKED` is terminal in the activation guard), so it cannot alter the new
  revision's sync health;
- if the `P` write commits first, cutover blocks on the row lock, then revokes
  `P`; the already-written `P` membership is closed by the supersession in the
  same cutover transaction.

`begin_sync`, `publish_ready`, `mark_failed` and `activate_revision` already
`lock_job_lease` first, so a stale lease (reclaimed job, lapsed deadline) writes
nothing. Two workers syncing two *different* revisions of one scope write under
disjoint `(…, source_scope_revision)` membership PKs, so they never corrupt each
other before cutover; cutover then fences the superseded one.

A reordered stale worker whose activation was still `DRAFT` when a newer revision
cut over is not reached by that cutover's REVOKE (which only touches `READY`/
`SYNCING` older activations), so `begin_sync` carries a forward-only fence of its
own: under a `FOR UPDATE` lock on the scope row (serializing against cutover) it
refuses to begin a sync for a revision older than the current `active_revision`.
Without it the stale worker could drive `DRAFT -> SYNCING` and commit `ACTIVE`
memberships *at* its (superseded) revision — memberships that sit at that revision,
not below a future candidate's `< candidate` sweep, and would linger as a stray
membership until the next cutover past them.

## 4. Scan safety — cutover requires complete coverage

Changing include/exclude/root must not turn a partial first scan of the new
revision into a mass deletion of the prior revision's objects. Two layers
enforce it:

- **Semantic owner (`internal/ingestion`).** A cutover (a candidate revision
  distinct from the current `active_revision`) publishes and supersedes *only*
  when the candidate's FULL scan was authoritative and complete
  (`DiscoveryResult.Complete` and non-empty — the same coverage gate S1e
  reconciliation uses). On incomplete coverage of a cutover candidate the run
  records `INGEST_PARTIAL_COVERAGE` (or `INGEST_EMPTY_SCAN_UNCORROBORATED`), the
  candidate is **not** made active, the prior revision stays authoritative, and
  the candidate activation is marked `FAILED` so it never masquerades as ready.
  The first activation (no prior `active_revision`) and a re-sync of the current
  active revision keep their existing S1e behavior — they build/refresh their own
  revision's memberships and never supersede a distinct revision.
- **DB containment on the run reference.** The worker records
  `coverage_complete=true` on the candidate's `sync_run` only for a complete
  non-empty FULL scan (migration `000016` adds the column). `activate_revision`
  accepts a `p_coverage_run_id` and refuses the transition unless that run is a
  `SUCCEEDED FULL` run for exactly this scope and candidate revision with
  `coverage_complete=true`. This independently rejects a cutover the orchestrator
  drives from a wrong, foreign, stale or partial run id — it does not, and cannot,
  second-guess the completeness signal itself: `coverage_complete` and the
  decision to call `activate_revision` share one trust anchor, the connector's
  `DiscoveryResult.Complete`. A connector that wrongly reports `Complete=true` on
  a truncated listing defeats both layers, exactly as it would defeat S1e
  reconciliation; that connector-honesty boundary is the pre-existing S1c/S1e
  control, not something this slice can re-establish.

Absence therefore closes a prior membership only after the new revision proved
full authoritative coverage and the audited transition policy ran to completion.

## 5. Recovery

Crash before the `activate_revision` commit: `active_revision` stays `P`, the
candidate stays `SYNCING`, no prior membership is closed — a reclaimed re-run
re-scans and re-attempts the transition. Crash after commit: `N+1` is
authoritative, `P` superseded, its narrowed-out objects `DELETED`; the results of
the two revisions never mix because each revision's memberships are keyed by its
own `source_scope_revision` and the superseded set is closed atomically with the
advance. No new SourceVersion, Extraction or Evidence is rewritten by any of
this — the closure is entirely at the membership and lifecycle projections.

## 6. Acceptance

Proven on real PostgreSQL 18.4 and filesystem (three layers per §DoD): a semantic
`internal/ingestion` owner test, an independent DB-function containment test, and
negative/concurrency/mutation tests. Minimum scenarios: first activation (no
prior); successful cutover `N -> N+1` advancing authority and superseding `P`;
rollback of a crashed cutover leaving `P` authoritative; concurrent old/new
workers; a stale/reclaimed old lease writing nothing; narrowing scope (a
narrowed-out object closes to `DELETED` only after complete `N+1` coverage);
widening scope (a newly-included object gains an `N+1` membership and the prior
set is superseded with no false deletion); root replacement; a partial first scan
of `N+1` performing no supersession and no deletion; overlapping scopes (a shared
object an overlapping *different* scope still holds `ACTIVE` survives cutover); a
superseded `P` membership no longer holding a gone object open against purge; a
read after cutover resolving only through the new authoritative revision; and an
audit trace that carries scope/revision/run ids but never a path, title or
content.

## 7. Status of delivery

Delivered in migration `000016` (`app.source_scope_activate_revision`,
`app.assert_scope_revision_syncing`, `sync_run.coverage_complete`) and the
`internal/ingestion` cutover orchestrator, proven by
`tests/integration/postgres/catalog_evidence_cutover_test.go` and the
DB-containment cases. This slice supersedes the ADR-0059 §1 known risk.
