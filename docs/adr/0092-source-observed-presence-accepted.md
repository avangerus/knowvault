# ADR-0092: Source absence and final deletion

Status: accepted for pilot correction; delivery and measurements — in [PLAN.md](../release/PLAN.md). Owner approved on 16.09.2026 the correction of file and SQL-entity return prior to the pilot, estimate 6–12 hours. Decision acceptance does not mean that the migration candidate has already been verified or deployed.

## Reason

The full traversal noted the missing object `DELETED`, membership — `REMOVED`.
These states are terminal, and the object's identity is unique within the connection.
The returned file found the previous record but remained inaccessible upon successful
synchronization. The A→B→A change check did not detect disappearance between traversals.

## Solution

`MISSING` denotes proven absence in a full successful sweep of the exact revision of the scope. The membership retains the time and the sync run that caused the absence. If another scope still has an ACTIVE membership, the object remains accessible through it. Without ACTIVE memberships, the object becomes `MISSING/queryable=false`. Read checks continue to require ACTIVE: temporary absence does not open the stored bytes.

Successful observation and data extraction can return MISSING membership to ACTIVE. Publishing re-checks the lease, the exact scope revision and its live authorization, successful extraction of the current version, and retention. All changes are included in the publishing transaction; denial or loss of the lease rolls back restoration. Direct UPDATE by the worker role must not transition MISSING to ACTIVE outside the authorized publishing function; this boundary is verified on real PostgreSQL. Previous bytes may reuse an existing immutable version; new bytes create the next version under the same contract. Membership return creates a new indexing event for existing fragments: the first event is not reused because it may have already been completed.

The old UPSERT task for a confirmed MISSING can be completed without reading text or writing to the index, after verifying the exact chain of chunk/version/extraction/artifact/hash and index generation. The physical copy in the index does not permit reading itself: current authorization excludes MISSING. Temporary absence does not trigger an external DELETE, which upon late network completion could have already deleted the returned copy. For a confirmed immutable SUPERSEDED version, only its old chunk ID may be deleted before task completion; the new current version has different fragments. Arbitrary availability failure is not grounds to skip the task. Quarantine, incomplete traversal, and a single identifier match do not prove successful re-observation.

`REMOVED` and `DELETED` remain terminal. Closing the old scope revision closes its MISSING memberships as well. No old membership grants rights to a new revision, and access revocation and purge are not undone by file restoration.

For previous DELETED/REMOVED, only conservative reclassification to MISSING is allowed in migration: exact audit of absence, successful full sync run/job, times, current scope revision, live authorization and retention must match. It does not make the object available itself. Ambiguous and closed records retain terminal state. Global restoration and manual correction via operational SQL are prohibited.

Audit distinguishes `source.object_missing`, `source.object_restored`, and the final `source.object_deleted`. Events do not contain the document path or content. When preserving availability through another scope, a false event of the entire object's absence does not occur.

## Result Verification

Folder and SQL: appearance → absence → original bytes → new bytes → repeat;
search, full read, version count, original addresses, and audit. Separately:
overlapping scopes, closed revision, revocation, retention/purge, quarantine,
lost lease, publication rollback, and migration of the previous state.
A positive inventory by itself does not prove a working search.

Universal new incarnations of finally deleted objects and arbitrary restoration of old scope revisions are not included in this fix.
