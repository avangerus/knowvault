# ADR-0010: Immutable Extraction between SourceVersion and EvidenceFragment

Status: `ACCEPTED`

Date: 2026-07-14

## Context

The same immutable `SourceVersion` can be reprocessed after updating the parser, OCR, normalization, or extraction profile. If `EvidenceFragment` belongs only to SourceVersion, replacing fragments breaks historical citations, and adding a new set does not determine which set should participate in new questions.

## Solution

- Each processing run creates an immutable `SourceExtraction` with its own profile hash and evidence-set hash.
- `EvidenceFragment` and `SearchChunk` belong to a specific Extraction.
- After `SUCCEEDED` or `FAILED`, the Extraction provenance fields are immutable. A separate retention projection manages privileged purge without rewriting profile/evidence hashes.
- A separate mutable projection `source_version_active_extraction` selects exactly one successfully completed Extraction for new search/question runs.
- A new Extraction is first fully built and indexed as `STAGED`, then the active pointer switches atomically; the previous set ceases to participate in new retrieval but remains available as historical citations according to the retention policy.
- A citation records `extraction_id`; the context pack additionally records `extraction_profile_hash`, and the top-level Answer Manifest records the used extraction records and verifies them against the trusted catalog. The profile hash is not duplicated within each citation.
- Changing the active Extraction does not create a new SourceVersion and does not mean the source document has changed, but the read-time citation resolver shows `EXTRACTION_SUPERSEDED` and offers a new Question Run. If the historical Extraction is already `PURGING/PURGED`, the resolver returns `EXTRACTION_PURGED` and the disclosure gate does not issue body/excerpt.

## Consequences

- Parser/OCR upgrade does not rewrite EvidenceFragment and does not break old answers.
- The index can be rebuilt from active extraction sets.
- Additional FK, uniqueness, terminal validators, and regression fixtures are required.
- Answer-retention purge of a specific Question Run removes only question-owned answer body, excerpts, and snapshots and never removes shared Extraction/Evidence that may be used by other runs/workspaces.
- Source-derived-data purge of a specific SourceVersion is a separate privileged state machine with version-level retention aggregate and monotonic fence: first, the fence increases, new Extraction is forbidden, retention/queryability for this version and the exact set of all its Extractions fail closed, old fence leases are revoked, and the active pointer of exactly this SourceVersion is cleared. Late DB commit loses CAS, and stale OpenSearch mutation is discarded by the ordered outbox applier. Cleanup and absence of artifacts are confirmed before `PURGED`; immutable provenance hashes remain as tombstone metadata. `SourceObject.queryable` is closed only if this version is current or the logical object is deleted; historical purge does not disable a new current version.

## Rejected Alternative

Prohibit re-extraction of unchanged SourceVersion. This makes updating the parser/OCR operationally hazardous and contradicts the mandatory regression/reindex lifecycle.
