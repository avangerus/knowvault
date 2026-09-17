# ADR-0077: Keyed Evidence content digest (text_hash)

Status: accepted.

Owner decision recorded 2026-08-14: the owner delegated the closure of the blocker to the EVIDENCE-CONTENT-HASH-IMPLEMENTATION executor with the right to make decisions on the scope. This ADR records the decisions of the package; they do not weaken any gate and do not change the accepted ADR-0070/0071.

## 1. Decision

1. `evidence_fragment.text_hash` translates to organization-scoped HMAC-SHA-256 with mandatory `text_digest_key_version` (format `hmac-sha256:k<v>:<hex>`, validator `app.source_keyed_digest_matches_version`). Plain SHA-256 for Evidence content is no longer accepted by the scheme: CHECK on new lines rejects `sha256:`-format. Historical plain-SHA strings remain under `NOT VALID`-boundary and are closed with a read/publication failure (fail closed) until digest-rotation redesigns them.
2. The binding "artifact contains exactly text fragment" is moved to a separate keyed-projection `evidence_text_projection` (symmetric to `evidence_anchor_projection` from 000017): the fenced bind-function writes the artifact and projection atomically; the fragment guard verifies the pair `(text_hash, text_digest_key_version)` against the projection. The `plaintext_hash = text_hash` verification is removed — `plaintext_hash` remains internal SHA-256 integrity (G6, unchanged).
3. Digest-rotation (ADR-0070 §1.4) extends to both projections: `evidence_digest_remaining_count`/`candidate_batch`/`rewrite` cover `text_hash` together with `anchor_hash` in one fenced transaction; zero-remaining complete requires both pairs under the active version. Fragments of PURGING/PURGED versions are excluded from candidates and zero-remaining: reprojecting purged content is impossible and unnecessary (unreadability is already fail-closed), otherwise their legacy projections would permanently block complete.
4. Purge (000015): projection strings `evidence_text_projection`/`evidence_anchor_projection` are deleted during cleanup. Keyed-projections within the strings `evidence_fragment` remain as non-decryptable purge provenance — after transition they are not a suitable hash oracle (digest key is not stored in DB); plain-SHA projections of content in the tree are nowhere anymore.
5. Scope G3/G5: `source_version.content_hash` and `acl_snapshot.content_hash` remain plain SHA-256. They are identity/integrity projections of the source and ACL (change detection, version comparison), not equality projections of Evidence content; translation to keyed would break cross-version identity comparison after digest-key rotation. The solution is fixed here as conscious; it is reopened only by a new owner decision.
6. Scope G4: `evidence_set_hash` remains SHA-256 wrapper over JCS descriptors; descriptor inputs (`evidence_text_hash`, `anchor_hash`) are keyed after this package. Full keyed for the wrapper is not required: it publishes composition, not content.
7. P4-projections (G8: `evidence_text_hash`, `exact_context_hash`, `cited_excerpt_hash`, `claim_text_hash`, `supporting_claim_text_hash`) — phase has not arrived; registration of the unarrived phase is preserved; upon P4 implementation, keyed is mandatory (owner decision in IMPLEMENTATION_PLAN).

## 2. Mechanical contract

- Migration 000020: `text_digest_key_version`, CHECK keyed (NOT VALID for historical rows), table `evidence_text_projection`, 15-arg `app.evidence_fragment_bind_normalized_text` (13-arg becomes inert), guard-branches, extended DIGEST functions, purge projection cleanup.
- Runtime: `pipeline.go` counts `text_hash` via `canon.HMACDigest(digester.Key, digester.KeyVersion, unit.text)`;
  text is written only via keyed-path (`StoreKeyedProjection` for
  `EvidenceNormalizedText`; generic `Store` for this field is closed).
- `evidence_fragment_readable` and active extraction publication require
  keyed text (fail closed for legacy).
- CANONICALIZATION.md: `normalized_text_hash` and descriptor
  `evidence_set_hash` transition to keyed format.

## 3. Consequences

- Closes the Evidence delivery precondition from the owner's solution and removes the EVIDENCE-CONTENT-HASH-IMPLEMENTATION blocker after independent review.
- Mutations of the registry targeting overridden DIGEST functions 000019 are redirected to 000020 via equivalent transformations.
- NFR-B1/B2 windows remain unchanged in meaning; re-projection now opens both the anchor and the text in a single transaction.

## 4. Acceptance evidence

- PG-package `tests/integration/postgres/keyed_text_digest_test.go`: new
  fragments keyed; CHECK rejects plain SHA; absence of version — RED;
  legacy line is unreadable and not published; DIGEST rotation redesigns
  both projections and ends with zero-remaining; purge deletes projections and
  preserves unreadability; rotation with purged version does not block complete.
- Mutation corpus: RED — pipeline returns plain SHA;
  rewrite/complete relaxations; GREEN — semantically-preserving equivalents.
- Checker, unit, PG-package, mutation-runner on real PostgreSQL.
- Independent package review.
