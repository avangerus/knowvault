# Executable Contract Semantics 1.0

Status: `ACCEPTED`. The JSON Schema checks the form, while this document defines mandatory cross-field validations. Successful schema validation without these checks does not allow ingestion or completion of Question Run.

## 1. General Rules

- Input first passes JSON Schema, then canonicalization, then semantic validation.
- Any unknown revision, enum, field, hash algorithm, or normalization version is rejected.
- All IDs in a single aggregate check belong to one organization; composite tenant FKs confirm this in PostgreSQL.
- A semantic validation error has a stable machine `error_code`, is audited without the original content, and is not silently corrected.
- The strict decoder preserves number tokens until typed unmarshal and rejects duplicate names, invalid UTF-8, lone surrogate, non-finite value, and any numeric value outside `[-9007199254740991, 9007199254740991]` with `JSON_NUMBER_NOT_IJSON`. Do not first decode a number to `float64` and then check the already rounded value.
- The signing key must exact-match a trusted organization/purpose/connection-agent scope record and `not_before <= signed_at <= sign_until`. A new artifact signs only with a single ACTIVE key; historical Answer/Audit verification allows ACTIVE/RETIRED within a valid signing interval, but REVOKED always fails closed. A new connector event on ingest accepts only an ACTIVE key exact `CONNECTOR_EVENT` connection/agent scope on server receive; RETIRED is allowed only for a separate offline historical verification operation. Private/public key from payload is not accepted.

## 2. Model Claim Plan

Before verifier and renderer is checked:

1. `claim_id` and `section_id` are unique.
2. Each ID from section exists.
3. Each published claim appears in exactly one section.
4. FACT contains only evidence IDs from the current authorized context pack.
5. INFERENCE references only FACT from the same plan; self-reference, chain, and cycle are prohibited.
6. UNKNOWN contains no model text, evidence, or supporting claims; it contains only typed `unknown_reason`. The server materializes exact fixed Russian text per `CANONICALIZATION.md`; the factual payload in the UNKNOWN schema is invalid.
7. The model does not set a terminal status and does not return a separate insufficient flag/reason: the server outputs status only from verified FACT/INFERENCE and UNKNOWN.
8. Model text remains single-paragraph data: leading/trailing Unicode whitespace, controls, newline, and bidi overrides are rejected; the renderer inserts it only as an AST Text node and does not interpret HTML, Markdown links/images/autolinks, entities, backticks, or citation markers.
9. `sections[].title` is always `null`; the model cannot place an unverified fact in a heading. Any visible labels/prefixes are created only by the renderer from fixed strings.

## 2.1 Answer mode

`answer_mode` and `verification_method` — mandatory signed fields Answer Manifest. Their allowed pairs and mode boundaries are checked before terminal commit:

| `answer_mode` | `verification_method` | Mandatory semantics |
|---|---|---|
| `EXTRACTIVE` | `BYTE_EXACT_CITATION` | claim — deterministic projection of authorized context; exactly one citation with byte-exact cited excerpt |
| `GENERATIVE` | `SEMANTIC_VERIFIER` | model execution plan, generation, and verification gates of section 3 apply |

In extractive mode, `claim_verifications` is empty, generation/verification profiles and model runs are absent, and each published FACT has exactly one symmetric citation. Canonical UTF-8 bytes claim and cited excerpt are compared directly; CR/LF are forbidden, length is limited to 2000 bytes. Plan `extractive-answer-plan-v1` obtains a server-owned authorized context snapshot from outside: the validator recalculates the full candidate-set hash, verifies source/version/extraction/anchor identity, and allows the cited sentence only from exact context bytes. The plan cannot assign its own hash authority and cannot reference a missing or foreign fragment. UNKNOWN is materialized by the server and does not become a model assertion.

`authorized_context_hash` and extractive `anchor_hash` are organization-scoped HMAC-SHA-256 equality digests in `hmac-sha256:k<version>:<hex>` format, not public plain-SHA content projections. Trusted snapshot separately carries a plain-SHA integrity hash candidate set; the validator recalculates it and only then accepts the HMAC equality binding from the snapshot. Therefore, the plan cannot issue its own digest as an authorization source.

Connection is not a 'trust' text check: the external trusted catalog contains organization/workspace scope, a full canonical candidate projection, and a separate signed HMAC catalog record. The Runner recalculates `entries_integrity_hash`, the HMAC candidate-set digest, the catalog signature, and the snapshot signature using the test-key vector, and then requires byte-exact equality for each candidate catalog entry. Substitution of the source object/version/extraction/anchor, key version, catalog, or snapshot yields `EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID` or `EXTRACTIVE_CONTEXT_ENTRY_NOT_AUTHORIZED`; registered mutation cases check both branches of divergence. The production key comes from the external KMS, while the fixture-key exists only for reproducible contract runner.

For sandbox, JSON Schema fixes the shape and deny-capabilities, while the Go contract runner separately checks the comparison of `deadline_at > submitted_at`, lease duration, parser binding, handoff state matrix, and trusted kernel observation. These cross-field rules are registered as executable negative cases; the description in the schema itself is not considered a gate.

In generative mode, current rules require exact persisted profiles, plan, selected successful runs, and semantic/numeric validation. Switching modes is not a way to bypass these requirements. The presence of a schema or fixture does not mean Question Run activation at the current coordinate.

## 3. Answer Manifest and terminal commit

Before the only completion transaction, the following is checked:

1. Each FACT has `SUPPORTED`, at least one citation, and a successful persisted verifier result; semantic support may be a paraphrase or joint inference from multiple evidence items and does not reduce to checking `claim.text` as a literal substring;
2. `claim.citation_numbers` and `citation.claim_ids` are strictly symmetric;
3. Each citation is independently resolved into its own chain: source object → catalog SourceVersion → immutable SourceExtraction → persisted EvidenceFragment → canonical excerpt/anchor and an exact-match record of the authorized context pack by evidence/version/extraction/profile/content/evidence/anchor hashes; one EvidenceFragment creates no more than one citation number, while multiple claims reuse it; the source hash is verified against the trusted catalog record, not via the false requirement that "extracted text is a byte-substring of PDF/DOCX/MIME"; the validator rejects missing, duplicate, mismatched, or unpassed-to-the-model chains;
4. manifest `extractions` exact-matches trusted catalog Extraction records, covers exactly the set of extraction IDs of citations, and fixes profile/evidence-set hashes; self-declared extractor/OCR metadata are forbidden;
5. Each terminal citation anchor kind/hash exact-matches the trusted EvidenceFragment descriptor of a specific Extraction and passes a common format-specific resolver, which returns a byte-exact cited excerpt; a single valid geometry/cell is insufficient. Source object type checks the allowed class (`GIT_FILE→GIT`, `EMAIL→EMAIL`, `WEB_PAGE→HTML`), while FILE/ATTACHMENT uses the parser/OCR kind from the trusted extraction profile, not a naive MIME-only mapping; text ranges require `end > start`, an XLSX range cannot be reversed, and an OCR bounding box must remain inside the normalized page and link to saved OCR tokens;
6. `source_version_content_hash`, `evidence_text_hash`, `cited_excerpt_hash`, and `anchor_hash` are recalculated from saved canonical bytes;
7. `answer_span.end > answer_span.start` boundaries lie within canonical Markdown and byte-exactly match `escape(claim.text)` by `answer-renderer-v1`;
8. All sections exist, their claim IDs are globally unique, and cover each claim exactly once;
9. Configured profiles have four different purposes and exact-match persisted Model Gateway profile records; actual `model_runs` exact-matches trusted persisted run records by ID, purpose, attempt, model/revision/artifact/profile/prompt, outcome, hashes, and selected flag—internal field consistency of the manifest alone is insufficient; `model_run_id` is unique;
10. `(purpose, attempt)` is unique; a successful run has a non-null output hash; `selected_for_result` is allowed only for a successful run. `model-execution-plan-v1` is created by the server before the first model call, is append-only, includes every planned and retry attempt in the allowed order, and exact-matches links the corpus snapshot with model artifact IDs/profile hashes, inputs, and outputs. For each required purpose, there is exactly one selected successful attempt; for others, none; unplanned, skipped, or self-declared attempts are forbidden. Purpose-specific artifacts are recalculated and link EMBEDDING with the exact question, RERANKING with the **entire** immutable authorized candidate set, GENERATION with the final context, and VERIFICATION with exact claims/evidence; unrelated but real ModelRuns are forbidden;
11. manifest `question_run_id`, organization/workspace/revision, canonical question text/hash, actor, started/completed timestamps, and `supersedes_question_run_id` byte-exactly match the trusted persisted QuestionRun aggregate. It supersedes the target if non-null, exists in the same organization/workspace, and is not passed to the model; cross-run/cross-tenant provenance is forbidden even with a self-consistent new signature;
12. Workspace scope hash, access context hash, and policy revision are recalculated by the server. Manifest `retrieval.model_execution_plan_hash` exact-matches both the full trusted `model-execution-plan-v1` and the same field of the persisted `retrieval-authorization-v1` snapshot. Other retrieval fields exact-match the snapshot, immutable `authorized-candidate-set-v1` and trusted retrieval profile: pipeline revision/hash, analyzer/code/model profiles, full post-authorized candidate set/hash/count, lesser than or equal to final context count/order, selected embedding/reranking bindings, truncation/reason, and errors. Reranker input exact-match contains every authorized candidate, including those not included in the final context; collapsing the candidate set to context is forbidden. Pre-authorization count is not included in manifest/snapshot/user metadata. Self-declared/floating retrieval configuration is forbidden;
13. Each snapshot entry exact-matches the final context pack and trusted catalog/policy state immediately before the terminal commit: exact ACTIVE scope membership of the current WorkspaceRevision, `CURRENT` SourceVersion, version retention/fence/queryability, active Extraction/activation revision, Extraction retention/fence/queryability, and selected ALLOW grant path. Old SUCCEEDED but non-active Extraction is not allowed;
14. Each grant requires a trusted `RESOLVED` principal-set snapshot, exact effective principals/provider/session revisions, and freshness on `authorized_at`; stale identity mapping or group expansion fails closed and invalidates the cache. The terminal transaction does not trust repeated grant fields: it exact-matches verifies the current WorkspaceRevision, membership/role, enabled binding, and the saved ALLOW PolicyDecision. Then, one canonical minimal grant path is selected: `WORKSPACE_MANAGED` requires exact active confirmation, `SOURCE_ENFORCED` requires the current `RESOLVED` ACL snapshot, freshness, and a non-empty intersection of source-native ACL token digests with effective principal digests. Missing/stale identity/ACL does not create a grant regardless of `COMPLETE/PARTIAL`; `WORKSPACE_MANAGED` cannot pretend to be a source ACL. Concurrent revision change gives bounded retry/fail;
15. `corpus_snapshot` contains the exact set of enabled bindings for the fixed WorkspaceRevision and an exact-match persisted trusted source-health snapshot by connector type/version, health, watermark, last successful sync, and ACL freshness; access mode/SLA are taken from the trusted scope config but are not silently added to the canonical workspace-scope hash; self-declared READY/timestamps, missing, duplicate, and extra scopes are forbidden;
16. corpus status is deterministically computed relative to `started_at`: `last_successful_sync`/`acl_fresh_at` cannot be in the future; content age equals `started_at-last_successful_sync`, ACL age equals `started_at-acl_fresh_at`; `COMPLETE` requires READY, both applicable ages `<=` trusted SLA, absence of retrieval errors, and truncation. Otherwise status is exactly `PARTIAL`; SOURCE_ENFORCED with missing/stale ACL fails closed for this binding until retrieval;
17. `claim_verifications` contains the exact set of all published FACT and INFERENCE and exact-match persisted records: claim kind/text hash, canonical verification input hash, verifier run ID, evidence descriptors, supporting FACT descriptors, and `SUPPORTED` outcome. FACT uses exactly its own citations; INFERENCE uses exactly direct supporting FACT and the union of their citations. Each record references one trusted selected successful `VERIFICATION` ModelRun; UNKNOWN record does not. Any replacement of text, citations, or supporting claims after verification forbids terminal commit;
18. canonical verifier output passes a separate strict schema; results exact-match input claim IDs/hashes without missing/extra/duplicate, and persisted `ModelRun.output_hash` is recomputed from its JCS bytes. Only outcome `SUPPORTED` allows ClaimVerification and claim publication;
19. `deterministic_validations` contains the same exact set of FACT/INFERENCE, uses exact verification input hash, and trusted `numeric-validator-v1` output. Every material number/date/currency/unit exact-match cited excerpt or supporting passed FACT; FAILED/self-declared/stale result blocks completion;
20. selected GENERATION output is schema-valid and byte-exact matches the inverse model-plan projection of final claims/sections. After verifier/numeric gate, a claim cannot be silently removed, changed, or re-bound: a new bounded generation attempt is required;
21. status is computed strictly in both directions: `COMPLETED` requires at least one FACT and does not allow UNKNOWN; `INSUFFICIENT_EVIDENCE` requires at least one UNKNOWN, and FACT in it is optional. Therefore, a non-empty but irrelevant context cannot become a successful answer, and a facts-only answer cannot be arbitrarily marked insufficient;
22. for zero-hit paths `context_count=0`, `citations=[]`, `extractions=[]`, snapshot `entries=[]`, claims contain only UNKNOWN, result equals `INSUFFICIENT_EVIDENCE`, and selected purpose set contains exactly `EMBEDDING`. Empty context does not cancel the pre-retrieval freshness gate: fresh PrincipalSetSnapshot and exact current workspace membership are mandatory. Fictional model calls are forbidden;
23. trusted corpus capture, authorization, model runs, deterministic validations, terminal completion, and signature obey QuestionRun interval/order from `CANONICALIZATION.md`; out-of-window/backdated artifacts are forbidden;
24. manifest canonical bytes, signing bytes, hash, and signature are preserved until terminal status in the same transaction.

Retention purge has two independent safeguards: the completion validator requires the physical absence of answer/excerpt/normalized content and returns `RETENTION_PURGE_INCOMPLETE` if bytes remain; the read gate for state `PURGED` always returns `ANSWER_CONTENT_PURGED` on any content request regardless of the actual storage state.

## 4. Connector Event

Before access mode verification, a common trust gate applies: the exact connection revision must reference approved connector version/build artifact hash, capability profile hash, and contract-suite hash with status `VERIFIED` and non-expired `verified_at`. `WORKSPACE_MANAGED` does not bypass this gate.

Event is allowed in catalog only if:

1. mTLS registration determined the organization, connector, and permitted connection/scope;
2. claimed organization, connection, scope, immutable scope revision, and `connector_job_id` matched the mTLS registration and the pre-signed bounded job;
3. payload hash and signature were recalculated according to `CANONICALIZATION.md`;
4. the key is active, `signed_at` is within the acceptable window, and the nonce was atomically consumed;
5. an exact repeat of the event/idempotency key returns the previous result, while a repeat with a different payload yields a security conflict;
6. for content-bearing/MOVED event discriminator `object_type` matches `object_metadata.kind`; DELETE and ACL_CHANGED contain `object_metadata=null`, and the server uses the latest trusted metadata from the catalog;
7. object metadata conforms to the source-specific contract;
8. the read bytes match `content_reference.content_hash`, `size_bytes`, and `media_type`;
9. the opaque content reference has not expired. Expiration before fetch transitions the version to `CONTENT_UNAVAILABLE`/quarantine; the connector must issue a new signed event, and the server does not bypass expiry;
10. ACL tokens are canonical, sorted, unique, namespaced, and do not contain wildcards, leading/trailing/internal whitespace, or control characters; the ACL hash was recalculated according to `CANONICALIZATION.md`;
11. `SOURCE_ENFORCED` never becomes queryable without a fresh RESOLVED ACL.

For DELETE, fields `external_version_key`, `object_metadata`, `content_reference`, and `acl_snapshot` must equal `null`, and `delete_semantics` is required:

- `SOURCE_OBJECT_DELETED` is allowed only when source has confirmed the disappearance of the logical object across the entire connection. The server atomically closes `SourceObject.queryable`, marks all memberships as removed, and then clears the active indexes;
- `SCOPE_MEMBERSHIP_REMOVED` signifies only the disappearance of the object from the exact pair `(source_scope_id, scope_revision)`. The server closes this membership; SourceObject and current version remain queryable if another ACTIVE membership exists, accessible to a specific WorkspaceRevision.

For all operations except DELETE `delete_semantics=null`. Connector cannot infer global deletion solely from the fact that an object was not encountered in a single scope scan. Reconciliation must prove the chosen semantics, and the overlapping-scope test verifies that deletion of a narrow membership does not destroy a common object.

Content-bearing event additionally exact-match stable-read record. Object identity, external version, size/native token and bytes are fixed by a single open/conditional read; before/after mismatch or failed condition yields retry/quarantine. Server does not create SourceVersion from a torn read, even if the sent content hash formally matches one of the intermediate states.

## 5. Source Scope Revision

`source-scope.schema.json` checks the tagged shape, then the semantic validator requires:

- an exact immutable connection revision exists in the same organization, has the same source type, trusted discovered `external_scope_id`, connector build/capability/trust profiles, and allows the requested access mode; the mutable current connection does not substitute the revision;
- all strings are NFC; the scope revision is immutable, while the config hash is recalculated based on `CANONICALIZATION.md`;
- SOURCE_ENFORCED is allowed only with verified stable identity/item ACL/ACL-refresh capabilities, exact build, and non-null ACL SLA; self-declared capability or a numeric-only SLA is insufficient;
- Folder paths/globs, after platform normalization, remain within the admin root; symlinks/reparse/ADS, Windows device names/trailing dot-space, and traversal are prohibited;
- The Git branch is selected from trusted discovered refs and exact-matches `refs/heads/...`; revision expressions, raw SHA/tag/HEAD/refspec/wildcard/leading options are prohibited; connection transport in 1.0 is verified HTTPS only;
- Mail provider identity follows `SOURCE_CONTRACTS.md`: Graph ImmutableId, Gmail stable message ID, or IMAP mailbox+UIDVALIDITY+UID;
- Site URLs are canonical HTTP(S), pass exact origin + path-segment-prefix semantics; raw string prefix is prohibited. Seed/sitemap/each redirect pass the network-zone SSRF gate, redirect count, decoded-size/ratio, and XXE-disabled XML policy;
- general `object_limit`/`byte_limit` are aggregate authority; nested file/blob/message/attachment/response byte cap `<= byte_limit`. Requested limits do not exceed organization/connection limits; the connector job receives an even narrower exact signed config but cannot expand it. `respect_robots_txt` in 1.0 is strictly true.

## 6. Anchors and canonical text

- The exact excerpt must be a byte-exact slice of the canonical UTF-8 text within a half-open range.
- The start and end positions must lie on UTF-8 code-point boundaries.
- The structural resolver confirms the page/paragraph/shape/cell/MIME part/path/DOM node and bounds.
- The source version hash verifies the exact transient source bytes; the evidence text hash is the canonical fragment; the excerpt hash is the actually quoted slice. These hashes are not interchangeable.
- The FILE/ATTACHMENT parser-kind mapping is trusted extraction metadata: JSON/XML/CSV/TXT/Markdown/HTML/source code yield `TEXT`; EML (`message/rfc822`) yields `EMAIL`, where the anchor message ID equals the provider immutable ID or a deterministic `source-object:<source_object_id>` for file EML, and the MIME part exact-match parser tree. The site page remains `HTML`, and the provider mail is `EMAIL`.
- Changing chunking does not alter the EvidenceFragment anchor and does not invalidate the old citation.
- The File/Git path first translates `\\` to `/`, then the validator forbids absolute paths, empty segments, `.`, and `..`; the schema pattern does not replace this check.

## 7. Encrypted Artifact AAD

Each encrypted artifact first undergoes `encrypted-artifact-aad.schema.json`, then the repository verifies the owning table/column against the closed map of exact `resource_type + field + resource_id`:

- organization, resource type, resource ID, field, and schema version are included in authenticated JCS AAD;
- common type `BLOB`, unknown type/field pair, and reuse of ciphertext in another field are prohibited;
- tampering with organization, resource ID, resource type, or field must result in authentication failure;
- adding a new encrypted column requires extending the schema, repository map, and ciphertext-swap fixture prior to migration.

## 8. Audit Event and checkpoint

Each row passes `audit-event.schema.json`. The checkpoint builder loads full event bodies, re-validates allowlisted metadata, JCS-canonizes the event without `event_hash`, recalculates the hash, and verifies contiguous `sequence + previous_event_hash` for the entire range. A list of saved hashes without event bodies is not proof of a chain. Changes to actor, action, resource, outcome, evidence IDs, or metadata with a saved old hash must be detected.

## 9. Mandatory negative and adversarial fixtures

Contract suite contains a minimum of:

- malformed/unknown JSON field;
- duplicate claim/model/section purpose;
- missing, foreign, self-referencing and cyclic claim reference;
- asymmetric claim↔citation mapping;
- invalid UTF-8 boundary and `end <= start`;
- Unicode NFC/NFD, Cyrillic, emoji and CRLF/LF golden cases;
- wrong source/evidence/excerpt/anchor hash;
- expired content reference;
- replay nonce and same idempotency key/different payload;
- wrong metadata discriminator;
- wildcard/colliding ACL identity;
- overlapping scopes for the same source object;
- retention purge disclosure attempt.
- post-verification mutation claim text/citation/supporting FACT;
- verifier output with missing/extra/duplicate claim, incorrect verification input hash or incorrect canonical output hash;
- non-empty irrelevant context + UNKNOWN with false `COMPLETED`;
- stale SOURCE_ENFORCED ACL at `PARTIAL`, old non-active Extraction, self-declared retrieval counts/truncation and foreign QuestionRun provenance;
- source scope unknown field/type mismatch, Folder traversal/Windows ADS-device path, Git revision expression and Site raw-prefix/encoded-separator bypass;
- torn-read stable version mismatch;
- retired signing key historical verification, revoked/multiple-active key rejection and audit checkpoint chain mismatch;
- stale external identity/group snapshot with fresh object ACL;
- real ModelRun from another question/candidate/context, generation output drift, model-profile hash drift and timestamp outside QuestionRun interval;
- changed number/date/currency/unit, `1200 USD` against `1200 EUR`, split date across citations, arbitrary literal span and numeric-validation TOCTOU;
- Russian and English compound dates/ranges as one numeric span, split-citation bypass, inference, borrowing global citations, and a number appearing in the direct FACT citation but missing in the canonical text/PASSED literals of the FACT itself;
- OCR geometry without contiguous token range, token/box count mismatch and incorrect join text;
- WORKSPACE_MANAGED without exact confirmation, SourceScope under another connection revision and trusted parser canonical-format mismatch;
- manifest corpus snapshot with two bindings, as well as missing, duplicate and extra scope;
- manifest with two citations from different source object/version/evidence and missing/duplicate/mismatched citation chain;
- Markdown link/image, autolink, raw HTML/entity, backtick and heading/list markers must yield exact escaped renderer output; newline/control and RTL-override must be rejected.
- model-controlled factual section title must be rejected by schema before renderer.
- stale live WorkspaceRevision/membership/binding/PolicyDecision, ambiguous grant path and zero-context with stale principal snapshot;
- reranker, receiving only final context instead of full candidate set, collapsed candidate/context counts, self-declared execution plan, unplanned attempt and snapshot/model-profile swap;
- WORKSPACE_MANAGED event from unknown connector build, trust-record mismatch, encrypted AAD type/field swap and change of full AuditEvent body with same hash;

Each fixture must have an expected error code. A test that checks only for 'failure' is insufficient.

## 10. Sandbox dispatcher contracts

`sandbox-job-v1`, `sandbox-lease-v1`, `sandbox-outcome-v1` and `sandbox-limit-confirmation-v1` record the inter-process boundary prior to runtime composition. Job does not provide container-creation capability; lease registers exactly one socket and the same parser type, while worker only retrieves the document. Handoff must distinguish retry before transfer from quarantine after transfer; a successful outcome requires a confirmed extraction identity. Transfer state matrix is mechanical: `CONFIRMED` pairs only with `SUCCEEDED` and a non-null identity, `RETRY` only with `FAILED` and null identity, and `QUARANTINED` only with `QUARANTINED` and null identity. Limits and sandbox identity are accepted only when the outcome matches a separate trusted kernel observation by lease/job/worker/time/identity and the canonical limits integrity hash. Unknown fields, self-reported limits, parser mismatch, deadline inversion and contradictory handoff state yield stable negative outcomes.

## 11. Operator contracts

`operator-failure-v1` requires a typed failure code, a closed code→action→metric registry, retryability, and a forbidden fallback. `operator-readiness-v1` separates liveness and readiness, allows only registered dependency names, and marks readiness as red when `UNAVAILABLE`/`INCOMPATIBLE` required dependency is missing. These schemas describe the future operator surface and do not assert that `knowvault-operator` is already built or available in production.
