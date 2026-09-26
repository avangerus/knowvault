# Encryption Boundary 1.0

Status: `ACCEPTED`. This document prohibits promising cryptographic tenant isolation where 1.0 provides logical isolation.

## 1. Honest contract

Reference on-edge deployment requires:

- customer-managed encryption of disks/volumes for PostgreSQL, OpenSearch, and ephemeral processing;
- encryption and access policy for customer backup/snapshot repository;
- TLS for all network hops, mTLS for Connector Agent;
- application envelope encryption for sensitive payloads that must not be indexed;
- secrets/signing private keys only in file-based mounted secrets (ADR-P1.11) and on-disk in an encrypted volume; external KMS/HSM is not a 1.0 requirement.

OpenSearch stores searchable text and vectors in a form accessible to the search engine. They are protected by encrypted volume/snapshot, process/network isolation, and policy, but not by per-organization application field encryption. PostgreSQL RLS and OpenSearch organization namespace provide logical tenant isolation, not a separate cryptographic key for each indexed document.

If the agreement requires that one organization CMK cryptographically isolates **all** its text/vectors/backups from other organizations, a separate data plane is allocated for this organization: separate PostgreSQL/OpenSearch instances, volumes, snapshot prefix/repository, and customer key. It is not possible to include the "CMK" flag in a shared index and consider the requirement fulfilled.

## 2. Application envelope encryption

Only the standard Go library is used: AES-256-GCM, 96-bit nonce from `crypto/rand`, a new nonce for each encryption under the given DEK. KEK is provided via a replaceable key-wrapping provider boundary: reference implementation on-edge 1.0 — purpose-typed mounted-secret KEK (ADR-0055), a future external-KMS adapter implements the same interface without changing the artifact/repository contract. DEK is generated from OS CSPRNG, wrapped by the provider into a versioned/authenticated wrapped DEK, and is never written in plaintext; raw KEK is not exposed to application code.

Persisted envelope:

```text
cipher = AES_256_GCM
ciphertext
size_bytes
nonce
wrapped_dek
kek_reference
kek_version
aad_hash
plaintext_hash
created_at
```

In 1.0, one artifact contains 1 to 8 MiB plaintext; AES-GCM ciphertext must have exactly `size_bytes + 16` bytes. Nonce has exactly 12 bytes, wrapped DEK — from 1 to 64 KiB. After content purge, ciphertext and wrapped DEK are deleted, but nonce and `wrapped_dek_hash` remain as a secure cryptographic tombstone. Database forbids repeating nonce across the entire `(organization, KEK reference, KEK version)`, not trusting caller-supplied wrapped-DEK hash as part of the uniqueness boundary.

AAD passes `architecture/contracts/encrypted-artifact-aad.schema.json` and is a JCS object of exact form:

```json
{
  "organization_id": "...",
  "owner_table": "question_run",
  "owner_column": "question_text_artifact_id",
  "resource_type": "QUESTION_RUN",
  "resource_id": "...",
  "field": "QUESTION_TEXT",
  "schema_version": "encrypted-artifact-aad-v1"
}
```

`resource_type` cannot be used as a general container for another type of data. The normative closed inventory of 28 owning columns is located directly in `oneOf` file `encrypted-artifact-aad.schema.json`; it must match one-to-one with all columns `*_artifact_id` in `DATA_MODEL.md`.

| owning table.column | resource_type / field | trusted resource_id |
|---|---|---|
| `external_identity.external_subject_artifact_id` | `EXTERNAL_IDENTITY / SUBJECT` | `external_identity.id` |
| `source_connection_revision.trust_profile_artifact_id` | `SOURCE_TRUST_CONFIG / TRUST_CONFIG` | canonical SourceConnectionRevision key |
| `source_discovery_result.metadata_artifact_id` | `SOURCE_DISCOVERY_RESULT / DISCOVERY_METADATA` | `source_discovery_result.id` |
| `source_discovered_scope.identity_artifact_id` | `SOURCE_SCOPE_IDENTITY / EXTERNAL_SCOPE_IDENTITY` | `source_discovered_scope.id` |
| `source_discovered_scope.display_metadata_artifact_id` | `SOURCE_SCOPE_METADATA / DISPLAY_METADATA` | `source_discovered_scope.id` |
| `source_scope_revision.scope_config_artifact_id` | `SOURCE_SCOPE_CONFIG / SCOPE_CONFIG` | canonical SourceScopeRevision key |
| `source_object.external_object_id_artifact_id` | `SOURCE_OBJECT_ID / EXTERNAL_OBJECT_ID` | `source_object.id` |
| `source_object.canonical_locator_artifact_id` | `SOURCE_LOCATOR / CANONICAL_LOCATOR` | `source_object.id` |
| `source_object.title_artifact_id` | `SOURCE_TITLE / DISPLAY_TITLE` | `source_object.id` |
| `acl_snapshot.principal_tokens_artifact_id` | `ACL_PRINCIPAL_SET / PRINCIPAL_TOKENS` | `acl_snapshot.id` |
| `evidence_fragment.normalized_text_artifact_id` | `EVIDENCE_TEXT / NORMALIZED_TEXT` | `evidence_fragment.id` |
| `evidence_fragment.anchor_artifact_id` | `EVIDENCE_ANCHOR / CANONICAL_ANCHOR` | `evidence_fragment.id` |
| `evidence_fragment.metadata_artifact_id` | `EVIDENCE_METADATA / METADATA` | `evidence_fragment.id` |
| `search_chunk.search_text_artifact_id` | `SEARCH_CHUNK_TEXT / NORMALIZED_TEXT` | `search_chunk.id` |
| `question_run.question_text_artifact_id` | `QUESTION_RUN / QUESTION_TEXT` | `question_run.id` |
| `question_run.answer_markdown_artifact_id` | `QUESTION_RUN / ANSWER_MARKDOWN` | `question_run.id` |
| `question_run.answer_structured_artifact_id` | `QUESTION_RUN / ANSWER_STRUCTURED` | `question_run.id` |
| `question_run.manifest_content_artifact_id` | `MANIFEST_CONTENT / CANONICAL_BYTES` | `question_run.id` |
| `question_authorized_candidate_set.canonical_artifact_id` | `AUTHORIZED_CANDIDATE_SET / CANONICAL_BYTES` | `question_run.id` |
| `question_model_execution_plan.canonical_artifact_id` | `MODEL_EXECUTION_PLAN / CANONICAL_BYTES` | `question_run.id` |
| `question_claim.text_artifact_id` | `CLAIM_TEXT / CLAIM_TEXT` | `question_claim.id` |
| `claim_deterministic_validation_artifact.output_artifact_id` | `DETERMINISTIC_VALIDATION / VALIDATION_OUTPUT` | canonical validation key |
| `question_citation.cited_excerpt_artifact_id` | `CITED_EXCERPT / EXACT_TEXT` | `question_citation.id` |
| `question_citation.anchor_artifact_id` | `CITATION_ANCHOR / CANONICAL_ANCHOR` | `question_citation.id` |
| `question_citation.deep_link_artifact_id` | `SOURCE_DEEPLINK / DEEPLINK` | `question_citation.id` |
| `model_run_artifact.input_artifact_id` | `MODEL_ARTIFACT / CANONICAL_INPUT` | `model_run.id` |
| `model_run_artifact.output_artifact_id` | `MODEL_ARTIFACT / CANONICAL_OUTPUT` | `model_run.id` |
| `question_feedback.comment_artifact_id` | `QUESTION_FEEDBACK / COMMENT_TEXT` | `question_feedback.id` |

One owning row and one owning column always yield one exact AAD tuple. An unused pair is forbidden, even if its `resource_type/field` looks plausible. Decrypt recalculates owner table/column, organization/resource ID, type, and field from the trusted repository mapping; none of these values are accepted from the ciphertext envelope or API. Copying ciphertext between tenants, rows, columns, or resource types must result in a GCM authentication error. `plaintext_hash` is required for integrity/provenance after an allowed purge/rotation and does not replace GCM authentication.

Envelope encryption is mandatory for:

- question text and answer body;
- cited excerpts and canonical manifest content bytes;
- normalized Evidence text and stored SearchChunk text outside OpenSearch;
- model canonical input/output artifacts;
- an answer-feedback free-text comment (`question_feedback.comment_artifact_id`); unlike the other branches above it is replaceable in place when the mark changes, not write-once.

Raw OCR/parser output in 1.0 is not persisted as a separate artifact: it exists only within the bounded worker job until normalization. Only the Evidence text/metadata/anchor, profile, and hashes extraction listed in the closed inventory are persistently stored. Adding raw extraction storage requires a new owning `*_artifact_id` column, AAD branches, a retention/purge contract, and acceptance tests before the first write.

In 1.0, ciphertext for each `encrypted_artifact` is stored only in PostgreSQL `bytea`/TOAST. Application-level cap on one artifact and aggregate retention limits are applied before insert; a large source object is split into independently encrypted bounded evidence artifacts. Clear plaintext is not materialized in a durable table. A separate S3/object-storage artifact backend is not a hidden option for 1.0: its addition requires an accepted ADR, a typed storage contract, a version/license lock, a tenant prefix policy, and purge/backup tests.

Metadata required for filtering/auditing (IDs, enums, timestamps, hashes, safe status) remains as typed columns and is protected by storage encryption/RLS. Title, path, email subject/addresses, and other potentially sensitive metadata are not allowed in logs; if a field is not required by a server-side filter, it is envelope-encrypted. Raw credentials, DSN, OID, privilege graph, and source rows never leave the worker boundary in the API or Model Gateway. Only a bounded sanitized semantic metadata projection may be passed to the Model Gateway under the active policy; native comments are untrusted data, not instructions.

External subjects, native object IDs, canonical locator/path, source title, scope/trust/discovery payload, anchors and deeplinks are stored as `encrypted_artifact`. For equality/index lookup, stored alongside is not a plain SHA, but an organization-scoped `HMAC-SHA-256` digest canonical value with `digest_key_version`; the raw value is not a typed column.

ACL/effective-principal token canonical form is encrypted for authorized resolution. PostgreSQL comparison and OpenSearch prefilter use only digest `hmac-sha256:k<version>:<lowercase-hex>` from JCS `{namespace,type,subject,revision}`. Index document contains digest key version, but not email/group/source subject. Key material is located in file-based mounted secret (ADR-P1.11) and differs from envelope KEK. Rotation builds a staged dual-digest/index projection, replays mutations up to the watermark, atomically switches the active digest version, and only then removes old digests; unknown version fails closed.

## 3. OpenSearch and snapshots

The OpenSearch index contains only the current queryable Evidence projection, including searchable text/vector. Mandatory:

- encrypted customer volume and encrypted snapshot repository;
- TLS and service identity; browser/connector do not access OpenSearch directly;
- organization filter, exact scope/ACL prefilter and DB post-authorization;
- `_source`/stored fields are minimized; secret, OAuth token, model input and original binary are prohibited;
- snapshot prefix/repository access does not cross the deployment boundary;
- delete/purge reconciliation checks both live index and snapshots according to the retention policy.

The application does not declare per-row CMK for shared OpenSearch. Separate-data-plane mode is the only mode for full per-organization CMK.

## 4. Keys, rotation and restore

- Key references/version are stored; key material is not.
- Envelope rotation creates a new ciphertext under a new key version and atomically switches the reference; plaintext/old DEK do not remain in log/temp/backup.
- Volume/snapshot key rotation is performed by the customer platform and confirms the restore test.
- Operator backup writes one encrypted bundle (ADR-0070 §1.5): the DEK is sealed with a separate recovery key, which is stored outside the bundle; the bundle does not contain source binaries, clear DEK, recovery-key material, or signing private key.
- Restore without the correct recovery key must fail closed with a typed error (missing key — invalid, wrong/tampered — failed); use of a recovery key from another organization does not allow partial restoration (denied until decryption).
- Hard-delete of an organization removes envelopes/index/snapshots according to the retention contract and destroys or revokes the organization key when it is not shared.

## 5. Poka-yoke

1. Cannot create a sensitive artifact without encryption metadata and AAD.
2. Nonce uniqueness is verified via unique `(organization_id, kek_reference, kek_version, nonce)` and does not trust caller-supplied hash.
3. Decrypt API always requires server-created `AuthorizedContext` and expected resource identity.
4. Plaintext is forbidden in audit/application logs, job payload, and dead letter.
5. OpenSearch deployment without a confirmed encrypted volume/snapshot does not receive readiness.
6. Backup/restore test is a mandatory restore drill: negative checks (missing key, wrong key, tampered bundle) before restoration and measurement of NFR-B2 window (≤2 h); ciphertext swap is covered by separate ciphertext-swap tests (item 9).
7. UI/admin API distinguishes `storage encrypted`, `application envelope encrypted`, and `separate CMK data plane`; a single label "encrypted" is forbidden.
8. Raw source identity, path, title, anchor, deeplink, or ACL principal are forbidden in OpenSearch stored fields, audit, logs, and unencrypted PostgreSQL columns.
9. Repository accepts only the exact permissible pair `resource_type + field`; general `BLOB`, type substitution, and reuse of ciphertext between two rows are forbidden by schema and ciphertext-swap tests.
