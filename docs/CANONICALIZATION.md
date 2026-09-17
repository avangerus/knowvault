# Canonization, offsets, hashes and signatures 1.0

Notation: Cyrillic source literals and fixed renderer text use standard `\uXXXX` escapes in this English document. Decode them before comparing runtime text or UTF-8 bytes; this notation does not change the canonicalization or renderer version.

Status: `ACCEPTED`. This document is part of the security boundary.

## 1. Canonical text `text-v1`

Before creating EvidenceFragment, the text passes through a fixed order:

1. decode the declared source encoding with error on ambiguity;
2. remove the single initial Unicode BOM;
3. translate `CRLF` and single `CR` to `LF`;
4. full Unicode normalization form NFC via exact `golang.org/x/text/unicode/norm` from version lock; separate character tables and partial manual composition are forbidden;
5. preserve all other spaces and line breaks without collapse;
6. encode UTF-8 without BOM.

`normalized_text_hash` — organization-scoped HMAC-SHA-256 of canonical UTF-8 bytes in the form `hmac-sha256:k<version>:<hex>` with mandatory `text_digest_key_version` (ADR-0077; plain `sha256:` for Evidence content is not accepted by the schema). Each fragment stores `normalization_version = text-v1`.

## 2. Text offsets

All text offsets are measured in **canonical UTF-8 text bytes**:

```text
offset_unit = UTF8_BYTE
start inclusive
end exclusive
0 <= start < end <= len(canonical UTF-8 bytes)
```

Start and end must fall on the boundary of a UTF-8 code point. UTF-16 code units, Unicode code-point indexes, and grapheme indexes are prohibited.

Golden fixtures must contain Cyrillic, emoji, NFC/NFD, CRLF/LF, and combining marks.

### 2.1. Full TEXT read and preservation of gaps

Line-range anchor excludes LF, terminating the last line of the fragment.
`text-v1`, fragment bytes and anchor geometry remain unchanged.
New TEXT-stream extractions use a separate parser-profile revision `<base>-layout-v2` and preserve encrypted `EvidenceMetadata` exact form:

```text
schema = text-fragment-layout-v2
normalization_version = text-v1
parser_profile_revision
ordinal
line_start, line_end
canonical_byte_start, canonical_byte_end
gap_after_base64
canonical_total_bytes
canonical_sha256
```

All fields are mandatory. Offsets are semi-open UTF-8 byte offsets of the full canonical buffer; `gap_after_base64` — exact LF bytes between the end of the fragment and the start of the next, including the document's final LF. Full length and SHA-256 are repeated in all fragments within encryption; plain hash is not added as an index or equality projection to the database. The generator computes the hash from one full canonical buffer before its removal.

Reader opens text, anchor, and metadata through the same current rights and retention check. It verifies ordinals, range and interval continuity, profile/total/hash matching, anchor geometry, and final bytes/hash. Absence, mixing, or contradiction of data closes reading without a partial result. `CANONICAL_TEXT_V1_LAYOUT_V2` is issued only after these checks.

Old extractions preserve bytes and addresses, return the previous concatenation as `LEGACY_FRAGMENT_CONCAT_V1`; equality of such an assembly to the full canonical input is not asserted. Upgrade creates new immutable extraction/fragment IDs. Structured Office/PDF/EML/OCR remain assemblies of individual structural fragments until a separate contract defines the full canonical container artifact. `whole_hash` is always the hash of the actually returned assembly.

The completed question context stores extraction, active at the moment of authorization.
Its `active_extraction_id` is FK-linked to immutable `source_extraction(organization_id, source_version_id, id)` and does not hold a mutable active pointer row (migration 000105). On a new INSERT and upon response completion, the live active pointer, activation revision, permissions, and retention are still checked; this change does not allow capturing an outdated context. Saved context rows and manifest remain unchanged after extraction change.

## 3. Structural anchors

- PDF: page 1-based; bounding boxes in PDF points after applying page rotation, origin top-left, within crop box.
- DOCX: `section_path` — non-empty array of NFC strings from root to leaf; `paragraph_id` — native ID or deterministic derived ID. If native ID is absent, canonical paragraph bytes pass through `text-v1`, then `paragraph_text_hash` is computed, and the ID equals `derived:sha256:<hex>` from the JCS object in exact form:

```json
{
  "normalization_version": "text-v1",
  "paragraph_ordinal": 1,
  "paragraph_text_hash": "sha256:...",
  "section_path": ["\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442", "\u0420\u0430\u0437\u0434\u0435\u043b 1"]
}
```

`paragraph_ordinal` 1-based within the last section. Native ID must have the form `native:<safe-opaque-value>`; unsafe native ID connector encodes as base64url without padding.
- PPTX: slide 1-based + stable shape ID + UTF-8 byte range of text shape.
- XLSX: sheet + one A1 cell or normalized inclusive A1 range; reversed range is forbidden.
- Email: immutable message ID + MIME part ID + UTF-8 byte range of canonical body part.
- Git/Text: line numbers 1-based inclusive; `line_end >= line_start`; Git path slash-normalized, relative, without `.`/`..` traversal.
- HTML: canonical in-scope URL + DOM path + UTF-8 byte range of canonical node text.
- OCR: page 1-based, for a single image page=1; boxes in normalized coordinate space `0..1`, origin top-left.

Anchor resolver checks the existence of a structural element, range bounds, exact excerpt, and hash. JSON Schema checks the form, and an executable validator checks value relationships.

### 3.1. Canonical source locator

Connector `canonical_locator_hash` equals SHA-256 of a JCS object in one of the following exact forms and protects the signed transport event. After ingest, the raw locator/event artifact is stored envelope-encrypted, and DB equality/uniqueness uses organization-scoped `canonical_locator_digest = HMAC-SHA-256(key_version, JCS(locator))`; plain SHA is not used as a public lookup key. The locator identifies a logical object, so version-specific fields, including Git commit SHA, ETag, and content hash, are not included in it.

```json
{"connection_id":"...","kind":"FILE","relative_path":"projects/alpha/spec.docx"}
```

```json
{"branch":"main","connection_id":"...","kind":"GIT_FILE","path":"src/auth.go","provider":"GITHUB","repository":"org/repo"}
```

```json
{"connection_id":"...","immutable_message_id":"...","kind":"EMAIL","mailbox_id":"..."}
```

```json
{"connection_id":"...","kind":"EMAIL_ATTACHMENT","mime_part_id":"2.1","parent_message_external_object_id":"..."}
```

```json
{"canonical_url":"https://docs.example.com/product?a=1","connection_id":"...","kind":"WEB_PAGE"}
```

FILE `relative_path` is defined relative to the immutable root of the connection itself, not relative to a specific scope. FILE and GIT paths are translated from `\\` to `/`, normalized to NFC, and must be relative without an empty segment, `.`/, `..`, NUL, or control characters. Case is preserved; a connector for a case-insensitive source must return the actual canonical case and reject a collision of two objects with the same case-folded path.

WEB URL must be absolute `http`/`https`: scheme and ASCII/punycode host are converted to lowercase, default port is removed, userinfo and fragment are forbidden, dot segments are removed, empty path becomes `/`, percent escapes are converted to uppercase hex, percent-encoded unreserved characters are decoded. Order and duplicates of query parameters are preserved. IDN connector passes the already-verified ASCII punycode host; hidden URL loading from content is forbidden.

Hash is recorded as `sha256:<64 lowercase hex>`. Server recalculates it from typed metadata and trusted `connection_id`; the connector-provided value itself is not proof of identity.

## 4. Canonical JSON `json-v1`

Event, manifest, and signature payload are serialized according to RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8, without BOM and trailing newline.

Reference implementation for 1.0 — standard `encoding/json/jsontext.Value.Canonicalize` from exact Go 1.26.5, built only with `GOEXPERIMENT=jsonv2`. The experimental API is intentionally accepted with an immutable toolchain; its absence blocks the build. Before canonicalization, the decoder operates in RFC 7493/I-JSON mode: duplicate object names, invalid UTF-8, lone surrogates, and non-finite numbers are rejected. All numeric fields in canonical contracts are limited to safe integer bounds `abs(n) <= 2^53-1`; large IDs/hashes are transmitted as strings.

```text
hash = sha256:<lowercase hex SHA-256(canonical JSON bytes)>
```

Fields are excluded only where the corresponding contract explicitly specifies this. Unknown fields are forbidden by the schema prior to canonicalization. Arrays representing sets are sorted by the key specified below before hashing; arrays representing order are not sorted.

## 5. Question request hash

Question text is canonized as `text-v1`, then only leading/trailing Unicode whitespace is removed. Internal whitespace is not collapsed.

Request hash is calculated from the JCS object:

```json
{
  "workspace_id": "...",
  "workspace_revision": 1,
  "question_text": "..."
}
```

Organization and actor are in the idempotency namespace and are not accepted from the request body.

## 6. Scope and access hashes

`scope_config_hash` is considered from the JCS object in the following exact form:

```json
{
  "source_scope_id": "...",
  "revision": 1,
  "connection_id": "...",
  "connection_revision": 1,
  "external_scope_id": "...",
  "source_type": "FOLDER",
  "access_mode": "WORKSPACE_MANAGED",
  "content_freshness_sla_seconds": 600,
  "acl_freshness_sla_seconds": 900,
  "sync_interval_seconds": 300,
  "object_limit": 100000,
  "byte_limit": 10737418240,
  "scope_config": {}
}
```

`workspace_scope_hash` is considered from JCS object:

```json
{
  "workspace_id": "...",
  "workspace_revision": 1,
  "bindings": [
    {
      "source_scope_id": "...",
      "source_scope_revision": 1,
      "scope_config_hash": "sha256:...",
      "enabled": true
    }
  ]
}
```

`bindings` are sorted by Unicode code-point order of fields `source_scope_id`; duplicate ID is prohibited.

Canonical binding intentionally does not contain a mutable confirmation ID. The stable `workspace_source_id` is stored in the exact `workspace_revision_source` relation and is uniquely derived for the canonical tuple via tenant/workspace/revision and the unique `source_scope_id`; confirmation separately records this ID and the entire tuple. Adding the binding ID to canonical bytes would require a new version `workspace-configuration`, not a hidden change to v1.

`WORKSPACE_MANAGED` confirmation is not a configuration of the reusable scope and does not fall into `scope_config_hash` or `workspace_scope_hash`. It is attached server-side as a separate live authority relation only after an exact-match with a specific `WorkspaceRevision` and its enabled binding. Canonical workspace/scope bytes are never overwritten upon confirmation or revocation.

`confirmation_actor_grant_hash` is computed from an immutable JCS object:

Only for authority contracts in this section, timestamps have canonical form `authority-timestamp-v1`: UTC RFC 3339 `YYYY-MM-DDTHH:MM:SSZ`, mandatory seconds, exactly four digits for the year, no fractional seconds, no leap second, and no offset different from `Z`. The parser must parse and serialize back to the exact same bytes.

```json
{
  "schema_version": "workspace-source-confirmation-grant-v1",
  "grant_id": "...",
  "revision": 1,
  "organization_id": "...",
  "workspace_id": "...",
  "principal_id": "...",
  "permission": "workspace.source.confirm",
  "valid_from": "2026-07-16T10:00:00Z",
  "valid_until": "2026-07-17T10:00:00Z",
  "policy_revision": "policy-...",
  "granted_by": "...",
  "granted_at": "2026-07-16T09:55:00Z"
}
```

Grant identity is always an exact tuple `(grant_id, revision, confirmation_actor_grant_hash)`. Equal principal/workspace/permission without equal ID, revision, and hash do not replace the grant. A grant is suitable for confirmation only if `granted_at <= valid_from <= confirmed_at < valid_until`, its separate append-only revocation is absent on `confirmed_at`, and the policy revision remains exact. Revocation of the grant acts as a kill-switch for all confirmations that reference it; expiration of `valid_until` prohibits new confirmations but, by itself, does not overwrite the already created immutable record.

`warning_contract_hash` for the first version is computed from a registry-owned JCS object. `risk_codes` are a set and are sorted by Unicode code-point order before hashing; unknown or duplicate codes are prohibited:

```json
{
  "schema_version": "workspace-managed-warning-contract-v1",
  "warning_version": "workspace-managed-risk-v1",
  "access_mode": "WORKSPACE_MANAGED",
  "risk_codes": [
    "SOURCE_NATIVE_ACL_NOT_ENFORCED",
    "WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"
  ],
  "acknowledgement_code": "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
}
```

Registry bytes and the expected hash are server-owned protected contract;
request cannot propose its own warning object or localized text.

`workspace_managed_confirmation_hash` is computed from an immutable JCS object:

```json
{
  "schema_version": "workspace-managed-confirmation-v1",
  "confirmation_id": "...",
  "organization_id": "...",
  "workspace_id": "...",
  "workspace_revision": 7,
  "workspace_configuration_hash": "sha256:...",
  "workspace_source_id": "binding_...",
  "source_scope_id": "scope_...",
  "source_scope_revision": 3,
  "scope_config_hash": "sha256:...",
  "access_mode": "WORKSPACE_MANAGED",
  "confirmation_actor_grant_id": "...",
  "confirmation_actor_grant_revision": 1,
  "confirmation_actor_grant_hash": "sha256:...",
  "warning_version": "workspace-managed-risk-v1",
  "warning_contract_hash": "sha256:...",
  "acknowledgement_code": "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",
  "confirmed_by": "...",
  "confirmed_at": "2026-07-16T10:05:00Z",
  "policy_revision": "policy-..."
}
```

`confirmed_by` requires an exact-match principal actor grant. Warning version, its canonical contract hash, and its closed acknowledgement code are included in the command's request hash and the confirmation hash; localized UI text is not authority.
Both revocation relations are also immutable canonical records;
`confirmation_actor_grant_revocation_hash` and
`workspace_managed_confirmation_revocation_hash` are computed respectively from the following exact objects:

```json
{
  "schema_version": "workspace-source-confirmation-grant-revocation-v1",
  "revocation_id": "...",
  "organization_id": "...",
  "grant_id": "...",
  "grant_revision": 1,
  "grant_hash": "sha256:...",
  "revoked_by": "...",
  "revoked_at": "2026-07-16T11:00:00Z",
  "reason_code": "AUTHORITY_REVOKED",
  "policy_revision": "policy-..."
}
```

```json
{
  "schema_version": "workspace-managed-confirmation-revocation-v1",
  "revocation_id": "...",
  "organization_id": "...",
  "confirmation_id": "...",
  "confirmation_hash": "sha256:...",
  "revoked_by": "...",
  "revoked_at": "2026-07-16T11:00:00Z",
  "reason_code": "ACCESS_REVOKED",
  "policy_revision": "policy-..."
}
```

Their hashes are computed using the same JCS/SHA-256 rules. Revocation exact-match
references the immutable parent ID and hash, acts monotonically with `revoked_at` and
is never replaced by restoration or `UPDATE`. Grant revocation requires
`granted_at <= revoked_at`; confirmation revocation requires
`confirmed_at <= revoked_at`.
The current state `CONFIRMED|REVOKED|STALE` is computed via a join of immutable
confirmation, append-only confirmation/grant revocations, current policy and
exact current workspace binding. It is not stored as a mutable confirmation field.
For an exact tuple `(organization_id, workspace_id, workspace_revision,
workspace_configuration_hash, workspace_source_id, source_scope_id,
source_scope_revision, scope_config_hash, policy_revision, warning_version,
warning_contract_hash)`, there can be at most one unrevoked
derived-live confirmation. A deferred validator under the same workspace row lock
calculates the live set using both revocation relations and rejects an ambiguous join.
A revoked confirmation can be replaced only by a new command with a new ID;
revocation of one confirmation does not affect another if they do not reference
the same explicitly revoked actor grant.

In all canonical objects of this section, the string `policy_revision` is an opaque immutable ID from `organization_policy_revision`, not a textual representation of a numeric counter. Persistence additionally stores a monotonic `policy_revision_number`; the exact registry tuple `(organization_id, number, ID, policy_hash)` is the authority, but number and policy hash are not added to already defined external JCS objects. Implicit padding/formatting of numbers is forbidden.

`access_context_hash` is considered from JCS object:

```json
{
  "organization_id": "...",
  "human_principal_id": "...",
  "workspace_id": "...",
  "workspace_revision": 1,
  "workspace_role": "MEMBER",
  "policy_revision": "...",
  "principal_set_snapshot_id": "...",
  "principal_set_snapshot_hash": "sha256:...",
  "principal_set_captured_at": "...",
  "principal_set_expires_at": "...",
  "effective_principals": [
    {
      "namespace": "oidc:issuer-hash|source:connection-id",
      "type": "USER|GROUP|SERVICE|SPECIAL",
      "subject_digest": "hmac-sha256:k7:...",
      "revision": "..."
    }
  ]
}
```

`effective_principals` are sorted lexicographically by tuple `(namespace, type, subject_digest, revision)` and contain no duplicates. Namespace and digest cannot be empty; raw subject in access context is forbidden. Source-native ACL token uses organization-scoped HMAC digest exact canonical raw token per `ENCRYPTION.md`, not plain ID or concatenated string. All entries/revisions exact-match trusted immutable `principal_set_snapshot`; its canonical `content_hash` is derived from JCS object `{"human_principal_id":"...","identity_provider_revision":"...","session_revision":7,"digest_key_version":7,"effective_principals":[...]}`. Snapshot must have `RESOLVED`, `captured_at <= authorized_at < expires_at`; any identity/group/digest-key revision change invalidates it and access cache.

`acl_snapshot.content_hash` is considered from JCS object `{"status":"...","digest_key_version":7,"principal_token_digests":[...]}`. Digests are pre-sorted by the same tuple order; raw tokens are stored envelope-encrypted, and `resolved_at` and `expires_at` are not included in the permission-set hash and are stored separately as freshness metadata.

### 6.1. Workspace-managed authority command envelope

Four authority commands `WORKSPACE_CONFIRMATION_GRANT_ISSUE`, `WORKSPACE_CONFIRMATION_GRANT_REVOKE`, `WORKSPACE_MANAGED_CONFIRM`, and `WORKSPACE_MANAGED_CONFIRM_REVOKE` use one closed canonical envelope:

```json
{
  "schema_version": "workspace-managed-authority-command-v1",
  "operation": "WORKSPACE_MANAGED_CONFIRM",
  "request": {}
}
```

The request hash is calculated as `sha256:` of the exact JCS bytes of the entire envelope.

The envelope and each request are closed: any unknown or extraneous field at any level, nullable/missing alias, free-form metadata/map, or integer outside the safe range `abs(n) <= 2^53-1` are rejected as `WORKSPACE_AUTHORITY_REQUEST_INVALID` prior to any authorization. The Authority receipt namespace is `(organization_id, actor_principal_id, idempotency_key_hash)`, where `organization_id` is always trusted `AccessContext.OrganizationID`, and not a field `request.organization_id`. Request field `organization_id` is included in canonical bytes and the request hash like any other field, but never selects the tenant: prior to any tenant-scoped access, it is exact-matched against `AccessContext.OrganizationID`, while namespace, `database.Write`, RLS context, `receipt.organization_id`, and `audit.organization_id` are taken exclusively from trusted `AccessContext`. A mismatch terminates `WORKSPACE_AUTHORITY_NOT_FOUND` before any workspace/target/grant/confirmation/binding/policy/warning lookup.

The raw Idempotency-Key is not included in the envelope and is never persisted—only its SHA-256 is persisted. Substitution of `operation` with an unchanged request changes the request hash, since the hash covers the entire envelope.

`WORKSPACE_CONFIRMATION_GRANT_ISSUE` request:

```json
{
  "organization_id": "...",
  "workspace_id": "...",
  "expected_workspace_revision": 7,
  "expected_workspace_configuration_hash": "sha256:...",
  "target_principal_id": "...",
  "ttl_seconds": 3600,
  "expected_policy_revision": "policy-..."
}
```

`ttl_seconds` — integer from 60 to 86400 inclusive. Server derives from a single PostgreSQL transaction-second: grant ID, revision `1`, permission `workspace.source.confirm`, `granted_by`, `granted_at`, `valid_from = granted_at`, `valid_until = granted_at + ttl_seconds`, and canonical grant hash from `workspace-source-confirmation-grant-v1`. Client cannot pass any of these fields.

`WORKSPACE_CONFIRMATION_GRANT_REVOKE` request:

```json
{
  "organization_id": "...",
  "workspace_id": "...",
  "grant_id": "...",
  "grant_revision": 1,
  "grant_hash": "sha256:...",
  "expected_policy_revision": "policy-..."
}
```

Server-owned: revocation ID, `revoked_by`, `revoked_at`, reason code
`AUTHORITY_REVOKED` and canonical revocation hash. Expected WorkspaceRevision
is intentionally absent: stale grant must remain revocable, therefore
access reduction does not depend on fresh optimistic configuration
precondition.

`WORKSPACE_MANAGED_CONFIRM` request:

```json
{
  "organization_id": "...",
  "workspace_id": "...",
  "workspace_revision": 7,
  "workspace_configuration_hash": "sha256:...",
  "workspace_source_id": "binding_...",
  "source_scope_id": "scope_...",
  "source_scope_revision": 3,
  "scope_config_hash": "sha256:...",
  "access_mode": "WORKSPACE_MANAGED",
  "confirmation_actor_grant_id": "...",
  "confirmation_actor_grant_revision": 1,
  "confirmation_actor_grant_hash": "sha256:...",
  "warning_version": "workspace-managed-risk-v1",
  "warning_contract_hash": "sha256:...",
  "acknowledgement_code": "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",
  "expected_policy_revision": "policy-..."
}
```

Server-owned: confirmation ID, `confirmed_by`, `confirmed_at` and canonical confirmation hash by `workspace-managed-confirmation-v1`. Warning body, `risk_codes`, localized warning text and arbitrary acknowledgement are forbidden; only server-owned `warning_version`, canonical `warning_contract_hash` and closed acknowledgement code from `workspace-managed-warning-contract-v1` registry are accepted.

`WORKSPACE_MANAGED_CONFIRM_REVOKE` request:

```json
{
  "organization_id": "...",
  "workspace_id": "...",
  "confirmation_id": "...",
  "confirmation_hash": "sha256:...",
  "expected_policy_revision": "policy-..."
}
```

Server-owned: revocation ID, `revoked_by`, `revoked_at`, reason code
`ACCESS_REVOKED` and canonical revocation hash. Current WorkspaceRevision
precondition is absent; the mandatory precondition is exact historical
parent ID and hash.

In all four requests `expected_policy_revision` — opaque immutable `policy_revision_id`; numeric ordinal, formatted string counter, or hash in its place are rejected. Golden JCS vectors for all four operations are anchored in `tests/contracts/fixtures/golden/workspace-managed-authority-command-jcs.json` and must match byte-for-byte with the canonical form of fixtures; semantically equivalent JSON with different encoding is not accepted as golden canonical bytes.

### 6.2. Source connection trust verify (ADR-0087 §2)

`VerifyConnectionTrust` (`internal/workspace/repository/trust_verify.go`,
migration `000057` + `000059`) — CONNECTOR_ADMIN-gated `DRAFT → VERIFIED` for
`source_connection_trust_projection` — uses three closed JSON documents,
following the form of §6.1, but not sharing with it either the authority-namespace or
the receipt table: this is an organization/connection-scoped command with mandatory
attestation instead of a workspace-revision optimistic precondition, and not one of
the four ADR-0053 operations.

Request (canonical envelope, included in request hash, never persisted entirely):

```json
{
  "schema_version": "source-connection-trust-verify-request-v1",
  "operation": "VERIFY_TRUST",
  "connection_id": "conn_...",
  "attested_connector_identity": "...",
  "attested_by": "...",
  "attested_at": "2026-09-06T12:00:00Z"
}
```

Schema: `architecture/contracts/source-connection-trust-verify-request.schema.json`.
Closed object: an unknown field or an empty or missing attestation (`attested_connector_identity`, `attested_by`, `attested_at`) is rejected. Raw Idempotency-Key never enters the envelope; only its SHA-256 persists (namespace — `(organization_id, actor_principal_id, idempotency_key_hash)` on `public.source_connection_trust_verification`, separate from the authority receipt in §6.1).

Result (closed REST/MCP response and repeats with the same key):

```json
{ "result_id": "wctv_...", "result_hash": "sha256:..." }
```

Schema: `architecture/contracts/source-connection-trust-verify-result.schema.json`.
Does not carry any connector identity, nor attestation text, nor timestamp — they live only in the canonical document below.

The canonical document (`connectionTrustVerifyDocument`, `source-connection-trust-verify-v1`)
is the document whose RFC 8785 JCS hash becomes `result_hash`; it is stored beside the receipt
(`source_connection_trust_verification.canonical_hash`), but is not included in the audit
event in full — only `trust_verification_id`/`trust_verification_hash` appear in
metadata:

```json
{
  "schema_version": "source-connection-trust-verify-v1",
  "verification_id": "wctv_...",
  "organization_id": "...",
  "connection_id": "conn_...",
  "attested_connector_identity": "...",
  "attested_by": "...",
  "attested_at": "2026-09-06T12:00:00Z",
  "verified_by": "usr_...",
  "verified_at": "2026-09-06T12:00:01Z"
}
```

Schema: `architecture/contracts/source-connection-trust-verify.schema.json`.
`verified_by`/`verified_at` — server-owned; the client cannot transfer them.

Two independent layers verify attestation completeness (POKA_YOKE.md s1):
`VerifyConnectionTrustRequest.valid()` (Go) rejects empty/incomplete attestation before opening the transaction, while `app.source_connection_trust_verify`
(SECURITY DEFINER, migration `000059`) rejects it (`ERRCODE 23514`)
independently of Go — a direct SQL call as a runtime role, bypassing the product surface, also requires full attestation. Separation of duty (ADR-0087 §2): the same principal cannot simultaneously be a trust verifier (CONNECTOR_ADMIN) and a confirming (`confirmed_by`) `WORKSPACE_MANAGED`
'binding' of a scope belonging to the verifiable connection — this is checked within the same SECURITY DEFINER function, using the same content-free `ERRCODE 42501`,
as is the check for the CONNECTOR_ADMIN role (indistinguishable to the caller).

## 7. Context pack and answer

`SourceExtraction.profile_hash` is considered an exact form from the JCS object:

```json
{
  "canonical_format": "PDF",
  "extractor": {
    "name": "...",
    "version": "...",
    "artifact_hash": "sha256:...",
    "parser_profile_revision": "..."
  },
  "normalization_version": "text-v1",
  "ocr": null
}
```

`canonical_format` is selected by the trusted parser after media signature/sniffing and is not re-extracted from mutable MIME during citation. If OCR is used, `ocr` has the exact form `{"model_id":"...","model_revision":"...","artifact_hash":"sha256:...","profile_revision":"..."}`. Status, timestamps, and tenant IDs in the profile hash are not included.

`SourceExtraction.evidence_set_hash` is considered from the JCS array, sorted by `ordinal`, with exact objects `{"evidence_fragment_id":"...","ordinal":1,"evidence_text_hash":"hmac-sha256:k<version>:...","anchor_hash":"hmac-sha256:k<version>:..."}`. After terminal `SUCCEEDED` profile and evidence set are immutable.

Context pack hash is computed from the ordered JCS array with `evidence_fragment_id`, `source_version_id`, `extraction_id`, `extraction_profile_hash`, `source_version_content_hash`, `evidence_text_hash`, `anchor_hash`, and `exact_context_hash`. The order is the final reranker order; `evidence_fragment_id` is unique after retrieval deduplication. `EvidenceFragment` has one canonical exact anchor/excerpt and creates no more than one citation number in Answer; several claims reuse this citation number. Another exact excerpt/anchor is a different EvidenceFragment of the same Extraction. Search chunk may cover multiple EvidenceFragment at the same time.

### 7.0. Answer mode and extractive projection

`answer_mode` and `verification_method` are included in the signed top-level Answer Manifest. Only the following pairs are allowed:

| `answer_mode` | `verification_method` | model profiles/runs |
|---|---|---|
| `EXTRACTIVE` | `BYTE_EXACT_CITATION` | generation and verification are prohibited |
| `GENERATIVE` | `SEMANTIC_VERIFIER` | allowed only after a separate model/AIBOM gate |

In `EXTRACTIVE` mode, claim is a server-owned deterministic projection of a signed organization/workspace-scoped authorization snapshot and its exact context. For each published FACT, exactly one citation number is allowed; its `claim_id` and citation mapping are symmetric. After applying `text-v1` canonicalization, UTF-8 bytes `claim.text` and `citation.cited_excerpt` must be identical. Line breaks are forbidden, and the length of each sentence citation does not exceed 2000 UTF-8 bytes. UNKNOWN does not create a citation and retains only server-owned typed reason.

In extractive plan `authorized_context_hash` and equality-fields `text_hash`/`anchor_hash` have
organization-scoped HMAC-SHA-256 form `hmac-sha256:k<version>:<hex>`. Plain
SHA `candidate_set_integrity_hash` is allowed only as internal proof of integrity of trusted snapshot; it is not a public content/equality
projection and cannot replace HMAC digest.

The extractive trusted snapshot is bound to a signed catalog: the validator
recomputes the canonical catalog-entry integrity hash, the keyed candidate-set
digest, and both catalog and snapshot HMAC signatures. Every candidate is then
compared byte-for-byte with the catalog entry for its evidence fragment, and
the source object/version/extraction/anchor projection is keyed from that
trusted entry. Any mismatch is a typed rejection; a plan cannot manufacture
its own authorization catalog or HMAC value.

This rule is not a general semantic check relaxation: literal equality replaces the verifier only in `EXTRACTIVE` mode. In `GENERATIVE` mode, §7.1, verifier-output, and model execution-plan rules apply; the absence of a generative runtime cannot be hidden by changing the mode in the manifest.

`retrieval.authorization_snapshot_hash` equals SHA-256 JCS persisted `retrieval-authorization-v1` object of exact shape:

`retrieval_profile.profile_hash` equals the SHA-256 JCS object of exact shape; config values below are an example of typed shape, but are always present:

```json
{
  "schema_version": "retrieval-profile-v1",
  "profile_revision": "...",
  "implementation_artifact_hash": "sha256:...",
  "analyzer_revision": "...",
  "analyzer_config_hash": "sha256:...",
  "embedding_profile_hash": "sha256:...",
  "reranking_profile_hash": "sha256:...",
  "lexical": {"candidate_limit":50,"bm25_k1":1.2,"bm25_b":0.75},
  "vector": {"candidate_limit":50,"similarity":"COSINE","ef_search":128},
  "fusion": {"method":"RRF","rrf_k":60,"tie_break":"EVIDENCE_ID_ASC"},
  "reranking": {"candidate_limit":100,"output_limit":30},
  "context": {"max_evidence":30,"token_budget":24000,"parent_expansion":"ONE_LEVEL","source_diversity_limit":12}
}
```

Analyzer/index mapping exact-match config hash, model profile hashes exact-match selected profiles, all limits/tie-breakers server-owned. Changing code/analyzer/top-k/RRF/expansion/budget/diversity creates a new profile revision/hash. Label `pipeline_version` without this hash is not provenance.

```json
{
  "schema_version": "retrieval-authorization-v1",
  "question_run_id": "...",
  "captured_at": "...",
  "pipeline_version": "...",
  "pipeline_profile_hash": "sha256:...",
  "embedding_model_run_id": "...",
  "embedding_output_hash": "sha256:...",
  "authorized_candidate_set_hash": "sha256:...",
  "reranking_model_run_id": "...",
  "reranking_output_hash": "sha256:...",
  "authorized_candidate_count": 40,
  "context_count": 30,
  "truncated": false,
  "truncation_reason": null,
  "error_codes": [],
  "entries": []
}
```

`error_codes` are sorted by Unicode code-point order. `entries` has exactly one object for each final context evidence in the same order, with a continuous `ordinal` starting from 1:

```json
{
  "ordinal": 1,
  "source_object_id": "...",
  "source_version_id": "...",
  "source_version_state": "CURRENT",
  "source_version_retention_state": "ACTIVE",
  "source_version_queryable": true,
  "source_version_retention_fence": 7,
  "extraction_id": "...",
  "active_extraction_id": "...",
  "activation_revision": 3,
  "extraction_retention_state": "ACTIVE",
  "extraction_queryable": true,
  "extraction_retention_fence_at_start": 7,
  "evidence_fragment_id": "...",
  "extraction_profile_hash": "sha256:...",
  "source_version_content_hash": "sha256:...",
  "evidence_text_hash": "hmac-sha256:k<version>:...",
  "anchor_hash": "hmac-sha256:k<version>:...",
  "exact_context_hash": "sha256:...",
  "grant": {
    "source_scope_id": "...",
    "source_scope_revision": 2,
    "access_mode": "WORKSPACE_MANAGED",
    "membership_state": "ACTIVE",
    "policy_decision_id": "...",
    "policy_decision": "ALLOW",
    "principal_set_snapshot_id": "...",
    "principal_set_snapshot_hash": "sha256:...",
    "principal_set_captured_at": "...",
    "principal_set_expires_at": "...",
    "authorized_at": "...",
    "acl_snapshot_id": null,
    "acl_snapshot_hash": null,
    "acl_snapshot_status": null,
    "acl_resolved_at": null,
    "acl_expires_at": null
  }
}
```

No single field `grant` is proof in itself. Capture and terminal validator exact-match read four trusted live projections:

1. `workspace_revision_source`: the current Workspace revision equals the QuestionRun revision; binding exact `(workspace_id, workspace_revision, source_scope_id, source_scope_revision, scope_config_hash)`, `enabled=true`.
2. `source_object_scope`: exact SourceObject/Evidence belongs to the same scope revision, membership `ACTIVE`; access mode exact-match trusted SourceScopeRevision. Another broad revision or membership of a different workspace path does not fit.
3. `policy_decision`: exact organization, actor, principal-set hash, operation `question.evidence.read`, workspace/revision, EvidenceFragment resource, policy revision, `decision=ALLOW` and `decided_at == authorized_at`. ID/ALLOW from the snapshot without this row is forbidden.
4. For `WORKSPACE_MANAGED` — active immutable confirmation exact scope/config/actor/policy/warning; ACL fields strictly null. For `SOURCE_ENFORCED` — trusted immutable `AclSnapshot` exact ID/hash/status/times/digest-key version and sorted token digests. At least one source-native principal digest from the fresh PrincipalSetSnapshot must exact-match the ACL allow token; a single fresh timestamp or equal hash is insufficient.

Principal-set fields are non-null for any grant, exact-match `access_context` and fresh on `authorized_at`. Even with `context_count=0`, PrincipalSetSnapshot must be `RESOLVED` and `captured_at <= started_at < completed_at < expires_at`; an empty response does not bypass identity freshness. For `SOURCE_ENFORCED`, source-native identity/group entries are present in the principal set, the ACL snapshot covers them and remains fresh on `authorized_at`; otherwise, the grant does not exist. From all trusted valid paths, the server computes the set and selects the lexicographically minimal `(source_scope_id, source_scope_revision, policy_decision_id)`. The passed snapshot has no right to choose a more convenient path itself.

A snapshot is created once after post-authorization candidates → reranking → final-context post-authorization and before selected generation. It is immutable and serves as the sole context source for generation. The terminal transaction does not recapture the snapshot but instead exact-match re-verifies the listed live projections, current SourceVersion, version fence/retention, active Extraction pointer/activation revision, and Extraction retention. Any change to any projection between capture and commit results in a bounded full QuestionRun retry/fail, but does not sign the old context. Manifest retrieval fields and context pack must exact-match the persisted snapshot; self-declared counters/status are prohibited.

The authorized candidate artifact has the exact form `authorized-candidate-set-v1` and is stored envelope-encrypted:

```json
{
  "schema_version": "authorized-candidate-set-v1",
  "question_run_id": "...",
  "pipeline_profile_hash": "sha256:...",
  "candidates": [
    {
      "ordinal": 1,
      "evidence_fragment_id": "...",
      "source_version_id": "...",
      "extraction_id": "...",
      "evidence_text_hash": "hmac-sha256:k<version>:...",
      "exact_context_text": "...",
      "exact_context_hash": "sha256:...",
      "authorization_grant_hash": "sha256:..."
    }
  ]
}
```

`authorized_candidate_set_hash` — SHA-256 JCS of the entire object. The order of candidates is deterministic RRF order, with the ordinal starting from 1; `authorization_grant_hash` is recalculated from the exact trusted grant projection above. The artifact contains only post-authorized candidates before reranking; pre-authorization hits and counts are prohibited. The reranker receives **the entire** array, even when the final `context_count` is less than `authorized_candidate_count`.

`authorized_candidate_count` — length of this array after context expansion and post-authorization, but before final rerank/budget; `context_count` — number of final context entries. Pre-authorization hit count is forbidden in Answer Manifest, signed public snapshot, and user/auditor metadata: differences in counts could reveal the existence of inaccessible objects. Only limited aggregate operations telemetry is permitted without question/evidence dimension. Normal deterministic top-k is part of pipeline revision, and `truncated=true` means unplanned budget/time/source/candidate truncation relative to this revision. At `truncated=true` reason is non-null; at false reason is null.

- `source_version_content_hash` — SHA-256 exact transient source bytes received by the connector after transport decoding and before extraction: file/blob bytes, raw MIME message, or HTTP entity body;
- `evidence_text_hash` — organization-scoped HMAC-SHA-256 keyed digest of the canonical `text-v1` EvidenceFragment bytes, with its `digest_key_version` carried by the trusted Evidence row (ADR-0077, §7.0 above);
- `extraction_profile_hash` — trusted immutable profile hash Extraction to which the EvidenceFragment belongs;
- `cited_excerpt_hash` — SHA-256 exact canonical `text-v1` slice;
- `anchor_hash` — organization-scoped HMAC-SHA-256 digest of the JCS anchor object, with its `digest_key_version` carried by the trusted Evidence row;
- `exact_context_hash` — SHA-256 canonical `text-v1` expanded context, actually passed to the model.

Source bytes are deleted after hash and extraction verification, but the hash remains part of SourceVersion.

### 7.1. Claim verification binding

Each published `FACT` and `INFERENCE` has an immutable `ClaimVerification`; `UNKNOWN` does not have it. This binds exactly the claim text and exactly the proofs that the verifier saw, and excludes replacement of the text or citations after verification.

`claim_text_hash` equals SHA-256 canonical `text-v1` bytes exact `claim.text`. `verification_input_hash` equals SHA-256 JCS object exact form:

```json
{
  "claim_id": "C1",
  "kind": "FACT",
  "claim_text_hash": "sha256:...",
  "evidence": [
    {
      "citation_number": 1,
      "source_version_id": "...",
      "extraction_id": "...",
      "evidence_fragment_id": "...",
      "evidence_text_hash": "hmac-sha256:k<version>:...",
      "cited_excerpt_hash": "sha256:...",
      "anchor_hash": "hmac-sha256:k<version>:..."
    }
  ],
  "supporting_claims": []
}
```

`evidence` is sorted by `citation_number`, which is unique within the array. For FACT, this is the exact set of citations of the claim itself; `supporting_claims=[]`. For INFERENCE, `supporting_claims` is the exact set of directly supporting FACT and contains objects `{"claim_id":"C1","claim_text_hash":"sha256:..."}`, sorted by numeric suffix `claim_id`; evidence is the exact union of citations of these FACT without duplicates. INFERENCE cannot be supported by UNKNOWN, another INFERENCE, or hidden evidence.

The selected `VERIFICATION` ModelRun validates the entire batch. Its `input_hash` equals SHA-256 JCS object `{"profile_revision":"...","prompt_version":"...","question_hash":"sha256:...","claims":[...]}`, where `claims` contains only objects `{"claim_id":"C1","verification_input_hash":"sha256:..."}` for all FACT/INFERENCE in numerical claim ID order.

Verifier must return only the object `verifier-output.schema.json`. `results` contains the exact set of input claim IDs without missing/extra/duplicate, in the same numerical order; each `verification_input_hash` is byte-exact to the input. `ModelRun.output_hash` equals the SHA-256 canonical JCS of the entire schema-valid verifier output. Only `SUPPORTED` creates the published ClaimVerification; all other outcomes leave the generation/verification attempt unselected and trigger bounded regeneration or the deterministic insufficient-evidence path. Silent removal from an already selected model plan is forbidden. Manifest must exact-match persisted ClaimVerification, canonical verifier output, and the selected successful ModelRun; a self-consistent manifest is insufficient.

### 7.2. Purpose-specific ModelRun provenance

`model_profile.profile_hash` equals the SHA-256 JCS object of exact form:

```json
{
  "schema_version": "model-profile-v1",
  "purpose": "GENERATION",
  "profile_revision": "...",
  "model_id": "...",
  "model_revision": "...",
  "model_artifact_hash": "sha256:...",
  "runtime_id": "vllm",
  "runtime_revision": "...",
  "runtime_artifact_hash": "sha256:...",
  "tokenizer_revision": "...",
  "tokenizer_hash": "sha256:...",
  "chat_template_hash": "sha256:...",
  "prompt_version": "...",
  "prompt_template_hash": "sha256:...",
  "output_schema_id": "model-answer-1.4",
  "output_schema_hash": "sha256:...",
  "decoding": {
    "temperature": 0,
    "top_p": 1,
    "seed": 0,
    "max_input_tokens": 32768,
    "max_output_tokens": 4096,
    "dtype": "BFLOAT16",
    "quantization": "NONE"
  },
  "embedding_dimension": null
}
```

Nullable/non-applicable fields remain explicit `null`; they cannot be removed. Prompt hash is calculated from exact template bytes, schema hash — from JCS schema, tokenizer/chat-template/runtime artifacts are taken only from version lock/AIBOM. `configured_profiles` and each ModelRun contain `profile_hash` and exact-match trusted record. Label `profile_revision` without hash is not provenance.

Each Model Gateway call stores encrypted exact canonical input/output bytes. `ModelRun.input_hash` and `output_hash` are recalculated from these bytes, not accepted from the manifest. QuestionRun has a server-created append-only `model-execution-plan-v1`; its JCS hash is stored in the trusted QuestionRun aggregate and retrieval snapshot, but not accepted from the manifest/fixture. Plan contains exact profile hashes, ordered phases, all valid attempt IDs, and the single selected ID of each required purpose. The state-machine reducer independently derives mandatory purposes:

- `EMBEDDING` always;
- `RERANKING`, if `authorized_candidate_count > 0`;
- `GENERATION`, if `answer_mode == GENERATIVE` and `context_count > 0`;
- `VERIFICATION`, if `answer_mode == GENERATIVE` and the final plan contains FACT or INFERENCE.

For the required purpose, there is exactly one selected successful run; for the non-required purpose, the selected run is prohibited. Failed/rejected attempts remain as provenance, have a continuous `attempt` within the purpose, and must be present in the execution plan. No unplanned purpose/attempt is permitted.

Canonical inputs have exact forms:

```json
{
  "schema_version": "embedding-input-v1",
  "profile_revision": "...",
  "profile_hash": "sha256:...",
  "question_text": "...",
  "question_hash": "sha256:..."
}
```

```json
{
  "schema_version": "reranking-input-v1",
  "profile_revision": "...",
  "profile_hash": "sha256:...",
  "question_text": "...",
  "question_hash": "sha256:...",
  "authorized_candidate_set_hash": "sha256:...",
  "candidates": [
    {
      "ordinal": 1,
      "evidence_fragment_id": "...",
      "exact_context_text": "...",
      "exact_context_hash": "sha256:..."
    }
  ]
}
```

```json
{
  "schema_version": "generation-input-v1",
  "profile_revision": "...",
  "profile_hash": "sha256:...",
  "prompt_version": "...",
  "question_text": "...",
  "question_hash": "sha256:...",
  "context_pack_hash": "sha256:...",
  "corpus_status": "COMPLETE",
  "context": [
    {
      "ordinal": 1,
      "evidence_fragment_id": "...",
      "exact_context_text": "...",
      "exact_context_hash": "sha256:..."
    }
  ]
}
```

`question_text` and each `exact_context_text` are canonical `text-v1`; corresponding hashes and ordered IDs exact-match QuestionRun/retrieval snapshot. Reranking `candidates` exact-match **all** `authorized-candidate-set-v1`, not final context projection; fixture with `authorized_candidate_count > context_count` is mandatory. Input verifier has the form from §7.1. Any additional model-visible field requires a new input schema version: hidden prompt metadata are forbidden.

Embedding output — JCS object `{"schema_version":"embedding-output-v1","dimension":1024,"vector_sha256":"sha256:..."}`; `vector_sha256` is verified by exact float32 little-endian vector bytes. Reranking output — strict JCS object `{"schema_version":"reranking-output-v1","ordered_evidence_fragment_ids":[...]}` with exact permutation of the full candidate ID set without missing/extra/duplicate. Final context is a deterministic projection of this order by budget/diversity rules pinned `pipeline_version`. Retrieval authorization snapshot exact-match references selected embedding/reranking ModelRun IDs, their recomputed output hashes, and trusted execution-plan hash; swapping ID/hash between successful attempts is blocked. Manifest `retrieval.model_execution_plan_hash` must exact-match this snapshot field and JCS hash of the full server-created plan artifact.

Selected `GENERATION` output must be schema-valid `model-answer.schema.json`. The terminal validator builds an inverse model-plan projection from manifest claims/sections: for FACT `evidence_ids`, they are derived from its citation numbers; for INFERENCE, they are empty and exact `supporting_claim_ids`; for UNKNOWN `text=null`, both arrays are empty and only typed `unknown_reason` is preserved; server-only rendered text/status, answer spans, and citation numbers are excluded. The JCS projection must byte-exactly match the selected generator output. After verification/numeric validation, changing the text, order, evidence/support mapping, or sections is not allowed; a new generation attempt is required.

All attempts, not only selected ModelRun, principal/ACL `authorized_at`, retrieval `captured_at` and deterministic validation timestamps are inside trusted `[QuestionRun.started_at, QuestionRun.completed_at]`. Selected embedding completes before materialization candidate set; all reranking attempts follow candidate set and complete before retrieval capture; generation starts after retrieval capture; verification follows selected generation; `signature.signed_at == completed_at`. Corpus snapshots have `captured_at == started_at`. Violation of phase order blocks terminal commit.

### 7.3. Deterministic numeric validation

For each FACT/INFERENCE, there is exactly one immutable `numeric-validator-v1` record; UNKNOWN does not have one. `validation_input_hash` exact-match `verification_input_hash`, therefore the validator is linked to the same claim text and the same evidence/support set. Output must pass `numeric-validator-output.schema.json`, its hash is recalculated from JCS bytes, and the terminal manifest publishes only `PASSED`.

The Validator independently re-extracts material literals from the claim and cited excerpts every `NUMERIC_VALIDATION.md`. For each FACT, every literal must exact-match one cited excerpt. For each INFERENCE, the literal must exact-match the text of at least one supporting FACT and already have `PASSED` in it. A mismatch in output, input hash, validator version, or claim set blocks terminal commit.

Model claim text is always considered untrusted plain text. Before the renderer, the semantic validator rejects C0/C1 controls, tab/newline, and Unicode bidi-control characters (`U+200E`, `U+200F`, `U+202A..U+202E`, `U+2066..U+2069`). In 1.0, only `answer-renderer-v1` is allowed, locale `ru-RU`.

UNKNOWN does not contain model-controlled text. Before plan projection server materializes the string only for typed reason:

```text
NO_RELEVANT_EVIDENCE → \u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e \u0434\u0430\u043d\u043d\u044b\u0445, \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u044e\u0449\u0438\u0445 \u043e\u0442\u0432\u0435\u0442\u0438\u0442\u044c \u043d\u0430 \u0432\u043e\u043f\u0440\u043e\u0441.
INSUFFICIENT_SUPPORT → \u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438 \u043d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0439 \u0434\u043b\u044f \u043d\u0430\u0434\u0451\u0436\u043d\u043e\u0433\u043e \u043e\u0442\u0432\u0435\u0442\u0430.
CONFLICTING_EVIDENCE → \u0418\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0438 \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0442 \u043f\u0440\u043e\u0442\u0438\u0432\u043e\u0440\u0435\u0447\u0438\u0432\u044b\u0435 \u0441\u0432\u0435\u0434\u0435\u043d\u0438\u044f; \u043e\u0434\u043d\u043e\u0437\u043d\u0430\u0447\u043d\u044b\u0439 \u043e\u0442\u0432\u0435\u0442 \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d.
```

Manifest UNKNOWN `text` must byte-exactly match this table, `unknown_reason` is preserved. For FACT/INFERENCE `unknown_reason=null`. Changing formulations creates a new answer renderer version.

The Renderer first creates its own document AST; the claim is inserted only as a Text node and is never passed to the Markdown/HTML parser. `sections[].title` in 1.0 is always `null`: the model cannot create a header outside the claim/verification pipeline. Then the Renderer builds an array of Markdown blocks in the order `sections[].ordered_claim_ids`:

1. FACT provides block `{escape(claim.text)}{citation markers}`;
2. INFERENCE provides block `**\u0412\u044b\u0432\u043e\u0434:** {escape(claim.text)}`;
3. UNKNOWN provides block `**\u041d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e:** {escape(server-owned claim.text)}`;
4. citation markers FACT are sorted by number and have the exact form ` [n]`;
5. blocks are connected exactly `LF LF`, and exactly one `LF` is added after the last block.

`escape` first replaces `&` with `&amp;`, then places an ASCII backslash before each character from the set:

```text
\\ ` * _ { } [ ] < > ( ) # + - . ! | ~
```

Server prefixes/headings/citation markers do not pass `escape`. They are created by the renderer code, not by the model.

`answer_span` claim is measured in UTF-8 bytes of the final canonical Markdown and covers only `escape(claim.text)`, excluding server prefix and citation markers. Validator re-executes `escape` and requires byte-exact equality. Thus, Markdown escaping does not destroy claim mapping.

Additional renderer rules:

- accepts only verified claim IDs and sections;
- rejects claims with leading or trailing Unicode whitespace before AST construction to prevent FACT from being converted into an indented Markdown code block;
- constructs citation markers and UI link metadata exclusively from persisted Citation;
- Markdown retains only the marker `[n]`; clickable UI/deeplink is built from structured Citation and server-side connector policy, not from model text;
- adds Fact/Inference/Unknown markers server-side;
- normalizes output to NFC + LF;
- removes trailing spaces from each line and retains exactly one trailing LF.

`answer_hash` is considered from the UTF-8 bytes of this canonical Markdown.

## 8. Answer Manifest integrity

Manifest uses a two-stage envelope:

1. `manifest_content_bytes = JCS(manifest excluding manifest_hash and signature)`;
2. `manifest_hash = SHA-256(manifest_content_bytes)`;
3. `manifest_signing_bytes = JCS({"algorithm":"ED25519","key_id":"...","manifest_hash":"sha256:...","signed_at":"..."})`;
4. `signature.value_base64 = Ed25519(manifest_signing_bytes)`;
5. canonical content bytes and signing bytes are preserved together with the full manifest;
6. hash is included in the append-only audit event and periodic sealed audit digest.

The names and composition of the signing object are fixed; additional fields are prohibited. After retention purge, the envelope signature still confirms the preserved manifest hash, but does not allow restoring the deleted content.

When reading signature and hash, checks are performed before issuing the answer body. An error indicates an integrity failure, not fallback rendering.

### 8.1. Signing key lifecycle

Public key is taken only from trusted `signing_key` record via `(organization_id, purpose, key_id)`; public key from payload is forbidden. Purpose: `ANSWER_MANIFEST`, `CONNECTOR_EVENT` or `AUDIT_CHECKPOINT`; connector key is additionally scoped to exact connection/agent identity.

```text
ACTIVE   — may sign and verify
RETIRED  — verifies historical artifacts only
REVOKED  — neither signs nor is considered trusted for verification
```

Signing requires exactly one ACTIVE key with exact purpose/scope and `not_before <= signed_at <= sign_until`. Rotation atomically transitions the old key to RETIRED and activates the new one; two ACTIVE or zero ACTIVE keys block signing. A RETIRED key remains verify-only for no less than the retention period of all artifacts it signed. A REVOKED/compromised key yields `SIGNATURE_KEY_REVOKED`; the Answer body does not receive fallback rendering, and the connector event is not accepted. The private key exists only in the customer secret/KMS/HSM reference and is never stored in PostgreSQL, payload, log, or model context.

The new connector event is accepted only from key ACTIVE on server receive; RETIRED is allowed only for offline verification of previously accepted immutable event. `key_id` and `signed_at` are included in signing bytes, therefore rotation does not re-sign old artifacts.

## 9. Connector event integrity and replay protection

Connector event uses the field `integrity`:

```text
algorithm = ED25519
key_id
signed_at
nonce
payload_hash
value_base64
```

The calculation is strictly two-step:

1. `event_payload_bytes = JCS(event excluding integrity)`;
2. `payload_hash = SHA-256(event_payload_bytes)`;
3. signing bytes equal JCS object exact form:

```json
{
  "algorithm": "ED25519",
  "connection_id": "...",
  "connector_job_id": "...",
  "event_id": "...",
  "key_id": "...",
  "nonce": "...",
  "payload_hash": "sha256:...",
  "signed_at": "...",
  "source_scope_id": "...",
  "scope_revision": 1
}
```

4. `integrity.value_base64 = Ed25519(signing bytes)`.

Thus, the signature covers the payload hash, `algorithm`, `key_id`, `signed_at`, `nonce`, job, connection, scope, and scope revision. The server receives the trusted organization/connector identity from mTLS registration, compares it with the event connection/scope, verifies both canonical forms, the signature, the acceptable time window, key status, and atomically consumes the one-time nonce. A repeated nonce, event ID, or idempotency key with a different payload is a security error; an exact repeat returns the original ingest result.

Private keys are never passed in event, job, audit, or model context.

## 10. Audit hash chain

Each audit event must pass `architecture/contracts/audit-event.schema.json`. `event_hash` is computed as a SHA-256 JCS of the full `audit-event-v1` object without the single field `event_hash`, but with `previous_event_hash`; a hash of a pre-transferred projection or part of metadata is not accepted. `action` is an exact-match server-owned action registry, while `metadata` passes a separate per-action subset allowlist over the general schema. For the first event, `previous_event_hash = sha256:` + 64 zeros is used.

Append locks the organization's `audit_chain_head`, verifies `(last_sequence,last_event_hash)`, recalculates event hash, inserts event, and changes head in a single transaction. Unique `(organization_id, sequence)` and `(organization_id, event_hash)` forbid fork/duplicate. Checkpoint builder loads **full** rows of the range, re-validates schema/per-action metadata, recalculates each event hash and contiguous chain, and only then uses first/last hashes. A list `(sequence, previous_event_hash, event_hash)` without event bodies is insufficient. Periodic sealed digest signs the JCS object with organization ID, sequence range, first/last hash, and sealing time; source contents in the digest are not included.

Periodic sealed digest has strict `audit-checkpoint.schema.json`. Content bytes equal JCS(checkpoint without `checkpoint_hash` and `signature`), `checkpoint_hash` — their SHA-256. Signing bytes have the exact form:

```json
{
  "algorithm": "ED25519",
  "checkpoint_hash": "sha256:...",
  "key_id": "...",
  "signed_at": "..."
}
```

`event_first_sequence <= event_last_sequence`. The first checkpoint uses zero previous checkpoint hash; each subsequent one requires `checkpoint_sequence = previous + 1`, `event_first_sequence = previous.event_last_sequence + 1`, and exact `previous_checkpoint_hash`. First/last event hashes exact-match audit rows. Signed canonical checkpoint is exported to at least one admin-configured external append-only sink: customer WORM Object Lock, immutable on-edge archive, or SIEM with signed receipt. Sink receipt hash is stored locally but is not included in checkpoint content.

Before the production release, the organization cannot have audit status `READY` without a verified checkpoint sink. Checkpoint/sink acknowledgement timeout is visible as `AUDIT_CHECKPOINT_DEGRADED`; after the organization policy max lag, privileged configuration/source/member/key operations fail closed, whereas data reads receive an explicit security-health banner and continue to be audited locally. External checkpoint allows detection of a privileged DB operator rewriting, who could only rebuild the local hash chain.
