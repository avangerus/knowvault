# Normative Data Model 1.0

The document defines table ownership and constraints. Physical column names may be refined only without changing semantics.

## 1. Identity and tenancy

```text
organization
  id, name, status, region, policy_revision, role_revision,
  owner_principal_id,
  encryption_key_reference, created_at

organization_policy_revision
  organization_id, revision, policy_revision_id, policy_hash,
  activated_at, activated_by,
  PK(organization_id, revision),
  UNIQUE(organization_id, policy_revision_id),
  UNIQUE(organization_id, revision, policy_revision_id, policy_hash)

principal
  id, organization_id, type(USER|GROUP|SERVICE),
  display_name, status, session_revision, created_at

external_identity
  id, organization_id, principal_id, provider_id,
  external_subject_digest, digest_key_version, attributes_hash,
  status(ACTIVE|REVOKED), last_verified_at, revoked_at

oidc_provider
  id, organization_id, issuer_url, status(ACTIVE|DISABLED),
  current_revision, created_by, disabled_at

oidc_provider_revision
  organization_id, provider_id, revision,
  client_id, client_secret_reference, redirect_uri,
  allowed_id_token_algorithms_json, configuration_hash, created_by

oidc_login_attempt
  id, organization_id, provider_id, provider_revision,
  state_digest, browser_binding_digest, nonce_digest,
  pkce_verifier_digest, return_path,
  status(PENDING|CLAIMED|CONSUMED|FAILED|EXPIRED),
  created_at, expires_at, claimed_at, completed_at

identity_session
  id, organization_id, principal_id, provider_id, external_identity_id,
  login_attempt_id, session_token_digest,
  principal_session_revision, provider_revision,
  issued_at, expires_at, revoked_at, revocation_code

group_member
  organization_id, group_principal_id, member_principal_id,
  source, revision, valid_from, valid_until

principal_set_snapshot
  id, organization_id, human_principal_id,
  identity_provider_revision, session_revision,
  captured_at, expires_at, status(RESOLVED|STALE|FAILED),
  canonical_bytes, content_hash

principal_set_snapshot_entry
  organization_id, principal_set_snapshot_id,
  namespace, type(USER|GROUP|SERVICE|SPECIAL), subject_digest,
  digest_key_version, provider_revision

organization_role_assignment
  id, organization_id, principal_id,
  role(OWNER|ADMIN|CONNECTOR_ADMIN|SECURITY_AUDITOR|MEMBER),
  valid_from_revision, valid_to_revision,
  assigned_by, assigned_at, revoked_by, revoked_at

encrypted_artifact
  id, organization_id, aad_schema_version,
  owner_table, owner_column, resource_type, resource_id, field_name,
  cipher(AES_256_GCM), ciphertext BYTEA, size_bytes, nonce,
  wrapped_dek, wrapped_dek_hash, kek_reference, kek_version,
  aad_hash, plaintext_hash, created_at, purged_at
```

Limitations:

- unique `(organization_id, provider_id, digest_key_version, external_subject_digest)`;
- `external_subject_digest`, login-state, nonce, browser binding, PKCE verifier and session handle are keyed digests. Raw OIDC `sub`, email, claims, authorization code and tokens are not stored;
- `oidc_provider_revision` is immutable; `identity_session` records the exact provider revision and current `principal.session_revision` at the time of issuance;
- one `oidc_login_attempt` passes only `PENDING → CLAIMED → CONSUMED|FAILED` or `PENDING → EXPIRED` and can produce exactly one `identity_session`;
- `identity_session` is immutable except for one-way revoke. Changing principal revision or its deprovision technically revokes all its active sessions;
- an unknown or disabled principal does not receive a session;
- the administrative role is stored separately from data membership;
- an ACTIVE organization has exactly one active OWNER-USER, matching `organization.owner_principal_id`; transferring owner closes/creates assignments and increases `role_revision` in a single transaction;
- OWNER manages ownership/policy, ADMIN — users/groups/SSO/policy, CONNECTOR_ADMIN — connection credentials/trust/scopes, SECURITY_AUDITOR — audit/security metadata, MEMBER — without management rights. No organization role grants workspace/source content access without separate workspace membership/grant;
- role assignment is immutable/audited; revoke closes the revision range and increases the session revision of the affected principal;
- deleting a user increases `session_revision` and revokes active sessions;
- effective principal/group expansion is taken only from immutable `principal_set_snapshot`; unknown provider revision, `STALE/FAILED` or `expires_at <= authorized_at` means deny;
- identity/group revocation increases provider/session revision, invalidates policy/search cache and prohibits reuse of the old principal-set snapshot.

`encrypted_artifact` follows `ENCRYPTION.md` and `encrypted-artifact-aad.schema.json`: nonce is unique across the entire organization + KEK reference/version and does not rely on caller-supplied wrapped-DEK hash; trusted AAD includes organization, owning table/column, resource type/ID, field, and schema. `oneOf` schema is a closed inventory of all owning `*_artifact_id` columns of this model; unknown column, missing column, or reuse of a common type are prohibited. Ciphertext is stored bounded only in PostgreSQL; nullable external reference in 1.0 is prohibited. Application repositories do not return plaintext without `AuthorizedContext`; ciphertext of another organization/resource/type/field/owner-column is not authenticated.

The foundation migration establishes this closed inventory before most owning tables. This is not permission to use orphan artifacts: a specific owner's repository cannot be connected to runtime until its migration binds `(organization_id, artifact_id)` to the exact owning column via a composite FK or an accepted deferred exact-owner validator.

Outbox accepts only internal links in the exact form `typed-prefix + canonical ULID`; source-native ID, title, path, email, and other human-readable strings are not queue links.

## 2. Workspace

```text
workspace
  id, organization_id, name, description, status,
  owner_principal_id, current_revision, retention_policy_id,
  created_at, updated_at

workspace_revision
  workspace_id, organization_id, revision,
  configuration_hash, created_by, created_at

workspace_member
  id, workspace_id, organization_id, principal_id,
  role(OWNER|MANAGER|MEMBER|VIEWER|AUDITOR),
  valid_from_revision, valid_to_revision,
  added_by, added_at, removed_at
```

Any change to members, source bindings, or answer policy creates the next revision. Question Run fixes a specific revision.

Role change does not update the historical row: the previous membership is closed `valid_to_revision`, the new one is inserted with the new role. Partial unique index allows only one active membership on `(organization_id, workspace_id, principal_id)`.

In ACTIVE workspace, there is exactly one active OWNER role, matching `workspace.owner_principal_id`. Ownership transfer changes the owner, updating both membership history rows and WorkspaceRevision in a single transaction.

## 3. Sources

```text
source_connection
  id, organization_id, type(FOLDER|GIT|MAIL|SITE|POSTGRESQL_QUERY),
  name, latest_revision, active_revision, status, created_by, created_at

source_connection_revision
  organization_id, connection_id, revision,
  credential_reference, connector_build_id,
  capability_profile_id, capability_profile_hash,
  connector_agent_id, execution_target(CENTRAL_WORKER|CONNECTOR_AGENT),
  trust_record_id, trust_profile_artifact_id, trust_profile_hash,
  connector_version, connector_artifact_hash,
  connector_contract_suite_hash, connector_verified_at,
  allowed_access_modes_json,
  max_scope_objects, max_scope_bytes, max_object_bytes,
  created_by, created_at

source_connection_trust_record
  id, organization_id, connection_id, connection_revision,
  connector_agent_id, execution_target,
  trust_profile_artifact_id, trust_profile_hash,
  verified_at, expires_at

source_connection_trust_projection
  organization_id, trust_record_id, revision,
  status(DRAFT|VERIFIED|REVOKED|EXPIRED), changed_at

source_discovery_request
  organization_id, id, actor_principal_id, connection_id,
  connection_revision, trust_profile_hash,
  security_epoch, bounded limits, request_hash,
  idempotency_key_hash, status, result_id, result_hash,
  issued_at, expires_at, started_at, completed_at

source_discovery_result
  organization_id, id, request_id, actor_principal_id, connection_id,
  connection_revision, database_identity_hash, trust_profile_hash,
  privilege_digest, security_epoch,
  status(SUCCEEDED|NEEDS_INTERPRETATION), view_count,
  prepared_view_count, needs_interpretation_view_count,
  metadata_artifact_id, metadata_plaintext_hash, result_hash,
  created_at, expires_at

connector_capability_profile
  id, profile_hash, connector_build_id, connector_type,
  connector_version, connector_artifact_hash,
  stable_object_ids, native_versions, incremental_cursor,
  webhooks, item_level_acl, acl_refresh,
  historical_versions, deep_links, deletion_events, local_extraction,
  contract_suite_hash, verified_at

source_discovered_scope
  id, organization_id, connection_id, connection_revision,
  identity_artifact_id, identity_digest,
  display_metadata_artifact_id,
  status(ACTIVE|REMOVED), discovered_at, removed_at

source_scope
  id, organization_id, connection_id, discovered_scope_id,
  scope_type, latest_revision, active_revision,
  status, created_at

source_scope_revision
  source_scope_id, organization_id, revision,
  connection_id, connection_revision,
  discovered_scope_id, discovered_identity_digest,
  source_type,
  scope_config_artifact_id, scope_config_hash,
  access_mode(WORKSPACE_MANAGED|SOURCE_ENFORCED),
  content_freshness_sla, acl_freshness_sla,
  sync_interval, object_limit, byte_limit,
  created_by, created_at

source_scope_activation
  organization_id, source_scope_id, source_scope_revision,
  revision, status(DRAFT|SYNCING|READY|REVOKED|FAILED),
  scan_run_id, changed_at, activated_at

workspace_source_confirmation_actor_grant
  grant_id, organization_id, workspace_id, revision,
  principal_id, permission(workspace.source.confirm),
  valid_from, valid_until, policy_revision_number, policy_revision, grant_hash,
  granted_by, granted_at,
  PK(organization_id, grant_id, revision),
  UNIQUE(organization_id, grant_id, revision, grant_hash)

workspace_source_confirmation_actor_grant_revocation
  revocation_id, confirmation_actor_grant_revocation_hash,
  organization_id, grant_id, grant_revision, grant_hash,
  revoked_by, revoked_at, reason_code, policy_revision_number, policy_revision,
  PK(organization_id, revocation_id),
  UNIQUE(organization_id, revocation_id, confirmation_actor_grant_revocation_hash),
  UNIQUE(organization_id, grant_id, grant_revision)

workspace_managed_grant_confirmation
  confirmation_id, confirmation_hash,
  organization_id, workspace_id, workspace_revision,
  workspace_configuration_hash, workspace_source_id,
  source_scope_id, source_scope_revision, scope_config_hash,
  access_mode(WORKSPACE_MANAGED),
  confirmation_actor_grant_id, confirmation_actor_grant_revision,
  confirmation_actor_grant_hash,
  warning_version, warning_contract_hash, acknowledgement_code,
  confirmed_by, confirmed_at, policy_revision_number, policy_revision,
  PK(organization_id, confirmation_id),
  UNIQUE(organization_id, confirmation_id, confirmation_hash)

workspace_managed_grant_revocation
  revocation_id, workspace_managed_confirmation_revocation_hash,
  organization_id, confirmation_id, confirmation_hash,
  revoked_by, revoked_at, reason_code, policy_revision_number, policy_revision,
  PK(organization_id, revocation_id),
  UNIQUE(organization_id, revocation_id, workspace_managed_confirmation_revocation_hash),
  UNIQUE(organization_id, confirmation_id)

workspace_source
  id, organization_id, workspace_id, source_scope_id,
  added_by, added_at, removed_at

workspace_revision_source
  organization_id, workspace_id, workspace_revision,
  workspace_source_id, source_scope_id, source_scope_revision,
  enabled
```

Credentials are never stored in `source_connection`; there is only an opaque reference to the secret provider there. The PostgreSQL connection bootstrap creates exactly `source_connection`, an immutable revision, a trust record/projection, and a sealed trust artifact. The parent remains `DRAFT`, the trust projection starts at `DRAFT`, and `source_discovered_scope`, `source_scope`, activation, and workspace binding are not created. A separate CONNECTOR_ADMIN verification translates the exact trust record into `VERIFIED`; only after this can the OWNER request metadata discovery.

`source_discovery_request` and `source_discovery_result` belong to the source-management plane. Request fixes the exact immutable connection revision, current trust/security recheck tuple, bounded catalog limits and expiry; it does not create a scope, scope revision, activation or workspace binding. Worker receives the target only through the lease-fenced `SECURITY DEFINER` projection; direct `SELECT` source-management tables are not issued to it. The worker derives the bounded database identity and privilege digests during the read-only probe and derives both again before result commit; the terminal result persists them only when both observations match. The result is immutable after its worker-owned terminal write, except for the one-time binding of its exact encrypted `metadata_artifact_id`; it expires no later than 15 minutes after creation. Its artifact uses the dedicated `source_discovery_result.metadata_artifact_id` AAD owner tuple. Full catalog details and native comments remain encrypted; raw credentials, DSN, OID, privilege graph and source rows are never persisted in an API/model projection. A visible but incomplete or ambiguous view is `NEEDS_INTERPRETATION`, not a guessed contract.

`source_connection_revision` is fully immutable and serves as authority only as an exact tuple connector build/capabilities, access modes, execution target, trust/network profile, credential reference, and upper limits. `latest_revision` denotes only management lineage; nullable `active_revision` is a separate authority; mixing them is forbidden. Prior to **any** branch, the access mode server performs an exact-match check of connection ID/revision, connector build ID/version/artifact hash, capability profile ID/**hash**/build/type, contract-suite hash, connector agent ID/execution target, and trust record ID/profile hash. A separate monotonic `source_connection_trust_projection` must be `VERIFIED`; `REVOKED` and `EXPIRED` are irreversible for the trust record. `capability_profile_id` references only a profile of the same exact build that has passed the connector contract suite; a free `capability_json` is forbidden. For Git, the trust profile fixes HTTPS/CA; for Site — origin/port/network-zone/CIDR/CA; for Mail — provider/tenant/host/CA; for Folder — trusted root alias/identity/platform. Credentials are stored only as a generated opaque secret-provider reference ID, not as a URI, path, or secret bytes.

WORKSPACE_MANAGED confirmation does not belong to a reusable SourceScopeRevision and is not included in `scope_config_hash` or the canonical WorkspaceRevision. It is a separate immutable authority relation: it exact-match links organization, workspace, and WorkspaceRevision with its configuration hash, a specific `workspace_source`, scope/revision, and `scope_config_hash`. Confirmation is created only by an actor for whom there exists an exact immutable grant `(grant_id, revision, grant_hash)` with permission `workspace.source.confirm`, required for the workspace, principal, policy revision, and order `granted_at <= valid_from <= confirmed_at < valid_until`. Authority timestamps use only UTC RFC 3339 second-precision form `YYYY-MM-DDTHH:MM:SSZ`; any other offset, fractional, or non-round-tripping form is forbidden. Workspace `OWNER`, `MANAGER`, or Organization Admin without such a grant does not receive authority automatically.

`organization.policy_revision` is a monotonic safe integer ordinal, and the canonical/API field `policy_revision` is an immutable opaque `policy_revision_id`, not a number formatting. Append-only `organization_policy_revision` exact links ordinal, ID, and policy hash. Authority persistence stores both `policy_revision_number` and `policy_revision`; their composite FK must exact-match a registry row, and the number must be the current `organization.policy_revision` at the time of creation. Decreasing the organization counter, reusing ID/hash, and implicitly deriving a string from a number are forbidden. Therefore, values such as `policy-0007` and `policy-42` are unambiguous only through the registry, not through a padding convention.

Warning is also a contract, not a UI checkbox: confirmation fixes server-owned `warning_version`, canonical `warning_contract_hash`, and closed `acknowledgement_code`. Localized text may change only together with the checked contract version and never replaces these fields.

Warning contract is a protected registry JCS object with fixed `access_mode`, sorted risk codes, and acknowledgement code; the client does not transmit an arbitrary warning body.

Confirmation and actor grant are not updated. Their revocation creates a separate append-only revocation. Confirmation-specific revocation terminates one confirmation; actor-grant revocation is a kill-switch for all confirmations that exact-match reference this grant. Live state `CONFIRMED|REVOKED|STALE` is a derived join, not a column: it requires the absence of both revocations, the current policy/warning, and the exact current enabled `WORKSPACE_MANAGED` binding of the same WorkspaceRevision. For exact current tuple organization/workspace/revision/configuration hash/binding/scope revision/scope hash/policy/warning, no more than one unrevoked derived-live confirmation is permitted; the deferred database validator computes this set under a workspace row lock. A revoked confirmation can be replaced only by a new command and a new ID. Revocation of one confirmation does not affect another, except for an intentional common kill-switch via the exact same actor grant. Any subsequent WorkspaceRevision makes the previous confirmation `STALE`; there is no automatic carry-forward. A new `source_scope.latest_revision` by itself does not replace the exact revision selected by the workspace. SOURCE_ENFORCED confirmation cannot have. Even a live confirmation without separate activation, connector-event, and retrieval gates does nothing queryable.

Commands over grant and confirmation receive their own future idempotency relation `workspace_managed_authority_command_receipt`; it is created only by migration `000011` together with repository checkpoint ADR-0053, and is not present in the current table schema. This is a separate receipt family: expanding `workspace_command_receipt` is forbidden because the authority sidecar does not create WorkspaceRevision. The namespace is `(organization_id, actor_principal_id, idempotency_key_hash)`, where `organization_id` is always trusted `AccessContext.OrganizationID`, never `request.organization_id`; the request field must exact-match it, but does not control tenant context for `database.Write`, nor for RLS, nor for namespace lookup during replay. Identical raw keys in workspace and authority families address different namespaces, and within the authority family, one key cannot be reused for another operation. Statuses are closed: `PENDING`, `SUCCESS`, `DENIED`, `NOT_FOUND`, `PRECONDITION_FAILED`. `PENDING` cannot commit; the terminal receipt is immutable; canonical request bytes and request hash are immutable; `command_id`, result ID/hash, and server timestamps are saved exactly once; replay returns the original immutable result and creates neither a new authority row nor an audit event; one audit event belongs to exactly one receipt. Operation-specific projection is closed by an exhaustive CHECK; generic intent JSON and uncontrolled nullable-union are forbidden. Request ID, raw Idempotency-Key, credential, warning text, and source content are not saved in the receipt. Migration `000011` must fail closed if it discovers authority rows created before the receipt boundary: declaring them trusted automatically or silently performing a backfill is forbidden.

`command_id` is reserved upon receipt creation, before any authorization decision: server-generated, immutable, unique within the tenant, and never included in canonical request bytes/hash. It exists for any business terminal outcome (`SUCCESS`, `DENIED`, `NOT_FOUND`, `PRECONDITION_FAILED`), since reservation occurs before the business outcome becomes known. `command_id` is the only audit resource ID for all four operations: on failure paths, no grant/confirmation/revocation row is created or read, so the created/parent authority ID cannot be a resource ID.

`source_discovered_scope` belongs to a specific connection revision; one connection has many records. Raw external identity is stored only in `identity_artifact_id`, while database lookup uses keyed `identity_digest`. Scope revision has a composite exact FK on organization, `discovered_scope_id`, connection/revision and `discovered_identity_digest`; raw external ID remains inside the encrypted canonical scope config. Site identity server derives from the canonical identity subset. Arbitrary user external_scope_id, display label, or discovery of another revision is not accepted.

`source_scope_revision` is fully immutable; validation/activation lives only in monotonic `source_scope_activation`. Any change to scope, access mode, or SLA creates a new revision with projection `DRAFT`, then a full scan/reconciliation builds revision-specific memberships. `latest_revision` does not grant data authority; nullable `active_revision` and associated WorkspaceRevision switch only via explicit audited activation after `READY`. Creating a new connection/scope revision does not perform implicit cutover. Connector event is accepted only for an existing signed `SYNCING|READY` activation and bounded job; unknown/REVOKED revision does not modify the catalog.

Migrations `000006` and `000007` together complete the fail-closed DRAFT control plane: all scope activation projections only `DRAFT`, `source_connection.active_revision`, and `source_scope.active_revision` equal `NULL`, and query/content jobs/connector events are forbidden by database and application gates. Transition permissions to `SYNCING/READY` establish a separate subsequent checkpoint only together with scan, binding/confirmation, signed-event, and audit invariants. `DEGRADED` is a computed effective health under non-`VERIFIED` connection trust, not a mutable state of an immutable revision or activation projection.

Requested access mode intersects with `allowed_access_modes`; SOURCE_ENFORCED requires verified `stable_object_ids + item_level_acl + acl_refresh`. `object_limit`/`byte_limit` do not exceed connection revision; format-specific per-object cap does not exceed scope byte limit and connection max object bytes.

`workspace_revision_source` is an immutable snapshot bindings for a specific WorkspaceRevision. Changing the binding or transitioning the scope to a new revision creates the next WorkspaceRevision and a new full snapshot; the old Question Run does not read the mutable current binding.

## 4. Objects, versions, and evidence

```text
source_object
  id, organization_id, connection_id,
  external_object_id_artifact_id, external_object_id_digest,
  digest_key_version, object_type,
  canonical_locator_artifact_id, canonical_locator_digest,
  title_artifact_id, current_version_id, current_acl_snapshot_id,
  lifecycle_state(ACTIVE|MISSING|DELETED),
  queryable, first_seen_at, last_seen_at

source_object_scope
  organization_id, source_object_id, source_scope_id, source_scope_revision,
  membership_state(ACTIVE|MISSING|MOVED|REMOVED),
  first_seen_at, last_seen_at, removed_at, missing_at, missing_sync_run_id

source_version
  id, organization_id, source_object_id,
  external_version_key, content_hash, source_updated_at,
  observed_at, superseded_at, deleted_at,
  state(PENDING|CURRENT|SUPERSEDED|DELETED|REDACTED)

source_version_retention
  organization_id, source_version_id,
  state(ACTIVE|PURGING|PURGED), queryable, extraction_allowed,
  retention_fence,
  purge_reason, purged_at

source_extraction
  id, organization_id, source_version_id,
  retention_fence_at_start,
  canonical_format, profile_json, profile_hash,
  extractor_name, extractor_version, extractor_artifact_hash,
  normalization_version,
  parser_profile_revision,
  ocr_used, ocr_model_id, ocr_model_revision,
  ocr_artifact_hash, ocr_profile_revision,
  evidence_set_hash,
  status(PENDING|RUNNING|SUCCEEDED|FAILED),
  started_at, completed_at, failure_code

source_extraction_retention
  organization_id, extraction_id,
  state(ACTIVE|PURGING|PURGED), queryable,
  purge_reason, purged_at

source_version_active_extraction
  organization_id, source_version_id, extraction_id,
  activation_revision, activated_at

acl_snapshot
  id, organization_id, source_object_id, source_version_id,
  mode, principal_tokens_artifact_id, principal_token_digests_json,
  digest_key_version,
  resolved_at, expires_at, content_hash, status

evidence_fragment
  id, organization_id, source_version_id, extraction_id,
  ordinal, normalized_text_artifact_id, text_hash, token_count,
  anchor_artifact_id, anchor_hash, anchor_digest_key_version,
  metadata_artifact_id, extraction_confidence,
  language, created_at

search_chunk
  id, organization_id, source_version_id, extraction_id,
  chunk_hash,
  search_text_artifact_id, token_count,
  embedding_profile_hash, embedding_model_artifact_hash,
  embedding_dimension

organization_search_profile
  organization_id, embedding_profile_id, embedding_profile_hash,
  index_generation, activation_revision, generation_fence,
  catalog_snapshot_watermark, outbox_applied_sequence,
  status(STAGING|ACTIVE|FAILED), activated_at

search_chunk_fragment
  organization_id, search_chunk_id, evidence_fragment_id,
  ordinal
```

Mandatory constraints:

- unique `(organization_id, connection_id, digest_key_version, external_object_id_digest)`;
- unique `(organization_id, source_object_id, external_version_key)`;
- `external_version_key NOT NULL`: connector input — `native:<safe-opaque-value>` or `hash:sha256:<64 lowercase hex>`. A return A→B→A creates a new immutable SourceVersion with internal key `observation:sha256:<hash of original version key>:<previous current version ID>`; content_hash remains the hash of the original bytes, observation time is new. Repeating the current observation is idempotent. Previous versions are not returned from SUPERSEDED to CURRENT; closed retention of the original version forbids bypass via a new observation. The internal key is not accepted from the connector and is not issued as a native source version;
- unique `(organization_id, source_object_id, source_scope_id, source_scope_revision)` in membership;
- `SourceExtraction` is immutable after terminal state; profile hash is calculated based on the canonical JCS profile, evidence-set hash — based on ordered canonical fragment descriptors;
- `source_version_retention` is created together with SourceVersion; `PURGING/PURGED` and `extraction_allowed=false` are irreversible for this version and forbid a new extraction run;
- every derived DB write and terminal Extraction commit locks the version-retention row and CAS-checks `ACTIVE/queryable`, `extraction_allowed=true` and the unchanged `retention_fence`; purge first increases the fence. If a late worker loses the race, its entire transaction is rolled back;
- partial unique `(organization_id, source_version_id, profile_hash) WHERE status='SUCCEEDED'` does not allow two activatable successful results of one exact profile, but allows a new run after terminal failure;
- `source_version_active_extraction` can point only to `SUCCEEDED` Extraction of the same SourceVersion, when version retention and extraction retention equal `ACTIVE/queryable`, and changes only after a full staged index;
- `EvidenceFragment` always points to immutable `SourceVersion` and a specific immutable `SourceExtraction` of this version via a composite FK;
- anchor passes format-specific JSON Schema;
- `search_chunk` cannot be used as a citation;
- vector document and SearchChunk exact-match contain one active `embedding_profile_hash`, model artifact hash and dimension; query embedding run must use the same full profile hash;
- changing the embedding profile fixes the catalog/outbox watermark, builds a full staged index generation from this snapshot, then ordered replay/dual-apply brings the new generation to the activation cut sequence. After checking for absence of sequence gaps and document/vector reconciliation, one operation increases the generation fence and switches the PostgreSQL active pointer + OpenSearch alias; writers carry generation/fence and stale write is rejected. Mixed vector spaces, count-only cutover and in-place partial overwrite are forbidden;
- `CURRENT` version for one object is no more than one;
- `queryable=false` is stronger than the index state.
- new retrieval and post-authorization use only current SourceVersion + version retention `ACTIVE/queryable` + active Extraction + extraction retention `ACTIVE/queryable`; source-derived purge in one transaction first increases the retention fence, moves the version and the exact set of all its Extraction to fail-closed, sets `extraction_allowed=false`, cancels jobs of the old fence and clears the pointer of this version. Bytes/index cleanup is performed only after commit. All OpenSearch mutations go only through an ordered transactional outbox and carry `(source_version_id, retention_fence, sequence)`; index applier before write rechecks current fence/state and discards stale add, while a purge event of a higher fence deletes version documents. Purge becomes `PURGED` only after terminal/cancelled old leases and checking for absence of PostgreSQL encrypted artifacts/OpenSearch projections. If the version is historical, the new current version and SourceObject remain queryable; if the purged version is current, the SourceObject is also closed until a new current version is selected;
- deleting one membership does not delete the SourceObject if another membership is ACTIVE;
- absence in a full successful pass moves the exact membership to `MISSING`; the object becomes `MISSING/queryable=false` only if no ACTIVE memberships remain. This state authorizes neither current nor historical reading. Return requires a successful observation, check of current scope permission, lease and retention in the publication transaction; `REMOVED/DELETED` remain terminal. Compatibility of previous records and negative controls: [ADR-0092](adr/0092-source-observed-presence-accepted.md);
- `SCOPE_MEMBERSHIP_REMOVED` changes only the exact membership; only proven `SOURCE_OBJECT_DELETED` closes the SourceObject and all memberships;
- membership of an old scope revision never authorizes a new revision;
- all tenant relations use a composite FK `(organization_id, parent_id)`.

Normalized Evidence/SearchChunk text is stored via tenant-bound `encrypted_artifact`; a clear searchable projection exists only within OpenSearch on a customer-encrypted volume according to `ENCRYPTION.md`. Binary source objects do not enter tables or backups.

## 5. Sync and durable jobs

```text
sync_run
  id, organization_id, source_scope_id,
  mode(FULL|INCREMENTAL|RECONCILIATION), status,
  cursor_before, cursor_after, counters_json,
  started_at, completed_at, error_summary

job
  id, organization_id, type, payload_json,
  idempotency_key, status, priority,
  available_at, lease_owner, lease_token, lease_deadline,
  attempt_count, max_attempts, created_at, completed_at

job_attempt
  id, organization_id, job_id, attempt_number,
  started_at, completed_at, outcome, error_code

outbox_event
  id, organization_id, sequence, aggregate_type, aggregate_id,
  event_type, bounded_reference_payload_json, created_at, published_at

outbox_sequence_head
  organization_id, last_assigned_sequence,
  last_published_sequence, updated_at
```

Limitations:

- unique `(organization_id, idempotency_key)`;
- completed job does not return to RUNNING;
- worker confirms lease token upon commit;
- outbox is created in the same transaction as the aggregate change;
- payload does not contain source content or secret.
- `SOURCE_DISCOVERY` is an existing-queue job type whose payload contains only the opaque `source_discovery_request_id`; connection credentials are resolved by the worker from the trusted mounted provider.
- sequence is assigned only by the transactional tenant head; identity/sequence and gap after rollback are prohibited;
- `knowvault_app` may enqueue, but not UPDATE/DELETE event and cannot change head. `published_at` in 000005 is a closed ordered acknowledgement primitive, not a ready delivery engine. Production applier is prohibited until a separate worker role and lease/CAS/retry/dead-letter state machine are implemented; silent skip of events is prohibited.

## 6. Question Run

```text
question_run
  id, organization_id, workspace_id, workspace_revision,
  created_by, question_text_artifact_id, question_hash,
  answer_mode(EXTRACTIVE|GENERATIVE),
  verification_method(BYTE_EXACT_CITATION|SEMANTIC_VERIFIER),
  result_status(QUEUED|RUNNING|COMPLETED|INSUFFICIENT_EVIDENCE|
                FAILED|CANCELLED),
  corpus_status(COMPLETE|PARTIAL),
  started_at, completed_at,
  answer_markdown_artifact_id, answer_structured_artifact_id, answer_hash,
  workspace_scope_hash, context_pack_hash,
  retrieval_version, policy_revision,
  manifest_content_artifact_id, manifest_signing_bytes,
  manifest_hash, manifest_signature_json,
  supersedes_question_run_id, failure_code

`answer_mode` and `verification_method` are included in the signed Answer Manifest and
fixed before terminal commit. `EXTRACTIVE` permits only
`BYTE_EXACT_CITATION`; its claim is a server projection of authorized
context with exactly one byte-exact citation. `GENERATIVE` permits
`SEMANTIC_VERIFIER`; generation/verifier profiles and model runs are required
only for that mode. A mismatched pair or an attempt to add model
artifacts to an extractive run is rejected before publication.

question_run_retention
  organization_id, question_run_id,
  state(ACTIVE|PURGING|PURGED), disclosure_allowed,
  retention_fence, purge_reason, purge_started_at, purged_at

question_idempotency
  organization_id, actor_principal_id, idempotency_key,
  canonical_request_hash, question_run_id, created_at

question_corpus_snapshot
  id, organization_id, question_run_id, source_scope_id,
  source_scope_revision, access_mode, scope_config_hash,
  connector_type, connector_version,
  health, content_watermark, last_successful_sync,
  acl_fresh_at, captured_at

UNIQUE (organization_id, question_run_id,
        source_scope_id, source_scope_revision)

question_retrieval_authorization_snapshot
  organization_id, question_run_id, schema_version,
  captured_at, pipeline_version, pipeline_profile_hash,
  model_execution_plan_hash,
  embedding_model_run_id, embedding_output_hash,
  authorized_candidate_set_hash,
  reranking_model_run_id, reranking_output_hash,
  authorized_candidate_count, context_count,
  truncated, truncation_reason, error_codes_json,
  canonical_bytes, snapshot_hash

question_authorized_candidate_set
  organization_id, question_run_id, schema_version,
  candidate_count, canonical_artifact_id,
  candidate_set_hash, created_at

question_authorized_candidate
  organization_id, question_run_id, ordinal,
  evidence_fragment_id, source_version_id, extraction_id,
  evidence_text_hash, exact_context_hash,
  authorization_grant_hash

question_retrieval_context_entry
  organization_id, question_run_id, ordinal,
  source_object_id, source_version_id, source_version_state,
  source_version_retention_state, source_version_queryable,
  source_version_retention_fence,
  extraction_id, active_extraction_id, activation_revision,
  extraction_retention_state, extraction_queryable,
  extraction_retention_fence_at_start,
  evidence_fragment_id, extraction_profile_hash,
  source_version_content_hash, evidence_text_hash,
  anchor_hash, exact_context_hash,
  source_scope_id, source_scope_revision, access_mode,
  membership_state, policy_decision_id, policy_decision,
  principal_set_snapshot_id, principal_set_snapshot_hash,
  principal_set_captured_at, principal_set_expires_at,
  authorized_at, acl_snapshot_id, acl_snapshot_hash,
  acl_snapshot_status, acl_resolved_at, acl_expires_at

The `question_corpus_snapshot` row set must match the enabled bindings of the pinned `workspace_revision` exactly: the same scope IDs, revisions, access modes and `scope_config_hash` values, without omissions, duplicates or extra scopes. An unavailable binding is retained as a separate row with its corresponding health and makes the corpus `PARTIAL`; omitting a row must not conceal a failure.

`question_authorized_candidate_set` is immutable and contains the entire post-authorized pre-rerank set and encrypted exact model-visible candidate texts; its rows are a safe typed/hash projection of the artifact. The candidate count may, and normally should, exceed the final context count. Reranker input exact-match uses the entire artifact, and the output is a permutation of all candidate IDs; final context is produced only through deterministic budget/diversity projection.

`question_retrieval_authorization_snapshot` and its entries are immutable from capture onward. The entry set matches the ordered final context pack exactly. Each entry records evidence hashes, current/active retention projections and one deterministically selected valid grant path. The terminal validator retrieves trusted `workspace.current_revision`, exact enabled `workspace_revision_source`, ACTIVE `source_object_scope`, persisted PolicyDecision and WorkspaceManagedConfirmation or AclSnapshot again. Snapshot strings `ACTIVE/ALLOW` are not authority. A principal-set snapshot is mandatory even with zero context, must exact-match the access context, and must remain fresh throughout the QuestionRun interval. For SOURCE_ENFORCED, the source-native principal digest intersects the allow tokens of the exact trusted ACL snapshot; stale identity mapping, group expansion or ACL cannot create an entry even with a `PARTIAL` corpus. The snapshot binds exact selected embedding/reranking IDs and recomputed outputs, the candidate-set hash, the execution-plan hash and final context. It is created after final-context post-authorization and before generation; the terminal transaction only repeats the exact-match check of all projections and performs bounded retry/fail on drift. The manifest contains the canonical snapshot hash, required `retrieval.model_execution_plan_hash` and safe post-authorization counters/status; both plan hashes must exact-match the full trusted plan artifact.

question_model_execution_plan
  organization_id, question_run_id, plan_revision,
  pipeline_profile_hash, configured_profile_hashes_json,
  required_purposes_json, ordered_attempt_ids_json,
  selected_run_ids_json, canonical_artifact_id,
  canonical_bytes_hash, plan_hash

`question_model_execution_plan` is created only by the server state machine, advances through append-only CAS revisions, and is finalized before terminal commit. Required purposes are derived again from trusted candidate/context counts and selected generated claim kinds. All attempts exact-match the plan, have contiguous purpose-local numbers, and fall within the QuestionRun interval; an unplanned attempt is prohibited. Selected embedding precedes the candidate set; reranking runs after the full candidate set and before retrieval capture; generation follows capture, and verification follows generation.

retrieval_profile
  id, organization_id, profile_revision,
  implementation_artifact_hash,
  analyzer_revision, analyzer_config_hash,
  embedding_profile_hash, reranking_profile_hash,
  config_json, canonical_bytes, profile_hash,
  status(ACTIVE|RETIRED)

question_extraction_snapshot
  organization_id, question_run_id, extraction_id, source_version_id,
  profile_json, profile_hash, evidence_set_hash

`question_extraction_snapshot` contains exact trusted catalog records only for Extractions actually used by citations. The extraction ID set matches the set referenced by citations exactly; duplicates and self-declared model/parser metadata are prohibited.

question_claim
  id, organization_id, question_run_id, claim_id, ordinal,
  text_artifact_id, text_hash, kind(FACT|INFERENCE|UNKNOWN),
  unknown_reason, support_status, answer_span_start, answer_span_end

question_claim_support
  organization_id, question_run_id, claim_id, supporting_claim_id

claim_verification
  organization_id, question_run_id, claim_id, kind,
  claim_text_hash, verification_input_hash,
  verifier_model_run_id, outcome

claim_verification_evidence
  organization_id, question_run_id, claim_id, citation_number,
  source_version_id, extraction_id, evidence_fragment_id,
  evidence_text_hash, cited_excerpt_hash, anchor_hash

claim_verification_support
  organization_id, question_run_id, claim_id,
  supporting_claim_id, supporting_claim_text_hash

claim_deterministic_validation
  organization_id, question_run_id, claim_id,
  validator_version, validation_input_hash,
  output_hash, outcome

claim_deterministic_validation_artifact
  organization_id, question_run_id, claim_id,
  output_artifact_id, retention_state, retention_until

question_citation
  id, organization_id, question_run_id, citation_number,
  source_object_id, source_version_id, extraction_id,
  evidence_fragment_id, cited_excerpt_artifact_id,
  source_version_content_hash, evidence_text_hash, cited_excerpt_hash,
  anchor_artifact_id, deep_link_artifact_id, state_at_generation

question_claim_citation
  organization_id, question_run_id, claim_id, citation_number

question_feedback
  id, organization_id, question_run_id, workspace_id, created_by,
  verdict(CORRECT|INCORRECT), comment_artifact_id,
  created_at, updated_at

model_profile
  id, organization_id, purpose, profile_revision,
  model_id, model_revision, model_artifact_hash,
  runtime_id, runtime_revision, runtime_artifact_hash,
  tokenizer_revision, tokenizer_hash, chat_template_hash,
  prompt_version, prompt_template_hash,
  output_schema_id, output_schema_hash,
  decoding_config_json, embedding_dimension,
  canonical_bytes, profile_hash, status(ACTIVE|RETIRED)

model_run
  id, organization_id, question_run_id,
  purpose, attempt, selected_for_result,
  model_id, model_revision, model_artifact_hash,
  profile_revision, profile_hash, prompt_version, input_hash, output_hash,
  token_counts_json, started_at, completed_at, outcome

model_run_artifact
  organization_id, model_run_id,
  input_artifact_id, output_artifact_id,
  retention_state(ACTIVE|PURGING|PURGED), retention_until
```

`question_idempotency` has a mandatory `UNIQUE (organization_id, actor_principal_id, idempotency_key)` and stores exact `workspace_id` bindings. An exact duplicate with the same canonical request hash in the same workspace returns the original Question Run regardless of its current or terminal status. The same key with a different hash or workspace returns `409 QUESTION_IDEMPOTENCY_CONFLICT`. The question text is never the deduplication key.

The terminal manifest builder receives `question_run_context` only from the locked persisted aggregate row and performs an exact-match verification of ID, organization/workspace/revision, canonical question/hash, actor, started/completed timestamps, and supersedes ID. These fields cannot be accepted from model output or a resubmitted client body.

Question Run may receive nullable `conversation_id` and `conversation_turn_id` in the next surface transition; Loop-33a first creates the referenced conversation substrate. These fields are only server-owned provenance links. Conversation history never passes to the model as an unstructured prompt: planner receives only the current canonical question and Evidence-authorized context. If conversation is unavailable, revoked, expired or purged, Question Run remains UNKNOWN/inaccessible under the same fail-closed rules as a standalone run.
`supersedes_question_run_id` means only a user rerun and is not passed to the model.

`result_status` and `corpus_status` are independent: a proven answer may be `COMPLETED + PARTIAL`. After terminal result status database trigger, UPDATE protected columns and INSERT/UPDATE/DELETE on child claims/citations/snapshots are forbidden.

`question_claim` has a unique `(organization_id, question_run_id, claim_id)`. `question_citation` has a unique `(organization_id, question_run_id, citation_number)`. `question_claim_citation` stores an M:N mapping with a unique `(organization_id, question_run_id, claim_id, citation_number)` and two composite FKs to claim and citation of the same Question Run. `question_claim_support` has composite FKs `(organization_id, question_run_id, claim_id)` and `(organization_id, question_run_id, supporting_claim_id)`. Self-reference, cycle, reference to `UNKNOWN`, and reference to a claim of another Question Run are forbidden by the semantic validator and deferred completion constraint. Citation↔claim mapping is checked bidirectionally before terminal commit.

`claim_verification` has a unique `(organization_id, question_run_id, claim_id)` and composite FKs to the same claim and selected successful `VERIFICATION` model run. Its child evidence/support rows are immutable and exact-match the canonical input described in `CANONICALIZATION.md`. `claim_deterministic_validation` has the same exact set of FACT/INFERENCE, exact-match verification input, and schema-valid output `numeric-validator-v1`; only `PASSED` is published. The terminal validator requires both records for each FACT/INFERENCE and none for UNKNOWN; mismatch in claim text hash, citations, evidence hashes, or supporting FACT means a TOCTOU error.

`model_profile` immutable; `profile_hash` covers exact prompt/template/schema/tokenizer/chat-template/runtime/decoding parameters per `CANONICALIZATION.md`. Identical revision string with a different hash is forbidden, and changing any covered byte creates a new profile revision. ModelRun exact-match references one trusted profile and does not repeat self-declared configuration.

For `model_run`, a unique `(organization_id, question_run_id, purpose, attempt)` applies; failed/retried attempts are retained, and fake calls are prohibited. `model_run_artifact` stores purpose-specific canonical input/output encrypted and with limited retention so that the terminal validator can recalculate hashes from trusted Model Gateway bytes; content does not enter audit/log. Exact rules are defined in `CANONICALIZATION.md`: query embedding is linked to question hash, reranking — to authorized candidate set, generation — to final context, verification — to exact claims/evidence. Selected generation output must be schema-valid and exact-match deterministic projection of final manifest claims/sections; post-verifier silent editing is prohibited. After artifact purge, immutable hashes, ClaimVerification, and deterministic validation remain as provenance, but raw model context is no longer provided. `selected_for_result=true` is permitted only for `SUCCEEDED`; required purposes exact-match immutable `question_model_execution_plan`. Answer span must have `end > start` and canonical UTF-8 boundaries.

Status coupling is a database completion invariant in both directions: `COMPLETED` requires at least one FACT and forbids UNKNOWN; `INSUFFICIENT_EVIDENCE` requires at least one UNKNOWN, FACT optional. Precheck/policy denial ends without an Answer Manifest.

`question_feedback` holds one *current* correctness mark per `(organization_id, question_run_id, created_by)` (`UNIQUE`, enforced by `ON CONFLICT` upsert, not append-only history) on a terminal `COMPLETED`/`INSUFFICIENT_EVIDENCE` run. `verdict` is `CORRECT` or `INCORRECT`; a free-text comment is only accepted by the service when `INCORRECT`, and is stored through the same envelope-encryption boundary as question/answer text (`comment_artifact_id`, ENCRYPTION.md), never as a plain column. Unlike every other owning column in the closed AAD inventory, `comment_artifact_id` is replaceable in place rather than write-once, because the mark itself can change. Row identity (`organization_id`, `id`, `question_run_id`, `workspace_id`, `created_by`, `created_at`) is immutable and there is no DELETE grant; changing a mind means UPDATE, not delete. Visibility mirrors the Question Run it marks: a member reads only their own feedback row, and the workspace OWNER/MANAGER additionally reads every member's row for the error-review report.

Transition to terminal status is performed in a single transaction only after saving claims, citations, corpus snapshot, canonical manifest bytes, manifest hash/signature, and audit event. Corpus snapshots are captured in `started_at`; model runs, principal/ACL authorization, retrieval capture, and deterministic validations are inside `[started_at, completed_at]`; manifest `signature.signed_at` exact-match `completed_at`. Violation of order or trusted interval blocks terminal commit. Repeat `Idempotency-Key` with the same canonical request hash returns the original Question Run; with a different hash returns conflict.

Repository Read Question Run first checks current access to all citations: current workspace membership, enabled binding of the current WorkspaceRevision, ACTIVE source-object membership of the exact scope revision, and, for `SOURCE_ENFORCED`, current identity mapping/ACL. Historical WorkspaceRevision in the manifest is provenance, not a grant. Scope narrowing/removal immediately blocks the old answer if the citation is no longer reachable through the current scope. `DELETED` or `ACCESS_REVOKED` do not change saved fields, but block issuance of `answer_markdown`, structured claims, and `cited_excerpt`.

`question_run_retention` is created together with QuestionRun. Read gate requires `ACTIVE && disclosure_allowed=true`; transition to `PURGING` atomically sets `disclosure_allowed=false` prior to physical deletion, so content is not revealed and during purge. Retention purge deletes `question_text`, answer body, excerpts, and canonical manifest content bytes via a separate privileged role. Only after verifying the physical absence of content does the state become `PURGED`. Tombstones, IDs, timestamps, non-secret statuses, manifest hash, signing envelope bytes, signature metadata, and audit events remain; after purge, the previous manifest can no longer be issued or reproduced, but the preserved hash can be cryptographically confirmed.

## 7. Audit and policy decisions

```text
signing_key
  id, organization_id,
  purpose(ANSWER_MANIFEST|CONNECTOR_EVENT|AUDIT_CHECKPOINT),
  connection_id, connector_agent_id,
  public_key_bytes, private_key_reference,
  status(ACTIVE|RETIRED|REVOKED),
  not_before, sign_until, retired_at, revoked_at, revocation_reason

policy_decision
  id, organization_id, actor_principal_id,
  operation, resource_type, resource_id,
  workspace_id, policy_revision, decision(ALLOW|DENY),
  reason_codes_json, decided_at

audit_event
  id, schema_version, organization_id, sequence, workspace_id,
  actor_type, actor_principal_id, on_behalf_of_principal_id,
  action, resource_type, resource_id,
  request_id, policy_decision_id,
  outcome, error_code, referenced_evidence_ids_json, metadata_json,
  canonical_bytes,
  previous_event_hash, event_hash, occurred_at

audit_chain_head
  organization_id, last_sequence, last_event_hash, updated_at

audit_checkpoint
  id, organization_id, checkpoint_sequence,
  event_first_sequence, event_last_sequence,
  first_event_hash, last_event_hash, previous_checkpoint_hash,
  canonical_bytes, checkpoint_hash, signature_json, created_at

audit_checkpoint_sink
  id, organization_id, type(WORM_OBJECT|IMMUTABLE_ARCHIVE|SIEM),
  endpoint_reference, credential_reference,
  status(PENDING|VERIFIED|DEGRADED|REVOKED),
  max_checkpoint_lag_seconds, last_verified_at

audit_checkpoint_delivery
  organization_id, checkpoint_id, sink_id,
  status(PENDING|ACKNOWLEDGED|FAILED), attempt,
  delivered_at, receipt_hash, error_code
```

The application role does not have UPDATE/DELETE on audit. the organization's `audit_chain_head` is locked on append to prevent two parallel transactions from creating a fork. Row passes `audit-event.schema.json`; `metadata_json` is formed only from the per-action allowlisted subset and does not contain an arbitrary body. `event_hash` is recalculated from full canonical bytes without the `event_hash` field. Checkpoint range loads full rows and repeats schema, metadata, and hash-chain validation; trusting only saved event hashes is forbidden.

unique `(organization_id, sequence)` and `(organization_id, event_hash)` are mandatory. Hash is computed based on `CANONICALIZATION.md` before the atomic update of chain head.

For each `(organization_id, purpose, connection/agent scope)` partial unique, exactly one ACTIVE signing key is permitted. The Signer uses the private key only via secret/KMS/HSM reference; PostgreSQL stores the public key and metadata. RETIRED remains verify-only for historical artifacts, REVOKED always results in integrity deny. Rotation of old/new key is performed in a single transaction. For connector server, only the public key is stored; the private key remains in the agent/customer vault.

`audit_checkpoint` has a unique `(organization_id, checkpoint_sequence)` and `(organization_id, checkpoint_hash)`, exact contiguous ranges, and a signed canonical contract from `CANONICALIZATION.md`. The Production organization has at least one `VERIFIED` external append-only sink; the delivery receipt is linked by hash. Expiration of `max_checkpoint_lag_seconds` transitions audit health to DEGRADED and blocks privileged config/member/source/key operations according to organization policy. An Application role cannot change checkpoint/delivery acknowledgement retroactively.

## 8. RLS

Each request transaction sets local parameters from the verified server context:

```text
app.organization_id
app.principal_id
app.request_id
```

Missing `app.organization_id` leads to zero rows/deny, not to unscoped query. For tenant tables, `FORCE ROW LEVEL SECURITY` is enabled; the application role does not own the tables. System workers use a service principal and a single explicitly specified organization on the job.

Repository method without `AuthorizedContext` is forbidden. Raw database pool is unavailable to transport handlers.

## 9. Product-scope tables

```text
conversation
  id, organization_id, workspace_id, workspace_revision, created_by,
  title_hash, lifecycle_state, created_at, archived_at

conversation_turn
  id, organization_id, conversation_id, ordinal, question_run_id,
  created_at

conversation_retention
  organization_id, conversation_id, state, disclosure_allowed,
  retention_fence, purge_reason, purge_started_at, purged_at

agent
agent_tool
report
notification
write_action
public_share
```

Autonomous agents, reports/notifications, write actions, and public shares remain prohibited. Conversation is a limited persistence layer only for workspace Question Runs; agent-specific memory, hidden tool calls, and cross-workspace history are prohibited. Within the scope of ADR-0085, the canonical knowledge graph is now a mandatory product layer and is not considered drift:

```text
canonical_entity
  id, organization_id, workspace_id, workspace_revision,
  entity_type, canonical_key_hash, display_name_hash, source_object_id,
  source_version_id, evidence_fragment_id, freshness_at, lifecycle_state,
  queryable, retention_fence, attributes_json

entity_relation
  id, organization_id, workspace_id, workspace_revision,
  subject_entity_id, predicate, object_entity_id, source_object_id,
  source_version_id, evidence_fragment_id, confidence, freshness_at,
  lifecycle_state, queryable, retention_fence, attributes_json

semantic_term
  id, organization_id, workspace_id, workspace_revision,
  canonical_entity_id, term_kind, language, term_hash, context_hash,
  source_object_id, source_version_id, evidence_fragment_id, confidence,
  freshness_at, lifecycle_state, queryable, retention_fence, attributes_json
```

All three tables are append-only, tenant/workspace-scoped and must carry exact
source/version/Evidence provenance. Their vectors, catalog projections and
derived snapshots inherit the same current-access, freshness, retention and
revocation gates; a graph edge is never an independent authorization grant.
