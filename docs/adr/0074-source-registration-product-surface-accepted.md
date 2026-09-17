# ADR-0074: Source registration and activation product surface (D3-1, D3-3)

Status: accepted.

Extends ADR-0059 (source lifecycle), ADR-0058 (catalog/extraction/Evidence) and
ADR-0073 (product surface for revision activation and Evidence delivery).
ADR-0073 records the enqueue contract but composes no surface itself; this ADR
is the first result that composes it: a product surface that creates a FOLDER
source connection and its WORKSPACE_MANAGED scope, binds it to a workspace,
requests revision activation through the production job queue, and reports the
typed sync status back to the UI. Trust verification stays outside this
surface, unchanged (ADR-0059 §authority, migration 000014/000016).

## 1. Decision

1. **Registration surface (D3-1).** `POST /api/v1/sources` creates the full
   Stage 2 DRAFT lineage — connection, connection revision 1, trust record and
   its DRAFT projection, discovered scope, scope, scope revision 1 and the
   DRAFT activation row — in one Go write transaction through two SECURITY
   DEFINER functions owned by the application role:

   - `app.source_folder_registration_begin(...)` performs every insert and
     returns the derived ids plus `created`. It is idempotent by construction:
     every id except the artifact ids is content-derived from the lineage, so a
     replay converges on the same rows; an exact-match replay returns
     `created = false` without touching rows, and a lineage collision with a
     different configuration raises a typed `23505` conflict.
   - The four sealed artifacts (trust profile, identity, display metadata,
     scope config) are written afterwards by four owner-branch bind functions
     (`app.source_trust_config_bind`, `app.source_scope_config_bind`,
     `app.source_discovered_scope_identity_bind`,
     `app.source_discovered_scope_display_bind`). The owning rows already
     record the pre-generated artifact ids and hashes; the deferred
     `DEFERRABLE INITIALLY DEFERRED` artifact-guard constraint triggers of
     migrations 000006/000007 validate exact ownership, resource ids and
     plaintext hashes at commit, so a partial or mismatched artifact set can
     never commit. The owning-row FK cycle (revision rows reference artifact
     ids with deferred FKs) is therefore closed without weakening a single
     guard.

2. **Content-derived ids.** `connection_id`, `discovered_scope_id`,
   `source_scope_id`, `trust_record_id` and `credential_reference` are
   `prefix + "_" + 26 Crockford characters` encoding 128 bits of `sha256` over
   a canonical lineage string (connection lineage includes the tenant and the
   trusted root identity; the scope lineage includes the connection). The first
   character carries three bits and therefore always falls in `[0-7]`, exactly
   the shape `app.source_generated_id_is_valid` requires. Artifact ids are
   minted by `ids.New("artifact")` because artifacts are not lineage-stable.
   The idempotency property above follows from this derivation, not from a
   key-column deduplication.

3. **Identity/display plaintext forms.** `CANONICALIZATION.md` deliberately
   does not define these; this ADR freezes them:
   - identity plaintext: canonical JCS of
     `{"schema_version":"source-scope-identity-v1","source_type":"FOLDER","connection_id":...,"relative_root":...}`;
     the stored `identity_digest` is `canon.HMACDigest` over those bytes under
     the platform SourceDigestKey (the same keyed-digest scheme as object
     locators), so the worker can re-derive and compare it.
   - display plaintext: canonical JCS of
     `{"schema_version":"source-scope-display-v1","name":...,"kind":...}`.

4. **Trust verification boundary (unchanged).** Registration produces a DRAFT
   trust projection only. `DRAFT -> VERIFIED` remains the admin/control-plane
   authority of migration 000014/000016; this ADR deliberately composes no
   SECURITY DEFINER trust setter, and the activation surface refuses any scope
   whose `trust_verified` is false with a typed code. The S1 scenario therefore
   includes the documented admin verification step between registration and
   activation.

5. **Connector profile selection.** The application reads the newest verified
   `connector_capability_profile` with `connector_type = 'FOLDER'` and passes
   the exact tuple into `begin`; the non-deferred capability FK on
   `source_connection_revision` re-validates the tuple verbatim, so a profile
   that disappears or changes between read and write fails the transaction.
   Missing profile is a typed service-unavailable condition, never a fallback
   connector.

6. **Activation request.** `POST /api/v1/sources/{id}:activate` gates on the
   `app.source_scope_sync_target` projection of the pending revision:
   activation status must be DRAFT/READY/FAILED (SYNCING and REVOKED return
   typed conflicts), `trust_verified` must be true, and for WORKSPACE_MANAGED
   the derived-live confirmation gate
   `app.source_scope_activation_confirmed(scope, revision, config_hash)` must
   hold — the mirror of the 000010 `derived_live_guard`: current workspace
   revision, enabled binding with the exact config hash, current warning
   contract revision, a grant that covers the confirmation and is not revoked
   by either revocation type. The work is then placed through
   `jobs.Queue.Enqueue` (ADR-0073 §1.1) with the client Idempotency-Key as the
   queue key, so a retried request converges on one job. A
   `source.activation_requested` audit event follows the enqueue; a failure
   after enqueue returns a persistence error and the idempotent retry heals
   both the enqueue deduplication and the audit record.

7. **Status surface (D3-3).** `GET /api/v1/workspaces/{id}/sources` is
   member-only and resolves the current workspace revision: per binding it
   reports scope id, revision, access mode, enabled, config hash, connection
   name, activation status, trust verification and the last sync run
   (`status`, typed `error_code`, timestamps, counters). Sync error codes are
   the typed OPS-010 surface the UI renders; no parser path or content ever
   crosses this endpoint.

8. **Audit vocabulary.** Registration emits `source.registration_created`
   (resource type SOURCE_SCOPE) with metadata restricted to
   `source_connection_id`, `source_scope_id`, `source_scope_revision` — the
   reserved workspace-source vocabulary (`scope_config_hash`, `access_mode`,
   `enabled`) is deliberately absent because the 000011 projection guard bans
   it on non-workspace-source events. Activation emits
   `source.activation_requested`. Both actions are new members of the Go
   audit-action inventory; the schema already admits them by its action
   pattern.

9. **Policy.** Registration requires the organization-level OWNER role (the
   `currentActor` pattern of the workspace repository). Workspace binding keeps
   the existing `OperationWorkspaceManageSources` policy and If-Match
   precondition of `AddSource`; the activation request is an OWNER-gated
   organization action on the source itself.

10. **Not in this ADR.** A trust-verification setter (DRAFT -> VERIFIED stays
    admin-only), revision > 1 lineage evolution, non-FOLDER connectors,
    SOURCE_ENFORCED access mode (registration serves WORKSPACE_MANAGED only),
    the Evidence viewer and inspection UI (ADR-0073 §2), and key rotation
    (ADR-0070).

## 2. Acceptance binding

D3-1 (folder connection and sync scope created through the product surface,
end-to-end S1, `jobs.Queue.Enqueue` called from a non-test production path)
and D3-3 (sync status and typed errors visible in API responses and the UI)
become the acceptance criteria of the result that lands this surface, executed
on real PostgreSQL in CI: register -> bind -> admin trust verification ->
activation request -> worker sync -> READY status; idempotent replay converges
without duplicates; lineage collision returns a typed conflict; activation
without a derived-live confirmation returns a typed denial; a broken object
surfaces a typed sync error code in the status endpoint.

## 3. Consequences

The product loop gains its first composed source surface and the D3 criteria
gain an executable definition. The surface is deliberately thin: all authority
stays in SQL gates (000006/000007/000010/000014/000016) that the new
functions reuse verbatim, and every denial is a typed repository or API code
with no existence oracle. The trust-verification authority boundary remains
explicitly unset, which keeps the S1 scenario's admin step visible to the
owner until a future ADR defines the verification product surface.
