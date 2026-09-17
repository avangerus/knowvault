-- Exact historical evidence reads are a separate capability from the normal
-- current-fragment reader. They retain the same tenant, membership, scope,
-- confirmation, revocation, keyed-projection and retention fences, while
-- resolving one immutable source version and one successful extraction without
-- requiring that extraction to remain the version's active search extraction.

BEGIN;

CREATE OR REPLACE FUNCTION app.evidence_fragment_exact_readable(
    p_fragment_id text,
    p_workspace_id text,
    p_expected_version_id text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.evidence_fragment f
        JOIN public.evidence_anchor_projection ap
          ON ap.organization_id = f.organization_id AND ap.fragment_id = f.id
         AND ap.anchor_hash = f.anchor_hash AND ap.digest_key_version = f.anchor_digest_key_version
        JOIN public.evidence_text_projection tp
          ON tp.organization_id = f.organization_id AND tp.fragment_id = f.id
         AND tp.text_hash = f.text_hash AND tp.digest_key_version = f.text_digest_key_version
        JOIN public.source_version v
          ON v.organization_id = f.organization_id AND v.id = f.source_version_id
        JOIN public.source_object o
          ON o.organization_id = v.organization_id AND o.id = v.source_object_id
        JOIN public.source_version_retention vr
          ON vr.organization_id = v.organization_id AND vr.source_version_id = v.id
        JOIN public.source_extraction e
          ON e.organization_id = f.organization_id
         AND e.id = f.extraction_id
         AND e.source_version_id = f.source_version_id
        JOIN public.source_extraction_retention er
          ON er.organization_id = e.organization_id AND er.extraction_id = e.id
        JOIN public.source_object_scope os
          ON os.organization_id = o.organization_id AND os.source_object_id = o.id
        JOIN public.workspace w
          ON w.organization_id = f.organization_id AND w.id = p_workspace_id
        JOIN public.workspace_member wm
          ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
         AND wm.principal_id = app.current_principal_id()
         AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
        JOIN public.workspace_revision_source wrs
          ON wrs.organization_id = w.organization_id AND wrs.workspace_id = w.id
         AND wrs.workspace_revision = w.current_revision
         AND wrs.source_scope_id = os.source_scope_id
         AND wrs.source_scope_revision = os.source_scope_revision
         AND wrs.enabled
        JOIN public.workspace_managed_grant_confirmation c
          ON c.organization_id = w.organization_id AND c.workspace_id = w.id
         AND c.workspace_source_id = wrs.workspace_source_id
         AND c.source_scope_id = os.source_scope_id
         AND c.source_scope_revision = os.source_scope_revision
         AND c.scope_config_hash = wrs.scope_config_hash
         AND c.access_mode = 'WORKSPACE_MANAGED'
        WHERE f.organization_id = app.current_organization_id()
          AND f.id = p_fragment_id
          AND p_expected_version_id IS NOT NULL AND p_expected_version_id <> ''
          AND f.source_version_id = p_expected_version_id
          AND f.anchor_digest_key_version IS NOT NULL
          AND app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
          AND f.text_digest_key_version IS NOT NULL
          AND app.source_keyed_digest_matches_version(f.text_hash, f.text_digest_key_version)
          AND o.lifecycle_state = 'ACTIVE' AND o.queryable
          AND v.state IN ('CURRENT', 'SUPERSEDED')
          AND vr.state = 'ACTIVE' AND vr.queryable
          AND e.status = 'SUCCEEDED'
          AND er.state = 'ACTIVE' AND er.queryable
          AND os.membership_state = 'ACTIVE'
          AND wrs.access_mode = 'WORKSPACE_MANAGED'
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_managed_grant_revocation gr
              WHERE gr.organization_id = c.organization_id AND gr.confirmation_id = c.confirmation_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
              WHERE ar.organization_id = c.organization_id
                AND ar.grant_id = c.confirmation_actor_grant_id
          )
    );
$$;

CREATE OR REPLACE FUNCTION app.evidence_fragment_read_exact_normalized_text(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.evidence_fragment f
    JOIN public.evidence_text_projection tp
      ON tp.organization_id = f.organization_id AND tp.fragment_id = f.id
     AND tp.text_hash = f.text_hash AND tp.digest_key_version = f.text_digest_key_version
    JOIN public.source_version v
      ON v.organization_id = f.organization_id AND v.id = f.source_version_id
    JOIN public.encrypted_artifact a
      ON a.organization_id = f.organization_id AND a.id = f.normalized_text_artifact_id
    WHERE f.organization_id = app.current_organization_id()
      AND f.id = p_owning_row_id
      AND f.source_version_id = NULLIF(current_setting('app.evidence_source_version_id', true), '')
      AND a.purged_at IS NULL
      AND app.evidence_fragment_exact_readable(
          f.id, NULLIF(current_setting('app.workspace_id', true), ''), v.id);
$$;

CREATE OR REPLACE FUNCTION app.evidence_fragment_read_exact_anchor(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.evidence_fragment f
    JOIN public.evidence_anchor_projection ap
      ON ap.organization_id = f.organization_id AND ap.fragment_id = f.id
     AND ap.anchor_hash = f.anchor_hash AND ap.digest_key_version = f.anchor_digest_key_version
    JOIN public.source_version v
      ON v.organization_id = f.organization_id AND v.id = f.source_version_id
    JOIN public.encrypted_artifact a
      ON a.organization_id = f.organization_id AND a.id = f.anchor_artifact_id
    WHERE f.organization_id = app.current_organization_id()
      AND f.id = p_owning_row_id
      AND f.source_version_id = NULLIF(current_setting('app.evidence_source_version_id', true), '')
      AND f.anchor_digest_key_version IS NOT NULL
      AND app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
      AND a.purged_at IS NULL
      AND app.evidence_fragment_exact_readable(
          f.id, NULLIF(current_setting('app.workspace_id', true), ''), v.id);
$$;

REVOKE ALL ON FUNCTION app.evidence_fragment_exact_readable(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.evidence_fragment_read_exact_normalized_text(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.evidence_fragment_read_exact_anchor(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_exact_readable(text, text, text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_read_exact_normalized_text(text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_read_exact_anchor(text) TO knowvault_app;

COMMIT;
