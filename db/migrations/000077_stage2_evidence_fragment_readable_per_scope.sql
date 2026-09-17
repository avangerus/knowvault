-- 000077: app.evidence_fragment_readable (000014, last replaced by 000020)
-- has the exact same defect 000076 fixed in app.source_scope_activation_
-- confirmed: it requires the confirmation's own recorded workspace_revision
-- to equal workspace.current_revision. Every read of an evidence fragment --
-- every citation, every AGG-1 structured-snapshot cell (loadStructuredSnapshot
-- calls this same function per cell), every retrieval hit's authorization --
-- goes through this predicate, so this is the more directly demo-visible half
-- of the "any workspace mutation invalidates confirmation for all
-- sources" defect: "answers arrive without citations" after any unrelated
-- workspace mutation is THIS join losing its match, not the activation gate.
--
-- Fix is the same shape as 000076: stop requiring the confirmation's own
-- workspace_revision to equal the current one. The workspace_revision_source
-- binding (wrs) is already correctly joined at the workspace's CURRENT
-- revision; join the confirmation against that same current-revision binding
-- row's own tuple (workspace_source_id, scope_config_hash) instead of
-- requiring the confirmation to separately match the live revision. A
-- confirmation for THIS exact, unchanged source tuple still authorizes the
-- read no matter how many unrelated sources were toggled since; a
-- confirmation whose own source's tuple changed (disabled, reconfigured, a
-- new scope revision) no longer matches wrs at the current revision and
-- correctly stops authorizing reads, fail-closed exactly as before.

BEGIN;

CREATE OR REPLACE FUNCTION app.evidence_fragment_readable(p_fragment_id text, p_workspace_id text)
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
        JOIN public.source_extraction_retention er
          ON er.organization_id = f.organization_id AND er.extraction_id = f.extraction_id
        JOIN public.source_version_active_extraction ae
          ON ae.organization_id = f.organization_id AND ae.source_version_id = f.source_version_id
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
          AND f.anchor_digest_key_version IS NOT NULL
          AND app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
          AND f.text_digest_key_version IS NOT NULL
          AND app.source_keyed_digest_matches_version(f.text_hash, f.text_digest_key_version)
          AND o.lifecycle_state = 'ACTIVE'
          AND o.current_version_id = v.id
          AND v.state = 'CURRENT'
          AND vr.state = 'ACTIVE' AND vr.queryable
          AND er.state = 'ACTIVE' AND er.queryable
          AND ae.extraction_id = f.extraction_id
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

REVOKE ALL ON FUNCTION app.evidence_fragment_readable(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_readable(text, text) TO knowvault_app;

COMMIT;
