-- Stage 2 source-status projection extension.
--
-- The existing status function deliberately exposed the scope lineage but not
-- the stable workspace binding identity.  The product surface needs that
-- identity to issue an exact, optimistic-concurrency-protected remove/re-enable
-- command without deriving an authority id in the browser.  Keep the original
-- function for compatibility and publish a v2 projection with one additional
-- content-free column.

BEGIN;

CREATE OR REPLACE FUNCTION app.workspace_source_status_v2(p_workspace_id text)
RETURNS TABLE(
    workspace_source_id text,
    source_scope_id text,
    source_scope_revision bigint,
    access_mode text,
    enabled boolean,
    scope_config_hash text,
    connection_id text,
    connection_name text,
    activation_status text,
    trust_verified boolean,
    sync_status text,
    sync_error_code text,
    sync_started_at timestamptz,
    sync_completed_at timestamptz,
    objects_seen bigint,
    objects_ingested bigint,
    versions_created bigint,
    evidence_published bigint,
    quarantined bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT binding.workspace_source_id, binding.source_scope_id,
           binding.source_scope_revision, binding.access_mode, binding.enabled,
           binding.scope_config_hash, scope.connection_id, connection.name,
           activation.status,
           EXISTS (
               SELECT 1
               FROM public.source_connection_trust_record AS trust_record
               JOIN public.source_connection_trust_projection AS projection
                 ON projection.organization_id = trust_record.organization_id
                AND projection.trust_record_id = trust_record.id
               JOIN public.source_scope_revision AS scope_revision
                 ON scope_revision.organization_id = trust_record.organization_id
                AND scope_revision.connection_id = trust_record.connection_id
                AND scope_revision.connection_revision = trust_record.connection_revision
               JOIN public.source_connection_revision AS connection_revision
                 ON connection_revision.organization_id = scope_revision.organization_id
                AND connection_revision.connection_id = scope_revision.connection_id
                AND connection_revision.revision = scope_revision.connection_revision
                AND connection_revision.trust_profile_hash = trust_record.trust_profile_hash
               WHERE scope_revision.organization_id = binding.organization_id
                 AND scope_revision.source_scope_id = binding.source_scope_id
                 AND scope_revision.revision = binding.source_scope_revision
                 AND projection.status = 'VERIFIED'
           ),
           sync_run.status, sync_run.error_code, sync_run.started_at,
           sync_run.completed_at, sync_run.objects_seen, sync_run.objects_ingested,
           sync_run.versions_created, sync_run.evidence_published,
           sync_run.quarantined
    FROM public.workspace_revision_source AS binding
    JOIN public.source_scope AS scope
      ON scope.organization_id = binding.organization_id
     AND scope.id = binding.source_scope_id
    JOIN public.source_connection AS connection
      ON connection.organization_id = binding.organization_id
     AND connection.id = scope.connection_id
    JOIN public.source_scope_activation AS activation
      ON activation.organization_id = binding.organization_id
     AND activation.source_scope_id = binding.source_scope_id
     AND activation.source_scope_revision = binding.source_scope_revision
    LEFT JOIN LATERAL (
        SELECT run.status, run.error_code, run.started_at, run.completed_at,
               run.objects_seen, run.objects_ingested, run.versions_created,
               run.evidence_published, run.quarantined
        FROM public.sync_run AS run
        WHERE run.organization_id = binding.organization_id
          AND run.source_scope_id = binding.source_scope_id
          AND run.source_scope_revision = binding.source_scope_revision
        ORDER BY run.started_at DESC, run.id DESC
        LIMIT 1
    ) AS sync_run ON true
    WHERE binding.organization_id = app.current_organization_id()
      AND binding.workspace_id = p_workspace_id
      AND binding.workspace_revision = (
          SELECT workspace.current_revision
          FROM public.workspace
          WHERE workspace.organization_id = app.current_organization_id()
            AND workspace.id = p_workspace_id
      )
      AND EXISTS (
          SELECT 1
          FROM public.workspace_member AS member
          WHERE member.organization_id = app.current_organization_id()
            AND member.workspace_id = p_workspace_id
            AND member.principal_id = app.current_principal_id()
            AND member.removed_at IS NULL
      )
    ORDER BY binding.source_scope_id;
$$;

REVOKE ALL ON FUNCTION app.workspace_source_status_v2(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.workspace_source_status_v2(text) TO knowvault_app;

COMMIT;
