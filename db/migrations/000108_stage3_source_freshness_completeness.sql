-- F1/F2/F6: successful synchronization does not prove every observed update
-- was processed. Preserve readable immutable versions and run status, but
-- degrade the existing source/question freshness projections while the exact
-- bound scope/revision has unresolved skips or its applicable successful scan
-- was incomplete. The existing skip-resolution ledger owns recovery; neither
-- these projections nor this migration changes lifecycle, retention or ACLs.
-- Existing captured Question Run snapshots are intentionally not rewritten.
BEGIN;

CREATE OR REPLACE FUNCTION app.workspace_source_status_v3(p_workspace_id text)
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
    quarantined bigint,
    job_id text,
    job_status text,
    job_attempt_count integer,
    job_max_attempts integer,
    job_available_at timestamptz,
    job_lease_expires_at timestamptz,
    job_last_error_code text,
    content_freshness_sla_seconds integer,
    last_successful_sync_at timestamptz,
    freshness_state text,
    sync_interval_seconds integer
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
               JOIN public.source_scope_revision AS trust_scope_revision
                 ON trust_scope_revision.organization_id = trust_record.organization_id
                AND trust_scope_revision.connection_id = trust_record.connection_id
                AND trust_scope_revision.connection_revision = trust_record.connection_revision
               JOIN public.source_connection_revision AS connection_revision
                 ON connection_revision.organization_id = trust_scope_revision.organization_id
                AND connection_revision.connection_id = trust_scope_revision.connection_id
                AND connection_revision.revision = trust_scope_revision.connection_revision
                AND connection_revision.trust_profile_hash = trust_record.trust_profile_hash
               WHERE trust_scope_revision.organization_id = binding.organization_id
                 AND trust_scope_revision.source_scope_id = binding.source_scope_id
                 AND trust_scope_revision.revision = binding.source_scope_revision
                 AND projection.status = 'VERIFIED'
           ),
           sync_run.status, sync_run.error_code, sync_run.started_at,
           sync_run.completed_at, sync_run.objects_seen, sync_run.objects_ingested,
           sync_run.versions_created, sync_run.evidence_published,
           sync_run.quarantined,
           COALESCE(sync_job.id, pending_job.id),
           COALESCE(sync_job.status, pending_job.status),
           COALESCE(sync_job.attempt_count, pending_job.attempt_count),
           COALESCE(sync_job.max_attempts, pending_job.max_attempts),
           COALESCE(sync_job.available_at, pending_job.available_at),
           COALESCE(sync_job.lease_deadline, pending_job.lease_deadline),
           COALESCE(sync_job.last_error_code, pending_job.last_error_code),
           scope_revision.content_freshness_sla_seconds,
           successful_run.completed_at,
           CASE
               WHEN successful_run.completed_at IS NULL THEN 'UNKNOWN'
               WHEN NOT successful_run.coverage_complete OR EXISTS (
                   SELECT 1 FROM app.source_object_current_skips() AS skipped
                   WHERE skipped.organization_id = binding.organization_id
                     AND skipped.source_scope_id = binding.source_scope_id
                     AND skipped.source_scope_revision = binding.source_scope_revision
               ) THEN 'STALE'
               WHEN transaction_timestamp() <= successful_run.completed_at
                    + make_interval(secs => scope_revision.content_freshness_sla_seconds)
                   THEN 'FRESH'
               ELSE 'STALE'
           END,
           scope_revision.sync_interval_seconds
    FROM public.workspace_revision_source AS binding
    JOIN public.workspace AS workspace
      ON workspace.organization_id = binding.organization_id
     AND workspace.id = binding.workspace_id
     AND workspace.current_revision = binding.workspace_revision
    JOIN public.source_scope AS scope
      ON scope.organization_id = binding.organization_id
     AND scope.id = binding.source_scope_id
    JOIN public.source_scope_revision AS scope_revision
      ON scope_revision.organization_id = binding.organization_id
     AND scope_revision.source_scope_id = binding.source_scope_id
     AND scope_revision.revision = binding.source_scope_revision
    JOIN public.source_connection AS connection
      ON connection.organization_id = binding.organization_id
     AND connection.id = scope.connection_id
    JOIN public.source_scope_activation AS activation
      ON activation.organization_id = binding.organization_id
     AND activation.source_scope_id = binding.source_scope_id
     AND activation.source_scope_revision = binding.source_scope_revision
    LEFT JOIN LATERAL (
        SELECT run.id, run.job_id, run.status, run.error_code, run.started_at,
               run.completed_at, run.objects_seen, run.objects_ingested,
               run.versions_created, run.evidence_published, run.quarantined
        FROM public.sync_run AS run
        WHERE run.organization_id = binding.organization_id
          AND run.source_scope_id = binding.source_scope_id
          AND run.source_scope_revision = binding.source_scope_revision
        ORDER BY run.started_at DESC, run.id DESC
        LIMIT 1
    ) AS sync_run ON true
    LEFT JOIN public.job AS sync_job
      ON sync_job.organization_id = binding.organization_id
     AND sync_job.id = sync_run.job_id
    LEFT JOIN LATERAL (
        SELECT run.completed_at, run.coverage_complete
        FROM public.sync_run AS run
        WHERE run.organization_id = binding.organization_id
          AND run.source_scope_id = binding.source_scope_id
          AND run.source_scope_revision = binding.source_scope_revision
          AND run.status = 'SUCCEEDED'
          AND run.completed_at IS NOT NULL
        ORDER BY run.started_at DESC, run.id DESC
        LIMIT 1
    ) AS successful_run ON true
    LEFT JOIN LATERAL (
        SELECT job.id, job.status, job.attempt_count, job.max_attempts,
               job.available_at, job.lease_deadline, job.last_error_code
        FROM public.job AS job
        WHERE job.organization_id = binding.organization_id
          AND job.type IN ('SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC')
          AND job.status = 'PENDING'
          AND job.payload_json ->> 'source_scope_id' = binding.source_scope_id
        ORDER BY job.created_at DESC, job.id DESC
        LIMIT 1
    ) AS pending_job ON sync_run.id IS NULL
    WHERE binding.organization_id = app.current_organization_id()
      AND binding.workspace_id = p_workspace_id
      AND EXISTS (
          SELECT 1
          FROM public.workspace_member AS member
          WHERE member.organization_id = binding.organization_id
            AND member.workspace_id = binding.workspace_id
            AND member.principal_id = app.current_principal_id()
            AND member.removed_at IS NULL
      )
    ORDER BY binding.source_scope_id;
$$;

REVOKE ALL ON FUNCTION app.workspace_source_status_v3(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.workspace_source_status_v3(text) TO knowvault_app;


CREATE OR REPLACE FUNCTION app.question_corpus_source_status(
    p_workspace_id text, p_source_scope_id text, p_source_scope_revision bigint
)
RETURNS TABLE(
    connector_type text,
    connector_version text,
    health text,
    content_watermark bigint,
    last_successful_sync timestamptz,
    trust_verified boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT scope.source_type,
           connection_revision.connector_version,
           CASE
               WHEN NOT trust_projection.trust_verified THEN 'UNKNOWN'
               WHEN sync.status = 'SUCCEEDED' AND (
                    NOT sync.coverage_complete OR EXISTS (
                        SELECT 1 FROM app.source_object_current_skips() AS skipped
                        WHERE skipped.organization_id = scope.organization_id
                          AND skipped.source_scope_id = scope.source_scope_id
                          AND skipped.source_scope_revision = scope.revision
                    )
                ) THEN 'STALE'
                WHEN sync.status = 'SUCCEEDED' THEN 'HEALTHY'
               WHEN sync.status = 'FAILED' THEN 'FAILED'
               WHEN sync.status = 'RUNNING' THEN 'STALE'
               ELSE 'UNKNOWN'
           END,
           CASE
               WHEN sync.cursor_after ~ '^[0-9]{1,16}$'
               THEN sync.cursor_after::bigint
               ELSE 0
           END,
           CASE WHEN sync.status = 'SUCCEEDED' THEN sync.completed_at ELSE NULL END,
           trust_projection.trust_verified
      FROM public.workspace_revision_source binding
      JOIN public.source_scope_revision scope
        ON scope.organization_id = binding.organization_id
       AND scope.source_scope_id = binding.source_scope_id
       AND scope.revision = binding.source_scope_revision
      JOIN public.source_connection_revision connection_revision
        ON connection_revision.organization_id = scope.organization_id
       AND connection_revision.connection_id = scope.connection_id
       AND connection_revision.revision = scope.connection_revision
      LEFT JOIN LATERAL (
          SELECT run.status, run.cursor_after, run.completed_at, run.coverage_complete
            FROM public.sync_run run
           WHERE run.organization_id = scope.organization_id
             AND run.source_scope_id = scope.source_scope_id
             AND run.source_scope_revision = scope.revision
           ORDER BY run.started_at DESC, run.id DESC
           LIMIT 1
      ) sync ON true
      CROSS JOIN LATERAL (
          SELECT EXISTS (
              SELECT 1
                FROM public.source_connection_trust_record trust_record
                JOIN public.source_connection_trust_projection projection
                  ON projection.organization_id = trust_record.organization_id
                 AND projection.trust_record_id = trust_record.id
               WHERE trust_record.organization_id = scope.organization_id
                 AND trust_record.connection_id = scope.connection_id
                 AND trust_record.connection_revision = scope.connection_revision
                 AND trust_record.trust_profile_hash = connection_revision.trust_profile_hash
                 AND projection.status = 'VERIFIED'
                 AND trust_record.expires_at > transaction_timestamp()
          ) AS trust_verified
      ) trust_projection
     WHERE binding.organization_id = app.current_organization_id()
       AND binding.workspace_id = p_workspace_id
       AND binding.workspace_revision = (
           SELECT workspace.current_revision
             FROM public.workspace
            WHERE workspace.organization_id = binding.organization_id
              AND workspace.id = p_workspace_id
       )
       AND binding.source_scope_id = p_source_scope_id
       AND binding.source_scope_revision = p_source_scope_revision
       AND binding.enabled;
$$;

REVOKE ALL ON FUNCTION app.question_corpus_source_status(text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_corpus_source_status(text, text, bigint) TO knowvault_app;


COMMIT;
