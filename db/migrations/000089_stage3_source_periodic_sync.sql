-- 000089: extend the existing worker schedule lookup to safe source syncs.
--
-- FOLDER is refreshed through the existing SOURCE_SCOPE_SYNC handler.  The
-- PostgreSQL projection keeps its POSTGRESQL_QUERY_SYNC handler.  GIT is not
-- scheduled here: the existing MOUNT provider reads a deployment-populated
-- checkout and does not own checkout refresh, while the HTTPS providers have
-- no autonomous credential/refresh contract in this worker.
--
-- The first function owns the worker-only row locks and rechecks due/live/DEAD
-- state after those locks. Registration.Service then enqueues through
-- app.enqueue_job and appends audit in the same transaction; the existing
-- operation=ACTIVATE unique index also closes scheduler/API races at the
-- durable job boundary.
BEGIN;

-- The worker can inspect source rows through the existing due lookup, but it
-- must not receive UPDATE privilege solely to lock them. This narrow worker
-- surface takes the source row lock first and the exact activation row lock
-- second; both locks live until the caller's enqueue/audit transaction ends.
CREATE OR REPLACE FUNCTION app.source_scope_schedule_lock(
    p_source_scope_id text, p_source_scope_revision bigint
)
RETURNS TABLE(active_revision bigint, activation_status text, still_due boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    active_revision_value bigint;
    activation_status_value text;
    still_due_value boolean;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source schedule lock is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'source schedule lock requires a tenant context' USING ERRCODE = '42501';
    END IF;
    SELECT scope.active_revision INTO active_revision_value
    FROM public.source_scope AS scope
    WHERE scope.organization_id = organization_value
      AND scope.id = p_source_scope_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT activation.status INTO activation_status_value
    FROM public.source_scope_activation AS activation
    WHERE activation.organization_id = organization_value
      AND activation.source_scope_id = p_source_scope_id
      AND activation.source_scope_revision = p_source_scope_revision
      AND activation.revision = 1
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT (
        COALESCE((
            SELECT run.completed_at
            FROM public.sync_run AS run
            WHERE run.organization_id = organization_value
              AND run.source_scope_id = activation.source_scope_id
              AND run.source_scope_revision = activation.source_scope_revision
              AND run.status = 'SUCCEEDED'
            ORDER BY run.started_at DESC, run.id DESC
            LIMIT 1
        ), activation.activated_at) <= transaction_timestamp()
            - make_interval(secs => scope_revision.sync_interval_seconds)
        AND NOT EXISTS (
            SELECT 1
            FROM public.job AS live_job
            WHERE live_job.organization_id = organization_value
              AND live_job.type IN ('SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC')
              AND live_job.status IN ('PENDING', 'RUNNING')
              AND live_job.payload_json ->> 'source_scope_id' = activation.source_scope_id
        )
        AND NOT EXISTS (
            SELECT 1
            FROM public.job AS dead_job
            WHERE dead_job.organization_id = organization_value
              AND dead_job.type IN ('SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC')
              AND dead_job.status = 'DEAD'
              AND dead_job.payload_json ->> 'source_scope_id' = activation.source_scope_id
              AND dead_job.completed_at > transaction_timestamp()
                  - make_interval(secs => scope_revision.sync_interval_seconds)
        )
    )
    INTO still_due_value
    FROM public.source_scope_activation AS activation
    JOIN public.source_scope_revision AS scope_revision
      ON scope_revision.organization_id = activation.organization_id
     AND scope_revision.source_scope_id = activation.source_scope_id
     AND scope_revision.revision = activation.source_scope_revision
    WHERE activation.organization_id = organization_value
      AND activation.source_scope_id = p_source_scope_id
      AND activation.source_scope_revision = p_source_scope_revision
      AND activation.revision = 1
      AND activation.status = 'READY';
    IF NOT FOUND THEN
        RETURN QUERY SELECT active_revision_value, activation_status_value, false;
        RETURN;
    END IF;
    RETURN QUERY SELECT active_revision_value, activation_status_value, COALESCE(still_due_value, false);
END;
$$;

REVOKE ALL ON FUNCTION app.source_scope_schedule_lock(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_scope_schedule_lock(text, bigint) TO knowvault_worker;

CREATE OR REPLACE FUNCTION app.postgresql_query_scope_due(p_limit integer)
RETURNS TABLE(source_scope_id text, source_scope_revision bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source schedule lookup is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'source schedule limit is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'source schedule lookup requires a tenant context' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT activation.source_scope_id, activation.source_scope_revision
    FROM public.source_scope_activation AS activation
    JOIN public.source_scope AS scope
      ON scope.organization_id = activation.organization_id
     AND scope.id = activation.source_scope_id
     AND scope.active_revision = activation.source_scope_revision
    JOIN public.source_scope_revision AS revision
      ON revision.organization_id = activation.organization_id
     AND revision.source_scope_id = activation.source_scope_id
     AND revision.revision = activation.source_scope_revision
    LEFT JOIN public.postgresql_query_projection AS projection
      ON projection.organization_id = activation.organization_id
     AND projection.source_scope_id = activation.source_scope_id
     AND projection.source_scope_revision = activation.source_scope_revision
    WHERE activation.organization_id = organization_value
      AND activation.status = 'READY'
      AND (
          revision.source_type = 'FOLDER'
          OR (revision.source_type = 'POSTGRESQL_QUERY' AND projection.status = 'ACTIVE')
      )
      AND EXISTS (
          SELECT 1
          FROM public.source_connection_trust_record AS trust_record
          JOIN public.source_connection_trust_projection AS trust_projection
            ON trust_projection.organization_id = trust_record.organization_id
           AND trust_projection.trust_record_id = trust_record.id
          JOIN public.source_connection_revision AS connection_revision
            ON connection_revision.organization_id = trust_record.organization_id
           AND connection_revision.connection_id = trust_record.connection_id
           AND connection_revision.revision = trust_record.connection_revision
           AND connection_revision.trust_profile_hash = trust_record.trust_profile_hash
          WHERE trust_record.organization_id = organization_value
            AND trust_record.connection_id = revision.connection_id
            AND trust_record.connection_revision = revision.connection_revision
            AND trust_projection.status = 'VERIFIED'
      )
      AND (
          revision.access_mode <> 'WORKSPACE_MANAGED'
          OR app.source_scope_activation_confirmed(
              activation.source_scope_id, activation.source_scope_revision,
              revision.scope_config_hash)
      )
      AND NOT EXISTS (
          SELECT 1 FROM public.job AS live_job
          WHERE live_job.organization_id = organization_value
            AND live_job.type IN ('SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC')
            AND live_job.status IN ('PENDING', 'RUNNING')
            AND live_job.payload_json ->> 'source_scope_id' = activation.source_scope_id
      )
      -- A DEAD scheduled job already consumed its bounded retry budget.  Do
      -- not recreate it on every poll; the configured source interval is the
      -- durable retry cooldown, after which the next scheduled run is due.
      AND NOT EXISTS (
          SELECT 1 FROM public.job AS dead_job
          WHERE dead_job.organization_id = organization_value
            AND dead_job.type IN ('SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC')
            AND dead_job.status = 'DEAD'
            AND dead_job.payload_json ->> 'source_scope_id' = activation.source_scope_id
            AND dead_job.completed_at > transaction_timestamp()
                - make_interval(secs => revision.sync_interval_seconds)
      )
      AND COALESCE(
          (SELECT run.completed_at FROM public.sync_run AS run
           WHERE run.organization_id = organization_value
             AND run.source_scope_id = activation.source_scope_id
             AND run.source_scope_revision = activation.source_scope_revision
             AND run.status = 'SUCCEEDED'
           ORDER BY run.started_at DESC, run.id DESC LIMIT 1),
          activation.activated_at
      ) <= transaction_timestamp() - make_interval(secs => revision.sync_interval_seconds)
    ORDER BY activation.source_scope_id
    LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION app.postgresql_query_scope_due(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.postgresql_query_scope_due(integer) TO knowvault_worker;

COMMIT;
