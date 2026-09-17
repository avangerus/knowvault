-- Stage 3 V1-A: scheduled autonomous sync for POSTGRESQL_QUERY sources.
--
-- The scope revision already carries an operator-set sync_interval_seconds
-- (000007, CHECK BETWEEN 60 AND 86400); nothing so far ever reads it. This
-- migration adds one read-only, worker-restricted lookup that names the exact
-- READY POSTGRESQL_QUERY scopes whose last completed sync is older than their
-- own interval and that have no PENDING/RUNNING sync job already in flight.
-- It creates no new table, widens no grant beyond the worker role, and
-- enqueues nothing itself: the caller still uses the existing, already
-- reviewed app.enqueue_job path (internal/source/registration.Service) so a
-- scheduled sync is indistinguishable, at the job/publication boundary, from
-- an operator-requested one.
BEGIN;

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
        RAISE EXCEPTION 'postgresql query schedule lookup is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'postgresql query schedule limit is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'postgresql query schedule lookup requires a tenant context' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT act.source_scope_id, act.source_scope_revision
    FROM public.source_scope_activation act
    JOIN public.source_scope_revision rev
      ON rev.organization_id = act.organization_id
     AND rev.source_scope_id = act.source_scope_id
     AND rev.revision = act.source_scope_revision
    JOIN public.postgresql_query_projection proj
      ON proj.organization_id = act.organization_id
     AND proj.source_scope_id = act.source_scope_id
     AND proj.source_scope_revision = act.source_scope_revision
    WHERE act.organization_id = organization_value
      AND act.status = 'READY'
      AND rev.source_type = 'POSTGRESQL_QUERY'
      AND proj.status = 'ACTIVE'
      AND NOT EXISTS (
          SELECT 1 FROM public.job job
          WHERE job.organization_id = organization_value
            AND job.type = 'POSTGRESQL_QUERY_SYNC'
            AND job.status IN ('PENDING', 'RUNNING')
            AND job.payload_json ->> 'source_scope_id' = act.source_scope_id
      )
      AND COALESCE(
          (SELECT run.completed_at FROM public.sync_run run
           WHERE run.organization_id = organization_value
             AND run.source_scope_id = act.source_scope_id
             AND run.source_scope_revision = act.source_scope_revision
             AND run.status = 'SUCCEEDED'
           ORDER BY run.started_at DESC, run.id DESC LIMIT 1),
          act.activated_at
      ) <= transaction_timestamp() - make_interval(secs => rev.sync_interval_seconds)
    ORDER BY act.source_scope_id
    LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION app.postgresql_query_scope_due(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.postgresql_query_scope_due(integer) TO knowvault_worker;

COMMIT;
