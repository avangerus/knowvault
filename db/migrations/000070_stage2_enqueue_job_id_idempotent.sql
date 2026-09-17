-- app.enqueue_job's idempotency ON CONFLICT target (organization_id,
-- idempotency_key) only collapses two enqueues of the SAME idempotency key.
-- A caller whose job id is content-derived rather than freshly minted per
-- attempt (registration.Service.Activate's syncJobID(organizationID,
-- sourceScopeID), deliberately fixed so a scope can never have two concurrent
-- activation jobs) hits a bare INSERT with a NEW idempotency key against an
-- id that already exists from an earlier attempt on that same scope. That
-- collides on the table's own PRIMARY KEY (organization_id, id) instead,
-- which this function's ON CONFLICT clause does not name, so PostgreSQL
-- raises an unhandled unique_violation. The caller only maps a handful of
-- registration.ErrorCode values to a typed HTTP response and treats every
-- unrecognized error as a raw persistence failure, so this surfaced as
-- 503 SERVICE_UNAVAILABLE for a repeat :activate of an already-registered
-- POSTGRESQL_QUERY or GIT scope -- verified live on the acceptance stand,
-- reproducible on any scope whose first activation attempt ever enqueued
-- this job id (the id survives regardless of that attempt's own outcome).
--
-- Fix: re-check by id (the table's actual primary key) exactly the way the
-- existing idempotency-key branch already does, before ever attempting the
-- INSERT. This is strictly additive to the existing contract: a genuinely
-- new job id still inserts as before, and a repeat with the SAME
-- idempotency key still converges through the original ON CONFLICT path
-- unchanged; the only new case is a repeat with a DIFFERENT idempotency key
-- against the SAME id, which now returns that existing job's id instead of
-- raising an unhandled error -- the same "a repeat always returns the
-- original job and never creates a second unit of work" guarantee this
-- function's own comment already promises, extended to cover id reuse.
BEGIN;

CREATE OR REPLACE FUNCTION app.enqueue_job(
    job_id_value text,
    type_value text,
    payload_value jsonb,
    idempotency_key_value text,
    priority_value integer,
    max_attempts_value integer,
    available_after_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    existing_id text;
BEGIN
    IF session_user NOT IN ('knowvault_app', 'knowvault_worker') THEN
        RAISE EXCEPTION 'job enqueue is restricted to the runtime and worker roles'
            USING ERRCODE = '42501';
    END IF;
    IF available_after_seconds IS NULL OR available_after_seconds < 0 OR available_after_seconds > 2592000 THEN
        RAISE EXCEPTION 'job availability delay is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job enqueue requires a tenant context' USING ERRCODE = '42501';
    END IF;

    PERFORM 1 FROM public.organization
    WHERE id = organization_value AND status = 'ACTIVE'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job enqueue requires an active tenant' USING ERRCODE = '55000';
    END IF;

    -- A caller with a content-derived (not freshly minted) job id may repeat
    -- this exact id with a different idempotency key across attempts; this
    -- never conflicts on the idempotency-key ON CONFLICT clause below, so it
    -- must be checked first, by the table's own primary key.
    SELECT id INTO existing_id FROM public.job
    WHERE organization_id = organization_value AND id = job_id_value;
    IF existing_id IS NOT NULL THEN
        RETURN existing_id;
    END IF;

    -- Race-safe idempotency: ON CONFLICT collapses two concurrent enqueues of
    -- the same key to one row instead of surfacing a unique violation to the
    -- loser. The loser then reads back the winning id, so a repeat always
    -- returns the original job and never creates a second unit of work.
    INSERT INTO public.job (
        organization_id, id, type, payload_json, idempotency_key,
        status, priority, max_attempts, attempt_count,
        available_at, lease_epoch, created_at, updated_at
    ) VALUES (
        organization_value, job_id_value, type_value, payload_value, idempotency_key_value,
        'PENDING', priority_value, max_attempts_value, 0,
        transaction_timestamp() + make_interval(secs => available_after_seconds), 0,
        transaction_timestamp(), transaction_timestamp()
    )
    ON CONFLICT (organization_id, idempotency_key) DO NOTHING
    RETURNING id INTO existing_id;

    IF existing_id IS NOT NULL THEN
        RETURN existing_id;
    END IF;

    SELECT id INTO existing_id FROM public.job
    WHERE organization_id = organization_value AND idempotency_key = idempotency_key_value;
    RETURN existing_id;
END;
$$;

COMMIT;
