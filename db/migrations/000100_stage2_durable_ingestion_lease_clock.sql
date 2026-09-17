-- 000100: heartbeat leases use one fresh wall-clock instant.
--
-- Publication of one PostgreSQL snapshot is intentionally one local,
-- lease-fenced transaction.  That transaction already owns the job row, so
-- its bounded in-transaction heartbeat must use clock_timestamp():
-- transaction_timestamp() would remain pinned to the transaction start and
-- could appear to renew an already expired lease.  The exact owner, worker,
-- epoch, RUNNING state and live-deadline checks remain mandatory.  Every
-- caller-side fence below locks first and samples the clock only after that
-- lock is acquired, so a wait on another transaction cannot revive a lease.

BEGIN;

CREATE OR REPLACE FUNCTION app.heartbeat_job(
    job_id_value text,
    worker_id_value text,
    lease_epoch_value bigint,
    extend_seconds integer
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    status_value text;
    owner_value text;
    epoch_value bigint;
    held_deadline timestamptz;
    observed_at timestamptz;
    new_deadline timestamptz;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'job heartbeat is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF extend_seconds IS NULL OR extend_seconds < 1 OR extend_seconds > 3600 THEN
        RAISE EXCEPTION 'heartbeat extension out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job heartbeat requires a tenant context' USING ERRCODE = '42501';
    END IF;

    -- Lock the exact row before reading the wall clock.  If another
    -- transaction held the row, a timestamp captured before this FOR UPDATE
    -- could become stale while waiting and revive a lease that expired before
    -- the lock was acquired.
    SELECT j.status, j.lease_owner, j.lease_epoch, j.lease_deadline
    INTO status_value, owner_value, epoch_value, held_deadline
    FROM public.job AS j
    WHERE j.organization_id = organization_value
      AND j.id = job_id_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    -- One fresh instant is used for both the expiry guard and the new
    -- deadline, after the row lock has been acquired.  A worker whose lease
    -- expired or was reclaimed cannot revive it, even in an old transaction.
    observed_at := clock_timestamp();
    IF status_value IS DISTINCT FROM 'RUNNING'
       OR owner_value IS DISTINCT FROM worker_id_value
       OR epoch_value IS DISTINCT FROM lease_epoch_value
       OR held_deadline IS NULL
       OR held_deadline <= observed_at THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;
    new_deadline := observed_at + make_interval(secs => extend_seconds);
    UPDATE public.job
    SET lease_deadline = new_deadline
    WHERE organization_id = organization_value
      AND id = job_id_value
      AND status = 'RUNNING'
      AND lease_owner = worker_id_value
      AND lease_epoch = lease_epoch_value
      AND lease_deadline = held_deadline;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;
    RETURN new_deadline;
END;
$$;

-- Keep the publication fence point-in-time correct as well.  A publication
-- transaction can call this after waiting on a row lock; validate its exact
-- owner/epoch/state and the deadline only after that lock is held.
CREATE OR REPLACE FUNCTION app.lock_job_lease(p_job_id text, p_worker text, p_epoch bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    status_value text;
    owner_value text;
    epoch_value bigint;
    held_deadline timestamptz;
    observed_at timestamptz;
BEGIN
    organization_value := app.current_organization_id();
    SELECT j.status, j.lease_owner, j.lease_epoch, j.lease_deadline
    INTO status_value, owner_value, epoch_value, held_deadline
    FROM public.job AS j
    WHERE j.organization_id = organization_value
      AND j.id = p_job_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not current' USING ERRCODE = '55000';
    END IF;

    observed_at := clock_timestamp();
    IF status_value IS DISTINCT FROM 'RUNNING'
       OR owner_value IS DISTINCT FROM p_worker
       OR epoch_value IS DISTINCT FROM p_epoch
       OR held_deadline IS NULL
       OR held_deadline <= observed_at THEN
        RAISE EXCEPTION 'job lease is not current' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- Completion and failure are also caller-side lease fences.  They normally
-- run in short queue transactions, but a row-lock wait can outlive a lease;
-- validate the exact row again with a post-lock wall-clock instant before
-- acknowledging or retrying the job.
CREATE OR REPLACE FUNCTION app.complete_job(
    job_id_value text,
    worker_id_value text,
    lease_epoch_value bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    status_value text;
    owner_value text;
    epoch_value bigint;
    held_deadline timestamptz;
    current_attempt integer;
    observed_at timestamptz;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'job completion is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job completion requires a tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT j.status, j.lease_owner, j.lease_epoch, j.lease_deadline, j.attempt_count
    INTO status_value, owner_value, epoch_value, held_deadline, current_attempt
    FROM public.job AS j
    WHERE j.organization_id = organization_value
      AND j.id = job_id_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    observed_at := clock_timestamp();
    IF status_value IS DISTINCT FROM 'RUNNING'
       OR owner_value IS DISTINCT FROM worker_id_value
       OR epoch_value IS DISTINCT FROM lease_epoch_value
       OR held_deadline IS NULL
       OR held_deadline <= observed_at THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    UPDATE public.job
    SET status = 'SUCCEEDED', lease_owner = NULL, lease_deadline = NULL,
        completed_at = observed_at, last_error_code = NULL
    WHERE organization_id = organization_value
      AND id = job_id_value
      AND status = 'RUNNING'
      AND lease_owner = worker_id_value
      AND lease_epoch = lease_epoch_value
      AND lease_deadline = held_deadline;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    UPDATE public.job_attempt
    SET completed_at = observed_at, outcome = 'SUCCEEDED'
    WHERE organization_id = organization_value
      AND job_id = job_id_value
      AND attempt_number = current_attempt
      AND completed_at IS NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app.fail_job(
    job_id_value text,
    worker_id_value text,
    lease_epoch_value bigint,
    error_code_value text,
    retry_after_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    status_value text;
    owner_value text;
    epoch_value bigint;
    held_deadline timestamptz;
    current_attempt integer;
    attempt_ceiling integer;
    resulting_status text;
    observed_at timestamptz;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'job failure is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF NOT app.job_error_code_is_valid(error_code_value) THEN
        RAISE EXCEPTION 'job error code is invalid' USING ERRCODE = '22023';
    END IF;
    IF retry_after_seconds IS NULL OR retry_after_seconds < 0 OR retry_after_seconds > 2592000 THEN
        RAISE EXCEPTION 'retry delay is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job failure requires a tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT j.status, j.lease_owner, j.lease_epoch, j.lease_deadline,
           j.attempt_count, j.max_attempts
    INTO status_value, owner_value, epoch_value, held_deadline,
         current_attempt, attempt_ceiling
    FROM public.job AS j
    WHERE j.organization_id = organization_value
      AND j.id = job_id_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    observed_at := clock_timestamp();
    IF status_value IS DISTINCT FROM 'RUNNING'
       OR owner_value IS DISTINCT FROM worker_id_value
       OR epoch_value IS DISTINCT FROM lease_epoch_value
       OR held_deadline IS NULL
       OR held_deadline <= observed_at THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    UPDATE public.job_attempt
    SET completed_at = observed_at, outcome = 'FAILED', error_code = error_code_value
    WHERE organization_id = organization_value
      AND job_id = job_id_value
      AND attempt_number = current_attempt
      AND completed_at IS NULL;

    IF current_attempt < attempt_ceiling THEN
        resulting_status := 'PENDING';
        UPDATE public.job
        SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
            available_at = observed_at + make_interval(secs => retry_after_seconds),
            last_error_code = error_code_value
        WHERE organization_id = organization_value AND id = job_id_value;
    ELSE
        resulting_status := 'DEAD';
        UPDATE public.job
        SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
            completed_at = observed_at, last_error_code = error_code_value
        WHERE organization_id = organization_value AND id = job_id_value;
    END IF;
    RETURN resulting_status;
END;
$$;

COMMIT;
