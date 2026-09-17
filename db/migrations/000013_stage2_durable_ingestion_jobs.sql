-- Stage 2 durable ingestion workflow: the dedicated worker role plus the
-- durable job / lease / retry / dead-letter state machine that ADR-0046
-- deferred. See ADR-0056.
--
-- The Web/API runtime (knowvault_app) may enqueue durable work; only the
-- dedicated worker runtime (knowvault_worker) may lease and execute it. Neither
-- login role receives direct DML on the job tables: every mutation flows
-- through a SECURITY DEFINER function that owns the transition, and an
-- independent trigger re-checks the invariants even on that privileged path.
--
-- Fencing is a per-job monotonic lease_epoch. Each lease bumps it, so a stale
-- worker whose lease already lapsed presents an old epoch and is refused. A
-- lost worker leaves a RUNNING row whose lease_deadline passes; reclamation
-- closes the crashed attempt against the retry budget and either re-queues the
-- job or dead-letters it. A completion or heartbeat requires a live, matching
-- lease, so a job is never acknowledged without proof the caller still owns it.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_worker') THEN
        RAISE EXCEPTION 'required worker role knowvault_worker does not exist';
    END IF;
END;
$$;

-- The worker runtime has no ownership, superuser or RLS-bypass capability. It is
-- a separate login identity from the Web/API runtime so lease/execute authority
-- can never be reached through a request handler.
ALTER ROLE knowvault_worker NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE knowvault_worker SET row_security = 'on';
GRANT USAGE ON SCHEMA app, public TO knowvault_worker;
GRANT EXECUTE ON FUNCTION app.current_organization_id() TO knowvault_worker;

-- Error codes are opaque operator-facing tokens. They never carry source or
-- model content; the operator correlates them with a runbook, not a payload.
CREATE OR REPLACE FUNCTION app.job_error_code_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL AND value ~ '^[A-Z][A-Z0-9_]{2,63}$';
$$;

-- A job payload is a bounded closed reference/hash object, exactly like an
-- outbox payload, except an empty object is allowed: a tenant-scoped job (for
-- example draining that tenant's outbox) references no single aggregate. Any
-- key that is present is still validated against the closed inventory, so text,
-- ciphertext, paths, titles, principals or secrets can never be smuggled in.
CREATE OR REPLACE FUNCTION app.job_payload_is_safe(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    payload_key text;
    payload_value jsonb;
    scalar_value text;
BEGIN
    IF value IS NULL
       OR jsonb_typeof(value) <> 'object'
       OR octet_length(value::text) > 16384 THEN
        RETURN false;
    END IF;

    FOR payload_key, payload_value IN SELECT key, val FROM jsonb_each(value) AS item(key, val)
    LOOP
        IF payload_key IN (
            'source_scope_id', 'source_object_id', 'source_version_id',
            'extraction_id', 'index_generation_id', 'workspace_id', 'artifact_id'
        ) THEN
            IF jsonb_typeof(payload_value) <> 'string' THEN RETURN false; END IF;
            scalar_value := payload_value #>> '{}';
            IF NOT app.outbox_reference_id_is_valid(scalar_value) THEN RETURN false; END IF;
        ELSIF payload_key IN ('content_hash', 'text_hash') THEN
            IF jsonb_typeof(payload_value) <> 'string'
               OR NOT app.stage2_sha256_is_valid(payload_value #>> '{}') THEN
                RETURN false;
            END IF;
        ELSIF payload_key IN ('retention_fence', 'generation_fence') THEN
            IF jsonb_typeof(payload_value) <> 'number'
               OR (payload_value #>> '{}') !~ '^(0|[1-9][0-9]{0,15})$'
               OR (payload_value #>> '{}')::numeric > 9007199254740991 THEN
                RETURN false;
            END IF;
        ELSIF payload_key = 'operation' THEN
            IF jsonb_typeof(payload_value) <> 'string'
               OR (payload_value #>> '{}') NOT IN ('UPSERT', 'DELETE', 'PURGE', 'ACTIVATE') THEN
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE public.job (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.outbox_reference_id_is_valid(id)),
    -- Closed inventory of the durable ingestion operations. Handlers for these
    -- types are composed in later slices; the substrate owns them today.
    type text NOT NULL CHECK (type IN (
        'SOURCE_SCOPE_SYNC', 'SOURCE_OBJECT_EXTRACTION',
        'OUTBOX_DELIVERY', 'SOURCE_VERSION_PURGE'
    )),
    payload_json jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (app.job_payload_is_safe(payload_json)),
    -- A repeat enqueue with the same key returns the original job; it never
    -- produces a second unit of work.
    idempotency_key text NOT NULL CHECK (app.stage2_opaque_id_is_valid(idempotency_key)),
    status text NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'DEAD')),
    priority smallint NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    attempt_count integer NOT NULL DEFAULT 0
        CHECK (attempt_count BETWEEN 0 AND max_attempts),
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    -- Monotonic fencing token. Never resets; every lease increments it.
    lease_epoch bigint NOT NULL DEFAULT 0
        CHECK (lease_epoch BETWEEN 0 AND 9007199254740991),
    lease_owner text CHECK (lease_owner IS NULL OR app.stage2_opaque_id_is_valid(lease_owner)),
    lease_deadline timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR app.job_error_code_is_valid(last_error_code)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, idempotency_key),
    -- Status and lease/terminal columns move together. A RUNNING job holds a
    -- lease; a PENDING job holds none; a terminal job is closed and unleased.
    CHECK (
        (status = 'RUNNING'
         AND lease_owner IS NOT NULL AND lease_deadline IS NOT NULL
         AND completed_at IS NULL AND attempt_count >= 1)
        OR
        (status = 'PENDING'
         AND lease_owner IS NULL AND lease_deadline IS NULL AND completed_at IS NULL)
        OR
        (status IN ('SUCCEEDED', 'DEAD')
         AND lease_owner IS NULL AND lease_deadline IS NULL
         AND completed_at IS NOT NULL)
    ),
    CHECK (updated_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX job_runnable_order
    ON public.job (organization_id, priority, available_at, id)
    WHERE status = 'PENDING';

CREATE INDEX job_reclaim_order
    ON public.job (organization_id, lease_deadline)
    WHERE status = 'RUNNING';

CREATE INDEX job_dead_letter_lookup
    ON public.job (organization_id, completed_at DESC)
    WHERE status = 'DEAD';

-- Every claim opens exactly one attempt row; the result closes it exactly once.
-- Attempts are append-only history: a closed attempt is immutable.
CREATE TABLE public.job_attempt (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    job_id text NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 100),
    lease_owner text NOT NULL CHECK (app.stage2_opaque_id_is_valid(lease_owner)),
    lease_epoch bigint NOT NULL CHECK (lease_epoch BETWEEN 1 AND 9007199254740991),
    started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    outcome text CHECK (outcome IS NULL OR outcome IN ('SUCCEEDED', 'FAILED', 'LEASE_EXPIRED')),
    error_code text CHECK (error_code IS NULL OR app.job_error_code_is_valid(error_code)),
    PRIMARY KEY (organization_id, job_id, attempt_number),
    FOREIGN KEY (organization_id, job_id)
        REFERENCES public.job(organization_id, id) ON DELETE RESTRICT,
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    CHECK ((outcome IS NULL) = (completed_at IS NULL)),
    -- Only a failed attempt carries an error code.
    CHECK (error_code IS NULL OR outcome = 'FAILED')
);

CREATE INDEX job_attempt_open_by_job
    ON public.job_attempt (organization_id, job_id, attempt_number)
    WHERE completed_at IS NULL;

CREATE OR REPLACE FUNCTION app.job_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Jobs are durable history; they disappear only when the tenant is torn
        -- down, and even then only after their attempts are already gone.
        IF NOT EXISTS (
            SELECT 1 FROM public.organization
            WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
        ) THEN
            RAISE EXCEPTION 'job deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    -- Identity and definition are immutable for the life of the job.
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.type IS DISTINCT FROM OLD.type
       OR NEW.payload_json IS DISTINCT FROM OLD.payload_json
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'job identity and definition are immutable'
            USING ERRCODE = '55000';
    END IF;

    -- A terminal job never moves again, so a completed job cannot return to
    -- RUNNING and its result cannot be rewritten.
    IF OLD.status IN ('SUCCEEDED', 'DEAD') THEN
        RAISE EXCEPTION 'job is terminal and cannot transition'
            USING ERRCODE = '55000';
    END IF;

    -- The fencing token and retry budget only ever advance.
    IF NEW.lease_epoch < OLD.lease_epoch OR NEW.attempt_count < OLD.attempt_count THEN
        RAISE EXCEPTION 'job lease epoch and attempt count are monotonic'
            USING ERRCODE = '55000';
    END IF;

    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_state_guard
BEFORE UPDATE OR DELETE ON public.job
FOR EACH ROW EXECUTE FUNCTION app.job_mutation_guard();

CREATE OR REPLACE FUNCTION app.job_attempt_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.organization
            WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
        ) THEN
            RAISE EXCEPTION 'job attempt deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    -- Attempt history is append-only: a closed attempt is frozen, and an open
    -- attempt may only take its single terminal transition.
    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'job attempt is closed and immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.attempt_number IS DISTINCT FROM OLD.attempt_number
       OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
       OR NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch
       OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'job attempt identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.completed_at IS NULL OR NEW.outcome IS NULL THEN
        RAISE EXCEPTION 'job attempt update must close the attempt'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER job_attempt_state_guard
BEFORE UPDATE OR DELETE ON public.job_attempt
FOR EACH ROW EXECUTE FUNCTION app.job_attempt_mutation_guard();

-- Enqueue a durable job. The producer is the Web/API runtime or a worker
-- chaining a follow-on unit inside its own result transaction. Idempotent on
-- (organization, idempotency_key): a repeat returns the existing job id.
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

-- Reclaim jobs whose worker lost its lease. Each expired lease closes its open
-- attempt as LEASE_EXPIRED (charged against the retry budget) and then either
-- re-queues the job or, if the budget is exhausted, dead-letters it. This is
-- how a crashed worker never loses or silently strands a job.
CREATE OR REPLACE FUNCTION app.reclaim_expired_jobs(reclaim_limit integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    reclaimed integer := 0;
    expired RECORD;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'job reclamation is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF reclaim_limit IS NULL OR reclaim_limit < 1 OR reclaim_limit > 1000 THEN
        RAISE EXCEPTION 'reclaim limit is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job reclamation requires a tenant context' USING ERRCODE = '42501';
    END IF;

    FOR expired IN
        SELECT id, attempt_count, max_attempts FROM public.job
        WHERE organization_id = organization_value
          AND status = 'RUNNING'
          AND lease_deadline < transaction_timestamp()
        ORDER BY lease_deadline
        FOR UPDATE SKIP LOCKED
        LIMIT reclaim_limit
    LOOP
        UPDATE public.job_attempt
        SET completed_at = transaction_timestamp(), outcome = 'LEASE_EXPIRED'
        WHERE organization_id = organization_value
          AND job_id = expired.id
          AND attempt_number = expired.attempt_count
          AND completed_at IS NULL;

        IF expired.attempt_count < expired.max_attempts THEN
            UPDATE public.job
            SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
                available_at = transaction_timestamp(), last_error_code = 'LEASE_EXPIRED'
            WHERE organization_id = organization_value AND id = expired.id;
        ELSE
            UPDATE public.job
            SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
                completed_at = transaction_timestamp(), last_error_code = 'LEASE_EXPIRED'
            WHERE organization_id = organization_value AND id = expired.id;
        END IF;
        reclaimed := reclaimed + 1;
    END LOOP;
    RETURN reclaimed;
END;
$$;

-- Lease the next runnable job. Concurrency-safe through FOR UPDATE SKIP LOCKED:
-- two workers never take the same job. Bumps the fencing epoch and opens a new
-- attempt. Returns no row when the tenant has nothing runnable.
CREATE OR REPLACE FUNCTION app.claim_next_job(
    worker_id_value text,
    lease_seconds integer
)
RETURNS TABLE (
    job_id text,
    job_type text,
    payload_json jsonb,
    lease_epoch bigint,
    attempt_number integer,
    max_attempts integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    claimed RECORD;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'job claim is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF NOT app.stage2_opaque_id_is_valid(worker_id_value) THEN
        RAISE EXCEPTION 'worker id is invalid' USING ERRCODE = '22023';
    END IF;
    IF lease_seconds IS NULL OR lease_seconds < 1 OR lease_seconds > 3600 THEN
        RAISE EXCEPTION 'lease seconds out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job claim requires a tenant context' USING ERRCODE = '42501';
    END IF;

    PERFORM 1 FROM public.organization
    WHERE id = organization_value AND status = 'ACTIVE'
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT j.id, j.type, j.payload_json, j.lease_epoch, j.attempt_count, j.max_attempts
    INTO claimed
    FROM public.job AS j
    WHERE j.organization_id = organization_value
      AND j.status = 'PENDING'
      AND j.available_at <= transaction_timestamp()
    ORDER BY j.priority, j.available_at, j.id
    FOR UPDATE SKIP LOCKED
    LIMIT 1;

    IF claimed.id IS NULL THEN
        RETURN;
    END IF;

    UPDATE public.job
    SET status = 'RUNNING',
        lease_owner = worker_id_value,
        lease_epoch = claimed.lease_epoch + 1,
        lease_deadline = transaction_timestamp() + make_interval(secs => lease_seconds),
        attempt_count = claimed.attempt_count + 1
    WHERE organization_id = organization_value AND id = claimed.id;

    INSERT INTO public.job_attempt (
        organization_id, job_id, attempt_number, lease_owner, lease_epoch, started_at
    ) VALUES (
        organization_value, claimed.id, claimed.attempt_count + 1,
        worker_id_value, claimed.lease_epoch + 1, transaction_timestamp()
    );

    job_id := claimed.id;
    job_type := claimed.type;
    payload_json := claimed.payload_json;
    lease_epoch := claimed.lease_epoch + 1;
    attempt_number := claimed.attempt_count + 1;
    max_attempts := claimed.max_attempts;
    RETURN NEXT;
END;
$$;

-- Extend a held lease. Fails closed unless the caller still owns a live lease
-- with the exact fencing epoch, so a worker that lost its lease cannot keep it
-- alive after another worker took over.
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

    new_deadline := transaction_timestamp() + make_interval(secs => extend_seconds);
    UPDATE public.job
    SET lease_deadline = new_deadline
    WHERE organization_id = organization_value
      AND id = job_id_value
      AND status = 'RUNNING'
      AND lease_owner = worker_id_value
      AND lease_epoch = lease_epoch_value
      AND lease_deadline > transaction_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;
    RETURN new_deadline;
END;
$$;

-- Acknowledge success. Requires a live matching lease, so a job can never be
-- marked done without proof the worker still owns it. Runs inside the worker's
-- result transaction: derived writes and follow-on enqueues commit atomically
-- with the acknowledgement, and a rollback leaves the job RUNNING to be
-- reclaimed.
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
    current_attempt integer;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'job completion is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'job completion requires a tenant context' USING ERRCODE = '42501';
    END IF;

    UPDATE public.job
    SET status = 'SUCCEEDED', lease_owner = NULL, lease_deadline = NULL,
        completed_at = transaction_timestamp(), last_error_code = NULL
    WHERE organization_id = organization_value
      AND id = job_id_value
      AND status = 'RUNNING'
      AND lease_owner = worker_id_value
      AND lease_epoch = lease_epoch_value
      AND lease_deadline > transaction_timestamp()
    RETURNING attempt_count INTO current_attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    UPDATE public.job_attempt
    SET completed_at = transaction_timestamp(), outcome = 'SUCCEEDED'
    WHERE organization_id = organization_value
      AND job_id = job_id_value
      AND attempt_number = current_attempt
      AND completed_at IS NULL;
END;
$$;

-- Record a failure. Requires a live matching lease. Within the retry budget the
-- job returns to PENDING after a bounded backoff; once the budget is exhausted
-- the failure dead-letters the job (DEAD) for operator attention. The attempt
-- and the job both carry the operator-facing error code.
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
    current_attempt integer;
    attempt_ceiling integer;
    resulting_status text;
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

    SELECT attempt_count, max_attempts INTO current_attempt, attempt_ceiling
    FROM public.job
    WHERE organization_id = organization_value
      AND id = job_id_value
      AND status = 'RUNNING'
      AND lease_owner = worker_id_value
      AND lease_epoch = lease_epoch_value
      AND lease_deadline > transaction_timestamp()
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not held by this worker at this epoch' USING ERRCODE = '55000';
    END IF;

    UPDATE public.job_attempt
    SET completed_at = transaction_timestamp(), outcome = 'FAILED', error_code = error_code_value
    WHERE organization_id = organization_value
      AND job_id = job_id_value
      AND attempt_number = current_attempt
      AND completed_at IS NULL;

    IF current_attempt < attempt_ceiling THEN
        resulting_status := 'PENDING';
        UPDATE public.job
        SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
            available_at = transaction_timestamp() + make_interval(secs => retry_after_seconds),
            last_error_code = error_code_value
        WHERE organization_id = organization_value AND id = job_id_value;
    ELSE
        resulting_status := 'DEAD';
        UPDATE public.job
        SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
            completed_at = transaction_timestamp(), last_error_code = error_code_value
        WHERE organization_id = organization_value AND id = job_id_value;
    END IF;
    RETURN resulting_status;
END;
$$;

-- Content-free operator snapshot: how many jobs sit in each state for the
-- tenant. Dead-letter drill-down reads the job table directly under RLS.
CREATE OR REPLACE FUNCTION app.job_status_counts()
RETURNS TABLE (status text, job_count bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT j.status, count(*)
    FROM public.job AS j
    WHERE j.organization_id = app.current_organization_id()
    GROUP BY j.status;
$$;

ALTER TABLE public.job ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.job FORCE ROW LEVEL SECURITY;
CREATE POLICY job_tenant_isolation ON public.job
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.job_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.job_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY job_attempt_tenant_isolation ON public.job_attempt
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.job, public.job_attempt FROM PUBLIC;

-- Both runtimes may read their tenant's job state for diagnostics, but neither
-- gets direct DML: every mutation is owned by a SECURITY DEFINER function.
GRANT SELECT ON TABLE public.job, public.job_attempt TO knowvault_app;
GRANT SELECT ON TABLE public.job, public.job_attempt TO knowvault_worker;

REVOKE ALL ON FUNCTION
    app.job_error_code_is_valid(text),
    app.job_payload_is_safe(jsonb),
    app.job_mutation_guard(),
    app.job_attempt_mutation_guard(),
    app.enqueue_job(text, text, jsonb, text, integer, integer, integer),
    app.reclaim_expired_jobs(integer),
    app.claim_next_job(text, integer),
    app.heartbeat_job(text, text, bigint, integer),
    app.complete_job(text, text, bigint),
    app.fail_job(text, text, bigint, text, integer),
    app.job_status_counts()
FROM PUBLIC;

-- The producer role may enqueue and read diagnostics; it can never lease or
-- acknowledge work.
GRANT EXECUTE ON FUNCTION
    app.enqueue_job(text, text, jsonb, text, integer, integer, integer),
    app.job_status_counts()
TO knowvault_app;

-- The worker role owns the execution surface.
GRANT EXECUTE ON FUNCTION
    app.enqueue_job(text, text, jsonb, text, integer, integer, integer),
    app.reclaim_expired_jobs(integer),
    app.claim_next_job(text, integer),
    app.heartbeat_job(text, text, bigint, integer),
    app.complete_job(text, text, bigint),
    app.fail_job(text, text, bigint, text, integer),
    app.job_status_counts()
TO knowvault_worker;

COMMIT;
