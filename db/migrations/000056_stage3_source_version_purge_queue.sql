-- Stage 3: durable, privileged source-version purge requests.
--
-- Migrations 000015/000030 own the source-version retention state machine and
-- all physical cleanup.  This migration adds only the restart/lease boundary
-- around that authority.  The request contains an opaque version reference
-- and a closed reason code; it never carries SQL, source content, paths or a
-- model-produced selector.  Unlike conversation retention, source-version
-- purge is organization-wide, so enqueue is restricted to the trusted purger
-- role rather than exposing a workspace member a global destructive operation.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_purger') THEN
        RAISE EXCEPTION 'trusted purge role knowvault_purger must exist before this migration';
    END IF;
END;
$$;

CREATE TABLE public.source_version_purge_request (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.outbox_reference_id_is_valid(id)),
    source_version_id text NOT NULL
        CHECK (app.source_generated_id_is_valid(source_version_id, 'version')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    idempotency_key text NOT NULL CHECK (app.stage2_opaque_id_is_valid(idempotency_key)),
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'DEAD')),
    priority smallint NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000),
    max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND max_attempts),
    available_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch BETWEEN 0 AND 9007199254740991),
    lease_owner text CHECK (lease_owner IS NULL OR app.stage2_opaque_id_is_valid(lease_owner)),
    lease_deadline timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, idempotency_key),
    CONSTRAINT source_version_purge_request_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT source_version_purge_request_retention_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version_retention (organization_id, source_version_id)
        ON DELETE RESTRICT,
    CONSTRAINT source_version_purge_request_state_shape CHECK (
        (status = 'PENDING'
         AND lease_owner IS NULL AND lease_deadline IS NULL AND completed_at IS NULL)
        OR
        (status = 'RUNNING'
         AND lease_owner IS NOT NULL AND lease_deadline IS NOT NULL AND completed_at IS NULL
         AND attempt_count >= 1)
        OR
        (status IN ('SUCCEEDED', 'DEAD')
         AND lease_owner IS NULL AND lease_deadline IS NULL AND completed_at IS NOT NULL)
    ),
    CONSTRAINT source_version_purge_request_time_order CHECK (
        updated_at >= created_at AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE INDEX source_version_purge_request_runnable
    ON public.source_version_purge_request (organization_id, priority, available_at, id)
    WHERE status = 'PENDING';

CREATE INDEX source_version_purge_request_lease
    ON public.source_version_purge_request (organization_id, lease_deadline, id)
    WHERE status = 'RUNNING';

CREATE OR REPLACE FUNCTION app.source_version_purge_request_mutation_guard()
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
            RAISE EXCEPTION 'source-version purge request deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.priority IS DISTINCT FROM OLD.priority
       OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'source-version purge request identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IN ('SUCCEEDED', 'DEAD') THEN
        RAISE EXCEPTION 'source-version purge request is terminal' USING ERRCODE = '55000';
    END IF;
    IF NEW.lease_epoch < OLD.lease_epoch OR NEW.attempt_count < OLD.attempt_count THEN
        RAISE EXCEPTION 'source-version purge request fence and attempts are monotonic'
            USING ERRCODE = '55000';
    END IF;
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_version_purge_request_state_guard
BEFORE UPDATE OR DELETE ON public.source_version_purge_request
FOR EACH ROW EXECUTE FUNCTION app.source_version_purge_request_mutation_guard();

-- Enqueue is a trusted control-plane operation.  A source-version purge is
-- global to every workspace that can observe that version, therefore no
-- workspace member receives this destructive capability through knowvault_app.
-- Idempotency replay is safe after a crash, including for a PURGING target.
CREATE OR REPLACE FUNCTION app.source_version_purge_request_enqueue(
    p_request_id text,
    p_source_version_id text,
    p_reason_code text,
    p_idempotency_key text,
    p_priority integer,
    p_max_attempts integer,
    p_available_after_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    organization_value text := app.current_organization_id();
    retention_state text;
    existing RECORD;
    returned_id text;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'source-version purge enqueue requires the purger role'
            USING ERRCODE = '42501';
    END IF;
    IF organization_value IS NULL
       OR p_request_id IS NULL OR NOT app.outbox_reference_id_is_valid(p_request_id)
       OR p_source_version_id IS NULL OR NOT app.source_generated_id_is_valid(p_source_version_id, 'version')
       OR p_reason_code IS NULL OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
       OR p_idempotency_key IS NULL OR NOT app.stage2_opaque_id_is_valid(p_idempotency_key)
       OR p_priority IS NULL OR p_priority < 0 OR p_priority > 1000
       OR p_max_attempts IS NULL OR p_max_attempts < 1 OR p_max_attempts > 100
       OR p_available_after_seconds IS NULL OR p_available_after_seconds < 0
       OR p_available_after_seconds > 2592000 THEN
        RAISE EXCEPTION 'source-version purge request is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.organization
     WHERE id = organization_value AND status = 'ACTIVE' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source-version purge request requires an active tenant' USING ERRCODE = '55000';
    END IF;

    SELECT retention.state INTO retention_state
      FROM public.source_version_retention AS retention
      JOIN public.source_version AS version
        ON version.organization_id = retention.organization_id
       AND version.id = retention.source_version_id
     WHERE retention.organization_id = organization_value
       AND retention.source_version_id = p_source_version_id;
    IF NOT FOUND OR retention_state NOT IN ('ACTIVE', 'PURGING') THEN
        RAISE EXCEPTION 'source-version purge request target is unavailable' USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.source_version_purge_request (
        organization_id, id, source_version_id, reason_code, idempotency_key,
        status, priority, max_attempts, attempt_count, available_at,
        lease_epoch, created_at, updated_at
    ) VALUES (
        organization_value, p_request_id, p_source_version_id, p_reason_code,
        p_idempotency_key, 'PENDING', p_priority, p_max_attempts, 0,
        transaction_timestamp() + make_interval(secs => p_available_after_seconds),
        0, transaction_timestamp(), transaction_timestamp()
    ) ON CONFLICT (organization_id, idempotency_key) DO NOTHING
    RETURNING id INTO returned_id;

    IF returned_id IS NOT NULL THEN
        RETURN returned_id;
    END IF;

    SELECT request.id, request.source_version_id, request.reason_code
      INTO existing
      FROM public.source_version_purge_request AS request
     WHERE request.organization_id = organization_value
       AND request.idempotency_key = p_idempotency_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source-version purge request idempotency race lost' USING ERRCODE = '40001';
    END IF;
    IF existing.source_version_id IS DISTINCT FROM p_source_version_id
       OR existing.reason_code IS DISTINCT FROM p_reason_code THEN
        RAISE EXCEPTION 'source-version purge request idempotency key conflict' USING ERRCODE = '23505';
    END IF;
    RETURN existing.id;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_version_purge_request_claim(
    p_worker_id text, p_lease_seconds integer
)
RETURNS TABLE (
    request_id text,
    source_version_id text,
    reason_code text,
    lease_epoch bigint,
    attempt_number integer,
    max_attempts integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    organization_value text := app.current_organization_id();
    claimed RECORD;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'source-version purge request claim requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF organization_value IS NULL
       OR p_worker_id IS NULL OR NOT app.stage2_opaque_id_is_valid(p_worker_id)
       OR p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 3600 THEN
        RAISE EXCEPTION 'source-version purge claim is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT request.*
      INTO claimed
      FROM public.source_version_purge_request AS request
     WHERE request.organization_id = organization_value
       AND request.status = 'PENDING'
       AND request.available_at <= transaction_timestamp()
     ORDER BY request.priority, request.available_at, request.id
     FOR UPDATE SKIP LOCKED
     LIMIT 1;
    IF claimed.id IS NULL THEN
        RETURN;
    END IF;

    UPDATE public.source_version_purge_request
       SET status = 'RUNNING', lease_owner = p_worker_id,
           lease_epoch = claimed.lease_epoch + 1,
           lease_deadline = transaction_timestamp() + make_interval(secs => p_lease_seconds),
           attempt_count = claimed.attempt_count + 1,
           last_error_code = NULL
     WHERE organization_id = organization_value AND id = claimed.id;

    request_id := claimed.id;
    source_version_id := claimed.source_version_id;
    reason_code := claimed.reason_code;
    lease_epoch := claimed.lease_epoch + 1;
    attempt_number := claimed.attempt_count + 1;
    max_attempts := claimed.max_attempts;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_version_purge_request_heartbeat(
    p_request_id text, p_worker_id text, p_lease_epoch bigint, p_extend_seconds integer
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    new_deadline timestamptz;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'source-version purge heartbeat requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_extend_seconds IS NULL OR p_extend_seconds < 1 OR p_extend_seconds > 3600 THEN
        RAISE EXCEPTION 'source-version purge heartbeat interval is invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE public.source_version_purge_request
       SET lease_deadline = transaction_timestamp() + make_interval(secs => p_extend_seconds)
     WHERE organization_id = app.current_organization_id()
       AND id = p_request_id AND status = 'RUNNING'
       AND lease_owner = p_worker_id AND lease_epoch = p_lease_epoch
       AND lease_deadline > transaction_timestamp()
    RETURNING lease_deadline INTO new_deadline;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source-version purge request lease is not held' USING ERRCODE = '55000';
    END IF;
    RETURN new_deadline;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_version_purge_request_complete(
    p_request_id text, p_worker_id text, p_lease_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'source-version purge completion requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM public.source_version_purge_request AS request
          JOIN public.source_version_retention AS retention
            ON retention.organization_id = request.organization_id
           AND retention.source_version_id = request.source_version_id
         WHERE request.organization_id = app.current_organization_id()
           AND request.id = p_request_id
           AND request.status = 'RUNNING'
           AND request.lease_owner = p_worker_id
           AND request.lease_epoch = p_lease_epoch
           AND request.lease_deadline > transaction_timestamp()
           AND retention.state = 'PURGED'
    ) THEN
        RAISE EXCEPTION 'source-version purge request cannot complete before PURGED retention or lease loss'
            USING ERRCODE = '55000';
    END IF;
    UPDATE public.source_version_purge_request
       SET status = 'SUCCEEDED', lease_owner = NULL, lease_deadline = NULL,
           completed_at = transaction_timestamp()
     WHERE organization_id = app.current_organization_id()
       AND id = p_request_id AND status = 'RUNNING'
       AND lease_owner = p_worker_id AND lease_epoch = p_lease_epoch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source-version purge request lease is not held' USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_version_purge_request_fail(
    p_request_id text, p_worker_id text, p_lease_epoch bigint,
    p_error_code text, p_retry_after_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    current_attempt integer;
    attempt_ceiling integer;
    resulting_status text;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'source-version purge failure requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_error_code IS NULL OR p_error_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
       OR p_retry_after_seconds IS NULL OR p_retry_after_seconds < 0
       OR p_retry_after_seconds > 2592000 THEN
        RAISE EXCEPTION 'source-version purge failure is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT attempt_count, max_attempts
      INTO current_attempt, attempt_ceiling
      FROM public.source_version_purge_request
     WHERE organization_id = app.current_organization_id()
       AND id = p_request_id AND status = 'RUNNING'
       AND lease_owner = p_worker_id AND lease_epoch = p_lease_epoch
       AND lease_deadline > transaction_timestamp()
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source-version purge request lease is not held' USING ERRCODE = '55000';
    END IF;
    IF current_attempt < attempt_ceiling THEN
        resulting_status := 'PENDING';
        UPDATE public.source_version_purge_request
           SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
               available_at = transaction_timestamp() + make_interval(secs => p_retry_after_seconds),
               last_error_code = p_error_code
         WHERE organization_id = app.current_organization_id() AND id = p_request_id;
    ELSE
        resulting_status := 'DEAD';
        UPDATE public.source_version_purge_request
           SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
               completed_at = transaction_timestamp(), last_error_code = p_error_code
         WHERE organization_id = app.current_organization_id() AND id = p_request_id;
    END IF;
    RETURN resulting_status;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_version_purge_request_reclaim(p_limit integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    reclaimed integer := 0;
    request RECORD;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'source-version purge reclaim requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'source-version purge reclaim limit is invalid' USING ERRCODE = '22023';
    END IF;
    FOR request IN
        SELECT id, attempt_count, max_attempts
          FROM public.source_version_purge_request
         WHERE organization_id = app.current_organization_id()
           AND status = 'RUNNING' AND lease_deadline < transaction_timestamp()
         ORDER BY lease_deadline, id
         FOR UPDATE SKIP LOCKED
         LIMIT p_limit
    LOOP
        IF request.attempt_count < request.max_attempts THEN
            UPDATE public.source_version_purge_request
               SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
                   available_at = transaction_timestamp(), last_error_code = 'LEASE_EXPIRED'
             WHERE organization_id = app.current_organization_id() AND id = request.id;
        ELSE
            UPDATE public.source_version_purge_request
               SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
                   completed_at = transaction_timestamp(), last_error_code = 'LEASE_EXPIRED'
             WHERE organization_id = app.current_organization_id() AND id = request.id;
        END IF;
        reclaimed := reclaimed + 1;
    END LOOP;
    RETURN reclaimed;
END;
$$;

ALTER TABLE public.source_version_purge_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_version_purge_request FORCE ROW LEVEL SECURITY;
CREATE POLICY source_version_purge_request_purger_read ON public.source_version_purge_request
FOR SELECT TO knowvault_purger
USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_version_purge_request FROM PUBLIC;
GRANT SELECT ON TABLE public.source_version_purge_request TO knowvault_purger;
REVOKE ALL ON FUNCTION
    app.source_version_purge_request_enqueue(text, text, text, text, integer, integer, integer),
    app.source_version_purge_request_claim(text, integer),
    app.source_version_purge_request_heartbeat(text, text, bigint, integer),
    app.source_version_purge_request_complete(text, text, bigint),
    app.source_version_purge_request_fail(text, text, bigint, text, integer),
    app.source_version_purge_request_reclaim(integer)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    app.source_version_purge_request_enqueue(text, text, text, text, integer, integer, integer),
    app.source_version_purge_request_claim(text, integer),
    app.source_version_purge_request_heartbeat(text, text, bigint, integer),
    app.source_version_purge_request_complete(text, text, bigint),
    app.source_version_purge_request_fail(text, text, bigint, text, integer),
    app.source_version_purge_request_reclaim(integer)
TO knowvault_purger;
GRANT USAGE ON SCHEMA app, public TO knowvault_purger;
GRANT EXECUTE ON FUNCTION app.current_organization_id() TO knowvault_purger;

COMMIT;
