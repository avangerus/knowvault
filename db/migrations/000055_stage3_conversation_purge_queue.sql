-- Stage 3: durable, privileged conversation-purge requests.
--
-- Physical conversation cleanup is intentionally not a web request.  This
-- queue gives the trusted purger process a lease/fence/retry boundary while
-- keeping the conversation retention functions as the sole data authority.
-- The payload is an opaque target tuple plus a closed reason code; it never
-- carries text, SQL, a path or a model-produced selector.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'runtime role knowvault_app must exist before this migration';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_purger') THEN
        RAISE EXCEPTION 'trusted purge role knowvault_purger must exist before this migration';
    END IF;
END;
$$;

CREATE TABLE public.conversation_purge_request (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    id text NOT NULL CHECK (app.outbox_reference_id_is_valid(id)),
    workspace_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(workspace_id)),
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    conversation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(conversation_id)),
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
    CONSTRAINT conversation_purge_request_conversation_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id, workspace_revision)
        REFERENCES public.conversation (organization_id, id, workspace_id, workspace_revision)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_purge_request_state_shape CHECK (
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
    CONSTRAINT conversation_purge_request_time_order CHECK (
        updated_at >= created_at AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE INDEX conversation_purge_request_runnable
    ON public.conversation_purge_request (organization_id, priority, available_at, id)
    WHERE status = 'PENDING';

CREATE INDEX conversation_purge_request_lease
    ON public.conversation_purge_request (organization_id, lease_deadline, id)
    WHERE status = 'RUNNING';

CREATE OR REPLACE FUNCTION app.conversation_purge_request_mutation_guard()
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
            RAISE EXCEPTION 'conversation purge request deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.priority IS DISTINCT FROM OLD.priority
       OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'conversation purge request identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status IN ('SUCCEEDED', 'DEAD') THEN
        RAISE EXCEPTION 'conversation purge request is terminal' USING ERRCODE = '55000';
    END IF;
    IF NEW.lease_epoch < OLD.lease_epoch OR NEW.attempt_count < OLD.attempt_count THEN
        RAISE EXCEPTION 'conversation purge request fence and attempts are monotonic'
            USING ERRCODE = '55000';
    END IF;
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_purge_request_state_guard
BEFORE UPDATE OR DELETE ON public.conversation_purge_request
FOR EACH ROW EXECUTE FUNCTION app.conversation_purge_request_mutation_guard();

-- Enqueue is the only application-facing write.  A member can request purge
-- only for a conversation visible in the current workspace; the purger may
-- enqueue a resumable request for an already PURGING conversation after a
-- crash.  Idempotency collisions with a different target fail closed.
CREATE OR REPLACE FUNCTION app.conversation_purge_request_enqueue(
    p_request_id text,
    p_workspace_id text,
    p_conversation_id text,
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
    conversation_revision bigint;
    retention_state text;
    existing RECORD;
    returned_id text;
BEGIN
    IF session_user NOT IN ('knowvault_app', 'knowvault_purger') THEN
        RAISE EXCEPTION 'conversation purge enqueue requires an authorized runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF organization_value IS NULL
       OR p_request_id IS NULL OR NOT app.outbox_reference_id_is_valid(p_request_id)
       OR p_workspace_id IS NULL OR NOT app.stage2_opaque_id_is_valid(p_workspace_id)
       OR p_conversation_id IS NULL OR NOT app.stage2_opaque_id_is_valid(p_conversation_id)
       OR p_reason_code IS NULL OR p_reason_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
       OR p_idempotency_key IS NULL OR NOT app.stage2_opaque_id_is_valid(p_idempotency_key)
       OR p_priority IS NULL OR p_priority < 0 OR p_priority > 1000
       OR p_max_attempts IS NULL OR p_max_attempts < 1 OR p_max_attempts > 100
       OR p_available_after_seconds IS NULL OR p_available_after_seconds < 0
       OR p_available_after_seconds > 2592000 THEN
        RAISE EXCEPTION 'conversation purge request is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.organization
     WHERE id = organization_value AND status = 'ACTIVE' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation purge request requires an active tenant' USING ERRCODE = '55000';
    END IF;

    SELECT conversation.workspace_revision, retention.state
      INTO conversation_revision, retention_state
      FROM public.conversation AS conversation
      JOIN public.conversation_retention AS retention
        ON retention.organization_id = conversation.organization_id
       AND retention.conversation_id = conversation.id
       AND retention.workspace_id = conversation.workspace_id
       AND retention.workspace_revision = conversation.workspace_revision
     WHERE conversation.organization_id = organization_value
       AND conversation.id = p_conversation_id
       AND conversation.workspace_id = p_workspace_id;
    IF NOT FOUND OR retention_state NOT IN ('ACTIVE', 'PURGING') THEN
        RAISE EXCEPTION 'conversation purge request target is unavailable' USING ERRCODE = '55000';
    END IF;
    IF session_user = 'knowvault_app' AND retention_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'runtime purge request requires ACTIVE retention' USING ERRCODE = '55000';
    END IF;
    IF session_user = 'knowvault_app' AND NOT EXISTS (
        SELECT 1 FROM public.workspace_member AS member
         WHERE member.organization_id = organization_value
           AND member.workspace_id = p_workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_revision)
    ) THEN
        RAISE EXCEPTION 'conversation purge request requires workspace membership' USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.conversation_purge_request (
        organization_id, id, workspace_id, workspace_revision, conversation_id,
        reason_code, idempotency_key, status, priority, max_attempts,
        attempt_count, available_at, lease_epoch, created_at, updated_at
    ) VALUES (
        organization_value, p_request_id, p_workspace_id, conversation_revision,
        p_conversation_id, p_reason_code, p_idempotency_key, 'PENDING', p_priority,
        p_max_attempts, 0,
        transaction_timestamp() + make_interval(secs => p_available_after_seconds),
        0, transaction_timestamp(), transaction_timestamp()
    ) ON CONFLICT (organization_id, idempotency_key) DO NOTHING
    RETURNING id INTO returned_id;

    IF returned_id IS NOT NULL THEN
        RETURN returned_id;
    END IF;

    SELECT request.id, request.workspace_id, request.workspace_revision,
           request.conversation_id, request.reason_code
      INTO existing
      FROM public.conversation_purge_request AS request
     WHERE request.organization_id = organization_value
       AND request.idempotency_key = p_idempotency_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation purge request idempotency race lost' USING ERRCODE = '40001';
    END IF;
    IF existing.workspace_id IS DISTINCT FROM p_workspace_id
       OR existing.workspace_revision IS DISTINCT FROM conversation_revision
       OR existing.conversation_id IS DISTINCT FROM p_conversation_id
       OR existing.reason_code IS DISTINCT FROM p_reason_code THEN
        RAISE EXCEPTION 'conversation purge request idempotency key conflict' USING ERRCODE = '23505';
    END IF;
    RETURN existing.id;
END;
$$;

-- Claim, heartbeat, complete, fail and reclaim are purger-only state-machine
-- operations.  Each mutation carries the exact lease epoch and owner.
CREATE OR REPLACE FUNCTION app.conversation_purge_request_claim(
    p_worker_id text, p_lease_seconds integer
)
RETURNS TABLE (
    request_id text,
    workspace_id text,
    workspace_revision bigint,
    conversation_id text,
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
        RAISE EXCEPTION 'conversation purge request claim requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF organization_value IS NULL
       OR p_worker_id IS NULL OR NOT app.stage2_opaque_id_is_valid(p_worker_id)
       OR p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 3600 THEN
        RAISE EXCEPTION 'conversation purge claim is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT request.*
      INTO claimed
      FROM public.conversation_purge_request AS request
     WHERE request.organization_id = organization_value
       AND request.status = 'PENDING'
       AND request.available_at <= transaction_timestamp()
     ORDER BY request.priority, request.available_at, request.id
     FOR UPDATE SKIP LOCKED
     LIMIT 1;
    IF claimed.id IS NULL THEN
        RETURN;
    END IF;

    UPDATE public.conversation_purge_request
       SET status = 'RUNNING', lease_owner = p_worker_id,
           lease_epoch = claimed.lease_epoch + 1,
           lease_deadline = transaction_timestamp() + make_interval(secs => p_lease_seconds),
           attempt_count = claimed.attempt_count + 1,
           last_error_code = NULL
     WHERE organization_id = organization_value AND id = claimed.id;

    request_id := claimed.id;
    workspace_id := claimed.workspace_id;
    workspace_revision := claimed.workspace_revision;
    conversation_id := claimed.conversation_id;
    reason_code := claimed.reason_code;
    lease_epoch := claimed.lease_epoch + 1;
    attempt_number := claimed.attempt_count + 1;
    max_attempts := claimed.max_attempts;
    RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION app.conversation_purge_request_heartbeat(
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
        RAISE EXCEPTION 'conversation purge heartbeat requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_extend_seconds IS NULL OR p_extend_seconds < 1 OR p_extend_seconds > 3600 THEN
        RAISE EXCEPTION 'conversation purge heartbeat interval is invalid' USING ERRCODE = '22023';
    END IF;
    UPDATE public.conversation_purge_request
       SET lease_deadline = transaction_timestamp() + make_interval(secs => p_extend_seconds)
     WHERE organization_id = app.current_organization_id()
       AND id = p_request_id AND status = 'RUNNING'
       AND lease_owner = p_worker_id AND lease_epoch = p_lease_epoch
       AND lease_deadline > transaction_timestamp()
    RETURNING lease_deadline INTO new_deadline;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation purge request lease is not held' USING ERRCODE = '55000';
    END IF;
    RETURN new_deadline;
END;
$$;

CREATE OR REPLACE FUNCTION app.conversation_purge_request_complete(
    p_request_id text, p_worker_id text, p_lease_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'conversation purge completion requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM public.conversation_purge_request AS request
          JOIN public.conversation_retention AS retention
            ON retention.organization_id = request.organization_id
           AND retention.conversation_id = request.conversation_id
           AND retention.workspace_id = request.workspace_id
           AND retention.workspace_revision = request.workspace_revision
         WHERE request.organization_id = app.current_organization_id()
           AND request.id = p_request_id
           AND request.status = 'RUNNING'
           AND request.lease_owner = p_worker_id
           AND request.lease_epoch = p_lease_epoch
           AND request.lease_deadline > transaction_timestamp()
           AND retention.state = 'PURGED'
    ) THEN
        RAISE EXCEPTION 'conversation purge request cannot complete before PURGED retention or lease loss'
            USING ERRCODE = '55000';
    END IF;
    UPDATE public.conversation_purge_request
       SET status = 'SUCCEEDED', lease_owner = NULL, lease_deadline = NULL,
           completed_at = transaction_timestamp()
     WHERE organization_id = app.current_organization_id()
       AND id = p_request_id AND status = 'RUNNING'
       AND lease_owner = p_worker_id AND lease_epoch = p_lease_epoch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation purge request lease is not held'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.conversation_purge_request_fail(
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
        RAISE EXCEPTION 'conversation purge failure requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_error_code IS NULL OR p_error_code !~ '^[A-Z][A-Z0-9_]{2,63}$'
       OR p_retry_after_seconds IS NULL OR p_retry_after_seconds < 0
       OR p_retry_after_seconds > 2592000 THEN
        RAISE EXCEPTION 'conversation purge failure is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT attempt_count, max_attempts
      INTO current_attempt, attempt_ceiling
      FROM public.conversation_purge_request
     WHERE organization_id = app.current_organization_id()
       AND id = p_request_id AND status = 'RUNNING'
       AND lease_owner = p_worker_id AND lease_epoch = p_lease_epoch
       AND lease_deadline > transaction_timestamp()
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation purge request lease is not held' USING ERRCODE = '55000';
    END IF;
    IF current_attempt < attempt_ceiling THEN
        resulting_status := 'PENDING';
        UPDATE public.conversation_purge_request
           SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
               available_at = transaction_timestamp() + make_interval(secs => p_retry_after_seconds),
               last_error_code = p_error_code
         WHERE organization_id = app.current_organization_id() AND id = p_request_id;
    ELSE
        resulting_status := 'DEAD';
        UPDATE public.conversation_purge_request
           SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
               completed_at = transaction_timestamp(), last_error_code = p_error_code
         WHERE organization_id = app.current_organization_id() AND id = p_request_id;
    END IF;
    RETURN resulting_status;
END;
$$;

CREATE OR REPLACE FUNCTION app.conversation_purge_request_reclaim(p_limit integer)
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
        RAISE EXCEPTION 'conversation purge reclaim requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'conversation purge reclaim limit is invalid' USING ERRCODE = '22023';
    END IF;
    FOR request IN
        SELECT id, attempt_count, max_attempts
          FROM public.conversation_purge_request
         WHERE organization_id = app.current_organization_id()
           AND status = 'RUNNING' AND lease_deadline < transaction_timestamp()
         ORDER BY lease_deadline, id
         FOR UPDATE SKIP LOCKED
         LIMIT p_limit
    LOOP
        IF request.attempt_count < request.max_attempts THEN
            UPDATE public.conversation_purge_request
               SET status = 'PENDING', lease_owner = NULL, lease_deadline = NULL,
                   available_at = transaction_timestamp(), last_error_code = 'LEASE_EXPIRED'
             WHERE organization_id = app.current_organization_id() AND id = request.id;
        ELSE
            UPDATE public.conversation_purge_request
               SET status = 'DEAD', lease_owner = NULL, lease_deadline = NULL,
                   completed_at = transaction_timestamp(), last_error_code = 'LEASE_EXPIRED'
             WHERE organization_id = app.current_organization_id() AND id = request.id;
        END IF;
        reclaimed := reclaimed + 1;
    END LOOP;
    RETURN reclaimed;
END;
$$;

ALTER TABLE public.conversation_purge_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation_purge_request FORCE ROW LEVEL SECURITY;
CREATE POLICY conversation_purge_request_member_read ON public.conversation_purge_request
FOR SELECT TO knowvault_app
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1 FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_purge_request.organization_id
           AND member.workspace_id = conversation_purge_request.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_purge_request.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_purge_request.workspace_revision)
    )
);
CREATE POLICY conversation_purge_request_purger_read ON public.conversation_purge_request
FOR SELECT TO knowvault_purger
USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.conversation_purge_request FROM PUBLIC;
GRANT SELECT ON TABLE public.conversation_purge_request TO knowvault_app, knowvault_purger;
REVOKE ALL ON FUNCTION
    app.conversation_purge_request_enqueue(text, text, text, text, text, integer, integer, integer),
    app.conversation_purge_request_claim(text, integer),
    app.conversation_purge_request_heartbeat(text, text, bigint, integer),
    app.conversation_purge_request_complete(text, text, bigint),
    app.conversation_purge_request_fail(text, text, bigint, text, integer),
    app.conversation_purge_request_reclaim(integer)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    app.conversation_purge_request_enqueue(text, text, text, text, text, integer, integer, integer)
TO knowvault_app, knowvault_purger;
GRANT EXECUTE ON FUNCTION
    app.conversation_purge_request_claim(text, integer),
    app.conversation_purge_request_heartbeat(text, text, bigint, integer),
    app.conversation_purge_request_complete(text, text, bigint),
    app.conversation_purge_request_fail(text, text, bigint, text, integer),
    app.conversation_purge_request_reclaim(integer)
TO knowvault_purger;
GRANT USAGE ON SCHEMA app, public TO knowvault_app, knowvault_purger;
GRANT EXECUTE ON FUNCTION app.current_principal_id(), app.current_organization_id() TO knowvault_app, knowvault_purger;

COMMIT;
