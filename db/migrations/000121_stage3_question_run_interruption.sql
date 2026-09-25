-- Question runs must not stay RUNNING forever after the answering process
-- died. Every run records the process that owns it plus a heartbeat the owner
-- refreshes while it is still answering; a run whose owner stopped beating is
-- finished as INTERRUPTED ("interrupted, ask again") by the surviving server.
--
-- The liveness decision is deliberately made from persisted state, never from
-- an in-memory guess: several server replicas and one slow model call share
-- the same table, and only a run whose recorded owner is provably gone may be
-- finished. A run that is still being answered keeps a fresh heartbeat, so the
-- reconciler (below) never touches it.
--
-- The recovery gates are SECURITY DEFINER and read past FORCE ROW LEVEL
-- SECURITY because the reconciler runs for the whole tenant before any user
-- request exists and therefore has no workspace membership to be authorized
-- through. They are restricted to the runtime application role and to the
-- transaction-local organization, exactly like the job reclamation gates, and
-- they only ever move a RUNNING row to INTERRUPTED; a run owned by a live
-- process is never selected.
--
-- This migration owner gate mirrors 000011: the SECURITY DEFINER gates below
-- must see rows their caller cannot, and FORCE ROW LEVEL SECURITY applies to a
-- table's owner too. An owner that is neither SUPERUSER nor BYPASSRLS would
-- silently see zero runs and never reconcile anything, so the property is
-- asserted here rather than assumed.

BEGIN;

DO $$
DECLARE
    owner_bypasses_rls boolean;
BEGIN
    SELECT rolsuper OR rolbypassrls
    INTO owner_bypasses_rls
    FROM pg_catalog.pg_roles
    WHERE rolname = current_user;

    IF NOT FOUND OR NOT owner_bypasses_rls THEN
        RAISE EXCEPTION
            'question interruption migration owner % is neither SUPERUSER nor BYPASSRLS; its SECURITY DEFINER gates would silently under-count runs under FORCE ROW LEVEL SECURITY',
            current_user
            USING ERRCODE = '55000';
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- 1. Owner identity and heartbeat.
-- ---------------------------------------------------------------------------

ALTER TABLE public.question_run
    ADD COLUMN owner_id text
        CHECK (owner_id IS NULL OR (
            char_length(owner_id) BETWEEN 1 AND 128
            AND btrim(owner_id) = owner_id
            AND owner_id !~ '[[:cntrl:]]'
        )),
    ADD COLUMN owner_heartbeat_at timestamptz;

COMMENT ON COLUMN public.question_run.owner_id IS
    'Process instance that is answering this run; NULL only for rows written before 000121';
COMMENT ON COLUMN public.question_run.owner_heartbeat_at IS
    'Last proof that owner_id was still answering; refreshed while RUNNING';

-- Only RUNNING rows are ever reconciled, so the candidate scan is a partial
-- index over exactly those rows, ordered by the heartbeat that fences them.
CREATE INDEX question_run_running_heartbeat
    ON public.question_run (organization_id, owner_heartbeat_at)
    WHERE result_status = 'RUNNING' AND owner_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. The closed terminal vocabulary gains INTERRUPTED.
-- ---------------------------------------------------------------------------

ALTER TABLE public.question_run
    DROP CONSTRAINT IF EXISTS question_run_terminal_shape_check,
    DROP CONSTRAINT IF EXISTS question_run_answer_shape_check;

-- The inline result_status CHECK is unnamed, so it is dropped by definition
-- rather than by a name this migration would have to guess.
DO $$
DECLARE
    status_constraint text;
BEGIN
    FOR status_constraint IN
        SELECT constraint_record.conname
        FROM pg_catalog.pg_constraint AS constraint_record
        JOIN pg_catalog.pg_class AS relation_record
          ON relation_record.oid = constraint_record.conrelid
        JOIN pg_catalog.pg_namespace AS namespace_record
          ON namespace_record.oid = relation_record.relnamespace
        WHERE namespace_record.nspname = 'public'
          AND relation_record.relname = 'question_run'
          AND constraint_record.contype = 'c'
          AND pg_catalog.pg_get_constraintdef(constraint_record.oid) LIKE '%result_status%'
    LOOP
        EXECUTE format('ALTER TABLE public.question_run DROP CONSTRAINT %I', status_constraint);
    END LOOP;
END;
$$;

ALTER TABLE public.question_run
    ADD CONSTRAINT question_run_result_status_check CHECK (
        result_status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'INSUFFICIENT_EVIDENCE', 'FAILED', 'CANCELLED', 'INTERRUPTED')
    ),
    ADD CONSTRAINT question_run_terminal_shape_check CHECK (
        (result_status IN ('QUEUED', 'RUNNING') AND completed_at IS NULL)
        OR (result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE', 'FAILED', 'CANCELLED', 'INTERRUPTED') AND completed_at IS NOT NULL)
    ),
    ADD CONSTRAINT question_run_answer_shape_check CHECK (
        (result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE') AND answer_hash IS NOT NULL)
        OR (result_status IN ('QUEUED', 'RUNNING', 'FAILED', 'CANCELLED', 'INTERRUPTED'))
    );

-- ---------------------------------------------------------------------------
-- 3. The existing state guard learns exactly one new terminal state and keeps
--    the owner identity immutable once assigned.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.question_run_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'question runs are immutable' USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_app'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR NEW.created_by IS DISTINCT FROM app.current_principal_id()
           OR NOT EXISTS (
               SELECT 1 FROM public.workspace_member member
               JOIN public.workspace workspace
                 ON workspace.organization_id = member.organization_id
                AND workspace.id = member.workspace_id
               WHERE member.organization_id = NEW.organization_id
                 AND member.workspace_id = NEW.workspace_id
                 AND member.principal_id = NEW.created_by
                 AND member.removed_at IS NULL
                 AND member.role IN ('OWNER', 'MANAGER', 'MEMBER')
                 AND workspace.status = 'ACTIVE'
           ) THEN
            RAISE EXCEPTION 'question run requires an active workspace asker' USING ERRCODE = '42501';
        END IF;
        IF NEW.result_status NOT IN ('QUEUED', 'RUNNING') THEN
            RAISE EXCEPTION 'question run must start queued or running' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE', 'FAILED', 'CANCELLED', 'INTERRUPTED') THEN
        RAISE EXCEPTION 'terminal question runs are immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR (OLD.question_text_artifact_id IS NOT NULL AND NEW.question_text_artifact_id IS DISTINCT FROM OLD.question_text_artifact_id)
       OR NEW.question_hash IS DISTINCT FROM OLD.question_hash
       OR NEW.answer_mode IS DISTINCT FROM OLD.answer_mode
       OR NEW.verification_method IS DISTINCT FROM OLD.verification_method
       OR (OLD.owner_id IS NOT NULL AND NEW.owner_id IS DISTINCT FROM OLD.owner_id)
       OR NEW.started_at IS DISTINCT FROM OLD.started_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.workspace_scope_hash IS DISTINCT FROM OLD.workspace_scope_hash
       OR NEW.retrieval_version IS DISTINCT FROM OLD.retrieval_version
       OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
       OR NEW.supersedes_question_run_id IS DISTINCT FROM OLD.supersedes_question_run_id THEN
        RAISE EXCEPTION 'question run identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.result_status = 'QUEUED' AND OLD.result_status <> 'QUEUED' THEN
        RAISE EXCEPTION 'question run status cannot move backwards' USING ERRCODE = '23514';
    END IF;
    IF NEW.result_status = 'RUNNING' AND OLD.result_status NOT IN ('QUEUED', 'RUNNING') THEN
        RAISE EXCEPTION 'question run status cannot move backwards' USING ERRCODE = '23514';
    END IF;
    IF OLD.answer_markdown_artifact_id IS NOT NULL AND NEW.answer_markdown_artifact_id IS DISTINCT FROM OLD.answer_markdown_artifact_id THEN
        RAISE EXCEPTION 'answer markdown artifact is write-once' USING ERRCODE = '55000';
    END IF;
    IF OLD.answer_structured_artifact_id IS NOT NULL AND NEW.answer_structured_artifact_id IS DISTINCT FROM OLD.answer_structured_artifact_id THEN
        RAISE EXCEPTION 'answer structured artifact is write-once' USING ERRCODE = '55000';
    END IF;
    IF OLD.manifest_content_artifact_id IS NOT NULL AND NEW.manifest_content_artifact_id IS DISTINCT FROM OLD.manifest_content_artifact_id THEN
        RAISE EXCEPTION 'manifest artifact is write-once' USING ERRCODE = '55000';
    END IF;
    IF NEW.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE')
       AND (NEW.answer_markdown_artifact_id IS NULL OR NEW.answer_structured_artifact_id IS NULL
            OR NEW.context_pack_hash IS NULL OR NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION 'terminal question run is missing answer artifacts' USING ERRCODE = '23514';
    END IF;
    IF NEW.result_status = 'FAILED' AND (NEW.failure_code IS NULL OR NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION 'failed question run is missing failure state' USING ERRCODE = '23514';
    END IF;
    IF NEW.result_status = 'INTERRUPTED' AND (NEW.failure_code IS NULL OR NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION 'interrupted question run is missing interruption state' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Tenant-wide orphan discovery and the lease-fenced finish.
-- ---------------------------------------------------------------------------

-- Lists RUNNING runs in the caller's tenant whose recorded owner stopped
-- beating before the grace window. Runs without an owner (written before this
-- migration) are deliberately excluded: their liveness cannot be proven, and
-- an old binary's in-flight run must never be finished by mistake.
CREATE OR REPLACE FUNCTION app.question_run_orphan_candidates(
    p_grace_seconds integer,
    p_limit integer
)
RETURNS TABLE (
    run_id text,
    workspace_id text,
    owner_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'question run reconciliation is restricted to the application role' USING ERRCODE = '42501';
    END IF;
    IF p_grace_seconds IS NULL OR p_grace_seconds < 0 OR p_grace_seconds > 86400 THEN
        RAISE EXCEPTION 'question run grace window is out of range' USING ERRCODE = '22023';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'question run reconciliation limit is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'question run reconciliation requires a tenant context' USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
        SELECT run.id, run.workspace_id, run.owner_id
        FROM public.question_run AS run
        WHERE run.organization_id = organization_value
          AND run.result_status = 'RUNNING'
          AND run.owner_id IS NOT NULL
          AND COALESCE(run.owner_heartbeat_at, run.started_at)
              < transaction_timestamp() - make_interval(secs => p_grace_seconds)
        ORDER BY COALESCE(run.owner_heartbeat_at, run.started_at), run.id
        LIMIT p_limit;
END;
$$;

-- Finishes exactly one run whose owner is still the one that was found gone.
-- It is a compare-and-set: a run that completed, or whose heartbeat the owner
-- refreshed after discovery, is left untouched and returns NULL. The returned
-- workspace is the row that was actually finished, so the audit event is only
-- ever appended for a real terminal transition.
CREATE OR REPLACE FUNCTION app.question_run_interrupt_orphan(
    p_run_id text,
    p_owner_id text,
    p_grace_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    finished_workspace text;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'question run reconciliation is restricted to the application role' USING ERRCODE = '42501';
    END IF;
    IF p_run_id IS NULL OR p_run_id = '' OR p_owner_id IS NULL OR p_owner_id = '' THEN
        RAISE EXCEPTION 'question run reconciliation identity is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_grace_seconds IS NULL OR p_grace_seconds < 0 OR p_grace_seconds > 86400 THEN
        RAISE EXCEPTION 'question run grace window is out of range' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'question run reconciliation requires a tenant context' USING ERRCODE = '42501';
    END IF;

    UPDATE public.question_run AS run
    SET result_status = 'INTERRUPTED',
        completed_at = transaction_timestamp(),
        failure_code = 'QUESTION_INTERRUPTED'
    WHERE run.organization_id = organization_value
      AND run.id = p_run_id
      AND run.result_status = 'RUNNING'
      AND run.owner_id = p_owner_id
      AND COALESCE(run.owner_heartbeat_at, run.started_at)
          < transaction_timestamp() - make_interval(secs => p_grace_seconds)
    RETURNING run.workspace_id INTO finished_workspace;

    RETURN finished_workspace;
END;
$$;

REVOKE ALL ON FUNCTION app.question_run_orphan_candidates(integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.question_run_interrupt_orphan(text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_run_orphan_candidates(integer, integer) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.question_run_interrupt_orphan(text, text, integer) TO knowvault_app;

COMMIT;
