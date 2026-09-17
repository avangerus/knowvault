-- GEN-1 (ADR-0088): content-free Model Gateway attempt provenance.
--
-- This relation exists only to prove MOD-007/MOD-008: every bounded
-- generation attempt the interim GEN-1 adapter makes is durably recorded
-- before the caller can see its outcome, bound to the exact Question Run and
-- the exact set of Evidence IDs offered to that attempt. It never carries
-- question text, Evidence text, prompt bytes or model output; only byte
-- counts, a hash of the Evidence-ID set and a content-free status/failure
-- code cross the boundary into this table.
--
-- This does not activate GENERATIVE mode: question_run.answer_mode is
-- unchanged by this migration, and the interim adapter is off by default
-- (see internal/modelgateway/mount_lab.go).

BEGIN;

CREATE TABLE public.question_model_gateway_attempt (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    question_run_id text NOT NULL,
    workspace_id text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('GENERATION')),
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 2),
    model_id text NOT NULL CHECK (
        char_length(model_id) BETWEEN 1 AND 256 AND model_id !~ '[[:cntrl:]]'
        AND model_id = btrim(model_id)
    ),
    evidence_set_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(evidence_set_hash)),
    request_bytes bigint NOT NULL CHECK (request_bytes BETWEEN 0 AND 8388608),
    response_bytes bigint NOT NULL CHECK (response_bytes BETWEEN 0 AND 8388608),
    status text NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED')),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    -- GEN-2: typed, content-free classification of the adapter endpoint this
    -- attempt used. LOCAL_LAB is the default (no workspace restriction);
    -- EXTERNAL_WORKSPACE_SCOPED means a public endpoint an operator explicitly
    -- allow-listed exact workspaces for (internal/modelgateway/lab_adapter.go
    -- AllowsWorkspace). Never carries a hostname, key or other content.
    runtime_scope text NOT NULL CHECK (runtime_scope IN ('LOCAL_LAB', 'EXTERNAL_WORKSPACE_SCOPED')),
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, question_run_id, attempt_number),
    CONSTRAINT question_model_gateway_attempt_question_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_model_gateway_attempt_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_model_gateway_attempt_time_check CHECK (completed_at >= started_at),
    CONSTRAINT question_model_gateway_attempt_status_shape_check CHECK (
        (status = 'SUCCEEDED' AND failure_code IS NULL)
        OR (status = 'FAILED' AND failure_code IS NOT NULL)
    )
);

CREATE INDEX question_model_gateway_attempt_question_order
    ON public.question_model_gateway_attempt (organization_id, question_run_id, attempt_number);

CREATE OR REPLACE FUNCTION app.question_model_gateway_attempt_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_workspace text;
    run_mode text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'model gateway attempts are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'model gateway attempt requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT workspace_id, answer_mode INTO run_workspace, run_mode
      FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id
       AND result_status IN ('QUEUED', 'RUNNING');
    IF run_workspace IS NULL OR run_workspace IS DISTINCT FROM NEW.workspace_id
       OR run_mode IS DISTINCT FROM 'GENERATIVE' THEN
        RAISE EXCEPTION 'model gateway attempt is not bound to an active GENERATIVE run' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_model_gateway_attempt_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_model_gateway_attempt
FOR EACH ROW EXECUTE FUNCTION app.question_model_gateway_attempt_guard();

ALTER TABLE public.question_model_gateway_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_model_gateway_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY question_model_gateway_attempt_membership ON public.question_model_gateway_attempt
    USING (
        organization_id = app.current_organization_id()
        AND app.question_run_readable(question_run_id, workspace_id)
    )
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.question_run run
            WHERE run.organization_id = question_model_gateway_attempt.organization_id
              AND run.id = question_model_gateway_attempt.question_run_id
              AND run.workspace_id = question_model_gateway_attempt.workspace_id
        )
    );

REVOKE ALL ON TABLE public.question_model_gateway_attempt FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.question_model_gateway_attempt TO knowvault_app;
REVOKE ALL ON FUNCTION app.question_model_gateway_attempt_guard() FROM PUBLIC;

COMMIT;
