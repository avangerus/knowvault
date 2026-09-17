-- Stage 3 typed analytic-tool provenance.
--
-- The registry is the in-process dispatch boundary; this relation is the
-- durable hand-off.  It records which server-owned binding ran for which
-- immutable planner decision and which Evidence IDs were actually returned.
-- It accepts no SQL, relation names, credentials or model payloads.

BEGIN;

CREATE OR REPLACE FUNCTION app.question_tool_evidence_ids_valid(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    item text;
    seen text[] := ARRAY[]::text[];
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array'
       OR jsonb_array_length(value) > 256
       OR octet_length(value::text) > 65536 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value_item FROM jsonb_array_elements_text(value) AS row(value_item)
    LOOP
        IF NOT app.stage2_opaque_id_is_valid(item) OR item = ANY(seen) THEN
            RETURN false;
        END IF;
        seen := array_append(seen, item);
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE public.question_tool_run (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    question_run_id text NOT NULL,
    workspace_id text NOT NULL,
    tool_id text NOT NULL CHECK (tool_id ~ '^analytic[.][a-z0-9][a-z0-9.-]{0,95}-v[1-9][0-9]{0,3}$'),
    binding_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(binding_hash)),
    plan_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(plan_hash)),
    result_hash text CHECK (result_hash IS NULL OR app.stage2_sha256_is_valid(result_hash)),
    evidence_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (app.question_tool_evidence_ids_valid(evidence_ids_json)),
    row_count bigint NOT NULL CHECK (row_count BETWEEN 0 AND 100000),
    cell_count bigint NOT NULL CHECK (cell_count BETWEEN 0 AND 100000),
    bucket_count bigint NOT NULL CHECK (bucket_count BETWEEN 0 AND 128),
    status text NOT NULL CHECK (status IN ('SUCCEEDED', 'FAILED')),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    receipt_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(receipt_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT question_tool_run_question_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_tool_run_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_tool_run_time_check CHECK (completed_at >= started_at),
    CONSTRAINT question_tool_run_status_shape_check CHECK (
        (status = 'SUCCEEDED' AND result_hash IS NOT NULL AND failure_code IS NULL)
        OR (status = 'FAILED' AND result_hash IS NULL AND failure_code IS NOT NULL)
    )
);

CREATE INDEX question_tool_run_question_order
    ON public.question_tool_run (organization_id, question_run_id, created_at, id);

CREATE OR REPLACE FUNCTION app.question_tool_run_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_workspace text;
    run_plan_hash text;
    item text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'analytic tool runs are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'analytic tool run requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT workspace_id, planner_plan_hash INTO run_workspace, run_plan_hash
      FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id
       AND result_status IN ('QUEUED', 'RUNNING');
    IF run_workspace IS NULL OR run_workspace IS DISTINCT FROM NEW.workspace_id
       OR run_plan_hash IS DISTINCT FROM NEW.plan_hash THEN
        RAISE EXCEPTION 'analytic tool run is not bound to the active planner decision' USING ERRCODE = '23514';
    END IF;
    FOR item IN SELECT value_item FROM jsonb_array_elements_text(NEW.evidence_ids_json) AS row(value_item)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM public.evidence_fragment fragment
            WHERE fragment.organization_id = NEW.organization_id AND fragment.id = item
        ) THEN
            RAISE EXCEPTION 'analytic tool run references an unknown Evidence fragment' USING ERRCODE = '23503';
        END IF;
        IF NOT app.evidence_fragment_readable(item, NEW.workspace_id) THEN
            RAISE EXCEPTION 'analytic tool run references Evidence outside the current workspace authority' USING ERRCODE = '42501';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_tool_run_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_tool_run
FOR EACH ROW EXECUTE FUNCTION app.question_tool_run_guard();

ALTER TABLE public.question_tool_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_tool_run FORCE ROW LEVEL SECURITY;
CREATE POLICY question_tool_run_membership ON public.question_tool_run
    USING (
        organization_id = app.current_organization_id()
        AND app.question_run_readable(question_run_id, workspace_id)
        AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(question_tool_run.evidence_ids_json) AS item(value)
            WHERE NOT app.evidence_fragment_readable(item.value, question_tool_run.workspace_id)
        )
    )
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.question_run run
            WHERE run.organization_id = question_tool_run.organization_id
              AND run.id = question_tool_run.question_run_id
              AND run.workspace_id = question_tool_run.workspace_id
        )
    );

REVOKE ALL ON TABLE public.question_tool_run FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.question_tool_run TO knowvault_app;
REVOKE ALL ON FUNCTION app.question_tool_evidence_ids_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.question_tool_run_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_tool_evidence_ids_valid(jsonb) TO knowvault_app, knowvault_worker;

COMMIT;
