-- Persist the server-owned generic planner decision alongside every Question
-- Run.  The plan hash is provenance, never executable SQL or an access grant.
BEGIN;

ALTER TABLE public.question_run
    ADD COLUMN planner_status text NOT NULL DEFAULT 'READY'
        CHECK (planner_status IN ('READY', 'UNKNOWN', 'CLARIFICATION_REQUIRED')),
    ADD COLUMN planner_operation text NOT NULL DEFAULT 'LOOKUP'
        CHECK (planner_operation IN ('LOOKUP', 'EXPLAIN', 'COMPARE', 'AGGREGATE', 'AUDIT', 'CODE_TRACE', 'UNKNOWN', 'CLARIFY')),
    ADD COLUMN planner_confidence text NOT NULL DEFAULT 'LOW'
        CHECK (planner_confidence IN ('NONE', 'LOW', 'MEDIUM', 'HIGH')),
    ADD COLUMN planner_plan_hash text
        CHECK (planner_plan_hash IS NULL OR app.stage2_sha256_is_valid(planner_plan_hash)),
    ADD COLUMN planner_clarification text
        CHECK (planner_clarification IS NULL OR (char_length(planner_clarification) <= 2048 AND planner_clarification !~ '[[:cntrl:]]'));

CREATE OR REPLACE FUNCTION app.question_run_planner_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.planner_status IS DISTINCT FROM OLD.planner_status
        OR NEW.planner_operation IS DISTINCT FROM OLD.planner_operation
        OR NEW.planner_confidence IS DISTINCT FROM OLD.planner_confidence
        OR NEW.planner_plan_hash IS DISTINCT FROM OLD.planner_plan_hash
        OR NEW.planner_clarification IS DISTINCT FROM OLD.planner_clarification
    ) THEN
        RAISE EXCEPTION 'question planner decision is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_run_planner_identity_guard
BEFORE UPDATE OF planner_status, planner_operation, planner_confidence,
                 planner_plan_hash, planner_clarification
ON public.question_run
FOR EACH ROW EXECUTE FUNCTION app.question_run_planner_guard();

COMMENT ON COLUMN public.question_run.planner_plan_hash IS
    'Canonical server-owned knowledge-plan-v1 digest; never executable SQL or model output';

COMMIT;
