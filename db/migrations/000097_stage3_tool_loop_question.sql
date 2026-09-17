-- Tool-loop runs retain the existing run/conversation authorization, encrypted
-- artifacts, audit and purge lifecycle. Only the mode vocabulary is extended.
BEGIN;
ALTER TABLE public.question_run DROP CONSTRAINT question_run_answer_mode_check;
ALTER TABLE public.question_run ADD CONSTRAINT question_run_answer_mode_check
    CHECK (answer_mode IN ('EXTRACTIVE', 'GENERATIVE', 'TOOL_LOOP'));
ALTER TABLE public.question_run DROP CONSTRAINT question_run_verification_method_check;
ALTER TABLE public.question_run ADD CONSTRAINT question_run_verification_method_check
    CHECK (verification_method IN ('BYTE_EXACT_CITATION', 'SEMANTIC_VERIFIER', 'ADDRESS_BOUND'));
ALTER TABLE public.question_run DROP CONSTRAINT question_run_mode_pair_check;
ALTER TABLE public.question_run ADD CONSTRAINT question_run_mode_pair_check CHECK (
    (answer_mode = 'EXTRACTIVE' AND verification_method = 'BYTE_EXACT_CITATION') OR
    (answer_mode = 'GENERATIVE' AND verification_method = 'SEMANTIC_VERIFIER') OR
    (answer_mode = 'TOOL_LOOP' AND verification_method = 'ADDRESS_BOUND')
);
-- Retain the two-attempt limit for the legacy generation mode; the tool loop
-- is bounded by its mounted profile and at most twenty model turns.
ALTER TABLE public.question_model_gateway_attempt
    DROP CONSTRAINT question_model_gateway_attempt_attempt_number_check;
ALTER TABLE public.question_model_gateway_attempt
    ADD CONSTRAINT question_model_gateway_attempt_attempt_number_check
    CHECK (attempt_number BETWEEN 1 AND 20);

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
       OR run_mode NOT IN ('GENERATIVE', 'TOOL_LOOP')
       OR (run_mode = 'GENERATIVE' AND NEW.attempt_number > 2) THEN
        RAISE EXCEPTION 'model gateway attempt is not bound to an active generation run' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
