-- Stage 3 conversation binding for Question Runs.
--
-- Conversation/turn rows remain the durable graph.  This transition adds only
-- opaque, server-owned references to the immutable Question Run row so every
-- API/MCP projection can resolve its conversation without copying plaintext
-- history.  Both references are nullable for legacy runs created before the
-- conversation substrate; new runs must provide the pair atomically.

BEGIN;

ALTER TABLE public.conversation_turn
    ADD CONSTRAINT conversation_turn_question_run_identity_uq
    UNIQUE (organization_id, conversation_id, id, workspace_id, workspace_revision, question_run_id);

ALTER TABLE public.question_run
    ADD COLUMN conversation_id text
        CHECK (conversation_id IS NULL OR app.stage2_opaque_id_is_valid(conversation_id)),
    ADD COLUMN conversation_turn_id text
        CHECK (conversation_turn_id IS NULL OR app.stage2_opaque_id_is_valid(conversation_turn_id));

ALTER TABLE public.question_run
    ADD CONSTRAINT question_run_conversation_pair_check CHECK (
        (conversation_id IS NULL AND conversation_turn_id IS NULL)
        OR (conversation_id IS NOT NULL AND conversation_turn_id IS NOT NULL)
    ),
    ADD CONSTRAINT question_run_conversation_binding_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id, workspace_revision)
        REFERENCES public.conversation (organization_id, id, workspace_id, workspace_revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT question_run_conversation_turn_binding_fk
        FOREIGN KEY (organization_id, conversation_id, conversation_turn_id, workspace_id, workspace_revision, id)
        REFERENCES public.conversation_turn (
            organization_id, conversation_id, id, workspace_id, workspace_revision, question_run_id
        )
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX question_run_conversation_created
    ON public.question_run (organization_id, conversation_id, created_at DESC, id DESC)
    WHERE conversation_id IS NOT NULL;

CREATE OR REPLACE FUNCTION app.question_run_conversation_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (NEW.conversation_id IS NULL) <> (NEW.conversation_turn_id IS NULL) THEN
            RAISE EXCEPTION 'question run conversation binding must be paired' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.conversation_turn_id IS DISTINCT FROM OLD.conversation_turn_id THEN
        RAISE EXCEPTION 'question run conversation binding is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_run_conversation_binding_guard
BEFORE INSERT OR UPDATE ON public.question_run
FOR EACH ROW EXECUTE FUNCTION app.question_run_conversation_binding_guard();

REVOKE ALL ON FUNCTION app.question_run_conversation_binding_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_run_conversation_binding_guard() TO knowvault_app;

COMMIT;
