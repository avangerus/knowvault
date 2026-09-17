-- FIX-2 #5: a conversation continues across an unrelated workspace revision
-- bump, not just across an unrelated source-scope mutation (000076/000077's
-- same fix for the aggregate/evidence gates).
--
-- Defect (question.Service.start, documented at the exact call site removed
-- below, FIX-1 #4 investigation note): migration 000048 stores ONE fixed
-- workspace_revision on public.conversation, set once when the conversation
-- is created, and enforces exact equality with it in three independent
-- places -- the conversation_turn_conversation_fk (a FOREIGN KEY over all
-- four columns including workspace_revision), and the
-- conversation/conversation_turn/conversation_retention RLS policies' own
-- `parent.workspace_revision = conversation_turn.workspace_revision` and
-- `retention.workspace_revision = conversation_turn.workspace_revision`
-- joins. Every new Question Run is created at the workspace's CURRENT
-- revision (question.Service.start's own workspaceRevision, already correct
-- -- see the INSERT INTO conversation_turn a few lines below this
-- migration's own predicates), so the instant ANY workspace mutation
-- unrelated to this conversation (a membership change, an access code, a
-- different source's confirmation) advances workspace.current_revision, the
-- next turn's own workspace_revision stops matching the conversation's
-- ORIGINAL, frozen value and both the FK and the RLS policies reject it --
-- the FK with a hard constraint violation, the RLS policies by silently
-- excluding the parent/retention row from the join and denying the insert.
-- Owner-report symptom: ask a follow-up in an existing conversation after
-- touching anything else in "Sources" and the continuation is refused.
--
-- Fix, mirroring 000076/000077 exactly: stop requiring the STORED value to
-- match. A conversation's identity is (organization_id, id, workspace_id);
-- the FK now targets that tuple instead of the frozen revision, and every
-- RLS join between conversation_turn and its parent/retention row drops the
-- revision equality entirely (the parent/retention row is looked up by
-- conversation_id + workspace_id, exactly like a citation's evidence gate
-- already looks up a source scope's binding by scope id, not by the
-- confirmation's own historical revision).
--
-- What this does NOT weaken: this is CONTINUATION, not first read. Rights
-- are still fully re-checked on every hop, and MORE strictly than before --
-- conversation_member_read/insert/update now check membership against
-- workspace.current_revision (a live snapshot) instead of the
-- conversation's own frozen creation-time revision, so a member REMOVED
-- since a conversation was created can no longer read or continue it (the
-- old equality check could not see that removal happened after the
-- recorded revision). retention.disclosure_allowed is still required on
-- every read/insert, unchanged. A NEW turn's own workspace_revision is
-- still exactly the workspace's current revision at the moment
-- question.Service.start inserts it (unchanged Go code) -- "snapshot of the current
-- revision", not a wider window. Tenant isolation
-- (organization_id = app.current_organization_id()) is untouched on every
-- policy below.

BEGIN;

ALTER TABLE public.conversation
    ADD CONSTRAINT conversation_id_workspace_uq UNIQUE (organization_id, id, workspace_id);

ALTER TABLE public.conversation_turn
    DROP CONSTRAINT conversation_turn_conversation_fk,
    ADD CONSTRAINT conversation_turn_conversation_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id)
        REFERENCES public.conversation (organization_id, id, workspace_id)
        ON DELETE RESTRICT;

-- 000049 added a SECOND fk from question_run straight to conversation, on the
-- exact same frozen-revision tuple, DEFERRABLE INITIALLY DEFERRED (checked at
-- COMMIT, so start()'s own INSERT INTO question_run for a continuation turn
-- hits it too, one statement before the conversation_turn insert above ever
-- runs). It needs the identical loosening.
ALTER TABLE public.question_run
    DROP CONSTRAINT question_run_conversation_binding_fk,
    ADD CONSTRAINT question_run_conversation_binding_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id)
        REFERENCES public.conversation (organization_id, id, workspace_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

DROP POLICY conversation_member_read ON public.conversation;
CREATE POLICY conversation_member_read ON public.conversation
FOR SELECT
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status NOT IN ('ARCHIVED', 'DELETING', 'DELETED')
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= workspace.current_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation.organization_id
           AND retention.conversation_id = conversation.id
           AND retention.workspace_id = conversation.workspace_id
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
);
DROP POLICY conversation_member_insert ON public.conversation;
CREATE POLICY conversation_member_insert ON public.conversation
FOR INSERT
WITH CHECK (
    organization_id = app.current_organization_id()
    AND archived_at IS NULL
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= workspace.current_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
    )
);
DROP POLICY conversation_member_update ON public.conversation;
CREATE POLICY conversation_member_update ON public.conversation
FOR UPDATE
USING (
    organization_id = app.current_organization_id()
    AND archived_at IS NULL
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= workspace.current_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
    )
)
WITH CHECK (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= workspace.current_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
    )
);

DROP POLICY conversation_turn_member_read ON public.conversation_turn;
CREATE POLICY conversation_turn_member_read ON public.conversation_turn
FOR SELECT
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_turn.organization_id
           AND member.workspace_id = conversation_turn.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_turn.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_turn.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation AS parent
         WHERE parent.organization_id = conversation_turn.organization_id
           AND parent.id = conversation_turn.conversation_id
           AND parent.workspace_id = conversation_turn.workspace_id
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation_turn.organization_id
           AND retention.conversation_id = conversation_turn.conversation_id
           AND retention.workspace_id = conversation_turn.workspace_id
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
);
DROP POLICY conversation_turn_member_insert ON public.conversation_turn;
CREATE POLICY conversation_turn_member_insert ON public.conversation_turn
FOR INSERT
WITH CHECK (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_turn.organization_id
           AND member.workspace_id = conversation_turn.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_turn.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_turn.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation AS parent
         WHERE parent.organization_id = conversation_turn.organization_id
           AND parent.id = conversation_turn.conversation_id
           AND parent.workspace_id = conversation_turn.workspace_id
           AND parent.archived_at IS NULL
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation_turn.organization_id
           AND retention.conversation_id = conversation_turn.conversation_id
           AND retention.workspace_id = conversation_turn.workspace_id
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
);
DROP POLICY conversation_turn_member_update ON public.conversation_turn;
CREATE POLICY conversation_turn_member_update ON public.conversation_turn
FOR UPDATE
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_turn.organization_id
           AND member.workspace_id = conversation_turn.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_turn.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_turn.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation_turn.organization_id
           AND retention.conversation_id = conversation_turn.conversation_id
           AND retention.workspace_id = conversation_turn.workspace_id
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
)
WITH CHECK (false);

-- app.question_run_readable (000053) independently re-derived the identical
-- frozen-revision coupling one join further out: it required
-- conversation_retention.workspace_revision (fixed at the conversation's
-- creation) to equal THIS RUN's OWN workspace_revision (the run's real,
-- current-at-creation revision) before a conversation-bound run counts as
-- readable at all. A continuation run created at a later revision than the
-- conversation's original one therefore failed this gate even after the FK
-- and RLS fixes above let its rows insert -- exactly the QUESTION_DENIED
-- this migration's own test caught. The retention row is looked up by
-- conversation_id + workspace_id, matching every other join this migration
-- touches; disclosure_allowed/state are still fully re-checked, unchanged.
CREATE OR REPLACE FUNCTION app.question_run_readable(p_question_run_id text, p_workspace_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.question_run run
        JOIN public.workspace workspace
          ON workspace.organization_id = run.organization_id AND workspace.id = run.workspace_id
        JOIN public.workspace_member member
          ON member.organization_id = run.organization_id AND member.workspace_id = run.workspace_id
         AND member.principal_id = app.current_principal_id() AND member.removed_at IS NULL
        JOIN public.question_run_retention retention
          ON retention.organization_id = run.organization_id AND retention.question_run_id = run.id
        WHERE run.organization_id = app.current_organization_id()
          AND run.id = p_question_run_id
          AND run.workspace_id = p_workspace_id
          AND workspace.status IN ('ACTIVE', 'READ_ONLY', 'ARCHIVED')
          AND retention.state = 'ACTIVE'
          AND retention.disclosure_allowed
          AND (
              run.conversation_id IS NULL
              OR EXISTS (
                  SELECT 1
                  FROM public.conversation_retention conversation_retention
                  WHERE conversation_retention.organization_id = run.organization_id
                    AND conversation_retention.conversation_id = run.conversation_id
                    AND conversation_retention.workspace_id = run.workspace_id
                    AND conversation_retention.state = 'ACTIVE'
                    AND conversation_retention.disclosure_allowed
              )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM public.question_citation citation
              WHERE citation.organization_id = run.organization_id
                AND citation.question_run_id = run.id
                AND NOT app.evidence_fragment_readable(citation.evidence_fragment_id, run.workspace_id)
          )
    );
$$;

GRANT EXECUTE ON FUNCTION app.question_run_readable(text, text) TO knowvault_app;

-- conversation_retention's OWN member_read/member_insert policies had the
-- same latent staleness one level deeper (membership checked against the
-- retention row's OWN frozen workspace_revision rather than a live
-- snapshot); harmless while the only member is the conversation's own owner
-- (never removed in this fix's own regression tests) but the same class of
-- bug as the rest of this migration, so it is closed the same way: against
-- workspace.current_revision.
DROP POLICY conversation_retention_member_read ON public.conversation_retention;
CREATE POLICY conversation_retention_member_read ON public.conversation_retention
FOR SELECT TO knowvault_app
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation_retention.organization_id
           AND workspace.id = conversation_retention.workspace_id
           AND workspace.status NOT IN ('ARCHIVED', 'DELETING', 'DELETED')
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= workspace.current_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
    )
);
DROP POLICY conversation_retention_member_insert ON public.conversation_retention;
CREATE POLICY conversation_retention_member_insert ON public.conversation_retention
FOR INSERT TO knowvault_app
WITH CHECK (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation_retention.organization_id
           AND workspace.id = conversation_retention.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= workspace.current_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
    )
);

COMMIT;
