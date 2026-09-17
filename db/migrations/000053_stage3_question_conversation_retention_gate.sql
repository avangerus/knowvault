-- Stage 3: conversation retention must revoke every Question Run disclosure.
--
-- Question runs created after the conversation substrate carry an immutable
-- conversation binding.  The original question_run_readable gate checked the
-- per-run retention row and source Evidence, but did not also check the
-- conversation retention row.  That left a revoked conversation's Question
-- Run replayable through the REST question GET route.  This migration extends
-- the existing server-side gate and its RLS policy without changing legacy
-- unbound runs.

BEGIN;

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
                    AND conversation_retention.workspace_revision = run.workspace_revision
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

DROP POLICY IF EXISTS question_run_tenant_membership ON public.question_run;
CREATE POLICY question_run_tenant_membership ON public.question_run
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member member
            WHERE member.organization_id = question_run.organization_id
              AND member.workspace_id = question_run.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    )
    WITH CHECK (organization_id = app.current_organization_id());

GRANT EXECUTE ON FUNCTION app.question_run_readable(text, text) TO knowvault_app;

COMMIT;
