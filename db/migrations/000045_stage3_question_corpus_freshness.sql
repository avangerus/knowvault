-- Stage 3 server-owned content freshness projection for Question Runs.
-- The question service must not read source-scope tables directly: this narrow
-- SECURITY DEFINER function keeps source lifecycle authority behind the same
-- tenant/workspace binding used by question_corpus_source_status.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'runtime role knowvault_app must exist before this migration';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_corpus_content_freshness_sla(
    p_workspace_id text, p_source_scope_id text, p_source_scope_revision bigint
)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT scope.content_freshness_sla_seconds
      FROM public.workspace_revision_source binding
      JOIN public.workspace w
        ON w.organization_id = binding.organization_id
       AND w.id = binding.workspace_id
      JOIN public.workspace_member member
        ON member.organization_id = w.organization_id
       AND member.workspace_id = w.id
       AND member.principal_id = app.current_principal_id()
       AND member.valid_to_revision IS NULL
       AND member.removed_at IS NULL
      JOIN public.source_scope_revision scope
        ON scope.organization_id = binding.organization_id
       AND scope.source_scope_id = binding.source_scope_id
       AND scope.revision = binding.source_scope_revision
     WHERE binding.organization_id = app.current_organization_id()
       AND binding.workspace_id = p_workspace_id
       AND binding.workspace_revision = w.current_revision
       AND binding.source_scope_id = p_source_scope_id
       AND binding.source_scope_revision = p_source_scope_revision
       AND binding.enabled;
$$;

REVOKE ALL ON FUNCTION app.question_corpus_content_freshness_sla(text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_corpus_content_freshness_sla(text, text, bigint) TO knowvault_app;

COMMIT;
