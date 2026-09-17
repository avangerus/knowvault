-- Stage 3 graph projector read surface.
--
-- Runtime workers need to materialize one graph projection for every current
-- workspace that enables a source revision. Those workspace tables are
-- FORCE-RLS and their normal policies intentionally depend on a principal;
-- a worker has no user principal. This narrow SECURITY DEFINER function is a
-- tenant-bound read authority for that exact projection target, not a general
-- workspace query or mutation surface.

BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_projection_targets(
    p_source_scope_id text, p_source_scope_revision bigint
)
RETURNS TABLE(workspace_id text, workspace_revision bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT workspace.id, workspace.current_revision
      FROM public.workspace AS workspace
      JOIN public.workspace_revision_source AS binding
        ON binding.organization_id = workspace.organization_id
       AND binding.workspace_id = workspace.id
       AND binding.workspace_revision = workspace.current_revision
     WHERE workspace.organization_id = app.current_organization_id()
       AND workspace.status IN ('ACTIVE', 'READ_ONLY')
       AND binding.source_scope_id = p_source_scope_id
       AND binding.source_scope_revision = p_source_scope_revision
       AND binding.enabled
     ORDER BY workspace.id;
$$;

REVOKE ALL ON FUNCTION app.knowledge_graph_projection_targets(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.knowledge_graph_projection_targets(text, bigint) TO knowvault_worker;

COMMIT;

