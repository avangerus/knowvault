-- Stage 3 graph relation projector read surface.
--
-- The ingestion worker may need to discover an already projected entity that
-- shares an explicitly asserted catalog term.  Graph tables stay FORCE-RLS
-- with no broad worker SELECT policy; this function exposes only a bounded,
-- tenant-bound, same-workspace target list for that one projection step.

BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_shared_term_targets(
    p_workspace_id text, p_entity_id text, p_term_hash text
)
RETURNS TABLE(canonical_entity_id text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT term.canonical_entity_id
      FROM public.semantic_term AS term
      JOIN public.canonical_entity AS entity
        ON entity.organization_id = term.organization_id
       AND entity.id = term.canonical_entity_id
       AND entity.workspace_id = term.workspace_id
     WHERE term.organization_id = app.current_organization_id()
       AND term.workspace_id = p_workspace_id
       AND term.canonical_entity_id <> p_entity_id
       AND term.term_hash = p_term_hash
       AND term.term_kind IN ('CANONICAL','SYNONYM','ABBREVIATION')
       AND term.lifecycle_state = 'ACTIVE'
       AND term.queryable
       AND entity.lifecycle_state = 'ACTIVE'
       AND entity.queryable
     GROUP BY term.canonical_entity_id
     ORDER BY term.canonical_entity_id
     LIMIT 8;
$$;

REVOKE ALL ON FUNCTION app.knowledge_graph_shared_term_targets(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.knowledge_graph_shared_term_targets(text, text, text) TO knowvault_worker;

COMMIT;
