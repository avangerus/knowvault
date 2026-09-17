-- Stage 3 / P2: relation visibility must include both canonical endpoints.
--
-- The relation policy already proves the edge's own source provenance.  This
-- migration keeps that proof and adds the two endpoint visibility proofs so
-- a relation cannot outlive either canonical entity's authorization chain.
BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_relation_visible(
    p_organization_id text,
    p_workspace_id text,
    p_source_scope_id text,
    p_source_scope_revision bigint,
    p_source_object_id text,
    p_source_version_id text,
    p_evidence_fragment_id text,
    p_lifecycle_state text,
    p_queryable boolean,
    p_subject_entity_id text,
    p_object_entity_id text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
    SELECT app.knowledge_graph_row_visible(
               p_organization_id, p_workspace_id, p_source_scope_id,
               p_source_scope_revision, p_source_object_id,
               p_source_version_id, p_evidence_fragment_id,
               p_lifecycle_state, p_queryable)
       AND EXISTS (
            SELECT 1
              FROM public.canonical_entity endpoint
             WHERE endpoint.organization_id = p_organization_id
               AND endpoint.workspace_id = p_workspace_id
               AND endpoint.id = p_subject_entity_id
               AND app.knowledge_graph_row_visible(
                   endpoint.organization_id, endpoint.workspace_id,
                   endpoint.source_scope_id, endpoint.source_scope_revision,
                   endpoint.source_object_id, endpoint.source_version_id,
                   endpoint.evidence_fragment_id, endpoint.lifecycle_state,
                   endpoint.queryable)
       )
       AND EXISTS (
            SELECT 1
              FROM public.canonical_entity endpoint
             WHERE endpoint.organization_id = p_organization_id
               AND endpoint.workspace_id = p_workspace_id
               AND endpoint.id = p_object_entity_id
               AND app.knowledge_graph_row_visible(
                   endpoint.organization_id, endpoint.workspace_id,
                   endpoint.source_scope_id, endpoint.source_scope_revision,
                   endpoint.source_object_id, endpoint.source_version_id,
                   endpoint.evidence_fragment_id, endpoint.lifecycle_state,
                   endpoint.queryable)
       );
$$;

ALTER POLICY entity_relation_app_read ON public.entity_relation
    USING (app.knowledge_graph_relation_visible(
        organization_id, workspace_id, source_scope_id,
        source_scope_revision, source_object_id, source_version_id,
        evidence_fragment_id, lifecycle_state, queryable,
        subject_entity_id, object_entity_id));

REVOKE ALL ON FUNCTION app.knowledge_graph_relation_visible(
    text, text, text, bigint, text, text, text, text, boolean, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.knowledge_graph_relation_visible(
    text, text, text, bigint, text, text, text, text, boolean, text, text
) TO knowvault_app, knowvault_worker, knowvault_purger;

COMMIT;
