-- Stage 3 knowledge graph visibility hardening.
--
-- Graph rows are derived, but they remain tenant data.  A source membership
-- revoke, version purge, extraction purge, or row lifecycle transition must
-- hide them immediately through the same app-facing RLS predicate.  The
-- predicate intentionally receives the row's immutable provenance so callers
-- cannot bypass retention by selecting a different source object.

BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_row_visible(
    p_organization_id text,
    p_workspace_id text,
    p_source_scope_id text,
    p_source_scope_revision bigint,
    p_source_object_id text,
    p_source_version_id text,
    p_evidence_fragment_id text,
    p_lifecycle_state text,
    p_queryable boolean
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT p_organization_id = app.current_organization_id()
       AND p_lifecycle_state = 'ACTIVE'
       AND p_queryable
       AND EXISTS (
            SELECT 1 FROM public.workspace w
             JOIN public.workspace_member member
               ON member.organization_id = w.organization_id
              AND member.workspace_id = w.id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
            WHERE w.organization_id = p_organization_id
              AND w.id = p_workspace_id
              AND w.status IN ('ACTIVE', 'READ_ONLY')
       )
       AND EXISTS (
            SELECT 1 FROM public.workspace w
             JOIN public.workspace_revision_source binding
               ON binding.organization_id = w.organization_id
              AND binding.workspace_id = w.id
              AND binding.workspace_revision = w.current_revision
              AND binding.source_scope_id = p_source_scope_id
              AND binding.source_scope_revision = p_source_scope_revision
              AND binding.enabled
            WHERE w.organization_id = p_organization_id AND w.id = p_workspace_id
       )
       AND EXISTS (
            SELECT 1 FROM public.source_object_scope membership
             WHERE membership.organization_id = p_organization_id
               AND membership.source_object_id = p_source_object_id
               AND membership.source_scope_id = p_source_scope_id
               AND membership.source_scope_revision = p_source_scope_revision
               AND membership.membership_state = 'ACTIVE'
       )
       AND EXISTS (
            SELECT 1 FROM public.source_version version
             JOIN public.source_version_retention retention
               ON retention.organization_id = version.organization_id
              AND retention.source_version_id = version.id
            WHERE version.organization_id = p_organization_id
              AND version.id = p_source_version_id
              AND version.source_object_id = p_source_object_id
              AND version.state IN ('PENDING', 'CURRENT', 'SUPERSEDED')
              AND retention.state = 'ACTIVE'
              AND retention.queryable
              AND retention.extraction_allowed
       )
       AND EXISTS (
            SELECT 1 FROM public.evidence_fragment fragment
             JOIN public.source_extraction_retention extraction_retention
               ON extraction_retention.organization_id = fragment.organization_id
              AND extraction_retention.extraction_id = fragment.extraction_id
            WHERE fragment.organization_id = p_organization_id
              AND fragment.id = p_evidence_fragment_id
              AND fragment.source_version_id = p_source_version_id
              AND extraction_retention.state = 'ACTIVE'
              AND extraction_retention.queryable
       );
$$;

ALTER POLICY canonical_entity_app_read ON public.canonical_entity
    USING (app.knowledge_graph_row_visible(
        organization_id, workspace_id, source_scope_id,
        source_scope_revision, source_object_id, source_version_id,
        evidence_fragment_id, lifecycle_state, queryable));
ALTER POLICY entity_relation_app_read ON public.entity_relation
    USING (app.knowledge_graph_row_visible(
        organization_id, workspace_id, source_scope_id,
        source_scope_revision, source_object_id, source_version_id,
        evidence_fragment_id, lifecycle_state, queryable));
ALTER POLICY semantic_term_app_read ON public.semantic_term
    USING (app.knowledge_graph_row_visible(
        organization_id, workspace_id, source_scope_id,
        source_scope_revision, source_object_id, source_version_id,
        evidence_fragment_id, lifecycle_state, queryable));

DROP FUNCTION app.knowledge_graph_row_visible(text, text, text, bigint, text);
GRANT EXECUTE ON FUNCTION app.knowledge_graph_row_visible(
    text, text, text, bigint, text, text, text, text, boolean
) TO knowvault_app, knowvault_worker, knowvault_purger;

COMMIT;
