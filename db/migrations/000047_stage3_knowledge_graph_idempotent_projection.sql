-- 000047: make the worker's canonical graph projection replay-safe.
--
-- Graph tables intentionally expose no broad SELECT policy to knowvault_worker;
-- the worker receives only the current tenant's narrow projector capability.
-- A SECURITY DEFINER function performs the unique-key upsert and returns the
-- winning entity id, so a crash replay cannot mistake an RLS-hidden row for a
-- new entity or weaken the immutable unique constraint.

BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_entity_upsert(
    p_workspace_id text,
    p_workspace_revision bigint,
    p_source_scope_id text,
    p_source_scope_revision bigint,
    p_entity_id text,
    p_entity_type text,
    p_canonical_key_hash text,
    p_display_name_hash text,
    p_source_object_id text,
    p_source_version_id text,
    p_evidence_fragment_id text,
    p_observed_at timestamptz,
    p_freshness_at timestamptz,
    p_attributes_json jsonb
)
RETURNS TABLE(entity_id text, inserted boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text := app.current_organization_id();
BEGIN
    IF session_user <> 'knowvault_worker' OR organization_value IS NULL THEN
        RAISE EXCEPTION 'knowledge graph entity projection requires worker tenant context'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.canonical_entity (
        organization_id, workspace_id, workspace_revision, source_scope_id,
        source_scope_revision, id, entity_type, canonical_key_hash,
        display_name_hash, source_object_id, source_version_id,
        evidence_fragment_id, observed_at, freshness_at, attributes_json
    ) VALUES (
        organization_value, p_workspace_id, p_workspace_revision, p_source_scope_id,
        p_source_scope_revision, p_entity_id, p_entity_type, p_canonical_key_hash,
        NULLIF(p_display_name_hash, ''), p_source_object_id, p_source_version_id,
        p_evidence_fragment_id, p_observed_at, p_freshness_at, p_attributes_json
    )
    ON CONFLICT (organization_id, workspace_id, canonical_key_hash, entity_type,
                 source_version_id, evidence_fragment_id) DO NOTHING;

    SELECT entity.id
      INTO entity_id
      FROM public.canonical_entity AS entity
     WHERE entity.organization_id = organization_value
       AND entity.workspace_id = p_workspace_id
       AND entity.canonical_key_hash = p_canonical_key_hash
       AND entity.entity_type = p_entity_type
       AND entity.source_version_id = p_source_version_id
       AND entity.evidence_fragment_id = p_evidence_fragment_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'knowledge graph entity projection did not resolve its unique identity'
            USING ERRCODE = '23514';
    END IF;
    inserted := entity_id = p_entity_id;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION app.knowledge_graph_entity_upsert(
    text, bigint, text, bigint, text, text, text, text, text, text, text,
    timestamptz, timestamptz, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.knowledge_graph_entity_upsert(
    text, bigint, text, bigint, text, text, text, text, text, text, text,
    timestamptz, timestamptz, jsonb
) TO knowvault_worker;

COMMIT;
