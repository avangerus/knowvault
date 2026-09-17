-- Stage 3 graph purge role correction.
--
-- 000032 originally allowed graph DELETE only during tenant hard-delete. The
-- source-version purge is a separate, per-version lifecycle and is executed
-- by knowvault_purger; keep that narrow role able to remove its own derived
-- rows while retaining the hard-delete requirement for every other caller.

BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_provenance_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    source_object text;
    source_version text;
    evidence_version text;
    evidence_extraction_id text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user IN ('knowvault_app', 'knowvault_worker')
           OR (session_user <> 'knowvault_purger' AND NOT EXISTS (
                SELECT 1 FROM public.organization
                 WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED'))) THEN
            RAISE EXCEPTION '% deletion requires tenant hard-delete state', TG_TABLE_NAME USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.workspace_revision_source binding
             WHERE binding.organization_id = NEW.organization_id
               AND binding.workspace_id = NEW.workspace_id
               AND binding.workspace_revision = NEW.workspace_revision
               AND binding.source_scope_id = NEW.source_scope_id
               AND binding.source_scope_revision = NEW.source_scope_revision
               AND binding.enabled
        ) THEN
            RAISE EXCEPTION 'knowledge graph provenance lacks enabled workspace source binding' USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM public.source_object_scope membership
             WHERE membership.organization_id = NEW.organization_id
               AND membership.source_object_id = NEW.source_object_id
               AND membership.source_scope_id = NEW.source_scope_id
               AND membership.source_scope_revision = NEW.source_scope_revision
               AND membership.membership_state = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION 'knowledge graph provenance lacks active source membership' USING ERRCODE = '23514';
        END IF;
        SELECT v.id, v.source_object_id INTO source_version, source_object
          FROM public.source_version v
         WHERE v.organization_id = NEW.organization_id
           AND v.id = NEW.source_version_id
           AND v.source_object_id = NEW.source_object_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'knowledge graph provenance version does not belong to object' USING ERRCODE = '23514';
        END IF;
        SELECT f.source_version_id, f.extraction_id INTO evidence_version, evidence_extraction_id
          FROM public.evidence_fragment f
         WHERE f.organization_id = NEW.organization_id AND f.id = NEW.evidence_fragment_id;
        IF NOT FOUND OR evidence_version <> NEW.source_version_id THEN
            RAISE EXCEPTION 'knowledge graph provenance evidence does not belong to version' USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM public.source_version_retention vr
             WHERE vr.organization_id = NEW.organization_id
               AND vr.source_version_id = NEW.source_version_id
               AND vr.state = 'ACTIVE' AND vr.queryable
        ) OR NOT EXISTS (
            SELECT 1 FROM public.source_extraction_retention er
             WHERE er.organization_id = NEW.organization_id
               AND er.extraction_id = evidence_extraction_id
               AND er.state = 'ACTIVE' AND er.queryable
        ) THEN
            RAISE EXCEPTION 'knowledge graph provenance requires active queryable retention' USING ERRCODE = '23514';
        END IF;
        IF NEW.lifecycle_state <> 'ACTIVE' OR NOT NEW.queryable THEN
            RAISE EXCEPTION 'knowledge graph rows must start ACTIVE and queryable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision
       OR NEW.source_scope_id IS DISTINCT FROM OLD.source_scope_id
       OR NEW.source_scope_revision IS DISTINCT FROM OLD.source_scope_revision
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.evidence_fragment_id IS DISTINCT FROM OLD.evidence_fragment_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION '% provenance identity is immutable', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF TG_TABLE_NAME = 'canonical_entity' AND (
           NEW.entity_type IS DISTINCT FROM OLD.entity_type
        OR NEW.canonical_key_hash IS DISTINCT FROM OLD.canonical_key_hash
        OR NEW.display_name_hash IS DISTINCT FROM OLD.display_name_hash
        OR NEW.attributes_json IS DISTINCT FROM OLD.attributes_json
    ) THEN
        RAISE EXCEPTION 'canonical_entity semantic identity is immutable' USING ERRCODE = '55000';
    ELSIF TG_TABLE_NAME = 'entity_relation' AND (
           NEW.subject_entity_id IS DISTINCT FROM OLD.subject_entity_id
        OR NEW.predicate IS DISTINCT FROM OLD.predicate
        OR NEW.object_entity_id IS DISTINCT FROM OLD.object_entity_id
        OR NEW.confidence IS DISTINCT FROM OLD.confidence
        OR NEW.attributes_json IS DISTINCT FROM OLD.attributes_json
    ) THEN
        RAISE EXCEPTION 'entity_relation semantic identity is immutable' USING ERRCODE = '55000';
    ELSIF TG_TABLE_NAME = 'semantic_term' AND (
           NEW.canonical_entity_id IS DISTINCT FROM OLD.canonical_entity_id
        OR NEW.term_kind IS DISTINCT FROM OLD.term_kind
        OR NEW.language IS DISTINCT FROM OLD.language
        OR NEW.term_hash IS DISTINCT FROM OLD.term_hash
        OR NEW.context_hash IS DISTINCT FROM OLD.context_hash
        OR NEW.confidence IS DISTINCT FROM OLD.confidence
        OR NEW.attributes_json IS DISTINCT FROM OLD.attributes_json
    ) THEN
        RAISE EXCEPTION 'semantic_term identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.lifecycle_state = 'RETIRED' AND NEW.lifecycle_state <> 'RETIRED' THEN
        RAISE EXCEPTION '% lifecycle cannot be resurrected', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF OLD.lifecycle_state = 'REVOKED' AND NEW.lifecycle_state = 'ACTIVE' THEN
        RAISE EXCEPTION '% lifecycle cannot be resurrected', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF NEW.retention_fence < OLD.retention_fence THEN
        RAISE EXCEPTION '% retention fence never decreases', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF NEW.lifecycle_state <> 'ACTIVE' AND NEW.queryable THEN
        RAISE EXCEPTION '% non-active rows cannot be queryable', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
