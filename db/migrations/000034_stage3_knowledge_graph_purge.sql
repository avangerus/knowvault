-- Stage 3 knowledge graph purge propagation.
--
-- RLS hides graph rows as soon as retention enters PURGING.  Once the
-- privileged source-version state machine commits PURGED, the derived graph is
-- physically removed as part of that same transaction; there is no orphaned
-- semantic identity left behind for a future reindex or hash oracle.

BEGIN;

CREATE OR REPLACE FUNCTION app.knowledge_graph_purge_after_retention()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.state = 'PURGED' AND OLD.state IS DISTINCT FROM 'PURGED' THEN
        IF session_user <> 'knowvault_purger' THEN
            RAISE EXCEPTION 'knowledge graph purge requires the purger role' USING ERRCODE = '42501';
        END IF;
        DELETE FROM public.entity_relation
         WHERE organization_id = NEW.organization_id
           AND source_version_id = NEW.source_version_id;
        DELETE FROM public.semantic_term
         WHERE organization_id = NEW.organization_id
           AND source_version_id = NEW.source_version_id;
        DELETE FROM public.canonical_entity
         WHERE organization_id = NEW.organization_id
           AND source_version_id = NEW.source_version_id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS knowledge_graph_retention_purge ON public.source_version_retention;
CREATE TRIGGER knowledge_graph_retention_purge
    AFTER UPDATE OF state ON public.source_version_retention
    FOR EACH ROW EXECUTE FUNCTION app.knowledge_graph_purge_after_retention();

REVOKE ALL ON FUNCTION app.knowledge_graph_purge_after_retention() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.knowledge_graph_purge_after_retention() TO knowvault_purger;

COMMIT;
