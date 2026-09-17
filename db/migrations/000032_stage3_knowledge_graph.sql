-- Stage 3 enterprise knowledge graph contract.
--
-- The source catalog remains the authority for bytes and Evidence.  This
-- migration adds the durable, workspace-scoped semantic layer that links
-- documents, mail, Git/code and SQL business objects through versioned
-- provenance.  Every graph row is tied to one concrete Evidence fragment;
-- there is no ungrounded entity, relation or term.  Labels are represented by
-- hashes (the source text stays behind the encrypted Evidence owner branch).
--
-- The graph is deliberately append-first.  Only lifecycle/queryability,
-- freshness and the monotonic retention fence can move after insert.  The
-- visibility policy checks the current workspace source projection, so source
-- removal or membership revocation hides graph rows immediately even before a
-- background reindex has caught up.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'runtime role knowvault_app must exist before this migration';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_worker') THEN
        RAISE EXCEPTION 'worker role knowvault_worker must exist before this migration';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_purger') THEN
        RAISE EXCEPTION 'purger role knowvault_purger must exist before this migration';
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Shape validators
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.knowledge_graph_id_is_valid(value text, prefix_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND prefix_value IN ('entity', 'relation', 'term')
       AND value ~ ('^' || prefix_value || '_[0-7][0-9A-HJKMNP-TV-Z]{25}$');
$$;

CREATE OR REPLACE FUNCTION app.knowledge_graph_predicate_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL AND value ~ '^[a-z][a-z0-9_.:-]{1,127}$';
$$;

CREATE OR REPLACE FUNCTION app.knowledge_graph_attributes_are_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND jsonb_typeof(value) = 'object'
       AND octet_length(value::text) BETWEEN 2 AND 65536;
$$;

-- ---------------------------------------------------------------------------
-- Canonical entities
-- ---------------------------------------------------------------------------

CREATE TABLE public.canonical_entity (
    organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    id text NOT NULL CHECK (app.knowledge_graph_id_is_valid(id, 'entity')),
    entity_type text NOT NULL CHECK (entity_type IN (
        'DOCUMENT', 'EMAIL', 'GIT_COMMIT', 'CODE_SYMBOL', 'SQL_BUSINESS_OBJECT',
        'PERSON', 'PROCESS', 'CONTROL', 'TERM', 'OTHER')),
    canonical_key_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(canonical_key_hash)),
    display_name_hash text CHECK (display_name_hash IS NULL OR app.stage2_sha256_is_valid(display_name_hash)),
    source_object_id text NOT NULL,
    source_version_id text NOT NULL,
    evidence_fragment_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    freshness_at timestamptz NOT NULL,
    lifecycle_state text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_state IN ('ACTIVE', 'REVOKED', 'RETIRED')),
    queryable boolean NOT NULL DEFAULT true,
    retention_fence bigint NOT NULL DEFAULT 0 CHECK (retention_fence >= 0),
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (app.knowledge_graph_attributes_are_valid(attributes_json)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT canonical_entity_workspace_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision) ON DELETE RESTRICT,
    CONSTRAINT canonical_entity_scope_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision) ON DELETE RESTRICT,
    CONSTRAINT canonical_entity_membership_fk
        FOREIGN KEY (organization_id, source_object_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_object_scope (organization_id, source_object_id, source_scope_id, source_scope_revision)
        ON DELETE RESTRICT,
    CONSTRAINT canonical_entity_version_fk
        FOREIGN KEY (organization_id, source_object_id, source_version_id)
        REFERENCES public.source_version (organization_id, source_object_id, id) ON DELETE RESTRICT,
    CONSTRAINT canonical_entity_evidence_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT,
    UNIQUE (organization_id, workspace_id, canonical_key_hash, entity_type, source_version_id, evidence_fragment_id)
);

CREATE INDEX canonical_entity_workspace_lookup
    ON public.canonical_entity (organization_id, workspace_id, entity_type, canonical_key_hash);

-- ---------------------------------------------------------------------------
-- Versioned, Evidence-backed relations
-- ---------------------------------------------------------------------------

CREATE TABLE public.entity_relation (
    organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    id text NOT NULL CHECK (app.knowledge_graph_id_is_valid(id, 'relation')),
    subject_entity_id text NOT NULL,
    predicate text NOT NULL CHECK (app.knowledge_graph_predicate_is_valid(predicate)),
    object_entity_id text NOT NULL,
    source_object_id text NOT NULL,
    source_version_id text NOT NULL,
    evidence_fragment_id text NOT NULL,
    confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    observed_at timestamptz NOT NULL,
    freshness_at timestamptz NOT NULL,
    lifecycle_state text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_state IN ('ACTIVE', 'REVOKED', 'RETIRED')),
    queryable boolean NOT NULL DEFAULT true,
    retention_fence bigint NOT NULL DEFAULT 0 CHECK (retention_fence >= 0),
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (app.knowledge_graph_attributes_are_valid(attributes_json)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT entity_relation_workspace_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision) ON DELETE RESTRICT,
    CONSTRAINT entity_relation_scope_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision) ON DELETE RESTRICT,
    CONSTRAINT entity_relation_membership_fk
        FOREIGN KEY (organization_id, source_object_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_object_scope (organization_id, source_object_id, source_scope_id, source_scope_revision)
        ON DELETE RESTRICT,
    CONSTRAINT entity_relation_version_fk
        FOREIGN KEY (organization_id, source_object_id, source_version_id)
        REFERENCES public.source_version (organization_id, source_object_id, id) ON DELETE RESTRICT,
    CONSTRAINT entity_relation_evidence_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT entity_relation_subject_fk
        FOREIGN KEY (organization_id, subject_entity_id)
        REFERENCES public.canonical_entity (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT entity_relation_object_fk
        FOREIGN KEY (organization_id, object_entity_id)
        REFERENCES public.canonical_entity (organization_id, id) ON DELETE RESTRICT,
    CHECK (subject_entity_id <> object_entity_id OR predicate LIKE 'self.%'),
    UNIQUE (organization_id, workspace_id, subject_entity_id, predicate, object_entity_id,
            source_version_id, evidence_fragment_id)
);

CREATE INDEX entity_relation_traversal_lookup
    ON public.entity_relation (organization_id, workspace_id, subject_entity_id, predicate, object_entity_id);

-- ---------------------------------------------------------------------------
-- Semantic catalog / ontology terms
-- ---------------------------------------------------------------------------

CREATE TABLE public.semantic_term (
    organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    id text NOT NULL CHECK (app.knowledge_graph_id_is_valid(id, 'term')),
    canonical_entity_id text NOT NULL,
    term_kind text NOT NULL CHECK (term_kind IN ('CANONICAL', 'SYNONYM', 'ABBREVIATION', 'CONTEXT')),
    language text NOT NULL CHECK (language ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$'),
    term_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(term_hash)),
    context_hash text CHECK (context_hash IS NULL OR app.stage2_sha256_is_valid(context_hash)),
    source_object_id text NOT NULL,
    source_version_id text NOT NULL,
    evidence_fragment_id text NOT NULL,
    confidence double precision NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    observed_at timestamptz NOT NULL,
    freshness_at timestamptz NOT NULL,
    lifecycle_state text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_state IN ('ACTIVE', 'REVOKED', 'RETIRED')),
    queryable boolean NOT NULL DEFAULT true,
    retention_fence bigint NOT NULL DEFAULT 0 CHECK (retention_fence >= 0),
    attributes_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (app.knowledge_graph_attributes_are_valid(attributes_json)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT semantic_term_workspace_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision) ON DELETE RESTRICT,
    CONSTRAINT semantic_term_scope_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision) ON DELETE RESTRICT,
    CONSTRAINT semantic_term_membership_fk
        FOREIGN KEY (organization_id, source_object_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_object_scope (organization_id, source_object_id, source_scope_id, source_scope_revision)
        ON DELETE RESTRICT,
    CONSTRAINT semantic_term_version_fk
        FOREIGN KEY (organization_id, source_object_id, source_version_id)
        REFERENCES public.source_version (organization_id, source_object_id, id) ON DELETE RESTRICT,
    CONSTRAINT semantic_term_evidence_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT semantic_term_entity_fk
        FOREIGN KEY (organization_id, canonical_entity_id)
        REFERENCES public.canonical_entity (organization_id, id) ON DELETE RESTRICT,
    UNIQUE (organization_id, workspace_id, canonical_entity_id, term_kind, language, term_hash,
            source_version_id, evidence_fragment_id)
);

CREATE INDEX semantic_term_lookup
    ON public.semantic_term (organization_id, workspace_id, language, term_hash, term_kind);

-- ---------------------------------------------------------------------------
-- Provenance and visibility guards
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.knowledge_graph_provenance_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    source_object text;
    source_scope text;
    source_scope_revision bigint;
    source_version text;
    evidence text;
    workspace_revision bigint;
    workspace_id text;
    evidence_version text;
    evidence_extraction_id text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user IN ('knowvault_app', 'knowvault_worker')
           OR (session_user <> 'knowvault_purger' AND NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED'))) THEN
            RAISE EXCEPTION '% deletion requires tenant hard-delete state', TG_TABLE_NAME USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'INSERT' THEN
        -- The workspace source snapshot is the authorization root.  A graph
        -- row cannot be inserted for a scope that was not enabled in the
        -- captured workspace revision.
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

    -- Content identity, source lineage and workspace placement never change.
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

CREATE OR REPLACE FUNCTION app.knowledge_graph_row_visible(
    p_organization_id text, p_workspace_id text, p_source_scope_id text,
    p_source_scope_revision bigint, p_source_object_id text
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT p_organization_id = app.current_organization_id()
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
       );
$$;

CREATE TRIGGER canonical_entity_provenance_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.canonical_entity
    FOR EACH ROW EXECUTE FUNCTION app.knowledge_graph_provenance_guard();
CREATE TRIGGER entity_relation_provenance_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.entity_relation
    FOR EACH ROW EXECUTE FUNCTION app.knowledge_graph_provenance_guard();
CREATE TRIGGER semantic_term_provenance_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.semantic_term
    FOR EACH ROW EXECUTE FUNCTION app.knowledge_graph_provenance_guard();

-- ---------------------------------------------------------------------------
-- RLS and grants
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['canonical_entity', 'entity_relation', 'semantic_term'] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR SELECT TO knowvault_app USING (app.knowledge_graph_row_visible(organization_id, workspace_id, source_scope_id, source_scope_revision, source_object_id))', tbl || '_app_read', tbl);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR INSERT TO knowvault_worker WITH CHECK (organization_id = app.current_organization_id())', tbl || '_worker_insert', tbl);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR UPDATE TO knowvault_worker USING (organization_id = app.current_organization_id()) WITH CHECK (organization_id = app.current_organization_id())', tbl || '_worker_update', tbl);
        EXECUTE format('CREATE POLICY %I ON public.%I FOR DELETE TO knowvault_purger USING (organization_id = app.current_organization_id())', tbl || '_purger_delete', tbl);
    END LOOP;
END;
$$;

REVOKE ALL ON TABLE public.canonical_entity, public.entity_relation, public.semantic_term FROM PUBLIC;
GRANT SELECT ON TABLE public.canonical_entity, public.entity_relation, public.semantic_term TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.canonical_entity, public.entity_relation, public.semantic_term TO knowvault_worker;
GRANT SELECT, DELETE ON TABLE public.canonical_entity, public.entity_relation, public.semantic_term TO knowvault_purger;
GRANT EXECUTE ON FUNCTION app.knowledge_graph_id_is_valid(text, text), app.knowledge_graph_predicate_is_valid(text), app.knowledge_graph_attributes_are_valid(jsonb), app.knowledge_graph_row_visible(text, text, text, bigint, text) TO knowvault_app, knowvault_worker, knowvault_purger;

COMMIT;
