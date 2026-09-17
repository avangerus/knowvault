-- ADR-0089 (governed model-authored SQL over an operator-exposed schema).
--
-- Minimal, self-contained registration for the V1-D slice: since the V1-A
-- full POSTGRESQL_QUERY registration/capability-profile path is not yet
-- merged onto this branch, this migration adds its own narrow connection
-- record for the dedicated governed-execution database role (distinct code
-- path from ADR-0078's ingestion connection, per ADR-0089 §3) plus the
-- exposed-schema artifact ADR-0089 §1 describes: an immutable, versioned,
-- operator-narrowed subset of what that dedicated role's own
-- information_schema already shows, each object/column carrying an
-- operator-written description. Widening exposure never widens the role's
-- own database grants -- that happens only at the external PostgreSQL server,
-- out of band from this control-plane record.

BEGIN;

CREATE TABLE public.governed_query_connection (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    workspace_id text NOT NULL,
    database_identity text NOT NULL CHECK (
        char_length(database_identity) BETWEEN 1 AND 128
        AND btrim(database_identity) = database_identity
        AND database_identity !~ '[[:cntrl:]]'
    ),
    -- Live queries are opt-in and default OFF (ADR-0089 §6 / owner decision
    -- 10): an operator must explicitly enable them per connection.
    live_queries_enabled boolean NOT NULL DEFAULT false,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT governed_query_connection_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_connection_created_by_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_connection_updated_by_fk
        FOREIGN KEY (organization_id, updated_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

-- Only the live-queries flag (and its own bookkeeping columns) may ever
-- change after creation; every other column is set once at registration.
CREATE OR REPLACE FUNCTION app.governed_query_connection_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'governed_query_connection rows cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.database_identity IS DISTINCT FROM OLD.database_identity
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'governed_query_connection identity fields are immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER governed_query_connection_immutable
BEFORE UPDATE OR DELETE ON public.governed_query_connection
FOR EACH ROW EXECUTE FUNCTION app.governed_query_connection_guard();

ALTER TABLE public.governed_query_connection ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governed_query_connection FORCE ROW LEVEL SECURITY;
CREATE POLICY governed_query_connection_tenant_isolation ON public.governed_query_connection
    USING (organization_id = app.current_organization_id());

CREATE TABLE public.governed_query_exposed_schema (
    organization_id text NOT NULL,
    connection_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    -- objects_json is the closed, operator-narrowed object/column inventory:
    -- an array of {schema_name, table_name, description, columns:
    -- [{name, data_type, description, unit}]}. It is application-validated
    -- (governedquery.ExposedSchema.Validate) before insert; this column is
    -- immutable and append-only per revision, exactly like an ADR-0078
    -- projection contract.
    objects_json jsonb NOT NULL CHECK (jsonb_typeof(objects_json) = 'array' AND jsonb_array_length(objects_json) > 0),
    revision_hash text NOT NULL CHECK (revision_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, connection_id, revision),
    CONSTRAINT governed_query_exposed_schema_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.governed_query_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_exposed_schema_created_by_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    UNIQUE (organization_id, connection_id, revision_hash)
);

CREATE OR REPLACE FUNCTION app.governed_query_exposed_schema_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'governed_query_exposed_schema is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER governed_query_exposed_schema_immutable
BEFORE UPDATE OR DELETE ON public.governed_query_exposed_schema
FOR EACH ROW EXECUTE FUNCTION app.governed_query_exposed_schema_guard();

ALTER TABLE public.governed_query_exposed_schema ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governed_query_exposed_schema FORCE ROW LEVEL SECURITY;
CREATE POLICY governed_query_exposed_schema_tenant_isolation ON public.governed_query_exposed_schema
    USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.governed_query_connection, public.governed_query_exposed_schema FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON public.governed_query_connection TO knowvault_app;
GRANT SELECT, INSERT ON public.governed_query_exposed_schema TO knowvault_app;

COMMIT;
