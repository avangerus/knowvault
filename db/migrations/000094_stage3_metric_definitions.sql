-- R2 Outcome 1 (POSITION.md section 3 "Semantics"): the durable, tenant-scoped
-- catalog of workspace MetricDefinition versions.
--
-- A definition belongs to exactly one workspace. It carries the product fields
-- the definition contract publishes (name, pinned source connection +
-- projection version, entity key, period grain, allowed filters, unit) plus a
-- monotonic version and a closed DRAFT | APPROVED | RETIRED status. Only the
-- workspace owner approves a version through the audited boundary, and an
-- APPROVED version is immutable: editing it is a new version, never an in-place
-- update. Identity is (organization_id, workspace_id, id) so one workspace's
-- definition can never collide with or read another's.
--
-- The tables are additive, tenant-isolated with forced row level security and
-- carry organization_id so the dynamic TEN-001 catalog check holds without
-- touching any other migration. DELETE is not granted: retirement is an
-- explicit state, not a row removal.

BEGIN;

CREATE TABLE public.metric_definition (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    id text NOT NULL CHECK (char_length(id) BETWEEN 1 AND 256),
    owner_principal_id text NOT NULL,
    current_version bigint NOT NULL CHECK (current_version BETWEEN 1 AND 9007199254740991),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, id),
    CONSTRAINT metric_definition_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT metric_definition_owner_fk
        FOREIGN KEY (organization_id, owner_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT metric_definition_creator_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE public.metric_definition_version (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    definition_id text NOT NULL,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    status text NOT NULL CHECK (status IN ('DRAFT', 'APPROVED', 'RETIRED')),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    source_connection_id text NOT NULL CHECK (char_length(source_connection_id) BETWEEN 1 AND 256),
    projection_version bigint NOT NULL CHECK (projection_version BETWEEN 1 AND 9007199254740991),
    entity_key text NOT NULL CHECK (char_length(entity_key) BETWEEN 1 AND 256),
    grain text NOT NULL CHECK (grain IN ('DAY', 'WEEK', 'MONTH', 'QUARTER', 'YEAR')),
    allowed_filters text[] NOT NULL DEFAULT ARRAY[]::text[],
    unit text NOT NULL DEFAULT '' CHECK (char_length(unit) <= 64),
    owner_principal_id text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    approved_by text,
    approved_at timestamptz,
    PRIMARY KEY (organization_id, workspace_id, definition_id, version),
    CONSTRAINT metric_definition_version_definition_fk
        FOREIGN KEY (organization_id, workspace_id, definition_id)
        REFERENCES public.metric_definition (organization_id, workspace_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT metric_definition_version_status_consistent CHECK (
        status <> 'APPROVED' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)
    )
);

CREATE INDEX metric_definition_version_workspace
    ON public.metric_definition_version (organization_id, workspace_id, definition_id, version);

-- A version is append-only and an APPROVED/RETIRED row can never change again.
-- The only update the product allows is a DRAFT edit in place and the one-way
-- DRAFT -> APPROVED transition; identity columns are frozen for every row.
CREATE OR REPLACE FUNCTION app.metric_definition_version_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'metric definition versions are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.status IN ('APPROVED', 'RETIRED') THEN
        RAISE EXCEPTION 'an approved metric definition version is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.workspace_id <> OLD.workspace_id
       OR NEW.definition_id <> OLD.definition_id
       OR NEW.version <> OLD.version
       OR NEW.owner_principal_id <> OLD.owner_principal_id
       OR NEW.created_by <> OLD.created_by
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'metric definition version identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER metric_definition_version_immutable
BEFORE UPDATE OR DELETE ON public.metric_definition_version
FOR EACH ROW EXECUTE FUNCTION app.metric_definition_version_guard();

-- The version pointer of a definition id can only move forward: a persisted
-- transition can never lower, reuse or rewrite the issued history.
CREATE OR REPLACE FUNCTION app.metric_definition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'metric definitions are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.current_version < OLD.current_version THEN
        RAISE EXCEPTION 'metric definition versions are monotonic'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.workspace_id <> OLD.workspace_id
       OR NEW.id <> OLD.id
       OR NEW.owner_principal_id <> OLD.owner_principal_id
       OR NEW.created_by <> OLD.created_by
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'metric definition identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER metric_definition_immutable
BEFORE UPDATE OR DELETE ON public.metric_definition
FOR EACH ROW EXECUTE FUNCTION app.metric_definition_guard();

ALTER TABLE public.metric_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.metric_definition FORCE ROW LEVEL SECURITY;
CREATE POLICY metric_definition_tenant_isolation
    ON public.metric_definition
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.metric_definition_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.metric_definition_version FORCE ROW LEVEL SECURITY;
CREATE POLICY metric_definition_version_tenant_isolation
    ON public.metric_definition_version
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.metric_definition, public.metric_definition_version
    FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT, INSERT, UPDATE ON public.metric_definition TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON public.metric_definition_version TO knowvault_app;

REVOKE ALL ON FUNCTION app.metric_definition_guard()
    FROM PUBLIC, knowvault_app, knowvault_worker;
REVOKE ALL ON FUNCTION app.metric_definition_version_guard()
    FROM PUBLIC, knowvault_app, knowvault_worker;

COMMIT;
