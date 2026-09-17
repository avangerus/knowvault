-- Stage 1: the minimal durable tenancy/workspace foundation.
--
-- This migration is executed only by the dedicated migration role. The runtime
-- role is deliberately named knowvault_app, has no ownership or bypass rights,
-- and receives only SELECT/INSERT/UPDATE on the Stage 1 tables.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'required runtime role knowvault_app does not exist';
    END IF;
END;
$$;

ALTER ROLE knowvault_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE knowvault_app SET row_security = 'on';

CREATE SCHEMA IF NOT EXISTS app;
REVOKE ALL ON SCHEMA app FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA app, public TO knowvault_app;

CREATE OR REPLACE FUNCTION app.current_organization_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT NULLIF(current_setting('app.organization_id', true), '');
$$;

CREATE TABLE public.organization (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DELETING', 'DELETED')),
    region text NOT NULL CHECK (char_length(region) BETWEEN 1 AND 64),
    policy_revision bigint NOT NULL DEFAULT 1 CHECK (policy_revision > 0),
    role_revision bigint NOT NULL DEFAULT 1 CHECK (role_revision > 0),
    owner_principal_id text NOT NULL CHECK (char_length(owner_principal_id) BETWEEN 3 AND 128),
    encryption_key_reference text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (id, owner_principal_id)
);

CREATE TABLE public.principal (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),
    organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
    type text NOT NULL CHECK (type IN ('USER', 'GROUP', 'SERVICE')),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED', 'DEPROVISIONED')),
    session_revision bigint NOT NULL DEFAULT 1 CHECK (session_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, id)
);

ALTER TABLE public.organization
    ADD CONSTRAINT organization_owner_principal_fk
    FOREIGN KEY (id, owner_principal_id)
    REFERENCES public.principal (organization_id, id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE public.organization_role_assignment (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),
    organization_id text NOT NULL,
    principal_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'CONNECTOR_ADMIN', 'SECURITY_AUDITOR', 'MEMBER')),
    valid_from_revision bigint NOT NULL CHECK (valid_from_revision > 0),
    valid_to_revision bigint CHECK (valid_to_revision > valid_from_revision),
    assigned_by text NOT NULL CHECK (char_length(assigned_by) BETWEEN 3 AND 128),
    assigned_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_by text,
    revoked_at timestamptz,
    CONSTRAINT organization_role_principal_fk
        FOREIGN KEY (organization_id, principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CHECK ((valid_to_revision IS NULL) = (revoked_at IS NULL)),
    CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE UNIQUE INDEX organization_one_active_owner
    ON public.organization_role_assignment (organization_id)
    WHERE role = 'OWNER' AND revoked_at IS NULL;

CREATE UNIQUE INDEX organization_one_active_role_per_principal
    ON public.organization_role_assignment (organization_id, principal_id, role)
    WHERE revoked_at IS NULL;

CREATE TABLE public.workspace (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),
    organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 4096),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'READ_ONLY', 'ARCHIVED', 'DELETING', 'DELETED')),
    owner_principal_id text NOT NULL CHECK (char_length(owner_principal_id) BETWEEN 3 AND 128),
    current_revision bigint NOT NULL DEFAULT 1 CHECK (current_revision > 0),
    retention_policy_id text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, id),
    CONSTRAINT workspace_owner_principal_fk
        FOREIGN KEY (organization_id, owner_principal_id)
        REFERENCES public.principal (organization_id, id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE public.workspace_revision (
    organization_id text NOT NULL,
    workspace_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    configuration_hash text NOT NULL CHECK (configuration_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 3 AND 128),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, revision),
    CONSTRAINT workspace_revision_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_revision_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE public.workspace_member (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),
    organization_id text NOT NULL,
    workspace_id text NOT NULL,
    principal_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('OWNER', 'MANAGER', 'MEMBER', 'VIEWER', 'AUDITOR')),
    valid_from_revision bigint NOT NULL CHECK (valid_from_revision > 0),
    valid_to_revision bigint CHECK (valid_to_revision > valid_from_revision),
    added_by text NOT NULL CHECK (char_length(added_by) BETWEEN 3 AND 128),
    added_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    removed_at timestamptz,
    CONSTRAINT workspace_member_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_member_principal_fk
        FOREIGN KEY (organization_id, principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_member_actor_fk
        FOREIGN KEY (organization_id, added_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CHECK ((valid_to_revision IS NULL) = (removed_at IS NULL))
);

CREATE UNIQUE INDEX workspace_one_active_member_per_principal
    ON public.workspace_member (organization_id, workspace_id, principal_id)
    WHERE removed_at IS NULL;

CREATE UNIQUE INDEX workspace_one_active_owner
    ON public.workspace_member (organization_id, workspace_id)
    WHERE role = 'OWNER' AND removed_at IS NULL;

CREATE OR REPLACE FUNCTION app.enforce_organization_owner()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    target_organization_id text;
    target_status text;
    expected_owner text;
    active_owner_count bigint;
    active_owner_principal text;
BEGIN
    IF TG_TABLE_NAME = 'organization' THEN
        target_organization_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target_organization_id := OLD.organization_id;
    ELSE
        target_organization_id := NEW.organization_id;
    END IF;

    SELECT status, owner_principal_id
    INTO target_status, expected_owner
    FROM public.organization
    WHERE id = target_organization_id;

    IF NOT FOUND OR target_status <> 'ACTIVE' THEN
        RETURN NULL;
    END IF;

    SELECT count(*), min(principal_id)
    INTO active_owner_count, active_owner_principal
    FROM public.organization_role_assignment
    WHERE organization_id = target_organization_id
      AND role = 'OWNER'
      AND revoked_at IS NULL;

    IF active_owner_count <> 1 OR active_owner_principal IS DISTINCT FROM expected_owner THEN
        RAISE EXCEPTION 'active organization requires exactly its declared owner role';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app.enforce_workspace_owner()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    target_organization_id text;
    target_workspace_id text;
    target_status text;
    expected_owner text;
    active_owner_count bigint;
    active_owner_principal text;
BEGIN
    IF TG_TABLE_NAME = 'workspace' THEN
        target_organization_id := NEW.organization_id;
        target_workspace_id := NEW.id;
    ELSIF TG_OP = 'DELETE' THEN
        target_organization_id := OLD.organization_id;
        target_workspace_id := OLD.workspace_id;
    ELSE
        target_organization_id := NEW.organization_id;
        target_workspace_id := NEW.workspace_id;
    END IF;

    SELECT status, owner_principal_id
    INTO target_status, expected_owner
    FROM public.workspace
    WHERE organization_id = target_organization_id AND id = target_workspace_id;

    IF NOT FOUND OR target_status <> 'ACTIVE' THEN
        RETURN NULL;
    END IF;

    SELECT count(*), min(principal_id)
    INTO active_owner_count, active_owner_principal
    FROM public.workspace_member
    WHERE organization_id = target_organization_id
      AND workspace_id = target_workspace_id
      AND role = 'OWNER'
      AND removed_at IS NULL;

    IF active_owner_count <> 1 OR active_owner_principal IS DISTINCT FROM expected_owner THEN
        RAISE EXCEPTION 'active workspace requires exactly its declared owner membership';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER organization_owner_matches_active_role
AFTER INSERT OR UPDATE OR DELETE ON public.organization
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_organization_owner();

CREATE CONSTRAINT TRIGGER organization_role_owner_matches_organization
AFTER INSERT OR UPDATE OR DELETE ON public.organization_role_assignment
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_organization_owner();

CREATE CONSTRAINT TRIGGER workspace_owner_matches_active_member
AFTER INSERT OR UPDATE OR DELETE ON public.workspace
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_workspace_owner();

CREATE CONSTRAINT TRIGGER workspace_member_owner_matches_workspace
AFTER INSERT OR UPDATE OR DELETE ON public.workspace_member
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_workspace_owner();

ALTER TABLE public.organization ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_tenant_isolation ON public.organization
    USING (id = app.current_organization_id())
    WITH CHECK (id = app.current_organization_id());

ALTER TABLE public.principal ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.principal FORCE ROW LEVEL SECURITY;
CREATE POLICY principal_tenant_isolation ON public.principal
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.organization_role_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_role_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_role_tenant_isolation ON public.organization_role_assignment
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_tenant_isolation ON public.workspace
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.workspace_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_revision_tenant_isolation ON public.workspace_revision
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.workspace_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_member FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_member_tenant_isolation ON public.workspace_member
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE
    public.organization,
    public.principal,
    public.organization_role_assignment,
    public.workspace,
    public.workspace_revision,
    public.workspace_member
TO knowvault_app;

REVOKE ALL ON FUNCTION app.current_organization_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.enforce_organization_owner() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.enforce_workspace_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.current_organization_id() TO knowvault_app;

COMMIT;
