-- AGG-2 defect B: ADR-0089's governed-execution connection was authorized
-- per-request against a single hardcoded workspace_id -- both the mounted
-- capability file (governedquery.Config.WorkspaceID, an administrator
-- artifact loaded once at process start) and this table's own
-- governed_query_connection.workspace_id column (NOT NULL, and the
-- immutability trigger 000068's app.governed_query_connection_guard forbids
-- ever changing it after the first workspace registers the connection). A
-- structural source's governed-execution connection is a property of the
-- SOURCE (the external database and the dedicated least-privilege role that
-- reaches it), not of whichever workspace happened to register it first: a
-- second workspace that also has this source's live corpus bound and wants
-- "live queries" for it had no way to ever satisfy
-- workspace_id = governed_query_connection.workspace_id, no matter its own
-- membership or role in that second workspace.
--
-- This migration does not touch governed_query_connection's existing
-- workspace_id column (the append-only/immutable discipline every table in
-- this family already follows forbids rewriting it in place, and dropping a
-- NOT NULL column those triggers still reference would break the running
-- guard function) -- it becomes vestigial history: "the workspace that first
-- registered this connection's exposed schema", nothing more. The table
-- below is the actual authorization surface going forward: one row per
-- (connection, workspace) that has independently opted in, each carrying its
-- own live_queries_enabled toggle, so opting a second workspace in never
-- touches the first workspace's row. It is seeded from every existing
-- connection's row so no live opt-in observed on any stand is lost.
--
-- Access is still gated by internal/governedask.Service.authorize's ordinary
-- workspace-membership/role policy check (mirrors every other
-- workspace-scoped mutation): this table only ever grants a source's
-- governed-execution connection visibility to a workspace an operator has
-- explicitly opted in, one workspace at a time; it never widens who may act
-- inside a workspace they already belong to.

BEGIN;

CREATE TABLE public.governed_query_workspace_binding (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    connection_id text NOT NULL,
    workspace_id text NOT NULL,
    -- Live queries are opt-in and default OFF per binding (ADR-0089 §6 /
    -- owner decision 10), exactly like the connection-wide flag this table
    -- supersedes: one workspace enabling live queries for a shared source
    -- never enables them for another workspace that shares the same
    -- connection.
    live_queries_enabled boolean NOT NULL DEFAULT false,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, connection_id, workspace_id),
    CONSTRAINT governed_query_workspace_binding_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.governed_query_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_workspace_binding_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_workspace_binding_created_by_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_workspace_binding_updated_by_fk
        FOREIGN KEY (organization_id, updated_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

-- Identity fields are immutable, exactly like governed_query_connection's own
-- guard (000068): only live_queries_enabled (and its own bookkeeping) may
-- ever change on an existing binding row.
CREATE OR REPLACE FUNCTION app.governed_query_workspace_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'governed_query_workspace_binding rows cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'governed_query_workspace_binding identity fields are immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER governed_query_workspace_binding_immutable
BEFORE UPDATE OR DELETE ON public.governed_query_workspace_binding
FOR EACH ROW EXECUTE FUNCTION app.governed_query_workspace_binding_guard();

ALTER TABLE public.governed_query_workspace_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governed_query_workspace_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY governed_query_workspace_binding_tenant_isolation ON public.governed_query_workspace_binding
    USING (organization_id = app.current_organization_id());

-- Backfill: every connection's original (first-registering) workspace keeps
-- exactly the opt-in state it already had. This is additive only -- it never
-- removes or narrows governed_query_connection's own row, which stays as
-- immutable history.
INSERT INTO public.governed_query_workspace_binding
    (organization_id, connection_id, workspace_id, live_queries_enabled, created_by, updated_by, created_at, updated_at)
SELECT organization_id, id, workspace_id, live_queries_enabled, created_by, updated_by, created_at, updated_at
FROM public.governed_query_connection
ON CONFLICT (organization_id, connection_id, workspace_id) DO NOTHING;

REVOKE ALL ON TABLE public.governed_query_workspace_binding FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON public.governed_query_workspace_binding TO knowvault_app;

COMMIT;
