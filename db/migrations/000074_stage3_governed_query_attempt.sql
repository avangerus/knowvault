-- ADR-0089 §5 correction: :promote must save an already EXECUTED model
-- attempt, identified by its server-owned attempt id and SQL hash, and must
-- never accept SQL text from a request body. PRODUCT_CONSTITUTION.md §7
-- forbids SQL authorship on any product, UI, API or operator surface; the
-- ADR-0089 carve-out is exactly "the model composes SQL over the exposed
-- schema and the dedicated role executes it", not "an HTTP caller may post
-- arbitrary SQL and have the server keep it".
--
-- This migration adds the durable record of one executed governed-query
-- attempt. The SQL text stored here is written by the server from
-- governedquery.Execute's own successful attempt -- the exact text the model
-- composed and the dedicated read-only role actually ran -- never from a
-- request body. It is append-only, tenant-isolated and readable only by the
-- runtime role, and it is what the promotion command dereferences so the
-- operator's request carries only a reference plus the hash it saw.

BEGIN;

CREATE TABLE public.governed_query_attempt (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    connection_id text NOT NULL,
    workspace_id text NOT NULL,
    exposed_schema_revision bigint NOT NULL CHECK (exposed_schema_revision >= 1),
    sql_hash text NOT NULL CHECK (sql_hash ~ '^sha256:[0-9a-f]{64}$'),
    -- The executed statement, server-written from the successful attempt.
    -- Bounded by the same ceiling governedquery.Execute enforces.
    sql_text text NOT NULL CHECK (length(sql_text) BETWEEN 1 AND 8192),
    row_count bigint NOT NULL CHECK (row_count >= 0),
    executed_by text NOT NULL,
    executed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT governed_query_attempt_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.governed_query_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_attempt_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_attempt_actor_fk
        FOREIGN KEY (organization_id, executed_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX governed_query_attempt_connection_hash
    ON public.governed_query_attempt (organization_id, connection_id, sql_hash);

CREATE OR REPLACE FUNCTION app.governed_query_attempt_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'governed_query_attempt is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER governed_query_attempt_immutable
BEFORE UPDATE OR DELETE ON public.governed_query_attempt
FOR EACH ROW EXECUTE FUNCTION app.governed_query_attempt_guard();

ALTER TABLE public.governed_query_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governed_query_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY governed_query_attempt_tenant_isolation ON public.governed_query_attempt
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.governed_query_attempt FROM PUBLIC;
GRANT SELECT, INSERT ON public.governed_query_attempt TO knowvault_app;

-- A promotion now names the executed attempt it saves. attempt_id is added
-- as a nullable column with a NOT VALID check so the constraint binds every
-- future row without rewriting or revalidating history (the append-only
-- trigger forbids backfilling in place anyway); the unique constraint makes
-- a repeated promotion of the same attempt converge instead of duplicating.
ALTER TABLE public.governed_query_promotion ADD COLUMN attempt_id text;

ALTER TABLE public.governed_query_promotion
    ADD CONSTRAINT governed_query_promotion_attempt_required
    CHECK (attempt_id IS NOT NULL) NOT VALID;

ALTER TABLE public.governed_query_promotion
    ADD CONSTRAINT governed_query_promotion_attempt_fk
    FOREIGN KEY (organization_id, attempt_id)
    REFERENCES public.governed_query_attempt (organization_id, id)
    ON DELETE RESTRICT;

CREATE UNIQUE INDEX governed_query_promotion_attempt_unique
    ON public.governed_query_promotion (organization_id, attempt_id);

COMMIT;
