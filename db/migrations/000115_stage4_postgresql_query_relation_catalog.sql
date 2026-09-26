-- ADR-0097's knowvault_source_schema tool (S3 card 1) answers from stored
-- projections and discovery metadata of tables registered for one enabled
-- source, with no live call to the external database. The projection itself
-- (public.postgresql_query_projection, migration 000025) already carries the
-- typed, exclusion-narrowed column contract, but it deliberately stores no
-- catalog display metadata: pg_class.reltuples row estimates, relation/column
-- comments and native PostgreSQL type names are discovery-time observations
-- that were never persisted. source_discovery_result holds them only inside a
-- 15-minute, OWNER-only encrypted artifact, so it cannot serve a later read.
--
-- This migration is purely additive. It adds one companion table that records,
-- once, at registration, exactly the catalog metadata of the SAME columns the
-- projection exposes -- never a column the administrator excluded. The table
-- is foreign-keyed to the projection row it describes, immutable, and readable
-- by the application role; the single SECURITY DEFINER command that writes it
-- re-checks the projection and refuses any column outside the stored contract,
-- so the exclusion boundary is enforced in the database as well as in Go.

BEGIN;

-- A small database-side shape gate for the catalog column array. It mirrors
-- app.postgresql_query_columns_contract_is_valid's discipline: bounded size,
-- server-generated identifiers and no duplicate names. It never interprets
-- values or accepts SQL text.
CREATE OR REPLACE FUNCTION app.postgresql_query_column_catalog_is_valid(p_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    item jsonb;
    item_name text;
BEGIN
    IF p_value IS NULL OR jsonb_typeof(p_value) <> 'array'
       OR jsonb_array_length(p_value) < 1 OR jsonb_array_length(p_value) > 128
       OR octet_length(p_value::text) > 262144 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT element FROM jsonb_array_elements(p_value) AS elements(element)
    LOOP
        IF jsonb_typeof(item) <> 'object'
           OR NOT (item ? 'name' AND item ? 'type_name' AND item ? 'comment' AND item ? 'primary_key')
           OR jsonb_typeof(item->'name') <> 'string'
           OR (item->>'name') !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
           OR jsonb_typeof(item->'type_name') <> 'string'
           OR char_length(item->>'type_name') > 128
           OR jsonb_typeof(item->'comment') <> 'string'
           OR char_length(item->>'comment') > 4096
           OR jsonb_typeof(item->'primary_key') <> 'boolean' THEN
            RETURN false;
        END IF;
        item_name := item->>'name';
        IF (SELECT count(*) FROM jsonb_array_elements(p_value) AS duplicate(element)
            WHERE duplicate.element->>'name' = item_name) > 1 THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE public.postgresql_query_relation_catalog (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    connection_id text NOT NULL,
    -- The relation's own native comment, bounded and empty when absent.
    relation_comment text NOT NULL DEFAULT ''
        CHECK (char_length(relation_comment) <= 4096),
    -- pg_class.reltuples at discovery, rounded. -1 is the established
    -- "PostgreSQL has not analyzed this relation yet" sentinel (ADR-0097); it
    -- is display metadata only and never a capacity or security decision.
    approx_row_count bigint NOT NULL DEFAULT -1
        CHECK (approx_row_count BETWEEN -1 AND 9007199254740991),
    -- One entry per projected column, in projection order:
    -- {name, type_name, comment, primary_key}. The recording command refuses
    -- any name outside the projection's own columns_json, so an excluded
    -- column can never appear here.
    columns_catalog jsonb NOT NULL
        CHECK (app.postgresql_query_column_catalog_is_valid(columns_catalog)),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, source_scope_id, source_scope_revision),
    CONSTRAINT postgresql_query_relation_catalog_projection_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.postgresql_query_projection (organization_id, source_scope_id, source_scope_revision)
        ON DELETE RESTRICT,
    CONSTRAINT postgresql_query_relation_catalog_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT postgresql_query_relation_catalog_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

-- A catalog row is written once, in the same transaction as its projection,
-- and never changes: there is no UPDATE or DELETE path and the trigger refuses
-- both unconditionally.
CREATE OR REPLACE FUNCTION app.postgresql_query_relation_catalog_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'postgresql query relation catalog is immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER postgresql_query_relation_catalog_immutable
BEFORE UPDATE OR DELETE ON public.postgresql_query_relation_catalog
FOR EACH ROW EXECUTE FUNCTION app.postgresql_query_relation_catalog_guard();

-- The one writer. It re-checks that the named projection exists for the same
-- scope revision and connection and is still DRAFT, that every catalog name is
-- a real column of that exact projection (and vice versa), and then inserts the
-- row. A replay of the identical registration inserts nothing (ON CONFLICT DO
-- NOTHING): the table's immutability means first write wins.
CREATE OR REPLACE FUNCTION app.postgresql_query_relation_catalog_record(
    p_scope_id text,
    p_scope_revision bigint,
    p_connection_id text,
    p_relation_comment text,
    p_approx_row_count bigint,
    p_columns_catalog jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text := app.current_organization_id();
    principal_value text := app.current_principal_id();
    projection_columns jsonb;
BEGIN
    IF session_user <> 'knowvault_app' OR organization_value IS NULL OR principal_value IS NULL THEN
        RAISE EXCEPTION 'postgresql query relation catalog recording requires the application role and tenant context'
            USING ERRCODE = '42501';
    END IF;
    IF NOT app.source_generated_id_is_valid(p_scope_id, 'scope')
       OR p_scope_revision NOT BETWEEN 1 AND 9007199254740991
       OR p_relation_comment IS NULL
       OR char_length(p_relation_comment) > 4096
       OR p_approx_row_count NOT BETWEEN -1 AND 9007199254740991
       OR NOT app.postgresql_query_column_catalog_is_valid(p_columns_catalog) THEN
        RAISE EXCEPTION 'postgresql query relation catalog contains an invalid bounded value'
            USING ERRCODE = '22023';
    END IF;
    SELECT columns_json INTO projection_columns
    FROM public.postgresql_query_projection
    WHERE organization_id = organization_value
      AND source_scope_id = p_scope_id
      AND source_scope_revision = p_scope_revision
      AND connection_id = p_connection_id
      AND status = 'DRAFT';
    IF projection_columns IS NULL THEN
        RAISE EXCEPTION 'postgresql query relation catalog must bind an exact draft projection'
            USING ERRCODE = '23503';
    END IF;
    -- Both directions: a catalog name the projection does not carry (an
    -- excluded or invented column) and a projected column the catalog omits are
    -- equally refused, so the catalog can never disagree with the contract.
    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(p_columns_catalog) AS catalog(element)
        WHERE NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(projection_columns) AS projected(element)
            WHERE projected.element->>'name' = catalog.element->>'name'
        )
    ) OR (SELECT count(*) FROM jsonb_array_elements(p_columns_catalog))
         <> (SELECT count(*) FROM jsonb_array_elements(projection_columns)) THEN
        RAISE EXCEPTION 'postgresql query relation catalog must match the projection columns exactly'
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.postgresql_query_relation_catalog (
        organization_id, source_scope_id, source_scope_revision, connection_id,
        relation_comment, approx_row_count, columns_catalog, created_by
    ) VALUES (
        organization_value, p_scope_id, p_scope_revision, p_connection_id,
        p_relation_comment, p_approx_row_count, p_columns_catalog, principal_value
    )
    ON CONFLICT (organization_id, source_scope_id, source_scope_revision) DO NOTHING;
END;
$$;

ALTER TABLE public.postgresql_query_relation_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.postgresql_query_relation_catalog FORCE ROW LEVEL SECURITY;
CREATE POLICY postgresql_query_relation_catalog_tenant ON public.postgresql_query_relation_catalog
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.postgresql_query_relation_catalog
    FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT ON TABLE public.postgresql_query_relation_catalog TO knowvault_app;

REVOKE ALL ON FUNCTION app.postgresql_query_column_catalog_is_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.postgresql_query_relation_catalog_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.postgresql_query_relation_catalog_record(text, bigint, text, text, bigint, jsonb)
    FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.postgresql_query_column_catalog_is_valid(jsonb)
    TO knowvault_app, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.postgresql_query_relation_catalog_record(text, bigint, text, text, bigint, jsonb)
    TO knowvault_app;

COMMIT;
