-- S3 card 4: a PostgreSQL relation can be registered "only for SQL queries
-- (not indexed)". A query-only relation keeps the whole ADR-0097 registration
-- contract -- the same separate read-only query role, the same excluded
-- columns, the same workspace enablement, the same limits -- but its rows are
-- never copied into the search index. It is registered, listed by
-- knowvault_source_schema and usable by knowvault_source_sql; the sync worker
-- completes an empty, authoritative sync without reading a row.
--
-- The mode is part of the immutable table contract, never a per-call flag:
-- migration 000120 adds the column, and registration mints a distinct
-- ContractHash/LineageID for a query-only relation (see
-- postgresqlquery.WithQueryOnly). Switching an indexed relation to query-only
-- is therefore a distinct lineage, exactly like a column exclusion, and this
-- migration closes the superseded indexed lineage's objects so its fragments
-- leave search and readback.
--
-- This migration is additive. Every existing projection keeps query_only =
-- false and its exact meaning.

BEGIN;

ALTER TABLE public.postgresql_query_projection
    ADD COLUMN query_only boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.postgresql_query_projection.query_only IS
    'S3 card 4 registration mode: true means the relation is registered only for knowvault_source_sql and its rows are never copied into the search index. Part of the immutable contract (WithQueryOnly mints a distinct ContractHash/LineageID).';

-- The registration command gains the one new contract field. The 18-argument
-- version is dropped, not overloaded, so there is exactly one writer.
DROP FUNCTION app.postgresql_query_projection_register(
    text, bigint, text, text, text, bigint, text, text, text, text, jsonb, text,
    bigint, integer, bigint, bigint, bigint, integer);

CREATE FUNCTION app.postgresql_query_projection_register(
    p_scope_id text, p_scope_revision bigint, p_connection_id text,
    p_database_identity text, p_lineage_id text, p_projection_revision bigint,
    p_contract_hash text, p_schema_name text, p_relation_name text,
    p_relation_kind text, p_columns_json jsonb, p_empty_snapshot_policy text,
    p_query_only boolean,
    p_max_rows bigint, p_max_columns integer, p_max_field_bytes bigint,
    p_max_row_bytes bigint, p_max_total_bytes bigint, p_statement_timeout_ms integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    principal text := app.current_principal_id();
BEGIN
    IF session_user <> 'knowvault_app' OR org IS NULL OR principal IS NULL THEN
        RAISE EXCEPTION 'postgresql query registration requires the application role and tenant context'
            USING ERRCODE = '42501';
    END IF;
    IF p_query_only IS NULL THEN
        RAISE EXCEPTION 'postgresql query registration mode is required'
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.source_scope_revision
        WHERE organization_id = org AND source_scope_id = p_scope_id
          AND revision = p_scope_revision AND connection_id = p_connection_id
          AND source_type = 'POSTGRESQL_QUERY'
          AND scope_contract_version = 'postgresql-query-v1'
    ) THEN
        RAISE EXCEPTION 'postgresql query projection must bind an exact POSTGRESQL_QUERY scope revision'
            USING ERRCODE = '23503';
    END IF;
    INSERT INTO public.postgresql_query_projection (
        organization_id, source_scope_id, source_scope_revision, connection_id,
        database_identity, lineage_id, projection_revision, contract_version,
        contract_hash, schema_name, relation_name, relation_kind, columns_json,
        empty_snapshot_policy, query_only, max_rows, max_columns, max_field_bytes,
        max_row_bytes, max_total_bytes, statement_timeout_ms, status, created_by
    ) VALUES (
        org, p_scope_id, p_scope_revision, p_connection_id, p_database_identity,
        p_lineage_id, p_projection_revision, 'postgresql-query-value-v1',
        p_contract_hash, p_schema_name, p_relation_name, p_relation_kind,
        p_columns_json, p_empty_snapshot_policy, p_query_only, p_max_rows, p_max_columns,
        p_max_field_bytes, p_max_row_bytes, p_max_total_bytes,
        p_statement_timeout_ms, 'DRAFT', principal
    );
END;
$$;

REVOKE ALL ON FUNCTION app.postgresql_query_projection_register(
    text, bigint, text, text, text, bigint, text, text, text, text, jsonb, text,
    boolean, bigint, integer, bigint, bigint, bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.postgresql_query_projection_register(
    text, bigint, text, text, text, bigint, text, text, text, text, jsonb, text,
    boolean, bigint, integer, bigint, bigint, bigint, integer) TO knowvault_app;

-- Switching an indexed relation to query-only is a supersede: the previous
-- indexed lineage must stop being readable. This command revokes every other
-- indexed registration of the SAME connection and relation and closes the
-- source objects it was the only ACTIVE reader of, so search, retrieval and
-- evidence readback stop returning its fragments. The new query-only lineage
-- (p_keep_scope_id) is never touched, and a different relation's indexed
-- objects on the same connection stay ACTIVE.
CREATE FUNCTION app.postgresql_query_relation_supersede(
    p_connection_id text, p_schema_name text, p_relation_name text, p_keep_scope_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    principal text := app.current_principal_id();
    closed bigint := 0;
BEGIN
    IF session_user <> 'knowvault_app' OR org IS NULL OR principal IS NULL THEN
        RAISE EXCEPTION 'postgresql query relation supersede requires the application role and tenant context'
            USING ERRCODE = '42501';
    END IF;
    IF p_connection_id IS NULL OR char_length(p_connection_id) NOT BETWEEN 1 AND 128
       OR p_schema_name IS NULL OR p_schema_name !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
       OR p_relation_name IS NULL OR p_relation_name !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
       OR p_keep_scope_id IS NULL OR char_length(p_keep_scope_id) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'postgresql query relation supersede contains an invalid identifier'
            USING ERRCODE = '22023';
    END IF;

    -- Revoke the superseded indexed registrations' live activations so no
    -- worker can keep publishing into them.
    UPDATE public.source_scope_activation AS activation
       SET status = 'REVOKED', changed_at = now(), activated_at = now()
     WHERE activation.organization_id = org AND activation.revision = 1
       AND activation.status IN ('READY', 'SYNCING')
       AND EXISTS (
           SELECT 1
             FROM public.source_scope_revision AS scope_revision
             JOIN public.postgresql_query_projection AS projection
               ON projection.organization_id = scope_revision.organization_id
              AND projection.source_scope_id = scope_revision.source_scope_id
              AND projection.source_scope_revision = scope_revision.revision
            WHERE scope_revision.organization_id = org
              AND scope_revision.source_scope_id = activation.source_scope_id
              AND scope_revision.revision = activation.source_scope_revision
              AND scope_revision.connection_id = p_connection_id
              AND projection.schema_name = p_schema_name
              AND projection.relation_name = p_relation_name
              AND projection.query_only = false
              AND scope_revision.source_scope_id <> p_keep_scope_id
       );

    -- Remove the superseded memberships. REMOVED is terminal, so a later
    -- re-registration cannot silently revive them.
    UPDATE public.source_object_scope AS membership
       SET membership_state = 'REMOVED', removed_at = now(),
           missing_at = NULL, missing_sync_run_id = NULL
     WHERE membership.organization_id = org
       AND membership.membership_state IN ('ACTIVE', 'MISSING')
       AND EXISTS (
           SELECT 1
             FROM public.source_scope_revision AS scope_revision
             JOIN public.postgresql_query_projection AS projection
               ON projection.organization_id = scope_revision.organization_id
              AND projection.source_scope_id = scope_revision.source_scope_id
              AND projection.source_scope_revision = scope_revision.revision
            WHERE scope_revision.organization_id = org
              AND scope_revision.source_scope_id = membership.source_scope_id
              AND scope_revision.revision = membership.source_scope_revision
              AND scope_revision.connection_id = p_connection_id
              AND projection.schema_name = p_schema_name
              AND projection.relation_name = p_relation_name
              AND projection.query_only = false
              AND scope_revision.source_scope_id <> p_keep_scope_id
       );

    -- Close every object of this connection the supersede just removed the
    -- last ACTIVE membership from. Other relations of the connection keep
    -- their ACTIVE membership and stay queryable.
    UPDATE public.source_object AS object_row
       SET lifecycle_state = 'MISSING', queryable = false, last_seen_at = now()
     WHERE object_row.organization_id = org
       AND object_row.connection_id = p_connection_id
       AND object_row.lifecycle_state = 'ACTIVE'
       AND NOT EXISTS (
           SELECT 1 FROM public.source_object_scope AS active_membership
            WHERE active_membership.organization_id = object_row.organization_id
              AND active_membership.source_object_id = object_row.id
              AND active_membership.membership_state = 'ACTIVE'
       );
    GET DIAGNOSTICS closed = ROW_COUNT;
    RETURN closed;
END;
$$;

REVOKE ALL ON FUNCTION app.postgresql_query_relation_supersede(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.postgresql_query_relation_supersede(text, text, text, text) TO knowvault_app;

COMMIT;
