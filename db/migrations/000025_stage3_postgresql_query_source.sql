-- Stage 3 PostgreSQL business-object source.
--
-- This migration opens one deliberately narrow connector variant: a
-- DBA-managed VIEW/MATERIALIZED VIEW projection.  The application never
-- receives SQL text and the worker never receives a database credential in a
-- job payload.  A projection is an immutable, typed contract; its rows are
-- read in one bounded read-only snapshot and then enter the existing
-- SourceObject/SourceVersion/Extraction/Evidence publication path.

BEGIN;

-- The Stage 2 source lineage is shared by all connector variants.  Keep the
-- original constraint names explicit so a future migration cannot silently
-- widen one table and forget the matching foreign-key side.
ALTER TABLE public.connector_capability_profile
    DROP CONSTRAINT connector_capability_profile_connector_type_check,
    ADD CONSTRAINT connector_capability_profile_connector_type_check
        CHECK (connector_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

ALTER TABLE public.source_connection
    DROP CONSTRAINT source_connection_type_check,
    ADD CONSTRAINT source_connection_type_check
        CHECK (type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

ALTER TABLE public.source_connection_revision
    DROP CONSTRAINT source_connection_revision_connector_type_check,
    ADD CONSTRAINT source_connection_revision_connector_type_check
        CHECK (connector_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

ALTER TABLE public.source_discovered_scope
    DROP CONSTRAINT source_discovered_scope_source_type_check,
    ADD CONSTRAINT source_discovered_scope_source_type_check
        CHECK (source_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

ALTER TABLE public.source_scope
    DROP CONSTRAINT source_scope_source_type_check,
    ADD CONSTRAINT source_scope_source_type_check
        CHECK (source_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

ALTER TABLE public.source_scope_revision
    DROP CONSTRAINT source_scope_revision_source_type_check,
    ADD CONSTRAINT source_scope_revision_source_type_check
        CHECK (source_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

ALTER TABLE public.source_scope_revision
    DROP CONSTRAINT source_scope_revision_scope_contract_version_check,
    ADD CONSTRAINT source_scope_revision_scope_contract_version_check
        CHECK (scope_contract_version IN ('1.2', 'postgresql-query-v1'));

ALTER TABLE public.source_object
    DROP CONSTRAINT source_object_object_type_check,
    ADD CONSTRAINT source_object_object_type_check
        CHECK (object_type IN ('FILE', 'POSTGRESQL_QUERY_ROW'));

ALTER TABLE public.source_extraction
    DROP CONSTRAINT source_extraction_canonical_format_check,
    ADD CONSTRAINT source_extraction_canonical_format_check
        CHECK (canonical_format IN ('TEXT', 'PDF', 'DOCX', 'PPTX', 'XLSX', 'EMAIL', 'HTML', 'OCR', 'POSTGRESQL_QUERY'));

-- The PG projection uses the same sealed owner branches and activation gates as
-- a folder source, but has its own SECURITY DEFINER begin function so a caller
-- can never smuggle a FOLDER identity or scope contract into this lineage.
CREATE OR REPLACE FUNCTION app.source_postgresql_query_registration_begin(
    p_connection_id text, p_connection_name text, p_trust_record_id text,
    p_credential_reference text, p_trust_profile_artifact_id text,
    p_trust_profile_hash text, p_discovered_scope_id text,
    p_identity_digest text, p_identity_digest_key_version bigint,
    p_identity_artifact_id text, p_identity_plaintext_hash text,
    p_display_metadata_artifact_id text, p_display_metadata_hash text,
    p_source_scope_id text, p_scope_config_artifact_id text,
    p_scope_config_hash text, p_capability_profile_id text,
    p_capability_profile_hash text, p_connector_build_id text,
    p_connector_version text, p_connector_artifact_hash text,
    p_connector_contract_suite_hash text, p_connector_verified_at timestamptz,
    p_max_scope_objects bigint, p_max_scope_bytes bigint,
    p_max_object_bytes bigint, p_sync_interval_seconds integer,
    p_content_freshness_sla_seconds integer, p_object_limit bigint,
    p_byte_limit bigint, p_scope_max_object_bytes bigint, p_access_mode text
)
RETURNS TABLE(connection_id text, source_scope_id text, discovered_scope_id text, revision bigint, created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    principal text := app.current_principal_id();
    existing public.source_connection%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_app' OR org IS NULL OR principal IS NULL THEN
        RAISE EXCEPTION 'postgresql query registration requires application tenant context' USING ERRCODE = '42501';
    END IF;
    IF p_access_mode <> 'WORKSPACE_MANAGED' THEN
        RAISE EXCEPTION 'registration serves WORKSPACE_MANAGED access mode only' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.connector_capability_profile
        WHERE id = p_capability_profile_id AND profile_hash = p_capability_profile_hash
          AND connector_build_id = p_connector_build_id AND connector_type = 'POSTGRESQL_QUERY'
          AND connector_version = p_connector_version AND connector_artifact_hash = p_connector_artifact_hash
          AND contract_suite_hash = p_connector_contract_suite_hash AND verified_at = p_connector_verified_at
    ) THEN
        RAISE EXCEPTION 'exact verified POSTGRESQL_QUERY capability profile is missing' USING ERRCODE = '23503';
    END IF;
    SELECT * INTO existing FROM public.source_connection
     WHERE organization_id = org AND id = p_connection_id FOR UPDATE;
    IF FOUND THEN
        IF existing.type <> 'POSTGRESQL_QUERY' OR existing.name <> p_connection_name
           OR existing.latest_revision <> 1 OR existing.status <> 'DRAFT'
           OR NOT EXISTS (
               SELECT 1 FROM public.source_connection_revision r
                WHERE r.organization_id=org AND r.connection_id=p_connection_id AND r.revision=1
                  AND r.credential_reference=p_credential_reference AND r.connector_type='POSTGRESQL_QUERY'
                  AND r.connector_build_id=p_connector_build_id AND r.capability_profile_id=p_capability_profile_id
                  AND r.capability_profile_hash=p_capability_profile_hash AND r.connector_agent_id IS NULL
                  AND r.execution_target='CENTRAL_WORKER' AND r.trust_record_id=p_trust_record_id
                  AND r.trust_profile_hash=p_trust_profile_hash AND r.connector_version=p_connector_version
                  AND r.connector_artifact_hash=p_connector_artifact_hash
                  AND r.connector_contract_suite_hash=p_connector_contract_suite_hash
                  AND r.connector_verified_at=p_connector_verified_at
                  AND r.allowed_access_modes_json='["WORKSPACE_MANAGED"]'
                  AND r.max_scope_objects=p_max_scope_objects AND r.max_scope_bytes=p_max_scope_bytes
                  AND r.max_object_bytes=p_max_object_bytes)
           OR NOT EXISTS (
               SELECT 1 FROM public.source_discovered_scope d
                WHERE d.organization_id=org AND d.id=p_discovered_scope_id AND d.connection_id=p_connection_id
                  AND d.connection_revision=1 AND d.source_type='POSTGRESQL_QUERY'
                  AND d.identity_digest=p_identity_digest AND d.identity_digest_key_version=p_identity_digest_key_version
                  AND d.identity_plaintext_hash=p_identity_plaintext_hash AND d.display_metadata_hash=p_display_metadata_hash)
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope s
                WHERE s.organization_id=org AND s.id=p_source_scope_id AND s.connection_id=p_connection_id
                  AND s.discovered_scope_id=p_discovered_scope_id AND s.source_type='POSTGRESQL_QUERY'
                  AND s.latest_revision=1)
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope_revision sr
                WHERE sr.organization_id=org AND sr.source_scope_id=p_source_scope_id AND sr.revision=1
                  AND sr.connection_id=p_connection_id AND sr.connection_revision=1
                  AND sr.discovered_scope_id=p_discovered_scope_id AND sr.source_type='POSTGRESQL_QUERY'
                  AND sr.scope_config_hash=p_scope_config_hash AND sr.scope_contract_version='postgresql-query-v1'
                  AND sr.access_mode=p_access_mode AND sr.sync_interval_seconds=p_sync_interval_seconds
                  AND sr.content_freshness_sla_seconds=p_content_freshness_sla_seconds
                  AND sr.acl_freshness_sla_seconds IS NULL AND sr.object_limit=p_object_limit
                  AND sr.byte_limit=p_byte_limit AND sr.max_object_bytes=p_scope_max_object_bytes)
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope_activation a
                WHERE a.organization_id=org AND a.source_scope_id=p_source_scope_id
                  AND a.source_scope_revision=1 AND a.revision=1 AND a.status='DRAFT') THEN
            RAISE EXCEPTION 'source lineage id collides with a different configuration' USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT existing.id, p_source_scope_id, p_discovered_scope_id, 1::bigint, false;
        RETURN;
    END IF;
    INSERT INTO public.source_connection
        (organization_id,id,type,name,latest_revision,active_revision,status,created_by)
    VALUES (org,p_connection_id,'POSTGRESQL_QUERY',p_connection_name,1,NULL,'DRAFT',principal);
    INSERT INTO public.source_connection_revision
        (organization_id,connection_id,revision,credential_reference,connector_build_id,connector_type,
         capability_profile_id,capability_profile_hash,connector_agent_id,execution_target,trust_record_id,
         trust_profile_artifact_id,trust_profile_hash,connector_version,connector_artifact_hash,
         connector_contract_suite_hash,connector_verified_at,allowed_access_modes_json,max_scope_objects,
         max_scope_bytes,max_object_bytes,created_by)
    VALUES (org,p_connection_id,1,p_credential_reference,p_connector_build_id,'POSTGRESQL_QUERY',
         p_capability_profile_id,p_capability_profile_hash,NULL,'CENTRAL_WORKER',p_trust_record_id,
         p_trust_profile_artifact_id,p_trust_profile_hash,p_connector_version,p_connector_artifact_hash,
         p_connector_contract_suite_hash,p_connector_verified_at,'["WORKSPACE_MANAGED"]',p_max_scope_objects,
         p_max_scope_bytes,p_max_object_bytes,principal);
    INSERT INTO public.source_connection_trust_record
        (organization_id,id,connection_id,connection_revision,connector_agent_id,execution_target,
         trust_profile_artifact_id,trust_profile_hash,verified_at,expires_at)
    VALUES (org,p_trust_record_id,p_connection_id,1,NULL,'CENTRAL_WORKER',p_trust_profile_artifact_id,
         p_trust_profile_hash,p_connector_verified_at,p_connector_verified_at+interval '90 days');
    INSERT INTO public.source_connection_trust_projection (organization_id,trust_record_id,revision,status)
    VALUES (org,p_trust_record_id,1,'DRAFT');
    INSERT INTO public.source_discovered_scope
        (organization_id,id,connection_id,connection_revision,source_type,identity_digest,
         identity_digest_key_version,identity_artifact_id,identity_plaintext_hash,display_metadata_artifact_id,
         display_metadata_hash)
    VALUES (org,p_discovered_scope_id,p_connection_id,1,'POSTGRESQL_QUERY',p_identity_digest,
         p_identity_digest_key_version,p_identity_artifact_id,p_identity_plaintext_hash,
         p_display_metadata_artifact_id,p_display_metadata_hash);
    INSERT INTO public.source_scope
        (organization_id,id,connection_id,discovered_scope_id,source_type,latest_revision,active_revision,status,created_by)
    VALUES (org,p_source_scope_id,p_connection_id,p_discovered_scope_id,'POSTGRESQL_QUERY',1,NULL,'DRAFT',principal);
    INSERT INTO public.source_scope_revision
        (organization_id,source_scope_id,revision,connection_id,connection_revision,discovered_scope_id,
         discovered_identity_digest,discovered_identity_digest_key_version,source_type,scope_config_artifact_id,
         scope_config_hash,scope_contract_version,access_mode,sync_interval_seconds,content_freshness_sla_seconds,
         acl_freshness_sla_seconds,object_limit,byte_limit,max_object_bytes,created_by)
    VALUES (org,p_source_scope_id,1,p_connection_id,1,p_discovered_scope_id,p_identity_digest,
         p_identity_digest_key_version,'POSTGRESQL_QUERY',p_scope_config_artifact_id,p_scope_config_hash,
         'postgresql-query-v1',p_access_mode,p_sync_interval_seconds,p_content_freshness_sla_seconds,NULL,
         p_object_limit,p_byte_limit,p_scope_max_object_bytes,principal);
    INSERT INTO public.source_scope_activation
        (organization_id,source_scope_id,source_scope_revision,revision,status)
    VALUES (org,p_source_scope_id,1,1,'DRAFT');
    RETURN QUERY SELECT p_connection_id,p_source_scope_id,p_discovered_scope_id,1::bigint,true;
END;
$$;

REVOKE ALL ON FUNCTION app.source_postgresql_query_registration_begin(text,text,text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,bigint,bigint,bigint,integer,integer,bigint,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_postgresql_query_registration_begin(text,text,text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,bigint,bigint,bigint,integer,integer,bigint,bigint,bigint,text) TO knowvault_app;

-- A small database-side shape gate complements the full Go contract validator.
-- It intentionally does not interpret values or accept executable SQL: the
-- canonical bytes and semantic column checks are owned by the connector.
CREATE OR REPLACE FUNCTION app.postgresql_query_columns_contract_is_valid(p_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    item jsonb;
    item_name text;
    item_type text;
    item_ordinal text;
BEGIN
    IF p_value IS NULL OR jsonb_typeof(p_value) <> 'array'
       OR jsonb_array_length(p_value) < 1 OR jsonb_array_length(p_value) > 128
       OR octet_length(p_value::text) > 262144 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT element FROM jsonb_array_elements(p_value) AS elements(element)
    LOOP
        IF jsonb_typeof(item) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(item)) < 5
           OR NOT (item ? 'ordinal' AND item ? 'name' AND item ? 'type_fingerprint'
                   AND item ? 'logical_type' AND item ? 'roles')
           OR jsonb_typeof(item->'ordinal') <> 'number'
           OR (item->>'ordinal') !~ '^[1-9][0-9]{0,2}$'
           OR jsonb_typeof(item->'name') <> 'string'
           OR (item->>'name') !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
           OR jsonb_typeof(item->'type_fingerprint') <> 'string'
           OR (item->>'type_fingerprint') !~ '^[A-Za-z0-9_.:-]{1,160}$'
           OR jsonb_typeof(item->'logical_type') <> 'string'
           OR (item->>'logical_type') NOT IN ('BOOL','INT','NUMERIC','UUID','DATE','TIMESTAMP','TIMESTAMPTZ','TEXT','JSON','JSONB')
           OR jsonb_typeof(item->'roles') <> 'array'
           OR jsonb_array_length(item->'roles') < 1 THEN
            RETURN false;
        END IF;
        item_name := item->>'name';
        item_type := item->>'logical_type';
        item_ordinal := item->>'ordinal';
        IF item_ordinal::integer > jsonb_array_length(p_value) THEN
            RETURN false;
        END IF;
        IF EXISTS (
            SELECT 1 FROM jsonb_array_elements(p_value) AS duplicate(item)
            WHERE duplicate.item->>'name' = item_name
              AND duplicate.item->>'ordinal' <> item_ordinal
        ) THEN
            RETURN false;
        END IF;
        IF item_type = 'NUMERIC' AND NOT (item ? 'precision' AND item ? 'scale') THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE public.postgresql_query_projection (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    connection_id text NOT NULL,
    database_identity text NOT NULL CHECK (
        char_length(database_identity) BETWEEN 1 AND 256
        AND btrim(database_identity) = database_identity
        AND database_identity !~ '[[:cntrl:]]'
    ),
    lineage_id text NOT NULL CHECK (
        char_length(lineage_id) BETWEEN 1 AND 256
        AND btrim(lineage_id) = lineage_id
        AND lineage_id !~ '[[:cntrl:]]'
    ),
    projection_revision bigint NOT NULL CHECK (projection_revision BETWEEN 1 AND 9007199254740991),
    contract_version text NOT NULL CHECK (contract_version = 'postgresql-query-value-v1'),
    contract_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(contract_hash)),
    schema_name text NOT NULL CHECK (schema_name ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
    relation_name text NOT NULL CHECK (relation_name ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
    relation_kind text NOT NULL CHECK (relation_kind IN ('VIEW', 'MATERIALIZED_VIEW')),
    columns_json jsonb NOT NULL CHECK (app.postgresql_query_columns_contract_is_valid(columns_json)),
    empty_snapshot_policy text NOT NULL CHECK (empty_snapshot_policy IN ('HELD', 'AUTHORITATIVE')),
    max_rows bigint NOT NULL CHECK (max_rows BETWEEN 1 AND 10000000),
    max_columns integer NOT NULL CHECK (max_columns BETWEEN 1 AND 128),
    max_field_bytes bigint NOT NULL CHECK (max_field_bytes BETWEEN 1 AND 1048576),
    max_row_bytes bigint NOT NULL CHECK (max_row_bytes BETWEEN 1 AND 16777216),
    max_total_bytes bigint NOT NULL CHECK (max_total_bytes BETWEEN 1 AND 1073741824),
    statement_timeout_ms integer NOT NULL CHECK (statement_timeout_ms BETWEEN 100 AND 300000),
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'ACTIVE', 'REVOKED')),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, source_scope_id, source_scope_revision),
    UNIQUE (organization_id, connection_id, lineage_id, projection_revision),
    UNIQUE (organization_id, source_scope_id, contract_hash),
    CONSTRAINT postgresql_query_projection_scope_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT postgresql_query_projection_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT postgresql_query_projection_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION app.postgresql_query_projection_register(
    p_scope_id text, p_scope_revision bigint, p_connection_id text,
    p_database_identity text, p_lineage_id text, p_projection_revision bigint,
    p_contract_hash text, p_schema_name text, p_relation_name text,
    p_relation_kind text, p_columns_json jsonb, p_empty_snapshot_policy text,
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
        empty_snapshot_policy, max_rows, max_columns, max_field_bytes,
        max_row_bytes, max_total_bytes, statement_timeout_ms, status, created_by
    ) VALUES (
        org, p_scope_id, p_scope_revision, p_connection_id, p_database_identity,
        p_lineage_id, p_projection_revision, 'postgresql-query-value-v1',
        p_contract_hash, p_schema_name, p_relation_name, p_relation_kind,
        p_columns_json, p_empty_snapshot_policy, p_max_rows, p_max_columns,
        p_max_field_bytes, p_max_row_bytes, p_max_total_bytes,
        p_statement_timeout_ms, 'DRAFT', principal
    );
END;
$$;

CREATE OR REPLACE FUNCTION app.postgresql_query_projection_activate(
    p_scope_id text, p_scope_revision bigint, p_contract_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'postgresql query projection activation requires the worker role'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.postgresql_query_projection
        WHERE organization_id = app.current_organization_id()
          AND source_scope_id = p_scope_id
          AND source_scope_revision = p_scope_revision
          AND contract_hash = p_contract_hash
          AND status = 'ACTIVE'
    ) THEN
        RETURN;
    END IF;
    UPDATE public.postgresql_query_projection
       SET status = 'ACTIVE'
     WHERE organization_id = app.current_organization_id()
       AND source_scope_id = p_scope_id
       AND source_scope_revision = p_scope_revision
       AND contract_hash = p_contract_hash
       AND status = 'DRAFT';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'postgresql query projection is not an exact DRAFT row'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

-- The worker receives only the credential reference; the secret itself stays
-- in the deployment's protected mount. This SECURITY DEFINER read prevents
-- granting the worker direct SELECT on the control-plane connection tables.
CREATE OR REPLACE FUNCTION app.postgresql_query_connection_target(
    p_scope_id text, p_scope_revision bigint
)
RETURNS TABLE(connection_id text, connection_revision bigint, credential_reference text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public
AS $$
    SELECT revision.connection_id, revision.connection_revision, connection.credential_reference
    FROM public.source_scope_revision AS revision
    JOIN public.source_connection_revision AS connection
      ON connection.organization_id = revision.organization_id
     AND connection.connection_id = revision.connection_id
     AND connection.revision = revision.connection_revision
     AND connection.connector_type = 'POSTGRESQL_QUERY'
    WHERE revision.organization_id = app.current_organization_id()
      AND revision.source_scope_id = p_scope_id
      AND revision.revision = p_scope_revision
      AND revision.source_type = 'POSTGRESQL_QUERY'
      AND revision.scope_contract_version = 'postgresql-query-v1';
$$;

ALTER TABLE public.postgresql_query_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.postgresql_query_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY postgresql_query_projection_tenant ON public.postgresql_query_projection
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.postgresql_query_projection FROM PUBLIC;
GRANT SELECT ON TABLE public.postgresql_query_projection TO knowvault_app, knowvault_worker;
REVOKE ALL ON FUNCTION app.postgresql_query_columns_contract_is_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.postgresql_query_projection_register(text, bigint, text, text, text, bigint, text, text, text, text, jsonb, text, bigint, integer, bigint, bigint, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.postgresql_query_projection_activate(text, bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.postgresql_query_connection_target(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.postgresql_query_projection_register(text, bigint, text, text, text, bigint, text, text, text, text, jsonb, text, bigint, integer, bigint, bigint, bigint, integer) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.postgresql_query_projection_activate(text, bigint, text) TO knowvault_worker;
GRANT EXECUTE ON FUNCTION app.postgresql_query_connection_target(text, bigint) TO knowvault_worker;
GRANT EXECUTE ON FUNCTION app.postgresql_query_columns_contract_is_valid(jsonb) TO knowvault_app, knowvault_worker;

-- Extend the durable taxonomy without widening the payload vocabulary.  The
-- PG connector job carries only the scope reference, exactly like folder sync.
ALTER TABLE public.job
    DROP CONSTRAINT job_type_check,
    ADD CONSTRAINT job_type_check CHECK (type IN (
        'SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC', 'SOURCE_OBJECT_EXTRACTION',
        'OUTBOX_DELIVERY', 'SOURCE_VERSION_PURGE', 'KEK_REWRAP', 'DIGEST_RECOMPUTE'
    ));

COMMIT;
