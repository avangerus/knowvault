-- Stage 4 registration of one prepared view from a live discovery result.
--
-- The browser returns only the result request and opaque view selector. The
-- application decrypts the result, resolves the server-generated projection,
-- and this command rechecks the current OWNER, result, security epoch, trust
-- and connection revision before creating the first DRAFT scope revision.

BEGIN;

-- Tighten every application and worker recheck to the trust record referenced
-- by the immutable connection revision. A duplicate attestation row cannot
-- substitute for a revoked referenced record.
CREATE OR REPLACE FUNCTION app.source_discovery_revision_is_probeable(
    organization_value text,
    connection_value text,
    revision_value bigint,
    trust_hash_value text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.organization AS organization
        JOIN public.source_connection AS connection
          ON connection.organization_id = organization.id
         AND connection.id = connection_value
         AND connection.status = 'DRAFT'
         AND connection.active_revision IS NULL
        JOIN public.source_connection_revision AS revision
          ON revision.organization_id = connection.organization_id
         AND revision.connection_id = connection.id
         AND revision.revision = revision_value
         AND revision.connector_type = 'POSTGRESQL_QUERY'
         AND revision.trust_profile_hash = trust_hash_value
        JOIN public.source_connection_trust_record AS trust_record
          ON trust_record.organization_id = revision.organization_id
         AND trust_record.id = revision.trust_record_id
         AND trust_record.connection_id = revision.connection_id
         AND trust_record.connection_revision = revision.revision
         AND trust_record.trust_profile_hash = revision.trust_profile_hash
         AND trust_record.trust_profile_artifact_id = revision.trust_profile_artifact_id
         AND trust_record.execution_target = revision.execution_target
         AND trust_record.connector_agent_binding_id = revision.connector_agent_binding_id
         AND trust_record.verified_at = revision.connector_verified_at
        JOIN public.source_connection_trust_projection AS projection
          ON projection.organization_id = trust_record.organization_id
         AND projection.trust_record_id = trust_record.id
         AND projection.status = 'VERIFIED'
        WHERE organization.id = organization_value
          AND organization.status = 'ACTIVE'
          AND trust_record.expires_at > transaction_timestamp()
    );
$$;

-- Versioned owner projection adds the two result digests needed to prove the
-- decrypted metadata belongs to the persisted database and privilege tuple.
CREATE OR REPLACE FUNCTION app.source_discovery_result_read_for_owner_v2(p_request_id text)
RETURNS TABLE(
    request_id text,
    result_id text,
    result_status text,
    connection_id text,
    connection_revision bigint,
    database_identity_hash text,
    privilege_digest text,
    view_count integer,
    prepared_view_count integer,
    needs_interpretation_view_count integer,
    artifact_id text,
    ciphertext bytea,
    size_bytes integer,
    nonce bytea,
    wrapped_dek bytea,
    wrapped_dek_hash text,
    kek_reference text,
    kek_version bigint,
    aad_hash text,
    plaintext_hash text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    principal_value text;
    security_epoch_value bigint;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source discovery result read is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    principal_value := app.current_principal_id();
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    IF organization_value IS NULL OR principal_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, principal_value, security_epoch_value) THEN
        RAISE EXCEPTION 'source discovery result read requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT request.id, result.id, result.status, result.connection_id,
           result.connection_revision, result.database_identity_hash,
           result.privilege_digest, result.view_count,
           result.prepared_view_count,
           result.needs_interpretation_view_count, artifact.id,
           artifact.ciphertext, artifact.size_bytes, artifact.nonce,
           artifact.wrapped_dek, artifact.wrapped_dek_hash,
           artifact.kek_reference, artifact.kek_version,
           artifact.aad_hash, artifact.plaintext_hash
    FROM public.source_discovery_request AS request
    JOIN public.source_discovery_result AS result
      ON result.organization_id = request.organization_id
     AND result.id = request.result_id
     AND result.request_id = request.id
     AND result.actor_principal_id = request.actor_principal_id
     AND result.connection_id = request.connection_id
     AND result.connection_revision = request.connection_revision
     AND result.trust_profile_hash = request.trust_profile_hash
     AND result.security_epoch = request.security_epoch
     AND result.result_hash = request.result_hash
     AND result.expires_at > transaction_timestamp()
    JOIN public.encrypted_artifact AS artifact
      ON artifact.organization_id = result.organization_id
     AND artifact.id = result.metadata_artifact_id
     AND artifact.owner_table = 'source_discovery_result'
     AND artifact.owner_column = 'metadata_artifact_id'
     AND artifact.resource_type = 'SOURCE_DISCOVERY_RESULT'
     AND artifact.resource_id = result.id
     AND artifact.field_name = 'DISCOVERY_METADATA'
     AND artifact.plaintext_hash = result.metadata_plaintext_hash
     AND artifact.purged_at IS NULL
    WHERE request.organization_id = organization_value
      AND request.id = p_request_id
      AND request.actor_principal_id = principal_value
      AND request.status = 'SUCCEEDED'
      AND request.security_epoch = security_epoch_value
      AND request.expires_at > transaction_timestamp()
      AND app.source_discovery_revision_is_probeable(
          organization_value, request.connection_id,
          request.connection_revision, request.trust_profile_hash);
END;
$$;

CREATE TABLE public.source_discovery_registration (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    request_id text NOT NULL,
    result_id text NOT NULL,
    view_selector text NOT NULL CHECK (view_selector ~ '^sdv_[0-9a-f]{64}$'),
    connection_id text NOT NULL,
    connection_revision bigint NOT NULL CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    source_scope_id text NOT NULL,
    scope_config_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(scope_config_hash)),
    projection_contract_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(projection_contract_hash)),
    registered_by text NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, request_id, view_selector),
    UNIQUE (organization_id, source_scope_id),
    CONSTRAINT source_discovery_registration_request_fk
        FOREIGN KEY (organization_id, request_id)
        REFERENCES public.source_discovery_request (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_registration_result_fk
        FOREIGN KEY (organization_id, result_id)
        REFERENCES public.source_discovery_result (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_registration_revision_fk
        FOREIGN KEY (organization_id, connection_id, connection_revision)
        REFERENCES public.source_connection_revision (organization_id, connection_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_registration_scope_fk
        FOREIGN KEY (organization_id, source_scope_id)
        REFERENCES public.source_scope (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_registration_actor_fk
        FOREIGN KEY (organization_id, registered_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION app.source_discovery_registration_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP <> 'INSERT'
       OR session_user <> 'knowvault_app'
       OR current_setting('app.source_discovery_register_scope', true)
          IS DISTINCT FROM NEW.request_id || ':' || NEW.view_selector THEN
        RAISE EXCEPTION 'source discovery registrations are append-only command output'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_discovery_registration_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.source_discovery_registration
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_registration_mutation_guard();

CREATE OR REPLACE FUNCTION app.source_discovery_view_registration_begin(
    p_request_id text,
    p_result_id text,
    p_view_selector text,
    p_connection_id text,
    p_connection_revision bigint,
    p_discovered_scope_id text,
    p_identity_digest text,
    p_identity_digest_key_version bigint,
    p_identity_artifact_id text,
    p_identity_plaintext_hash text,
    p_display_metadata_artifact_id text,
    p_display_metadata_hash text,
    p_source_scope_id text,
    p_scope_config_artifact_id text,
    p_scope_config_hash text,
    p_projection_contract_hash text,
    p_sync_interval_seconds integer,
    p_content_freshness_sla_seconds integer,
    p_object_limit bigint,
    p_byte_limit bigint,
    p_scope_max_object_bytes bigint,
    p_access_mode text
)
RETURNS TABLE(connection_id text, source_scope_id text, discovered_scope_id text, revision bigint, created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    actor_value text;
    security_epoch_value bigint;
    existing public.source_discovery_registration%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source discovery registration is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    actor_value := app.current_principal_id();
    IF organization_value IS NULL OR actor_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.source_generated_id_is_valid(p_result_id, 'sdr')
       OR p_view_selector !~ '^sdv_[0-9a-f]{64}$'
       OR NOT app.source_generated_id_is_valid(p_connection_id, 'conn')
       OR p_connection_revision NOT BETWEEN 1 AND 9007199254740991
       OR NOT app.source_generated_id_is_valid(p_discovered_scope_id, 'discovered')
       OR NOT app.source_keyed_digest_matches_version(
           p_identity_digest, p_identity_digest_key_version)
       OR NOT app.stage2_opaque_id_is_valid(p_identity_artifact_id)
       OR NOT app.stage2_sha256_is_valid(p_identity_plaintext_hash)
       OR NOT app.stage2_opaque_id_is_valid(p_display_metadata_artifact_id)
       OR NOT app.stage2_sha256_is_valid(p_display_metadata_hash)
       OR NOT app.source_generated_id_is_valid(p_source_scope_id, 'scope')
       OR NOT app.stage2_opaque_id_is_valid(p_scope_config_artifact_id)
       OR NOT app.stage2_sha256_is_valid(p_scope_config_hash)
       OR NOT app.stage2_sha256_is_valid(p_projection_contract_hash)
       OR p_access_mode <> 'WORKSPACE_MANAGED'
       OR p_sync_interval_seconds NOT BETWEEN 60 AND 86400
       OR p_content_freshness_sla_seconds NOT BETWEEN 60 AND 604800
       OR p_object_limit NOT BETWEEN 1 AND 10000000
       OR p_byte_limit NOT BETWEEN 1 AND 9007199254740991
       OR p_scope_max_object_bytes NOT BETWEEN 1 AND p_byte_limit THEN
        RAISE EXCEPTION 'source discovery registration contains an invalid bounded value'
            USING ERRCODE = '22023';
    END IF;

    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    IF security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, actor_value, security_epoch_value) THEN
        RAISE EXCEPTION 'source discovery registration requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM public.source_discovery_request AS request
    JOIN public.source_discovery_result AS result
      ON result.organization_id = request.organization_id
     AND result.id = request.result_id
     AND result.request_id = request.id
     AND result.result_hash = request.result_hash
     AND result.actor_principal_id = request.actor_principal_id
     AND result.connection_id = request.connection_id
     AND result.connection_revision = request.connection_revision
     AND result.trust_profile_hash = request.trust_profile_hash
     AND result.security_epoch = request.security_epoch
     AND result.expires_at > transaction_timestamp()
    JOIN public.source_connection AS connection
      ON connection.organization_id = request.organization_id
     AND connection.id = request.connection_id
     AND connection.type = 'POSTGRESQL_QUERY'
     AND connection.latest_revision = request.connection_revision
     AND connection.status = 'DRAFT'
     AND connection.active_revision IS NULL
    WHERE request.organization_id = organization_value
      AND request.id = p_request_id
      AND request.actor_principal_id = actor_value
      AND request.status = 'SUCCEEDED'
      AND request.result_id = p_result_id
      AND request.connection_id = p_connection_id
      AND request.connection_revision = p_connection_revision
      AND request.security_epoch = security_epoch_value
      AND request.expires_at > transaction_timestamp()
      AND result.prepared_view_count > 0
      AND app.source_discovery_revision_is_probeable(
          organization_value, request.connection_id,
          request.connection_revision, request.trust_profile_hash)
    FOR UPDATE OF request, result, connection;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery registration target is unavailable'
            USING ERRCODE = '55000';
    END IF;

    SELECT * INTO existing
    FROM public.source_discovery_registration
    WHERE organization_id = organization_value
      AND request_id = p_request_id
      AND view_selector = p_view_selector
    FOR UPDATE;
    IF FOUND THEN
        IF existing.result_id <> p_result_id
           OR existing.connection_id <> p_connection_id
           OR existing.connection_revision <> p_connection_revision
           OR existing.source_scope_id <> p_source_scope_id
           OR existing.scope_config_hash <> p_scope_config_hash
           OR existing.projection_contract_hash <> p_projection_contract_hash
           OR NOT EXISTS (
               SELECT 1
               FROM public.source_scope_revision AS scope_revision
               JOIN public.source_scope AS scope
                 ON scope.organization_id = scope_revision.organization_id
                AND scope.id = scope_revision.source_scope_id
               JOIN public.source_discovered_scope AS discovered
                 ON discovered.organization_id = scope_revision.organization_id
                AND discovered.id = scope_revision.discovered_scope_id
               JOIN public.postgresql_query_projection AS projection
                 ON projection.organization_id = scope_revision.organization_id
                AND projection.source_scope_id = scope_revision.source_scope_id
                AND projection.source_scope_revision = scope_revision.revision
               WHERE scope_revision.organization_id = organization_value
                 AND scope_revision.source_scope_id = p_source_scope_id
                 AND scope_revision.revision = 1
                 AND scope_revision.connection_id = p_connection_id
                 AND scope_revision.connection_revision = p_connection_revision
                 AND scope_revision.discovered_scope_id = p_discovered_scope_id
                 AND scope_revision.source_type = 'POSTGRESQL_QUERY'
                 AND scope_revision.scope_config_hash = p_scope_config_hash
                 AND scope_revision.scope_contract_version = 'postgresql-query-v1'
                 AND scope_revision.access_mode = p_access_mode
                 AND scope_revision.sync_interval_seconds = p_sync_interval_seconds
                 AND scope_revision.content_freshness_sla_seconds = p_content_freshness_sla_seconds
                 AND scope_revision.object_limit = p_object_limit
                 AND scope_revision.byte_limit = p_byte_limit
                 AND scope_revision.max_object_bytes = p_scope_max_object_bytes
                 AND scope.discovered_scope_id = p_discovered_scope_id
                 AND scope.status = 'DRAFT'
                 AND discovered.identity_digest = p_identity_digest
                 AND discovered.identity_digest_key_version = p_identity_digest_key_version
                 AND discovered.identity_plaintext_hash = p_identity_plaintext_hash
                 AND discovered.display_metadata_hash = p_display_metadata_hash
                 AND projection.connection_id = p_connection_id
                 AND projection.contract_hash = p_projection_contract_hash)
        THEN
            RAISE EXCEPTION 'source discovery selection collides with a different registration'
                USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT p_connection_id, p_source_scope_id,
            p_discovered_scope_id, 1::bigint, false;
        RETURN;
    END IF;

    INSERT INTO public.source_discovered_scope (
        organization_id, id, connection_id, connection_revision, source_type,
        identity_digest, identity_digest_key_version, identity_artifact_id,
        identity_plaintext_hash, display_metadata_artifact_id,
        display_metadata_hash
    ) VALUES (
        organization_value, p_discovered_scope_id, p_connection_id,
        p_connection_revision, 'POSTGRESQL_QUERY', p_identity_digest,
        p_identity_digest_key_version, p_identity_artifact_id,
        p_identity_plaintext_hash, p_display_metadata_artifact_id,
        p_display_metadata_hash
    );
    INSERT INTO public.source_scope (
        organization_id, id, connection_id, discovered_scope_id, source_type,
        latest_revision, active_revision, status, created_by
    ) VALUES (
        organization_value, p_source_scope_id, p_connection_id,
        p_discovered_scope_id, 'POSTGRESQL_QUERY', 1, NULL, 'DRAFT', actor_value
    );
    INSERT INTO public.source_scope_revision (
        organization_id, source_scope_id, revision, connection_id,
        connection_revision, discovered_scope_id, discovered_identity_digest,
        discovered_identity_digest_key_version, source_type,
        scope_config_artifact_id, scope_config_hash, scope_contract_version,
        access_mode, sync_interval_seconds, content_freshness_sla_seconds,
        acl_freshness_sla_seconds, object_limit, byte_limit, max_object_bytes,
        created_by
    ) VALUES (
        organization_value, p_source_scope_id, 1, p_connection_id,
        p_connection_revision, p_discovered_scope_id, p_identity_digest,
        p_identity_digest_key_version, 'POSTGRESQL_QUERY',
        p_scope_config_artifact_id, p_scope_config_hash, 'postgresql-query-v1',
        p_access_mode, p_sync_interval_seconds, p_content_freshness_sla_seconds,
        NULL, p_object_limit, p_byte_limit, p_scope_max_object_bytes, actor_value
    );
    INSERT INTO public.source_scope_activation (
        organization_id, source_scope_id, source_scope_revision, revision, status
    ) VALUES (organization_value, p_source_scope_id, 1, 1, 'DRAFT');

    PERFORM set_config(
        'app.source_discovery_register_scope',
        p_request_id || ':' || p_view_selector, true);
    INSERT INTO public.source_discovery_registration (
        organization_id, request_id, result_id, view_selector, connection_id,
        connection_revision, source_scope_id, scope_config_hash,
        projection_contract_hash, registered_by
    ) VALUES (
        organization_value, p_request_id, p_result_id, p_view_selector,
        p_connection_id, p_connection_revision, p_source_scope_id,
        p_scope_config_hash, p_projection_contract_hash, actor_value
    );

    RETURN QUERY SELECT p_connection_id, p_source_scope_id,
        p_discovered_scope_id, 1::bigint, true;
END;
$$;

ALTER TABLE public.source_discovery_registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_discovery_registration FORCE ROW LEVEL SECURITY;
CREATE POLICY source_discovery_registration_tenant_isolation
    ON public.source_discovery_registration
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_discovery_registration
    FROM PUBLIC, knowvault_app, knowvault_worker;
REVOKE ALL ON FUNCTION app.source_discovery_registration_mutation_guard()
    FROM PUBLIC, knowvault_app, knowvault_worker;
REVOKE ALL ON FUNCTION app.source_discovery_result_read_for_owner_v2(text)
    FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_discovery_result_read_for_owner_v2(text)
    TO knowvault_app;
REVOKE ALL ON FUNCTION app.source_discovery_view_registration_begin(
    text, text, text, text, bigint, text, text, bigint, text, text, text,
    text, text, text, text, text, integer, integer, bigint, bigint, bigint, text
) FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_discovery_view_registration_begin(
    text, text, text, text, bigint, text, text, bigint, text, text, text,
    text, text, text, text, text, integer, integer, bigint, bigint, bigint, text
) TO knowvault_app;

COMMIT;
