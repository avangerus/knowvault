-- Stage 4 source discovery application read projections.
--
-- The application may derive the exact probeable connection revision for an
-- OWNER request and may read a completed discovery envelope only for the same
-- OWNER who created the still-live request. Raw source tables remain outside
-- application and worker authority.

BEGIN;

CREATE OR REPLACE FUNCTION app.source_discovery_connection_target(p_connection_id text)
RETURNS TABLE(connection_revision bigint, trust_profile_hash text)
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
        RAISE EXCEPTION 'source discovery connection target is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    principal_value := app.current_principal_id();
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    IF organization_value IS NULL OR principal_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_connection_id, 'conn')
       OR security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, principal_value, security_epoch_value) THEN
        RAISE EXCEPTION 'source discovery connection target requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT connection.latest_revision, revision.trust_profile_hash
    FROM public.source_connection AS connection
    JOIN public.source_connection_revision AS revision
      ON revision.organization_id = connection.organization_id
     AND revision.connection_id = connection.id
     AND revision.revision = connection.latest_revision
    WHERE connection.organization_id = organization_value
      AND connection.id = p_connection_id
      AND connection.type = 'POSTGRESQL_QUERY'
      AND connection.status = 'DRAFT'
      AND connection.active_revision IS NULL
      AND app.source_discovery_revision_is_probeable(
          organization_value, connection.id, revision.revision,
          revision.trust_profile_hash);
END;
$$;

CREATE OR REPLACE FUNCTION app.source_discovery_result_read_for_owner(p_request_id text)
RETURNS TABLE(
    request_id text,
    result_id text,
    result_status text,
    connection_id text,
    connection_revision bigint,
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
           result.connection_revision, result.view_count,
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

REVOKE ALL ON FUNCTION app.source_discovery_connection_target(text)
    FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_discovery_connection_target(text)
    TO knowvault_app;

REVOKE ALL ON FUNCTION app.source_discovery_result_read_for_owner(text)
    FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_discovery_result_read_for_owner(text)
    TO knowvault_app;

COMMIT;
