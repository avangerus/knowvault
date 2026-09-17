-- Stage 4 PostgreSQL connection bootstrap and discovery worker target.
--
-- An organization OWNER may create the immutable DRAFT connection revision
-- required by discovery without creating a discovered scope, source scope,
-- activation or workspace binding. The worker reads an exact running request
-- through a lease-fenced SECURITY DEFINER projection rather than receiving
-- SELECT authority on source-management tables.

BEGIN;

CREATE OR REPLACE FUNCTION app.source_postgresql_connection_bootstrap_begin(
    p_connection_id text,
    p_connection_name text,
    p_trust_record_id text,
    p_credential_reference text,
    p_trust_profile_artifact_id text,
    p_trust_profile_hash text,
    p_capability_profile_id text,
    p_capability_profile_hash text,
    p_connector_build_id text,
    p_connector_version text,
    p_connector_artifact_hash text,
    p_connector_contract_suite_hash text,
    p_connector_verified_at timestamptz,
    p_max_scope_objects bigint,
    p_max_scope_bytes bigint,
    p_max_object_bytes bigint
)
RETURNS TABLE(connection_id text, revision bigint, created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    actor_value text;
    security_epoch_value bigint;
    existing public.source_connection%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'PostgreSQL connection bootstrap is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    actor_value := app.current_principal_id();
    IF organization_value IS NULL OR actor_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_connection_id, 'conn')
       OR NOT app.source_generated_id_is_valid(p_credential_reference, 'cred')
       OR NOT app.stage2_opaque_id_is_valid(p_connection_name)
       OR NOT app.stage2_opaque_id_is_valid(p_trust_record_id)
       OR NOT app.stage2_opaque_id_is_valid(p_trust_profile_artifact_id)
       OR NOT app.stage2_sha256_is_valid(p_trust_profile_hash)
       OR p_max_scope_objects NOT BETWEEN 1 AND 10000000
       OR p_max_scope_bytes NOT BETWEEN 1 AND 100000000000
       OR p_max_object_bytes NOT BETWEEN 1 AND 1000000000
       OR p_max_object_bytes > p_max_scope_bytes THEN
        RAISE EXCEPTION 'PostgreSQL connection bootstrap contains an invalid bounded value'
            USING ERRCODE = '22023';
    END IF;

    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    IF security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, actor_value, security_epoch_value) THEN
        RAISE EXCEPTION 'PostgreSQL connection bootstrap requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM public.connector_capability_profile AS profile
        WHERE profile.id = p_capability_profile_id
          AND profile.profile_hash = p_capability_profile_hash
          AND profile.connector_build_id = p_connector_build_id
          AND profile.connector_type = 'POSTGRESQL_QUERY'
          AND profile.connector_version = p_connector_version
          AND profile.connector_artifact_hash = p_connector_artifact_hash
          AND profile.contract_suite_hash = p_connector_contract_suite_hash
          AND profile.verified_at = p_connector_verified_at
    ) THEN
        RAISE EXCEPTION 'exact verified POSTGRESQL_QUERY capability profile is missing'
            USING ERRCODE = '23503';
    END IF;

    SELECT * INTO existing
    FROM public.source_connection
    WHERE organization_id = organization_value AND id = p_connection_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing.type <> 'POSTGRESQL_QUERY'
           OR existing.name <> p_connection_name
           OR existing.latest_revision <> 1
           OR existing.status <> 'DRAFT'
           OR existing.active_revision IS NOT NULL
           OR NOT EXISTS (
               SELECT 1
               FROM public.source_connection_revision AS revision
               JOIN public.source_connection_trust_record AS trust_record
                 ON trust_record.organization_id = revision.organization_id
                AND trust_record.id = revision.trust_record_id
                AND trust_record.connection_id = revision.connection_id
                AND trust_record.connection_revision = revision.revision
                AND trust_record.connector_agent_binding_id = revision.connector_agent_binding_id
                AND trust_record.execution_target = revision.execution_target
                AND trust_record.trust_profile_artifact_id = revision.trust_profile_artifact_id
                AND trust_record.trust_profile_hash = revision.trust_profile_hash
                AND trust_record.verified_at = revision.connector_verified_at
               WHERE revision.organization_id = organization_value
                 AND revision.connection_id = p_connection_id
                 AND revision.revision = 1
                 AND revision.credential_reference = p_credential_reference
                 AND revision.connector_build_id = p_connector_build_id
                 AND revision.connector_type = 'POSTGRESQL_QUERY'
                 AND revision.capability_profile_id = p_capability_profile_id
                 AND revision.capability_profile_hash = p_capability_profile_hash
                 AND revision.connector_agent_id IS NULL
                 AND revision.execution_target = 'CENTRAL_WORKER'
                 AND revision.trust_record_id = p_trust_record_id
                 AND revision.trust_profile_hash = p_trust_profile_hash
                 AND revision.connector_version = p_connector_version
                 AND revision.connector_artifact_hash = p_connector_artifact_hash
                 AND revision.connector_contract_suite_hash = p_connector_contract_suite_hash
                 AND revision.connector_verified_at = p_connector_verified_at
                 AND revision.allowed_access_modes_json = '["WORKSPACE_MANAGED"]'
                 AND revision.max_scope_objects = p_max_scope_objects
                 AND revision.max_scope_bytes = p_max_scope_bytes
                 AND revision.max_object_bytes = p_max_object_bytes
           ) THEN
            RAISE EXCEPTION 'source connection ID collides with a different immutable configuration'
                USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT existing.id, 1::bigint, false;
        RETURN;
    END IF;

    INSERT INTO public.source_connection (
        organization_id, id, type, name, latest_revision, active_revision, status, created_by
    ) VALUES (
        organization_value, p_connection_id, 'POSTGRESQL_QUERY', p_connection_name,
        1, NULL, 'DRAFT', actor_value
    );
    INSERT INTO public.source_connection_revision (
        organization_id, connection_id, revision, credential_reference,
        connector_build_id, connector_type, capability_profile_id,
        capability_profile_hash, connector_agent_id, execution_target,
        trust_record_id, trust_profile_artifact_id, trust_profile_hash,
        connector_version, connector_artifact_hash,
        connector_contract_suite_hash, connector_verified_at,
        allowed_access_modes_json, max_scope_objects, max_scope_bytes,
        max_object_bytes, created_by
    ) VALUES (
        organization_value, p_connection_id, 1, p_credential_reference,
        p_connector_build_id, 'POSTGRESQL_QUERY', p_capability_profile_id,
        p_capability_profile_hash, NULL, 'CENTRAL_WORKER', p_trust_record_id,
        p_trust_profile_artifact_id, p_trust_profile_hash, p_connector_version,
        p_connector_artifact_hash, p_connector_contract_suite_hash,
        p_connector_verified_at, '["WORKSPACE_MANAGED"]', p_max_scope_objects,
        p_max_scope_bytes, p_max_object_bytes, actor_value
    );
    INSERT INTO public.source_connection_trust_record (
        organization_id, id, connection_id, connection_revision,
        connector_agent_id, execution_target, trust_profile_artifact_id,
        trust_profile_hash, verified_at, expires_at
    ) VALUES (
        organization_value, p_trust_record_id, p_connection_id, 1, NULL,
        'CENTRAL_WORKER', p_trust_profile_artifact_id, p_trust_profile_hash,
        p_connector_verified_at, p_connector_verified_at + interval '90 days'
    );
    INSERT INTO public.source_connection_trust_projection (
        organization_id, trust_record_id, revision, status
    ) VALUES (organization_value, p_trust_record_id, 1, 'DRAFT');

    RETURN QUERY SELECT p_connection_id, 1::bigint, true;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_discovery_worker_target(
    p_request_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint
)
RETURNS TABLE(
    actor_principal_id text,
    connection_id text,
    connection_revision bigint,
    credential_reference text,
    trust_profile_hash text,
    trust_profile_artifact_id text,
    max_views integer,
    max_columns integer,
    max_comment_bytes integer,
    statement_timeout_ms integer,
    transaction_timeout_ms integer,
    security_epoch bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery target is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR p_job_id <> p_request_id
       OR NOT app.stage2_opaque_id_is_valid(p_worker_id)
       OR p_lease_epoch < 1 THEN
        RAISE EXCEPTION 'source discovery target requires an exact live lease'
            USING ERRCODE = '55000';
    END IF;

    RETURN QUERY
    SELECT request.actor_principal_id, revision.connection_id, revision.revision,
           revision.credential_reference, revision.trust_profile_hash,
           revision.trust_profile_artifact_id, request.max_views,
           request.max_columns, request.max_comment_bytes,
           request.statement_timeout_ms, request.transaction_timeout_ms,
           request.security_epoch
    FROM public.source_discovery_request AS request
    JOIN public.organization AS organization
      ON organization.id = request.organization_id
     AND organization.status = 'ACTIVE'
     AND organization.role_revision = request.security_epoch
    JOIN public.source_connection AS connection
      ON connection.organization_id = request.organization_id
     AND connection.id = request.connection_id
     AND connection.type = 'POSTGRESQL_QUERY'
     AND connection.status = 'DRAFT'
     AND connection.active_revision IS NULL
    JOIN public.source_connection_revision AS revision
      ON revision.organization_id = request.organization_id
     AND revision.connection_id = request.connection_id
     AND revision.revision = request.connection_revision
     AND revision.connector_type = 'POSTGRESQL_QUERY'
     AND revision.connector_agent_id IS NULL
     AND revision.execution_target = 'CENTRAL_WORKER'
     AND revision.trust_profile_hash = request.trust_profile_hash
    JOIN public.source_connection_trust_record AS trust_record
      ON trust_record.organization_id = revision.organization_id
     AND trust_record.id = revision.trust_record_id
     AND trust_record.connection_id = revision.connection_id
     AND trust_record.connection_revision = revision.revision
     AND trust_record.connector_agent_binding_id = revision.connector_agent_binding_id
     AND trust_record.execution_target = revision.execution_target
     AND trust_record.trust_profile_artifact_id = revision.trust_profile_artifact_id
     AND trust_record.trust_profile_hash = revision.trust_profile_hash
     AND trust_record.verified_at = revision.connector_verified_at
     AND trust_record.expires_at > transaction_timestamp()
    JOIN public.source_connection_trust_projection AS trust_projection
      ON trust_projection.organization_id = trust_record.organization_id
     AND trust_projection.trust_record_id = trust_record.id
     AND trust_projection.status = 'VERIFIED'
    JOIN public.job AS job
      ON job.organization_id = request.organization_id
     AND job.id = p_job_id
     AND job.id = request.id
     AND job.type = 'SOURCE_DISCOVERY'
     AND job.status = 'RUNNING'
     AND job.idempotency_key = 'source-discovery:' || request.id
     AND job.lease_owner = p_worker_id
     AND job.lease_epoch = p_lease_epoch
     AND job.lease_deadline > transaction_timestamp()
     AND job.payload_json = jsonb_build_object(
         'source_discovery_request_id', request.id)
    JOIN public.job_attempt AS attempt
      ON attempt.organization_id = job.organization_id
     AND attempt.job_id = job.id
     AND attempt.attempt_number = job.attempt_count
     AND attempt.lease_owner = job.lease_owner
     AND attempt.lease_epoch = job.lease_epoch
     AND attempt.completed_at IS NULL
    WHERE request.organization_id = organization_value
      AND request.id = p_request_id
      AND request.status = 'RUNNING'
      AND request.expires_at > transaction_timestamp();
END;
$$;

REVOKE ALL ON FUNCTION app.source_postgresql_connection_bootstrap_begin(
    text, text, text, text, text, text, text, text, text, text, text, text,
    timestamptz, bigint, bigint, bigint
) FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_postgresql_connection_bootstrap_begin(
    text, text, text, text, text, text, text, text, text, text, text, text,
    timestamptz, bigint, bigint, bigint
) TO knowvault_app;

REVOKE ALL ON FUNCTION app.source_discovery_worker_target(text, text, text, bigint)
    FROM PUBLIC, knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_discovery_worker_target(text, text, text, bigint)
    TO knowvault_worker;

COMMIT;
