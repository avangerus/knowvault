-- 000042: common DRAFT registration for Git/IMAP sources.
--
-- Remote connectors use exactly the same immutable lineage and owner-artifact
-- branches as Folder/PostgreSQL.  This function adds no activation authority:
-- the capability profile must already be verified and the resulting trust and
-- scope projections remain DRAFT until the existing activation confirmation
-- gate is satisfied.  Endpoint configuration is sealed by the application;
-- credentials are only opaque secret-provider references.

BEGIN;

CREATE OR REPLACE FUNCTION app.source_remote_registration_begin(
    p_source_type text,
    p_connection_id text,
    p_connection_name text,
    p_trust_record_id text,
    p_credential_reference text,
    p_trust_profile_artifact_id text,
    p_trust_profile_hash text,
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
    p_capability_profile_id text,
    p_capability_profile_hash text,
    p_connector_build_id text,
    p_connector_version text,
    p_connector_artifact_hash text,
    p_connector_contract_suite_hash text,
    p_connector_verified_at timestamptz,
    p_max_scope_objects bigint,
    p_max_scope_bytes bigint,
    p_max_object_bytes bigint,
    p_sync_interval_seconds integer,
    p_content_freshness_sla_seconds integer,
    p_object_limit bigint,
    p_byte_limit bigint,
    p_scope_max_object_bytes bigint,
    p_access_mode text,
    p_scope_contract_version text
)
RETURNS TABLE(connection_id text, source_scope_id text, discovered_scope_id text, revision bigint, created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text;
    principal text;
    existing public.source_connection%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source registration is an application-role surface' USING ERRCODE = '42501';
    END IF;
    org := app.current_organization_id();
    principal := app.current_principal_id();
    IF org IS NULL OR principal IS NULL THEN
        RAISE EXCEPTION 'source registration requires tenant and principal context' USING ERRCODE = '42501';
    END IF;
    IF p_source_type NOT IN ('GIT', 'MAIL') OR p_access_mode <> 'WORKSPACE_MANAGED' OR
       p_scope_contract_version IS DISTINCT FROM (CASE p_source_type WHEN 'GIT' THEN 'git-v1' WHEN 'MAIL' THEN 'imap-v1' END) THEN
        RAISE EXCEPTION 'remote source registration contract is invalid' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.connector_capability_profile
        WHERE id = p_capability_profile_id
          AND profile_hash = p_capability_profile_hash
          AND connector_build_id = p_connector_build_id
          AND connector_type = p_source_type
          AND connector_version = p_connector_version
          AND connector_artifact_hash = p_connector_artifact_hash
          AND contract_suite_hash = p_connector_contract_suite_hash
          AND verified_at = p_connector_verified_at
    ) THEN
        RAISE EXCEPTION 'exact verified remote connector capability profile is missing' USING ERRCODE = '23503';
    END IF;

    SELECT * INTO existing FROM public.source_connection
    WHERE organization_id = org AND id = p_connection_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing.type <> p_source_type
           OR existing.name <> p_connection_name
           OR existing.latest_revision <> 1
           OR existing.status <> 'DRAFT'
           OR NOT EXISTS (
               SELECT 1 FROM public.source_connection_revision r
               WHERE r.organization_id = org AND r.connection_id = p_connection_id AND r.revision = 1
                 AND r.credential_reference = p_credential_reference
                 AND r.connector_build_id = p_connector_build_id
                 AND r.connector_type = p_source_type
                 AND r.capability_profile_id = p_capability_profile_id
                 AND r.capability_profile_hash = p_capability_profile_hash
                 AND r.connector_agent_id IS NULL
                 AND r.execution_target = 'CENTRAL_WORKER'
                 AND r.trust_record_id = p_trust_record_id
                 AND r.trust_profile_hash = p_trust_profile_hash
                 AND r.connector_version = p_connector_version
                 AND r.connector_artifact_hash = p_connector_artifact_hash
                 AND r.connector_contract_suite_hash = p_connector_contract_suite_hash
                 AND r.connector_verified_at = p_connector_verified_at
                 AND r.allowed_access_modes_json = '["WORKSPACE_MANAGED"]'
                 AND r.max_scope_objects = p_max_scope_objects
                 AND r.max_scope_bytes = p_max_scope_bytes
                 AND r.max_object_bytes = p_max_object_bytes
           )
           OR NOT EXISTS (
               SELECT 1 FROM public.source_connection_trust_record t
               WHERE t.organization_id = org AND t.id = p_trust_record_id
                 AND t.connection_id = p_connection_id AND t.connection_revision = 1
                 AND t.connector_agent_id IS NULL AND t.execution_target = 'CENTRAL_WORKER'
                 AND t.trust_profile_hash = p_trust_profile_hash
                 AND t.verified_at = p_connector_verified_at
                 AND t.expires_at = p_connector_verified_at + interval '90 days'
           )
           OR NOT EXISTS (
               SELECT 1 FROM public.source_discovered_scope d
               WHERE d.organization_id = org AND d.id = p_discovered_scope_id
                 AND d.connection_id = p_connection_id AND d.connection_revision = 1
                 AND d.source_type = p_source_type
                 AND d.identity_digest = p_identity_digest
                 AND d.identity_digest_key_version = p_identity_digest_key_version
                 AND d.identity_plaintext_hash = p_identity_plaintext_hash
                 AND d.display_metadata_hash = p_display_metadata_hash
           )
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope s
               WHERE s.organization_id = org AND s.id = p_source_scope_id
                 AND s.connection_id = p_connection_id
                 AND s.discovered_scope_id = p_discovered_scope_id
                 AND s.source_type = p_source_type
                 AND s.latest_revision = 1
           )
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope_revision sr
               WHERE sr.organization_id = org AND sr.source_scope_id = p_source_scope_id AND sr.revision = 1
                 AND sr.connection_id = p_connection_id AND sr.connection_revision = 1
                 AND sr.discovered_scope_id = p_discovered_scope_id
                 AND sr.discovered_identity_digest = p_identity_digest
                 AND sr.discovered_identity_digest_key_version = p_identity_digest_key_version
                 AND sr.source_type = p_source_type
                 AND sr.scope_config_hash = p_scope_config_hash
                 AND sr.scope_contract_version = p_scope_contract_version
                 AND sr.access_mode = p_access_mode
                 AND sr.sync_interval_seconds = p_sync_interval_seconds
                 AND sr.content_freshness_sla_seconds = p_content_freshness_sla_seconds
                 AND sr.acl_freshness_sla_seconds IS NULL
                 AND sr.object_limit = p_object_limit
                 AND sr.byte_limit = p_byte_limit
                 AND sr.max_object_bytes = p_scope_max_object_bytes
           )
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope_activation a
               WHERE a.organization_id = org AND a.source_scope_id = p_source_scope_id
                 AND a.source_scope_revision = 1 AND a.revision = 1 AND a.status = 'DRAFT'
           ) THEN
            RAISE EXCEPTION 'source lineage id collides with a different configuration' USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT existing.id, p_source_scope_id, p_discovered_scope_id, 1::bigint, false;
        RETURN;
    END IF;

    INSERT INTO public.source_connection (
        organization_id, id, type, name, latest_revision, active_revision, status, created_by
    ) VALUES (org, p_connection_id, p_source_type, p_connection_name, 1, NULL, 'DRAFT', principal);

    INSERT INTO public.source_connection_revision (
        organization_id, connection_id, revision, credential_reference, connector_build_id,
        connector_type, capability_profile_id, capability_profile_hash, connector_agent_id,
        execution_target, trust_record_id, trust_profile_artifact_id, trust_profile_hash,
        connector_version, connector_artifact_hash, connector_contract_suite_hash,
        connector_verified_at, allowed_access_modes_json, max_scope_objects, max_scope_bytes,
        max_object_bytes, created_by
    ) VALUES (
        org, p_connection_id, 1, p_credential_reference, p_connector_build_id,
        p_source_type, p_capability_profile_id, p_capability_profile_hash, NULL,
        'CENTRAL_WORKER', p_trust_record_id, p_trust_profile_artifact_id, p_trust_profile_hash,
        p_connector_version, p_connector_artifact_hash, p_connector_contract_suite_hash,
        p_connector_verified_at, '["WORKSPACE_MANAGED"]', p_max_scope_objects, p_max_scope_bytes,
        p_max_object_bytes, principal
    );

    INSERT INTO public.source_connection_trust_record (
        organization_id, id, connection_id, connection_revision, connector_agent_id,
        execution_target, trust_profile_artifact_id, trust_profile_hash, verified_at, expires_at
    ) VALUES (
        org, p_trust_record_id, p_connection_id, 1, NULL, 'CENTRAL_WORKER',
        p_trust_profile_artifact_id, p_trust_profile_hash, p_connector_verified_at,
        p_connector_verified_at + interval '90 days'
    );

    INSERT INTO public.source_connection_trust_projection (organization_id, trust_record_id, revision, status)
    VALUES (org, p_trust_record_id, 1, 'DRAFT');

    INSERT INTO public.source_discovered_scope (
        organization_id, id, connection_id, connection_revision, source_type,
        identity_digest, identity_digest_key_version, identity_artifact_id, identity_plaintext_hash,
        display_metadata_artifact_id, display_metadata_hash
    ) VALUES (
        org, p_discovered_scope_id, p_connection_id, 1, p_source_type,
        p_identity_digest, p_identity_digest_key_version, p_identity_artifact_id, p_identity_plaintext_hash,
        p_display_metadata_artifact_id, p_display_metadata_hash
    );

    INSERT INTO public.source_scope (
        organization_id, id, connection_id, discovered_scope_id, source_type,
        latest_revision, active_revision, status, created_by
    ) VALUES (org, p_source_scope_id, p_connection_id, p_discovered_scope_id, p_source_type,
        1, NULL, 'DRAFT', principal);

    INSERT INTO public.source_scope_revision (
        organization_id, source_scope_id, revision, connection_id, connection_revision,
        discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version,
        source_type, scope_config_artifact_id, scope_config_hash, scope_contract_version,
        access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
        object_limit, byte_limit, max_object_bytes, created_by
    ) VALUES (
        org, p_source_scope_id, 1, p_connection_id, 1,
        p_discovered_scope_id, p_identity_digest, p_identity_digest_key_version,
        p_source_type, p_scope_config_artifact_id, p_scope_config_hash, p_scope_contract_version,
        p_access_mode, p_sync_interval_seconds, p_content_freshness_sla_seconds, NULL,
        p_object_limit, p_byte_limit, p_scope_max_object_bytes, principal
    );

    INSERT INTO public.source_scope_activation (
        organization_id, source_scope_id, source_scope_revision, revision, status
    ) VALUES (org, p_source_scope_id, 1, 1, 'DRAFT');

    RETURN QUERY SELECT p_connection_id, p_source_scope_id, p_discovered_scope_id, 1::bigint, true;
END;
$$;

REVOKE ALL ON FUNCTION app.source_remote_registration_begin(
    text, text, text, text, text, text, text, text, text, bigint, text, text, text, text,
    text, text, text, text, text, text, text, text, text, timestamptz, bigint, bigint, bigint,
    integer, integer, bigint, bigint, bigint, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_remote_registration_begin(
    text, text, text, text, text, text, text, text, text, bigint, text, text, text, text,
    text, text, text, text, text, text, text, text, text, timestamptz, bigint, bigint, bigint,
    integer, integer, bigint, bigint, bigint, text, text
) TO knowvault_app;

-- The worker resolves the opaque credential reference only after the exact
-- activated scope target has passed the normal trust gate.  Keep this lookup
-- separate from source_scope_sync_target so the existing ten-column contract
-- remains immutable for folder/PG callers.
CREATE OR REPLACE FUNCTION app.source_scope_credential_reference(
    p_scope_id text, p_revision bigint
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    credential text;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source credential lookup is a worker surface' USING ERRCODE = '42501';
    END IF;
    SELECT cr.credential_reference INTO credential
    FROM public.source_scope_revision sr
    JOIN public.source_connection_revision cr
      ON cr.organization_id = sr.organization_id
     AND cr.connection_id = sr.connection_id
     AND cr.revision = sr.connection_revision
     AND cr.connector_type = sr.source_type
    WHERE sr.organization_id = app.current_organization_id()
      AND sr.source_scope_id = p_scope_id
      AND sr.revision = p_revision
      AND sr.source_type IN ('GIT', 'MAIL');
    IF NOT FOUND OR credential IS NULL OR credential = '' THEN
        RAISE EXCEPTION 'source credential reference is unavailable' USING ERRCODE = '42501';
    END IF;
    RETURN credential;
END;
$$;

REVOKE ALL ON FUNCTION app.source_scope_credential_reference(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_scope_credential_reference(text, bigint) TO knowvault_worker;

COMMIT;
