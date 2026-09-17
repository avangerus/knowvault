-- 000018: product registration surface for Stage 2 sources (ADR-0074).
--
-- The registration surface composes the DRAFT lineage that the control plane
-- previously created only by direct SQL: one application-role write inserts the
-- connection, its revision 1, the trust record and its DRAFT projection, the
-- discovered scope, the scope, its revision 1 and the DRAFT activation row, and
-- then binds the four sealed artifacts whose ids the owning rows already
-- record. Every authority remains the deferred constraint triggers of
-- migrations 000006/000007 and the state guards of 000014/000016; these
-- functions add no new transition, no bypass and no fallback.

-- ---------------------------------------------------------------------------
-- 1. Registration begin: idempotent DRAFT lineage insert.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_folder_registration_begin(
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
    p_access_mode text
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
        RAISE EXCEPTION 'source registration is an application-role surface'
            USING ERRCODE = '42501';
    END IF;
    org := app.current_organization_id();
    principal := app.current_principal_id();
    IF org IS NULL OR principal IS NULL THEN
        RAISE EXCEPTION 'source registration requires tenant and principal context'
            USING ERRCODE = '42501';
    END IF;

    -- Registration serves WORKSPACE_MANAGED only; SOURCE_ENFORCED has no
    -- product path in this release (ADR-0074 s1.10).
    IF p_access_mode <> 'WORKSPACE_MANAGED' THEN
        RAISE EXCEPTION 'registration serves WORKSPACE_MANAGED access mode only'
            USING ERRCODE = '23514';
    END IF;

    -- The runtime passes the exact tuple it read; the non-deferred capability
    -- FK on the revision insert re-validates it verbatim. Missing profile is a
    -- typed environment condition, never a fallback connector.
    IF NOT EXISTS (
        SELECT 1 FROM public.connector_capability_profile
        WHERE id = p_capability_profile_id
          AND profile_hash = p_capability_profile_hash
          AND connector_build_id = p_connector_build_id
          AND connector_type = 'FOLDER'
          AND connector_version = p_connector_version
          AND connector_artifact_hash = p_connector_artifact_hash
          AND contract_suite_hash = p_connector_contract_suite_hash
          AND verified_at = p_connector_verified_at
    ) THEN
        RAISE EXCEPTION 'exact verified FOLDER connector capability profile is missing'
            USING ERRCODE = '23503';
    END IF;

    -- Idempotency and conflict resolution. The connection id is derived from
    -- the lineage, so a replay converges on the same row: an exact-match replay
    -- returns created=false without touching rows, and a lineage collision with
    -- a different configuration is a typed conflict, never a silent overwrite.
    -- The artifact ids are excluded from the exact match: they are per-call
    -- nonce locators minted by the runtime, not content, and the content
    -- identity is already pinned by the plaintext hashes and digests below.
    -- A replay never re-inserts artifacts — begin() only reports created=true
    -- for a fresh lineage, and the bind functions then run in the same
    -- transaction that created the owning rows.
    SELECT * INTO existing FROM public.source_connection
    WHERE organization_id = org AND id = p_connection_id
    FOR UPDATE;

    IF FOUND THEN
        IF existing.type <> 'FOLDER'
           OR existing.name <> p_connection_name
           OR existing.latest_revision <> 1
           OR existing.status <> 'DRAFT'
           OR NOT EXISTS (
               SELECT 1 FROM public.source_connection_revision r
               WHERE r.organization_id = org AND r.connection_id = p_connection_id AND r.revision = 1
                 AND r.credential_reference = p_credential_reference
                 AND r.connector_build_id = p_connector_build_id
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
                 AND d.source_type = 'FOLDER'
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
                 AND s.source_type = 'FOLDER'
                 AND s.latest_revision = 1
           )
           OR NOT EXISTS (
               SELECT 1 FROM public.source_scope_revision sr
               WHERE sr.organization_id = org AND sr.source_scope_id = p_source_scope_id AND sr.revision = 1
                 AND sr.connection_id = p_connection_id AND sr.connection_revision = 1
                 AND sr.discovered_scope_id = p_discovered_scope_id
                 AND sr.discovered_identity_digest = p_identity_digest
                 AND sr.discovered_identity_digest_key_version = p_identity_digest_key_version
                 AND sr.source_type = 'FOLDER'
                 AND sr.scope_config_hash = p_scope_config_hash
                 AND sr.scope_contract_version = '1.2'
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
            RAISE EXCEPTION 'source lineage id collides with a different configuration'
                USING ERRCODE = '23505';
        END IF;
        RETURN QUERY SELECT existing.id, p_source_scope_id, p_discovered_scope_id, 1::bigint, false;
        RETURN;
    END IF;

    -- Insert order follows the non-deferred foreign keys: connection, revision,
    -- trust record, trust projection, discovered scope, scope, scope revision,
    -- activation. Artifact foreign keys and the exact-ownership guards are
    -- deferred to commit, so rows may reference artifacts sealed afterwards.
    INSERT INTO public.source_connection (
        organization_id, id, type, name, latest_revision, active_revision, status, created_by
    ) VALUES (
        org, p_connection_id, 'FOLDER', p_connection_name, 1, NULL, 'DRAFT', principal
    );

    INSERT INTO public.source_connection_revision (
        organization_id, connection_id, revision, credential_reference, connector_build_id,
        connector_type, capability_profile_id, capability_profile_hash, connector_agent_id,
        execution_target, trust_record_id, trust_profile_artifact_id, trust_profile_hash,
        connector_version, connector_artifact_hash, connector_contract_suite_hash,
        connector_verified_at, allowed_access_modes_json, max_scope_objects, max_scope_bytes,
        max_object_bytes, created_by
    ) VALUES (
        org, p_connection_id, 1, p_credential_reference, p_connector_build_id,
        'FOLDER', p_capability_profile_id, p_capability_profile_hash, NULL,
        'CENTRAL_WORKER', p_trust_record_id, p_trust_profile_artifact_id, p_trust_profile_hash,
        p_connector_version, p_connector_artifact_hash, p_connector_contract_suite_hash,
        p_connector_verified_at, '["WORKSPACE_MANAGED"]', p_max_scope_objects, p_max_scope_bytes,
        p_max_object_bytes, principal
    );

    INSERT INTO public.source_connection_trust_record (
        organization_id, id, connection_id, connection_revision, connector_agent_id,
        execution_target, trust_profile_artifact_id, trust_profile_hash, verified_at, expires_at
    ) VALUES (
        org, p_trust_record_id, p_connection_id, 1, NULL,
        'CENTRAL_WORKER', p_trust_profile_artifact_id, p_trust_profile_hash,
        p_connector_verified_at, p_connector_verified_at + interval '90 days'
    );

    INSERT INTO public.source_connection_trust_projection (
        organization_id, trust_record_id, revision, status
    ) VALUES (
        org, p_trust_record_id, 1, 'DRAFT'
    );

    INSERT INTO public.source_discovered_scope (
        organization_id, id, connection_id, connection_revision, source_type,
        identity_digest, identity_digest_key_version, identity_artifact_id, identity_plaintext_hash,
        display_metadata_artifact_id, display_metadata_hash
    ) VALUES (
        org, p_discovered_scope_id, p_connection_id, 1, 'FOLDER',
        p_identity_digest, p_identity_digest_key_version, p_identity_artifact_id, p_identity_plaintext_hash,
        p_display_metadata_artifact_id, p_display_metadata_hash
    );

    INSERT INTO public.source_scope (
        organization_id, id, connection_id, discovered_scope_id, source_type,
        latest_revision, active_revision, status, created_by
    ) VALUES (
        org, p_source_scope_id, p_connection_id, p_discovered_scope_id, 'FOLDER',
        1, NULL, 'DRAFT', principal
    );

    INSERT INTO public.source_scope_revision (
        organization_id, source_scope_id, revision, connection_id, connection_revision,
        discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version,
        source_type, scope_config_artifact_id, scope_config_hash, scope_contract_version,
        access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
        object_limit, byte_limit, max_object_bytes, created_by
    ) VALUES (
        org, p_source_scope_id, 1, p_connection_id, 1,
        p_discovered_scope_id, p_identity_digest, p_identity_digest_key_version,
        'FOLDER', p_scope_config_artifact_id, p_scope_config_hash, '1.2',
        p_access_mode, p_sync_interval_seconds, p_content_freshness_sla_seconds, NULL,
        p_object_limit, p_byte_limit, p_scope_max_object_bytes, principal
    );

    INSERT INTO public.source_scope_activation (
        organization_id, source_scope_id, source_scope_revision, revision, status
    ) VALUES (
        org, p_source_scope_id, 1, 1, 'DRAFT'
    );

    RETURN QUERY SELECT p_connection_id, p_source_scope_id, p_discovered_scope_id, 1::bigint, true;
END;
$$;

REVOKE ALL ON FUNCTION app.source_folder_registration_begin(text, text, text, text, text, text, text, text, bigint, text, text, text, text, text, text, text, text, text, text, text, text, text, timestamptz, bigint, bigint, bigint, integer, integer, bigint, bigint, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_folder_registration_begin(text, text, text, text, text, text, text, text, bigint, text, text, text, text, text, text, text, text, text, text, text, text, text, timestamptz, bigint, bigint, bigint, integer, integer, bigint, bigint, bigint, text) TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 2. Registration complete: the four sealed-artifact owner branches.
--
-- Unlike the 000014 worker binds, the owning rows are created by begin() with
-- the artifact ids already set (NOT NULL), so each bind verifies the exact
-- owning row instead of updating a nullable column. The deferred artifact
-- guards of 000006/000007 still validate owner tuple, resource id and
-- plaintext hash at commit; a partial or mismatched artifact set can never
-- commit, and the nonce UNIQUE constraint keeps a replay from re-inserting.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_trust_config_bind(
    p_org text, p_connection_id text, p_revision bigint, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'registration bind is an application-role surface' USING ERRCODE = '42501';
    END IF;
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM app.source_connection_revision_resource_id(p_org, p_connection_id, p_revision) THEN
        RAISE EXCEPTION 'resource id must equal the connection revision resource id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
        ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'source_connection_revision', 'trust_profile_artifact_id',
        'SOURCE_TRUST_CONFIG', p_resource_id, 'TRUST_CONFIG',
        p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash,
        p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    PERFORM 1
    FROM public.source_connection_revision
    WHERE organization_id = p_org AND connection_id = p_connection_id AND revision = p_revision
      AND trust_profile_artifact_id = p_artifact_id AND trust_profile_hash = p_plaintext_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning connection revision missing or trust artifact mismatch' USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_scope_config_bind(
    p_org text, p_source_scope_id text, p_revision bigint, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'registration bind is an application-role surface' USING ERRCODE = '42501';
    END IF;
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM app.source_scope_revision_resource_id(p_org, p_source_scope_id, p_revision) THEN
        RAISE EXCEPTION 'resource id must equal the scope revision resource id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
        ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'source_scope_revision', 'scope_config_artifact_id',
        'SOURCE_SCOPE_CONFIG', p_resource_id, 'SCOPE_CONFIG',
        p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash,
        p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    PERFORM 1
    FROM public.source_scope_revision
    WHERE organization_id = p_org AND source_scope_id = p_source_scope_id AND revision = p_revision
      AND scope_config_artifact_id = p_artifact_id AND scope_config_hash = p_plaintext_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning scope revision missing or scope config artifact mismatch' USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_discovered_scope_identity_bind(
    p_org text, p_discovered_scope_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'registration bind is an application-role surface' USING ERRCODE = '42501';
    END IF;
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    -- encrypted-artifact-aad-v1 defines discovered-scope resource_id as the
    -- generated discovery row ID itself (000007 guard), not a caller value.
    IF p_resource_id IS DISTINCT FROM p_discovered_scope_id THEN
        RAISE EXCEPTION 'resource id must equal the discovered scope row id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
        ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'source_discovered_scope', 'identity_artifact_id',
        'SOURCE_SCOPE_IDENTITY', p_resource_id, 'EXTERNAL_SCOPE_IDENTITY',
        p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash,
        p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    PERFORM 1
    FROM public.source_discovered_scope
    WHERE organization_id = p_org AND id = p_discovered_scope_id
      AND identity_artifact_id = p_artifact_id AND identity_plaintext_hash = p_plaintext_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning discovered scope missing or identity artifact mismatch' USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_discovered_scope_display_bind(
    p_org text, p_discovered_scope_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'registration bind is an application-role surface' USING ERRCODE = '42501';
    END IF;
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM p_discovered_scope_id THEN
        RAISE EXCEPTION 'resource id must equal the discovered scope row id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
        ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'source_discovered_scope', 'display_metadata_artifact_id',
        'SOURCE_SCOPE_METADATA', p_resource_id, 'DISPLAY_METADATA',
        p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash,
        p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    PERFORM 1
    FROM public.source_discovered_scope
    WHERE organization_id = p_org AND id = p_discovered_scope_id
      AND display_metadata_artifact_id = p_artifact_id AND display_metadata_hash = p_plaintext_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning discovered scope missing or display artifact mismatch' USING ERRCODE = '23514';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION app.source_trust_config_bind(text, text, bigint, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.source_scope_config_bind(text, text, bigint, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.source_discovered_scope_identity_bind(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.source_discovered_scope_display_bind(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_trust_config_bind(text, text, bigint, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_scope_config_bind(text, text, bigint, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_discovered_scope_identity_bind(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_discovered_scope_display_bind(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 3. Activation request gate: derived-live confirmation mirror.
--
-- The predicate is the liveness half of the 000010 derived-live guard, asked
-- of a confirmation for the exact scope revision and config hash: the
-- confirmation's workspace must still be on the confirmed revision, the
-- binding must be enabled with the exact tuple, the warning contract must be
-- the current one, and neither revocation type may exist. A confirmation that
-- is foreign, revoked, stale or mismatched can never admit activation
-- (SOURCE_CONTRACTS.md s1).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_scope_activation_confirmed(
    p_source_scope_id text, p_source_scope_revision bigint, p_scope_config_hash text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.workspace_managed_grant_confirmation AS confirmation
        JOIN public.workspace AS workspace
          ON workspace.organization_id = confirmation.organization_id
         AND workspace.id = confirmation.workspace_id
         AND workspace.current_revision = confirmation.workspace_revision
        JOIN public.workspace_revision_source AS binding
          ON binding.organization_id = confirmation.organization_id
         AND binding.workspace_id = confirmation.workspace_id
         AND binding.workspace_revision = confirmation.workspace_revision
         AND binding.workspace_configuration_hash = confirmation.workspace_configuration_hash
         AND binding.workspace_source_id = confirmation.workspace_source_id
         AND binding.source_scope_id = confirmation.source_scope_id
         AND binding.source_scope_revision = confirmation.source_scope_revision
         AND binding.scope_config_hash = confirmation.scope_config_hash
         AND binding.access_mode = confirmation.access_mode
         AND binding.enabled
        JOIN public.workspace_managed_warning_contract AS warning
          ON warning.warning_version = confirmation.warning_version
         AND warning.warning_contract_hash = confirmation.warning_contract_hash
         AND warning.revision = app.workspace_managed_warning_contract_current_revision()
        WHERE confirmation.organization_id = app.current_organization_id()
          AND confirmation.source_scope_id = p_source_scope_id
          AND confirmation.source_scope_revision = p_source_scope_revision
          AND confirmation.scope_config_hash = p_scope_config_hash
          AND confirmation.access_mode = 'WORKSPACE_MANAGED'
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
              WHERE revocation.organization_id = confirmation.organization_id
                AND revocation.confirmation_id = confirmation.confirmation_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS grant_revocation
              WHERE grant_revocation.organization_id = confirmation.organization_id
                AND grant_revocation.grant_id = confirmation.confirmation_actor_grant_id
                AND grant_revocation.grant_revision = confirmation.confirmation_actor_grant_revision
          )
    );
$$;

REVOKE ALL ON FUNCTION app.source_scope_activation_confirmed(text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_scope_activation_confirmed(text, bigint, text) TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4. Workspace source status: the typed D3-3 surface.
--
-- Member-only and always resolved against the workspace's current revision:
-- a stale caller can never observe another revision's bindings. Activation,
-- trust and sync columns come from the same projections the pipeline itself
-- uses (sync_target's trust predicate, the sync_run bookkeeping table), so
-- the surface reports exactly what the pipeline will do, with typed error
-- codes and never source content.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.workspace_source_status(p_workspace_id text)
RETURNS TABLE(
    source_scope_id text,
    source_scope_revision bigint,
    access_mode text,
    enabled boolean,
    scope_config_hash text,
    connection_id text,
    connection_name text,
    activation_status text,
    trust_verified boolean,
    sync_status text,
    sync_error_code text,
    sync_started_at timestamptz,
    sync_completed_at timestamptz,
    objects_seen bigint,
    objects_ingested bigint,
    versions_created bigint,
    evidence_published bigint,
    quarantined bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT binding.source_scope_id, binding.source_scope_revision, binding.access_mode, binding.enabled,
           binding.scope_config_hash, scope.connection_id, connection.name,
           activation.status,
           EXISTS (
               SELECT 1
               FROM public.source_connection_trust_record AS trust_record
               JOIN public.source_connection_trust_projection AS projection
                 ON projection.organization_id = trust_record.organization_id
                AND projection.trust_record_id = trust_record.id
               JOIN public.source_scope_revision AS scope_revision
                 ON scope_revision.organization_id = trust_record.organization_id
                AND scope_revision.connection_id = trust_record.connection_id
                AND scope_revision.connection_revision = trust_record.connection_revision
               JOIN public.source_connection_revision AS connection_revision
                 ON connection_revision.organization_id = scope_revision.organization_id
                AND connection_revision.connection_id = scope_revision.connection_id
                AND connection_revision.revision = scope_revision.connection_revision
                AND connection_revision.trust_profile_hash = trust_record.trust_profile_hash
               WHERE scope_revision.organization_id = binding.organization_id
                 AND scope_revision.source_scope_id = binding.source_scope_id
                 AND scope_revision.revision = binding.source_scope_revision
                 AND projection.status = 'VERIFIED'
           ),
           sync_run.status, sync_run.error_code, sync_run.started_at, sync_run.completed_at,
           sync_run.objects_seen, sync_run.objects_ingested, sync_run.versions_created,
           sync_run.evidence_published, sync_run.quarantined
    FROM public.workspace_revision_source AS binding
    JOIN public.source_scope AS scope
      ON scope.organization_id = binding.organization_id AND scope.id = binding.source_scope_id
    JOIN public.source_connection AS connection
      ON connection.organization_id = binding.organization_id AND connection.id = scope.connection_id
    JOIN public.source_scope_activation AS activation
      ON activation.organization_id = binding.organization_id
     AND activation.source_scope_id = binding.source_scope_id
     AND activation.source_scope_revision = binding.source_scope_revision
    LEFT JOIN LATERAL (
        SELECT run.status, run.error_code, run.started_at, run.completed_at,
               run.objects_seen, run.objects_ingested, run.versions_created,
               run.evidence_published, run.quarantined
        FROM public.sync_run AS run
        WHERE run.organization_id = binding.organization_id
          AND run.source_scope_id = binding.source_scope_id
          AND run.source_scope_revision = binding.source_scope_revision
        ORDER BY run.started_at DESC, run.id DESC
        LIMIT 1
    ) AS sync_run ON true
    WHERE binding.organization_id = app.current_organization_id()
      AND binding.workspace_id = p_workspace_id
      AND binding.workspace_revision = (
          SELECT workspace.current_revision
          FROM public.workspace
          WHERE workspace.organization_id = app.current_organization_id()
            AND workspace.id = p_workspace_id
      )
      AND EXISTS (
          SELECT 1 FROM public.workspace_member AS member
          WHERE member.organization_id = app.current_organization_id()
            AND member.workspace_id = p_workspace_id
            AND member.principal_id = app.current_principal_id()
            AND member.removed_at IS NULL
      )
    ORDER BY binding.source_scope_id;
$$;

REVOKE ALL ON FUNCTION app.workspace_source_status(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.workspace_source_status(text) TO knowvault_app;

-- The app role must not EXECUTE the 000006/000007 resource-id derivations
-- directly (the 000007 fail-closed test pins that absence), yet the runtime
-- has to know the expected resource id before sealing the artifacts that the
-- SECURITY DEFINER binds then verify. The registration surface therefore
-- exposes thin SECURITY DEFINER wrappers: they forward to the canonical
-- derivations from the owner side, behind the same application-role check as
-- the binds. The wrapper also pins the passed organization to the session
-- tenant, so a caller can never derive an id for a foreign organization
-- (the resource id is only meaningful inside the caller's own tenant).
CREATE OR REPLACE FUNCTION app.registration_connection_resource_id(
    p_org text, p_connection_id text, p_revision bigint
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'registration resource id is an application-role surface' USING ERRCODE = '42501';
    END IF;
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'registration resource id is only derivable for the session tenant' USING ERRCODE = '42501';
    END IF;
    RETURN app.source_connection_revision_resource_id(p_org, p_connection_id, p_revision);
END;
$$;

CREATE OR REPLACE FUNCTION app.registration_scope_resource_id(
    p_org text, p_source_scope_id text, p_revision bigint
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'registration resource id is an application-role surface' USING ERRCODE = '42501';
    END IF;
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'registration resource id is only derivable for the session tenant' USING ERRCODE = '42501';
    END IF;
    RETURN app.source_scope_revision_resource_id(p_org, p_source_scope_id, p_revision);
END;
$$;

-- The registration surface (app role) is a new consumer of two activation-time
-- gates of 000014 and the two wrappers above; the original migrations grant
-- them to PUBLIC revocation only or to the worker role alone. Least privilege
-- is preserved — the app role receives exactly these four, nothing else.
GRANT EXECUTE ON FUNCTION
    app.registration_connection_resource_id(text, text, bigint),
    app.registration_scope_resource_id(text, text, bigint),
    app.source_scope_pending_revision(text),
    app.source_scope_sync_target(text, bigint)
TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 5. Registered activation begin: the worker-side TOCTOU closure.
--
-- The activation request checks the derived-live confirmation, but the sync
-- that follows runs later, as a claimed job. Between the request and the claim
-- a confirmation can be revoked; without a re-check at claim time the worker
-- would begin a sync whose grant was already withdrawn. The worker surface
-- therefore re-checks the exact-tuple confirmation inside the same fence as
-- the begin_sync cutover, resolving the hash from the sync target (the very
-- tuple the app role's request gate used) so a stale or mismatched hash can
-- never pass. REVOKE-then-GRANT keeps the surface out of PUBLIC, exactly like
-- every worker-side SECURITY DEFINER primitive (000014/000016).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_scope_registered_begin_sync(
    p_scope_id text, p_revision bigint, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    target record;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'registered begin sync is a worker surface' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO target FROM app.source_scope_sync_target(p_scope_id, p_revision);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope revision not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT app.source_scope_activation_confirmed(p_scope_id, p_revision, target.scope_config_hash) THEN
        RAISE EXCEPTION 'scope confirmation is not live at claim time' USING ERRCODE = '55000';
    END IF;
    PERFORM app.source_scope_begin_sync(p_scope_id, p_revision, p_job_id, p_worker, p_epoch);
END;
$$;

REVOKE ALL ON FUNCTION app.source_scope_registered_begin_sync(text, bigint, text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_scope_registered_begin_sync(text, bigint, text, text, bigint) TO knowvault_worker;
