-- Stage 2 source-scope control-plane draft.
--
-- Discovery identities and scope configuration remain encrypted artifacts.
-- These rows are deliberately inert: parents have no active revision and the
-- only activation projection is DRAFT.  No downstream data-plane authority is
-- introduced by this checkpoint.

BEGIN;

CREATE OR REPLACE FUNCTION app.source_keyed_digest_matches_version(value text, key_version_value bigint)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND key_version_value BETWEEN 1 AND 999999999
       AND value ~ ('^hmac-sha256:k' || key_version_value::text || ':[0-9a-f]{64}$');
$$;

CREATE OR REPLACE FUNCTION app.source_scope_revision_resource_id(
    organization_value text,
    source_scope_value text,
    revision_value bigint
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT 'sha256:' || encode(sha256(convert_to(
        '{"organization_id":' || to_json(organization_value)::text ||
        ',"revision":' || revision_value::text ||
        ',"source_scope_id":' || to_json(source_scope_value)::text || '}',
        'UTF8'
    )), 'hex');
$$;

-- Needed for exact source-type coupling from discovery and scope revisions.
ALTER TABLE public.source_connection_revision
    ADD CONSTRAINT source_connection_revision_exact_type_key
    UNIQUE (organization_id, connection_id, revision, connector_type);

CREATE TABLE public.source_discovered_scope (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'discovered')),
    connection_id text NOT NULL,
    connection_revision bigint NOT NULL CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    source_type text NOT NULL CHECK (source_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    identity_digest text NOT NULL,
    identity_digest_key_version bigint NOT NULL CHECK (
        app.source_keyed_digest_matches_version(identity_digest, identity_digest_key_version)
    ),
    identity_artifact_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(identity_artifact_id)),
    identity_plaintext_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(identity_plaintext_hash)),
    display_metadata_artifact_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(display_metadata_artifact_id)),
    display_metadata_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(display_metadata_hash)),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status = 'ACTIVE'),
    discovered_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    removed_at timestamptz CHECK (removed_at IS NULL),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_discovered_scope_connection_revision_fk
        FOREIGN KEY (organization_id, connection_id, connection_revision, source_type)
        REFERENCES public.source_connection_revision (
            organization_id, connection_id, revision, connector_type
        ) ON DELETE RESTRICT,
    CONSTRAINT source_discovered_scope_identity_artifact_fk
        FOREIGN KEY (organization_id, identity_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_discovered_scope_display_artifact_fk
        FOREIGN KEY (organization_id, display_metadata_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (organization_id, id, connection_id, source_type),
    UNIQUE (
        organization_id, connection_id, connection_revision,
        identity_digest_key_version, identity_digest
    ),
    UNIQUE (
        organization_id, id, connection_id, connection_revision, source_type,
        identity_digest, identity_digest_key_version
    )
);

CREATE TABLE public.source_scope (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'scope')),
    connection_id text NOT NULL,
    discovered_scope_id text NOT NULL,
    source_type text NOT NULL CHECK (source_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    latest_revision bigint NOT NULL CHECK (latest_revision BETWEEN 1 AND 9007199254740991),
    active_revision bigint CHECK (active_revision IS NULL),
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_scope_discovery_fk
        FOREIGN KEY (organization_id, discovered_scope_id, connection_id, source_type)
        REFERENCES public.source_discovered_scope (
            organization_id, id, connection_id, source_type
        ) ON DELETE RESTRICT,
    CONSTRAINT source_scope_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    UNIQUE (organization_id, id, connection_id, discovered_scope_id, source_type)
);

CREATE TABLE public.source_scope_revision (
    organization_id text NOT NULL,
    source_scope_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    connection_id text NOT NULL,
    connection_revision bigint NOT NULL CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    discovered_scope_id text NOT NULL,
    discovered_identity_digest text NOT NULL,
    discovered_identity_digest_key_version bigint NOT NULL CHECK (
        app.source_keyed_digest_matches_version(
            discovered_identity_digest, discovered_identity_digest_key_version)
    ),
    source_type text NOT NULL CHECK (source_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    scope_config_artifact_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(scope_config_artifact_id)),
    scope_config_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(scope_config_hash)),
    scope_contract_version text NOT NULL DEFAULT '1.2' CHECK (scope_contract_version = '1.2'),
    access_mode text NOT NULL CHECK (access_mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')),
    sync_interval_seconds integer NOT NULL CHECK (sync_interval_seconds BETWEEN 60 AND 86400),
    content_freshness_sla_seconds integer NOT NULL CHECK (
        content_freshness_sla_seconds BETWEEN 60 AND 604800
    ),
    acl_freshness_sla_seconds integer CHECK (
        acl_freshness_sla_seconds IS NULL
        OR acl_freshness_sla_seconds BETWEEN 60 AND 86400
    ),
    object_limit bigint NOT NULL CHECK (object_limit BETWEEN 1 AND 10000000),
    byte_limit bigint NOT NULL CHECK (byte_limit BETWEEN 1 AND 9007199254740991),
    max_object_bytes bigint NOT NULL CHECK (
        max_object_bytes BETWEEN 1 AND byte_limit
    ),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, source_scope_id, revision),
    CONSTRAINT source_scope_revision_parent_fk
        FOREIGN KEY (
            organization_id, source_scope_id, connection_id,
            discovered_scope_id, source_type
        ) REFERENCES public.source_scope (
            organization_id, id, connection_id, discovered_scope_id, source_type
        ) ON DELETE RESTRICT,
    CONSTRAINT source_scope_revision_connection_fk
        FOREIGN KEY (organization_id, connection_id, connection_revision, source_type)
        REFERENCES public.source_connection_revision (
            organization_id, connection_id, revision, connector_type
        ) ON DELETE RESTRICT,
    CONSTRAINT source_scope_revision_discovery_fk
        FOREIGN KEY (
            organization_id, discovered_scope_id, connection_id,
            connection_revision, source_type, discovered_identity_digest,
            discovered_identity_digest_key_version
        ) REFERENCES public.source_discovered_scope (
            organization_id, id, connection_id, connection_revision, source_type,
            identity_digest, identity_digest_key_version
        ) ON DELETE RESTRICT,
    CONSTRAINT source_scope_revision_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_scope_revision_config_artifact_fk
        FOREIGN KEY (organization_id, scope_config_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (access_mode <> 'SOURCE_ENFORCED' OR acl_freshness_sla_seconds IS NOT NULL)
);

CREATE TABLE public.source_scope_activation (
    organization_id text NOT NULL,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    revision bigint NOT NULL CHECK (revision = 1),
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT'),
    changed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    activated_at timestamptz CHECK (activated_at IS NULL),
    PRIMARY KEY (organization_id, source_scope_id, source_scope_revision, revision),
    CONSTRAINT source_scope_activation_revision_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (
            organization_id, source_scope_id, revision
        ) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION app.source_discovered_scope_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    identity_artifact public.encrypted_artifact%ROWTYPE;
    display_artifact public.encrypted_artifact%ROWTYPE;
    expected_resource_id text;
BEGIN
    -- encrypted-artifact-aad-v1 defines discovered-scope resource_id as the
    -- generated discovery row ID itself, not a caller-controlled native ID.
    expected_resource_id := NEW.id;

    SELECT * INTO identity_artifact FROM public.encrypted_artifact
    WHERE organization_id = NEW.organization_id AND id = NEW.identity_artifact_id;
    IF NOT FOUND
       OR identity_artifact.owner_table <> 'source_discovered_scope'
       OR identity_artifact.owner_column <> 'identity_artifact_id'
       OR identity_artifact.resource_type <> 'SOURCE_SCOPE_IDENTITY'
       OR identity_artifact.resource_id <> expected_resource_id
       OR identity_artifact.field_name <> 'EXTERNAL_SCOPE_IDENTITY'
       OR identity_artifact.plaintext_hash <> NEW.identity_plaintext_hash
       OR identity_artifact.purged_at IS NOT NULL THEN
        RAISE EXCEPTION 'discovery identity artifact does not exactly own the row'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO display_artifact FROM public.encrypted_artifact
    WHERE organization_id = NEW.organization_id AND id = NEW.display_metadata_artifact_id;
    IF NOT FOUND
       OR display_artifact.owner_table <> 'source_discovered_scope'
       OR display_artifact.owner_column <> 'display_metadata_artifact_id'
       OR display_artifact.resource_type <> 'SOURCE_SCOPE_METADATA'
       OR display_artifact.resource_id <> expected_resource_id
       OR display_artifact.field_name <> 'DISPLAY_METADATA'
       OR display_artifact.plaintext_hash <> NEW.display_metadata_hash
       OR display_artifact.purged_at IS NOT NULL THEN
        RAISE EXCEPTION 'discovery display artifact does not exactly own the row'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_discovered_scope_artifact_exact
AFTER INSERT OR UPDATE ON public.source_discovered_scope
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_discovered_scope_artifact_guard();

CREATE OR REPLACE FUNCTION app.source_scope_revision_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    artifact public.encrypted_artifact%ROWTYPE;
BEGIN
    SELECT * INTO artifact FROM public.encrypted_artifact
    WHERE organization_id = NEW.organization_id AND id = NEW.scope_config_artifact_id;
    IF NOT FOUND
       OR artifact.owner_table <> 'source_scope_revision'
       OR artifact.owner_column <> 'scope_config_artifact_id'
       OR artifact.resource_type <> 'SOURCE_SCOPE_CONFIG'
       OR artifact.resource_id <> app.source_scope_revision_resource_id(
            NEW.organization_id, NEW.source_scope_id, NEW.revision)
       OR artifact.field_name <> 'SCOPE_CONFIG'
       OR artifact.plaintext_hash <> NEW.scope_config_hash
       OR artifact.purged_at IS NOT NULL THEN
        RAISE EXCEPTION 'scope config artifact does not exactly own the revision'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_scope_revision_artifact_exact
AFTER INSERT OR UPDATE ON public.source_scope_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_scope_revision_artifact_guard();

CREATE OR REPLACE FUNCTION app.source_scope_revision_policy_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    connection_revision public.source_connection_revision%ROWTYPE;
    capability public.connector_capability_profile%ROWTYPE;
    discovery_identity_purged_at timestamptz;
    discovery_display_purged_at timestamptz;
BEGIN
    SELECT * INTO connection_revision
    FROM public.source_connection_revision
    WHERE organization_id = NEW.organization_id
      AND connection_id = NEW.connection_id
      AND revision = NEW.connection_revision
      AND connector_type = NEW.source_type;
    IF NOT FOUND
       OR NOT (connection_revision.allowed_access_modes_json @> jsonb_build_array(NEW.access_mode))
       OR NEW.object_limit > connection_revision.max_scope_objects
       OR NEW.byte_limit > connection_revision.max_scope_bytes
       OR NEW.max_object_bytes > connection_revision.max_object_bytes THEN
        RAISE EXCEPTION 'scope exceeds exact connection revision access mode or limits'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO capability
    FROM public.connector_capability_profile
    WHERE id = connection_revision.capability_profile_id
      AND profile_hash = connection_revision.capability_profile_hash
      AND connector_build_id = connection_revision.connector_build_id
      AND connector_type = connection_revision.connector_type
      AND connector_version = connection_revision.connector_version
      AND connector_artifact_hash = connection_revision.connector_artifact_hash
      AND contract_suite_hash = connection_revision.connector_contract_suite_hash
      AND verified_at = connection_revision.connector_verified_at;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'exact connection capability profile is missing' USING ERRCODE = '23503';
    END IF;
    IF NEW.access_mode = 'SOURCE_ENFORCED'
       AND NOT (capability.stable_object_ids AND capability.item_level_acl AND capability.acl_refresh) THEN
        RAISE EXCEPTION 'SOURCE_ENFORCED requires stable IDs, item ACL and ACL refresh'
            USING ERRCODE = '23514';
    END IF;

    SELECT identity_artifact.purged_at, display_artifact.purged_at
    INTO discovery_identity_purged_at, discovery_display_purged_at
    FROM public.source_discovered_scope AS discovery
    JOIN public.encrypted_artifact AS identity_artifact
      ON identity_artifact.organization_id = discovery.organization_id
     AND identity_artifact.id = discovery.identity_artifact_id
    JOIN public.encrypted_artifact AS display_artifact
      ON display_artifact.organization_id = discovery.organization_id
     AND display_artifact.id = discovery.display_metadata_artifact_id
    WHERE discovery.organization_id = NEW.organization_id
      AND discovery.id = NEW.discovered_scope_id
      AND discovery.connection_id = NEW.connection_id
      AND discovery.connection_revision = NEW.connection_revision
      AND discovery.source_type = NEW.source_type
      AND discovery.identity_digest = NEW.discovered_identity_digest
      AND discovery.identity_digest_key_version = NEW.discovered_identity_digest_key_version;
    IF NOT FOUND OR discovery_identity_purged_at IS NOT NULL OR discovery_display_purged_at IS NOT NULL THEN
        RAISE EXCEPTION 'scope revision requires live exact discovery artifacts'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_scope_revision_policy_exact
AFTER INSERT OR UPDATE ON public.source_scope_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_scope_revision_policy_guard();

CREATE OR REPLACE FUNCTION app.source_scope_latest_revision_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.source_scope_revision
        WHERE organization_id = NEW.organization_id
          AND source_scope_id = NEW.id
          AND revision = NEW.latest_revision
    ) THEN
        RAISE EXCEPTION 'source scope latest lineage must resolve to an exact revision'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_scope_latest_revision_exact
AFTER INSERT OR UPDATE OF latest_revision ON public.source_scope
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_scope_latest_revision_guard();

CREATE OR REPLACE FUNCTION app.source_scope_parent_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'source scope deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.discovered_scope_id IS DISTINCT FROM OLD.discovered_scope_id
       OR NEW.source_type IS DISTINCT FROM OLD.source_type
       OR NEW.active_revision IS NOT NULL
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.latest_revision <= OLD.latest_revision THEN
        RAISE EXCEPTION 'source scope permits only forward latest lineage'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_discovered_scope_immutable
BEFORE UPDATE OR DELETE ON public.source_discovered_scope
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

CREATE TRIGGER source_scope_parent_state_guard
BEFORE UPDATE OR DELETE ON public.source_scope
FOR EACH ROW EXECUTE FUNCTION app.source_scope_parent_guard();

CREATE TRIGGER source_scope_revision_immutable
BEFORE UPDATE OR DELETE ON public.source_scope_revision
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

CREATE TRIGGER source_scope_activation_immutable
BEFORE UPDATE OR DELETE ON public.source_scope_activation
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.source_discovered_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_discovered_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY source_discovered_scope_tenant_isolation ON public.source_discovered_scope
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.source_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY source_scope_tenant_isolation ON public.source_scope
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.source_scope_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_scope_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY source_scope_revision_tenant_isolation ON public.source_scope_revision
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.source_scope_activation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_scope_activation FORCE ROW LEVEL SECURITY;
CREATE POLICY source_scope_activation_tenant_isolation ON public.source_scope_activation
    USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE
    public.source_discovered_scope,
    public.source_scope,
    public.source_scope_revision,
    public.source_scope_activation
FROM PUBLIC;

GRANT SELECT ON TABLE
    public.source_discovered_scope,
    public.source_scope,
    public.source_scope_revision,
    public.source_scope_activation
TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.source_keyed_digest_matches_version(text, bigint),
    app.source_scope_revision_resource_id(text, text, bigint),
    app.source_discovered_scope_artifact_guard(),
    app.source_scope_revision_artifact_guard(),
    app.source_scope_revision_policy_guard(),
    app.source_scope_latest_revision_guard(),
    app.source_scope_parent_guard()
FROM PUBLIC;

COMMIT;
