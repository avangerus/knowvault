-- Stage 2 source control-plane draft.
--
-- This checkpoint records connector capabilities, immutable connection
-- revisions and fail-closed trust metadata.  It deliberately introduces no
-- activation authority: active_revision is always NULL and every trust
-- projection is DRAFT.  The shared application role can inspect these rows
-- through tenant RLS but cannot create, change, delete, or execute anything.

BEGIN;

CREATE OR REPLACE FUNCTION app.source_generated_id_is_valid(value text, prefix_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND value ~ ('^' || prefix_value || '_[0-7][0-9A-HJKMNP-TV-Z]{25}$');
$$;

CREATE OR REPLACE FUNCTION app.source_access_modes_are_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND jsonb_typeof(value) = 'array'
       AND jsonb_array_length(value) BETWEEN 1 AND 2
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_array_elements(value) AS mode(item)
           WHERE jsonb_typeof(item) <> 'string'
              OR item #>> '{}' NOT IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')
       )
       AND jsonb_array_length(value) = (
           SELECT count(DISTINCT item #>> '{}')
           FROM jsonb_array_elements(value) AS mode(item)
       );
$$;

-- This is the canonical JSON hash used as encrypted_artifact.resource_id for
-- SourceConnectionRevision.  Keys are UTF-8, lexicographically ordered, and
-- emitted without insignificant whitespace.
CREATE OR REPLACE FUNCTION app.source_connection_revision_resource_id(
    organization_value text,
    connection_value text,
    revision_value bigint
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT 'sha256:' || encode(sha256(convert_to(
        '{"connection_id":' || to_json(connection_value)::text ||
        ',"organization_id":' || to_json(organization_value)::text ||
        ',"revision":' || revision_value::text || '}',
        'UTF8'
    )), 'hex');
$$;

CREATE TABLE public.connector_capability_profile (
    id text PRIMARY KEY CHECK (app.stage2_opaque_id_is_valid(id)),
    profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(profile_hash)),
    connector_build_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(connector_build_id)),
    connector_type text NOT NULL CHECK (connector_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    connector_version text NOT NULL CHECK (
        char_length(connector_version) BETWEEN 1 AND 128
        AND btrim(connector_version) = connector_version
        AND connector_version !~ '[[:cntrl:]]'
    ),
    connector_artifact_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(connector_artifact_hash)),
    stable_object_ids boolean NOT NULL,
    native_versions boolean NOT NULL,
    incremental_cursor boolean NOT NULL,
    webhooks boolean NOT NULL,
    item_level_acl boolean NOT NULL,
    acl_refresh boolean NOT NULL,
    historical_versions boolean NOT NULL,
    deep_links boolean NOT NULL,
    deletion_events boolean NOT NULL,
    local_extraction boolean NOT NULL,
    contract_suite_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(contract_suite_hash)),
    verified_at timestamptz NOT NULL,
    UNIQUE (
        id, profile_hash, connector_build_id, connector_type,
        connector_version, connector_artifact_hash,
        contract_suite_hash, verified_at
    )
);

CREATE TABLE public.source_connection (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    type text NOT NULL CHECK (type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    name text NOT NULL CHECK (
        char_length(name) BETWEEN 1 AND 256
        AND btrim(name) = name
        AND name !~ '[[:cntrl:]]'
    ),
    latest_revision bigint NOT NULL CHECK (latest_revision > 0),
    active_revision bigint CHECK (active_revision IS NULL),
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_connection_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    UNIQUE (organization_id, id, type)
);

CREATE TABLE public.source_connection_revision (
    organization_id text NOT NULL,
    connection_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    credential_reference text NOT NULL
        CHECK (app.source_generated_id_is_valid(credential_reference, 'cred')),
    connector_build_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(connector_build_id)),
    connector_type text NOT NULL CHECK (connector_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    capability_profile_id text NOT NULL,
    capability_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(capability_profile_hash)),
    connector_agent_id text
        CHECK (connector_agent_id IS NULL OR app.source_generated_id_is_valid(connector_agent_id, 'agent')),
    execution_target text NOT NULL CHECK (execution_target IN ('CENTRAL_WORKER', 'CONNECTOR_AGENT')),
    connector_agent_binding_id text GENERATED ALWAYS AS (coalesce(connector_agent_id, 'CENTRAL_WORKER')) STORED,
    trust_record_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(trust_record_id)),
    trust_profile_artifact_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(trust_profile_artifact_id)),
    trust_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(trust_profile_hash)),
    connector_version text NOT NULL CHECK (
        char_length(connector_version) BETWEEN 1 AND 128
        AND btrim(connector_version) = connector_version
        AND connector_version !~ '[[:cntrl:]]'
    ),
    connector_artifact_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(connector_artifact_hash)),
    connector_contract_suite_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(connector_contract_suite_hash)),
    connector_verified_at timestamptz NOT NULL,
    allowed_access_modes_json jsonb NOT NULL CHECK (app.source_access_modes_are_valid(allowed_access_modes_json)),
    max_scope_objects bigint NOT NULL CHECK (max_scope_objects BETWEEN 1 AND 9007199254740991),
    max_scope_bytes bigint NOT NULL CHECK (max_scope_bytes BETWEEN 1 AND 9007199254740991),
    max_object_bytes bigint NOT NULL CHECK (max_object_bytes BETWEEN 1 AND max_scope_bytes),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, connection_id, revision),
    CONSTRAINT source_connection_revision_connection_fk
        FOREIGN KEY (organization_id, connection_id, connector_type)
        REFERENCES public.source_connection (organization_id, id, type)
        ON DELETE RESTRICT,
    CONSTRAINT source_connection_revision_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_connection_revision_capability_fk
        FOREIGN KEY (
            capability_profile_id, capability_profile_hash,
            connector_build_id, connector_type, connector_version,
            connector_artifact_hash, connector_contract_suite_hash,
            connector_verified_at
        ) REFERENCES public.connector_capability_profile (
            id, profile_hash, connector_build_id, connector_type,
            connector_version, connector_artifact_hash,
            contract_suite_hash, verified_at
        ) ON DELETE RESTRICT,
    CONSTRAINT source_connection_revision_artifact_fk
        FOREIGN KEY (organization_id, trust_profile_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (execution_target = 'CENTRAL_WORKER' AND connector_agent_id IS NULL)
        OR
        (execution_target = 'CONNECTOR_AGENT' AND connector_agent_id IS NOT NULL)
    )
);

CREATE TABLE public.source_connection_trust_record (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    connection_id text NOT NULL,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    connector_agent_id text
        CHECK (connector_agent_id IS NULL OR app.source_generated_id_is_valid(connector_agent_id, 'agent')),
    execution_target text NOT NULL CHECK (execution_target IN ('CENTRAL_WORKER', 'CONNECTOR_AGENT')),
    connector_agent_binding_id text GENERATED ALWAYS AS (coalesce(connector_agent_id, 'CENTRAL_WORKER')) STORED,
    trust_profile_artifact_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(trust_profile_artifact_id)),
    trust_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(trust_profile_hash)),
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > verified_at),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_connection_trust_revision_fk
        FOREIGN KEY (organization_id, connection_id, connection_revision)
        REFERENCES public.source_connection_revision (organization_id, connection_id, revision)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_connection_trust_artifact_fk
        FOREIGN KEY (organization_id, trust_profile_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (
        organization_id, id, connection_id, connection_revision,
        connector_agent_binding_id, execution_target,
        trust_profile_artifact_id, trust_profile_hash, verified_at
    ),
    CHECK (
        (execution_target = 'CENTRAL_WORKER' AND connector_agent_id IS NULL)
        OR
        (execution_target = 'CONNECTOR_AGENT' AND connector_agent_id IS NOT NULL)
    )
);

CREATE TABLE public.source_connection_trust_projection (
    organization_id text NOT NULL,
    trust_record_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision = 1),
    status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT'),
    changed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, trust_record_id, revision),
    CONSTRAINT source_connection_trust_projection_record_fk
        FOREIGN KEY (organization_id, trust_record_id)
        REFERENCES public.source_connection_trust_record (organization_id, id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION app.source_connection_revision_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    artifact public.encrypted_artifact%ROWTYPE;
BEGIN
    SELECT * INTO artifact
    FROM public.encrypted_artifact
    WHERE organization_id = NEW.organization_id
      AND id = NEW.trust_profile_artifact_id;

    IF NOT FOUND
       OR artifact.owner_table <> 'source_connection_revision'
       OR artifact.owner_column <> 'trust_profile_artifact_id'
       OR artifact.resource_type <> 'SOURCE_TRUST_CONFIG'
       OR artifact.resource_id <> app.source_connection_revision_resource_id(
              NEW.organization_id, NEW.connection_id, NEW.revision)
       OR artifact.field_name <> 'TRUST_CONFIG'
       OR artifact.plaintext_hash <> NEW.trust_profile_hash
       OR artifact.purged_at IS NOT NULL THEN
        RAISE EXCEPTION 'trust profile artifact must exactly own the connection revision and plaintext hash'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_connection_revision_artifact_exact
AFTER INSERT OR UPDATE ON public.source_connection_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_connection_revision_artifact_guard();

CREATE OR REPLACE FUNCTION app.source_connection_latest_revision_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.source_connection_revision
        WHERE organization_id = NEW.organization_id
          AND connection_id = NEW.id
          AND revision = NEW.latest_revision
    ) THEN
        RAISE EXCEPTION 'source connection latest lineage must resolve to an exact revision'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_connection_latest_revision_exact
AFTER INSERT OR UPDATE OF latest_revision ON public.source_connection
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_connection_latest_revision_guard();

CREATE OR REPLACE FUNCTION app.source_connection_revision_trust_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.source_connection_trust_record
        WHERE organization_id = NEW.organization_id
          AND id = NEW.trust_record_id
          AND connection_id = NEW.connection_id
          AND connection_revision = NEW.revision
          AND connector_agent_binding_id = NEW.connector_agent_binding_id
          AND execution_target = NEW.execution_target
          AND trust_profile_artifact_id = NEW.trust_profile_artifact_id
          AND trust_profile_hash = NEW.trust_profile_hash
          AND verified_at = NEW.connector_verified_at
    ) THEN
        RAISE EXCEPTION 'connection revision must resolve to its exact trust tuple'
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_connection_revision_trust_exact
AFTER INSERT OR UPDATE ON public.source_connection_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_connection_revision_trust_guard();

CREATE OR REPLACE FUNCTION app.source_immutable_or_hard_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION '% is immutable', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF session_user = 'knowvault_app'
       OR NOT EXISTS (
           SELECT 1 FROM public.organization
           WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
       ) THEN
        RAISE EXCEPTION '% deletion requires tenant hard-delete state', TG_TABLE_NAME
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_connection_parent_guard()
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
            RAISE EXCEPTION 'source connection deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.type IS DISTINCT FROM OLD.type
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.active_revision IS NOT NULL
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.latest_revision <= OLD.latest_revision THEN
        RAISE EXCEPTION 'source connection permits only forward latest lineage'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.connector_capability_profile_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'connector capability profiles are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER connector_capability_profile_immutable
BEFORE UPDATE OR DELETE ON public.connector_capability_profile
FOR EACH ROW EXECUTE FUNCTION app.connector_capability_profile_immutable_guard();

CREATE TRIGGER source_connection_parent_state_guard
BEFORE UPDATE OR DELETE ON public.source_connection
FOR EACH ROW EXECUTE FUNCTION app.source_connection_parent_guard();

CREATE TRIGGER source_connection_revision_immutable
BEFORE UPDATE OR DELETE ON public.source_connection_revision
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

CREATE TRIGGER source_connection_trust_record_immutable
BEFORE UPDATE OR DELETE ON public.source_connection_trust_record
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

CREATE TRIGGER source_connection_trust_projection_immutable
BEFORE UPDATE OR DELETE ON public.source_connection_trust_projection
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.source_connection ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_connection FORCE ROW LEVEL SECURITY;
CREATE POLICY source_connection_tenant_isolation ON public.source_connection
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.source_connection_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_connection_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY source_connection_revision_tenant_isolation ON public.source_connection_revision
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.source_connection_trust_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_connection_trust_record FORCE ROW LEVEL SECURITY;
CREATE POLICY source_connection_trust_record_tenant_isolation ON public.source_connection_trust_record
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.source_connection_trust_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_connection_trust_projection FORCE ROW LEVEL SECURITY;
CREATE POLICY source_connection_trust_projection_tenant_isolation ON public.source_connection_trust_projection
    USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE
    public.connector_capability_profile,
    public.source_connection,
    public.source_connection_revision,
    public.source_connection_trust_record,
    public.source_connection_trust_projection
FROM PUBLIC;

GRANT SELECT ON TABLE
    public.connector_capability_profile,
    public.source_connection,
    public.source_connection_revision,
    public.source_connection_trust_record,
    public.source_connection_trust_projection
TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.source_generated_id_is_valid(text, text),
    app.source_access_modes_are_valid(jsonb),
    app.source_connection_revision_resource_id(text, text, bigint),
    app.source_connection_revision_artifact_guard(),
    app.source_connection_latest_revision_guard(),
    app.source_connection_revision_trust_guard(),
    app.source_immutable_or_hard_delete_guard(),
    app.source_connection_parent_guard(),
    app.connector_capability_profile_immutable_guard()
FROM PUBLIC;

COMMIT;
