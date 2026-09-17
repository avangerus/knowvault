-- Stage 4 source onboarding storage.
--
-- This migration adds a connection-revision-bound metadata discovery request
-- and its encrypted, immutable terminal result. The parent source connection
-- stays DRAFT and no scope, activation, workspace binding or source row is
-- created here. A request is enqueued through the existing lease-fenced job
-- queue with one opaque request ID; only knowvault_worker may advance the
-- request and bind/read its encrypted metadata.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'required runtime role knowvault_app does not exist';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_worker') THEN
        RAISE EXCEPTION 'required worker role knowvault_worker does not exist';
    END IF;
END;
$$;

-- The AAD owner inventory is closed. This forward definition preserves every
-- earlier branch and adds exactly one owner for the discovery result.
CREATE OR REPLACE FUNCTION app.encrypted_artifact_owner_is_valid(
    owner_table_value text,
    owner_column_value text,
    resource_type_value text,
    field_value text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT (owner_table_value, owner_column_value, resource_type_value, field_value) IN (
        ('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT'),
        ('source_connection_revision', 'trust_profile_artifact_id', 'SOURCE_TRUST_CONFIG', 'TRUST_CONFIG'),
        ('source_discovery_result', 'metadata_artifact_id', 'SOURCE_DISCOVERY_RESULT', 'DISCOVERY_METADATA'),
        ('source_discovered_scope', 'identity_artifact_id', 'SOURCE_SCOPE_IDENTITY', 'EXTERNAL_SCOPE_IDENTITY'),
        ('source_discovered_scope', 'display_metadata_artifact_id', 'SOURCE_SCOPE_METADATA', 'DISPLAY_METADATA'),
        ('source_scope_revision', 'scope_config_artifact_id', 'SOURCE_SCOPE_CONFIG', 'SCOPE_CONFIG'),
        ('source_object', 'external_object_id_artifact_id', 'SOURCE_OBJECT_ID', 'EXTERNAL_OBJECT_ID'),
        ('source_object', 'canonical_locator_artifact_id', 'SOURCE_LOCATOR', 'CANONICAL_LOCATOR'),
        ('source_object', 'title_artifact_id', 'SOURCE_TITLE', 'DISPLAY_TITLE'),
        ('acl_snapshot', 'principal_tokens_artifact_id', 'ACL_PRINCIPAL_SET', 'PRINCIPAL_TOKENS'),
        ('evidence_fragment', 'normalized_text_artifact_id', 'EVIDENCE_TEXT', 'NORMALIZED_TEXT'),
        ('evidence_fragment', 'anchor_artifact_id', 'EVIDENCE_ANCHOR', 'CANONICAL_ANCHOR'),
        ('evidence_fragment', 'metadata_artifact_id', 'EVIDENCE_METADATA', 'METADATA'),
        ('search_chunk', 'search_text_artifact_id', 'SEARCH_CHUNK_TEXT', 'NORMALIZED_TEXT'),
        ('question_run', 'question_text_artifact_id', 'QUESTION_RUN', 'QUESTION_TEXT'),
        ('question_run', 'answer_markdown_artifact_id', 'QUESTION_RUN', 'ANSWER_MARKDOWN'),
        ('question_run', 'answer_structured_artifact_id', 'QUESTION_RUN', 'ANSWER_STRUCTURED'),
        ('question_run', 'manifest_content_artifact_id', 'MANIFEST_CONTENT', 'CANONICAL_BYTES'),
        ('question_authorized_candidate_set', 'canonical_artifact_id', 'AUTHORIZED_CANDIDATE_SET', 'CANONICAL_BYTES'),
        ('question_model_execution_plan', 'canonical_artifact_id', 'MODEL_EXECUTION_PLAN', 'CANONICAL_BYTES'),
        ('question_claim', 'text_artifact_id', 'CLAIM_TEXT', 'CLAIM_TEXT'),
        ('claim_deterministic_validation_artifact', 'output_artifact_id', 'DETERMINISTIC_VALIDATION', 'VALIDATION_OUTPUT'),
        ('question_citation', 'cited_excerpt_artifact_id', 'CITED_EXCERPT', 'EXACT_TEXT'),
        ('question_citation', 'anchor_artifact_id', 'CITATION_ANCHOR', 'CANONICAL_ANCHOR'),
        ('question_citation', 'deep_link_artifact_id', 'SOURCE_DEEPLINK', 'DEEPLINK'),
        ('model_run_artifact', 'input_artifact_id', 'MODEL_ARTIFACT', 'CANONICAL_INPUT'),
        ('model_run_artifact', 'output_artifact_id', 'MODEL_ARTIFACT', 'CANONICAL_OUTPUT')
    );
$$;

-- Extend the existing closed job payload vocabulary with the one discovery
-- request reference. The type-specific check below requires this key to be the
-- only key on SOURCE_DISCOVERY jobs.
CREATE OR REPLACE FUNCTION app.job_payload_is_safe(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    payload_key text;
    payload_value jsonb;
    scalar_value text;
BEGIN
    IF value IS NULL
       OR jsonb_typeof(value) <> 'object'
       OR octet_length(value::text) > 16384 THEN
        RETURN false;
    END IF;

    FOR payload_key, payload_value IN SELECT key, val FROM jsonb_each(value) AS item(key, val)
    LOOP
        IF payload_key IN (
            'source_scope_id', 'source_object_id', 'source_version_id',
            'extraction_id', 'index_generation_id', 'workspace_id', 'artifact_id',
            'source_discovery_request_id'
        ) THEN
            IF jsonb_typeof(payload_value) <> 'string' THEN RETURN false; END IF;
            scalar_value := payload_value #>> '{}';
            IF NOT app.outbox_reference_id_is_valid(scalar_value) THEN RETURN false; END IF;
        ELSIF payload_key IN ('content_hash', 'text_hash') THEN
            IF jsonb_typeof(payload_value) <> 'string'
               OR NOT app.stage2_sha256_is_valid(payload_value #>> '{}') THEN
                RETURN false;
            END IF;
        ELSIF payload_key IN ('retention_fence', 'generation_fence') THEN
            IF jsonb_typeof(payload_value) <> 'number'
               OR (payload_value #>> '{}') !~ '^(0|[1-9][0-9]{0,15})$'
               OR (payload_value #>> '{}')::numeric > 9007199254740991 THEN
                RETURN false;
            END IF;
        ELSIF payload_key = 'operation' THEN
            IF jsonb_typeof(payload_value) <> 'string'
               OR (payload_value #>> '{}') NOT IN ('UPSERT', 'DELETE', 'PURGE', 'ACTIVATE') THEN
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_discovery_job_payload_is_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND jsonb_typeof(value) = 'object'
       AND (SELECT count(*) FROM jsonb_object_keys(value)) = 1
       AND jsonb_typeof(value->'source_discovery_request_id') = 'string'
       AND app.source_generated_id_is_valid(value->>'source_discovery_request_id', 'sdrq');
$$;

-- Failure codes are operator-facing tokens only. They never carry a driver
-- message, SQL, catalog value or source/model content.
CREATE OR REPLACE FUNCTION app.source_discovery_failure_code_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IN (
        'DISCOVERY_CREDENTIAL_UNAVAILABLE',
        'DISCOVERY_TRUST_STALE',
        'DISCOVERY_DATABASE_CHANGED',
        'DISCOVERY_PRIVILEGE_CHANGED',
        'DISCOVERY_LIMIT_EXCEEDED',
        'DISCOVERY_METADATA_INVALID',
        'DISCOVERY_EXTERNAL_UNAVAILABLE',
        'DISCOVERY_EXPIRED',
        'DISCOVERY_LEASE_LOST',
        'DISCOVERY_INTERNAL_FAILURE'
    );
$$;

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

-- Cleanup may need to record a stale-trust or expired request. It still binds
-- the immutable connection revision and trust attestation, but does not require
-- the attestation to remain currently probeable or unexpired.
CREATE OR REPLACE FUNCTION app.source_discovery_revision_is_bound(
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
        WHERE organization.id = organization_value
          AND organization.status = 'ACTIVE'
    );
$$;

CREATE TABLE public.source_discovery_request (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'sdrq')),
    actor_principal_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(actor_principal_id)),
    connection_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(connection_id)),
    connection_revision bigint NOT NULL CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    trust_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(trust_profile_hash)),
    security_epoch bigint NOT NULL CHECK (security_epoch BETWEEN 1 AND 9007199254740991),
    max_views integer NOT NULL CHECK (max_views BETWEEN 1 AND 64),
    max_columns integer NOT NULL CHECK (max_columns BETWEEN 1 AND 256),
    max_comment_bytes integer NOT NULL CHECK (max_comment_bytes BETWEEN 0 AND 65536),
    statement_timeout_ms integer NOT NULL CHECK (statement_timeout_ms BETWEEN 100 AND 300000),
    transaction_timeout_ms integer NOT NULL CHECK (transaction_timeout_ms BETWEEN 100 AND 600000),
    idempotency_key_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(idempotency_key_hash)),
    request_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(request_hash)),
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'EXPIRED')),
    result_id text CHECK (result_id IS NULL OR app.source_generated_id_is_valid(result_id, 'sdr')),
    result_hash text CHECK (result_hash IS NULL OR app.stage2_sha256_is_valid(result_hash)),
    failure_code text CHECK (failure_code IS NULL OR app.source_discovery_failure_code_is_valid(failure_code)),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT transaction_timestamp() + interval '15 minutes',
    started_at timestamptz,
    completed_at timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, actor_principal_id, idempotency_key_hash),
    CONSTRAINT source_discovery_request_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_request_revision_fk
        FOREIGN KEY (organization_id, connection_id, connection_revision)
        REFERENCES public.source_connection_revision (organization_id, connection_id, revision)
        ON DELETE RESTRICT,
    CHECK (expires_at = issued_at + interval '15 minutes'),
    CHECK (
        (status = 'PENDING'
         AND started_at IS NULL AND completed_at IS NULL
         AND result_id IS NULL AND result_hash IS NULL AND failure_code IS NULL)
        OR
        (status = 'RUNNING'
         AND started_at IS NOT NULL AND completed_at IS NULL
         AND result_id IS NULL AND result_hash IS NULL AND failure_code IS NULL)
        OR
        (status = 'SUCCEEDED'
         AND started_at IS NOT NULL AND completed_at IS NOT NULL
         AND result_id IS NOT NULL AND result_hash IS NOT NULL AND failure_code IS NULL
         AND completed_at >= started_at)
        OR
        (status IN ('FAILED', 'EXPIRED')
         AND completed_at IS NOT NULL AND result_id IS NULL AND result_hash IS NULL
         AND failure_code IS NOT NULL
         AND (started_at IS NULL OR completed_at >= started_at))
    )
);

CREATE INDEX source_discovery_request_status_order
    ON public.source_discovery_request (organization_id, status, issued_at, id);

CREATE INDEX source_discovery_request_expiry_order
    ON public.source_discovery_request (organization_id, expires_at)
    WHERE status IN ('PENDING', 'RUNNING');

CREATE TABLE public.source_discovery_result (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'sdr')),
    request_id text NOT NULL CHECK (app.source_generated_id_is_valid(request_id, 'sdrq')),
    actor_principal_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(actor_principal_id)),
    connection_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(connection_id)),
    connection_revision bigint NOT NULL CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    database_identity_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(database_identity_hash)),
    trust_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(trust_profile_hash)),
    privilege_digest text NOT NULL CHECK (app.stage2_sha256_is_valid(privilege_digest)),
    security_epoch bigint NOT NULL CHECK (security_epoch BETWEEN 1 AND 9007199254740991),
    status text NOT NULL CHECK (status IN ('SUCCEEDED', 'NEEDS_INTERPRETATION')),
    view_count integer NOT NULL CHECK (view_count BETWEEN 0 AND 64),
    prepared_view_count integer NOT NULL CHECK (prepared_view_count BETWEEN 0 AND 64),
    needs_interpretation_view_count integer NOT NULL CHECK (needs_interpretation_view_count BETWEEN 0 AND 64),
    metadata_artifact_id text CHECK (metadata_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(metadata_artifact_id)),
    metadata_plaintext_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(metadata_plaintext_hash)),
    result_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(result_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT transaction_timestamp() + interval '15 minutes',
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, request_id),
    UNIQUE (organization_id, id, result_hash),
    CONSTRAINT source_discovery_result_request_fk
        FOREIGN KEY (organization_id, request_id)
        REFERENCES public.source_discovery_request (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_result_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_result_revision_fk
        FOREIGN KEY (organization_id, connection_id, connection_revision)
        REFERENCES public.source_connection_revision (organization_id, connection_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT source_discovery_result_artifact_fk
        FOREIGN KEY (organization_id, metadata_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (expires_at = created_at + interval '15 minutes'),
    CHECK (prepared_view_count + needs_interpretation_view_count = view_count),
    CHECK (status <> 'SUCCEEDED' OR needs_interpretation_view_count = 0)
);

ALTER TABLE public.source_discovery_request
    ADD CONSTRAINT source_discovery_request_result_fk
    FOREIGN KEY (organization_id, result_id, result_hash)
    REFERENCES public.source_discovery_result (organization_id, id, result_hash)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX source_discovery_result_expiry_order
    ON public.source_discovery_result (organization_id, expires_at, id);

CREATE INDEX source_discovery_result_connection_order
    ON public.source_discovery_result (organization_id, connection_id, connection_revision, created_at DESC);

CREATE OR REPLACE FUNCTION app.source_discovery_request_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'source discovery request deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_app'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR current_setting('app.source_discovery_enqueue', true) IS DISTINCT FROM NEW.id
           OR NEW.actor_principal_id IS DISTINCT FROM app.current_principal_id()
           OR NEW.status <> 'PENDING'
           OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL
           OR NEW.result_id IS NOT NULL OR NEW.result_hash IS NOT NULL
           OR NEW.failure_code IS NOT NULL
           OR NEW.expires_at IS DISTINCT FROM NEW.issued_at + interval '15 minutes' THEN
            RAISE EXCEPTION 'source discovery request insertion requires the owner enqueue command'
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    IF session_user <> 'knowvault_worker'
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.actor_principal_id IS DISTINCT FROM OLD.actor_principal_id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.connection_revision IS DISTINCT FROM OLD.connection_revision
       OR NEW.trust_profile_hash IS DISTINCT FROM OLD.trust_profile_hash
       OR NEW.security_epoch IS DISTINCT FROM OLD.security_epoch
       OR NEW.max_views IS DISTINCT FROM OLD.max_views
       OR NEW.max_columns IS DISTINCT FROM OLD.max_columns
       OR NEW.max_comment_bytes IS DISTINCT FROM OLD.max_comment_bytes
       OR NEW.statement_timeout_ms IS DISTINCT FROM OLD.statement_timeout_ms
       OR NEW.transaction_timeout_ms IS DISTINCT FROM OLD.transaction_timeout_ms
       OR NEW.idempotency_key_hash IS DISTINCT FROM OLD.idempotency_key_hash
       OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
       OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'source discovery request definition is immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status IN ('SUCCEEDED', 'FAILED', 'EXPIRED') THEN
        RAISE EXCEPTION 'source discovery request is terminal and immutable'
            USING ERRCODE = '55000';
    END IF;

    IF OLD.status = 'PENDING' AND NEW.status = 'RUNNING' THEN
        NEW.started_at := transaction_timestamp();
        NEW.completed_at := NULL;
        NEW.result_id := NULL;
        NEW.result_hash := NULL;
        NEW.failure_code := NULL;
    ELSIF OLD.status = 'RUNNING' AND NEW.status = 'RUNNING' THEN
        -- A reclaimed queue lease may restart the same request with a new
        -- worker epoch. The request definition remains frozen.
        NEW.started_at := transaction_timestamp();
        NEW.completed_at := NULL;
        NEW.result_id := NULL;
        NEW.result_hash := NULL;
        NEW.failure_code := NULL;
    ELSIF OLD.status = 'RUNNING' AND NEW.status = 'PENDING' THEN
        NEW.started_at := NULL;
        NEW.completed_at := NULL;
        NEW.result_id := NULL;
        NEW.result_hash := NULL;
        NEW.failure_code := NULL;
    ELSIF OLD.status IN ('PENDING', 'RUNNING') AND NEW.status IN ('SUCCEEDED', 'FAILED', 'EXPIRED') THEN
        IF OLD.status = 'PENDING' AND NEW.status <> 'EXPIRED' THEN
            RAISE EXCEPTION 'pending source discovery request can only expire before a lease'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.status = 'SUCCEEDED' THEN
            IF NEW.result_id IS NULL OR NEW.result_hash IS NULL OR NEW.failure_code IS NOT NULL THEN
                RAISE EXCEPTION 'successful source discovery request requires exactly one result'
                    USING ERRCODE = '23514';
            END IF;
        ELSE
            IF NEW.result_id IS NOT NULL OR NEW.result_hash IS NOT NULL OR NEW.failure_code IS NULL THEN
                RAISE EXCEPTION 'failed source discovery request requires one content-free failure code'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
        NEW.completed_at := transaction_timestamp();
    ELSE
        RAISE EXCEPTION 'invalid source discovery request transition'
            USING ERRCODE = '55000';
    END IF;

    IF (NEW.result_id IS NULL) <> (NEW.result_hash IS NULL) THEN
        RAISE EXCEPTION 'source discovery result ID and hash must be paired'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_discovery_request_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.source_discovery_request
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_request_mutation_guard();

CREATE OR REPLACE FUNCTION app.source_discovery_result_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'source discovery result deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_worker'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR current_setting('app.source_discovery_result_begin', true) IS DISTINCT FROM NEW.id
           OR NEW.metadata_artifact_id IS NOT NULL THEN
            RAISE EXCEPTION 'source discovery result insertion requires the worker result command'
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    IF session_user <> 'knowvault_worker'
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.actor_principal_id IS DISTINCT FROM OLD.actor_principal_id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.connection_revision IS DISTINCT FROM OLD.connection_revision
       OR NEW.database_identity_hash IS DISTINCT FROM OLD.database_identity_hash
       OR NEW.trust_profile_hash IS DISTINCT FROM OLD.trust_profile_hash
       OR NEW.privilege_digest IS DISTINCT FROM OLD.privilege_digest
       OR NEW.security_epoch IS DISTINCT FROM OLD.security_epoch
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.view_count IS DISTINCT FROM OLD.view_count
       OR NEW.prepared_view_count IS DISTINCT FROM OLD.prepared_view_count
       OR NEW.needs_interpretation_view_count IS DISTINCT FROM OLD.needs_interpretation_view_count
       OR NEW.metadata_plaintext_hash IS DISTINCT FROM OLD.metadata_plaintext_hash
       OR NEW.result_hash IS DISTINCT FROM OLD.result_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR OLD.metadata_artifact_id IS NOT NULL
       OR NEW.metadata_artifact_id IS NULL THEN
        RAISE EXCEPTION 'source discovery result is immutable except for one artifact binding'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_discovery_result_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.source_discovery_result
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_result_mutation_guard();

CREATE OR REPLACE FUNCTION app.source_discovery_result_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    artifact public.encrypted_artifact%ROWTYPE;
BEGIN
    IF NEW.metadata_artifact_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO artifact
    FROM public.encrypted_artifact
    WHERE organization_id = NEW.organization_id
      AND id = NEW.metadata_artifact_id;
    IF NOT FOUND
       OR artifact.owner_table <> 'source_discovery_result'
       OR artifact.owner_column <> 'metadata_artifact_id'
       OR artifact.resource_type <> 'SOURCE_DISCOVERY_RESULT'
       OR artifact.resource_id <> NEW.id
       OR artifact.field_name <> 'DISCOVERY_METADATA'
       OR artifact.plaintext_hash <> NEW.metadata_plaintext_hash
       OR artifact.purged_at IS NOT NULL THEN
        RAISE EXCEPTION 'discovery metadata artifact must exactly own the result and plaintext hash'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_discovery_result_artifact_exact
AFTER INSERT OR UPDATE ON public.source_discovery_result
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_result_artifact_guard();

CREATE OR REPLACE FUNCTION app.source_discovery_result_artifact_required()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    artifact_id text;
BEGIN
    SELECT metadata_artifact_id INTO artifact_id
    FROM public.source_discovery_result
    WHERE organization_id = NEW.organization_id AND id = NEW.id;
    IF artifact_id IS NULL THEN
        RAISE EXCEPTION 'source discovery result requires an encrypted metadata artifact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_discovery_result_artifact_required
AFTER INSERT OR UPDATE ON public.source_discovery_result
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_result_artifact_required();

CREATE OR REPLACE FUNCTION app.source_discovery_request_result_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    result_status text;
    result_request_id text;
    result_actor_principal_id text;
    result_connection_id text;
    result_connection_revision bigint;
    result_trust_profile_hash text;
    result_security_epoch bigint;
    result_hash text;
    result_artifact_id text;
    result_created_at timestamptz;
    result_expires_at timestamptz;
BEGIN
    IF NEW.status = 'SUCCEEDED' THEN
        SELECT result.status, result.request_id, result.actor_principal_id,
               result.connection_id, result.connection_revision,
               result.trust_profile_hash, result.security_epoch,
               result.result_hash, result.metadata_artifact_id,
               result.created_at, result.expires_at
          INTO result_status, result_request_id, result_actor_principal_id,
               result_connection_id, result_connection_revision,
               result_trust_profile_hash, result_security_epoch, result_hash,
               result_artifact_id, result_created_at, result_expires_at
        FROM public.source_discovery_result AS result
        WHERE result.organization_id = NEW.organization_id
          AND result.id = NEW.result_id;
        IF NOT FOUND
           OR result_status NOT IN ('SUCCEEDED', 'NEEDS_INTERPRETATION')
           OR result_request_id <> NEW.id
           OR result_actor_principal_id <> NEW.actor_principal_id
           OR result_connection_id <> NEW.connection_id
           OR result_connection_revision <> NEW.connection_revision
           OR result_trust_profile_hash <> NEW.trust_profile_hash
           OR result_security_epoch <> NEW.security_epoch
           OR result_hash <> NEW.result_hash
           OR result_artifact_id IS NULL
           OR result_expires_at <> result_created_at + interval '15 minutes'
           OR result_expires_at <= transaction_timestamp() THEN
            RAISE EXCEPTION 'source discovery request result is not an exact terminal result'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.result_id IS NOT NULL OR NEW.result_hash IS NOT NULL THEN
        RAISE EXCEPTION 'non-successful source discovery request cannot reference a result'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_discovery_request_result_exact
AFTER INSERT OR UPDATE ON public.source_discovery_request
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_request_result_guard();

CREATE OR REPLACE FUNCTION app.source_discovery_result_request_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    request_status text;
    request_result_id text;
    request_result_hash text;
    request_actor_principal_id text;
    request_connection_id text;
    request_connection_revision bigint;
    request_trust_profile_hash text;
    request_security_epoch bigint;
BEGIN
    SELECT status, result_id, result_hash, actor_principal_id, connection_id,
           connection_revision, trust_profile_hash, security_epoch
      INTO request_status, request_result_id, request_result_hash,
           request_actor_principal_id, request_connection_id,
           request_connection_revision, request_trust_profile_hash,
           request_security_epoch
    FROM public.source_discovery_request
    WHERE organization_id = NEW.organization_id AND id = NEW.request_id;
    IF NOT FOUND
       OR request_status <> 'SUCCEEDED'
       OR request_result_id <> NEW.id
       OR request_result_hash <> NEW.result_hash
       OR request_actor_principal_id <> NEW.actor_principal_id
       OR request_connection_id <> NEW.connection_id
       OR request_connection_revision <> NEW.connection_revision
       OR request_trust_profile_hash <> NEW.trust_profile_hash
       OR request_security_epoch <> NEW.security_epoch THEN
        RAISE EXCEPTION 'source discovery result requires one matching successful request'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER source_discovery_result_request_exact
AFTER INSERT OR UPDATE ON public.source_discovery_result
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_discovery_result_request_guard();

-- Complete binds the worker's second digest observation to the same result
-- tuple before acknowledging the queue lease. The result artifact, request
-- terminal state and generic job acknowledgement therefore commit together.
CREATE OR REPLACE FUNCTION app.source_discovery_request_complete(
    p_request_id text,
    p_result_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint,
    p_database_identity_hash text,
    p_privilege_digest text,
    p_result_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
    result_row public.source_discovery_result%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery completion is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.source_generated_id_is_valid(p_result_id, 'sdr')
       OR NOT app.stage2_sha256_is_valid(p_database_identity_hash)
       OR NOT app.stage2_sha256_is_valid(p_privilege_digest)
       OR NOT app.stage2_sha256_is_valid(p_result_hash)
       OR p_lease_epoch < 1 THEN
        RAISE EXCEPTION 'source discovery completion contains an invalid terminal tuple'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery completion lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery request does not exist in this tenant'
            USING ERRCODE = '55000';
    END IF;
    SELECT * INTO result_row
    FROM public.source_discovery_result
    WHERE organization_id = organization_value AND id = p_result_id
    FOR UPDATE;
    IF NOT FOUND
       OR request_row.status <> 'RUNNING'
       OR request_row.expires_at <= transaction_timestamp()
       OR request_row.result_id IS NOT NULL
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_probeable(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash)
       OR result_row.request_id <> request_row.id
       OR result_row.actor_principal_id <> request_row.actor_principal_id
       OR result_row.connection_id <> request_row.connection_id
       OR result_row.connection_revision <> request_row.connection_revision
       OR result_row.trust_profile_hash <> request_row.trust_profile_hash
       OR result_row.security_epoch <> request_row.security_epoch
       OR result_row.database_identity_hash <> p_database_identity_hash
       OR result_row.privilege_digest <> p_privilege_digest
       OR result_row.result_hash <> p_result_hash
       OR result_row.metadata_artifact_id IS NULL
       OR result_row.expires_at <= transaction_timestamp()
       OR result_row.expires_at <> result_row.created_at + interval '15 minutes' THEN
        RAISE EXCEPTION 'source discovery terminal result is stale or not an exact tuple'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.source_discovery_request
    SET status = 'SUCCEEDED', result_id = result_row.id, result_hash = result_row.result_hash
    WHERE organization_id = organization_value
      AND id = request_row.id
      AND status = 'RUNNING';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery request terminal transition was not applied'
            USING ERRCODE = '55000';
    END IF;
    PERFORM app.complete_job(p_job_id, p_worker_id, p_lease_epoch);
END;
$$;

-- Failure stores only a closed operator token. A retry returns the request to
-- PENDING with no result; an exhausted queue budget closes it as FAILED in the
-- same transaction that closes the queue attempt.
CREATE OR REPLACE FUNCTION app.source_discovery_request_fail(
    p_request_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint,
    p_failure_code text,
    p_retry_after_seconds integer
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
    resulting_status text;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery failure is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.stage2_opaque_id_is_valid(p_job_id)
       OR NOT app.stage2_opaque_id_is_valid(p_worker_id)
       OR p_lease_epoch < 1
       OR NOT app.source_discovery_failure_code_is_valid(p_failure_code)
       OR p_retry_after_seconds IS NULL
       OR p_retry_after_seconds NOT BETWEEN 0 AND 2592000 THEN
        RAISE EXCEPTION 'source discovery failure contains an invalid content-free transition'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery failure lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND
       OR request_row.status <> 'RUNNING'
       OR request_row.expires_at <= transaction_timestamp()
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_bound(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash) THEN
        RAISE EXCEPTION 'source discovery request is stale, expired or not probeable'
            USING ERRCODE = '55000';
    END IF;
    resulting_status := app.fail_job(
        p_job_id, p_worker_id, p_lease_epoch, p_failure_code,
        p_retry_after_seconds);
    IF resulting_status = 'PENDING' THEN
        UPDATE public.source_discovery_request
        SET status = 'PENDING'
        WHERE organization_id = organization_value
          AND id = p_request_id AND status = 'RUNNING';
    ELSIF resulting_status = 'DEAD' THEN
        UPDATE public.source_discovery_request
        SET status = 'FAILED', failure_code = p_failure_code
        WHERE organization_id = organization_value
          AND id = p_request_id AND status = 'RUNNING';
    ELSE
        RAISE EXCEPTION 'source discovery queue returned an unknown terminal state'
            USING ERRCODE = '55000';
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery failure transition was not applied'
            USING ERRCODE = '55000';
    END IF;
    RETURN resulting_status;
END;
$$;

-- Expiration is a worker-owned terminal acknowledgement after the queue lease
-- has been claimed. The request may still be PENDING when the queue lease is
-- claimed after its TTL elapsed; both states close through this exact lease.
-- It deliberately does not expose a driver error or source data.
CREATE OR REPLACE FUNCTION app.source_discovery_request_expire(
    p_request_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery expiration is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.stage2_opaque_id_is_valid(p_job_id)
       OR NOT app.stage2_opaque_id_is_valid(p_worker_id)
       OR p_lease_epoch < 1 THEN
        RAISE EXCEPTION 'source discovery expiration contains an invalid lease reference'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery expiration lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND
       OR request_row.status NOT IN ('PENDING', 'RUNNING')
       OR request_row.expires_at > transaction_timestamp()
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_bound(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash) THEN
        RAISE EXCEPTION 'source discovery request is not ready to expire'
            USING ERRCODE = '55000';
    END IF;
    UPDATE public.source_discovery_request
    SET status = 'EXPIRED', failure_code = 'DISCOVERY_EXPIRED'
    WHERE organization_id = organization_value
      AND id = p_request_id AND status IN ('PENDING', 'RUNNING');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery expiration transition was not applied'
            USING ERRCODE = '55000';
    END IF;
    PERFORM app.complete_job(p_job_id, p_worker_id, p_lease_epoch);
END;
$$;

-- The application poll surface exposes status and bounded counts only. It
-- never exposes credential references, database identity, privilege digests,
-- artifact envelope fields or metadata bytes.
CREATE OR REPLACE FUNCTION app.source_discovery_request_status(p_request_id text)
RETURNS TABLE (
    request_id text,
    request_status text,
    result_id text,
    result_status text,
    view_count integer,
    prepared_view_count integer,
    needs_interpretation_view_count integer,
    failure_code text,
    expires_at timestamptz
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
        RAISE EXCEPTION 'source discovery status is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    principal_value := app.current_principal_id();
    IF organization_value IS NULL OR principal_value IS NULL THEN
        RAISE EXCEPTION 'source discovery status requires tenant and principal context'
            USING ERRCODE = '42501';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    IF security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, principal_value, security_epoch_value) THEN
        RAISE EXCEPTION 'source discovery status requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT request.id, request.status, request.result_id, result.status,
           result.view_count, result.prepared_view_count,
           result.needs_interpretation_view_count, request.failure_code,
           request.expires_at
    FROM public.source_discovery_request AS request
    LEFT JOIN public.source_discovery_result AS result
      ON result.organization_id = request.organization_id
     AND result.id = request.result_id
    WHERE request.organization_id = organization_value
      AND request.id = p_request_id
      AND request.actor_principal_id = principal_value;
END;
$$;

-- Only the worker can retrieve the encrypted metadata envelope. Decryption and
-- semantic projection remain outside this storage slice.
CREATE OR REPLACE FUNCTION app.source_discovery_result_read_metadata(p_result_id text)
RETURNS TABLE (
    result_id text,
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
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT result.id, artifact.id, artifact.ciphertext, artifact.size_bytes,
           artifact.nonce, artifact.wrapped_dek, artifact.wrapped_dek_hash,
           artifact.kek_reference, artifact.kek_version, artifact.aad_hash,
           artifact.plaintext_hash
    FROM public.source_discovery_result AS result
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
    WHERE result.organization_id = app.current_organization_id()
      AND result.id = p_result_id
      AND result.expires_at > transaction_timestamp();
$$;

ALTER TABLE public.source_discovery_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_discovery_request FORCE ROW LEVEL SECURITY;
CREATE POLICY source_discovery_request_tenant_isolation
    ON public.source_discovery_request
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.source_discovery_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_discovery_result FORCE ROW LEVEL SECURITY;
CREATE POLICY source_discovery_result_tenant_isolation
    ON public.source_discovery_result
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_discovery_request, public.source_discovery_result FROM PUBLIC;
REVOKE ALL ON TABLE public.source_discovery_request, public.source_discovery_result
    FROM knowvault_app, knowvault_worker;
GRANT SELECT ON TABLE public.source_discovery_request, public.source_discovery_result
    TO knowvault_worker;

-- Queue table DML remains a worker function concern; discovery tables have no
-- direct runtime DML grants, and their own helper functions are the only
-- application/worker command surface.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON TABLE public.source_discovery_request, public.source_discovery_result
    FROM knowvault_app, knowvault_worker;


-- SOURCE_DISCOVERY is the only new durable job type. Its payload is one typed
-- request reference; every other job type is explicitly barred from carrying
-- that reference so a handler cannot reinterpret an unrelated job as a probe.
ALTER TABLE public.job
    DROP CONSTRAINT job_type_check,
    ADD CONSTRAINT job_type_check CHECK (type IN (
        'SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC', 'SOURCE_OBJECT_EXTRACTION',
        'OUTBOX_DELIVERY', 'SOURCE_VERSION_PURGE', 'KEK_REWRAP', 'DIGEST_RECOMPUTE',
        'SOURCE_DISCOVERY'
    )),
    ADD CONSTRAINT job_source_discovery_payload_check CHECK (
        (type = 'SOURCE_DISCOVERY'
         AND app.source_discovery_job_payload_is_valid(payload_json))
        OR
        (type <> 'SOURCE_DISCOVERY'
         AND NOT (payload_json ? 'source_discovery_request_id'))
    );

CREATE OR REPLACE FUNCTION app.source_discovery_request_hash(
    p_request_id text,
    p_organization_id text,
    p_actor_principal_id text,
    p_connection_id text,
    p_connection_revision bigint,
    p_trust_profile_hash text,
    p_security_epoch bigint,
    p_max_views integer,
    p_max_columns integer,
    p_max_comment_bytes integer,
    p_statement_timeout_ms integer,
    p_transaction_timeout_ms integer,
    p_idempotency_key_hash text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT 'sha256:' || encode(sha256(convert_to(
        jsonb_build_object(
            'actor_principal_id', p_actor_principal_id,
            'connection_id', p_connection_id,
            'connection_revision', p_connection_revision,
            'idempotency_key_hash', p_idempotency_key_hash,
            'max_columns', p_max_columns,
            'max_comment_bytes', p_max_comment_bytes,
            'max_views', p_max_views,
            'organization_id', p_organization_id,
            'request_id', p_request_id,
            'security_epoch', p_security_epoch,
            'statement_timeout_ms', p_statement_timeout_ms,
            'transaction_timeout_ms', p_transaction_timeout_ms,
            'trust_profile_hash', p_trust_profile_hash
        )::text,
        'UTF8'
    )), 'hex');
$$;

CREATE OR REPLACE FUNCTION app.source_discovery_owner_is_current(
    p_organization_id text,
    p_principal_id text,
    p_security_epoch bigint
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
        JOIN public.principal AS principal
          ON principal.organization_id = organization.id
         AND principal.id = p_principal_id
         AND principal.status = 'ACTIVE'
        JOIN public.organization_role_assignment AS assignment
          ON assignment.organization_id = organization.id
         AND assignment.principal_id = principal.id
         AND assignment.role = 'OWNER'
         AND assignment.revoked_at IS NULL
         AND assignment.valid_from_revision <= p_security_epoch
         AND (assignment.valid_to_revision IS NULL
              OR p_security_epoch < assignment.valid_to_revision)
        WHERE organization.id = p_organization_id
          AND organization.status = 'ACTIVE'
          AND organization.role_revision = p_security_epoch
    );
$$;

CREATE OR REPLACE FUNCTION app.source_discovery_job_lease_is_live(
    p_organization_id text,
    p_request_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    job_row public.job%ROWTYPE;
BEGIN
    -- Lock the authoritative job row while the caller mutates its request or
    -- result. A lease steal therefore either happens before this check or after
    -- the enclosing transaction's fenced queue transition.
    SELECT job.* INTO job_row
    FROM public.organization AS organization
    JOIN public.job AS job
      ON job.organization_id = organization.id
     AND job.id = p_job_id
     AND job.id = p_request_id
     AND job.type = 'SOURCE_DISCOVERY'
     AND job.status = 'RUNNING'
     AND job.idempotency_key = 'source-discovery:' || p_request_id
     AND job.lease_owner = p_worker_id
     AND job.lease_epoch = p_lease_epoch
     AND job.lease_deadline > transaction_timestamp()
     AND job.payload_json = jsonb_build_object(
         'source_discovery_request_id', p_request_id)
    JOIN public.job_attempt AS attempt
      ON attempt.organization_id = job.organization_id
     AND attempt.job_id = job.id
     AND attempt.attempt_number = job.attempt_count
     AND attempt.lease_owner = job.lease_owner
     AND attempt.lease_epoch = job.lease_epoch
     AND attempt.completed_at IS NULL
    WHERE organization.id = p_organization_id
      AND organization.status = 'ACTIVE'
      AND app.current_organization_id() = p_organization_id
    FOR UPDATE OF job;
    RETURN FOUND;
END;
$$;

-- This is the only application write command for a discovery request. The
-- actor, role epoch, request timestamps and request hash are all derived in
-- this transaction; the caller supplies only bounded opaque IDs, hashes and
-- probe limits. The request row and its queue row are one transaction.
CREATE OR REPLACE FUNCTION app.source_discovery_request_enqueue(
    p_request_id text,
    p_connection_id text,
    p_connection_revision bigint,
    p_trust_profile_hash text,
    p_max_views integer,
    p_max_columns integer,
    p_max_comment_bytes integer,
    p_statement_timeout_ms integer,
    p_transaction_timeout_ms integer,
    p_idempotency_key_hash text
)
RETURNS TABLE(request_id text, job_id text, created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    actor_value text;
    security_epoch_value bigint;
    issued_at_value timestamptz;
    expires_at_value timestamptz;
    request_hash_value text;
    job_id_value text;
    inserted_request_id text;
    existing_request public.source_discovery_request%ROWTYPE;
    existing_job public.job%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source discovery enqueue is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    actor_value := app.current_principal_id();
    IF organization_value IS NULL OR actor_value IS NULL THEN
        RAISE EXCEPTION 'source discovery enqueue requires tenant and principal context'
            USING ERRCODE = '42501';
    END IF;
    IF NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.stage2_opaque_id_is_valid(p_connection_id)
       OR NOT app.stage2_sha256_is_valid(p_trust_profile_hash)
       OR NOT app.stage2_sha256_is_valid(p_idempotency_key_hash) THEN
        RAISE EXCEPTION 'source discovery enqueue contains an invalid opaque request value'
            USING ERRCODE = '22023';
    END IF;

    SELECT organization.role_revision
      INTO security_epoch_value
    FROM public.organization AS organization
    JOIN public.principal AS principal
      ON principal.organization_id = organization.id
     AND principal.id = actor_value
     AND principal.status = 'ACTIVE'
    WHERE organization.id = organization_value
      AND organization.status = 'ACTIVE'
    FOR SHARE;
    IF security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, actor_value, security_epoch_value) THEN
        RAISE EXCEPTION 'source discovery enqueue requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;
    IF NOT app.source_discovery_revision_is_probeable(
        organization_value, p_connection_id, p_connection_revision,
        p_trust_profile_hash) THEN
        RAISE EXCEPTION 'source discovery enqueue requires an exact probeable trusted revision'
            USING ERRCODE = '55000';
    END IF;

    request_hash_value := app.source_discovery_request_hash(
        p_request_id, organization_value, actor_value, p_connection_id,
        p_connection_revision, p_trust_profile_hash, security_epoch_value,
        p_max_views, p_max_columns, p_max_comment_bytes,
        p_statement_timeout_ms, p_transaction_timeout_ms, p_idempotency_key_hash);
    issued_at_value := transaction_timestamp();
    expires_at_value := issued_at_value + interval '15 minutes';
    job_id_value := p_request_id;

    SELECT * INTO existing_request
    FROM public.source_discovery_request
    WHERE organization_id = organization_value
      AND id = p_request_id
    FOR UPDATE;
    IF FOUND THEN
        IF existing_request.actor_principal_id <> actor_value
           OR existing_request.connection_id <> p_connection_id
           OR existing_request.connection_revision <> p_connection_revision
           OR existing_request.trust_profile_hash <> p_trust_profile_hash
           OR existing_request.security_epoch <> security_epoch_value
           OR existing_request.max_views <> p_max_views
           OR existing_request.max_columns <> p_max_columns
           OR existing_request.max_comment_bytes <> p_max_comment_bytes
           OR existing_request.statement_timeout_ms <> p_statement_timeout_ms
           OR existing_request.transaction_timeout_ms <> p_transaction_timeout_ms
           OR existing_request.idempotency_key_hash <> p_idempotency_key_hash
           OR existing_request.request_hash <> request_hash_value THEN
            RAISE EXCEPTION 'source discovery request ID collides with a different immutable tuple'
                USING ERRCODE = '23505';
        END IF;
        SELECT * INTO existing_job
        FROM public.job
        WHERE organization_id = organization_value AND id = job_id_value;
        IF NOT FOUND
           OR existing_job.type <> 'SOURCE_DISCOVERY'
           OR existing_job.payload_json <> jsonb_build_object(
               'source_discovery_request_id', p_request_id)
           OR existing_job.idempotency_key <> 'source-discovery:' || p_request_id THEN
            RAISE EXCEPTION 'source discovery request is missing its exact durable job'
                USING ERRCODE = '55000';
        END IF;
        request_id := existing_request.id;
        job_id := existing_job.id;
        created := false;
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT * INTO existing_request
    FROM public.source_discovery_request
    WHERE organization_id = organization_value
      AND actor_principal_id = actor_value
      AND idempotency_key_hash = p_idempotency_key_hash
    FOR UPDATE;
    IF FOUND THEN
        RAISE EXCEPTION 'source discovery idempotency key collides with a different request ID'
            USING ERRCODE = '23505';
    END IF;

    PERFORM set_config('app.source_discovery_enqueue', p_request_id, true);
    INSERT INTO public.source_discovery_request (
        organization_id, id, actor_principal_id, connection_id,
        connection_revision, trust_profile_hash, security_epoch,
        max_views, max_columns, max_comment_bytes, statement_timeout_ms,
        transaction_timeout_ms, idempotency_key_hash, request_hash,
        issued_at, expires_at
    ) VALUES (
        organization_value, p_request_id, actor_value, p_connection_id,
        p_connection_revision, p_trust_profile_hash, security_epoch_value,
        p_max_views, p_max_columns, p_max_comment_bytes, p_statement_timeout_ms,
        p_transaction_timeout_ms, p_idempotency_key_hash, request_hash_value,
        issued_at_value, expires_at_value
    )
    ON CONFLICT DO NOTHING
    RETURNING id INTO inserted_request_id;

    IF inserted_request_id IS NULL THEN
        SELECT * INTO existing_request
        FROM public.source_discovery_request
        WHERE organization_id = organization_value
          AND (id = p_request_id
               OR (actor_principal_id = actor_value
                   AND idempotency_key_hash = p_idempotency_key_hash))
        ORDER BY id
        LIMIT 1
        FOR UPDATE;
        IF NOT FOUND
           OR existing_request.id <> p_request_id
           OR existing_request.actor_principal_id <> actor_value
           OR existing_request.connection_id <> p_connection_id
           OR existing_request.connection_revision <> p_connection_revision
           OR existing_request.trust_profile_hash <> p_trust_profile_hash
           OR existing_request.security_epoch <> security_epoch_value
           OR existing_request.max_views <> p_max_views
           OR existing_request.max_columns <> p_max_columns
           OR existing_request.max_comment_bytes <> p_max_comment_bytes
           OR existing_request.statement_timeout_ms <> p_statement_timeout_ms
           OR existing_request.transaction_timeout_ms <> p_transaction_timeout_ms
           OR existing_request.idempotency_key_hash <> p_idempotency_key_hash
           OR existing_request.request_hash <> request_hash_value THEN
            RAISE EXCEPTION 'source discovery enqueue lost an exact idempotency race'
                USING ERRCODE = '23505';
        END IF;
        SELECT * INTO existing_job
        FROM public.job
        WHERE organization_id = organization_value AND id = p_request_id;
        IF NOT FOUND
           OR existing_job.type <> 'SOURCE_DISCOVERY'
           OR existing_job.payload_json <> jsonb_build_object(
               'source_discovery_request_id', p_request_id)
           OR existing_job.idempotency_key <> 'source-discovery:' || p_request_id THEN
            RAISE EXCEPTION 'source discovery idempotency race produced a non-exact job'
                USING ERRCODE = '55000';
        END IF;
        request_id := existing_request.id;
        job_id := existing_job.id;
        created := false;
        RETURN NEXT;
        RETURN;
    END IF;

    job_id_value := app.enqueue_job(
        p_request_id,
        'SOURCE_DISCOVERY',
        jsonb_build_object('source_discovery_request_id', p_request_id),
        'source-discovery:' || p_request_id,
        100, 3, 0);
    SELECT * INTO existing_job
    FROM public.job
    WHERE organization_id = organization_value AND id = job_id_value;
    IF NOT FOUND
       OR existing_job.type <> 'SOURCE_DISCOVERY'
       OR existing_job.payload_json <> jsonb_build_object(
           'source_discovery_request_id', p_request_id)
       OR existing_job.idempotency_key <> 'source-discovery:' || p_request_id THEN
        RAISE EXCEPTION 'source discovery enqueue did not create its exact durable job'
            USING ERRCODE = '55000';
    END IF;
    request_id := p_request_id;
    job_id := job_id_value;
    created := true;
    RETURN NEXT;
END;
$$;

-- The worker claims the generic queue row first, then binds that live lease to
-- the request and rechecks all control-plane facts before any source probe.
CREATE OR REPLACE FUNCTION app.source_discovery_request_start(
    p_request_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery start is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.stage2_opaque_id_is_valid(p_job_id)
       OR NOT app.stage2_opaque_id_is_valid(p_worker_id)
       OR p_lease_epoch < 1 THEN
        RAISE EXCEPTION 'source discovery start contains an invalid lease reference'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery job lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND OR request_row.status NOT IN ('PENDING', 'RUNNING')
       OR request_row.expires_at <= transaction_timestamp()
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_probeable(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash) THEN
        RAISE EXCEPTION 'source discovery request is stale, expired or not probeable'
            USING ERRCODE = '55000';
    END IF;
    UPDATE public.source_discovery_request
    SET status = 'RUNNING'
    WHERE organization_id = organization_value AND id = p_request_id;
END;
$$;

-- Result insertion is deliberately incomplete until the same worker
-- transaction binds the encrypted metadata artifact and completes the request.
CREATE OR REPLACE FUNCTION app.source_discovery_result_begin(
    p_request_id text,
    p_result_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint,
    p_status text,
    p_view_count integer,
    p_prepared_view_count integer,
    p_needs_interpretation_view_count integer,
    p_database_identity_hash text,
    p_privilege_digest text,
    p_metadata_plaintext_hash text,
    p_result_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery result creation is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.source_generated_id_is_valid(p_result_id, 'sdr')
       OR NOT app.stage2_sha256_is_valid(p_database_identity_hash)
       OR NOT app.stage2_sha256_is_valid(p_privilege_digest)
       OR NOT app.stage2_sha256_is_valid(p_metadata_plaintext_hash)
       OR NOT app.stage2_sha256_is_valid(p_result_hash)
       OR p_status NOT IN ('SUCCEEDED', 'NEEDS_INTERPRETATION')
       OR p_view_count NOT BETWEEN 0 AND 64
       OR p_prepared_view_count NOT BETWEEN 0 AND 64
       OR p_needs_interpretation_view_count NOT BETWEEN 0 AND 64
       OR p_prepared_view_count + p_needs_interpretation_view_count <> p_view_count
       OR (p_status = 'SUCCEEDED' AND p_needs_interpretation_view_count <> 0) THEN
        RAISE EXCEPTION 'source discovery result has an invalid bounded terminal projection'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery result job lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND OR request_row.status <> 'RUNNING'
       OR request_row.expires_at <= transaction_timestamp()
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_probeable(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash) THEN
        RAISE EXCEPTION 'source discovery request is stale, expired or not probeable'
            USING ERRCODE = '55000';
    END IF;
    PERFORM set_config('app.source_discovery_result_begin', p_result_id, true);
    INSERT INTO public.source_discovery_result (
        organization_id, id, request_id, actor_principal_id, connection_id,
        connection_revision, database_identity_hash, trust_profile_hash,
        privilege_digest, security_epoch, status, view_count,
        prepared_view_count, needs_interpretation_view_count,
        metadata_plaintext_hash, result_hash
    ) VALUES (
        organization_value, p_result_id, p_request_id,
        request_row.actor_principal_id, request_row.connection_id,
        request_row.connection_revision, p_database_identity_hash,
        request_row.trust_profile_hash, p_privilege_digest,
        request_row.security_epoch, p_status, p_view_count,
        p_prepared_view_count, p_needs_interpretation_view_count,
        p_metadata_plaintext_hash, p_result_hash
    );
END;
$$;

-- The artifact envelope is supplied by the worker's existing encryption
-- adapter. Fixed owner/AAD fields and the result plaintext hash are server-side
-- values; the worker cannot attach metadata to another result or owner.
CREATE OR REPLACE FUNCTION app.source_discovery_result_bind_metadata(
    p_request_id text,
    p_result_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint,
    p_artifact_id text,
    p_size_bytes integer,
    p_nonce bytea,
    p_ciphertext bytea,
    p_wrapped_dek bytea,
    p_wrapped_dek_hash text,
    p_kek_reference text,
    p_kek_version bigint,
    p_aad_hash text,
    p_plaintext_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
    result_row public.source_discovery_result%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery artifact binding is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.source_generated_id_is_valid(p_result_id, 'sdr')
       OR NOT app.stage2_opaque_id_is_valid(p_artifact_id)
       OR NOT app.stage2_sha256_is_valid(p_wrapped_dek_hash)
       OR NOT app.stage2_sha256_is_valid(p_aad_hash)
       OR NOT app.stage2_sha256_is_valid(p_plaintext_hash) THEN
        RAISE EXCEPTION 'source discovery artifact binding contains an invalid envelope value'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery artifact job lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery request does not exist for artifact binding'
            USING ERRCODE = '55000';
    END IF;
    SELECT * INTO result_row
    FROM public.source_discovery_result
    WHERE organization_id = organization_value AND id = p_result_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery result does not exist for artifact binding'
            USING ERRCODE = '55000';
    END IF;
    IF request_row.status <> 'RUNNING'
       OR request_row.expires_at <= transaction_timestamp()
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_probeable(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash)
       OR result_row.request_id <> request_row.id
       OR result_row.actor_principal_id <> request_row.actor_principal_id
       OR result_row.connection_id <> request_row.connection_id
       OR result_row.connection_revision <> request_row.connection_revision
       OR result_row.trust_profile_hash <> request_row.trust_profile_hash
       OR result_row.security_epoch <> request_row.security_epoch
       OR result_row.metadata_artifact_id IS NOT NULL
       OR result_row.metadata_plaintext_hash <> p_plaintext_hash THEN
        RAISE EXCEPTION 'source discovery artifact binding is not an exact first binding'
            USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, owner_table, owner_column, resource_type,
        resource_id, field_name, cipher, ciphertext, size_bytes, nonce,
        wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash,
        plaintext_hash
    ) VALUES (
        organization_value, p_artifact_id, 'source_discovery_result',
        'metadata_artifact_id', 'SOURCE_DISCOVERY_RESULT', p_result_id,
        'DISCOVERY_METADATA', 'AES_256_GCM', p_ciphertext, p_size_bytes,
        p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference,
        p_kek_version, p_aad_hash, p_plaintext_hash
    );
    UPDATE public.source_discovery_result
    SET metadata_artifact_id = p_artifact_id
    WHERE organization_id = organization_value
      AND id = p_result_id
      AND metadata_artifact_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source discovery metadata artifact binding was not applied'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION
    app.source_discovery_job_payload_is_valid(jsonb),
    app.source_discovery_failure_code_is_valid(text),
    app.source_discovery_revision_is_probeable(text, text, bigint, text),
    app.source_discovery_revision_is_bound(text, text, bigint, text),
    app.source_discovery_result_artifact_guard(),
    app.source_discovery_result_artifact_required(),
    app.source_discovery_request_hash(text, text, text, text, bigint, text, bigint, integer, integer, integer, integer, integer, text),
    app.source_discovery_owner_is_current(text, text, bigint),
    app.source_discovery_job_lease_is_live(text, text, text, text, bigint),
    app.source_discovery_request_enqueue(text, text, bigint, text, integer, integer, integer, integer, integer, text),
    app.source_discovery_request_start(text, text, text, bigint),
    app.source_discovery_result_begin(text, text, text, text, bigint, text, integer, integer, integer, text, text, text, text),
    app.source_discovery_result_bind_metadata(text, text, text, text, bigint, text, integer, bytea, bytea, bytea, text, text, bigint, text, text),
    app.source_discovery_request_complete(text, text, text, text, bigint, text, text, text),
    app.source_discovery_request_fail(text, text, text, bigint, text, integer),
    app.source_discovery_request_expire(text, text, text, bigint),
    app.source_discovery_request_status(text),
    app.source_discovery_result_read_metadata(text)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    app.source_discovery_request_enqueue(text, text, bigint, text, integer, integer, integer, integer, integer, text),
    app.source_discovery_request_status(text)
FROM knowvault_worker;
REVOKE ALL ON FUNCTION
    app.source_discovery_request_start(text, text, text, bigint),
    app.source_discovery_result_begin(text, text, text, text, bigint, text, integer, integer, integer, text, text, text, text),
    app.source_discovery_result_bind_metadata(text, text, text, text, bigint, text, integer, bytea, bytea, bytea, text, text, bigint, text, text),
    app.source_discovery_request_complete(text, text, text, text, bigint, text, text, text),
    app.source_discovery_request_fail(text, text, text, bigint, text, integer),
    app.source_discovery_request_expire(text, text, text, bigint),
    app.source_discovery_result_read_metadata(text)
FROM knowvault_app;
GRANT EXECUTE ON FUNCTION
    app.source_discovery_request_enqueue(text, text, bigint, text, integer, integer, integer, integer, integer, text),
    app.source_discovery_request_status(text)
TO knowvault_app;
GRANT EXECUTE ON FUNCTION
    app.source_discovery_request_start(text, text, text, bigint),
    app.source_discovery_result_begin(text, text, text, text, bigint, text, integer, integer, integer, text, text, text, text),
    app.source_discovery_result_bind_metadata(text, text, text, text, bigint, text, integer, bytea, bytea, bytea, text, text, bigint, text, text),
    app.source_discovery_request_complete(text, text, text, text, bigint, text, text, text),
    app.source_discovery_request_fail(text, text, text, bigint, text, integer),
    app.source_discovery_request_expire(text, text, text, bigint),
    app.source_discovery_result_read_metadata(text)
TO knowvault_worker;

COMMIT;
