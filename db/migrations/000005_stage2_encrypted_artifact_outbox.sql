-- Stage 2 foundation: tenant-bound encrypted artifacts and an ordered
-- transactional outbox.
--
-- Encrypted payload bytes live only in encrypted_artifact.  The AAD owner
-- tuple is a closed inventory matching encrypted-artifact-aad-v1.  Runtime
-- code may create and read artifacts but cannot rewrite, purge or delete them.
--
-- Outbox sequence allocation is serialized per organization and participates
-- in the caller's transaction.  A rolled-back aggregate transaction therefore
-- cannot leave a sequence gap.  Publication is a one-way, in-order transition.

BEGIN;

CREATE OR REPLACE FUNCTION app.stage2_opaque_id_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND char_length(value) BETWEEN 1 AND 256
       AND btrim(value) = value
       AND value !~ '[[:cntrl:]]';
$$;

CREATE OR REPLACE FUNCTION app.stage2_sha256_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL AND value ~ '^sha256:[0-9a-f]{64}$';
$$;

CREATE OR REPLACE FUNCTION app.outbox_reference_id_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    -- Typed prefix plus canonical ULID. References are generated opaque IDs,
    -- not caller-selected labels, paths, principals or source-native values.
    SELECT value IS NOT NULL AND value ~ '^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$';
$$;

-- This exact map is intentionally verbose.  A new encrypted owning column is
-- not accepted until this database boundary and the canonical JSON schema are
-- changed together.
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

CREATE TABLE public.encrypted_artifact (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    aad_schema_version text NOT NULL DEFAULT 'encrypted-artifact-aad-v1'
        CHECK (aad_schema_version = 'encrypted-artifact-aad-v1'),
    owner_table text NOT NULL,
    owner_column text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(resource_id)),
    field_name text NOT NULL,
    cipher text NOT NULL DEFAULT 'AES_256_GCM'
        CHECK (cipher = 'AES_256_GCM'),
    ciphertext bytea,
    -- Plaintext size. AES-GCM appends one 16-byte authentication tag.
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 8388608),
    nonce bytea,
    wrapped_dek bytea,
    wrapped_dek_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(wrapped_dek_hash)),
    kek_reference text NOT NULL CHECK (
        char_length(kek_reference) BETWEEN 1 AND 1024
        AND btrim(kek_reference) = kek_reference
        AND kek_reference !~ '[[:cntrl:]]'
    ),
    kek_version bigint NOT NULL CHECK (kek_version BETWEEN 1 AND 9007199254740991),
    aad_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(aad_hash)),
    plaintext_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(plaintext_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    purged_at timestamptz,
    PRIMARY KEY (organization_id, id),
    CHECK (app.encrypted_artifact_owner_is_valid(owner_table, owner_column, resource_type, field_name)),
    CHECK (
        (purged_at IS NULL
         AND ciphertext IS NOT NULL
         AND octet_length(ciphertext) = size_bytes + 16
         AND nonce IS NOT NULL
         AND octet_length(nonce) = 12
         AND wrapped_dek IS NOT NULL
         AND octet_length(wrapped_dek) BETWEEN 1 AND 65536)
        OR
        (purged_at IS NOT NULL
         AND purged_at >= created_at
         AND ciphertext IS NULL
         -- Keep nonce and hashes as non-decryptable purge provenance.
         AND nonce IS NOT NULL
         AND octet_length(nonce) = 12
         AND wrapped_dek IS NULL)
    ),
    -- Stronger than trusting the caller-supplied wrapped_dek_hash: a nonce is
    -- never reused anywhere under one tenant KEK reference/version.
    UNIQUE (organization_id, kek_reference, kek_version, nonce)
);

CREATE INDEX encrypted_artifact_owner_lookup
    ON public.encrypted_artifact (
        organization_id, owner_table, owner_column, resource_id, created_at DESC
    );

CREATE OR REPLACE FUNCTION app.encrypted_artifact_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM 1
        FROM public.organization
        WHERE id = NEW.organization_id AND status = 'ACTIVE'
        -- SHARE conflicts with the NO KEY UPDATE lock used by a concurrent
        -- ACTIVE -> DELETING status transition and is held through commit.
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'encrypted artifact creation requires an active tenant'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.purged_at IS NOT NULL THEN
            RAISE EXCEPTION 'encrypted artifact must be active at creation'
                USING ERRCODE = '55000';
        END IF;
        NEW.created_at := transaction_timestamp();
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR OLD.purged_at IS NULL
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'encrypted artifact deletion requires purged content and tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF session_user = 'knowvault_app' THEN
        RAISE EXCEPTION 'runtime role cannot mutate encrypted artifact'
            USING ERRCODE = '42501';
    END IF;

    IF OLD.purged_at IS NOT NULL
       OR NEW.purged_at IS NULL
       OR NEW.ciphertext IS NOT NULL
       OR NEW.wrapped_dek IS NOT NULL
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.aad_schema_version IS DISTINCT FROM OLD.aad_schema_version
       OR NEW.owner_table IS DISTINCT FROM OLD.owner_table
       OR NEW.owner_column IS DISTINCT FROM OLD.owner_column
       OR NEW.resource_type IS DISTINCT FROM OLD.resource_type
       OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
       OR NEW.field_name IS DISTINCT FROM OLD.field_name
       OR NEW.cipher IS DISTINCT FROM OLD.cipher
       OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
       OR NEW.nonce IS DISTINCT FROM OLD.nonce
       OR NEW.wrapped_dek_hash IS DISTINCT FROM OLD.wrapped_dek_hash
       OR NEW.kek_reference IS DISTINCT FROM OLD.kek_reference
       OR NEW.kek_version IS DISTINCT FROM OLD.kek_version
       OR NEW.aad_hash IS DISTINCT FROM OLD.aad_hash
       OR NEW.plaintext_hash IS DISTINCT FROM OLD.plaintext_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'encrypted artifact permits only irreversible content purge'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER encrypted_artifact_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.encrypted_artifact
FOR EACH ROW EXECUTE FUNCTION app.encrypted_artifact_mutation_guard();

-- Outbox payloads contain references and hashes only.  Searchable content is
-- loaded through an authorized repository by the applier, never copied into a
-- job or dead-letter payload.
CREATE OR REPLACE FUNCTION app.outbox_payload_is_safe(value jsonb)
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
       OR value = '{}'::jsonb
       OR octet_length(value::text) > 16384 THEN
        RETURN false;
    END IF;

    FOR payload_key, payload_value IN SELECT key, val FROM jsonb_each(value) AS item(key, val)
    LOOP
        IF payload_key IN (
            'source_object_id', 'source_version_id', 'extraction_id',
            'evidence_fragment_id', 'search_chunk_id', 'index_generation_id',
            'source_scope_id', 'workspace_id', 'artifact_id'
        ) THEN
            IF jsonb_typeof(payload_value) <> 'string' THEN RETURN false; END IF;
            scalar_value := payload_value #>> '{}';
            IF NOT app.outbox_reference_id_is_valid(scalar_value) THEN RETURN false; END IF;
        ELSIF payload_key IN (
            'content_hash', 'text_hash', 'anchor_hash', 'embedding_profile_hash',
            'embedding_model_artifact_hash'
        ) THEN
            IF jsonb_typeof(payload_value) <> 'string'
               OR NOT app.stage2_sha256_is_valid(payload_value #>> '{}') THEN
                RETURN false;
            END IF;
        ELSIF payload_key IN (
            'retention_fence', 'generation_fence', 'catalog_revision', 'dimension'
        ) THEN
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
        ELSIF payload_key = 'is_current' THEN
            IF jsonb_typeof(payload_value) <> 'boolean' THEN RETURN false; END IF;
        ELSE
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE public.outbox_sequence_head (
    organization_id text PRIMARY KEY
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    last_assigned_sequence bigint NOT NULL DEFAULT 0
        CHECK (last_assigned_sequence BETWEEN 0 AND 9007199254740991),
    last_published_sequence bigint NOT NULL DEFAULT 0
        CHECK (last_published_sequence BETWEEN 0 AND last_assigned_sequence),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.outbox_event (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.outbox_reference_id_is_valid(id)),
    sequence bigint NOT NULL
        CHECK (sequence BETWEEN 1 AND 9007199254740991),
    aggregate_type text NOT NULL CHECK (aggregate_type IN (
        'ENCRYPTED_ARTIFACT', 'SOURCE_OBJECT', 'SOURCE_VERSION',
        'EXTRACTION', 'SEARCH_CHUNK', 'INDEX_GENERATION'
    )),
    aggregate_id text NOT NULL CHECK (app.outbox_reference_id_is_valid(aggregate_id)),
    event_type text NOT NULL CHECK (
        event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
        AND char_length(event_type) <= 128
    ),
    payload_json jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (app.outbox_payload_is_safe(payload_json)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    published_at timestamptz,
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, sequence),
    CHECK (published_at IS NULL OR published_at >= created_at)
);

ALTER TABLE public.outbox_event
    ADD CONSTRAINT outbox_event_sequence_head_fk
    FOREIGN KEY (organization_id)
    REFERENCES public.outbox_sequence_head(organization_id)
    ON DELETE RESTRICT;

CREATE INDEX outbox_event_pending_order
    ON public.outbox_event (organization_id, sequence)
    WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION app.outbox_sequence_head_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.organization
        WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
    ) THEN
        RAISE EXCEPTION 'outbox head deletion requires tenant hard-delete state'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER outbox_sequence_head_delete_only
BEFORE DELETE ON public.outbox_sequence_head
FOR EACH ROW EXECUTE FUNCTION app.outbox_sequence_head_delete_guard();

-- Direct INSERT is not granted. This is the only runtime enqueue capability,
-- so INSERT ... ON CONFLICT cannot run a BEFORE trigger, consume a sequence,
-- and silently discard the event. Any failure rolls back both head and event.
CREATE OR REPLACE FUNCTION app.enqueue_outbox_event(
    event_id_value text,
    aggregate_type_value text,
    aggregate_id_value text,
    event_type_value text,
    payload_value jsonb
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    assigned_sequence bigint;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'outbox enqueue is restricted to the runtime role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'outbox enqueue requires a tenant context'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM public.organization
    WHERE id = organization_value AND status = 'ACTIVE'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'outbox enqueue requires an active tenant'
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.outbox_sequence_head (organization_id)
    VALUES (organization_value)
    ON CONFLICT (organization_id) DO NOTHING;

    UPDATE public.outbox_sequence_head
    SET last_assigned_sequence = last_assigned_sequence + 1,
        updated_at = transaction_timestamp()
    WHERE organization_id = organization_value
      AND last_assigned_sequence < 9007199254740991
    RETURNING last_assigned_sequence INTO assigned_sequence;

    IF assigned_sequence IS NULL THEN
        RAISE EXCEPTION 'outbox sequence exhausted'
            USING ERRCODE = '54000';
    END IF;

    INSERT INTO public.outbox_event (
        organization_id, id, sequence, aggregate_type, aggregate_id,
        event_type, payload_json, created_at, published_at
    ) VALUES (
        organization_value, event_id_value, assigned_sequence,
        aggregate_type_value, aggregate_id_value, event_type_value,
        payload_value, transaction_timestamp(), NULL
    );
    RETURN assigned_sequence;
END;
$$;

CREATE OR REPLACE FUNCTION app.outbox_event_state_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    expected_sequence bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'outbox events are append-only outside tenant hard-delete'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.published_at IS NOT NULL
       OR NEW.published_at IS NULL
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.sequence IS DISTINCT FROM OLD.sequence
       OR NEW.aggregate_type IS DISTINCT FROM OLD.aggregate_type
       OR NEW.aggregate_id IS DISTINCT FROM OLD.aggregate_id
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.payload_json IS DISTINCT FROM OLD.payload_json
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'outbox event permits only first publication transition'
            USING ERRCODE = '55000';
    END IF;

    SELECT last_published_sequence + 1
    INTO expected_sequence
    FROM public.outbox_sequence_head
    WHERE organization_id = OLD.organization_id
    FOR UPDATE;

    IF expected_sequence IS NULL OR OLD.sequence <> expected_sequence THEN
        RAISE EXCEPTION 'outbox event must be published in tenant sequence order'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.outbox_sequence_head
    SET last_published_sequence = OLD.sequence,
        updated_at = transaction_timestamp()
    WHERE organization_id = OLD.organization_id;
    -- Callers request the transition, but cannot choose its trusted time.
    NEW.published_at := transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER outbox_event_state_guard
BEFORE UPDATE OR DELETE ON public.outbox_event
FOR EACH ROW EXECUTE FUNCTION app.outbox_event_state_guard();

ALTER TABLE public.encrypted_artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.encrypted_artifact FORCE ROW LEVEL SECURITY;
CREATE POLICY encrypted_artifact_tenant_isolation ON public.encrypted_artifact
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.outbox_sequence_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.outbox_sequence_head FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_sequence_head_tenant_isolation ON public.outbox_sequence_head
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.outbox_event FORCE ROW LEVEL SECURITY;
CREATE POLICY outbox_event_tenant_isolation ON public.outbox_event
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE
    public.encrypted_artifact,
    public.outbox_sequence_head,
    public.outbox_event
FROM PUBLIC;

GRANT SELECT, INSERT ON TABLE public.encrypted_artifact TO knowvault_app;
-- The runtime can inspect the cursor. SECURITY DEFINER trigger functions own
-- its mutations, so the runtime never receives direct write privileges.
GRANT SELECT ON TABLE public.outbox_sequence_head TO knowvault_app;
-- Delivery is deliberately not granted to the shared Web/API runtime. A
-- dedicated worker role and lease/CAS state machine are a later release gate;
-- until then no production outbox applier may be composed.
GRANT SELECT ON TABLE public.outbox_event TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.stage2_opaque_id_is_valid(text),
    app.stage2_sha256_is_valid(text),
    app.outbox_reference_id_is_valid(text),
    app.encrypted_artifact_owner_is_valid(text, text, text, text),
    app.encrypted_artifact_mutation_guard(),
    app.outbox_payload_is_safe(jsonb),
    app.outbox_sequence_head_delete_guard(),
    app.enqueue_outbox_event(text, text, text, text, jsonb),
    app.outbox_event_state_guard()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.stage2_opaque_id_is_valid(text),
    app.stage2_sha256_is_valid(text),
    app.outbox_reference_id_is_valid(text),
    app.encrypted_artifact_owner_is_valid(text, text, text, text),
    app.outbox_payload_is_safe(jsonb),
    app.enqueue_outbox_event(text, text, text, text, jsonb)
TO knowvault_app;

COMMIT;
