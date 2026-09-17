-- Stage 3 P3 retrieval persistence foundation.
--
-- These relations are the durable source of truth for search projections; they
-- do not enable a search runtime by themselves. OpenSearch mutations remain an
-- ordered outbox concern, and every candidate must be post-authorized against
-- the current PostgreSQL workspace/Evidence authority before disclosure.

BEGIN;

CREATE TABLE public.search_chunk (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'chunk')),
    source_version_id text NOT NULL,
    extraction_id text NOT NULL,
    chunk_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(chunk_hash)),
    search_text_artifact_id text CHECK (
        search_text_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(search_text_artifact_id)
    ),
    token_count bigint NOT NULL CHECK (token_count BETWEEN 0 AND 9007199254740991),
    embedding_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(embedding_profile_hash)),
    embedding_model_artifact_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(embedding_model_artifact_hash)),
    embedding_dimension integer NOT NULL CHECK (embedding_dimension BETWEEN 1 AND 65536),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, source_version_id, extraction_id, id),
    CONSTRAINT search_chunk_extraction_fk
        FOREIGN KEY (organization_id, source_version_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, source_version_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT search_chunk_text_artifact_fk
        FOREIGN KEY (organization_id, search_text_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX search_chunk_extraction_lookup
    ON public.search_chunk (organization_id, source_version_id, extraction_id, id);

CREATE TABLE public.organization_search_profile (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    embedding_profile_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(embedding_profile_id)),
    embedding_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(embedding_profile_hash)),
    index_generation bigint NOT NULL CHECK (index_generation BETWEEN 1 AND 9007199254740991),
    activation_revision bigint NOT NULL CHECK (activation_revision BETWEEN 1 AND 9007199254740991),
    generation_fence bigint NOT NULL CHECK (generation_fence BETWEEN 0 AND 9007199254740991),
    catalog_snapshot_watermark bigint NOT NULL CHECK (catalog_snapshot_watermark BETWEEN 0 AND 9007199254740991),
    outbox_applied_sequence bigint NOT NULL CHECK (outbox_applied_sequence BETWEEN 0 AND 9007199254740991),
    status text NOT NULL CHECK (status IN ('STAGING', 'ACTIVE', 'FAILED')),
    activated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id),
    UNIQUE (organization_id, index_generation),
    CHECK ((status = 'ACTIVE') = (activated_at IS NOT NULL))
);

CREATE TABLE public.search_chunk_fragment (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    search_chunk_id text NOT NULL,
    evidence_fragment_id text NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (organization_id, search_chunk_id, evidence_fragment_id),
    UNIQUE (organization_id, search_chunk_id, ordinal),
    CONSTRAINT search_chunk_fragment_chunk_fk
        FOREIGN KEY (organization_id, search_chunk_id)
        REFERENCES public.search_chunk (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT search_chunk_fragment_evidence_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT
);

CREATE INDEX search_chunk_fragment_evidence_lookup
    ON public.search_chunk_fragment (organization_id, evidence_fragment_id, search_chunk_id);

-- SearchChunk is an immutable derived projection. It can be created only by a
-- worker after a successful, retained extraction; activation of that
-- extraction is a separate fenced catalog transition.
CREATE OR REPLACE FUNCTION app.search_chunk_guard()
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
            RAISE EXCEPTION 'search_chunk deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_worker' THEN
            RAISE EXCEPTION 'search_chunk creation requires worker role' USING ERRCODE = '42501';
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM public.source_extraction extraction
            JOIN public.source_extraction_retention extraction_retention
              ON extraction_retention.organization_id = extraction.organization_id
             AND extraction_retention.extraction_id = extraction.id
            JOIN public.source_version_retention version_retention
              ON version_retention.organization_id = extraction.organization_id
             AND version_retention.source_version_id = extraction.source_version_id
            WHERE extraction.organization_id = NEW.organization_id
              AND extraction.source_version_id = NEW.source_version_id
              AND extraction.id = NEW.extraction_id
              AND extraction.status = 'SUCCEEDED'
              AND extraction_retention.state = 'ACTIVE'
              AND extraction_retention.queryable
              AND version_retention.state = 'ACTIVE'
              AND version_retention.queryable
        ) THEN
            RAISE EXCEPTION 'search_chunk requires a successful retained extraction' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF session_user <> 'knowvault_worker'
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.extraction_id IS DISTINCT FROM OLD.extraction_id
       OR NEW.chunk_hash IS DISTINCT FROM OLD.chunk_hash
       OR NEW.token_count IS DISTINCT FROM OLD.token_count
       OR NEW.embedding_profile_hash IS DISTINCT FROM OLD.embedding_profile_hash
       OR NEW.embedding_model_artifact_hash IS DISTINCT FROM OLD.embedding_model_artifact_hash
       OR NEW.embedding_dimension IS DISTINCT FROM OLD.embedding_dimension
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.search_text_artifact_id IS NOT NULL
       OR NEW.search_text_artifact_id IS NULL THEN
        RAISE EXCEPTION 'search_chunk identity is immutable and its text artifact binds once' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.search_chunk_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.search_chunk chunk
        JOIN public.encrypted_artifact artifact
          ON artifact.organization_id = chunk.organization_id
         AND artifact.id = chunk.search_text_artifact_id
        WHERE chunk.organization_id = NEW.organization_id
          AND chunk.id = NEW.id
          AND artifact.owner_table = 'search_chunk'
          AND artifact.owner_column = 'search_text_artifact_id'
          AND artifact.resource_type = 'SEARCH_CHUNK_TEXT'
          AND artifact.field_name = 'NORMALIZED_TEXT'
          AND artifact.resource_id = NEW.id
          AND artifact.plaintext_hash = NEW.chunk_hash
          AND artifact.purged_at IS NULL
    ) THEN
        RAISE EXCEPTION 'search_chunk text artifact does not exactly own the row' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- The bind/read pair is the only worker path that may create searchable clear
-- text. The owning row is inserted first with a NULL branch and is linked in
-- this same transaction; the deferred exact-owner trigger closes the gap.
CREATE OR REPLACE FUNCTION app.search_chunk_bind_text(
    p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
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
    IF p_org IS DISTINCT FROM app.current_organization_id()
       OR session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'search chunk artifact bind requires worker tenant context' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
        RAISE EXCEPTION 'resource id must equal search chunk id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, aad_schema_version, owner_table, owner_column,
        resource_type, resource_id, field_name, cipher, ciphertext, size_bytes,
        nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version,
        aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'search_chunk',
        'search_text_artifact_id', 'SEARCH_CHUNK_TEXT', p_resource_id,
        'NORMALIZED_TEXT', 'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce,
        p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version,
        p_aad_hash, p_plaintext_hash
    );
    UPDATE public.search_chunk
       SET search_text_artifact_id = p_artifact_id
     WHERE organization_id = p_org AND id = p_owning_row_id
       AND search_text_artifact_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning search chunk missing or already bound' USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.search_chunk_read_text(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea,
    wrapped_dek bytea, wrapped_dek_hash text, kek_reference text, kek_version bigint,
    aad_hash text, plaintext_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT artifact.resource_id, artifact.ciphertext, artifact.size_bytes,
           artifact.nonce, artifact.wrapped_dek, artifact.wrapped_dek_hash,
           artifact.kek_reference, artifact.kek_version, artifact.aad_hash,
           artifact.plaintext_hash
      FROM public.search_chunk chunk
      JOIN public.encrypted_artifact artifact
        ON artifact.organization_id = chunk.organization_id
       AND artifact.id = chunk.search_text_artifact_id
     WHERE chunk.organization_id = app.current_organization_id()
       AND chunk.id = p_owning_row_id
       AND artifact.purged_at IS NULL;
$$;

-- A SearchChunk becomes indexable only after its durable row and encrypted text
-- owner are both committed in the caller transaction.  The event id is the
-- immutable chunk id: one chunk has one initial UPSERT event, and a retry after
-- a committed transaction is idempotent rather than allocating a second
-- sequence value.  The worker cannot call the generic app enqueue function,
-- which remains an application-command capability; this narrow function is the
-- only projection publication capability exposed to knowvault_worker.
CREATE OR REPLACE FUNCTION app.enqueue_search_chunk_upsert(p_chunk_id text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    assigned_sequence bigint;
    existing_sequence bigint;
    existing_type text;
    existing_aggregate text;
    existing_event_type text;
    chunk_version text;
    chunk_extraction text;
    chunk_hash text;
    text_artifact_id text;
    profile_hash text;
    model_hash text;
    dimension integer;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'search chunk outbox requires worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL OR NOT app.source_generated_id_is_valid(p_chunk_id, 'chunk') THEN
        RAISE EXCEPTION 'search chunk outbox requires worker tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT event.sequence, event.aggregate_type, event.aggregate_id, event.event_type
      INTO existing_sequence, existing_type, existing_aggregate, existing_event_type
      FROM public.outbox_event event
     WHERE event.organization_id = organization_value AND event.id = p_chunk_id;
    IF FOUND THEN
        IF existing_type <> 'SEARCH_CHUNK'
           OR existing_aggregate <> p_chunk_id
           OR existing_event_type <> 'search.chunk.upsert' THEN
            RAISE EXCEPTION 'search chunk outbox id is already used by another event' USING ERRCODE = '23505';
        END IF;
        RETURN existing_sequence;
    END IF;

    SELECT chunk.source_version_id, chunk.extraction_id, chunk.chunk_hash,
           chunk.search_text_artifact_id, chunk.embedding_profile_hash,
           chunk.embedding_model_artifact_hash, chunk.embedding_dimension
      INTO chunk_version, chunk_extraction, chunk_hash, text_artifact_id,
           profile_hash, model_hash, dimension
      FROM public.search_chunk chunk
     WHERE chunk.organization_id = organization_value
       AND chunk.id = p_chunk_id
       AND chunk.search_text_artifact_id IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search chunk outbox requires a bound text artifact' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
      FROM public.organization
     WHERE id = organization_value AND status = 'ACTIVE'
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search chunk outbox requires an active tenant' USING ERRCODE = '55000';
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
        RAISE EXCEPTION 'outbox sequence exhausted' USING ERRCODE = '54000';
    END IF;

    INSERT INTO public.outbox_event (
        organization_id, id, sequence, aggregate_type, aggregate_id,
        event_type, payload_json, created_at, published_at
    ) VALUES (
        organization_value, p_chunk_id, assigned_sequence, 'SEARCH_CHUNK', p_chunk_id,
        'search.chunk.upsert',
        jsonb_build_object(
            'operation', 'UPSERT',
            'search_chunk_id', p_chunk_id,
            'source_version_id', chunk_version,
            'extraction_id', chunk_extraction,
            'artifact_id', text_artifact_id,
            'text_hash', chunk_hash,
            'embedding_profile_hash', profile_hash,
            'embedding_model_artifact_hash', model_hash,
            'dimension', dimension
        ),
        transaction_timestamp(), NULL
    );
    RETURN assigned_sequence;
END;
$$;

CREATE OR REPLACE FUNCTION app.search_chunk_fragment_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    chunk_version text;
    chunk_extraction text;
    fragment_version text;
    fragment_extraction text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'search_chunk_fragment deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'search_chunk_fragment is immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'search_chunk_fragment creation requires worker role' USING ERRCODE = '42501';
    END IF;

    SELECT source_version_id, extraction_id
      INTO chunk_version, chunk_extraction
      FROM public.search_chunk
     WHERE organization_id = NEW.organization_id AND id = NEW.search_chunk_id;
    SELECT source_version_id, extraction_id
      INTO fragment_version, fragment_extraction
      FROM public.evidence_fragment
     WHERE organization_id = NEW.organization_id AND id = NEW.evidence_fragment_id;
    IF chunk_version IS NULL OR fragment_version IS NULL
       OR chunk_version IS DISTINCT FROM fragment_version
       OR chunk_extraction IS DISTINCT FROM fragment_extraction THEN
        RAISE EXCEPTION 'search_chunk_fragment lineage must exact-match chunk and Evidence' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.organization_search_profile_guard()
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
            RAISE EXCEPTION 'organization_search_profile deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_worker' THEN
            RAISE EXCEPTION 'organization_search_profile creation requires worker role' USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    IF session_user <> 'knowvault_worker'
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.embedding_profile_id IS DISTINCT FROM OLD.embedding_profile_id
       OR NEW.embedding_profile_hash IS DISTINCT FROM OLD.embedding_profile_hash
       OR NEW.index_generation IS DISTINCT FROM OLD.index_generation
       OR NEW.activation_revision IS DISTINCT FROM OLD.activation_revision
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at)
       OR NEW.generation_fence < OLD.generation_fence
       OR NEW.catalog_snapshot_watermark < OLD.catalog_snapshot_watermark
       OR NEW.outbox_applied_sequence < OLD.outbox_applied_sequence THEN
        RAISE EXCEPTION 'organization_search_profile identity or watermarks are immutable/monotonic' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'FAILED' OR (OLD.status = 'ACTIVE' AND NEW.status <> 'ACTIVE')
       OR (OLD.status <> 'STAGING' AND NEW.status = 'STAGING') THEN
        RAISE EXCEPTION 'organization_search_profile status does not reverse' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'ACTIVE' AND NEW.activated_at IS NULL THEN
        RAISE EXCEPTION 'active search profile requires activation timestamp' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER search_chunk_state_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.search_chunk
    FOR EACH ROW EXECUTE FUNCTION app.search_chunk_guard();
CREATE CONSTRAINT TRIGGER search_chunk_artifact_exact
    AFTER INSERT ON public.search_chunk
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app.search_chunk_artifact_guard();
CREATE TRIGGER search_chunk_fragment_state_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.search_chunk_fragment
    FOR EACH ROW EXECUTE FUNCTION app.search_chunk_fragment_guard();
CREATE TRIGGER organization_search_profile_state_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.organization_search_profile
    FOR EACH ROW EXECUTE FUNCTION app.organization_search_profile_guard();

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'search_chunk', 'organization_search_profile', 'search_chunk_fragment'
    ] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON public.%I USING (organization_id = app.current_organization_id())',
            table_name || '_tenant_isolation', table_name
        );
    END LOOP;
END;
$$;

REVOKE ALL ON TABLE
    public.search_chunk, public.organization_search_profile,
    public.search_chunk_fragment
FROM PUBLIC;

GRANT SELECT, INSERT ON TABLE public.search_chunk TO knowvault_worker;
GRANT SELECT, INSERT, UPDATE ON TABLE public.organization_search_profile TO knowvault_worker;
GRANT SELECT, INSERT ON TABLE public.search_chunk_fragment TO knowvault_worker;
GRANT SELECT ON TABLE
    public.search_chunk, public.organization_search_profile,
    public.search_chunk_fragment
TO knowvault_app;

GRANT EXECUTE ON FUNCTION
    app.source_generated_id_is_valid(text, text),
    app.stage2_opaque_id_is_valid(text),
    app.stage2_sha256_is_valid(text),
    app.search_chunk_bind_text(text, text, text, text, bytea, integer, bytea,
        bytea, text, text, bigint, text, text),
    app.search_chunk_read_text(text),
    app.enqueue_search_chunk_upsert(text)
TO knowvault_worker;

REVOKE ALL ON FUNCTION
    app.search_chunk_bind_text(text, text, text, text, bytea, integer, bytea,
        bytea, text, text, bigint, text, text),
    app.search_chunk_read_text(text),
    app.enqueue_search_chunk_upsert(text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.search_chunk_read_text(text) TO knowvault_app;

COMMIT;
