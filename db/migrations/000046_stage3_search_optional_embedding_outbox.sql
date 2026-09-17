-- 000046: keep lexical search outbox payloads valid when vectors are not
-- qualified.  The durable SearchChunk tuple is intentionally optional: a
-- deployment may publish lexical evidence before a real embedding profile is
-- mounted. PostgreSQL's jsonb_build_object emits JSON null for NULL inputs,
-- while app.outbox_payload_is_safe accepts only typed reference/hash/number
-- values. Omit the optional vector keys unless the complete tuple is present.

BEGIN;

-- A lexical-only worker still needs an explicit generation profile.  The
-- embedding provider is optional, so the profile provenance pair is nullable
-- only as an all-or-nothing pair; a bootstrap must never invent a model or
-- artifact just to satisfy the profile contract.
ALTER TABLE public.organization_search_profile
    DROP CONSTRAINT IF EXISTS organization_search_profile_embedding_tuple,
    ALTER COLUMN embedding_profile_id DROP NOT NULL,
    ALTER COLUMN embedding_profile_hash DROP NOT NULL;

ALTER TABLE public.organization_search_profile
    ADD CONSTRAINT organization_search_profile_embedding_tuple CHECK (
        (
            embedding_profile_id IS NULL
            AND embedding_profile_hash IS NULL
        )
        OR (
            embedding_profile_id IS NOT NULL
            AND embedding_profile_hash IS NOT NULL
            AND app.stage2_sha256_is_valid(embedding_profile_hash)
        )
    );

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
    payload jsonb;
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
    IF chunk_version IS NULL OR chunk_extraction IS NULL OR chunk_hash IS NULL
       OR text_artifact_id IS NULL THEN
        RAISE EXCEPTION 'search chunk outbox has a null required reference' USING ERRCODE = '23514';
    END IF;
    IF (profile_hash IS NULL) <> (model_hash IS NULL)
       OR (profile_hash IS NULL) <> (dimension IS NULL) THEN
        RAISE EXCEPTION 'search chunk embedding tuple is incomplete' USING ERRCODE = '23514';
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

    payload := jsonb_build_object(
        'operation', 'UPSERT',
        'search_chunk_id', p_chunk_id,
        'source_version_id', chunk_version,
        'extraction_id', chunk_extraction,
        'artifact_id', text_artifact_id,
        'text_hash', chunk_hash
    );
    IF profile_hash IS NOT NULL THEN
        payload := payload || jsonb_build_object(
            'embedding_profile_hash', profile_hash,
            'embedding_model_artifact_hash', model_hash,
            'dimension', dimension
        );
    END IF;

    INSERT INTO public.outbox_event (
        organization_id, id, sequence, aggregate_type, aggregate_id,
        event_type, payload_json, created_at, published_at
    ) VALUES (
        organization_value, p_chunk_id, assigned_sequence, 'SEARCH_CHUNK', p_chunk_id,
        'search.chunk.upsert', payload, transaction_timestamp(), NULL
    );
    RETURN assigned_sequence;
END;
$$;

REVOKE ALL ON FUNCTION app.enqueue_search_chunk_upsert(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.enqueue_search_chunk_upsert(text) TO knowvault_worker;

COMMIT;
