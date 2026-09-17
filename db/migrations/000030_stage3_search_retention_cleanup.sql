-- Stage 3 search retention cleanup.
--
-- SearchChunk text is a decryptable derived copy of Evidence.  A source
-- version purge therefore has two independent obligations: erase that copy
-- from the encrypted-artifact store and enqueue an ordered, idempotent DELETE
-- for the external OpenSearch generation.  The delete is deliberately a
-- durable outbox event: a purge must not claim completion merely because the
-- external cluster happened to be reachable in the purger's transaction.

BEGIN;

CREATE OR REPLACE FUNCTION app.search_chunk_ids_for_purge(p_version_id text)
RETURNS TABLE(search_chunk_id text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT chunk.id
      FROM public.search_chunk AS chunk
     WHERE chunk.organization_id = app.current_organization_id()
       AND chunk.source_version_id = p_version_id
     ORDER BY chunk.id;
$$;

CREATE OR REPLACE FUNCTION app.enqueue_search_chunk_delete(
    p_event_id text, p_chunk_id text, p_version_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text := app.current_organization_id();
    chunk_version text;
    existing_sequence bigint;
    assigned_sequence bigint;
BEGIN
    IF session_user NOT IN ('knowvault_purger', 'knowvault_worker')
       OR organization_value IS NULL
       OR NOT app.outbox_reference_id_is_valid(p_event_id)
       OR NOT app.source_generated_id_is_valid(p_chunk_id, 'chunk')
       OR NOT app.source_generated_id_is_valid(p_version_id, 'version') THEN
        RAISE EXCEPTION 'search chunk delete requires a privileged tenant context'
            USING ERRCODE = '42501';
    END IF;

    SELECT chunk.source_version_id
      INTO chunk_version
      FROM public.search_chunk AS chunk
     WHERE chunk.organization_id = organization_value
       AND chunk.id = p_chunk_id;
    IF NOT FOUND OR chunk_version IS DISTINCT FROM p_version_id THEN
        RAISE EXCEPTION 'search chunk delete lineage mismatch' USING ERRCODE = '23514';
    END IF;

    -- Cleanup is retried after crashes.  One aggregate receives one DELETE
    -- event regardless of how many times the purger is called.
    SELECT event.sequence
      INTO existing_sequence
      FROM public.outbox_event AS event
     WHERE event.organization_id = organization_value
       AND event.aggregate_type = 'SEARCH_CHUNK'
       AND event.aggregate_id = p_chunk_id
       AND event.event_type = 'search.chunk.delete';
    IF FOUND THEN
        RETURN existing_sequence;
    END IF;

    PERFORM 1
      FROM public.source_version_retention AS retention
     WHERE retention.organization_id = organization_value
       AND retention.source_version_id = p_version_id
       AND retention.state IN ('PURGING', 'PURGED');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search chunk delete requires a committed purge' USING ERRCODE = '55000';
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
        organization_value, p_event_id, assigned_sequence, 'SEARCH_CHUNK', p_chunk_id,
        'search.chunk.delete',
        jsonb_build_object(
            'operation', 'DELETE',
            'search_chunk_id', p_chunk_id,
            'source_version_id', p_version_id
        ),
        transaction_timestamp(), NULL
    );
    RETURN assigned_sequence;
END;
$$;

-- Replace the existing cleanup body without changing its public signature or
-- privilege.  SearchChunk text is erased in the same resumable transaction as
-- Evidence text; the external DELETE itself is handled later by the worker.
CREATE OR REPLACE FUNCTION app.source_version_purge_cleanup(
    p_organization_id text, p_version_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    purged_count bigint;
BEGIN
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.source_version_retention
                   WHERE organization_id = p_organization_id AND source_version_id = p_version_id
                     AND state IN ('PURGING', 'PURGED')) THEN
        RAISE EXCEPTION 'cleanup requires a PURGING/PURGED version retention' USING ERRCODE = '55000';
    END IF;

    WITH cleaned AS (
        UPDATE public.encrypted_artifact AS artifact
           SET ciphertext = NULL, wrapped_dek = NULL, purged_at = now()
         WHERE artifact.organization_id = p_organization_id
           AND artifact.purged_at IS NULL
           AND (
               (artifact.owner_table = 'evidence_fragment' AND artifact.resource_id IN (
                   SELECT fragment.id FROM public.evidence_fragment AS fragment
                    WHERE fragment.organization_id = p_organization_id
                      AND fragment.source_version_id = p_version_id
               ))
               OR
               (artifact.owner_table = 'search_chunk' AND artifact.resource_id IN (
                   SELECT chunk.id FROM public.search_chunk AS chunk
                    WHERE chunk.organization_id = p_organization_id
                      AND chunk.source_version_id = p_version_id
               ))
           )
        RETURNING 1
    )
    SELECT count(*) INTO purged_count FROM cleaned;

    DELETE FROM public.evidence_text_projection AS projection
     USING public.evidence_fragment AS fragment
     WHERE projection.organization_id = fragment.organization_id
       AND projection.fragment_id = fragment.id
       AND fragment.organization_id = p_organization_id
       AND fragment.source_version_id = p_version_id;

    DELETE FROM public.evidence_anchor_projection AS projection
     USING public.evidence_fragment AS fragment
     WHERE projection.organization_id = fragment.organization_id
       AND projection.fragment_id = fragment.id
       AND fragment.organization_id = p_organization_id
       AND fragment.source_version_id = p_version_id;

    UPDATE public.evidence_fragment AS fragment
       SET text_hash = NULL, text_digest_key_version = NULL,
           anchor_hash = NULL, anchor_digest_key_version = NULL
     WHERE fragment.organization_id = p_organization_id
       AND fragment.source_version_id = p_version_id
       AND (fragment.text_hash IS NOT NULL OR fragment.anchor_hash IS NOT NULL);

    RETURN purged_count;
END;
$$;

-- CompletePurge must not be able to move a version to PURGED while a derived
-- SearchChunk ciphertext remains decryptable.
CREATE OR REPLACE FUNCTION app.source_version_complete_purge(
    p_organization_id text, p_version_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    object_id text;
    current_state text;
BEGIN
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;
    SELECT state INTO current_state FROM public.source_version_retention
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'version retention not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_state <> 'PURGING' THEN
        RAISE EXCEPTION 'completion requires a PURGING version retention' USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.encrypted_artifact AS artifact
         WHERE artifact.organization_id = p_organization_id
           AND artifact.purged_at IS NULL
           AND (
               (artifact.owner_table = 'evidence_fragment' AND artifact.resource_id IN (
                   SELECT fragment.id FROM public.evidence_fragment AS fragment
                    WHERE fragment.organization_id = p_organization_id
                      AND fragment.source_version_id = p_version_id
               ))
               OR
               (artifact.owner_table = 'search_chunk' AND artifact.resource_id IN (
                   SELECT chunk.id FROM public.search_chunk AS chunk
                    WHERE chunk.organization_id = p_organization_id
                      AND chunk.source_version_id = p_version_id
               ))
           )
    ) THEN
        RAISE EXCEPTION 'completion blocked: decryptable source-derived artifacts remain' USING ERRCODE = '55000';
    END IF;

    IF EXISTS (SELECT 1 FROM public.source_version_active_extraction
               WHERE organization_id = p_organization_id AND source_version_id = p_version_id) THEN
        RAISE EXCEPTION 'completion blocked: active extraction pointer remains' USING ERRCODE = '55000';
    END IF;

    IF EXISTS (SELECT 1 FROM public.job
               WHERE organization_id = p_organization_id AND status = 'RUNNING'
                 AND type IN ('SOURCE_OBJECT_EXTRACTION', 'SOURCE_VERSION_PURGE')
                 AND payload_json ->> 'source_version_id' = p_version_id) THEN
        RAISE EXCEPTION 'completion blocked: a running job of the version remains' USING ERRCODE = '55000';
    END IF;

    UPDATE public.source_version_retention
       SET state = 'PURGED', queryable = false, extraction_allowed = false, purged_at = now()
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id;

    UPDATE public.source_extraction_retention AS retention
       SET state = 'PURGED', queryable = false, purged_at = now()
      FROM public.source_extraction AS extraction
     WHERE retention.organization_id = p_organization_id
       AND extraction.organization_id = p_organization_id
       AND retention.extraction_id = extraction.id
       AND extraction.source_version_id = p_version_id
       AND retention.state <> 'PURGED';

    UPDATE public.source_version
       SET state = 'REDACTED'
     WHERE organization_id = p_organization_id AND id = p_version_id AND state <> 'REDACTED';

    SELECT source_object_id INTO object_id FROM public.source_version
     WHERE organization_id = p_organization_id AND id = p_version_id;
    UPDATE public.source_object
       SET queryable = false, last_seen_at = now()
     WHERE organization_id = p_organization_id AND id = object_id
       AND current_version_id = p_version_id;
END;
$$;

-- The original publication function accepted only UPSERT events.  Retention
-- DELETEs use the exact same tenant-sequence guard and publication transition;
-- widening only the event-type allowlist keeps the capability narrow while
-- allowing a purge to drain its durable cleanup event.
CREATE OR REPLACE FUNCTION app.publish_search_chunk_outbox(
    p_event_id text,
    p_expected_sequence bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text := app.current_organization_id();
    event_sequence bigint;
    event_aggregate_type text;
    event_aggregate_id text;
    event_type text;
    event_published_at timestamptz;
BEGIN
    IF session_user <> 'knowvault_worker'
       OR organization_value IS NULL
       OR NOT app.outbox_reference_id_is_valid(p_event_id)
       OR p_expected_sequence < 1
       OR p_expected_sequence > 9007199254740991 THEN
        RAISE EXCEPTION 'search outbox publication requires the worker tenant context'
            USING ERRCODE = '42501';
    END IF;

    SELECT event.sequence, event.aggregate_type, event.aggregate_id,
           event.event_type, event.published_at
      INTO event_sequence, event_aggregate_type, event_aggregate_id,
           event_type, event_published_at
      FROM public.outbox_event AS event
     WHERE event.organization_id = organization_value
       AND event.id = p_event_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF event_aggregate_type <> 'SEARCH_CHUNK'
       OR event_aggregate_id IS NULL
       OR event_type NOT IN ('search.chunk.upsert', 'search.chunk.delete') THEN
        RAISE EXCEPTION 'outbox event is not a search chunk mutation'
            USING ERRCODE = '23514';
    END IF;
    IF event_published_at IS NOT NULL THEN
        RETURN true;
    END IF;
    IF event_sequence <> p_expected_sequence THEN
        RAISE EXCEPTION 'search outbox event is not the requested sequence'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.outbox_event
       SET published_at = transaction_timestamp()
     WHERE organization_id = organization_value
       AND id = p_event_id
       AND published_at IS NULL;
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION
    app.search_chunk_ids_for_purge(text),
    app.enqueue_search_chunk_delete(text, text, text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.search_chunk_ids_for_purge(text),
    app.enqueue_search_chunk_delete(text, text, text)
TO knowvault_purger, knowvault_worker;

COMMIT;
