-- Stage 3 ordered search outbox applier boundary.
--
-- The worker may inspect only the next tenant-local pending outbox event and
-- may publish it through the narrow function below.  It never receives a
-- generic UPDATE capability on outbox_event: the existing append-only trigger
-- still owns sequence order and publication timestamps.

BEGIN;

CREATE OR REPLACE FUNCTION app.search_chunk_outbox_next()
RETURNS TABLE(
    event_id text,
    event_sequence bigint,
    aggregate_type text,
    aggregate_id text,
    event_type text,
    payload_json jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT event.id, event.sequence, event.aggregate_type, event.aggregate_id,
           event.event_type, event.payload_json
      FROM public.outbox_event AS event
     WHERE event.organization_id = app.current_organization_id()
       AND event.published_at IS NULL
     ORDER BY event.sequence
     LIMIT 1;
$$;

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
       OR event_aggregate_id <> p_event_id
       OR event_type <> 'search.chunk.upsert' THEN
        RAISE EXCEPTION 'outbox event is not a search chunk upsert'
            USING ERRCODE = '23514';
    END IF;
    IF event_published_at IS NOT NULL THEN
        RETURN true;
    END IF;
    IF event_sequence <> p_expected_sequence THEN
        RAISE EXCEPTION 'search outbox event is not the requested sequence'
            USING ERRCODE = '55000';
    END IF;

    -- The existing outbox_event_state_guard verifies the tenant head and
    -- advances last_published_sequence atomically.  This function adds only
    -- the worker/event-type capability boundary.
    UPDATE public.outbox_event
       SET published_at = transaction_timestamp()
     WHERE organization_id = organization_value
       AND id = p_event_id
       AND published_at IS NULL;
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION app.search_chunk_outbox_next() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.publish_search_chunk_outbox(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.search_chunk_outbox_next() TO knowvault_worker;
GRANT EXECUTE ON FUNCTION app.publish_search_chunk_outbox(text, bigint) TO knowvault_worker;

COMMIT;
