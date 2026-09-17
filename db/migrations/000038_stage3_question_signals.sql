-- Stage 3 typed uncertainty/conflict projection.
--
-- These arrays are durable, bounded Question Run metadata. They contain only
-- server-owned reason codes and concrete Evidence IDs; source text, SQL,
-- credentials and model output never cross this boundary. A conflict record
-- must cite at least two Evidence fragments.

BEGIN;

CREATE OR REPLACE FUNCTION app.question_run_uncertainties_valid(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    item jsonb;
    evidence_id text;
    seen text[] := ARRAY[]::text[];
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array'
       OR jsonb_array_length(value) > 32
       OR octet_length(value::text) > 65536 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value_item FROM jsonb_array_elements(value) AS row(value_item)
    LOOP
        IF jsonb_typeof(item) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(item)) <> 2
           OR NOT (item ? 'code') OR NOT (item ? 'evidence_ids')
           OR jsonb_typeof(item->'code') <> 'string'
           OR item->>'code' !~ '^[A-Z][A-Z0-9_]{2,63}$'
           OR jsonb_typeof(item->'evidence_ids') <> 'array'
           OR jsonb_array_length(item->'evidence_ids') > 256
           OR octet_length((item->'evidence_ids')::text) > 65536 THEN
            RETURN false;
        END IF;
        FOR evidence_id IN SELECT value_item FROM jsonb_array_elements_text(item->'evidence_ids') AS row(value_item)
        LOOP
            IF NOT app.stage2_opaque_id_is_valid(evidence_id) OR evidence_id = ANY(seen) THEN
                RETURN false;
            END IF;
            seen := array_append(seen, evidence_id);
        END LOOP;
    END LOOP;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_run_conflicts_valid(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
DECLARE
    item jsonb;
    evidence_id text;
    seen text[] := ARRAY[]::text[];
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array'
       OR jsonb_array_length(value) > 32
       OR octet_length(value::text) > 65536 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value_item FROM jsonb_array_elements(value) AS row(value_item)
    LOOP
        IF jsonb_typeof(item) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(item)) <> 2
           OR NOT (item ? 'code') OR NOT (item ? 'evidence_ids')
           OR jsonb_typeof(item->'code') <> 'string'
           OR item->>'code' !~ '^[A-Z][A-Z0-9_]{2,63}$'
           OR jsonb_typeof(item->'evidence_ids') <> 'array'
           OR jsonb_array_length(item->'evidence_ids') < 2
           OR jsonb_array_length(item->'evidence_ids') > 256
           OR octet_length((item->'evidence_ids')::text) > 65536 THEN
            RETURN false;
        END IF;
        FOR evidence_id IN SELECT value_item FROM jsonb_array_elements_text(item->'evidence_ids') AS row(value_item)
        LOOP
            IF NOT app.stage2_opaque_id_is_valid(evidence_id) OR evidence_id = ANY(seen) THEN
                RETURN false;
            END IF;
            seen := array_append(seen, evidence_id);
        END LOOP;
    END LOOP;
    RETURN true;
END;
$$;

ALTER TABLE public.question_run
    ADD COLUMN uncertainties_json jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (app.question_run_uncertainties_valid(uncertainties_json)),
    ADD COLUMN conflicts_json jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (app.question_run_conflicts_valid(conflicts_json));

COMMENT ON COLUMN public.question_run.uncertainties_json IS
    'Bounded server-owned reason codes and Evidence IDs for incomplete or ambiguous runs';
COMMENT ON COLUMN public.question_run.conflicts_json IS
    'Bounded server-owned contradiction records; every item cites at least two Evidence IDs';

REVOKE ALL ON FUNCTION app.question_run_uncertainties_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.question_run_conflicts_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_run_uncertainties_valid(jsonb) TO knowvault_app, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.question_run_conflicts_valid(jsonb) TO knowvault_app, knowvault_worker;

COMMIT;
