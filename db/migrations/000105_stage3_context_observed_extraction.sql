-- A question captures the extraction active when its context is authorized.
-- Its immutable history must not prevent a later extraction from becoming active.
-- The context INSERT guard still proves the live active tuple and revision.
BEGIN;

DO $$
DECLARE
    actual record;
BEGIN
    SELECT c.confrelid, c.confdeltype, c.confupdtype, c.convalidated,
           ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n, ord)
                 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY k.ord) AS child_columns,
           ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n, ord)
                 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.n ORDER BY k.ord) AS parent_columns
    INTO STRICT actual
    FROM pg_catalog.pg_constraint c
    WHERE c.conrelid='public.question_retrieval_context_entry'::regclass
      AND c.conname='question_context_active_extraction_fk' AND c.contype='f';
    IF actual.confrelid <> 'public.source_version_active_extraction'::regclass
       OR actual.confdeltype <> 'r' OR actual.confupdtype <> 'a' OR NOT actual.convalidated
       OR actual.child_columns <> ARRAY['organization_id','source_version_id','active_extraction_id']::text[]
       OR actual.parent_columns <> ARRAY['organization_id','source_version_id','extraction_id']::text[] THEN
        RAISE EXCEPTION 'question context active extraction constraint drift';
    END IF;
END;
$$;

ALTER TABLE public.question_retrieval_context_entry
    DROP CONSTRAINT question_context_active_extraction_fk,
    ADD CONSTRAINT question_context_observed_active_extraction_fk
        FOREIGN KEY (organization_id, source_version_id, active_extraction_id)
        REFERENCES public.source_extraction (organization_id, source_version_id, id)
        ON DELETE RESTRICT;

COMMENT ON CONSTRAINT question_context_observed_active_extraction_fk
    ON public.question_retrieval_context_entry IS
    'Retains the exact extraction active at context authorization; INSERT guard still validates the live pointer and activation revision.';

COMMIT;
