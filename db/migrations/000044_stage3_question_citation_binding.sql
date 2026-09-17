-- Stage 3 question-citation provenance hardening.
--
-- Migration 000024 was authored before the Evidence text projection became an
-- organization-keyed HMAC.  Its citation CHECK consequently accepted plain
-- SHA-256 and the trigger did not bind citation provenance back to the exact
-- Evidence row.  This forward migration refuses an already-corrupt candidate,
-- then makes every newly persisted citation carry the trusted keyed digest and
-- exact source/version/extraction lineage.

BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.question_citation
        WHERE evidence_text_hash IS NULL
           OR evidence_text_hash !~ '^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$'
    ) THEN
        RAISE EXCEPTION 'question citation contains a non-keyed evidence digest; refuse unsafe migration'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE public.question_citation
    DROP CONSTRAINT IF EXISTS question_citation_evidence_text_hash_check;

ALTER TABLE public.question_citation
    ADD CONSTRAINT question_citation_evidence_text_hash_check
    CHECK (evidence_text_hash ~ '^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$');

CREATE OR REPLACE FUNCTION app.question_citation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_workspace_id text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'question citations are immutable' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.id IS DISTINCT FROM OLD.id
           OR NEW.question_run_id IS DISTINCT FROM OLD.question_run_id
           OR NEW.citation_number IS DISTINCT FROM OLD.citation_number
           OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
           OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
           OR NEW.extraction_id IS DISTINCT FROM OLD.extraction_id
           OR NEW.evidence_fragment_id IS DISTINCT FROM OLD.evidence_fragment_id
           OR NEW.source_version_content_hash IS DISTINCT FROM OLD.source_version_content_hash
           OR NEW.evidence_text_hash IS DISTINCT FROM OLD.evidence_text_hash
           OR NEW.cited_excerpt_hash IS DISTINCT FROM OLD.cited_excerpt_hash
           OR NEW.state_at_generation IS DISTINCT FROM OLD.state_at_generation
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'question citation identity is immutable' USING ERRCODE = '55000';
        END IF;
        IF OLD.cited_excerpt_artifact_id IS NOT NULL AND NEW.cited_excerpt_artifact_id IS DISTINCT FROM OLD.cited_excerpt_artifact_id THEN
            RAISE EXCEPTION 'citation excerpt artifact is write-once' USING ERRCODE = '55000';
        END IF;
        IF OLD.anchor_artifact_id IS NOT NULL AND NEW.anchor_artifact_id IS DISTINCT FROM OLD.anchor_artifact_id THEN
            RAISE EXCEPTION 'citation anchor artifact is write-once' USING ERRCODE = '55000';
        END IF;
        IF OLD.deep_link_artifact_id IS NOT NULL AND NEW.deep_link_artifact_id IS DISTINCT FROM OLD.deep_link_artifact_id THEN
            RAISE EXCEPTION 'citation link artifact is write-once' USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;

    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'citation requires the tenant application role' USING ERRCODE = '42501';
    END IF;

    SELECT run.workspace_id
      INTO run_workspace_id
      FROM public.question_run run
     WHERE run.organization_id = NEW.organization_id
       AND run.id = NEW.question_run_id
       AND run.result_status IN ('QUEUED', 'RUNNING');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'citation requires an active question run' USING ERRCODE = '42501';
    END IF;

    -- The citation is accepted only when all identity fields and the keyed
    -- Evidence projection are copied from one current, readable fragment.  A
    -- caller cannot select a valid hash from one row and provenance from
    -- another, nor insert a citation for an inaccessible workspace source.
    IF NOT EXISTS (
        SELECT 1
          FROM public.evidence_fragment f
          JOIN public.source_version v
            ON v.organization_id = f.organization_id
           AND v.id = f.source_version_id
         WHERE f.organization_id = NEW.organization_id
           AND f.id = NEW.evidence_fragment_id
           AND f.source_version_id = NEW.source_version_id
           AND f.extraction_id = NEW.extraction_id
           AND f.text_hash = NEW.evidence_text_hash
           AND v.source_object_id = NEW.source_object_id
           AND v.content_hash = NEW.source_version_content_hash
           AND app.evidence_fragment_readable(f.id, run_workspace_id)
    ) THEN
        RAISE EXCEPTION 'citation provenance does not match a readable Evidence fragment' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
