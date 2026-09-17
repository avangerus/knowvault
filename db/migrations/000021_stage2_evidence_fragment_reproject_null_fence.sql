-- Stage 2 evidence fragment reproject NULL fence (ADR-0077 §1.3 hardening).
--
-- 000020 lets the worker digest reproject branch move either keyed pair to
-- NULL: `IS DISTINCT FROM` is true for the (NULL, NULL) shape, so a worker
-- could erase one or both pairs and RETURN NEW before the immutability fence.
-- The NULL shape is reserved for purge cleanup (knowvault_purger, PURGING/
-- PURGED versions) and must stay unreachable for the worker.
--
-- This migration redefines the fragment guard so the worker reproject branch
-- additionally requires all four digest columns to stay non-NULL; a NULL
-- transition now falls through to the immutability fence and fails closed.
-- The legitimate reproject flow (rotation/handler reprojectOne) writes both
-- complete pairs in one update and is unaffected.

BEGIN;

CREATE OR REPLACE FUNCTION app.evidence_fragment_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'evidence_fragment deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.text_digest_key_version IS NULL OR NEW.anchor_digest_key_version IS NULL THEN
            RAISE EXCEPTION 'evidence fragment requires keyed anchor and text digests'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    -- Purge erasure branch: purge cleanup erases both hash pairs of a
    -- PURGING/PURGED version, and nothing else may move.  The NULL shape is
    -- therefore reachable only through the purge cleanup function.
    IF session_user = 'knowvault_purger'
       AND NEW.text_hash IS NULL AND NEW.text_digest_key_version IS NULL
       AND NEW.anchor_hash IS NULL AND NEW.anchor_digest_key_version IS NULL
       AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.source_version_id IS NOT DISTINCT FROM OLD.source_version_id
       AND NEW.extraction_id IS NOT DISTINCT FROM OLD.extraction_id
       AND NEW.ordinal IS NOT DISTINCT FROM OLD.ordinal
       AND NEW.token_count IS NOT DISTINCT FROM OLD.token_count
       AND NEW.byte_count IS NOT DISTINCT FROM OLD.byte_count
       AND NEW.extraction_confidence IS NOT DISTINCT FROM OLD.extraction_confidence
       AND NEW.language IS NOT DISTINCT FROM OLD.language
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.normalized_text_artifact_id IS NOT DISTINCT FROM OLD.normalized_text_artifact_id
       AND NEW.anchor_artifact_id IS NOT DISTINCT FROM OLD.anchor_artifact_id
       AND NEW.metadata_artifact_id IS NOT DISTINCT FROM OLD.metadata_artifact_id
       AND EXISTS (SELECT 1 FROM public.source_version_retention vr
                   WHERE vr.organization_id = NEW.organization_id
                     AND vr.source_version_id = NEW.source_version_id
                     AND vr.state IN ('PURGING', 'PURGED')) THEN
        RETURN NEW;
    END IF;

    -- Digest reproject branch: only the two keyed projection pairs move; the
    -- fragment identity stays byte-identical.  Both destination pairs must be
    -- complete (all four digest columns non-NULL): a NULL transition is the
    -- purge shape and falls through to the immutability fence instead.
    -- NULLable identity columns (confidence, language, optional artifact
    -- bindings) compare with IS NOT DISTINCT FROM so NULL stays NULL.
    IF session_user = 'knowvault_worker'
       AND (
           (NEW.anchor_hash, NEW.anchor_digest_key_version)
               IS DISTINCT FROM (OLD.anchor_hash, OLD.anchor_digest_key_version)
           OR (NEW.text_hash, NEW.text_digest_key_version)
               IS DISTINCT FROM (OLD.text_hash, OLD.text_digest_key_version)
       )
       AND NEW.anchor_hash IS NOT NULL
       AND NEW.anchor_digest_key_version IS NOT NULL
       AND NEW.text_hash IS NOT NULL
       AND NEW.text_digest_key_version IS NOT NULL
       AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.source_version_id IS NOT DISTINCT FROM OLD.source_version_id
       AND NEW.extraction_id IS NOT DISTINCT FROM OLD.extraction_id
       AND NEW.ordinal IS NOT DISTINCT FROM OLD.ordinal
       AND NEW.token_count IS NOT DISTINCT FROM OLD.token_count
       AND NEW.byte_count IS NOT DISTINCT FROM OLD.byte_count
       AND NEW.extraction_confidence IS NOT DISTINCT FROM OLD.extraction_confidence
       AND NEW.language IS NOT DISTINCT FROM OLD.language
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.normalized_text_artifact_id IS NOT DISTINCT FROM OLD.normalized_text_artifact_id
       AND NEW.anchor_artifact_id IS NOT DISTINCT FROM OLD.anchor_artifact_id
       AND NEW.metadata_artifact_id IS NOT DISTINCT FROM OLD.metadata_artifact_id THEN
        RETURN NEW;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.extraction_id IS DISTINCT FROM OLD.extraction_id
       OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
       OR NEW.text_hash IS DISTINCT FROM OLD.text_hash
       OR NEW.text_digest_key_version IS DISTINCT FROM OLD.text_digest_key_version
       OR NEW.token_count IS DISTINCT FROM OLD.token_count
       OR NEW.byte_count IS DISTINCT FROM OLD.byte_count
       OR NEW.anchor_hash IS DISTINCT FROM OLD.anchor_hash
       OR NEW.anchor_digest_key_version IS DISTINCT FROM OLD.anchor_digest_key_version
       OR NEW.extraction_confidence IS DISTINCT FROM OLD.extraction_confidence
       OR NEW.language IS DISTINCT FROM OLD.language
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'evidence_fragment is immutable' USING ERRCODE = '55000';
    END IF;
    IF (OLD.normalized_text_artifact_id IS NOT NULL AND NEW.normalized_text_artifact_id IS DISTINCT FROM OLD.normalized_text_artifact_id)
       OR (OLD.anchor_artifact_id IS NOT NULL AND NEW.anchor_artifact_id IS DISTINCT FROM OLD.anchor_artifact_id)
       OR (OLD.metadata_artifact_id IS NOT NULL AND NEW.metadata_artifact_id IS DISTINCT FROM OLD.metadata_artifact_id) THEN
        RAISE EXCEPTION 'evidence_fragment artifact bindings are write-once' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
