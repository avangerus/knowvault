-- Stage 2 S2d OCR extraction identity.
--
-- The original catalog deliberately constrained OCR to false while the
-- renderer/worker qualification was deferred. This forward-only migration
-- opens the columns only for a canonical OCR extraction whose model/profile
-- identity is complete; every other format remains non-OCR. The migration is
-- inert until a qualified OCR worker is supplied by production composition.

BEGIN;

ALTER TABLE public.source_extraction
    DROP CONSTRAINT source_extraction_ocr_used_check,
    DROP CONSTRAINT source_extraction_ocr_model_id_check,
    DROP CONSTRAINT source_extraction_ocr_model_revision_check,
    DROP CONSTRAINT source_extraction_ocr_artifact_hash_check,
    DROP CONSTRAINT source_extraction_ocr_profile_revision_check;

ALTER TABLE public.source_extraction
    ADD CONSTRAINT source_extraction_ocr_used_check
        CHECK (ocr_used = false OR (ocr_used = true AND canonical_format = 'OCR')),
    ADD CONSTRAINT source_extraction_ocr_model_id_check
        CHECK (ocr_model_id IS NULL OR (ocr_used AND length(ocr_model_id) BETWEEN 1 AND 128 AND ocr_model_id !~ '[[:cntrl:][:space:]]')),
    ADD CONSTRAINT source_extraction_ocr_model_revision_check
        CHECK (ocr_model_revision IS NULL OR (ocr_used AND length(ocr_model_revision) BETWEEN 1 AND 128 AND ocr_model_revision !~ '[[:cntrl:][:space:]]')),
    ADD CONSTRAINT source_extraction_ocr_artifact_hash_check
        CHECK (ocr_artifact_hash IS NULL OR (ocr_used AND app.stage2_sha256_is_valid(ocr_artifact_hash))),
    ADD CONSTRAINT source_extraction_ocr_profile_revision_check
        CHECK (ocr_profile_revision IS NULL OR (ocr_used AND ocr_profile_revision ~ '^[a-z0-9][a-z0-9._-]{0,127}$')),
    ADD CONSTRAINT source_extraction_ocr_identity_check
        CHECK (
            (ocr_used = false
             AND ocr_model_id IS NULL
             AND ocr_model_revision IS NULL
             AND ocr_artifact_hash IS NULL
             AND ocr_profile_revision IS NULL)
            OR
            (ocr_used = true
             AND canonical_format = 'OCR'
             AND ocr_model_id IS NOT NULL
             AND ocr_model_revision IS NOT NULL
             AND ocr_artifact_hash IS NOT NULL
             AND ocr_profile_revision IS NOT NULL)
        );

COMMENT ON COLUMN public.source_extraction.ocr_used IS
    'True only for a qualified OCR extraction; identity columns are complete and immutable when true.';

COMMIT;
