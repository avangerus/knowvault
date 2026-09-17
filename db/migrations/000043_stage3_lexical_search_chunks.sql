-- Stage 3 lexical search projection activation.
--
-- SearchChunk is a durable, Evidence-bound lexical projection even when no
-- embedding provider has been qualified for the tenant. Vector provenance is
-- an optional all-or-nothing tuple and remains explicitly unavailable until a
-- deployment supplies the real profile/model artifact/dimension. This
-- migration changes only the derived projection metadata; it does not weaken
-- tenant, retention, owner-artifact or outbox guards.

BEGIN;

ALTER TABLE public.search_chunk
    DROP CONSTRAINT IF EXISTS search_chunk_embedding_profile_hash_check,
    DROP CONSTRAINT IF EXISTS search_chunk_embedding_model_artifact_hash_check,
    DROP CONSTRAINT IF EXISTS search_chunk_embedding_dimension_check,
    ALTER COLUMN embedding_profile_hash DROP NOT NULL,
    ALTER COLUMN embedding_model_artifact_hash DROP NOT NULL,
    ALTER COLUMN embedding_dimension DROP NOT NULL;

ALTER TABLE public.search_chunk
    ADD CONSTRAINT search_chunk_embedding_tuple CHECK (
        (
            embedding_profile_hash IS NULL
            AND embedding_model_artifact_hash IS NULL
            AND embedding_dimension IS NULL
        )
        OR (
            embedding_profile_hash IS NOT NULL
            AND embedding_model_artifact_hash IS NOT NULL
            AND embedding_dimension IS NOT NULL
            AND app.stage2_sha256_is_valid(embedding_profile_hash)
            AND app.stage2_sha256_is_valid(embedding_model_artifact_hash)
            AND embedding_dimension BETWEEN 1 AND 65536
        )
    );

COMMIT;
