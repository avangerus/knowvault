-- Stage 4 source discovery catalog-relation limit widening.
--
-- 000090 bounded the durable catalog-discovery probe at 64 relations end to
-- end. A customer catalog with several hundred tables/views (observed: 645)
-- exceeds that bound and fails closed with DISCOVERY_LIMIT_EXCEEDED before a
-- worker ever opens the external connection. This migration is append-only:
-- 000090 is never edited. It widens exactly the three durable relation-count
-- bounds -- source_discovery_request.max_views and the three
-- source_discovery_result view counters -- from 64 to 1024, and replaces
-- app.source_discovery_result_begin with the identical body except that same
-- widened bound. Every other discovery bound from 000090 (columns per
-- relation, comment bytes, encrypted metadata artifact size, statement and
-- transaction timeouts) is unchanged.

BEGIN;

ALTER TABLE public.source_discovery_request
    DROP CONSTRAINT source_discovery_request_max_views_check,
    ADD CONSTRAINT source_discovery_request_max_views_check
        CHECK (max_views BETWEEN 1 AND 1024);

ALTER TABLE public.source_discovery_result
    DROP CONSTRAINT source_discovery_result_view_count_check,
    ADD CONSTRAINT source_discovery_result_view_count_check
        CHECK (view_count BETWEEN 0 AND 1024),
    DROP CONSTRAINT source_discovery_result_prepared_view_count_check,
    ADD CONSTRAINT source_discovery_result_prepared_view_count_check
        CHECK (prepared_view_count BETWEEN 0 AND 1024),
    DROP CONSTRAINT source_discovery_result_needs_interpretation_view_count_check,
    ADD CONSTRAINT source_discovery_result_needs_interpretation_view_count_check
        CHECK (needs_interpretation_view_count BETWEEN 0 AND 1024);

-- Full replacement body of 000090's function. The only change from the
-- original is the three bounded-count checks, widened from 64 to 1024.
CREATE OR REPLACE FUNCTION app.source_discovery_result_begin(
    p_request_id text,
    p_result_id text,
    p_job_id text,
    p_worker_id text,
    p_lease_epoch bigint,
    p_status text,
    p_view_count integer,
    p_prepared_view_count integer,
    p_needs_interpretation_view_count integer,
    p_database_identity_hash text,
    p_privilege_digest text,
    p_metadata_plaintext_hash text,
    p_result_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    security_epoch_value bigint;
    request_row public.source_discovery_request%ROWTYPE;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'source discovery result creation is restricted to the worker role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_request_id, 'sdrq')
       OR NOT app.source_generated_id_is_valid(p_result_id, 'sdr')
       OR NOT app.stage2_sha256_is_valid(p_database_identity_hash)
       OR NOT app.stage2_sha256_is_valid(p_privilege_digest)
       OR NOT app.stage2_sha256_is_valid(p_metadata_plaintext_hash)
       OR NOT app.stage2_sha256_is_valid(p_result_hash)
       OR p_status NOT IN ('SUCCEEDED', 'NEEDS_INTERPRETATION')
       OR p_view_count NOT BETWEEN 0 AND 1024
       OR p_prepared_view_count NOT BETWEEN 0 AND 1024
       OR p_needs_interpretation_view_count NOT BETWEEN 0 AND 1024
       OR p_prepared_view_count + p_needs_interpretation_view_count <> p_view_count
       OR (p_status = 'SUCCEEDED' AND p_needs_interpretation_view_count <> 0) THEN
        RAISE EXCEPTION 'source discovery result has an invalid bounded terminal projection'
            USING ERRCODE = '22023';
    END IF;
    IF NOT app.source_discovery_job_lease_is_live(
        organization_value, p_request_id, p_job_id, p_worker_id, p_lease_epoch) THEN
        RAISE EXCEPTION 'source discovery result job lease is not live or exact'
            USING ERRCODE = '55000';
    END IF;
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    SELECT * INTO request_row
    FROM public.source_discovery_request
    WHERE organization_id = organization_value AND id = p_request_id
    FOR UPDATE;
    IF NOT FOUND OR request_row.status <> 'RUNNING'
       OR request_row.expires_at <= transaction_timestamp()
       OR request_row.security_epoch <> security_epoch_value
       OR NOT app.source_discovery_revision_is_probeable(
           organization_value, request_row.connection_id,
           request_row.connection_revision, request_row.trust_profile_hash) THEN
        RAISE EXCEPTION 'source discovery request is stale, expired or not probeable'
            USING ERRCODE = '55000';
    END IF;
    PERFORM set_config('app.source_discovery_result_begin', p_result_id, true);
    INSERT INTO public.source_discovery_result (
        organization_id, id, request_id, actor_principal_id, connection_id,
        connection_revision, database_identity_hash, trust_profile_hash,
        privilege_digest, security_epoch, status, view_count,
        prepared_view_count, needs_interpretation_view_count,
        metadata_plaintext_hash, result_hash
    ) VALUES (
        organization_value, p_result_id, p_request_id,
        request_row.actor_principal_id, request_row.connection_id,
        request_row.connection_revision, p_database_identity_hash,
        request_row.trust_profile_hash, p_privilege_digest,
        request_row.security_epoch, p_status, p_view_count,
        p_prepared_view_count, p_needs_interpretation_view_count,
        p_metadata_plaintext_hash, p_result_hash
    );
END;
$$;

COMMIT;
