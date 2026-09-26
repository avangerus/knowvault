-- S3 card 2d R1: the query credential revision only ever increases, including
-- across clear and set.
--
-- Migration 000117's clear function DELETEd the row, so the next set started
-- again at revision 1. A revision that can fall back to a value already used
-- for a different credential makes the least-privilege proof cache ambiguous:
-- a stale proof recorded for the old role could look like it still matches the
-- new one. This migration turns clear into a tombstone that keeps the
-- per-connection counter:
--
--   * public.source_query_credential.credential_reference becomes nullable and
--     is NULL exactly when the credential has been cleared; the connection row
--     itself (and its monotonic revision) survives.
--   * app.source_query_credential_clear writes the tombstone, creating it at
--     revision 1 for a connection that never had a credential. It never
--     changes an existing revision.
--   * app.source_query_credential_set keeps its ON CONFLICT increment, so a
--     clear followed by a set always yields revision 2 (and never 1 again).
--
-- The card's execution path no longer authorizes from the stored proof at all
-- (R1 requires a fresh in-transaction proof), so this is about the revision
-- being a truthful, monotonic change counter for the operator and the audit
-- trail, not about rescuing the cache.

BEGIN;

ALTER TABLE public.source_query_credential
    ALTER COLUMN credential_reference DROP NOT NULL;

ALTER TABLE public.source_query_credential
    DROP CONSTRAINT IF EXISTS source_query_credential_credential_reference_check;

ALTER TABLE public.source_query_credential
    ADD CONSTRAINT source_query_credential_reference_shape
        CHECK (
            credential_reference IS NULL
            OR app.source_generated_id_is_valid(credential_reference, 'cred')
        );

-- The ingestion-separation guard only applies to a real reference; a cleared
-- tombstone is not a credential and can never equal one.
CREATE OR REPLACE FUNCTION app.source_query_credential_separation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.credential_reference IS NULL THEN
        RETURN NEW;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM public.source_connection_revision AS revision
        WHERE revision.organization_id = NEW.organization_id
          AND revision.connection_id = NEW.connection_id
          AND revision.credential_reference = NEW.credential_reference
    ) THEN
        RAISE EXCEPTION 'the query credential must differ from the ingestion credential'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- Source Query Credential § clear (tombstone, revision preserved).
CREATE OR REPLACE FUNCTION app.source_query_credential_clear(
    p_connection_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    actor_value text;
    security_epoch_value bigint;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source query credential control is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    actor_value := app.current_principal_id();
    IF organization_value IS NULL OR actor_value IS NULL
       OR NOT app.source_generated_id_is_valid(p_connection_id, 'conn') THEN
        RAISE EXCEPTION 'source query credential control contains an invalid bounded value'
            USING ERRCODE = '22023';
    END IF;

    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE'
    FOR SHARE;
    IF security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, actor_value, security_epoch_value) THEN
        RAISE EXCEPTION 'source query credential control requires the current organization OWNER'
            USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM public.source_connection AS connection
        WHERE connection.organization_id = organization_value
          AND connection.id = p_connection_id
          AND connection.type = 'POSTGRESQL_QUERY'
    ) THEN
        RAISE EXCEPTION 'source query credential control requires an existing PostgreSQL source connection'
            USING ERRCODE = 'P0002';
    END IF;

    INSERT INTO public.source_query_credential (
        organization_id, connection_id, credential_reference, revision, updated_by
    ) VALUES (
        organization_value, p_connection_id, NULL, 1, actor_value
    )
    ON CONFLICT (organization_id, connection_id) DO UPDATE SET
        credential_reference = NULL,
        updated_by = EXCLUDED.updated_by,
        updated_at = transaction_timestamp();
END;
$$;

REVOKE ALL ON FUNCTION app.source_query_credential_clear(text) FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_query_credential_clear(text) TO knowvault_app;

COMMIT;
