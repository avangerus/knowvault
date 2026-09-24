-- S3 card 2b: the organization OWNER's control over the SQL query credential
-- of one PostgreSQL source connection (ADR-0097).
--
-- Migration 000116 put the optional query credential reference on the
-- immutable source_connection_revision. That is the right home for a
-- registration-time reference, but it cannot serve the card's runtime control:
-- a connection revision is immutable (000006's source_connection_revision_immutable
-- trigger), and every source scope pins the exact connection revision it was
-- registered against, so writing a new revision could never move an already
-- registered source's reference. This migration therefore adds the one mutable,
-- per-connection home for that reference:
--
--   * public.source_query_credential holds at most one row per connection. A
--     missing row means "no query credential", which knowvault_source_sql
--     reports as SOURCE_SQL_NOT_CONFIGURED and the Sources card as
--     "SQL not configured"; it is never inferred from the ingestion
--     credential, and the 000116 column is left in place as the immutable
--     registration-time record it was.
--   * app.source_query_credential_set / app.source_query_credential_clear are
--     the only writers. Both re-verify the caller is the current organization
--     OWNER inside the SECURITY DEFINER boundary (exactly like
--     app.source_postgresql_connection_bootstrap_begin), store only the opaque
--     'cred' reference, and never see, store or return a DSN, password or any
--     other secret value.
--   * The card's pre-acceptance checks (the reference resolves in the mounted
--     credentials, a read-only connection reaches the same database identity,
--     and the role cannot SELECT a column excluded from the registered tables)
--     happen before either function is called. A failed check returns a closed
--     code and changes nothing here.

BEGIN;

CREATE TABLE public.source_query_credential (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    connection_id text NOT NULL,
    credential_reference text NOT NULL
        CHECK (app.source_generated_id_is_valid(credential_reference, 'cred')),
    -- Monotonic per-connection change counter, so the audit trail can name the
    -- exact control operation even though the reference itself is opaque.
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, connection_id),
    CONSTRAINT source_query_credential_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_query_credential_actor_fk
        FOREIGN KEY (organization_id, updated_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

COMMENT ON TABLE public.source_query_credential IS
    'ADR-0097 mutable per-connection reference to the source''s read-only query credential; absence means SOURCE_SQL_NOT_CONFIGURED. Never a DSN or secret value.';

ALTER TABLE public.source_query_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_query_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY source_query_credential_tenant_isolation ON public.source_query_credential
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_query_credential FROM PUBLIC;
GRANT SELECT ON TABLE public.source_query_credential TO knowvault_app;

-- Source Query Credential § set
CREATE OR REPLACE FUNCTION app.source_query_credential_set(
    p_connection_id text,
    p_credential_reference text
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
       OR NOT app.source_generated_id_is_valid(p_connection_id, 'conn')
       OR NOT app.source_generated_id_is_valid(p_credential_reference, 'cred') THEN
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
        organization_value, p_connection_id, p_credential_reference, 1, actor_value
    )
    ON CONFLICT (organization_id, connection_id) DO UPDATE SET
        credential_reference = EXCLUDED.credential_reference,
        revision = public.source_query_credential.revision + 1,
        updated_by = EXCLUDED.updated_by,
        updated_at = transaction_timestamp();
END;
$$;

-- Source Query Credential § clear
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

    DELETE FROM public.source_query_credential
    WHERE organization_id = organization_value AND connection_id = p_connection_id;
END;
$$;

REVOKE ALL ON FUNCTION app.source_query_credential_set(text, text) FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_query_credential_set(text, text) TO knowvault_app;

REVOKE ALL ON FUNCTION app.source_query_credential_clear(text) FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_query_credential_clear(text) TO knowvault_app;

COMMIT;
