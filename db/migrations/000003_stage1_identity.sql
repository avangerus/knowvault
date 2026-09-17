-- Stage 1: durable, read-only OIDC identity and server-session foundation.
--
-- This schema intentionally stores only keyed digests of browser/session and
-- external-identity values. It never persists an authorization code, ID token,
-- access token, refresh token, raw OIDC subject, email address, nonce or PKCE
-- verifier. OIDC network exchange and cookie sealing are later adapters.

BEGIN;

CREATE OR REPLACE FUNCTION app.identity_digest_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND value ~ '^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$';
$$;

CREATE OR REPLACE FUNCTION app.identity_sha256_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND value ~ '^sha256:[0-9a-f]{64}$';
$$;

CREATE OR REPLACE FUNCTION app.oidc_allowed_algorithms_are_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN value IS NULL OR jsonb_typeof(value) <> 'array' THEN false
        WHEN jsonb_array_length(value) NOT BETWEEN 1 AND 4 THEN false
        WHEN (SELECT count(*) FROM jsonb_array_elements_text(value)) <> jsonb_array_length(value) THEN false
        WHEN EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(value) AS algorithm(value)
            WHERE algorithm.value NOT IN ('RS256', 'PS256', 'ES256', 'EdDSA')
        ) THEN false
        ELSE (
            SELECT count(DISTINCT algorithm.value)
            FROM jsonb_array_elements_text(value) AS algorithm(value)
        ) = jsonb_array_length(value)
    END;
$$;

CREATE OR REPLACE FUNCTION app.identity_return_path_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND char_length(value) BETWEEN 1 AND 1024
       AND value LIKE '/%'
       AND value NOT LIKE '//%'
       AND value !~ '[[:cntrl:]]';
$$;

CREATE TABLE public.oidc_provider (
    id text PRIMARY KEY CHECK (app.audit_opaque_id_is_valid(id)),
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    issuer_url text NOT NULL
        CHECK (char_length(issuer_url) BETWEEN 9 AND 2048)
        CHECK (issuer_url ~ '^https://[^[:space:]]+$'),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
    current_revision bigint NOT NULL DEFAULT 1 CHECK (current_revision > 0),
    created_by text NOT NULL CHECK (app.audit_opaque_id_is_valid(created_by)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    disabled_at timestamptz,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, issuer_url),
    CONSTRAINT oidc_provider_created_by_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CHECK (
        (status = 'ACTIVE' AND disabled_at IS NULL)
        OR (status = 'DISABLED' AND disabled_at IS NOT NULL)
    )
);

CREATE TABLE public.oidc_provider_revision (
    organization_id text NOT NULL,
    provider_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    client_id text NOT NULL
        CHECK (char_length(client_id) BETWEEN 1 AND 512)
        CHECK (btrim(client_id) = client_id)
        CHECK (client_id !~ '[[:cntrl:]]'),
    client_secret_reference text NOT NULL CHECK (app.audit_opaque_id_is_valid(client_secret_reference)),
    redirect_uri text NOT NULL
        CHECK (char_length(redirect_uri) BETWEEN 9 AND 2048)
        CHECK (redirect_uri ~ '^https://[^[:space:]]+$'),
    allowed_id_token_algorithms_json jsonb NOT NULL
        CHECK (app.oidc_allowed_algorithms_are_valid(allowed_id_token_algorithms_json)),
    configuration_hash text NOT NULL CHECK (app.identity_sha256_is_valid(configuration_hash)),
    created_by text NOT NULL CHECK (app.audit_opaque_id_is_valid(created_by)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, provider_id, revision),
    CONSTRAINT oidc_provider_revision_provider_fk
        FOREIGN KEY (organization_id, provider_id)
        REFERENCES public.oidc_provider (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT oidc_provider_revision_created_by_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

ALTER TABLE public.oidc_provider
    ADD CONSTRAINT oidc_provider_current_revision_fk
    FOREIGN KEY (organization_id, id, current_revision)
    REFERENCES public.oidc_provider_revision (organization_id, provider_id, revision)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE public.external_identity (
    id text PRIMARY KEY CHECK (app.audit_opaque_id_is_valid(id)),
    organization_id text NOT NULL,
    principal_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(principal_id)),
    provider_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(provider_id)),
    external_subject_digest text NOT NULL CHECK (app.identity_digest_is_valid(external_subject_digest)),
    digest_key_version integer NOT NULL CHECK (digest_key_version BETWEEN 1 AND 999999999),
    attributes_hash text NOT NULL CHECK (app.identity_sha256_is_valid(attributes_hash)),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    last_verified_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_at timestamptz,
    revoked_by text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, provider_id, digest_key_version, external_subject_digest),
    CONSTRAINT external_identity_principal_fk
        FOREIGN KEY (organization_id, principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT external_identity_provider_fk
        FOREIGN KEY (organization_id, provider_id)
        REFERENCES public.oidc_provider (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT external_identity_revoked_by_fk
        FOREIGN KEY (organization_id, revoked_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CHECK (
        (status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by IS NULL)
        OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)
    )
);

CREATE TABLE public.oidc_login_attempt (
    id text PRIMARY KEY CHECK (app.audit_opaque_id_is_valid(id)),
    organization_id text NOT NULL,
    provider_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(provider_id)),
    provider_revision bigint NOT NULL CHECK (provider_revision > 0),
    state_digest text NOT NULL CHECK (app.identity_digest_is_valid(state_digest)),
    browser_binding_digest text NOT NULL CHECK (app.identity_digest_is_valid(browser_binding_digest)),
    nonce_digest text NOT NULL CHECK (app.identity_digest_is_valid(nonce_digest)),
    pkce_verifier_digest text NOT NULL CHECK (app.identity_digest_is_valid(pkce_verifier_digest)),
    return_path text NOT NULL DEFAULT '/' CHECK (app.identity_return_path_is_valid(return_path)),
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CLAIMED', 'CONSUMED', 'FAILED', 'EXPIRED')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    claimed_at timestamptz,
    completed_at timestamptz,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, state_digest),
    CONSTRAINT oidc_login_attempt_provider_revision_fk
        FOREIGN KEY (organization_id, provider_id, provider_revision)
        REFERENCES public.oidc_provider_revision (organization_id, provider_id, revision)
        ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '15 minutes'),
    CHECK (
        (status = 'PENDING' AND claimed_at IS NULL AND completed_at IS NULL)
        OR (status = 'CLAIMED' AND claimed_at IS NOT NULL AND completed_at IS NULL)
        OR (status IN ('CONSUMED', 'FAILED') AND claimed_at IS NOT NULL AND completed_at IS NOT NULL)
        OR (status = 'EXPIRED' AND completed_at IS NOT NULL)
    ),
    CHECK (claimed_at IS NULL OR claimed_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE TABLE public.identity_session (
    id text PRIMARY KEY CHECK (app.audit_opaque_id_is_valid(id)),
    organization_id text NOT NULL,
    principal_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(principal_id)),
    provider_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(provider_id)),
    external_identity_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(external_identity_id)),
    login_attempt_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(login_attempt_id)),
    session_token_digest text NOT NULL CHECK (app.identity_digest_is_valid(session_token_digest)),
    principal_session_revision bigint NOT NULL CHECK (principal_session_revision > 0),
    provider_revision bigint NOT NULL CHECK (provider_revision > 0),
    issued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_code text,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, login_attempt_id),
    UNIQUE (session_token_digest),
    CONSTRAINT identity_session_principal_fk
        FOREIGN KEY (organization_id, principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT identity_session_provider_revision_fk
        FOREIGN KEY (organization_id, provider_id, provider_revision)
        REFERENCES public.oidc_provider_revision (organization_id, provider_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT identity_session_external_identity_fk
        FOREIGN KEY (organization_id, external_identity_id)
        REFERENCES public.external_identity (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT identity_session_login_attempt_fk
        FOREIGN KEY (organization_id, login_attempt_id)
        REFERENCES public.oidc_login_attempt (organization_id, id)
        ON DELETE RESTRICT,
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + interval '24 hours'),
    CHECK (
        (revoked_at IS NULL AND revocation_code IS NULL)
        OR (revoked_at IS NOT NULL AND revocation_code ~ '^[A-Z][A-Z0-9_]{1,127}$')
    )
);

CREATE INDEX identity_session_active_principal
    ON public.identity_session (organization_id, principal_id)
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION app.oidc_provider_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id OR NEW.id <> OLD.id OR NEW.issuer_url <> OLD.issuer_url OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'oidc provider identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.current_revision < OLD.current_revision THEN
        RAISE EXCEPTION 'oidc provider revision cannot decrease' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'DISABLED' AND NEW.status <> 'DISABLED' THEN
        RAISE EXCEPTION 'disabled oidc provider cannot be reactivated' USING ERRCODE = '55000';
    END IF;
    IF NEW.status = 'ACTIVE' AND NEW.disabled_at IS NOT NULL THEN
        RAISE EXCEPTION 'active oidc provider cannot have disabled timestamp' USING ERRCODE = '55000';
    END IF;
    IF NEW.status = 'DISABLED' AND NEW.disabled_at IS NULL THEN
        RAISE EXCEPTION 'disabled oidc provider requires disabled timestamp' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oidc_provider_mutation_guard
BEFORE UPDATE ON public.oidc_provider
FOR EACH ROW EXECUTE FUNCTION app.oidc_provider_mutation_guard();

CREATE OR REPLACE FUNCTION app.oidc_provider_revision_no_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'oidc provider revision is immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER oidc_provider_revision_no_mutation
BEFORE UPDATE OR DELETE ON public.oidc_provider_revision
FOR EACH ROW EXECUTE FUNCTION app.oidc_provider_revision_no_mutation();

CREATE OR REPLACE FUNCTION app.external_identity_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    principal_type text;
    principal_status text;
    provider_status text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.organization_id <> OLD.organization_id
           OR NEW.id <> OLD.id
           OR NEW.principal_id <> OLD.principal_id
           OR NEW.provider_id <> OLD.provider_id
           OR NEW.external_subject_digest <> OLD.external_subject_digest
           OR NEW.digest_key_version <> OLD.digest_key_version
           OR NEW.created_at <> OLD.created_at THEN
            RAISE EXCEPTION 'external identity binding is immutable' USING ERRCODE = '55000';
        END IF;
        IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
            RAISE EXCEPTION 'revoked external identity cannot be reactivated' USING ERRCODE = '55000';
        END IF;
        IF OLD.status = 'ACTIVE' AND NEW.status = 'ACTIVE' AND (NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL) THEN
            RAISE EXCEPTION 'active external identity cannot carry revocation state' USING ERRCODE = '55000';
        END IF;
        IF NEW.last_verified_at < OLD.last_verified_at THEN
            RAISE EXCEPTION 'external identity verification timestamp cannot decrease' USING ERRCODE = '55000';
        END IF;
    END IF;

    IF NEW.status = 'ACTIVE' THEN
        SELECT type, status
        INTO principal_type, principal_status
        FROM public.principal
        WHERE organization_id = NEW.organization_id AND id = NEW.principal_id;
        IF NOT FOUND OR principal_type <> 'USER' OR principal_status <> 'ACTIVE' THEN
            RAISE EXCEPTION 'external identity requires active user principal' USING ERRCODE = '23514';
        END IF;

        SELECT status
        INTO provider_status
        FROM public.oidc_provider
        WHERE organization_id = NEW.organization_id AND id = NEW.provider_id;
        IF NOT FOUND OR provider_status <> 'ACTIVE' THEN
            RAISE EXCEPTION 'external identity requires active oidc provider' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER external_identity_mutation_guard
BEFORE INSERT OR UPDATE ON public.external_identity
FOR EACH ROW EXECUTE FUNCTION app.external_identity_mutation_guard();

CREATE OR REPLACE FUNCTION app.oidc_login_attempt_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.id <> OLD.id
       OR NEW.provider_id <> OLD.provider_id
       OR NEW.provider_revision <> OLD.provider_revision
       OR NEW.state_digest <> OLD.state_digest
       OR NEW.browser_binding_digest <> OLD.browser_binding_digest
       OR NEW.nonce_digest <> OLD.nonce_digest
       OR NEW.pkce_verifier_digest <> OLD.pkce_verifier_digest
       OR NEW.return_path <> OLD.return_path
       OR NEW.created_at <> OLD.created_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'oidc login attempt payload is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'PENDING' AND NEW.status = 'CLAIMED'
       AND NEW.claimed_at = transaction_timestamp()
       AND NEW.completed_at IS NULL
       AND OLD.expires_at > transaction_timestamp() THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'PENDING' AND NEW.status = 'EXPIRED'
       AND NEW.claimed_at IS NULL
       AND NEW.completed_at = transaction_timestamp()
       AND OLD.expires_at <= transaction_timestamp() THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'CLAIMED' AND NEW.status IN ('CONSUMED', 'FAILED')
       AND NEW.claimed_at = OLD.claimed_at
       AND NEW.completed_at = transaction_timestamp()
       AND OLD.expires_at > transaction_timestamp() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid oidc login attempt state transition' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER oidc_login_attempt_mutation_guard
BEFORE UPDATE ON public.oidc_login_attempt
FOR EACH ROW EXECUTE FUNCTION app.oidc_login_attempt_mutation_guard();

CREATE OR REPLACE FUNCTION app.identity_session_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    principal_type text;
    principal_status text;
    current_session_revision bigint;
    provider_status text;
    current_provider_revision bigint;
    external_principal_id text;
    external_provider_id text;
    external_status text;
    login_provider_id text;
    login_provider_revision bigint;
    login_status text;
    login_expires_at timestamptz;
BEGIN
    SELECT type, status, session_revision
    INTO principal_type, principal_status, current_session_revision
    FROM public.principal
    WHERE organization_id = NEW.organization_id AND id = NEW.principal_id;
    IF NOT FOUND OR principal_type <> 'USER' OR principal_status <> 'ACTIVE' OR current_session_revision <> NEW.principal_session_revision THEN
        RAISE EXCEPTION 'identity session requires current active user principal' USING ERRCODE = '23514';
    END IF;

    SELECT status, current_revision
    INTO provider_status, current_provider_revision
    FROM public.oidc_provider
    WHERE organization_id = NEW.organization_id AND id = NEW.provider_id;
    IF NOT FOUND OR provider_status <> 'ACTIVE' OR current_provider_revision <> NEW.provider_revision THEN
        RAISE EXCEPTION 'identity session requires current active oidc provider revision' USING ERRCODE = '23514';
    END IF;

    SELECT principal_id, provider_id, status
    INTO external_principal_id, external_provider_id, external_status
    FROM public.external_identity
    WHERE organization_id = NEW.organization_id AND id = NEW.external_identity_id;
    IF NOT FOUND OR external_principal_id <> NEW.principal_id OR external_provider_id <> NEW.provider_id OR external_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'identity session requires active matching external identity' USING ERRCODE = '23514';
    END IF;

    SELECT provider_id, provider_revision, status, expires_at
    INTO login_provider_id, login_provider_revision, login_status, login_expires_at
    FROM public.oidc_login_attempt
    WHERE organization_id = NEW.organization_id AND id = NEW.login_attempt_id
    FOR UPDATE;
    IF NOT FOUND OR login_provider_id <> NEW.provider_id OR login_provider_revision <> NEW.provider_revision
       OR login_status <> 'CLAIMED' OR login_expires_at <= transaction_timestamp() THEN
        RAISE EXCEPTION 'identity session requires claimed current login attempt' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER identity_session_insert_guard
BEFORE INSERT ON public.identity_session
FOR EACH ROW EXECUTE FUNCTION app.identity_session_insert_guard();

CREATE OR REPLACE FUNCTION app.identity_session_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.id <> OLD.id
       OR NEW.principal_id <> OLD.principal_id
       OR NEW.provider_id <> OLD.provider_id
       OR NEW.external_identity_id <> OLD.external_identity_id
       OR NEW.login_attempt_id <> OLD.login_attempt_id
       OR NEW.session_token_digest <> OLD.session_token_digest
       OR NEW.principal_session_revision <> OLD.principal_session_revision
       OR NEW.provider_revision <> OLD.provider_revision
       OR NEW.issued_at <> OLD.issued_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'identity session payload is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.revocation_code IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'identity session may only transition to revoked' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER identity_session_mutation_guard
BEFORE UPDATE ON public.identity_session
FOR EACH ROW EXECUTE FUNCTION app.identity_session_mutation_guard();

CREATE OR REPLACE FUNCTION app.identity_session_login_completion_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    login_status text;
BEGIN
    SELECT status
    INTO login_status
    FROM public.oidc_login_attempt
    WHERE organization_id = NEW.organization_id AND id = NEW.login_attempt_id;
    IF NOT FOUND OR login_status <> 'CONSUMED' THEN
        RAISE EXCEPTION 'identity session requires consumed login attempt at commit' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER identity_session_login_completion_guard
AFTER INSERT ON public.identity_session
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.identity_session_login_completion_guard();

CREATE OR REPLACE FUNCTION app.principal_identity_revocation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id OR NEW.id <> OLD.id OR NEW.type <> OLD.type OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'principal identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.session_revision < OLD.session_revision THEN
        RAISE EXCEPTION 'principal session revision cannot decrease' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'DEPROVISIONED' AND NEW.status <> 'DEPROVISIONED' THEN
        RAISE EXCEPTION 'deprovisioned principal cannot be reactivated' USING ERRCODE = '55000';
    END IF;
    IF NEW.status <> OLD.status AND NEW.session_revision <= OLD.session_revision THEN
        RAISE EXCEPTION 'principal status change requires session revision increase' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_identity_revocation_guard
BEFORE UPDATE ON public.principal
FOR EACH ROW EXECUTE FUNCTION app.principal_identity_revocation_guard();

CREATE OR REPLACE FUNCTION app.revoke_identity_sessions_on_principal_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.status <> 'ACTIVE' OR NEW.session_revision <> OLD.session_revision THEN
        UPDATE public.identity_session
        SET revoked_at = transaction_timestamp(),
            revocation_code = 'PRINCIPAL_REVISION_CHANGED'
        WHERE organization_id = NEW.organization_id
          AND principal_id = NEW.id
          AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER revoke_identity_sessions_on_principal_change
AFTER UPDATE OF status, session_revision ON public.principal
FOR EACH ROW EXECUTE FUNCTION app.revoke_identity_sessions_on_principal_change();

ALTER TABLE public.oidc_provider ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_provider FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_provider_tenant_isolation ON public.oidc_provider
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.oidc_provider_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_provider_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_provider_revision_tenant_isolation ON public.oidc_provider_revision
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.external_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.external_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY external_identity_tenant_isolation ON public.external_identity
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.oidc_login_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.oidc_login_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_login_attempt_tenant_isolation ON public.oidc_login_attempt
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.identity_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_session FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_session_tenant_isolation ON public.identity_session
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE
    public.oidc_provider,
    public.oidc_provider_revision,
    public.external_identity,
    public.oidc_login_attempt,
    public.identity_session
FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE ON TABLE public.oidc_provider TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.oidc_provider_revision TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.external_identity TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.oidc_login_attempt TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.identity_session TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.identity_digest_is_valid(text),
    app.identity_sha256_is_valid(text),
    app.oidc_allowed_algorithms_are_valid(jsonb),
    app.identity_return_path_is_valid(text),
    app.oidc_provider_mutation_guard(),
    app.oidc_provider_revision_no_mutation(),
    app.external_identity_mutation_guard(),
    app.oidc_login_attempt_mutation_guard(),
    app.identity_session_insert_guard(),
    app.identity_session_mutation_guard(),
    app.identity_session_login_completion_guard(),
    app.principal_identity_revocation_guard(),
    app.revoke_identity_sessions_on_principal_change()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.identity_digest_is_valid(text),
    app.identity_sha256_is_valid(text),
    app.oidc_allowed_algorithms_are_valid(jsonb),
    app.identity_return_path_is_valid(text)
TO knowvault_app;

COMMIT;
