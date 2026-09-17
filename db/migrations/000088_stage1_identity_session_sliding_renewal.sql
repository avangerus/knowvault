-- 000088: FIX-7 #3 -- the owner was silently bounced out of a live browser
-- session roughly every 10-15 minutes while actively working (confirmed live
-- on knowvault-acc-proxy's access log for 08.09 ~08:15-09:00 UTC: the SAME
-- Keycloak SSO session (session_state=04ba7b26...) re-authenticated the app
-- session 6 times in 45 minutes, each cycle a full page reload). The root
-- cause was internal/platform/oidcweb/handler.go's callback handler setting
-- the freshly-issued app session's expires_at directly to the OIDC ID
-- token's own short-lived `exp` claim (subject.ExpiresAt), with nothing ever
-- extending it -- not this table's 15-minute oidc_login_attempt window (that
-- CHECK bounds only the PKCE browser round trip, a different table), and not
-- principal.session_revision (the previous agent's ruled-out hypothesis).
--
-- The fix (internal/identity/repository/repository.go's ResolveSession) is a
-- sliding renewal: a still-valid, non-revoked session that has burned through
-- more than half of its renewal window is pushed back out on every
-- authenticated request, capped at issued_at + 24 hours (maxSessionLifetime,
-- unchanged and still enforced by this table's own CHECK constraint) -- an
-- actively used session now lives the whole work shift; an idle one still
-- expires exactly as before. This requires one new, narrowly-scoped legal
-- transition on app.identity_session_mutation_guard (000003), which today
-- allows only the NULL->revoked transition and freezes every other column
-- including expires_at ("identity session payload is immutable"). That guard
-- is not weakened: every column it already froze stays frozen, revocation
-- still works exactly as before, and the one new transition is accepted only
-- when it is a strictly-forward extension of a still-live, non-revoked
-- session, bounded by the same 24-hour ceiling the table CHECK already
-- enforces, and it may never coincide with a revocation in the same
-- statement.
BEGIN;

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
       OR NEW.issued_at <> OLD.issued_at THEN
        RAISE EXCEPTION 'identity session payload is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.expires_at <> OLD.expires_at THEN
        -- FIX-7 #3's sliding renewal: forward-only, never touching revocation
        -- state, never past issued_at + 24 hours (the table's own CHECK
        -- ceiling, re-asserted here so this trigger fails closed even if that
        -- constraint were ever loosened independently).
        IF OLD.revoked_at IS NOT NULL
           OR NEW.revoked_at IS NOT NULL
           OR NEW.expires_at <= OLD.expires_at
           OR NEW.expires_at > OLD.issued_at + interval '24 hours' THEN
            RAISE EXCEPTION 'identity session payload is immutable' USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.revocation_code IS NOT NULL THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'identity session may only transition to revoked' USING ERRCODE = '55000';
END;
$$;

COMMIT;
