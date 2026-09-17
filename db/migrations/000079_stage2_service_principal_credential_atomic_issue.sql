-- Stage 2: V1-C fix — an agent access code must not exist as a partially
-- authorized credential, and re-issuing with the same idempotency key must
-- not mint a second SERVICE principal (FIX-1 #2).
--
-- 000066 let a credential authenticate the instant its row existed, gated
-- only by principal.status/expires_at/revoked_at. internal/serviceprincicial
-- grants every requested workspace's membership one at a time after that row
-- is already live, so a failure on the second (or later) workspace left a
-- fully authenticatable credential holding only the workspaces granted
-- before the failure -- a partial, silently-scoped-down credential the
-- caller never asked for and the audit trail cannot distinguish from an
-- intentionally narrow grant.
--
-- `activated_at` is the fix: it starts NULL and is set exactly once, by the
-- application, only after every requested workspace's AddMember (and its
-- scope row) has committed. Authenticate now requires it non-null in
-- addition to the existing checks, so a credential is unauthenticatable for
-- its entire partially-provisioned lifetime; a failure anywhere in the
-- per-workspace loop leaves it permanently unactivated (the caller revokes
-- it) rather than silently narrowed.
--
-- `idempotency_key`/`request_hash` give a client-facing retry of the same
-- Issue call a durable receipt to check before creating anything: the raw
-- code itself can never be replayed (000066's own doc comment: it is never
-- persisted), so a replay of an already-issued key answers a typed "already
-- issued" outcome instead of either fabricating a second principal or
-- pretending to hand back a secret that no longer exists in memory.

BEGIN;

ALTER TABLE public.service_principal_credential
    ADD COLUMN idempotency_key text
        CHECK (idempotency_key IS NULL
               OR (char_length(idempotency_key) BETWEEN 1 AND 255 AND idempotency_key !~ '[[:cntrl:]]')),
    ADD COLUMN request_hash text
        CHECK (request_hash IS NULL OR app.stage2_sha256_is_valid(request_hash)),
    ADD COLUMN activated_at timestamptz,
    ADD CONSTRAINT service_principal_credential_idempotency_pair
        CHECK ((idempotency_key IS NULL) = (request_hash IS NULL)),
    ADD CONSTRAINT service_principal_credential_activation_order
        CHECK (activated_at IS NULL OR activated_at >= created_at);

-- One idempotency key is single-use per (organization, issuing principal): a
-- retry with the same key -- whether the earlier attempt is still mid-flight,
-- already activated, or already revoked after a failed activation -- must hit
-- this index rather than mint a second principal/credential.
CREATE UNIQUE INDEX service_principal_credential_idempotency_unique
    ON public.service_principal_credential (organization_id, created_by, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMIT;
