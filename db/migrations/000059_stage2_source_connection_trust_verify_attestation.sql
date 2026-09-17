-- Stage 2: ADR-0087 §2 review blockers B2/B3 (review-opus-s2-4-5.md) --
-- SQL-layer attestation enforcement and verifier/confirmer separation of
-- duty for source connection trust verification.
--
-- Migration 000057 opened app.source_connection_trust_verify(text) as the
-- one SECURITY DEFINER door for DRAFT -> VERIFIED, gated on CONNECTOR_ADMIN.
-- Its own comment claimed "two independent layers for one critical
-- invariant" (POKA_YOKE.md s1), but the function accepted only
-- p_connection_id: completeness of the attestation was enforced solely by
-- the Go request validator (internal/workspace/repository/trust_verify.go),
-- so a direct database session as the runtime role could call the function
-- with no attestation at all. This migration replaces that function (same
-- name, a signature that carries the attestation) so the database itself
-- rejects an empty or incomplete attestation, independently of the Go
-- validator, and adds the ADR-0087 §2 verifier/confirmer separation of duty
-- at the same authorization step: "A principal cannot be both the
-- CONNECTOR_ADMIN verifier and the confirming workspace owner/manager for
-- the same scope; that separation is enforced at authorization time, not
-- left to operational discipline."
--
-- The old single-argument overload is dropped so no caller -- Go or a raw
-- SQL session as the runtime role -- can still reach the attestation-free
-- path; knowvault_app never held more than EXECUTE on this function, so
-- dropping the old overload removes a capability, never adds one.

BEGIN;

DROP FUNCTION IF EXISTS app.source_connection_trust_verify(text);

CREATE FUNCTION app.source_connection_trust_verify(
    p_connection_id text,
    p_attested_connector_identity text,
    p_attested_by text,
    p_attested_at timestamptz
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_trust_record_id text;
    v_status text;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'connection trust verification is an application-role surface'
            USING ERRCODE = '42501';
    END IF;

    -- B2: the second, independent layer of the attestation requirement
    -- (POKA_YOKE.md s1). The Go request validator (VerifyConnectionTrustRequest
    -- .valid(), trust_verify.go) already rejects an empty/incomplete
    -- attestation before this function is ever called from the product
    -- surface; this repeats the same check inside the SECURITY DEFINER
    -- boundary itself, so a direct database session as the runtime role
    -- cannot bypass it by calling the function directly.
    IF p_attested_connector_identity IS NULL OR btrim(p_attested_connector_identity) = ''
       OR p_attested_by IS NULL OR btrim(p_attested_by) = ''
       OR p_attested_at IS NULL THEN
        RAISE EXCEPTION 'connection trust verification requires a complete attestation'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.organization_role_assignment
         WHERE organization_id = app.current_organization_id()
           AND principal_id = app.current_principal_id()
           AND role = 'CONNECTOR_ADMIN' AND revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'connection trust verification requires CONNECTOR_ADMIN' USING ERRCODE = '42501';
    END IF;

    -- B3 (ADR-0087 §2 separation of duty): the verifying principal must
    -- never also be the confirming principal of a WORKSPACE_MANAGED binding
    -- of a source scope that belongs to this connection. Content-free and
    -- fail-closed: the identical ERRCODE and message as the role check
    -- above, so the caller can no more distinguish "wrong role" from "same
    -- principal as confirmer" than it can distinguish either from a hidden
    -- connection (acceptance test 3 of ADR-0087).
    IF EXISTS (
        SELECT 1
          FROM public.workspace_managed_grant_confirmation AS confirmation
          JOIN public.source_scope AS scope
            ON scope.organization_id = confirmation.organization_id
           AND scope.id = confirmation.source_scope_id
         WHERE confirmation.organization_id = app.current_organization_id()
           AND scope.connection_id = p_connection_id
           AND confirmation.confirmed_by = app.current_principal_id()
    ) THEN
        RAISE EXCEPTION 'connection trust verification requires CONNECTOR_ADMIN' USING ERRCODE = '42501';
    END IF;

    SELECT record.id, projection.status
      INTO v_trust_record_id, v_status
      FROM public.source_connection_trust_record AS record
      JOIN public.source_connection_trust_projection AS projection
        ON projection.organization_id = record.organization_id
       AND projection.trust_record_id = record.id
     WHERE record.organization_id = app.current_organization_id()
       AND record.connection_id = p_connection_id
     ORDER BY record.connection_revision DESC
     LIMIT 1
       FOR UPDATE OF projection;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'connection trust projection not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_status <> 'DRAFT' THEN
        RAISE EXCEPTION 'connection trust projection is not in DRAFT' USING ERRCODE = '55000';
    END IF;

    UPDATE public.source_connection_trust_projection
       SET status = 'VERIFIED', changed_at = transaction_timestamp()
     WHERE organization_id = app.current_organization_id()
       AND trust_record_id = v_trust_record_id;

    RETURN v_trust_record_id;
END;
$$;

REVOKE ALL ON FUNCTION app.source_connection_trust_verify(text, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_connection_trust_verify(text, text, text, timestamptz) TO knowvault_app;

COMMIT;
