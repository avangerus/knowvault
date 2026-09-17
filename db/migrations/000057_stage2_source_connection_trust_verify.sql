-- Stage 2: ADR-0087 §2 — CONNECTOR_ADMIN-gated source connection trust
-- verification (DRAFT -> VERIFIED).
--
-- 000006/000014 already declared DRAFT -> VERIFIED a control-plane/admin
-- authority action and left no runtime-role UPDATE grant on
-- source_connection_trust_projection (000006 grants only SELECT). This
-- migration opens exactly one product-callable door: a SECURITY DEFINER
-- function that requires an unrevoked CONNECTOR_ADMIN organization-role
-- assignment (re-checked here independently of the application policy gate)
-- and a complete attestation, and performs the transition itself. The runtime
-- application role gains no new grant on source_connection_trust_projection;
-- it is granted only EXECUTE on the function below and SELECT/INSERT/UPDATE on
-- its own actor-scoped idempotency/attestation ledger.
--
-- The transition remains exactly the monotonic guard
-- app.source_trust_projection_guard (000014) already enforces: DRAFT ->
-- VERIFIED only, never reversed by this or any other path.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Actor-scoped idempotency ledger and attestation record.
--
-- One row is both the command's idempotency receipt (keyed by organization,
-- actor and idempotency-key hash, exactly like public.conversation_command_
-- receipt) and, once SUCCESS, the immutable attestation the operator supplied:
-- who verified the connector, the exact connector identity attested, and the
-- time of verification. The raw attestation text never reaches the audit
-- chain; only this row's own generated id and canonical hash do.
-- ---------------------------------------------------------------------------

CREATE TABLE public.source_connection_trust_verification (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    actor_principal_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(actor_principal_id)),
    idempotency_key_hash text NOT NULL
        CHECK (app.stage2_sha256_is_valid(idempotency_key_hash)),
    verification_id text
        CHECK (verification_id IS NULL OR app.stage2_opaque_id_is_valid(verification_id)),
    connection_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(connection_id)),
    operation text NOT NULL CHECK (operation = 'VERIFY_TRUST'),
    canonical_request_hash text NOT NULL
        CHECK (app.stage2_sha256_is_valid(canonical_request_hash)),
    attested_connector_identity text NOT NULL
        CHECK (char_length(attested_connector_identity) BETWEEN 1 AND 512
               AND attested_connector_identity !~ '[[:cntrl:]]'),
    attested_by text NOT NULL
        CHECK (char_length(attested_by) BETWEEN 1 AND 256 AND attested_by !~ '[[:cntrl:]]'),
    attested_at timestamptz NOT NULL,
    canonical_hash text
        CHECK (canonical_hash IS NULL OR app.stage2_sha256_is_valid(canonical_hash)),
    canonical_bytes bytea,
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')),
    audit_event_id text
        CHECK (audit_event_id IS NULL OR app.stage2_opaque_id_is_valid(audit_event_id)),
    verified_by text
        CHECK (verified_by IS NULL OR app.stage2_opaque_id_is_valid(verified_by)),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    terminal_at timestamptz,
    PRIMARY KEY (organization_id, actor_principal_id, idempotency_key_hash),
    CONSTRAINT source_connection_trust_verification_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    -- connection_id is deliberately NOT foreign-keyed to source_connection: a
    -- receipt is reserved before the connection's existence is known (it may
    -- terminate NOT_FOUND for a hidden or absent connection), exactly like
    -- request_workspace_id on public.workspace_managed_authority_command_receipt
    -- (000011), which is not foreign-keyed to public.workspace for the same
    -- reason.
    CONSTRAINT source_connection_trust_verification_audit_fk
        FOREIGN KEY (organization_id, audit_event_id)
        REFERENCES public.audit_event (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_connection_trust_verification_result_unique
        UNIQUE (organization_id, verification_id),
    CONSTRAINT source_connection_trust_verification_state_shape CHECK (
        (status = 'PENDING' AND audit_event_id IS NULL AND terminal_at IS NULL
            AND verification_id IS NULL AND canonical_hash IS NULL
            AND verified_by IS NULL AND verified_at IS NULL)
        OR (status = 'SUCCESS' AND audit_event_id IS NOT NULL AND terminal_at IS NOT NULL
            AND verification_id IS NOT NULL AND canonical_hash IS NOT NULL
            AND verified_by IS NOT NULL AND verified_at IS NOT NULL)
        OR (status IN ('DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')
            AND audit_event_id IS NOT NULL AND terminal_at IS NOT NULL
            AND verification_id IS NULL AND canonical_hash IS NULL
            AND verified_by IS NULL AND verified_at IS NULL)
    ),
    CONSTRAINT source_connection_trust_verification_terminal_order CHECK (
        terminal_at IS NULL OR terminal_at >= created_at
    )
);

CREATE INDEX source_connection_trust_verification_connection
    ON public.source_connection_trust_verification (organization_id, connection_id, created_at DESC);

CREATE OR REPLACE FUNCTION app.source_connection_trust_verification_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.status <> 'PENDING' OR NEW.audit_event_id IS NOT NULL OR NEW.terminal_at IS NOT NULL
       OR NEW.verification_id IS NOT NULL OR NEW.canonical_hash IS NOT NULL THEN
        RAISE EXCEPTION 'source connection trust verification receipt must begin pending' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_connection_trust_verification_insert_guard
BEFORE INSERT ON public.source_connection_trust_verification
FOR EACH ROW EXECUTE FUNCTION app.source_connection_trust_verification_insert_guard();

CREATE OR REPLACE FUNCTION app.source_connection_trust_verification_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.actor_principal_id <> OLD.actor_principal_id
       OR NEW.idempotency_key_hash <> OLD.idempotency_key_hash
       OR NEW.connection_id <> OLD.connection_id
       OR NEW.operation <> OLD.operation
       OR NEW.canonical_request_hash <> OLD.canonical_request_hash
       OR NEW.attested_connector_identity <> OLD.attested_connector_identity
       OR NEW.attested_by <> OLD.attested_by
       OR NEW.attested_at <> OLD.attested_at
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'source connection trust verification identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status <> 'PENDING'
       OR NEW.status NOT IN ('SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')
       OR NEW.terminal_at <> transaction_timestamp() THEN
        RAISE EXCEPTION 'source connection trust verification must transition once to a terminal state' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_connection_trust_verification_terminal_guard
BEFORE UPDATE ON public.source_connection_trust_verification
FOR EACH ROW EXECUTE FUNCTION app.source_connection_trust_verification_terminal_guard();

CREATE OR REPLACE FUNCTION app.source_connection_trust_verification_no_pending_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    persisted_status text;
BEGIN
    SELECT status INTO persisted_status
      FROM public.source_connection_trust_verification
     WHERE organization_id = NEW.organization_id
       AND actor_principal_id = NEW.actor_principal_id
       AND idempotency_key_hash = NEW.idempotency_key_hash;
    IF NOT FOUND OR persisted_status = 'PENDING' THEN
        RAISE EXCEPTION 'source connection trust verification cannot commit pending' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER source_connection_trust_verification_requires_terminal
AFTER INSERT OR UPDATE ON public.source_connection_trust_verification
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.source_connection_trust_verification_no_pending_commit();

ALTER TABLE public.source_connection_trust_verification ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_connection_trust_verification FORCE ROW LEVEL SECURITY;
CREATE POLICY source_connection_trust_verification_actor ON public.source_connection_trust_verification
USING (
    organization_id = app.current_organization_id()
    AND actor_principal_id = app.current_principal_id()
)
WITH CHECK (
    organization_id = app.current_organization_id()
    AND actor_principal_id = app.current_principal_id()
);

REVOKE ALL ON TABLE public.source_connection_trust_verification FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.source_connection_trust_verification TO knowvault_app;
REVOKE ALL ON FUNCTION app.source_connection_trust_verification_insert_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.source_connection_trust_verification_terminal_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.source_connection_trust_verification_no_pending_commit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_connection_trust_verification_insert_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_connection_trust_verification_terminal_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_connection_trust_verification_no_pending_commit() TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 2. The one door: app.source_connection_trust_verify.
--
-- SECURITY DEFINER, so it runs with the privilege to UPDATE
-- source_connection_trust_projection that no runtime role holds. It re-checks
-- CONNECTOR_ADMIN itself (independent of the Go policy gate that already
-- restricts source.verify_trust to that role — two independent layers for one
-- critical invariant, per POKA_YOKE.md s1), requires the connection's DRAFT
-- trust projection to exist and locks it, and raises a distinct, closed
-- ERRCODE for each fail-closed branch so the calling transaction can classify
-- the outcome without parsing message text:
--   42501 (insufficient_privilege)      -- caller is not CONNECTOR_ADMIN
--   P0002 (no_data_found)               -- no such connection/trust projection
--   55000 (object_not_in_prerequisite_state) -- projection is not DRAFT
-- The projection UPDATE itself still passes through
-- app.source_trust_projection_guard (000014), so the monotonic DRAFT->VERIFIED
-- rule is enforced twice: once by this function's own precondition check and
-- once, unconditionally, by the trigger no caller of this function can bypass.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_connection_trust_verify(p_connection_id text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_trust_record_id text;
    v_status text;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM public.organization_role_assignment
         WHERE organization_id = app.current_organization_id()
           AND principal_id = app.current_principal_id()
           AND role = 'CONNECTOR_ADMIN' AND revoked_at IS NULL
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

REVOKE ALL ON FUNCTION app.source_connection_trust_verify(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_connection_trust_verify(text) TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 3. Audit metadata allowlist: add the two connection trust verification
-- keys (ADR-0087 §2) to the closed key set app.audit_metadata_is_allowed
-- enforces at the database boundary. Recreated cumulatively (the 000022
-- baseline) with exactly those two new keys, exactly as every prior migration
-- that extended this allowlist did; every value stays outside the database
-- boundary — only key names are constrained here.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.audit_metadata_is_allowed(metadata jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT jsonb_typeof(metadata) = 'object'
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_object_keys(metadata) AS metadata_key
           WHERE metadata_key NOT IN (
               'workspace_revision', 'workspace_source_id',
               'source_scope_id', 'source_scope_revision',
               'scope_config_hash', 'access_mode', 'enabled',
               'source_connection_id', 'connector_job_id', 'sync_run_id',
               'question_run_id', 'model_run_id', 'citation_number',
               'manifest_hash', 'policy_revision', 'reason_codes',
               'remote_address_digest', 'user_agent_family',
               -- Authority command vocabulary (ADR-0053).
               'authority_operation', 'authority_result_id', 'authority_result_hash',
               'authority_parent_id', 'authority_parent_hash',
               'authority_revocation_id', 'authority_revocation_hash',
               'authority_reason_code', 'target_principal_id',
               'workspace_configuration_hash', 'confirmation_actor_grant_id',
               'confirmation_actor_grant_revision', 'confirmation_actor_grant_hash',
               'warning_version', 'warning_contract_hash', 'acknowledgement_code',
               -- Rotation vocabulary (ADR-0070).
               'rotation_domain', 'key_reference', 'key_version',
               -- Amendment vocabulary (ADR-0076).
               'answer_document_version', 'amendment_class',
               -- Connection trust verification vocabulary (ADR-0087 §2).
               'trust_verification_id', 'trust_verification_hash'
           )
       );
$$;

COMMIT;
