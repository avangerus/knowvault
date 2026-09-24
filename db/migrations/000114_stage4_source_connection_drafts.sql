-- Stage 4 card D-1: a half-finished PostgreSQL connection is a visible,
-- workspace-scoped draft, and re-attesting an already-verified, unchanged
-- trust material is an idempotent success.
--
-- 000091 creates the immutable DRAFT connection revision a discovery probe
-- needs, but nothing records which workspace started that connection, so
-- after an administrator abandons the wizard the draft is invisible to the
-- Sources surface and can only be reached by replaying the exact bootstrap
-- call. This migration adds one append-only, workspace-scoped registry row per
-- (workspace, connection): the smallest fact that lets a workspace list and
-- discard its own unfinished connections without exposing another workspace's
-- draft, without inventing a second source authority and without granting the
-- runtime role any write on the source control plane.
--
-- It also replaces app.source_connection_trust_verify (000059) with a version
-- that treats a re-attestation of an already-VERIFIED, unexpired, unchanged
-- trust material as success instead of 55000, while keeping every other
-- fail-closed branch: an expired record, or an attestation that names a
-- different connector identity than the recorded verification, still raises
-- 55000 (WORKSPACE_CONNECTION_TRUST_PRECONDITION_FAILED).

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Workspace-scoped draft connection registry.
--
-- The row is a pointer, not a copy: connection identity, revision, trust
-- material and credential reference stay exactly where 000006/000091 put
-- them. created_by is the organization OWNER who ran bootstrap (bootstrap
-- itself is OWNER-gated), so the registry never becomes a second membership
-- or authority model.
-- ---------------------------------------------------------------------------

CREATE TABLE public.source_connection_draft (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    workspace_id text NOT NULL
        CHECK (char_length(workspace_id) BETWEEN 3 AND 128 AND workspace_id !~ '[[:cntrl:]]'),
    connection_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(connection_id)),
    connection_revision bigint NOT NULL
        CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    created_by text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(created_by)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, connection_id),
    CONSTRAINT source_connection_draft_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT source_connection_draft_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT source_connection_draft_actor_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT
);

ALTER TABLE public.source_connection_draft ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_connection_draft FORCE ROW LEVEL SECURITY;
CREATE POLICY source_connection_draft_tenant_isolation ON public.source_connection_draft
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_connection_draft FROM PUBLIC;
-- The runtime role reads its own tenant's drafts; every write goes through the
-- two SECURITY DEFINER functions below, so the runtime role still holds no
-- INSERT/UPDATE/DELETE on any source control-plane relation.
GRANT SELECT ON TABLE public.source_connection_draft TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 2. Register (idempotent) and discard (the workspace's own draft).
--
-- Registration is a replay-safe pointer write called in the same transaction
-- as an exact bootstrap: a replayed bootstrap re-links the same connection to
-- the same workspace without creating a second row, and a discard followed by
-- a fresh bootstrap links it again. Both functions re-check the current
-- organization OWNER independently of the Go policy gate, exactly like
-- app.source_postgresql_connection_bootstrap_begin.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_connection_draft_register(
    p_workspace_id text,
    p_connection_id text,
    p_connection_revision bigint
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
        RAISE EXCEPTION 'source connection draft registration is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    actor_value := app.current_principal_id();
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    IF organization_value IS NULL OR actor_value IS NULL
       OR security_epoch_value IS NULL
       OR p_workspace_id IS NULL OR btrim(p_workspace_id) = ''
       OR NOT app.source_generated_id_is_valid(p_connection_id, 'conn')
       OR p_connection_revision < 1
       OR NOT app.source_discovery_owner_is_current(
           organization_value, actor_value, security_epoch_value)
       OR NOT EXISTS (
           SELECT 1 FROM public.workspace AS workspace
           WHERE workspace.organization_id = organization_value
             AND workspace.id = p_workspace_id
             AND workspace.status = 'ACTIVE'
       )
       OR NOT EXISTS (
           SELECT 1 FROM public.source_connection AS connection
           WHERE connection.organization_id = organization_value
             AND connection.id = p_connection_id
             AND connection.type = 'POSTGRESQL_QUERY'
             AND connection.status = 'DRAFT'
             AND connection.latest_revision = p_connection_revision
       ) THEN
        RAISE EXCEPTION 'source connection draft registration requires the current organization OWNER and a live DRAFT connection'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.source_connection_draft (
        organization_id, workspace_id, connection_id, connection_revision, created_by
    ) VALUES (
        organization_value, p_workspace_id, p_connection_id, p_connection_revision, actor_value
    )
    ON CONFLICT (organization_id, workspace_id, connection_id) DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_connection_draft_discard(
    p_workspace_id text,
    p_connection_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    actor_value text;
    security_epoch_value bigint;
    removed integer;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source connection draft discard is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    actor_value := app.current_principal_id();
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    IF organization_value IS NULL OR actor_value IS NULL
       OR security_epoch_value IS NULL
       OR NOT (
           app.source_discovery_owner_is_current(
               organization_value, actor_value, security_epoch_value)
           OR EXISTS (
               SELECT 1 FROM public.workspace_member AS member
               WHERE member.organization_id = organization_value
                 AND member.workspace_id = p_workspace_id
                 AND member.principal_id = actor_value
                 AND member.removed_at IS NULL
                 AND member.role IN ('OWNER', 'MANAGER')
           )
       ) THEN
        RAISE EXCEPTION 'source connection draft discard requires the organization OWNER or a workspace OWNER/MANAGER'
            USING ERRCODE = '42501';
    END IF;

    DELETE FROM public.source_connection_draft
    WHERE organization_id = organization_value
      AND workspace_id = p_workspace_id
      AND connection_id = p_connection_id;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed > 0;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Workspace-scoped draft read.
--
-- The application layer performs the workspace-membership policy gate (the
-- same OperationWorkspaceViewMetadata gate ListSources uses); this read
-- repeats the tenant check and additionally requires an unremoved membership
-- of that exact workspace (or the current organization OWNER), so a foreign
-- workspace can never read a draft even if the application gate were
-- weakened. Only content-free identifiers and the derived draft state are
-- returned.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_connection_draft_list(p_workspace_id text)
RETURNS TABLE(
    connection_id text,
    connection_revision bigint,
    connection_name text,
    source_type text,
    trust_status text,
    state text,
    created_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    principal_value text;
    security_epoch_value bigint;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'source connection draft list is restricted to the application role'
            USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    principal_value := app.current_principal_id();
    SELECT organization.role_revision INTO security_epoch_value
    FROM public.organization AS organization
    WHERE organization.id = organization_value AND organization.status = 'ACTIVE';
    IF organization_value IS NULL OR principal_value IS NULL
       OR security_epoch_value IS NULL
       OR NOT app.source_discovery_owner_is_current(
           organization_value, principal_value, security_epoch_value)
       AND NOT EXISTS (
           SELECT 1 FROM public.workspace_member AS member
           WHERE member.organization_id = organization_value
             AND member.workspace_id = p_workspace_id
             AND member.principal_id = principal_value
             AND member.removed_at IS NULL
       ) THEN
        RAISE EXCEPTION 'source connection draft list requires workspace membership'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT draft.connection_id, draft.connection_revision, connection.name,
           connection.type,
           projection.status,
           CASE projection.status
               WHEN 'VERIFIED' THEN 'READY_FOR_DISCOVERY'
               ELSE 'AWAITING_TRUST_VERIFICATION'
           END,
           draft.created_at
    FROM public.source_connection_draft AS draft
    JOIN public.source_connection AS connection
      ON connection.organization_id = draft.organization_id
     AND connection.id = draft.connection_id
     AND connection.status = 'DRAFT'
     AND connection.active_revision IS NULL
    JOIN public.source_connection_revision AS revision
      ON revision.organization_id = connection.organization_id
     AND revision.connection_id = connection.id
     AND revision.revision = connection.latest_revision
    JOIN public.source_connection_trust_record AS trust_record
      ON trust_record.organization_id = revision.organization_id
     AND trust_record.id = revision.trust_record_id
     AND trust_record.connection_id = revision.connection_id
     AND trust_record.connection_revision = revision.revision
    JOIN public.source_connection_trust_projection AS projection
      ON projection.organization_id = trust_record.organization_id
     AND projection.trust_record_id = trust_record.id
    WHERE draft.organization_id = organization_value
      AND draft.workspace_id = p_workspace_id
    ORDER BY draft.created_at, draft.connection_id;
END;
$$;

REVOKE ALL ON FUNCTION app.source_connection_draft_register(text, text, bigint) FROM PUBLIC, knowvault_worker;
REVOKE ALL ON FUNCTION app.source_connection_draft_discard(text, text) FROM PUBLIC, knowvault_worker;
REVOKE ALL ON FUNCTION app.source_connection_draft_list(text) FROM PUBLIC, knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_connection_draft_register(text, text, bigint) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_connection_draft_discard(text, text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_connection_draft_list(text) TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4. Trust re-verification becomes idempotent for unchanged, trusted material.
--
-- 000059 raised 55000 for any projection that was not DRAFT, so an operator
-- reopening the wizard for an already-verified connection could not continue:
-- the exact same attestation was refused as a stale precondition. The function
-- now returns the verified trust record id when (a) the latest projection is
-- already VERIFIED, (b) its trust record has not expired, and (c) this
-- organization already recorded a SUCCESS verification of this exact
-- connector identity for this connection. Every other non-DRAFT case keeps the
-- closed 55000 vocabulary: a changed connector identity, an expired
-- certificate and any other untrusted state all fail closed. The transition
-- itself and both authorization layers are unchanged from 000059.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_connection_trust_verify(
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
    v_expires_at timestamptz;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'connection trust verification is an application-role surface'
            USING ERRCODE = '42501';
    END IF;

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

    SELECT record.id, projection.status, record.expires_at
      INTO v_trust_record_id, v_status, v_expires_at
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

    -- D-1: an unchanged, already-verified, unexpired trust material is a
    -- success, not a stale precondition. The comparison is against the
    -- content-free attestation already recorded for this connection, so a
    -- changed certificate identity (or a new attestation value) still fails
    -- closed with the same 55000 as any other untrusted state.
    IF v_status = 'VERIFIED' THEN
        IF v_expires_at > transaction_timestamp() AND EXISTS (
            SELECT 1 FROM public.source_connection_trust_verification AS verification
             WHERE verification.organization_id = app.current_organization_id()
               AND verification.connection_id = p_connection_id
               AND verification.status = 'SUCCESS'
               AND verification.attested_connector_identity = p_attested_connector_identity
        ) THEN
            RETURN v_trust_record_id;
        END IF;
        RAISE EXCEPTION 'connection trust material changed or expired since verification'
            USING ERRCODE = '55000';
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
