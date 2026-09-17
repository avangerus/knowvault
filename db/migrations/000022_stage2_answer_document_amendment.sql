-- Stage 2 answer document amendment layer (ADR-0076).
--
-- A published answer manifest is immutable: no amendment rewrites a published
-- version. Every amendment is a separate superseding version carrying its own
-- signature, the hash chain link to the previous version and a closed
-- amendment class (SUPERSEDE/RETRACT/REDACT). Amendments commit only through
-- the owner path (the runtime application role with a workspace OWNER actor),
-- and the application layer audits each one in the same transaction. Every
-- open re-checks access: a version whose cited fragments are no longer
-- available to the workspace (retention purge or scope unbinding) does not
-- open as proof, and retracted/redacted statements are not published as proof.

BEGIN;

CREATE TABLE public.answer_document_version (
    organization_id text NOT NULL,
    workspace_id text NOT NULL,
    answer_document_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(answer_document_id)),
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    previous_version_hash text CHECK (
        previous_version_hash IS NULL OR app.stage2_sha256_is_valid(previous_version_hash)
    ),
    amendment_class text CHECK (amendment_class IN ('SUPERSEDE', 'RETRACT', 'REDACT')),
    amendment_reason text CHECK (amendment_reason IS NULL OR char_length(amendment_reason) BETWEEN 1 AND 2000),
    manifest_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(manifest_hash)),
    actor_principal_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(actor_principal_id)),
    request_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(request_id)),
    amended_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, answer_document_id, version),
    CONSTRAINT answer_document_version_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT answer_document_version_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE TABLE public.answer_document_citation (
    organization_id text NOT NULL,
    answer_document_id text NOT NULL,
    version bigint NOT NULL,
    citation_number integer NOT NULL CHECK (citation_number BETWEEN 1 AND 9007199254740991),
    evidence_fragment_id text NOT NULL,
    PRIMARY KEY (organization_id, answer_document_id, version, citation_number),
    CONSTRAINT answer_document_citation_version_fk
        FOREIGN KEY (organization_id, answer_document_id, version)
        REFERENCES public.answer_document_version (organization_id, answer_document_id, version)
        ON DELETE RESTRICT,
    CONSTRAINT answer_document_citation_fragment_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION app.answer_document_version_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Published versions are immutable: neither UPDATE nor DELETE may touch
    -- them. Amendments are separate superseding versions only.
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'answer document versions are immutable'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'answer document versions are immutable'
            USING ERRCODE = '55000';
    END IF;

    -- Owner-only amendment path: only the runtime application role inserts,
    -- and the actor must hold an active workspace OWNER membership.
    IF session_user <> 'knowvault_app'
       OR NOT EXISTS (SELECT 1 FROM public.workspace_member
                      WHERE organization_id = NEW.organization_id
                        AND workspace_id = NEW.workspace_id
                        AND principal_id = NEW.actor_principal_id
                        AND role = 'OWNER'
                        AND valid_to_revision IS NULL) THEN
        RAISE EXCEPTION 'answer document amendment requires the workspace owner path'
            USING ERRCODE = '42501';
    END IF;

    -- Initial version: the amendment shape must be null and the document must
    -- not exist yet.
    IF NEW.version = 1 THEN
        IF NEW.previous_version_hash IS NOT NULL
           OR NEW.amendment_class IS NOT NULL
           OR NEW.amendment_reason IS NOT NULL
           OR EXISTS (SELECT 1 FROM public.answer_document_version
                      WHERE organization_id = NEW.organization_id
                        AND answer_document_id = NEW.answer_document_id) THEN
            RAISE EXCEPTION 'initial answer document version requires a null amendment shape'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    -- Superseding version: a closed amendment class with a reason, the exact
    -- successor number and an unbroken hash chain from the published previous
    -- version. A chain break or a version skip is rejected.
    IF NEW.amendment_class IS NULL
       OR NEW.amendment_reason IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM public.answer_document_version prev
           WHERE prev.organization_id = NEW.organization_id
             AND prev.answer_document_id = NEW.answer_document_id
             AND prev.version = NEW.version - 1
             AND prev.manifest_hash = NEW.previous_version_hash
             AND NOT EXISTS (SELECT 1 FROM public.answer_document_version newer
                             WHERE newer.organization_id = NEW.organization_id
                               AND newer.answer_document_id = NEW.answer_document_id
                               AND newer.version >= NEW.version)
       ) THEN
        RAISE EXCEPTION 'answer document amendment requires a closed class and an exact hash chain'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER answer_document_version_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.answer_document_version
FOR EACH ROW EXECUTE FUNCTION app.answer_document_version_guard();

-- Read path: the latest version opens as proof only while it is not a
-- retract/redact amendment and every cited fragment is still available to the
-- workspace: its retention is not in a purge state and its source scope stays
-- bound to the workspace.
--
-- The function is SECURITY DEFINER because the runtime open is a
-- service-to-service read: the caller is not a workspace member, so the
-- membership-conditioned workspace_source policy would hide the binding row
-- and turn every open into a denial. The re-check is therefore part of the
-- function itself (ADR-0076: access is re-checked on every open), and the
-- definer bypass of row security is compensated by binding every predicate to
-- the caller's tenant context: p_organization_id must equal
-- app.current_organization_id(), so no other tenant's version is ever visible.
CREATE OR REPLACE FUNCTION app.open_answer_document(
    p_organization_id text,
    p_workspace_id text,
    p_answer_document_id text
)
RETURNS TABLE(
    version bigint,
    amendment_class text,
    amended_at timestamptz,
    manifest_hash text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT v.version, v.amendment_class, v.amended_at, v.manifest_hash
    FROM public.answer_document_version v
    WHERE v.organization_id = p_organization_id
      AND p_organization_id = app.current_organization_id()
      AND v.workspace_id = p_workspace_id
      AND v.answer_document_id = p_answer_document_id
      AND v.version = (SELECT max(v2.version) FROM public.answer_document_version v2
                       WHERE v2.organization_id = p_organization_id
                         AND v2.answer_document_id = p_answer_document_id)
      AND (v.amendment_class IS NULL OR v.amendment_class = 'SUPERSEDE')
      AND NOT EXISTS (
          SELECT 1 FROM public.answer_document_citation c
          JOIN public.evidence_fragment f
            ON f.organization_id = c.organization_id AND f.id = c.evidence_fragment_id
          LEFT JOIN public.source_version_retention r
            ON r.organization_id = f.organization_id AND r.source_version_id = f.source_version_id
          LEFT JOIN public.source_version sv
            ON sv.organization_id = f.organization_id AND sv.id = f.source_version_id
          LEFT JOIN public.source_object_scope sos
            ON sos.organization_id = sv.organization_id
           AND sos.source_object_id = sv.source_object_id
           AND sos.membership_state = 'ACTIVE'
          WHERE c.organization_id = p_organization_id
            AND c.answer_document_id = p_answer_document_id
            AND c.version = v.version
            AND (
                COALESCE(r.state, 'ACTIVE') IN ('PURGING', 'PURGED')
                OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_source ws
                    WHERE ws.organization_id = p_organization_id
                      AND ws.workspace_id = p_workspace_id
                      AND ws.source_scope_id = sos.source_scope_id
                )
            )
      )
$$;

REVOKE ALL ON FUNCTION app.open_answer_document(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.open_answer_document(text, text, text) TO knowvault_app;

ALTER TABLE public.answer_document_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.answer_document_version FORCE ROW LEVEL SECURITY;
CREATE POLICY answer_document_version_tenant_isolation ON public.answer_document_version
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.answer_document_citation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.answer_document_citation FORCE ROW LEVEL SECURITY;
CREATE POLICY answer_document_citation_tenant_isolation ON public.answer_document_citation
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.answer_document_version, public.answer_document_citation FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.answer_document_version TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.answer_document_citation TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.open_answer_document(text, text, text) TO knowvault_app;

-- ADR-0076: the amendment audit event records an ANSWER_DOCUMENT resource, so
-- the closed audit resource-type enum gains that value exactly like the
-- rotation migration extended it with CRYPTO_KEY.
ALTER TABLE public.audit_event DROP CONSTRAINT audit_event_resource_type_check;
ALTER TABLE public.audit_event ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
    'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
    'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
    'SOURCE_CONNECTION', 'SOURCE_SCOPE',
    'SOURCE_OBJECT', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
    'SIGNING_KEY', 'AUDIT_CHECKPOINT', 'CRYPTO_KEY', 'ANSWER_DOCUMENT'
));

-- ADR-0076: the amendment audit event metadata gains the two protected
-- amendment fields, so the closed audit metadata key allowlist is recreated
-- cumulatively (the 000019 baseline) with exactly those two new keys; every
-- value stays outside the database boundary.
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
               'answer_document_version', 'amendment_class'
           )
       );
$$;

COMMIT;
