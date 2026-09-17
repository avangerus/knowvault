-- Stage 2: V1-C — agent access codes (ADR-0079 §3 delivery slice).
--
-- Implements the SERVICE principal credential the product calls an "access
-- code for an agent": a workspace OWNER issues one bounded-TTL code naming a
-- SERVICE principal, the raw code is shown exactly once, and MCP accepts it
-- as `Authorization: Bearer <code>` (internal/serviceprincipal,
-- internal/platform/workspaceapi). This migration adds only the credential
-- itself; which workspaces the resulting SERVICE principal may reach is
-- recorded by 000067 and granted through the existing, unmodified
-- workspace_member/AddMember authority (no change to workspace-configuration
-- canonicalization, ACL-*, WSP-* or the evidence disclosure gate is needed:
-- a SERVICE principal is simply another workspace_member row, so every
-- existing membership-gated read path already scopes it correctly).
--
-- The raw code is never stored. `code_digest` is a plain SHA-256 of the raw
-- code bytes: the code itself is a 256-bit CSPRNG value (internal/
-- serviceprincipal), so an unkeyed digest already has negligible reversal
-- risk (the same reasoning that lets a high-entropy API key be stored as a
-- bare hash elsewhere in the industry); this keeps issuance free of a new
-- KMS-mounted purpose key. `expires_at` is enforced at authentication time
-- (fail-closed, checked live on every call) rather than by a sweep job.
-- Explicit revoke sets `revoked_at`; both checks are independent (defense in
-- depth) and either one alone is sufficient to deny.

BEGIN;

CREATE TABLE public.service_principal_credential (
    id text PRIMARY KEY CHECK (app.stage2_opaque_id_is_valid(id) AND char_length(id) BETWEEN 3 AND 128),
    organization_id text NOT NULL,
    principal_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(principal_id)),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256 AND name !~ '[[:cntrl:]]'),
    code_digest text NOT NULL CHECK (app.stage2_sha256_is_valid(code_digest)),
    created_by text NOT NULL CHECK (app.stage2_opaque_id_is_valid(created_by)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by text CHECK (revoked_by IS NULL OR app.stage2_opaque_id_is_valid(revoked_by)),
    CONSTRAINT service_principal_credential_expiry_future CHECK (expires_at > created_at),
    CONSTRAINT service_principal_credential_revocation_pair
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT service_principal_credential_organization_fk
        FOREIGN KEY (organization_id) REFERENCES public.organization (id) ON DELETE RESTRICT,
    CONSTRAINT service_principal_credential_principal_fk
        FOREIGN KEY (organization_id, principal_id) REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT service_principal_credential_created_by_fk
        FOREIGN KEY (organization_id, created_by) REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT service_principal_credential_revoked_by_fk
        FOREIGN KEY (organization_id, revoked_by) REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT service_principal_credential_principal_unique UNIQUE (organization_id, principal_id),
    CONSTRAINT service_principal_credential_digest_unique UNIQUE (organization_id, code_digest),
    CONSTRAINT service_principal_credential_org_id_unique UNIQUE (organization_id, id)
);

ALTER TABLE public.service_principal_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.service_principal_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY service_principal_credential_tenant_isolation ON public.service_principal_credential
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

GRANT SELECT, INSERT, UPDATE ON TABLE public.service_principal_credential TO knowvault_app;

COMMIT;
