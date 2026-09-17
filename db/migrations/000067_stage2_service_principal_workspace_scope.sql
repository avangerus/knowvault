-- Stage 2: V1-C — records which workspaces one agent access code reaches.
--
-- Visibility itself is granted through the existing, unmodified
-- workspace_member/AddMember authority (internal/serviceprincipal calls the
-- same WorkspaceService.AddMember the REST "add member" action uses, with
-- Role=MEMBER, so every already-audited/canonicalized workspace-configuration
-- invariant — WSP-001..WSP-020 — applies unchanged). This table only records
-- the credential -> workspace mapping so revoke can find and remove exactly
-- the memberships one credential created, and so the issuing UI can display
-- "this code reaches workspaces X, Y" without re-deriving it from audit.

BEGIN;

CREATE TABLE public.service_principal_workspace_scope (
    organization_id text NOT NULL,
    credential_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(credential_id)),
    workspace_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(workspace_id)),
    added_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, credential_id, workspace_id),
    CONSTRAINT service_principal_workspace_scope_credential_fk
        FOREIGN KEY (organization_id, credential_id)
        REFERENCES public.service_principal_credential (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT service_principal_workspace_scope_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT
);

ALTER TABLE public.service_principal_workspace_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.service_principal_workspace_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY service_principal_workspace_scope_tenant_isolation ON public.service_principal_workspace_scope
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

GRANT SELECT, INSERT ON TABLE public.service_principal_workspace_scope TO knowvault_app;

COMMIT;
