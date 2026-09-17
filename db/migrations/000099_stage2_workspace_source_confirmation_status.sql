-- 000099: workspace source status must report the confirmation for its own
-- workspace binding, while the global activation predicate remains any-
-- workspace by design for worker activation.
--
-- app.source_scope_activation_confirmed is intentionally unchanged. It is
-- the source-level activation gate used by the worker and by :sync. The
-- workspace status read needs a narrower fact: whether this exact
-- (workspace, workspace_source, scope, revision, config hash, access mode)
-- tuple is currently confirmed. Keeping this as a database predicate avoids
-- a Go-side copy of the warning-contract and revocation rules.

BEGIN;

CREATE OR REPLACE FUNCTION app.workspace_source_confirmation_live(
    p_workspace_id text,
    p_workspace_source_id text,
    p_source_scope_id text,
    p_source_scope_revision bigint,
    p_scope_config_hash text,
    p_access_mode text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.workspace_managed_grant_confirmation AS confirmation
        JOIN public.organization AS organization
          ON organization.id = confirmation.organization_id
         AND organization.policy_revision = confirmation.policy_revision_number
        JOIN public.workspace AS workspace
          ON workspace.organization_id = confirmation.organization_id
         AND workspace.id = confirmation.workspace_id
        JOIN public.workspace_revision_source AS binding
          ON binding.organization_id = confirmation.organization_id
         AND binding.workspace_id = confirmation.workspace_id
         AND binding.workspace_revision = workspace.current_revision
         AND binding.workspace_source_id = confirmation.workspace_source_id
         AND binding.source_scope_id = confirmation.source_scope_id
         AND binding.source_scope_revision = confirmation.source_scope_revision
         AND binding.scope_config_hash = confirmation.scope_config_hash
         AND binding.access_mode = confirmation.access_mode
         AND binding.enabled
        JOIN public.workspace_managed_warning_contract AS warning
          ON warning.warning_version = confirmation.warning_version
         AND warning.warning_contract_hash = confirmation.warning_contract_hash
         AND warning.revision = app.workspace_managed_warning_contract_current_revision()
        WHERE confirmation.organization_id = app.current_organization_id()
          AND confirmation.workspace_id = p_workspace_id
          AND confirmation.workspace_source_id = p_workspace_source_id
          AND confirmation.source_scope_id = p_source_scope_id
          AND confirmation.source_scope_revision = p_source_scope_revision
          AND confirmation.scope_config_hash = p_scope_config_hash
          AND confirmation.access_mode = p_access_mode
          AND confirmation.access_mode = 'WORKSPACE_MANAGED'
          AND EXISTS (
              SELECT 1
              FROM public.workspace_member AS member
              WHERE member.organization_id = confirmation.organization_id
                AND member.workspace_id = confirmation.workspace_id
                AND member.principal_id = app.current_principal_id()
                AND member.removed_at IS NULL
                AND member.valid_from_revision <= workspace.current_revision
                AND (member.valid_to_revision IS NULL OR member.valid_to_revision > workspace.current_revision)
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
              WHERE revocation.organization_id = confirmation.organization_id
                AND revocation.confirmation_id = confirmation.confirmation_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS grant_revocation
              WHERE grant_revocation.organization_id = confirmation.organization_id
                AND grant_revocation.grant_id = confirmation.confirmation_actor_grant_id
                AND grant_revocation.grant_revision = confirmation.confirmation_actor_grant_revision
          )
    );
$$;

REVOKE ALL ON FUNCTION app.workspace_source_confirmation_live(text, text, text, bigint, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.workspace_source_confirmation_live(text, text, text, bigint, text, text) TO knowvault_app;

COMMIT;
