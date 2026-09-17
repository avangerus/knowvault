-- 000076: app.source_scope_activation_confirmed (000018) must stay live when
-- an UNRELATED workspace configuration mutation advances the workspace's
-- current_revision, and must still go stale when THIS scope's own binding
-- tuple changes.
--
-- Defect (owner demo-readiness report, FIN-1): every workspace configuration
-- mutation -- enabling a different source, disabling one, issuing or revoking
-- a confirmation-actor grant, anything that calls the workspace source-plane
-- command and therefore inserts a new workspace_revision/workspace_revision_
-- snapshot/workspace_revision_source row set -- bumps workspace.
-- current_revision for the WHOLE workspace. 000018's predicate required
-- confirmation.workspace_revision (the revision recorded at confirm time) to
-- equal workspace.current_revision, and the joined workspace_revision_source
-- binding to sit at that SAME historical revision. Because
-- workspace_revision_source is a full copy-forward snapshot -- every revision
-- bump inserts a fresh row for EVERY existing binding, changed or not, to
-- satisfy the 000008 exact-set guard -- a confirmation naming the previous
-- revision stops matching the instant the revision counter advances, for
-- every source in the workspace, not only the one whose own configuration
-- changed. Operator symptom: activate one more source, or issue an access
-- code, and every previously confirmed source loses its confirmation at once
-- (Activate/:sync fail-closed, GET .../sources shows the source back at
-- NEEDS_CONFIRMATION, answers stop citing that source's evidence).
--
-- Fix: stop pinning liveness to the confirmation's OWN recorded workspace_
-- revision. Instead, join the binding row at the workspace's CURRENT
-- revision and require it to still carry the exact confirmed tuple
-- (workspace_source_id, source_scope_id, source_scope_revision, scope_config_
-- hash, access_mode) and still be enabled. Because a revision bump that does
-- not touch this scope carries this scope's binding tuple forward unchanged
-- (000008's copy-forward), the current-revision binding still matches the
-- confirmation and the predicate stays true. A mutation that DOES touch this
-- scope's own configuration (its scope revision, config hash, access mode, or
-- an enabled->disabled toggle) changes the current-revision binding tuple, so
-- it no longer matches the confirmed tuple and the predicate correctly goes
-- false -- fail-closed for the scope that actually changed is preserved.
--
-- The confirmation's own workspace_revision and workspace_configuration_hash
-- columns are left in place (000018 schema, append-only): they remain the
-- historical record of what was current when the operator confirmed, used by
-- the authority command layer's own idempotency/derived-live bookkeeping
-- (confirmLiveConfirmationExists, migration 000011's deferred guard, the
-- ADR-0052 authority-command test suite) which is a different concern -- "is
-- there already a live confirmation for the request's own named revision" --
-- and is unaffected by this change. Only the RUNTIME gate that Activate,
-- :sync and the read-side confirmation_state consult
-- (app.source_scope_activation_confirmed) changes its join key.
--
-- The warning-contract and both revocation checks are unchanged: a warning
-- contract advance or a revocation still requires reconfirmation exactly as
-- before, for exactly the scope(s) it applies to (a warning contract advance
-- is global by design, per ADR-0087 §1, and is not the defect reported here).

BEGIN;

CREATE OR REPLACE FUNCTION app.source_scope_activation_confirmed(
    p_source_scope_id text, p_source_scope_revision bigint, p_scope_config_hash text
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
          AND confirmation.source_scope_id = p_source_scope_id
          AND confirmation.source_scope_revision = p_source_scope_revision
          AND confirmation.scope_config_hash = p_scope_config_hash
          AND confirmation.access_mode = 'WORKSPACE_MANAGED'
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

REVOKE ALL ON FUNCTION app.source_scope_activation_confirmed(text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_scope_activation_confirmed(text, bigint, text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.source_scope_activation_confirmed(text, bigint, text) TO knowvault_worker;

COMMIT;
