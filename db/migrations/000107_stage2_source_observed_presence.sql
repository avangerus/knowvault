-- A full observation may temporarily lose a path/SQL identity. This is
-- distinct from terminal scope removal, object deletion and retention purge.
-- Existing readable predicates still require ACTIVE; MISSING discloses no bytes.
BEGIN;

ALTER TABLE public.source_object
    DROP CONSTRAINT IF EXISTS source_object_lifecycle_state_check;
ALTER TABLE public.source_object
    ADD CONSTRAINT source_object_lifecycle_state_check
    CHECK (lifecycle_state IN ('ACTIVE', 'MISSING', 'DELETED'));
ALTER TABLE public.source_object
    DROP CONSTRAINT IF EXISTS source_object_missing_not_queryable;
ALTER TABLE public.source_object
    ADD CONSTRAINT source_object_missing_not_queryable CHECK (lifecycle_state <> 'MISSING' OR NOT queryable);

ALTER TABLE public.source_object_scope
    DROP CONSTRAINT IF EXISTS source_object_scope_membership_state_check;
ALTER TABLE public.source_object_scope
    ADD CONSTRAINT source_object_scope_membership_state_check
    CHECK (membership_state IN ('ACTIVE', 'MISSING', 'MOVED', 'REMOVED'));
ALTER TABLE public.source_object_scope
    ADD COLUMN IF NOT EXISTS missing_at timestamptz,
    ADD COLUMN IF NOT EXISTS missing_sync_run_id text;
ALTER TABLE public.source_object_scope
    DROP CONSTRAINT IF EXISTS source_object_scope_missing_run_fk,
    DROP CONSTRAINT IF EXISTS source_object_scope_missing_state_check;
ALTER TABLE public.source_object_scope
    ADD CONSTRAINT source_object_scope_missing_run_fk
    FOREIGN KEY (organization_id, missing_sync_run_id)
    REFERENCES public.sync_run (organization_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT source_object_scope_missing_state_check
    CHECK ((membership_state = 'MISSING') = (missing_at IS NOT NULL AND missing_sync_run_id IS NOT NULL)
           AND (membership_state = 'MISSING' OR (missing_at IS NULL AND missing_sync_run_id IS NULL)));

-- Conservative compatibility classification, without making anything readable.
-- A historical deletion event alone is insufficient: its exact successful FULL
-- run/job, membership timestamp, still-current scope revision and untouched
-- retention must agree. A cutover closes an OLDER revision, so cannot qualify.
-- Removed memberships of a still-active overlapping object lack this proof
-- and deliberately remain terminal. Unknown, purged and revoked tuples stay held.
-- These tables are locked by ALTER TABLE throughout this transaction.
CREATE TEMP TABLE kv_legacy_observed_absence ON COMMIT DROP AS
SELECT membership.organization_id, membership.source_object_id,
       membership.source_scope_id, membership.source_scope_revision,
       membership.removed_at AS missing_at, run.id AS missing_sync_run_id
FROM public.source_object_scope AS membership
JOIN public.source_object AS object
  ON object.organization_id = membership.organization_id AND object.id = membership.source_object_id
JOIN public.organization AS organization ON organization.id = object.organization_id AND organization.status = 'ACTIVE'
JOIN public.source_scope AS scope
  ON scope.organization_id = membership.organization_id AND scope.id = membership.source_scope_id
 AND scope.active_revision = membership.source_scope_revision
JOIN public.source_scope_revision AS revision
  ON revision.organization_id = scope.organization_id AND revision.source_scope_id = scope.id
 AND revision.revision = membership.source_scope_revision
JOIN public.source_scope_activation AS activation
  ON activation.organization_id = scope.organization_id AND activation.source_scope_id = scope.id
 AND activation.source_scope_revision = membership.source_scope_revision
 AND activation.revision = 1 AND activation.status = 'READY'
JOIN LATERAL (
    SELECT event.metadata_json, event.occurred_at
    FROM public.audit_event AS event
    WHERE event.organization_id = object.organization_id
      AND event.resource_type = 'SOURCE_OBJECT' AND event.resource_id = object.id
      AND event.action = 'source.object_deleted' AND event.actor_type = 'SYSTEM' AND event.outcome = 'SUCCESS'
    ORDER BY event.sequence DESC LIMIT 1
) AS deletion ON true
JOIN public.sync_run AS run
  ON run.organization_id = object.organization_id AND run.id = deletion.metadata_json ->> 'sync_run_id'
 AND run.job_id = deletion.metadata_json ->> 'connector_job_id'
 AND run.source_scope_id = membership.source_scope_id
 AND run.source_scope_revision = membership.source_scope_revision
 AND run.mode = 'FULL' AND run.status = 'SUCCEEDED' AND run.coverage_complete
 AND run.error_code IS NULL AND run.completed_at IS NOT NULL
JOIN public.job AS job ON job.organization_id = run.organization_id AND job.id = run.job_id
 AND job.type IN ('SOURCE_SCOPE_SYNC', 'POSTGRESQL_QUERY_SYNC')
 AND job.payload_json ->> 'source_scope_id' = membership.source_scope_id
WHERE object.lifecycle_state = 'DELETED' AND NOT object.queryable
  AND membership.membership_state = 'REMOVED'
  AND membership.removed_at >= run.started_at AND membership.removed_at <= run.completed_at
  AND deletion.occurred_at >= run.started_at AND deletion.occurred_at <= run.completed_at
  AND EXISTS (
      SELECT 1 FROM public.source_version AS version
      JOIN public.source_version_retention AS retention
        ON retention.organization_id = version.organization_id AND retention.source_version_id = version.id
      WHERE version.organization_id = object.organization_id AND version.id = object.current_version_id
        AND version.state = 'CURRENT' AND retention.state = 'ACTIVE'
        AND retention.queryable AND retention.extraction_allowed
  )
  AND NOT EXISTS (
      SELECT 1 FROM public.source_version AS version
      JOIN public.source_version_retention AS retention
        ON retention.organization_id = version.organization_id AND retention.source_version_id = version.id
      WHERE version.organization_id = object.organization_id AND version.source_object_id = object.id
        AND (retention.state <> 'ACTIVE' OR NOT retention.queryable OR NOT retention.extraction_allowed)
  )
  AND NOT EXISTS (
      SELECT 1 FROM public.source_object_scope AS other
      WHERE other.organization_id = object.organization_id AND other.source_object_id = object.id
        AND other.membership_state = 'ACTIVE'
  )
  AND EXISTS (
      SELECT 1 FROM public.workspace_revision_source AS binding
      JOIN public.workspace AS workspace
        ON workspace.organization_id = binding.organization_id AND workspace.id = binding.workspace_id
       AND workspace.current_revision = binding.workspace_revision
      JOIN public.workspace_managed_grant_confirmation AS confirmation
        ON confirmation.organization_id = binding.organization_id AND confirmation.workspace_id = binding.workspace_id
       AND confirmation.workspace_source_id = binding.workspace_source_id
       AND confirmation.source_scope_id = binding.source_scope_id
       AND confirmation.source_scope_revision = binding.source_scope_revision
       AND confirmation.scope_config_hash = binding.scope_config_hash
       AND confirmation.access_mode = binding.access_mode
       AND confirmation.policy_revision_number = organization.policy_revision
      JOIN public.workspace_managed_warning_contract AS warning
        ON warning.warning_version = confirmation.warning_version
       AND warning.warning_contract_hash = confirmation.warning_contract_hash
       AND warning.revision = app.workspace_managed_warning_contract_current_revision()
      WHERE binding.organization_id = membership.organization_id
        AND binding.source_scope_id = membership.source_scope_id
        AND binding.source_scope_revision = membership.source_scope_revision AND binding.enabled
        AND binding.access_mode = 'WORKSPACE_MANAGED'
        AND NOT EXISTS (
            SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
            WHERE revocation.organization_id = confirmation.organization_id AND revocation.confirmation_id = confirmation.confirmation_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS revocation
            WHERE revocation.organization_id = confirmation.organization_id AND revocation.grant_id = confirmation.confirmation_actor_grant_id
              AND revocation.grant_revision = confirmation.confirmation_actor_grant_revision
        )
  );

CREATE OR REPLACE FUNCTION app.source_object_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_object deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.object_type IS DISTINCT FROM OLD.object_type
       OR NEW.digest_key_version IS DISTINCT FROM OLD.digest_key_version
       OR NEW.external_object_id_digest IS DISTINCT FROM OLD.external_object_id_digest
       OR NEW.canonical_locator_digest IS DISTINCT FROM OLD.canonical_locator_digest
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'source_object identity is immutable' USING ERRCODE = '55000';
    END IF;
    -- Artifact bindings are one-time NULL -> value only.
    IF (OLD.external_object_id_artifact_id IS NOT NULL AND NEW.external_object_id_artifact_id IS DISTINCT FROM OLD.external_object_id_artifact_id)
       OR (OLD.canonical_locator_artifact_id IS NOT NULL AND NEW.canonical_locator_artifact_id IS DISTINCT FROM OLD.canonical_locator_artifact_id)
       OR (OLD.title_artifact_id IS NOT NULL AND NEW.title_artifact_id IS DISTINCT FROM OLD.title_artifact_id) THEN
        RAISE EXCEPTION 'source_object artifact bindings are write-once' USING ERRCODE = '55000';
    END IF;
    IF OLD.lifecycle_state = 'DELETED' AND NEW.lifecycle_state <> 'DELETED'
       AND NOT (NEW.lifecycle_state = 'MISSING' AND EXISTS (
           SELECT 1 FROM pg_temp.kv_legacy_observed_absence AS proof
           WHERE proof.organization_id = OLD.organization_id AND proof.source_object_id = OLD.id
       )) THEN
        RAISE EXCEPTION 'source_object lifecycle does not resurrect' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_object_scope_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_object_scope deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
       OR NEW.source_scope_id IS DISTINCT FROM OLD.source_scope_id
       OR NEW.source_scope_revision IS DISTINCT FROM OLD.source_scope_revision
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'source_object_scope identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.membership_state = 'REMOVED' AND NEW.membership_state <> 'REMOVED'
       AND NOT (NEW.membership_state = 'MISSING' AND EXISTS (
           SELECT 1 FROM pg_temp.kv_legacy_observed_absence AS proof
           WHERE proof.organization_id = OLD.organization_id AND proof.source_object_id = OLD.source_object_id
             AND proof.source_scope_id = OLD.source_scope_id AND proof.source_scope_revision = OLD.source_scope_revision
       )) THEN
        RAISE EXCEPTION 'source_object_scope membership does not un-remove' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- Only the classification above is admitted by these temporary guards.
-- Identity/artifact immutability stays enforced; no trigger is disabled.
UPDATE public.source_object_scope AS membership
SET membership_state = 'MISSING', missing_at = proof.missing_at,
    missing_sync_run_id = proof.missing_sync_run_id, removed_at = NULL
FROM pg_temp.kv_legacy_observed_absence AS proof
WHERE membership.organization_id = proof.organization_id
  AND membership.source_object_id = proof.source_object_id
  AND membership.source_scope_id = proof.source_scope_id
  AND membership.source_scope_revision = proof.source_scope_revision;
UPDATE public.source_object AS object
SET lifecycle_state = 'MISSING'
WHERE EXISTS (
    SELECT 1 FROM pg_temp.kv_legacy_observed_absence AS proof
    WHERE proof.organization_id = object.organization_id AND proof.source_object_id = object.id
);

-- The migration report contains counts only. Remaining terminal objects include
-- intentional closures and ambiguous legacy rows; they are not claimed safe to
-- restore. No source-native identifier or content is emitted.
DO $$
DECLARE classified bigint; terminal bigint;
BEGIN
    SELECT count(DISTINCT (organization_id, source_object_id)) INTO classified FROM pg_temp.kv_legacy_observed_absence;
    SELECT count(*) INTO terminal FROM public.source_object WHERE lifecycle_state = 'DELETED';
    RAISE NOTICE 'source presence compatibility: classified_missing_objects=%, retained_terminal_objects=%', classified, terminal;
END;
$$;

-- Restore terminal guards before the transaction can commit. Neither runtime
-- role can turn an unclassified DELETED/REMOVED row into MISSING or ACTIVE.
CREATE OR REPLACE FUNCTION app.source_object_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_object deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.object_type IS DISTINCT FROM OLD.object_type
       OR NEW.digest_key_version IS DISTINCT FROM OLD.digest_key_version
       OR NEW.external_object_id_digest IS DISTINCT FROM OLD.external_object_id_digest
       OR NEW.canonical_locator_digest IS DISTINCT FROM OLD.canonical_locator_digest
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'source_object identity is immutable' USING ERRCODE = '55000';
    END IF;
    -- Artifact bindings are one-time NULL -> value only.
    IF (OLD.external_object_id_artifact_id IS NOT NULL AND NEW.external_object_id_artifact_id IS DISTINCT FROM OLD.external_object_id_artifact_id)
       OR (OLD.canonical_locator_artifact_id IS NOT NULL AND NEW.canonical_locator_artifact_id IS DISTINCT FROM OLD.canonical_locator_artifact_id)
       OR (OLD.title_artifact_id IS NOT NULL AND NEW.title_artifact_id IS DISTINCT FROM OLD.title_artifact_id) THEN
        RAISE EXCEPTION 'source_object artifact bindings are write-once' USING ERRCODE = '55000';
    END IF;
    IF OLD.lifecycle_state = 'MISSING' AND NEW.lifecycle_state = 'ACTIVE'
       AND current_user <> pg_catalog.pg_get_userbyid((SELECT proowner FROM pg_catalog.pg_proc WHERE oid = 'app.source_object_observation_publish(text,text,bigint,text,text,text,text,bigint)'::regprocedure)) THEN
        RAISE EXCEPTION 'source presence restoration requires fenced publication' USING ERRCODE = '42501';
    END IF;
    IF OLD.lifecycle_state = 'DELETED' AND NEW.lifecycle_state <> 'DELETED' THEN
        RAISE EXCEPTION 'source_object lifecycle does not resurrect' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_object_scope_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_object_scope deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
       OR NEW.source_scope_id IS DISTINCT FROM OLD.source_scope_id
       OR NEW.source_scope_revision IS DISTINCT FROM OLD.source_scope_revision
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'source_object_scope identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.membership_state = 'MISSING' AND NEW.membership_state <> 'MISSING' AND NEW.membership_state <> 'REMOVED'
       AND current_user <> pg_catalog.pg_get_userbyid((SELECT proowner FROM pg_catalog.pg_proc WHERE oid = 'app.source_object_observation_publish(text,text,bigint,text,text,text,text,bigint)'::regprocedure)) THEN
        RAISE EXCEPTION 'source membership restoration requires fenced publication' USING ERRCODE = '42501';
    END IF;
    IF OLD.membership_state = 'REMOVED' AND NEW.membership_state <> 'REMOVED' THEN
        RAISE EXCEPTION 'source_object_scope membership does not un-remove' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- A successful immutable extraction is necessary but not sufficient to return
-- absent content: authority and retention are rechecked at this publication.
-- The caller invokes this only after its actual observed read/extraction, in the
-- same object/snapshot transaction; subsequent failure rolls restoration back.
CREATE OR REPLACE FUNCTION app.source_object_observation_publish(
    p_object_id text, p_scope_id text, p_revision bigint, p_version_id text,
    p_sync_run_id text, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS TABLE(object_restored boolean, membership_restored boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    object_state text;
    membership_status text;
    config_hash text;
    fence bigint;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);
    PERFORM app.assert_scope_revision_syncing(p_scope_id, p_revision);
    SELECT object.lifecycle_state, membership.membership_state
      INTO object_state, membership_status
      FROM public.source_object AS object
      JOIN public.source_object_scope AS membership
        ON membership.organization_id = object.organization_id AND membership.source_object_id = object.id
     WHERE object.organization_id = org AND object.id = p_object_id
       AND membership.source_scope_id = p_scope_id AND membership.source_scope_revision = p_revision
     FOR UPDATE OF object, membership;
    IF NOT FOUND OR object_state = 'DELETED' OR membership_status NOT IN ('ACTIVE', 'MISSING') THEN
        RAISE EXCEPTION 'terminal source closure cannot be restored by an observation' USING ERRCODE = '55000';
    END IF;
    IF object_state <> 'MISSING' AND membership_status <> 'MISSING' THEN
        RETURN QUERY SELECT false, false;
        RETURN;
    END IF;
    SELECT revision.scope_config_hash INTO config_hash
      FROM public.source_scope_revision AS revision
      JOIN public.sync_run AS run
        ON run.organization_id = revision.organization_id AND run.source_scope_id = revision.source_scope_id
       AND run.source_scope_revision = revision.revision
     WHERE revision.organization_id = org AND revision.source_scope_id = p_scope_id AND revision.revision = p_revision
       AND run.id = p_sync_run_id AND run.job_id = p_job_id AND run.status = 'RUNNING';
    IF NOT FOUND OR NOT app.source_scope_activation_confirmed(p_scope_id, p_revision, config_hash) THEN
        RAISE EXCEPTION 'source presence publication requires live scope authority' USING ERRCODE = '55000';
    END IF;
    SELECT retention.retention_fence INTO fence
      FROM public.source_object AS object
      JOIN public.source_version AS version
        ON version.organization_id = object.organization_id AND version.source_object_id = object.id
       AND version.id = object.current_version_id AND version.id = p_version_id AND version.state = 'CURRENT'
      JOIN public.source_version_retention AS retention
        ON retention.organization_id = version.organization_id AND retention.source_version_id = version.id
      JOIN public.source_version_active_extraction AS active
        ON active.organization_id = version.organization_id AND active.source_version_id = version.id
      JOIN public.source_extraction AS extraction
        ON extraction.organization_id = version.organization_id AND extraction.id = active.extraction_id
       AND extraction.source_version_id = version.id AND extraction.status = 'SUCCEEDED'
      JOIN public.source_extraction_retention AS extraction_retention
        ON extraction_retention.organization_id = extraction.organization_id AND extraction_retention.extraction_id = extraction.id
       AND extraction_retention.state = 'ACTIVE' AND extraction_retention.queryable
     WHERE object.organization_id = org AND object.id = p_object_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source presence publication requires a readable current extraction' USING ERRCODE = '55000';
    END IF;
    PERFORM app.assert_version_writable(p_version_id, fence);
    UPDATE public.source_object_scope
       SET membership_state = 'ACTIVE', missing_at = NULL, missing_sync_run_id = NULL, last_seen_at = now()
     WHERE organization_id = org AND source_object_id = p_object_id
       AND source_scope_id = p_scope_id AND source_scope_revision = p_revision AND membership_state = 'MISSING';
    UPDATE public.source_object
       SET lifecycle_state = 'ACTIVE', queryable = true, last_seen_at = now()
     WHERE organization_id = org AND id = p_object_id AND lifecycle_state IN ('ACTIVE', 'MISSING');
    RETURN QUERY SELECT object_state = 'MISSING', membership_status = 'MISSING';
END;
$$;

REVOKE ALL ON FUNCTION app.source_object_observation_publish(text, text, bigint, text, text, text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_object_observation_publish(text, text, bigint, text, text, text, text, bigint) TO knowvault_worker;

-- Close MISSING memberships terminally on revision cutover too. Another scope
-- still holding MISSING keeps the object recoverable only through that scope.
CREATE OR REPLACE FUNCTION app.source_scope_activate_revision(
    p_scope_id text, p_new_revision bigint, p_coverage_run_id text,
    p_job_id text, p_worker text, p_epoch bigint
)
RETURNS TABLE(outcome text, closed_object_id text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    prior bigint;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);

    -- Serialize the whole cutover on the scope row: two activations of one scope
    -- cannot interleave their authority transitions.
    SELECT active_revision INTO prior FROM public.source_scope
     WHERE organization_id = org AND id = p_scope_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source scope not found' USING ERRCODE = 'P0002';
    END IF;

    -- Scan-safety containment (ADR-0061 §4): the candidate may only become
    -- authoritative on the strength of its own complete, non-empty FULL scan.
    PERFORM 1 FROM public.sync_run
     WHERE organization_id = org AND id = p_coverage_run_id
       AND source_scope_id = p_scope_id AND source_scope_revision = p_new_revision
       AND mode = 'FULL' AND status = 'SUCCEEDED' AND coverage_complete;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope activation requires a complete coverage run for the candidate revision' USING ERRCODE = '55000';
    END IF;

    -- Stale candidate: a newer revision is already authoritative. Authority never
    -- moves backward, so this candidate is refused — neither published nor allowed
    -- to supersede the newer revision — and held FAILED. Without this a reordered
    -- retry of an older revision would REVOKE and mass-delete the newer one.
    IF prior IS NOT NULL AND p_new_revision < prior THEN
        UPDATE public.source_scope_activation
           SET status = 'FAILED', changed_at = now(), activated_at = now()
         WHERE organization_id = org AND source_scope_id = p_scope_id
           AND source_scope_revision = p_new_revision AND revision = 1
           AND status = 'SYNCING';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'candidate scope activation is not SYNCING' USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT 'HELD'::text, NULL::text;
        RETURN;
    END IF;

    -- Advance the candidate activation SYNCING -> READY (the activation guard
    -- rejects any other origin state).
    UPDATE public.source_scope_activation
       SET status = 'READY', changed_at = now(), activated_at = now()
     WHERE organization_id = org AND source_scope_id = p_scope_id
       AND source_scope_revision = p_new_revision AND revision = 1
       AND status = 'SYNCING';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'candidate scope activation is not SYNCING' USING ERRCODE = '55000';
    END IF;

    -- Advance authority forward-only (source_scope_parent_guard enforces
    -- monotonicity and exact-revision resolution).
    UPDATE public.source_scope
       SET active_revision = p_new_revision
     WHERE organization_id = org AND id = p_scope_id
       AND (active_revision IS NULL OR active_revision <= p_new_revision);

    -- First activation (no prior) or a re-sync of the current active revision:
    -- nothing older to supersede.
    IF prior IS NULL THEN
        RETURN QUERY SELECT 'ACTIVATED'::text, NULL::text;
        RETURN;
    END IF;
    IF prior = p_new_revision THEN
        RETURN QUERY SELECT 'RESYNC'::text, NULL::text;
        RETURN;
    END IF;

    -- Genuine forward cutover (prior < p_new_revision). Supersede EVERY older
    -- revision of this scope: revoke their live activations (REVOKED is terminal
    -- and fences any still-running older-revision worker through
    -- assert_scope_revision_syncing) and close their ACTIVE memberships. Newer
    -- in-flight revisions (> candidate) are untouched.
    UPDATE public.source_scope_activation
       SET status = 'REVOKED', changed_at = now(), activated_at = now()
     WHERE organization_id = org AND source_scope_id = p_scope_id
       AND source_scope_revision < p_new_revision AND revision = 1
       AND status IN ('READY', 'SYNCING');

    UPDATE public.source_object_scope
       SET membership_state = 'REMOVED', removed_at = now(), missing_at = NULL, missing_sync_run_id = NULL
     WHERE organization_id = org AND source_scope_id = p_scope_id
       AND source_scope_revision < p_new_revision AND membership_state IN ('ACTIVE', 'MISSING');

    -- Close every object this cutover just removed an older membership from that now
    -- holds zero ACTIVE membership across every scope and revision: a proven
    -- SOURCE_OBJECT_DELETED. An object still ACTIVE under the new revision or an
    -- overlapping different scope survives (VER-005). The plpgsql command-counter
    -- increment makes the closure see the REMOVED rows above.
    RETURN QUERY SELECT 'CUTOVER'::text, NULL::text;
    RETURN QUERY
    UPDATE public.source_object AS o
       SET lifecycle_state = CASE WHEN EXISTS (
           SELECT 1 FROM public.source_object_scope AS remaining
           WHERE remaining.organization_id = o.organization_id AND remaining.source_object_id = o.id
             AND remaining.membership_state = 'MISSING'
       ) THEN 'MISSING' ELSE 'DELETED' END, queryable = false, last_seen_at = now()
     WHERE o.organization_id = org AND o.lifecycle_state IN ('ACTIVE', 'MISSING')
       AND (o.lifecycle_state = 'ACTIVE' OR NOT EXISTS (
           SELECT 1 FROM public.source_object_scope AS remaining
           WHERE remaining.organization_id = o.organization_id AND remaining.source_object_id = o.id
             AND remaining.membership_state = 'MISSING'
       ))
       AND EXISTS (SELECT 1 FROM public.source_object_scope AS r
                   WHERE r.organization_id = o.organization_id AND r.source_object_id = o.id
                     AND r.source_scope_id = p_scope_id AND r.source_scope_revision < p_new_revision
                     AND r.membership_state = 'REMOVED')
       AND NOT EXISTS (SELECT 1 FROM public.source_object_scope AS m
                       WHERE m.organization_id = o.organization_id AND m.source_object_id = o.id
                         AND m.membership_state = 'ACTIVE')
    RETURNING 'CUTOVER'::text, o.id;
END;
$$;

-- Publishing a new immutable version does not reopen observed absence. Its
-- bytes become readable only through the subsequent authority-fenced presence
-- publication in the same transaction. All extraction/retention guards remain.
CREATE OR REPLACE FUNCTION app.source_version_publish_extraction(
    p_version_id text, p_extraction_id text, p_expected_evidence_set_hash text,
    p_make_current boolean, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    extraction record;
    object_id text;
    fragment_count bigint;
    ordinal_min bigint;
    ordinal_max bigint;
    ordinal_distinct bigint;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);

    SELECT * INTO extraction FROM public.source_extraction
     WHERE organization_id = org AND id = p_extraction_id AND source_version_id = p_version_id;
    IF NOT FOUND OR extraction.status <> 'SUCCEEDED' THEN
        RAISE EXCEPTION 'publication requires a SUCCEEDED extraction of the version' USING ERRCODE = '23514';
    END IF;
    IF extraction.evidence_set_hash IS DISTINCT FROM p_expected_evidence_set_hash THEN
        RAISE EXCEPTION 'evidence_set_hash mismatch at publication' USING ERRCODE = '23514';
    END IF;

    PERFORM app.assert_version_writable(p_version_id, extraction.retention_fence_at_start);

    IF NOT EXISTS (SELECT 1 FROM public.source_extraction_retention
                   WHERE organization_id = org AND extraction_id = p_extraction_id
                     AND state = 'ACTIVE' AND queryable) THEN
        RAISE EXCEPTION 'publication requires ACTIVE queryable extraction retention' USING ERRCODE = '23514';
    END IF;

    -- Ordinal set must be closed, unique and gap-free (1..N).
    SELECT count(*), min(ordinal), max(ordinal), count(DISTINCT ordinal)
      INTO fragment_count, ordinal_min, ordinal_max, ordinal_distinct
      FROM public.evidence_fragment
     WHERE organization_id = org AND extraction_id = p_extraction_id;
    IF fragment_count = 0 OR ordinal_min <> 1 OR ordinal_max <> fragment_count OR ordinal_distinct <> fragment_count THEN
        RAISE EXCEPTION 'evidence ordinal set is not closed' USING ERRCODE = '23514';
    END IF;

    INSERT INTO public.source_version_active_extraction
        (organization_id, source_version_id, extraction_id, activation_revision, activated_at)
    VALUES (org, p_version_id, p_extraction_id, 1, now())
    ON CONFLICT (organization_id, source_version_id) DO UPDATE
        SET extraction_id = EXCLUDED.extraction_id,
            activation_revision = public.source_version_active_extraction.activation_revision + 1,
            activated_at = now();

    -- The current-version cutover is part of the same lease-fenced transaction,
    -- not a separate raw UPDATE: a stale worker can never make a version current
    -- or flip queryability. Only invoked for a newly created version; re-extraction
    -- of an already-current version leaves the version state untouched.
    IF p_make_current THEN
        SELECT source_object_id INTO object_id FROM public.source_version
         WHERE organization_id = org AND id = p_version_id;
        UPDATE public.source_version SET state = 'SUPERSEDED', superseded_at = now()
         WHERE organization_id = org AND source_object_id = object_id AND state = 'CURRENT' AND id <> p_version_id;
        UPDATE public.source_version SET state = 'CURRENT'
         WHERE organization_id = org AND id = p_version_id AND state = 'PENDING';
        UPDATE public.source_object SET current_version_id = p_version_id, queryable = (lifecycle_state = 'ACTIVE'), last_seen_at = now()
         WHERE organization_id = org AND id = object_id;
    END IF;
END;
$$;

-- A returned membership must refresh the scope projection even when its immutable
-- chunks already exist. The caller emits these new sequences in the presence TX.
CREATE OR REPLACE FUNCTION app.enqueue_search_chunk_reobservation(p_chunk_id text, p_event_id text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    assigned_sequence bigint;
    existing_sequence bigint;
    existing_type text;
    existing_aggregate text;
    existing_event_type text;
    chunk_version text;
    chunk_extraction text;
    chunk_hash text;
    text_artifact_id text;
    profile_hash text;
    model_hash text;
    dimension integer;
    payload jsonb;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'search chunk outbox requires worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL OR NOT app.source_generated_id_is_valid(p_chunk_id, 'chunk')
       OR NOT app.source_generated_id_is_valid(p_event_id, 'searchupd') THEN
        RAISE EXCEPTION 'search chunk outbox requires worker tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT event.sequence, event.aggregate_type, event.aggregate_id, event.event_type
      INTO existing_sequence, existing_type, existing_aggregate, existing_event_type
      FROM public.outbox_event event
     WHERE event.organization_id = organization_value AND event.id = p_event_id;
    IF FOUND THEN
        IF existing_type <> 'SEARCH_CHUNK'
           OR existing_aggregate <> p_chunk_id
           OR existing_event_type <> 'search.chunk.upsert' THEN
            RAISE EXCEPTION 'search chunk outbox id is already used by another event' USING ERRCODE = '23505';
        END IF;
        RETURN existing_sequence;
    END IF;

    SELECT chunk.source_version_id, chunk.extraction_id, chunk.chunk_hash,
           chunk.search_text_artifact_id, chunk.embedding_profile_hash,
           chunk.embedding_model_artifact_hash, chunk.embedding_dimension
      INTO chunk_version, chunk_extraction, chunk_hash, text_artifact_id,
           profile_hash, model_hash, dimension
      FROM public.search_chunk chunk
     WHERE chunk.organization_id = organization_value
       AND chunk.id = p_chunk_id
       AND chunk.search_text_artifact_id IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search chunk outbox requires a bound text artifact' USING ERRCODE = '23514';
    END IF;
    IF chunk_version IS NULL OR chunk_extraction IS NULL OR chunk_hash IS NULL
       OR text_artifact_id IS NULL THEN
        RAISE EXCEPTION 'search chunk outbox has a null required reference' USING ERRCODE = '23514';
    END IF;
    IF (profile_hash IS NULL) <> (model_hash IS NULL)
       OR (profile_hash IS NULL) <> (dimension IS NULL) THEN
        RAISE EXCEPTION 'search chunk embedding tuple is incomplete' USING ERRCODE = '23514';
    END IF;

    PERFORM 1
      FROM public.organization
     WHERE id = organization_value AND status = 'ACTIVE'
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search chunk outbox requires an active tenant' USING ERRCODE = '55000';
    END IF;

    INSERT INTO public.outbox_sequence_head (organization_id)
    VALUES (organization_value)
    ON CONFLICT (organization_id) DO NOTHING;

    UPDATE public.outbox_sequence_head
       SET last_assigned_sequence = last_assigned_sequence + 1,
           updated_at = transaction_timestamp()
     WHERE organization_id = organization_value
       AND last_assigned_sequence < 9007199254740991
    RETURNING last_assigned_sequence INTO assigned_sequence;
    IF assigned_sequence IS NULL THEN
        RAISE EXCEPTION 'outbox sequence exhausted' USING ERRCODE = '54000';
    END IF;

    payload := jsonb_build_object(
        'operation', 'UPSERT',
        'search_chunk_id', p_chunk_id,
        'source_version_id', chunk_version,
        'extraction_id', chunk_extraction,
        'artifact_id', text_artifact_id,
        'text_hash', chunk_hash
    );
    IF profile_hash IS NOT NULL THEN
        payload := payload || jsonb_build_object(
            'embedding_profile_hash', profile_hash,
            'embedding_model_artifact_hash', model_hash,
            'dimension', dimension
        );
    END IF;

    INSERT INTO public.outbox_event (
        organization_id, id, sequence, aggregate_type, aggregate_id,
        event_type, payload_json, created_at, published_at
    ) VALUES (
        organization_value, p_event_id, assigned_sequence, 'SEARCH_CHUNK', p_chunk_id,
        'search.chunk.upsert', payload, transaction_timestamp(), NULL
    );
    RETURN assigned_sequence;
END;
$$;

REVOKE ALL ON FUNCTION app.enqueue_search_chunk_reobservation(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.enqueue_search_chunk_reobservation(text, text) TO knowvault_worker;

COMMIT;
