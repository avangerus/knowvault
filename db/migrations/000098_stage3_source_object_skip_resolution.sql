-- A successful per-object retry can resolve a prior skip even when another
-- subtree leaves the overall FULL scan partial. Store only such recoveries,
-- not one observation per healthy object per sync. Original skips and their
-- sealed identities stay unchanged. A RUNNING/FAILED resolving run never
-- clears inventory state; a later successful retry can append its own fact.
BEGIN;

CREATE TABLE public.source_object_skip_resolution (
    organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL,
    external_id_digest text NOT NULL,
    digest_key_version bigint NOT NULL,
    skipped_sync_run_id text NOT NULL,
    resolving_sync_run_id text NOT NULL,
    source_object_id text NOT NULL,
    resolved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CHECK (app.source_keyed_digest_matches_version(external_id_digest, digest_key_version)),
    CHECK (skipped_sync_run_id <> resolving_sync_run_id),
    PRIMARY KEY (organization_id, source_scope_id, source_scope_revision,
                 external_id_digest, skipped_sync_run_id, resolving_sync_run_id),
    FOREIGN KEY (organization_id, skipped_sync_run_id, source_scope_id,
                 source_scope_revision, external_id_digest)
        REFERENCES public.source_object_skip
            (organization_id, sync_run_id, source_scope_id, source_scope_revision, external_id_digest)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, resolving_sync_run_id)
        REFERENCES public.sync_run (organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, source_object_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_object_scope
            (organization_id, source_object_id, source_scope_id, source_scope_revision)
        ON DELETE RESTRICT
);

ALTER TABLE public.source_object_skip_resolution ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_object_skip_resolution FORCE ROW LEVEL SECURITY;
CREATE POLICY source_object_skip_resolution_tenant_isolation
    ON public.source_object_skip_resolution
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());
REVOKE ALL ON public.source_object_skip_resolution FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT ON public.source_object_skip_resolution TO knowvault_app;
GRANT SELECT, INSERT ON public.source_object_skip_resolution TO knowvault_worker;

-- The worker already holds the job lease and scope activation fence in the
-- object publication transaction. This guard also prevents attribution to an
-- unrelated run/scope/object or a run that completed before the prior skip.
CREATE FUNCTION app.source_object_skip_resolution_insert_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM app.current_organization_id()
       OR NEW.resolved_at IS DISTINCT FROM transaction_timestamp()
       OR NOT EXISTS (
           SELECT 1
           FROM public.sync_run resolving
           JOIN public.sync_run skipped
             ON skipped.organization_id = resolving.organization_id
            AND skipped.id = NEW.skipped_sync_run_id
            AND skipped.source_scope_id = resolving.source_scope_id
            AND skipped.source_scope_revision = resolving.source_scope_revision
            AND skipped.status = 'SUCCEEDED'
            AND skipped.completed_at <= resolving.started_at
           JOIN public.source_object_scope membership
             ON membership.organization_id = resolving.organization_id
            AND membership.source_object_id = NEW.source_object_id
            AND membership.source_scope_id = resolving.source_scope_id
            AND membership.source_scope_revision = resolving.source_scope_revision
            AND membership.membership_state = 'ACTIVE'
            AND membership.last_seen_at = transaction_timestamp()
           WHERE resolving.organization_id = NEW.organization_id
             AND resolving.id = NEW.resolving_sync_run_id
             AND resolving.source_scope_id = NEW.source_scope_id
             AND resolving.source_scope_revision = NEW.source_scope_revision
             AND resolving.status = 'RUNNING'
       ) THEN
        RAISE EXCEPTION 'skip resolution requires this transaction''s live object observation'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION app.source_object_skip_resolution_insert_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_object_skip_resolution_insert_guard() TO knowvault_worker;
CREATE TRIGGER source_object_skip_resolution_insert_guard
    BEFORE INSERT ON public.source_object_skip_resolution
    FOR EACH ROW EXECUTE FUNCTION app.source_object_skip_resolution_insert_guard();
CREATE TRIGGER source_object_skip_resolution_immutable
    BEFORE UPDATE OR DELETE ON public.source_object_skip_resolution
    FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

-- Shared tenant-fenced owner projection. The application has no direct SELECT
-- on sync_run; do not widen that grant just to determine the skip state. This
-- branch exposes only the same typed skip columns it could already read, and
-- the viewer still applies its exact workspace confirmation gates.
CREATE FUNCTION app.source_object_current_skips()
RETURNS TABLE (organization_id text, sync_run_id text, source_scope_id text,
    source_scope_revision bigint, external_id_digest text, digest_key_version bigint,
    external_id_artifact_id text, reason_code text, observed_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
SELECT s.organization_id, s.sync_run_id, s.source_scope_id, s.source_scope_revision,
       s.external_id_digest, s.digest_key_version, s.external_id_artifact_id,
       s.reason_code, s.observed_at
FROM public.source_object_skip s
JOIN public.sync_run observed
  ON observed.organization_id = s.organization_id AND observed.id = s.sync_run_id
 AND observed.source_scope_id = s.source_scope_id
 AND observed.source_scope_revision = s.source_scope_revision
 AND observed.status = 'SUCCEEDED'
WHERE s.organization_id = app.current_organization_id()
AND NOT EXISTS (
    SELECT 1 FROM public.sync_run complete
    WHERE complete.organization_id = s.organization_id
      AND complete.source_scope_id = s.source_scope_id
      AND complete.source_scope_revision = s.source_scope_revision
      AND complete.mode = 'FULL' AND complete.status = 'SUCCEEDED' AND complete.coverage_complete
      AND (complete.completed_at, complete.id) > (observed.completed_at, observed.id)
)
AND NOT EXISTS (
    SELECT 1
    FROM public.source_object_skip_resolution resolution
    JOIN public.sync_run through_run
      ON through_run.organization_id = resolution.organization_id
     AND through_run.id = resolution.skipped_sync_run_id
    JOIN public.sync_run resolved_run
      ON resolved_run.organization_id = resolution.organization_id
     AND resolved_run.id = resolution.resolving_sync_run_id
     AND resolved_run.status = 'SUCCEEDED'
    WHERE resolution.organization_id = s.organization_id
      AND resolution.source_scope_id = s.source_scope_id
      AND resolution.source_scope_revision = s.source_scope_revision
      AND resolution.external_id_digest = s.external_id_digest
      AND (through_run.completed_at, through_run.id) >= (observed.completed_at, observed.id)
);
$fn$;
REVOKE ALL ON FUNCTION app.source_object_current_skips() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_object_current_skips() TO knowvault_app, knowvault_worker;

-- Recovery facts contain no new content or identity artifacts. Like the skip
-- ledger and SourceObject metadata they survive source-version content purge;
-- they cannot make that version queryable. The FKs require any future tenant
-- hard-delete owner to remove these facts before their skips/memberships.
-- This repository currently implements version/conversation content purge,
-- not an operator for physical tenant deletion; no automatic cleanup is
-- claimed here. Runtime roles cannot erase or rewrite recovery facts.
COMMIT;
