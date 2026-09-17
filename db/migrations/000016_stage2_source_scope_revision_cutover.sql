-- Stage 2 / P2 / I2: source scope-revision cutover lifecycle (ADR-0061).
--
-- Closes the ADR-0059 §1 known risk: the scope-activation path never superseded
-- a prior revision's memberships, so a scope that moved to a new revision left
-- the old revision's source_object_scope rows ACTIVE and its activation
-- authoritative. This migration adds the atomic, audited authority transition and
-- the two fences that make it safe:
--
--  * app.assert_scope_revision_syncing — every derived write the sync worker
--    performs re-asserts, under FOR UPDATE, that its candidate revision's
--    activation is still SYNCING. A concurrent cutover that REVOKES a superseded
--    revision serializes on that row, so a superseded worker's whole transaction
--    rolls back (ADR-0061 §3, charter fencing).
--  * app.source_scope_activate_revision — one lease-fenced transaction that
--    advances the candidate activation SYNCING -> READY, moves
--    source_scope.active_revision forward, and (only when a distinct prior
--    authoritative revision exists) supersedes it: REVOKED activation, ACTIVE ->
--    REMOVED memberships of exactly the prior revision, and a proven
--    SOURCE_OBJECT_DELETED for every object that thereby holds zero ACTIVE
--    membership anywhere (ADR-0061 §1–§2, DATA_MODEL.md §3–§4, VER-005).
--  * sync_run.coverage_complete — the independent DB containment for scan safety
--    (ADR-0061 §4): the worker records complete non-empty FULL coverage on the
--    run, and activate_revision refuses the transition unless the caller passes a
--    SUCCEEDED FULL coverage run of the candidate revision with the flag set. A
--    partial/empty/foreign run cannot drive supersession, so narrowing a scope
--    can never mass-delete the old objects before the new revision proved full
--    coverage.
--
-- No immutable source_scope_revision row is rewritten; authority lives only in
-- the monotonic activation projection and the active_revision pointer (ADR-0047).
-- The transition's audit (source.scope_activated + per-object source.object_deleted)
-- is appended by the Go orchestrator in the same transaction (AUD-005); this
-- migration introduces no new resource_type and no new dependency.

BEGIN;

-- Independent DB containment for scan safety (ADR-0061 §4). Defaults false so
-- every historical run is treated as non-authoritative for a cutover.
ALTER TABLE public.sync_run
    ADD COLUMN coverage_complete boolean NOT NULL DEFAULT false;

-- Binds a derived worker write to its candidate revision's live SYNCING
-- authority. Mirrors app.lock_job_lease / app.assert_version_writable: it locks
-- the activation row FOR UPDATE so a concurrent cutover REVOKE serializes against
-- it, and raises 55000 if the revision is no longer SYNCING. A superseded
-- revision's worker therefore cannot create a membership, version, extraction or
-- evidence, delete an object, or alter the new revision's sync health.
CREATE OR REPLACE FUNCTION app.assert_scope_revision_syncing(p_scope_id text, p_revision bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM 1 FROM public.source_scope_activation
    WHERE organization_id = app.current_organization_id()
      AND source_scope_id = p_scope_id
      AND source_scope_revision = p_revision
      AND revision = 1
      AND status = 'SYNCING'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope revision is not authoritative for derived writes' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- Forward-only begin-sync fence (ADR-0061 §3/§5). Replaces the 000014 begin_sync
-- with one added guard: a worker may not begin a sync for a revision older than
-- the current authoritative one. Without it a reordered stale worker (whose
-- activation was still DRAFT when a newer revision cut over, so the cutover's
-- REVOKE of READY/SYNCING activations did not touch it) could drive DRAFT->SYNCING
-- and commit ACTIVE memberships at the stale revision — which sit AT that revision,
-- not below a future candidate's `< candidate` sweep, so they would linger as a
-- stray membership. The scope row is locked FOR UPDATE so this serializes against
-- app.source_scope_activate_revision / publish_partial, closing the read/advance
-- race. Every other begin_sync rule is carried unchanged.
CREATE OR REPLACE FUNCTION app.source_scope_begin_sync(
    p_scope_id text, p_revision bigint, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    target record;
    current_active bigint;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);
    SELECT * INTO target FROM app.source_scope_sync_target(p_scope_id, p_revision);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope revision not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT target.trust_verified THEN
        RAISE EXCEPTION 'scope activation requires VERIFIED connection trust' USING ERRCODE = '42501';
    END IF;
    SELECT active_revision INTO current_active FROM public.source_scope
     WHERE organization_id = app.current_organization_id() AND id = p_scope_id
     FOR UPDATE;
    IF current_active IS NOT NULL AND current_active > p_revision THEN
        RAISE EXCEPTION 'scope revision is older than the active revision' USING ERRCODE = '55000';
    END IF;
    UPDATE public.source_scope_activation
       SET status = 'SYNCING', changed_at = now(), activated_at = NULL
     WHERE organization_id = app.current_organization_id()
       AND source_scope_id = p_scope_id AND source_scope_revision = p_revision AND revision = 1
       AND status IN ('DRAFT', 'READY', 'FAILED', 'SYNCING');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope activation cannot begin sync from its current state' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- The atomic, audited authority transition (ADR-0061 §1–§2). One lease-fenced
-- transaction. It returns a typed outcome plus, for a cutover, the ids of the
-- objects it closed, so the caller audits the exact transition it performed in the
-- same transaction (AUD-005): the first row's `outcome` is the classification
-- ('ACTIVATED' first activation, 'RESYNC' re-sync of the current active revision,
-- 'CUTOVER' supersession of one or more older revisions, 'HELD' a stale candidate
-- that was refused), and every row whose `closed_object_id` is non-null is a
-- SOURCE_OBJECT_DELETED closure.
--
-- Authority only ever moves forward. A candidate strictly older than the current
-- active revision (a stale worker whose job was reordered behind a newer revision
-- that already became authoritative) is REFUSED — it is neither published nor
-- allowed to supersede the newer revision; it is held FAILED. A cutover supersedes
-- EVERY revision older than the candidate (not only the immediately-prior active),
-- so a stray ACTIVE membership left by an abandoned partial/failed intermediate
-- revision cannot keep a gone object open against object closure and purge.
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
       SET membership_state = 'REMOVED', removed_at = now()
     WHERE organization_id = org AND source_scope_id = p_scope_id
       AND source_scope_revision < p_new_revision AND membership_state = 'ACTIVE';

    -- Close every object this cutover just removed an older membership from that now
    -- holds zero ACTIVE membership across every scope and revision: a proven
    -- SOURCE_OBJECT_DELETED. An object still ACTIVE under the new revision or an
    -- overlapping different scope survives (VER-005). The plpgsql command-counter
    -- increment makes the closure see the REMOVED rows above.
    RETURN QUERY SELECT 'CUTOVER'::text, NULL::text;
    RETURN QUERY
    UPDATE public.source_object AS o
       SET lifecycle_state = 'DELETED', queryable = false, last_seen_at = now()
     WHERE o.organization_id = org AND o.lifecycle_state = 'ACTIVE'
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

-- The incomplete-coverage finalize (ADR-0061 §4). A candidate whose FULL scan was
-- not authoritative and complete must never supersede a distinct prior revision
-- (that would mass-delete objects the partial scan simply did not observe). This
-- function reads the prior authority under the scope-row lock and:
--   * first activation (no prior) or a re-sync of the current active revision —
--     publishes READY and advances active_revision, exactly the S1e partial
--     behaviour, and returns held=false;
--   * a distinct prior revision — holds: it marks the candidate activation FAILED,
--     leaves the prior revision authoritative and active_revision unchanged, and
--     returns held=true.
CREATE OR REPLACE FUNCTION app.source_scope_publish_partial(
    p_scope_id text, p_revision bigint, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    prior bigint;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);
    SELECT active_revision INTO prior FROM public.source_scope
     WHERE organization_id = app.current_organization_id() AND id = p_scope_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source scope not found' USING ERRCODE = 'P0002';
    END IF;

    IF prior IS NOT NULL AND prior <> p_revision THEN
        -- Hold: never cut over on partial coverage.
        UPDATE public.source_scope_activation
           SET status = 'FAILED', changed_at = now(), activated_at = now()
         WHERE organization_id = app.current_organization_id() AND source_scope_id = p_scope_id
           AND source_scope_revision = p_revision AND revision = 1
           AND status = 'SYNCING';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'candidate scope activation is not SYNCING' USING ERRCODE = '55000';
        END IF;
        RETURN true;
    END IF;

    -- No distinct prior: publish READY and advance authority, exactly as S1e did
    -- on a partial first activation / re-sync of the current active revision.
    UPDATE public.source_scope_activation
       SET status = 'READY', changed_at = now(), activated_at = now()
     WHERE organization_id = app.current_organization_id() AND source_scope_id = p_scope_id
       AND source_scope_revision = p_revision AND revision = 1
       AND status = 'SYNCING';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'candidate scope activation is not SYNCING' USING ERRCODE = '55000';
    END IF;
    UPDATE public.source_scope
       SET active_revision = p_revision
     WHERE organization_id = app.current_organization_id() AND id = p_scope_id
       AND (active_revision IS NULL OR active_revision <= p_revision);
    RETURN false;
END;
$$;

-- The cutover primitives are a worker capability only. CREATE FUNCTION grants
-- EXECUTE to PUBLIC by default, so — like every peer SECURITY DEFINER function
-- (000014, 000015) — the default grant is revoked first and re-granted only to
-- knowvault_worker. Without this the web/API role (knowvault_app), which holds
-- USAGE ON SCHEMA app, could invoke the mass-delete cutover primitive.
REVOKE ALL ON FUNCTION
    app.assert_scope_revision_syncing(text, bigint),
    app.source_scope_activate_revision(text, bigint, text, text, text, bigint),
    app.source_scope_publish_partial(text, bigint, text, text, bigint)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.assert_scope_revision_syncing(text, bigint),
    app.source_scope_activate_revision(text, bigint, text, text, text, bigint),
    app.source_scope_publish_partial(text, bigint, text, text, bigint)
TO knowvault_worker;

COMMIT;
