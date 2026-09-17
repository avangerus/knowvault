-- Stage 2 / P2 / I1 / S1e: source-derived retention purge state machine.
--
-- Purge makes source-derived content inaccessible first and forgets the bytes
-- later, and never lets a stale worker, job or index resurrect it. It is a
-- privileged control-plane operation: the three functions below are SECURITY
-- DEFINER, revoked from PUBLIC and granted only to knowvault_purger, so neither
-- the web/API runtime (knowvault_app) nor the sync worker (knowvault_worker) can
-- purge. Knowledge of an id is not authority; the caller must be the trusted
-- purger role and must pass the exact tenant, version and observed fence.
--
-- The single-transaction fail-close (begin_purge) advances the retention fence
-- first, closes queryability of the version and every one of its extractions,
-- forbids new extraction, clears the active pointer, and — because every derived
-- write CAS-checks the unchanged fence in app.assert_version_writable — thereby
-- invalidates any in-flight worker holding the old fence (its whole transaction
-- rolls back). Physical artifact cleanup is a separate, idempotently resumable
-- step that runs only after that commit. Completion to PURGED requires that no
-- decryptable artifact, active pointer, queryable evidence or running job of the
-- old fence remains. DATA_MODEL.md s4 (retention/purge bullets), POKA_YOKE.md
-- VER-008, IMM-004.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_purger') THEN
        RAISE EXCEPTION 'required privileged role knowvault_purger must exist before this migration';
    END IF;
END;
$$;

-- The shared retention guard's fence check reads NEW.retention_fence, a column
-- that exists only on source_version_retention. S1d never UPDATEd
-- source_extraction_retention, so the field reference was never reached for that
-- table; purge is the first extraction-retention UPDATE, so the reference is
-- moved inside the table-specific branch. Semantics are unchanged: retention is
-- forward-only and the version fence never decreases.
CREATE OR REPLACE FUNCTION app.source_retention_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION '% deletion requires tenant hard-delete state', TG_TABLE_NAME USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF (OLD.state = 'PURGED' AND NEW.state <> 'PURGED')
       OR (OLD.state = 'PURGING' AND NEW.state = 'ACTIVE') THEN
        RAISE EXCEPTION '% retention does not reverse', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF TG_TABLE_NAME = 'source_version_retention' THEN
        IF NEW.retention_fence < OLD.retention_fence THEN
            RAISE EXCEPTION 'retention fence never decreases' USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- The active-pointer guard denied every DELETE outside a tenant hard-delete. A
-- purge legitimately tears down the pointer of a version whose retention is
-- already PURGING/PURGED, so that exact case is now also permitted. The runtime
-- role (knowvault_app) remains denied unconditionally, and the sync worker cannot
-- reach this path because it cannot drive a version into PURGING. The UPDATE
-- (re-pointing) rules are unchanged: a pointer still requires ACTIVE queryable
-- retention, so it can never be re-established on a purged version.
CREATE OR REPLACE FUNCTION app.source_active_extraction_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    extraction_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT (
               EXISTS (SELECT 1 FROM public.organization
                       WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED'))
               OR EXISTS (SELECT 1 FROM public.source_version_retention r
                          WHERE r.organization_id = OLD.organization_id
                            AND r.source_version_id = OLD.source_version_id
                            AND r.state IN ('PURGING', 'PURGED'))
           ) THEN
            RAISE EXCEPTION 'source_version_active_extraction deletion requires tenant hard-delete or a purging version' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.activation_revision <= OLD.activation_revision THEN
        RAISE EXCEPTION 'active extraction pointer advances monotonically' USING ERRCODE = '55000';
    END IF;
    SELECT status INTO extraction_status FROM public.source_extraction
        WHERE organization_id = NEW.organization_id AND id = NEW.extraction_id
          AND source_version_id = NEW.source_version_id;
    IF extraction_status IS DISTINCT FROM 'SUCCEEDED' THEN
        RAISE EXCEPTION 'active extraction must be a SUCCEEDED extraction of the version' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.source_version_retention r
        WHERE r.organization_id = NEW.organization_id AND r.source_version_id = NEW.source_version_id
          AND r.state = 'ACTIVE' AND r.queryable) THEN
        RAISE EXCEPTION 'active extraction requires ACTIVE queryable version retention' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.source_extraction_retention r
        WHERE r.organization_id = NEW.organization_id AND r.extraction_id = NEW.extraction_id
          AND r.state = 'ACTIVE' AND r.queryable) THEN
        RAISE EXCEPTION 'active extraction requires ACTIVE queryable extraction retention' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Phase 1: fail-close transition ACTIVE -> PURGING (one transaction)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_version_begin_purge(
    p_organization_id text, p_version_id text, p_reason text, p_expected_fence bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_state text;
    current_fence bigint;
    new_fence bigint;
BEGIN
    -- Self-fence on the session tenant like every peer SECURITY DEFINER function:
    -- the definer owner bypasses RLS, so the caller-supplied tenant must equal the
    -- session tenant. Knowledge of another tenant's ids is never purge authority.
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;
    IF p_reason IS NULL OR btrim(p_reason) = '' OR p_reason !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
        RAISE EXCEPTION 'purge reason must be a safe operator code' USING ERRCODE = '22023';
    END IF;

    -- Lock the version retention row and CAS on the observed fence: a concurrent
    -- purge or derived write that already moved the fence makes this begin fail.
    SELECT state, retention_fence INTO current_state, current_fence
      FROM public.source_version_retention
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'version retention not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'purge may begin only from ACTIVE retention' USING ERRCODE = '55000';
    END IF;
    IF current_fence <> p_expected_fence THEN
        RAISE EXCEPTION 'purge fence CAS failed: retention moved under the caller' USING ERRCODE = '40001';
    END IF;

    new_fence := current_fence + 1;

    -- The fence advances first; every later derived write compares against it.
    UPDATE public.source_version_retention
       SET retention_fence = new_fence, state = 'PURGING', queryable = false,
           extraction_allowed = false, purge_reason = p_reason
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id;

    -- Every extraction of the version fails closed in the same transaction.
    UPDATE public.source_extraction_retention er
       SET state = 'PURGING', queryable = false, purge_reason = p_reason
      FROM public.source_extraction e
     WHERE er.organization_id = p_organization_id AND e.organization_id = p_organization_id
       AND er.extraction_id = e.id AND e.source_version_id = p_version_id
       AND er.state <> 'PURGED';

    -- The active pointer is cleared so retrieval resolves nothing even before the
    -- bytes are gone. The pointer's own guard forbids re-pointing at a non-ACTIVE
    -- retention, so it cannot be re-established while PURGING/PURGED.
    DELETE FROM public.source_version_active_extraction
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id;

    RETURN new_fence;
END;
$$;

-- ---------------------------------------------------------------------------
-- Cleanup: idempotent physical artifact purge (runs after the fail-close commit)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_version_purge_cleanup(
    p_organization_id text, p_version_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    purged_count bigint;
BEGIN
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;
    -- Cleanup is only ever a consequence of a committed fail-close.
    IF NOT EXISTS (SELECT 1 FROM public.source_version_retention
                   WHERE organization_id = p_organization_id AND source_version_id = p_version_id
                     AND state IN ('PURGING', 'PURGED')) THEN
        RAISE EXCEPTION 'cleanup requires a PURGING/PURGED version retention' USING ERRCODE = '55000';
    END IF;

    -- Irreversibly forget the decryptable bytes of every Evidence fragment of the
    -- version (text, anchor, metadata), keeping the nonce and hashes as
    -- non-decryptable purge provenance. Idempotent: already-purged rows are
    -- skipped, so a crashed cleanup is safely resumable.
    WITH cleaned AS (
        UPDATE public.encrypted_artifact a
           SET ciphertext = NULL, wrapped_dek = NULL, purged_at = now()
         WHERE a.organization_id = p_organization_id
           AND a.owner_table = 'evidence_fragment'
           AND a.purged_at IS NULL
           AND a.resource_id IN (
               SELECT f.id FROM public.evidence_fragment f
                WHERE f.organization_id = p_organization_id AND f.source_version_id = p_version_id
           )
        RETURNING 1
    )
    SELECT count(*) INTO purged_count FROM cleaned;
    RETURN purged_count;
END;
$$;

-- ---------------------------------------------------------------------------
-- Phase 2: completion PURGING -> PURGED (only when no resurrectable residue)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_version_complete_purge(
    p_organization_id text, p_version_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    object_id text;
    current_state text;
BEGIN
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;
    SELECT state INTO current_state FROM public.source_version_retention
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'version retention not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_state <> 'PURGING' THEN
        RAISE EXCEPTION 'completion requires a PURGING version retention' USING ERRCODE = '55000';
    END IF;

    -- No decryptable Evidence artifact of the version may remain.
    IF EXISTS (
        SELECT 1 FROM public.encrypted_artifact a
         WHERE a.organization_id = p_organization_id
           AND a.owner_table = 'evidence_fragment'
           AND a.purged_at IS NULL
           AND a.resource_id IN (
               SELECT f.id FROM public.evidence_fragment f
                WHERE f.organization_id = p_organization_id AND f.source_version_id = p_version_id
           )
    ) THEN
        RAISE EXCEPTION 'completion blocked: decryptable Evidence artifacts remain' USING ERRCODE = '55000';
    END IF;

    -- No active pointer may resolve the version.
    IF EXISTS (SELECT 1 FROM public.source_version_active_extraction
               WHERE organization_id = p_organization_id AND source_version_id = p_version_id) THEN
        RAISE EXCEPTION 'completion blocked: active extraction pointer remains' USING ERRCODE = '55000';
    END IF;

    -- No running job of the old fence may still target the version.
    IF EXISTS (SELECT 1 FROM public.job
               WHERE organization_id = p_organization_id AND status = 'RUNNING'
                 AND type IN ('SOURCE_OBJECT_EXTRACTION', 'SOURCE_VERSION_PURGE')
                 AND payload_json ->> 'source_version_id' = p_version_id) THEN
        RAISE EXCEPTION 'completion blocked: a running job of the version remains' USING ERRCODE = '55000';
    END IF;

    UPDATE public.source_version_retention
       SET state = 'PURGED', queryable = false, extraction_allowed = false, purged_at = now()
     WHERE organization_id = p_organization_id AND source_version_id = p_version_id;

    UPDATE public.source_extraction_retention er
       SET state = 'PURGED', queryable = false, purged_at = now()
      FROM public.source_extraction e
     WHERE er.organization_id = p_organization_id AND e.organization_id = p_organization_id
       AND er.extraction_id = e.id AND e.source_version_id = p_version_id
       AND er.state <> 'PURGED';

    -- The version's own lifecycle reaches the terminal redacted state; immutable
    -- hashes/provenance are retained by the rows themselves.
    UPDATE public.source_version SET state = 'REDACTED'
     WHERE organization_id = p_organization_id AND id = p_version_id AND state <> 'REDACTED';

    -- If the purged version was the object's current version, the object is closed
    -- until a safe new current version is chosen; a historical purge leaves the
    -- current version and object untouched. DATA_MODEL.md s4.
    SELECT source_object_id INTO object_id FROM public.source_version
     WHERE organization_id = p_organization_id AND id = p_version_id;
    UPDATE public.source_object
       SET queryable = false, last_seen_at = now()
     WHERE organization_id = p_organization_id AND id = object_id
       AND current_version_id = p_version_id;
END;
$$;

-- ---------------------------------------------------------------------------
-- Privilege: purge is a trusted control-plane operation only
-- ---------------------------------------------------------------------------

REVOKE ALL ON FUNCTION
    app.source_version_begin_purge(text, text, text, bigint),
    app.source_version_purge_cleanup(text, text),
    app.source_version_complete_purge(text, text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.source_version_begin_purge(text, text, text, bigint),
    app.source_version_purge_cleanup(text, text),
    app.source_version_complete_purge(text, text)
TO knowvault_purger;

-- The purger orchestrates the phases and appends the content-free purge audit
-- events in the same transactions, so it needs the audit-append surface (exactly
-- the worker's audit grants) and read access to the rows it audits, but none of
-- the worker's ingestion write grants.
GRANT USAGE ON SCHEMA app, public TO knowvault_purger;
GRANT SELECT ON TABLE
    public.source_object, public.source_version, public.source_version_retention,
    public.source_extraction, public.source_extraction_retention,
    public.source_version_active_extraction, public.evidence_fragment,
    public.encrypted_artifact, public.job, public.organization
TO knowvault_purger;
GRANT SELECT, INSERT ON TABLE public.audit_event TO knowvault_purger;
GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_chain_head TO knowvault_purger;
GRANT EXECUTE ON FUNCTION app.current_organization_id() TO knowvault_purger;
GRANT EXECUTE ON FUNCTION app.audit_opaque_id_is_valid(text) TO knowvault_purger;
GRANT EXECUTE ON FUNCTION app.audit_metadata_is_allowed(jsonb) TO knowvault_purger;
-- The audit_event CHECK constraints reference these validators; even a
-- non-authority event needs EXECUTE to be inserted.
GRANT EXECUTE ON FUNCTION app.authority_audit_metadata_is_exact(text, text, jsonb) TO knowvault_purger;

COMMIT;
