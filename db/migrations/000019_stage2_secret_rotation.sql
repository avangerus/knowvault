-- Stage 2 secret rotation machinery (ADR-0070).
--
-- Implements the two-phase envelope KEK rotation and the digest-key rotation:
--
-- * `rotation_state` records, per tenant and domain (KEK, DIGEST), the
--   previous/active key pair and a monotonic watermark that makes the
--   background pass resumable after a crash.
-- * `app.artifact_rewrap` rewrites an encrypted artifact's DEK wrapper from
--   the previous KEK pair to the active pair. It is fenced: it can only run
--   inside a live `KEK_REWRAP` job lease held by the calling worker
--   (leases/heartbeat/retry/fencing/crash-recovery of the S1b substrate).
-- * `app.evidence_digest_rewrite` re-projects the keyed anchor digest of one
--   evidence fragment under the active digest version. It is fenced by a live
--   `DIGEST_RECOMPUTE` job lease and updates the fragment and its staged
--   projection atomically, so citations never observe a torn pair.
-- * `app.*_rotation_complete` atomically switches the domain to COMPLETE only
--   when zero wrappers / zero projections remain under the previous pair
--   (fail closed), and is idempotent on repeat.
--
-- Unknown key versions fail closed: rewrap CAS requires the exact previous
-- pair, the rewrite CAS requires the exact previous digest version, and the
-- wrap backend (artifactcrypto) accepts only the active pair for writes.
--
-- The worker role owns every entry point; `knowvault_app` keeps no execute
-- privilege. Direct table UPDATE remains impossible for both roles (no table
-- privilege), so the guarded trigger branches below are reachable only from
-- the fenced SECURITY DEFINER functions.

BEGIN;

-- ---------------------------------------------------------------------------
-- Rotation state
-- ---------------------------------------------------------------------------

CREATE TABLE public.rotation_state (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    domain text NOT NULL CHECK (domain IN ('KEK', 'DIGEST')),
    phase text NOT NULL CHECK (phase IN ('REWRAPPING', 'COMPLETE')),
    previous_reference text CHECK (
        previous_reference IS NULL
        OR (char_length(previous_reference) BETWEEN 1 AND 1024
            AND previous_reference = btrim(previous_reference))
    ),
    previous_version bigint CHECK (
        previous_version IS NULL OR previous_version BETWEEN 1 AND 9007199254740991
    ),
    active_reference text NOT NULL CHECK (
        char_length(active_reference) BETWEEN 1 AND 1024
        AND active_reference = btrim(active_reference)
    ),
    active_version bigint NOT NULL CHECK (
        active_version BETWEEN 1 AND 9007199254740991
    ),
    -- Number of rows already rewritten by the background pass. Resumability
    -- indicator only; the pass itself re-selects by key pair / digest version,
    -- so a crashed pass continues without double work.
    watermark bigint NOT NULL DEFAULT 0 CHECK (watermark BETWEEN 0 AND 9007199254740991),
    started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, domain),
    CHECK (phase = 'REWRAPPING' OR completed_at IS NOT NULL),
    CHECK ((previous_reference IS NULL) = (previous_version IS NULL))
);

ALTER TABLE public.rotation_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rotation_state FORCE ROW LEVEL SECURITY;
CREATE POLICY rotation_state_tenant_isolation ON public.rotation_state
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.rotation_state FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Rotation state access (worker-only)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.rotation_state(p_domain text)
RETURNS TABLE(
    phase text,
    previous_reference text,
    previous_version bigint,
    active_reference text,
    active_version bigint,
    watermark bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.phase, r.previous_reference, r.previous_version,
           r.active_reference, r.active_version, r.watermark
    FROM public.rotation_state r
    WHERE r.organization_id = app.current_organization_id()
      AND r.domain = p_domain;
$$;

REVOKE ALL ON FUNCTION app.rotation_state(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.rotation_state(text) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- Begin: register the previous/active pair of a rotation domain. Idempotent:
-- a repeat of the same begin is a no-op; a begin after COMPLETE opens the
-- next cycle with the completed pair as the new previous pair.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.rotation_begin(
    p_domain text,
    p_previous_reference text,
    p_previous_version bigint,
    p_active_reference text,
    p_active_version bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    current_phase text;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'rotation begin is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF p_domain NOT IN ('KEK', 'DIGEST') THEN
        RAISE EXCEPTION 'unknown rotation domain' USING ERRCODE = '22023';
    END IF;
    IF p_previous_reference IS NULL OR p_previous_reference = ''
       OR char_length(p_previous_reference) > 1024 OR p_previous_reference <> btrim(p_previous_reference)
       OR p_active_reference IS NULL OR p_active_reference = ''
       OR char_length(p_active_reference) > 1024 OR p_active_reference <> btrim(p_active_reference)
       OR p_previous_version IS NULL OR p_previous_version < 1
       OR p_previous_version > 9007199254740991
       OR p_active_version IS NULL OR p_active_version < 1
       OR p_active_version > 9007199254740991 THEN
        RAISE EXCEPTION 'rotation key pair is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_previous_reference = p_active_reference AND p_previous_version = p_active_version THEN
        RAISE EXCEPTION 'rotation requires a distinct active pair' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'rotation begin requires a tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT r.phase INTO current_phase
        FROM public.rotation_state r
        WHERE r.organization_id = organization_value AND r.domain = p_domain
        FOR UPDATE;

    IF current_phase IS NULL THEN
        INSERT INTO public.rotation_state (
            organization_id, domain, phase,
            previous_reference, previous_version,
            active_reference, active_version
        ) VALUES (
            organization_value, p_domain, 'REWRAPPING',
            p_previous_reference, p_previous_version,
            p_active_reference, p_active_version
        );
    ELSIF current_phase = 'REWRAPPING' THEN
        -- Idempotent repeat of the same begin.
        PERFORM 1 FROM public.rotation_state r
            WHERE r.organization_id = organization_value AND r.domain = p_domain
              AND r.previous_reference = p_previous_reference
              AND r.previous_version = p_previous_version
              AND r.active_reference = p_active_reference
              AND r.active_version = p_active_version;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'rotation already in progress with different key pairs'
                USING ERRCODE = '55000';
        END IF;
    ELSIF current_phase = 'COMPLETE' THEN
        UPDATE public.rotation_state r SET
            phase = 'REWRAPPING',
            previous_reference = p_previous_reference,
            previous_version = p_previous_version,
            active_reference = p_active_reference,
            active_version = p_active_version,
            watermark = 0,
            started_at = transaction_timestamp(),
            completed_at = NULL,
            updated_at = transaction_timestamp()
        WHERE r.organization_id = organization_value AND r.domain = p_domain;
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION app.rotation_begin(text, text, bigint, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.rotation_begin(text, text, bigint, text, bigint) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- KEK rewrap machinery (ADR-0070 §1.3)
-- ---------------------------------------------------------------------------

-- Count of active artifacts still sealed under the given KEK pair. The
-- zero-wrappers completion precondition and the batch cursors use it.
CREATE OR REPLACE FUNCTION app.artifact_wrapped_under_key_count(
    p_kek_reference text,
    p_kek_version bigint
)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT count(*)
    FROM public.encrypted_artifact
    WHERE organization_id = app.current_organization_id()
      AND purged_at IS NULL
      AND kek_reference = p_kek_reference
      AND kek_version = p_kek_version;
$$;

REVOKE ALL ON FUNCTION app.artifact_wrapped_under_key_count(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.artifact_wrapped_under_key_count(text, bigint) TO knowvault_worker;

-- One batch of envelope material of active artifacts sealed under the given
-- pair, oldest first. The worker re-seals each wrapper under the active pair
-- and calls app.artifact_rewrap in the same fenced transaction. Re-select by
-- pair makes the pass idempotent and resumable: an already re-wrapped
-- artifact is no longer a candidate.
CREATE OR REPLACE FUNCTION app.artifact_rewrap_candidate_batch(
    p_kek_reference text,
    p_kek_version bigint,
    p_limit integer
)
RETURNS TABLE(
    id text,
    owner_table text,
    owner_column text,
    resource_type text,
    resource_id text,
    field_name text,
    ciphertext bytea,
    size_bytes integer,
    nonce bytea,
    wrapped_dek bytea,
    wrapped_dek_hash text,
    kek_reference text,
    kek_version bigint,
    aad_hash text,
    plaintext_hash text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'rewrap batch limit is out of range' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        SELECT a.id, a.owner_table, a.owner_column, a.resource_type, a.resource_id, a.field_name,
               a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
               a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
        FROM public.encrypted_artifact a
        WHERE a.organization_id = app.current_organization_id()
          AND a.purged_at IS NULL
          AND a.kek_reference = p_kek_reference
          AND a.kek_version = p_kek_version
        ORDER BY a.created_at, a.id
        LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION app.artifact_rewrap_candidate_batch(text, bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.artifact_rewrap_candidate_batch(text, bigint, integer) TO knowvault_worker;

-- Rewrite one artifact's DEK wrapper from the previous pair to the active
-- pair. Fenced: requires a live KEK_REWRAP lease held by the calling worker
-- (the row lock serializes concurrent workers), and a CAS on the previous
-- pair, so an artifact is never re-wrapped twice and never under an unknown
-- version. The artifact guard trigger additionally requires that the worker
-- touches exactly the wrapper columns.
CREATE OR REPLACE FUNCTION app.artifact_rewrap(
    p_artifact_id text,
    p_previous_reference text,
    p_previous_version bigint,
    p_new_reference text,
    p_new_version bigint,
    p_new_nonce bytea,
    p_new_wrapped_dek bytea,
    p_new_wrapped_dek_hash text,
    p_new_aad_hash text,
    p_job_id text,
    p_lease_owner text,
    p_lease_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    job_type_value text;
    rotation_previous_reference text;
    rotation_previous_version bigint;
    rotation_active_reference text;
    rotation_active_version bigint;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'artifact rewrap is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF p_previous_reference IS NULL OR p_previous_reference = ''
       OR p_previous_version IS NULL OR p_previous_version < 1
       OR p_new_reference IS NULL OR p_new_reference = ''
       OR p_new_version IS NULL OR p_new_version < 1 THEN
        RAISE EXCEPTION 'rewrap key pair is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_new_nonce IS NULL OR octet_length(p_new_nonce) <> 12 THEN
        RAISE EXCEPTION 'rewrap nonce must be exactly 12 bytes' USING ERRCODE = '22023';
    END IF;
    IF p_new_wrapped_dek IS NULL OR octet_length(p_new_wrapped_dek) < 62
       OR octet_length(p_new_wrapped_dek) > 65536 THEN
        RAISE EXCEPTION 'rewrap wrapped DEK is out of range' USING ERRCODE = '22023';
    END IF;
    IF p_new_wrapped_dek_hash IS NULL OR p_new_wrapped_dek_hash !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'rewrap wrapped DEK hash is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_new_aad_hash IS NULL OR p_new_aad_hash !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'rewrap AAD hash is invalid' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'rewrap requires a tenant context' USING ERRCODE = '42501';
    END IF;

    -- Fencing: the exact live lease held by this worker on the KEK_REWRAP job,
    -- then the row is locked for the rest of the transaction. A stale epoch or
    -- lapsed deadline raises and rolls back every write in the transaction.
    PERFORM app.lock_job_lease(p_job_id, p_lease_owner, p_lease_epoch);
    SELECT j.type INTO job_type_value
        FROM public.job j
        WHERE j.organization_id = organization_value AND j.id = p_job_id;
    IF job_type_value IS DISTINCT FROM 'KEK_REWRAP' THEN
        RAISE EXCEPTION 'rewrap requires a KEK_REWRAP job' USING ERRCODE = '55000';
    END IF;

    -- The pair must be the pair of the rotation in progress, so a worker with
    -- a stale manifest (unknown version) fails closed instead of sealing under
    -- a key the organization no longer tracks.
    SELECT r.previous_reference, r.previous_version, r.active_reference, r.active_version
        INTO rotation_previous_reference, rotation_previous_version,
             rotation_active_reference, rotation_active_version
        FROM public.rotation_state r
        WHERE r.organization_id = organization_value AND r.domain = 'KEK'
        FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no KEK rotation in progress' USING ERRCODE = '55000';
    END IF;
    IF rotation_previous_reference IS DISTINCT FROM p_previous_reference
       OR rotation_previous_version IS DISTINCT FROM p_previous_version
       OR rotation_active_reference IS DISTINCT FROM p_new_reference
       OR rotation_active_version IS DISTINCT FROM p_new_version THEN
        RAISE EXCEPTION 'rewrap key pair does not match the rotation in progress'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.encrypted_artifact SET
        nonce = p_new_nonce,
        wrapped_dek = p_new_wrapped_dek,
        wrapped_dek_hash = p_new_wrapped_dek_hash,
        kek_reference = p_new_reference,
        kek_version = p_new_version,
        aad_hash = p_new_aad_hash
    WHERE organization_id = organization_value
      AND id = p_artifact_id
      AND purged_at IS NULL
      AND kek_reference = p_previous_reference
      AND kek_version = p_previous_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'rewrap CAS failed: artifact missing, purged or under another key pair'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.rotation_state SET
        watermark = watermark + 1,
        updated_at = transaction_timestamp()
    WHERE organization_id = organization_value AND domain = 'KEK';
END;
$$;

REVOKE ALL ON FUNCTION app.artifact_rewrap(
    text, text, bigint, text, bigint, bytea, bytea, text, text, text, text, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.artifact_rewrap(
    text, text, bigint, text, bigint, bytea, bytea, text, text, text, text, bigint
) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- KEK completion (ADR-0070 §1.3): zero wrappers under the previous pair, then
-- atomic switch to COMPLETE. Idempotent on repeat.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.kek_rotation_complete(
    p_active_reference text,
    p_active_version bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    rotation_phase text;
    rotation_previous_reference text;
    rotation_previous_version bigint;
    rotation_active_reference text;
    rotation_active_version bigint;
    remaining bigint;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'rotation complete is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'rotation complete requires a tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT r.phase, r.previous_reference, r.previous_version,
           r.active_reference, r.active_version
        INTO rotation_phase, rotation_previous_reference, rotation_previous_version,
             rotation_active_reference, rotation_active_version
        FROM public.rotation_state r
        WHERE r.organization_id = organization_value AND r.domain = 'KEK'
        FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no KEK rotation in progress' USING ERRCODE = '55000';
    END IF;
    IF rotation_phase = 'COMPLETE' THEN
        IF rotation_active_reference = p_active_reference
           AND rotation_active_version = p_active_version THEN
            RETURN; -- idempotent repeat
        END IF;
        RAISE EXCEPTION 'KEK rotation already completed with a different active pair'
            USING ERRCODE = '55000';
    END IF;
    IF rotation_active_reference IS DISTINCT FROM p_active_reference
       OR rotation_active_version IS DISTINCT FROM p_active_version THEN
        RAISE EXCEPTION 'complete pair does not match the active pair' USING ERRCODE = '55000';
    END IF;

    SELECT app.artifact_wrapped_under_key_count(
        rotation_previous_reference, rotation_previous_version
    ) INTO remaining;
    IF remaining > 0 THEN
        RAISE EXCEPTION 'zero-wrappers precondition: artifacts still wrapped under the previous key'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.rotation_state SET
        phase = 'COMPLETE',
        completed_at = transaction_timestamp(),
        updated_at = transaction_timestamp()
    WHERE organization_id = organization_value AND domain = 'KEK';
END;
$$;

REVOKE ALL ON FUNCTION app.kek_rotation_complete(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.kek_rotation_complete(text, bigint) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- Digest rotation machinery (ADR-0070 §1.4)
-- ---------------------------------------------------------------------------

-- Active evidence fragments still projected under the previous digest
-- version. The zero-remaining completion precondition uses it.
CREATE OR REPLACE FUNCTION app.evidence_digest_remaining_count(p_previous_version bigint)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT count(*)
    FROM public.evidence_fragment
    WHERE organization_id = app.current_organization_id()
      AND anchor_digest_key_version = p_previous_version;
$$;

REVOKE ALL ON FUNCTION app.evidence_digest_remaining_count(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_digest_remaining_count(bigint) TO knowvault_worker;

-- One batch of fragments still projected under the previous digest version,
-- joined with the envelope material of each anchor artifact so the worker can
-- open the canonical anchor bytes, re-key the HMAC under the active digest
-- version and rewrite the pair in one fenced transaction.
CREATE OR REPLACE FUNCTION app.evidence_digest_candidate_batch(
    p_previous_version bigint,
    p_limit integer
)
RETURNS TABLE(
    fragment_id text,
    anchor_artifact_id text,
    anchor_hash text,
    anchor_digest_key_version bigint,
    ciphertext bytea,
    size_bytes integer,
    nonce bytea,
    wrapped_dek bytea,
    wrapped_dek_hash text,
    kek_reference text,
    kek_version bigint,
    aad_hash text,
    plaintext_hash text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'digest batch limit is out of range' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        SELECT f.id, f.anchor_artifact_id, f.anchor_hash, f.anchor_digest_key_version,
               a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
               a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
        FROM public.evidence_fragment f
        JOIN public.encrypted_artifact a
          ON a.organization_id = f.organization_id AND a.id = f.anchor_artifact_id
         AND a.purged_at IS NULL
        WHERE f.organization_id = app.current_organization_id()
          AND f.anchor_digest_key_version = p_previous_version
        ORDER BY f.created_at, f.id
        LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION app.evidence_digest_candidate_batch(bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_digest_candidate_batch(bigint, integer) TO knowvault_worker;

-- Re-project one fragment's keyed anchor digest under the active version.
-- Fenced by a live DIGEST_RECOMPUTE lease; CAS on the previous version; the
-- projection row is updated before the fragment row so the fragment artifact
-- guard observes the exact new pair inside the same transaction — citations
-- never observe a torn projection.
CREATE OR REPLACE FUNCTION app.evidence_digest_rewrite(
    p_fragment_id text,
    p_new_anchor_hash text,
    p_new_version bigint,
    p_job_id text,
    p_lease_owner text,
    p_lease_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    job_type_value text;
    active_version bigint;
    previous_version bigint;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'digest rewrite is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    IF p_new_version IS NULL OR p_new_version < 1 THEN
        RAISE EXCEPTION 'digest rewrite version is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_new_anchor_hash IS NULL
       OR NOT app.source_keyed_digest_matches_version(p_new_anchor_hash, p_new_version) THEN
        RAISE EXCEPTION 'digest rewrite value is invalid' USING ERRCODE = '22023';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'digest rewrite requires a tenant context' USING ERRCODE = '42501';
    END IF;

    PERFORM app.lock_job_lease(p_job_id, p_lease_owner, p_lease_epoch);
    SELECT j.type INTO job_type_value
        FROM public.job j
        WHERE j.organization_id = organization_value AND j.id = p_job_id;
    IF job_type_value IS DISTINCT FROM 'DIGEST_RECOMPUTE' THEN
        RAISE EXCEPTION 'digest rewrite requires a DIGEST_RECOMPUTE job' USING ERRCODE = '55000';
    END IF;

    SELECT r.active_version, r.previous_version
        INTO active_version, previous_version
        FROM public.rotation_state r
        WHERE r.organization_id = organization_value AND r.domain = 'DIGEST'
        FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no DIGEST rotation in progress' USING ERRCODE = '55000';
    END IF;
    IF active_version IS DISTINCT FROM p_new_version THEN
        RAISE EXCEPTION 'rewrite version does not match the active digest version'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.evidence_anchor_projection p SET
        anchor_hash = p_new_anchor_hash,
        digest_key_version = p_new_version
    WHERE p.organization_id = organization_value AND p.fragment_id = p_fragment_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'digest rewrite requires an existing anchor projection'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.evidence_fragment f SET
        anchor_hash = p_new_anchor_hash,
        anchor_digest_key_version = p_new_version
    WHERE f.organization_id = organization_value
      AND f.id = p_fragment_id
      AND f.anchor_digest_key_version = previous_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'digest rewrite CAS failed: fragment missing or already rewritten'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.rotation_state SET
        watermark = watermark + 1,
        updated_at = transaction_timestamp()
    WHERE organization_id = organization_value AND domain = 'DIGEST';
END;
$$;

REVOKE ALL ON FUNCTION app.evidence_digest_rewrite(text, text, bigint, text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_digest_rewrite(text, text, bigint, text, text, bigint) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- Digest completion: zero fragments under the previous digest version, then
-- atomic switch to COMPLETE. Idempotent on repeat.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.digest_rotation_complete(p_previous_version bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    organization_value text;
    rotation_phase text;
    rotation_previous_version bigint;
    rotation_active_version bigint;
    remaining bigint;
BEGIN
    IF session_user <> 'knowvault_worker' THEN
        RAISE EXCEPTION 'rotation complete is restricted to the worker role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'rotation complete requires a tenant context' USING ERRCODE = '42501';
    END IF;

    SELECT r.phase, r.previous_version, r.active_version
        INTO rotation_phase, rotation_previous_version, rotation_active_version
        FROM public.rotation_state r
        WHERE r.organization_id = organization_value AND r.domain = 'DIGEST'
        FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no DIGEST rotation in progress' USING ERRCODE = '55000';
    END IF;
    IF rotation_phase = 'COMPLETE' THEN
        IF rotation_previous_version = p_previous_version THEN
            RETURN; -- idempotent repeat
        END IF;
        RAISE EXCEPTION 'DIGEST rotation already completed with a different previous version'
            USING ERRCODE = '55000';
    END IF;

    SELECT app.evidence_digest_remaining_count(p_previous_version) INTO remaining;
    IF remaining > 0 THEN
        RAISE EXCEPTION 'zero-remaining precondition: fragments still projected under the previous digest version'
            USING ERRCODE = '55000';
    END IF;

    UPDATE public.rotation_state SET
        phase = 'COMPLETE',
        completed_at = transaction_timestamp(),
        updated_at = transaction_timestamp()
    WHERE organization_id = organization_value AND domain = 'DIGEST';
END;
$$;

REVOKE ALL ON FUNCTION app.digest_rotation_complete(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.digest_rotation_complete(bigint) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- Guard extension: encrypted artifact rewrap (ADR-0070 §1.3). The worker has
-- no table UPDATE privilege, so this branch is reachable only from the fenced
-- app.artifact_rewrap; it permits exactly the six wrapper columns to move and
-- nothing else. The purge branch below stays untouched.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.encrypted_artifact_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM 1
        FROM public.organization
        WHERE id = NEW.organization_id AND status = 'ACTIVE'
        -- SHARE conflicts with the NO KEY UPDATE lock used by a concurrent
        -- ACTIVE -> DELETING status transition and is held through commit.
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'encrypted artifact creation requires an active tenant'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.purged_at IS NOT NULL THEN
            RAISE EXCEPTION 'encrypted artifact must be active at creation'
                USING ERRCODE = '55000';
        END IF;
        NEW.created_at := transaction_timestamp();
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR OLD.purged_at IS NULL
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'encrypted artifact deletion requires purged content and tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    IF session_user = 'knowvault_app' THEN
        RAISE EXCEPTION 'runtime role cannot mutate encrypted artifact'
            USING ERRCODE = '42501';
    END IF;

    -- Rewrap branch: DEK wrapper moves to a new KEK pair; every other column
    -- and the purge state stay untouched.
    IF session_user = 'knowvault_worker'
       AND OLD.purged_at IS NULL AND NEW.purged_at IS NULL
       AND (NEW.kek_reference, NEW.kek_version)
           IS DISTINCT FROM (OLD.kek_reference, OLD.kek_version)
       AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.aad_schema_version IS NOT DISTINCT FROM OLD.aad_schema_version
       AND NEW.owner_table IS NOT DISTINCT FROM OLD.owner_table
       AND NEW.owner_column IS NOT DISTINCT FROM OLD.owner_column
       AND NEW.resource_type IS NOT DISTINCT FROM OLD.resource_type
       AND NEW.resource_id IS NOT DISTINCT FROM OLD.resource_id
       AND NEW.field_name IS NOT DISTINCT FROM OLD.field_name
       AND NEW.cipher IS NOT DISTINCT FROM OLD.cipher
       AND NEW.size_bytes IS NOT DISTINCT FROM OLD.size_bytes
       AND NEW.ciphertext IS NOT DISTINCT FROM OLD.ciphertext
       AND NEW.plaintext_hash IS NOT DISTINCT FROM OLD.plaintext_hash
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;

    IF OLD.purged_at IS NOT NULL
       OR NEW.purged_at IS NULL
       OR NEW.ciphertext IS NOT NULL
       OR NEW.wrapped_dek IS NOT NULL
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.aad_schema_version IS DISTINCT FROM OLD.aad_schema_version
       OR NEW.owner_table IS DISTINCT FROM OLD.owner_table
       OR NEW.owner_column IS DISTINCT FROM OLD.owner_column
       OR NEW.resource_type IS DISTINCT FROM OLD.resource_type
       OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
       OR NEW.field_name IS DISTINCT FROM OLD.field_name
       OR NEW.cipher IS DISTINCT FROM OLD.cipher
       OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
       OR NEW.nonce IS DISTINCT FROM OLD.nonce
       OR NEW.wrapped_dek_hash IS DISTINCT FROM OLD.wrapped_dek_hash
       OR NEW.kek_reference IS DISTINCT FROM OLD.kek_reference
       OR NEW.kek_version IS DISTINCT FROM OLD.kek_version
       OR NEW.aad_hash IS DISTINCT FROM OLD.aad_hash
       OR NEW.plaintext_hash IS DISTINCT FROM OLD.plaintext_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'encrypted artifact permits only irreversible content purge'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Guard extension: evidence fragment digest reproject (ADR-0070 §1.4). The
-- fragment identity (version, extraction, ordinal, text hash, confidence,
-- language, artifact bindings) stays immutable; only the two keyed anchor
-- projection columns move, and only under the worker role — which has no
-- table UPDATE privilege, so the branch is reachable only from the fenced
-- app.evidence_digest_rewrite.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.evidence_fragment_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'evidence_fragment deletion requires tenant hard-delete state'
                USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;

    -- Digest reproject branch: only the two keyed anchor projection columns
    -- move; the fragment identity stays byte-identical. NULLable identity
    -- columns (confidence, language, optional artifact bindings) compare with
    -- IS NOT DISTINCT FROM so NULL stays NULL.
    IF session_user = 'knowvault_worker'
       AND (NEW.anchor_hash, NEW.anchor_digest_key_version)
           IS DISTINCT FROM (OLD.anchor_hash, OLD.anchor_digest_key_version)
       AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.source_version_id IS NOT DISTINCT FROM OLD.source_version_id
       AND NEW.extraction_id IS NOT DISTINCT FROM OLD.extraction_id
       AND NEW.ordinal IS NOT DISTINCT FROM OLD.ordinal
       AND NEW.text_hash IS NOT DISTINCT FROM OLD.text_hash
       AND NEW.token_count IS NOT DISTINCT FROM OLD.token_count
       AND NEW.byte_count IS NOT DISTINCT FROM OLD.byte_count
       AND NEW.extraction_confidence IS NOT DISTINCT FROM OLD.extraction_confidence
       AND NEW.language IS NOT DISTINCT FROM OLD.language
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.normalized_text_artifact_id IS NOT DISTINCT FROM OLD.normalized_text_artifact_id
       AND NEW.anchor_artifact_id IS NOT DISTINCT FROM OLD.anchor_artifact_id
       AND NEW.metadata_artifact_id IS NOT DISTINCT FROM OLD.metadata_artifact_id THEN
        RETURN NEW;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.extraction_id IS DISTINCT FROM OLD.extraction_id
       OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
       OR NEW.text_hash IS DISTINCT FROM OLD.text_hash
       OR NEW.token_count IS DISTINCT FROM OLD.token_count
       OR NEW.byte_count IS DISTINCT FROM OLD.byte_count
       OR NEW.anchor_hash IS DISTINCT FROM OLD.anchor_hash
       OR NEW.anchor_digest_key_version IS DISTINCT FROM OLD.anchor_digest_key_version
       OR NEW.extraction_confidence IS DISTINCT FROM OLD.extraction_confidence
       OR NEW.language IS DISTINCT FROM OLD.language
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'evidence_fragment is immutable' USING ERRCODE = '55000';
    END IF;
    IF (OLD.normalized_text_artifact_id IS NOT NULL AND NEW.normalized_text_artifact_id IS DISTINCT FROM OLD.normalized_text_artifact_id)
       OR (OLD.anchor_artifact_id IS NOT NULL AND NEW.anchor_artifact_id IS DISTINCT FROM OLD.anchor_artifact_id)
       OR (OLD.metadata_artifact_id IS NOT NULL AND NEW.metadata_artifact_id IS DISTINCT FROM OLD.metadata_artifact_id) THEN
        RAISE EXCEPTION 'evidence_fragment artifact bindings are write-once' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Closed inventories: durable job types and audit vocabulary gain the
-- rotation operations. The audit resource-type inventory is replaced, not
-- extended in place: the previous inventory (000011) already carries
-- WORKSPACE_SOURCE and WORKSPACE_AUTHORITY_COMMAND.
-- ---------------------------------------------------------------------------

ALTER TABLE public.job DROP CONSTRAINT job_type_check;
ALTER TABLE public.job ADD CONSTRAINT job_type_check CHECK (type IN (
    'SOURCE_SCOPE_SYNC', 'SOURCE_OBJECT_EXTRACTION',
    'OUTBOX_DELIVERY', 'SOURCE_VERSION_PURGE',
    'KEK_REWRAP', 'DIGEST_RECOMPUTE'
));

ALTER TABLE public.audit_event DROP CONSTRAINT audit_event_resource_type_check;
ALTER TABLE public.audit_event ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
    'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
    'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
    'SOURCE_CONNECTION', 'SOURCE_SCOPE',
    'SOURCE_OBJECT', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
    'SIGNING_KEY', 'AUDIT_CHECKPOINT', 'CRYPTO_KEY'
));

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
               'rotation_domain', 'key_reference', 'key_version'
           )
       );
$$;

COMMIT;
