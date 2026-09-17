-- Stage 2 keyed Evidence text digest (ADR-0077).
--
-- Completes the owner decision that Evidence content equality projections are
-- organization-scoped HMAC-SHA-256 with a mandatory digest_key_version:
--
-- * `evidence_fragment.text_hash` becomes keyed.  The CHECK on new rows
--   rejects the legacy `sha256:` format; historical plain-SHA rows remain
--   under a NOT VALID boundary and fail closed at read/publication until the
--   digest rotation re-projects them.
-- * The artifact binding for text moves to a keyed projection table
--   (`evidence_text_projection`), symmetric to the anchor projection of 000017:
--   the fenced 15-argument bind writes artifact + projection atomically, and
--   the fragment artifact guard verifies the pair against the projection.
--   `encrypted_artifact.plaintext_hash` remains the internal SHA-256 integrity
--   value (ADR-0070: not a public projection).
-- * The DIGEST rotation machinery (000019) is redefined to cover both
--   projections in one fenced transaction; zero-remaining completion now
--   requires both pairs under the active version.  Fragments of PURGING/PURGED
--   versions are excluded: their content cannot and need not be re-projected,
--   and their legacy projections must not block completion forever.
-- * Purge cleanup removes both projection rows; the keyed projections inside
--   the fragment rows themselves remain as non-decryptable purge provenance
--   and are no longer a usable hash oracle without the digest key.
--
-- Functions redefined here shadow their 000019 definitions; the mutation
-- registry entries targeting the redefined DIGEST functions are re-pointed at
-- this file by the same package.

BEGIN;

-- ---------------------------------------------------------------------------
-- Schema: keyed text digest on evidence_fragment
-- ---------------------------------------------------------------------------

ALTER TABLE public.evidence_fragment
    DROP CONSTRAINT evidence_fragment_text_hash_check;

-- The purge erasure shape needs the hash columns nullable; ingestion of the
-- NULL shape is rejected by the fragment state guard, not by NOT NULL.
ALTER TABLE public.evidence_fragment ALTER COLUMN text_hash DROP NOT NULL;
ALTER TABLE public.evidence_fragment ALTER COLUMN anchor_hash DROP NOT NULL;

ALTER TABLE public.evidence_fragment
    ADD COLUMN text_digest_key_version bigint;

-- Existing S1d rows were written with plain-SHA text hashes.  NOT VALID
-- preserves those historical rows for controlled migration, while PostgreSQL
-- still enforces the check on every new or updated row.  The read and
-- publication gates below fail closed for the historical rows.
--
-- The NULL pair is the purge shape (ADR-0077 §1.4): purge cleanup erases
-- both hash pairs of a purged version, so no plain-SHA projection of
-- content survives in the tree.  The evidence_fragment_state_guard below
-- rejects INSERTs without both keyed pairs, so the NULL shape is reachable
-- only through the purge cleanup function, never through ingestion.
ALTER TABLE public.evidence_fragment
    ADD CONSTRAINT evidence_fragment_text_digest_check
    CHECK (
        (text_digest_key_version IS NULL AND text_hash IS NULL)
        OR (text_digest_key_version IS NOT NULL
            AND app.source_keyed_digest_matches_version(text_hash, text_digest_key_version))
    ) NOT VALID;

-- The anchor pair gets the same purge shape; 000017 froze the original
-- anchor-only check, so it is redefined here for the purge erasure.
ALTER TABLE public.evidence_fragment
    DROP CONSTRAINT evidence_fragment_anchor_digest_check;
ALTER TABLE public.evidence_fragment
    ADD CONSTRAINT evidence_fragment_anchor_digest_check
    CHECK (
        (anchor_digest_key_version IS NULL AND anchor_hash IS NULL)
        OR (anchor_digest_key_version IS NOT NULL
            AND app.source_keyed_digest_matches_version(anchor_hash, anchor_digest_key_version))
    ) NOT VALID;

-- ---------------------------------------------------------------------------
-- Keyed text projection (symmetric to evidence_anchor_projection, 000017)
-- ---------------------------------------------------------------------------

CREATE TABLE public.evidence_text_projection (
    organization_id text NOT NULL,
    artifact_id text NOT NULL,
    fragment_id text NOT NULL,
    text_hash text NOT NULL,
    digest_key_version bigint NOT NULL,
    PRIMARY KEY (organization_id, artifact_id),
    UNIQUE (organization_id, fragment_id),
    CHECK (app.source_keyed_digest_matches_version(text_hash, digest_key_version)),
    CONSTRAINT evidence_text_projection_artifact_fk
        FOREIGN KEY (organization_id, artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT evidence_text_projection_fragment_fk
        FOREIGN KEY (organization_id, fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id)
        ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------------
-- Text bind: the 13-argument path is inert, the 15-argument path is the only
-- way to persist a normalized-text artifact (ADR-0077 §1.2).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.evidence_fragment_bind_normalized_text(
    p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'keyed text projection is required' USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION app.evidence_fragment_bind_normalized_text(
    p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text,
    p_keyed_projection_digest text, p_keyed_projection_key_version bigint
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
        RAISE EXCEPTION 'resource id must equal the owning row id' USING ERRCODE = '23514';
    END IF;
    IF NOT app.source_keyed_digest_matches_version(p_keyed_projection_digest, p_keyed_projection_key_version) THEN
        RAISE EXCEPTION 'keyed text projection is invalid' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
        cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'evidence_fragment', 'normalized_text_artifact_id',
        'EVIDENCE_TEXT', p_resource_id, 'NORMALIZED_TEXT', 'AES_256_GCM', p_ciphertext, p_size_bytes,
        p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    INSERT INTO public.evidence_text_projection (
        organization_id, artifact_id, fragment_id, text_hash, digest_key_version
    ) VALUES (
        p_org, p_artifact_id, p_owning_row_id, p_keyed_projection_digest, p_keyed_projection_key_version
    );
    UPDATE public.evidence_fragment SET normalized_text_artifact_id = p_artifact_id
        WHERE organization_id = p_org AND id = p_owning_row_id
          AND normalized_text_artifact_id IS NULL
          AND text_hash = p_keyed_projection_digest
          AND text_digest_key_version = p_keyed_projection_key_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning evidence_fragment missing, already bound or projected under a different digest'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION app.evidence_fragment_bind_normalized_text(
    text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.evidence_fragment_bind_normalized_text(
    text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text,
    text, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_bind_normalized_text(
    text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text,
    text, bigint
) TO knowvault_worker;

-- ---------------------------------------------------------------------------
-- Artifact guard: the text artifact now binds through the keyed projection
-- (ADR-0077 §1.2).  The anchor and metadata branches stay as in 000017.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.evidence_fragment_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    ok boolean;
BEGIN
    -- Purge erasure branch: once purge cleanup has erased both hash pairs,
    -- the exact-ownership check no longer applies (the projections and the
    -- decryptable artifacts are gone with them).  Reachable only through the
    -- purge cleanup function, which demands a PURGING/PURGED retention.
    IF session_user = 'knowvault_purger'
       AND NEW.text_hash IS NULL AND NEW.text_digest_key_version IS NULL
       AND NEW.anchor_hash IS NULL AND NEW.anchor_digest_key_version IS NULL
       AND EXISTS (SELECT 1 FROM public.source_version_retention vr
                   WHERE vr.organization_id = NEW.organization_id
                     AND vr.source_version_id = NEW.source_version_id
                     AND vr.state IN ('PURGING', 'PURGED')) THEN
        RETURN NEW;
    END IF;
    SELECT bool_and(present) INTO ok FROM (
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            JOIN public.evidence_text_projection p
              ON p.organization_id = a.organization_id AND p.artifact_id = a.id
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'normalized_text_artifact_id'
              AND a.resource_type = 'EVIDENCE_TEXT' AND a.field_name = 'NORMALIZED_TEXT'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL
              AND p.fragment_id = NEW.id
              AND p.text_hash = NEW.text_hash
              AND p.digest_key_version = NEW.text_digest_key_version) AS present
        UNION ALL
        SELECT EXISTS (SELECT 1
            FROM public.encrypted_artifact a
            JOIN public.evidence_anchor_projection p
              ON p.organization_id = a.organization_id AND p.artifact_id = a.id
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'anchor_artifact_id'
              AND a.resource_type = 'EVIDENCE_ANCHOR' AND a.field_name = 'CANONICAL_ANCHOR'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL
              AND p.fragment_id = NEW.id
              AND p.anchor_hash = NEW.anchor_hash
              AND p.digest_key_version = NEW.anchor_digest_key_version) AS present
        UNION ALL
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'metadata_artifact_id'
              AND a.resource_type = 'EVIDENCE_METADATA' AND a.field_name = 'METADATA'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL) AS present
    ) checks;
    IF NOT ok THEN
        RAISE EXCEPTION 'evidence_fragment artifacts do not exactly own the fragment' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Fragment guard: the worker digest reproject branch now also permits the
-- keyed text pair to move (ADR-0077 §1.3).  The fragment identity stays
-- byte-identical otherwise.
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
    IF TG_OP = 'INSERT' THEN
        IF NEW.text_digest_key_version IS NULL OR NEW.anchor_digest_key_version IS NULL THEN
            RAISE EXCEPTION 'evidence fragment requires keyed anchor and text digests'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    -- Purge erasure branch: purge cleanup erases both hash pairs of a
    -- PURGING/PURGED version, and nothing else may move.  The NULL shape is
    -- therefore reachable only through the purge cleanup function.
    IF session_user = 'knowvault_purger'
       AND NEW.text_hash IS NULL AND NEW.text_digest_key_version IS NULL
       AND NEW.anchor_hash IS NULL AND NEW.anchor_digest_key_version IS NULL
       AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.source_version_id IS NOT DISTINCT FROM OLD.source_version_id
       AND NEW.extraction_id IS NOT DISTINCT FROM OLD.extraction_id
       AND NEW.ordinal IS NOT DISTINCT FROM OLD.ordinal
       AND NEW.token_count IS NOT DISTINCT FROM OLD.token_count
       AND NEW.byte_count IS NOT DISTINCT FROM OLD.byte_count
       AND NEW.extraction_confidence IS NOT DISTINCT FROM OLD.extraction_confidence
       AND NEW.language IS NOT DISTINCT FROM OLD.language
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
       AND NEW.normalized_text_artifact_id IS NOT DISTINCT FROM OLD.normalized_text_artifact_id
       AND NEW.anchor_artifact_id IS NOT DISTINCT FROM OLD.anchor_artifact_id
       AND NEW.metadata_artifact_id IS NOT DISTINCT FROM OLD.metadata_artifact_id
       AND EXISTS (SELECT 1 FROM public.source_version_retention vr
                   WHERE vr.organization_id = NEW.organization_id
                     AND vr.source_version_id = NEW.source_version_id
                     AND vr.state IN ('PURGING', 'PURGED')) THEN
        RETURN NEW;
    END IF;

    -- Digest reproject branch: only the two keyed projection pairs move; the
    -- fragment identity stays byte-identical. NULLable identity columns
    -- (confidence, language, optional artifact bindings) compare with
    -- IS NOT DISTINCT FROM so NULL stays NULL.
    IF session_user = 'knowvault_worker'
       AND (
           (NEW.anchor_hash, NEW.anchor_digest_key_version)
               IS DISTINCT FROM (OLD.anchor_hash, OLD.anchor_digest_key_version)
           OR (NEW.text_hash, NEW.text_digest_key_version)
               IS DISTINCT FROM (OLD.text_hash, OLD.text_digest_key_version)
       )
       AND NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.source_version_id IS NOT DISTINCT FROM OLD.source_version_id
       AND NEW.extraction_id IS NOT DISTINCT FROM OLD.extraction_id
       AND NEW.ordinal IS NOT DISTINCT FROM OLD.ordinal
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
       OR NEW.text_digest_key_version IS DISTINCT FROM OLD.text_digest_key_version
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

-- The fragment state guard now also fires on INSERT so the NULL purge shape
-- cannot be ingested; only purge cleanup (above) may write it.
DROP TRIGGER evidence_fragment_state_guard ON public.evidence_fragment;
CREATE TRIGGER evidence_fragment_state_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.evidence_fragment
    FOR EACH ROW EXECUTE FUNCTION app.evidence_fragment_guard();

-- ---------------------------------------------------------------------------
-- Read gate: only keyed text fragments are readable (fail closed for legacy)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.evidence_fragment_readable(p_fragment_id text, p_workspace_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.evidence_fragment f
        JOIN public.evidence_anchor_projection ap
          ON ap.organization_id = f.organization_id AND ap.fragment_id = f.id
         AND ap.anchor_hash = f.anchor_hash AND ap.digest_key_version = f.anchor_digest_key_version
        JOIN public.evidence_text_projection tp
          ON tp.organization_id = f.organization_id AND tp.fragment_id = f.id
         AND tp.text_hash = f.text_hash AND tp.digest_key_version = f.text_digest_key_version
        JOIN public.source_version v
          ON v.organization_id = f.organization_id AND v.id = f.source_version_id
        JOIN public.source_object o
          ON o.organization_id = v.organization_id AND o.id = v.source_object_id
        JOIN public.source_version_retention vr
          ON vr.organization_id = v.organization_id AND vr.source_version_id = v.id
        JOIN public.source_extraction_retention er
          ON er.organization_id = f.organization_id AND er.extraction_id = f.extraction_id
        JOIN public.source_version_active_extraction ae
          ON ae.organization_id = f.organization_id AND ae.source_version_id = f.source_version_id
        JOIN public.source_object_scope os
          ON os.organization_id = o.organization_id AND os.source_object_id = o.id
        JOIN public.workspace w
          ON w.organization_id = f.organization_id AND w.id = p_workspace_id
        JOIN public.workspace_member wm
          ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
         AND wm.principal_id = app.current_principal_id()
         AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
        JOIN public.workspace_revision_source wrs
          ON wrs.organization_id = w.organization_id AND wrs.workspace_id = w.id
         AND wrs.workspace_revision = w.current_revision
         AND wrs.source_scope_id = os.source_scope_id
         AND wrs.source_scope_revision = os.source_scope_revision
         AND wrs.enabled
        JOIN public.workspace_managed_grant_confirmation c
          ON c.organization_id = w.organization_id AND c.workspace_id = w.id
         AND c.workspace_revision = w.current_revision
         AND c.source_scope_id = os.source_scope_id
         AND c.source_scope_revision = os.source_scope_revision
         AND c.access_mode = 'WORKSPACE_MANAGED'
        WHERE f.organization_id = app.current_organization_id()
          AND f.id = p_fragment_id
          AND f.anchor_digest_key_version IS NOT NULL
          AND app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
          AND f.text_digest_key_version IS NOT NULL
          AND app.source_keyed_digest_matches_version(f.text_hash, f.text_digest_key_version)
          AND o.lifecycle_state = 'ACTIVE'
          AND o.current_version_id = v.id
          AND v.state = 'CURRENT'
          AND vr.state = 'ACTIVE' AND vr.queryable
          AND er.state = 'ACTIVE' AND er.queryable
          AND ae.extraction_id = f.extraction_id
          AND os.membership_state = 'ACTIVE'
          AND wrs.access_mode = 'WORKSPACE_MANAGED'
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_managed_grant_revocation gr
              WHERE gr.organization_id = c.organization_id AND gr.confirmation_id = c.confirmation_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
              WHERE ar.organization_id = c.organization_id
                AND ar.grant_id = c.confirmation_actor_grant_id
          )
    );
$$;

-- ---------------------------------------------------------------------------
-- Publication gate: the active pointer must never publish a legacy or
-- partially bound Evidence set (ADR-0077 §1.3).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_active_extraction_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    extraction_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- ADR-0059/000015: a purge legitimately tears down the pointer of a
        -- version whose retention is already PURGING/PURGED, so that exact
        -- case is permitted; every other DELETE remains denied.
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
    IF EXISTS (
        SELECT 1
        FROM public.evidence_fragment f
        LEFT JOIN public.evidence_anchor_projection pa
          ON pa.organization_id = f.organization_id
         AND pa.fragment_id = f.id
         AND pa.anchor_hash = f.anchor_hash
         AND pa.digest_key_version = f.anchor_digest_key_version
        LEFT JOIN public.evidence_text_projection pt
          ON pt.organization_id = f.organization_id
         AND pt.fragment_id = f.id
         AND pt.text_hash = f.text_hash
         AND pt.digest_key_version = f.text_digest_key_version
        WHERE f.organization_id = NEW.organization_id
          AND f.extraction_id = NEW.extraction_id
          AND (
              f.anchor_digest_key_version IS NULL
              OR NOT app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
              OR pa.artifact_id IS NULL
              OR f.text_digest_key_version IS NULL
              OR NOT app.source_keyed_digest_matches_version(f.text_hash, f.text_digest_key_version)
              OR pt.artifact_id IS NULL
          )
    ) THEN
        RAISE EXCEPTION 'active extraction requires keyed anchor and text projections' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- DIGEST rotation extension (ADR-0077 §1.3): remaining count, candidate batch
-- and rewrite cover both projections; completion stays zero-remaining.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.evidence_digest_remaining_count(p_previous_version bigint)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT count(*)
    FROM public.evidence_fragment f
    JOIN public.source_version_retention r
      ON r.organization_id = f.organization_id AND r.source_version_id = f.source_version_id
    WHERE f.organization_id = app.current_organization_id()
      AND r.state NOT IN ('PURGING', 'PURGED')
      AND (
          f.anchor_digest_key_version = p_previous_version
          OR f.text_digest_key_version IS NULL
          OR f.text_digest_key_version = p_previous_version
      );
$$;

-- The 000019 candidate shape (anchor-only) changes its return row type here,
-- which CREATE OR REPLACE cannot do; drop the old signature first.
DROP FUNCTION app.evidence_digest_candidate_batch(bigint, integer);

CREATE FUNCTION app.evidence_digest_candidate_batch(
    p_previous_version bigint,
    p_limit integer
)
RETURNS TABLE(
    fragment_id text,
    anchor_artifact_id text,
    anchor_hash text,
    anchor_digest_key_version bigint,
    text_hash text,
    text_digest_key_version bigint,
    ciphertext bytea,
    size_bytes integer,
    nonce bytea,
    wrapped_dek bytea,
    wrapped_dek_hash text,
    kek_reference text,
    kek_version bigint,
    aad_hash text,
    plaintext_hash text,
    text_artifact_id text,
    text_ciphertext bytea,
    text_size_bytes integer,
    text_nonce bytea,
    text_wrapped_dek bytea,
    text_wrapped_dek_hash text,
    text_kek_reference text,
    text_kek_version bigint,
    text_aad_hash text,
    text_plaintext_hash text
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
               f.text_hash, f.text_digest_key_version,
               a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
               a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash,
               at.id, at.ciphertext, at.size_bytes, at.nonce, at.wrapped_dek, at.wrapped_dek_hash,
               at.kek_reference, at.kek_version, at.aad_hash, at.plaintext_hash
        FROM public.evidence_fragment f
        JOIN public.source_version_retention r
          ON r.organization_id = f.organization_id AND r.source_version_id = f.source_version_id
        JOIN public.encrypted_artifact a
          ON a.organization_id = f.organization_id AND a.id = f.anchor_artifact_id
         AND a.purged_at IS NULL
        JOIN public.encrypted_artifact at
          ON at.organization_id = f.organization_id AND at.id = f.normalized_text_artifact_id
         AND at.purged_at IS NULL
        WHERE f.organization_id = app.current_organization_id()
          AND r.state NOT IN ('PURGING', 'PURGED')
          AND (
              f.anchor_digest_key_version = p_previous_version
              OR f.text_digest_key_version IS NULL
              OR f.text_digest_key_version = p_previous_version
          )
        ORDER BY f.created_at, f.id
        LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION app.evidence_digest_candidate_batch(bigint, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_digest_candidate_batch(bigint, integer) TO knowvault_worker;

-- The 000019 anchor-only rewrite (six arguments) is superseded by the paired
-- seven-argument rewrite; drop the old overload so no stale path survives.
DROP FUNCTION app.evidence_digest_rewrite(text, text, bigint, text, text, bigint);

CREATE OR REPLACE FUNCTION app.evidence_digest_rewrite(
    p_fragment_id text,
    p_new_anchor_hash text,
    p_new_text_hash text,
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
        RAISE EXCEPTION 'digest rewrite anchor value is invalid' USING ERRCODE = '22023';
    END IF;
    IF p_new_text_hash IS NULL
       OR NOT app.source_keyed_digest_matches_version(p_new_text_hash, p_new_version) THEN
        RAISE EXCEPTION 'digest rewrite text value is invalid' USING ERRCODE = '22023';
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

    UPDATE public.evidence_text_projection p SET
        text_hash = p_new_text_hash,
        digest_key_version = p_new_version
    WHERE p.organization_id = organization_value AND p.fragment_id = p_fragment_id;
    IF NOT FOUND THEN
        INSERT INTO public.evidence_text_projection (
            organization_id, artifact_id, fragment_id, text_hash, digest_key_version
        )
        SELECT organization_value, normalized_text_artifact_id, id, p_new_text_hash, p_new_version
        FROM public.evidence_fragment
        WHERE organization_id = organization_value AND id = p_fragment_id
          AND normalized_text_artifact_id IS NOT NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'digest rewrite requires a bound text artifact' USING ERRCODE = '55000';
        END IF;
    END IF;

    UPDATE public.evidence_fragment f SET
        anchor_hash = p_new_anchor_hash,
        anchor_digest_key_version = p_new_version,
        text_hash = p_new_text_hash,
        text_digest_key_version = p_new_version
    WHERE f.organization_id = organization_value
      AND f.id = p_fragment_id
      AND (
          f.anchor_digest_key_version = previous_version
          OR f.text_digest_key_version IS NULL
          OR f.text_digest_key_version = previous_version
      );
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

REVOKE ALL ON FUNCTION app.evidence_digest_rewrite(text, text, text, bigint, text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_digest_rewrite(text, text, text, bigint, text, text, bigint) TO knowvault_worker;

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
    IF rotation_previous_version IS DISTINCT FROM p_previous_version THEN
        RAISE EXCEPTION 'complete version does not match the previous version of the rotation'
            USING ERRCODE = '55000';
    END IF;

    SELECT app.evidence_digest_remaining_count(rotation_previous_version) INTO remaining;
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

-- ---------------------------------------------------------------------------
-- Purge cleanup: remove both projection rows; the keyed projections inside
-- the immutable fragment rows remain as non-decryptable purge provenance
-- (ADR-0077 §1.4) and are not a usable hash oracle without the digest key.
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
    -- version (text, anchor, metadata). Idempotent: already-purged rows are
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

    -- The keyed equality projections of the purged fragments are removed; the
    -- projection rows of the version must not outlive the decryptable bytes.
    DELETE FROM public.evidence_text_projection pt
     USING public.evidence_fragment f
     WHERE pt.organization_id = f.organization_id AND pt.fragment_id = f.id
       AND f.organization_id = p_organization_id AND f.source_version_id = p_version_id;

    DELETE FROM public.evidence_anchor_projection pa
     USING public.evidence_fragment f
     WHERE pa.organization_id = f.organization_id AND pa.fragment_id = f.id
       AND f.organization_id = p_organization_id AND f.source_version_id = p_version_id;

    -- Erase both hash pairs of the purged fragments (ADR-0077 §1.4): no
    -- plain-SHA projection of content may survive in the tree.  The guards
    -- above permit exactly this purge erasure; ingestion cannot write it.
    UPDATE public.evidence_fragment f
       SET text_hash = NULL, text_digest_key_version = NULL,
           anchor_hash = NULL, anchor_digest_key_version = NULL
     WHERE f.organization_id = p_organization_id
       AND f.source_version_id = p_version_id
       AND (f.text_hash IS NOT NULL OR f.anchor_hash IS NOT NULL);

    RETURN purged_count;
END;
$$;

COMMIT;
