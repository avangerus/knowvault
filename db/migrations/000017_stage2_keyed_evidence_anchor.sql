-- Stage 2 keyed Evidence anchor projection.
--
-- ENCRYPTION.md requires anchors to have an organization-scoped keyed equality
-- projection.  encrypted_artifact.plaintext_hash remains the internal SHA-256
-- integrity value used by artifactcrypto.Open; it is deliberately not reused as
-- the public Evidence anchor projection.

BEGIN;

ALTER TABLE public.evidence_fragment
    DROP CONSTRAINT evidence_fragment_anchor_hash_check;

ALTER TABLE public.evidence_fragment
    ADD COLUMN anchor_digest_key_version bigint;

-- Existing S1d rows were written before the keyed anchor projection existed.
-- NOT VALID preserves those historical rows for controlled migration, while
-- PostgreSQL still enforces the check on every new or updated row.  The read and
-- publication gates below fail closed for the historical NULL rows.
ALTER TABLE public.evidence_fragment
    ADD CONSTRAINT evidence_fragment_anchor_digest_check
    CHECK (
        anchor_digest_key_version IS NOT NULL
        AND app.source_keyed_digest_matches_version(anchor_hash, anchor_digest_key_version)
    ) NOT VALID;

CREATE TABLE public.evidence_anchor_projection (
    organization_id text NOT NULL,
    artifact_id text NOT NULL,
    fragment_id text NOT NULL,
    anchor_hash text NOT NULL,
    digest_key_version bigint NOT NULL,
    PRIMARY KEY (organization_id, artifact_id),
    UNIQUE (organization_id, fragment_id),
    CHECK (app.source_keyed_digest_matches_version(anchor_hash, digest_key_version)),
    CONSTRAINT evidence_anchor_projection_artifact_fk
        FOREIGN KEY (organization_id, artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT evidence_anchor_projection_fragment_fk
        FOREIGN KEY (organization_id, fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id)
        ON DELETE RESTRICT
);

-- The active pointer must never publish a historical or partially bound
-- Evidence set.  This is SECURITY DEFINER because the worker's direct table
-- privileges do not include the private projection table.
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
        LEFT JOIN public.evidence_anchor_projection p
          ON p.organization_id = f.organization_id
         AND p.fragment_id = f.id
         AND p.anchor_hash = f.anchor_hash
         AND p.digest_key_version = f.anchor_digest_key_version
        WHERE f.organization_id = NEW.organization_id
          AND f.extraction_id = NEW.extraction_id
          AND (
              f.anchor_digest_key_version IS NULL
              OR NOT app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
              OR p.artifact_id IS NULL
          )
    ) THEN
        RAISE EXCEPTION 'active extraction requires keyed anchor projections' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

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
            RAISE EXCEPTION 'evidence_fragment deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
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

CREATE OR REPLACE FUNCTION app.evidence_fragment_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    ok boolean;
BEGIN
    SELECT bool_and(present) INTO ok FROM (
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'normalized_text_artifact_id'
              AND a.resource_type = 'EVIDENCE_TEXT' AND a.field_name = 'NORMALIZED_TEXT'
              AND a.resource_id = NEW.id AND a.plaintext_hash = NEW.text_hash AND a.purged_at IS NULL) AS present
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

-- A 13-argument anchor bind is intentionally inert.  The extra keyed projection
-- arguments are part of the access boundary, not an optional caller convention.
CREATE OR REPLACE FUNCTION app.evidence_fragment_bind_anchor(
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
    RAISE EXCEPTION 'keyed anchor projection is required' USING ERRCODE = '23514';
END;
$$;

CREATE FUNCTION app.evidence_fragment_bind_anchor(
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
        RAISE EXCEPTION 'keyed anchor projection is invalid' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
        cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'evidence_fragment', 'anchor_artifact_id',
        'EVIDENCE_ANCHOR', p_resource_id, 'CANONICAL_ANCHOR', 'AES_256_GCM', p_ciphertext, p_size_bytes,
        p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    INSERT INTO public.evidence_anchor_projection (
        organization_id, artifact_id, fragment_id, anchor_hash, digest_key_version
    ) VALUES (
        p_org, p_artifact_id, p_owning_row_id, p_keyed_projection_digest, p_keyed_projection_key_version
    );
    UPDATE public.evidence_fragment SET anchor_artifact_id = p_artifact_id
        WHERE organization_id = p_org AND id = p_owning_row_id AND anchor_artifact_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'owning evidence_fragment missing or already bound' USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.evidence_fragment_read_normalized_text(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.evidence_fragment f
    JOIN public.encrypted_artifact a
      ON a.organization_id = f.organization_id AND a.id = f.normalized_text_artifact_id
    WHERE f.organization_id = app.current_organization_id()
      AND f.id = p_owning_row_id AND a.purged_at IS NULL
      AND app.evidence_fragment_readable(f.id, NULLIF(current_setting('app.workspace_id', true), ''));
$$;

CREATE OR REPLACE FUNCTION app.evidence_fragment_read_anchor(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.evidence_fragment f
    JOIN public.encrypted_artifact a
      ON a.organization_id = f.organization_id AND a.id = f.anchor_artifact_id
    JOIN public.evidence_anchor_projection p
      ON p.organization_id = f.organization_id AND p.artifact_id = a.id AND p.fragment_id = f.id
     AND p.anchor_hash = f.anchor_hash AND p.digest_key_version = f.anchor_digest_key_version
    WHERE f.organization_id = app.current_organization_id()
      AND f.id = p_owning_row_id
      AND f.anchor_digest_key_version IS NOT NULL
      AND app.source_keyed_digest_matches_version(f.anchor_hash, f.anchor_digest_key_version)
      AND a.purged_at IS NULL
      AND app.evidence_fragment_readable(f.id, NULLIF(current_setting('app.workspace_id', true), ''));
$$;

CREATE OR REPLACE FUNCTION app.evidence_fragment_read_metadata(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.evidence_fragment f
    JOIN public.encrypted_artifact a
      ON a.organization_id = f.organization_id AND a.id = f.metadata_artifact_id
    WHERE f.organization_id = app.current_organization_id()
      AND f.id = p_owning_row_id AND a.purged_at IS NULL
      AND app.evidence_fragment_readable(f.id, NULLIF(current_setting('app.workspace_id', true), ''));
$$;

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

REVOKE ALL ON FUNCTION app.evidence_fragment_bind_anchor(
    text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.evidence_fragment_bind_anchor(
    text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text,
    text, bigint
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_bind_anchor(
    text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text,
    text, bigint
) TO knowvault_worker;

COMMIT;
