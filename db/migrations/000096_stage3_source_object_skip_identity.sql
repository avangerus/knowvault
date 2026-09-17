-- R3a-1 KV-A02b: the typed skip ledger keeps no plaintext native object id.
--
-- 000095 stored the connector's native object id (a git/folder relative path or
-- a mail id) in a raw typed text column. docs/ENCRYPTION.md §106 and §141
-- require a source's native object identity to be persisted as an
-- organization-scoped HMAC-SHA-256 digest plus a digest_key_version and an
-- encrypted artifact holding the identity, exactly the policy the existing
-- public.source_object model already applies to external_object_id_digest /
-- external_object_id_artifact_id.
--
-- This migration drops the raw column and adds external_id_digest,
-- digest_key_version and external_id_artifact_id. The identity artifact reuses
-- the existing closed encrypted-artifact owner tuple
-- (source_object, external_object_id_artifact_id, SOURCE_OBJECT_ID,
-- EXTERNAL_OBJECT_ID): no new (owner_table, owner_column, resource_type,
-- field_name) tuple is introduced and app.encrypted_artifact_owner_is_valid is
-- unchanged.
--
-- The identity bind/read functions are tenant-fenced SECURITY DEFINER branches
-- matching the generated source_object pair: the worker may bind an identity
-- artifact for one skip row, and the application role may read/decrypt it only
-- inside the same governed workspace inventory transaction. No runtime role
-- touches the artifact table directly.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'required runtime role knowvault_app does not exist';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_worker') THEN
        RAISE EXCEPTION 'required worker role knowvault_worker does not exist';
    END IF;
END;
$$;

-- The raw native identity is removed; identity is now the org-keyed digest plus
-- a separately sealed, encrypted artifact. The row-level security and grants
-- asserted by 000095 stay in force and are re-asserted below.
ALTER TABLE public.source_object_skip DROP CONSTRAINT source_object_skip_pkey;
DROP INDEX public.source_object_skip_workspace_lookup;
ALTER TABLE public.source_object_skip DROP COLUMN external_id;

ALTER TABLE public.source_object_skip
    ADD COLUMN external_id_digest text NOT NULL,
    ADD COLUMN digest_key_version bigint NOT NULL
        CHECK (digest_key_version BETWEEN 1 AND 999999999),
    ADD COLUMN external_id_artifact_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(external_id_artifact_id));

ALTER TABLE public.source_object_skip
    ADD CONSTRAINT source_object_skip_external_id_digest_valid
        CHECK (app.source_keyed_digest_matches_version(external_id_digest, digest_key_version)),
    ADD CONSTRAINT source_object_skip_pkey
        PRIMARY KEY (organization_id, sync_run_id, source_scope_id,
                     source_scope_revision, external_id_digest),
    ADD CONSTRAINT source_object_skip_identity_artifact_fk
        FOREIGN KEY (organization_id, external_id_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX source_object_skip_workspace_lookup
    ON public.source_object_skip (organization_id, source_scope_id, source_scope_revision, external_id_digest);

-- ---------------------------------------------------------------------------
-- Identity artifact owner branch (reuses the closed source_object tuple)
-- ---------------------------------------------------------------------------

-- Binds one sealed skip identity artifact. The resource id is the owning row's
-- opaque id (the artifact id itself), so the AAD and the encrypted_artifact
-- resource_id agree with the read path.
CREATE FUNCTION app.source_object_skip_bind_external_id(
    p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
        RAISE EXCEPTION 'resource id must equal the owning row id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
        cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'source_object', 'external_object_id_artifact_id', 'SOURCE_OBJECT_ID', p_resource_id, 'EXTERNAL_OBJECT_ID',
        'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
END;
$fn$;

-- Reads one skip identity artifact by its opaque id inside the current tenant
-- and the closed owner tuple. An unregistered, foreign or purged artifact
-- returns no row, so the caller withholds the skip fail closed.
CREATE FUNCTION app.source_object_skip_read_external_id(p_artifact_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.encrypted_artifact a
    WHERE a.organization_id = app.current_organization_id()
      AND a.id = p_artifact_id
      AND a.owner_table = 'source_object'
      AND a.owner_column = 'external_object_id_artifact_id'
      AND a.resource_type = 'SOURCE_OBJECT_ID'
      AND a.field_name = 'EXTERNAL_OBJECT_ID'
      AND a.purged_at IS NULL;
$fn$;

REVOKE ALL ON FUNCTION app.source_object_skip_bind_external_id(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.source_object_skip_read_external_id(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_object_skip_bind_external_id(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_worker;
GRANT EXECUTE ON FUNCTION app.source_object_skip_read_external_id(text) TO knowvault_app, knowvault_worker;

ALTER TABLE public.source_object_skip ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_object_skip FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.source_object_skip FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT, INSERT, UPDATE ON public.source_object_skip TO knowvault_worker;
GRANT SELECT ON public.source_object_skip TO knowvault_app;

COMMIT;
