-- Exact layout metadata has the same access point as exact text and anchors.
-- The caller must select both the workspace and immutable source version.
BEGIN;

CREATE OR REPLACE FUNCTION app.evidence_fragment_read_exact_metadata(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.evidence_fragment f
    JOIN public.encrypted_artifact a
      ON a.organization_id = f.organization_id AND a.id = f.metadata_artifact_id
    WHERE f.organization_id = app.current_organization_id()
      AND f.id = p_owning_row_id
      AND f.source_version_id = NULLIF(current_setting('app.evidence_source_version_id', true), '')
      AND a.purged_at IS NULL
      AND app.evidence_fragment_exact_readable(
          f.id, NULLIF(current_setting('app.workspace_id', true), ''), f.source_version_id);
$$;

REVOKE ALL ON FUNCTION app.evidence_fragment_read_exact_metadata(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.evidence_fragment_read_exact_metadata(text) TO knowvault_app;

COMMIT;
