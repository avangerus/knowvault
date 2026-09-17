-- Encrypted-artifact containment.
--
-- Removes the runtime role's raw access to public.encrypted_artifact. After this
-- migration the runtime cannot SELECT or INSERT the table directly: the string
-- "encrypted_artifact" is only an anti-drift signal, while this REVOKE is the
-- security boundary. Every artifact write and read must flow through a
-- per-activated-branch SECURITY DEFINER function that proves, in one
-- transaction, the exact owning row, the tenant, the single permitted operation
-- and the transactional binding of owning row and artifact.
--
-- No owner branch is activated here. Each of the 26 closed owner branches stays
-- inert until its owning relation ships its own bind/read SECURITY DEFINER
-- functions (owning_table.<column> composite foreign key to
-- encrypted_artifact(organization_id, id)), its authorization resolver and its
-- negative tests. Until then artifact persistence is inert and a committed
-- artifact without its exact owning relation is technically impossible.

REVOKE SELECT, INSERT ON public.encrypted_artifact FROM knowvault_app;

-- Readiness preflight. Counts active artifacts for the current tenant that are
-- not sealed under the supplied key reference/version. A non-zero result means
-- an active artifact exists under an unavailable or historical key, so the
-- runtime must fail closed at startup rather than serve undecryptable content.
-- The function returns only a count and never discloses artifact content.
CREATE FUNCTION app.artifact_unavailable_key_count(expected_reference text, expected_version bigint)
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
      AND (kek_reference, kek_version) IS DISTINCT FROM (expected_reference, expected_version);
$$;

REVOKE ALL ON FUNCTION app.artifact_unavailable_key_count(text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.artifact_unavailable_key_count(text, bigint) TO knowvault_app;
