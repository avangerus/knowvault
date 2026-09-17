-- 000083: FIX-4 #1 needs each ambiguous structured source scope's own
-- owner-declared display name (source_connection.name, the exact string the
-- "Sources" UI already shows) to name candidates in AGG-1's clarifying
-- refusal when more than one enabled structured source can resolve a
-- question and neither retrieval nor the declared name/column tie-break
-- picks one (internal/question/snapshot_aggregate.go's
-- disambiguateStructuredScopeByName / persistAmbiguousStructuredSourceRefusal,
-- via structuredScopeNames).
--
-- check-architecture.go's source-scope guard forbids Go code selecting
-- straight from source_scope_revision/source_connection outside the accepted
-- command/audit gate (ADR-0053's confirm/trust boundary), so this is a
-- narrow, read-only SECURITY DEFINER getter in the same family as
-- app.evidence_fragment_readable: it discloses only a name already visible
-- to any workspace member through the ordinary "Sources" listing -- never
-- credentials, connector configuration or trust state -- and it is gated on
-- the same workspace-membership check evidence_fragment_readable already
-- applies before disclosing anything.

BEGIN;

CREATE OR REPLACE FUNCTION app.structured_source_scope_names(p_workspace_id text, p_scope_ids text[])
RETURNS TABLE(source_scope_id text, name text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT DISTINCT ON (revision.source_scope_id) revision.source_scope_id, connection.name
      FROM public.source_scope_revision AS revision
      JOIN public.source_connection AS connection
        ON connection.organization_id = revision.organization_id
       AND connection.id = revision.connection_id
     WHERE revision.organization_id = app.current_organization_id()
       AND revision.source_scope_id = ANY(p_scope_ids)
       AND EXISTS (
           SELECT 1
             FROM public.workspace_member wm
            WHERE wm.organization_id = app.current_organization_id()
              AND wm.workspace_id = p_workspace_id
              AND wm.principal_id = app.current_principal_id()
              AND wm.valid_to_revision IS NULL
              AND wm.removed_at IS NULL
       )
     ORDER BY revision.source_scope_id, revision.revision DESC
$$;

REVOKE ALL ON FUNCTION app.structured_source_scope_names(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.structured_source_scope_names(text, text[]) TO knowvault_app;

COMMIT;
