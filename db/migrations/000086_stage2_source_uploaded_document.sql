-- UPL-1: browser document upload.
--
-- The owner complaint was that adding a documents source demanded root_alias,
-- root_identity and a column contract before a single file could be seen.
-- This checkpoint lets a workspace owner drop files or a folder straight from
-- the browser: the FOLDER connection/scope is still registered exactly as
-- before (ADR-0074), but with server-fixed root_alias='browser-uploads' and
-- root_identity='managed' the owner never types, and the bytes the owner
-- drags in land here instead of a pre-mounted host directory. The ingestion
-- worker recognizes that reserved (root_alias, root_identity) tuple and reads
-- this table instead of the worker mount registry (internal/ingestion
-- handler.go), so every other FOLDER invariant -- format allowlist, per-file
-- size cap, immutable Extraction, Evidence anchor -- is unchanged.
--
-- One row is the current bytes of one sanitized object_key inside one FOLDER
-- connection. A second upload of the same object_key is a new version of the
-- same object (UPSERT increments version), never a second source: the
-- ingestion discovery pass keys objects by object_key, so a re-upload
-- produces a new immutable SourceVersion of the same SourceObject, exactly
-- like a changed file on a real mounted folder.

BEGIN;

-- Resolves a source_scope_id to its owning connection without letting the
-- upload write path touch public.source_scope/public.source_connection with
-- raw SQL from Go (the same command/audit-gate boundary
-- internal/workspace/repository/source_commands.go is the sole exception to;
-- scripts/check-architecture.go's checkStage1DatabaseGate enforces this by
-- scanning every other .go file for a direct query on those tables).
-- registration.Service.UploadDocuments calls this instead, exactly like the
-- existing app.source_scope_sync_target the ingestion worker uses.
CREATE OR REPLACE FUNCTION app.source_scope_upload_target(p_scope_id text)
RETURNS TABLE(connection_id text, source_type text, created_by text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT connection.id, connection.type, connection.created_by
    FROM public.source_scope AS scope
    JOIN public.source_connection AS connection
      ON connection.organization_id = scope.organization_id AND connection.id = scope.connection_id
    WHERE scope.organization_id = app.current_organization_id() AND scope.id = p_scope_id;
$$;

REVOKE ALL ON FUNCTION app.source_scope_upload_target(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.source_scope_upload_target(text) TO knowvault_app;

CREATE TABLE public.source_uploaded_document (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    connection_id text NOT NULL,
    -- object_key is the sanitized, extension-preserving file name validated by
    -- internal/source/upload before this row is ever written: no path
    -- separator, no control character, no "." or ".." segment, bounded length.
    object_key text NOT NULL CHECK (
        char_length(object_key) BETWEEN 1 AND 300
        AND object_key !~ '[[:cntrl:]]'
        AND object_key !~ '/'
        AND object_key !~ '\\'
        AND object_key NOT IN ('.', '..')
    ),
    version bigint NOT NULL DEFAULT 1 CHECK (version BETWEEN 1 AND 9007199254740991),
    declared_format text NOT NULL CHECK (
        declared_format IN ('PDF', 'DOCX', 'PPTX', 'XLSX', 'TXT', 'MARKDOWN', 'HTML', 'CSV')
    ),
    media_type text NOT NULL CHECK (char_length(media_type) BETWEEN 1 AND 128),
    media_family text NOT NULL CHECK (media_family IN ('TEXT', 'PDF', 'OOXML')),
    byte_size bigint NOT NULL CHECK (byte_size BETWEEN 0 AND 1073741824),
    content_sha256 text NOT NULL CHECK (app.stage2_sha256_is_valid(content_sha256)),
    content bytea NOT NULL,
    uploaded_by text NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, connection_id, object_key),
    CONSTRAINT source_uploaded_document_byte_size_matches_content
        CHECK (byte_size = octet_length(content)),
    CONSTRAINT source_uploaded_document_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id)
        ON DELETE CASCADE,
    CONSTRAINT source_uploaded_document_actor_fk
        FOREIGN KEY (organization_id, uploaded_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

-- The ingestion worker reads every current object of one connection each
-- sync; this is its only access path.
CREATE INDEX source_uploaded_document_connection
    ON public.source_uploaded_document (organization_id, connection_id);

ALTER TABLE public.source_uploaded_document ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_uploaded_document FORCE ROW LEVEL SECURITY;
CREATE POLICY source_uploaded_document_tenant_isolation
    ON public.source_uploaded_document
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_uploaded_document FROM PUBLIC;
-- knowvault_app is the web/API runtime role: it owns the upload write path
-- (registration.Service.UploadDocuments) and never deletes a row itself --
-- a re-upload is UPDATE (new version), and object lifecycle otherwise follows
-- the connection's own CASCADE. knowvault_worker only reads content to
-- observe objects during a SOURCE_SCOPE_SYNC job.
GRANT SELECT, INSERT, UPDATE ON TABLE public.source_uploaded_document TO knowvault_app;
GRANT SELECT ON TABLE public.source_uploaded_document TO knowvault_worker;

COMMIT;
