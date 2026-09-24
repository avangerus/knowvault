-- ADR-0097's knowvault_source_sql tool (S3 card 2) executes with the source's
-- own QUERY credential, which must stay distinct from the ingestion credential
-- the discovery/ingestion worker resolves. This migration adds that second,
-- optional and opaque reference to the immutable connection revision:
--
--   * NULL means "this connection has no query credential", which the tool
--     reports as SOURCE_SQL_NOT_CONFIGURED and the Sources card as
--     "SQL not configured"; it is never inferred from the ingestion reference.
--   * A non-NULL value is the same opaque worker-mounted secret reference
--     shape the ingestion reference already uses (a 'cred' generated id), so
--     the control plane stores only a reference and never a DSN or a password.
--
-- The column is additive and nullable, so every existing revision keeps its
-- exact meaning and no backfill or rewrite is needed. Registration verifies
-- that the referenced role is read-only and column-narrowed per ADR-0097; that
-- verification is a registration-time obligation, not part of this schema
-- change.

ALTER TABLE public.source_connection_revision
    ADD COLUMN query_credential_reference text
        CHECK (
            query_credential_reference IS NULL
            OR app.source_generated_id_is_valid(query_credential_reference, 'cred')
        );

COMMENT ON COLUMN public.source_connection_revision.query_credential_reference IS
    'ADR-0097 optional opaque reference to the source''s read-only query credential; NULL means knowvault_source_sql answers SOURCE_SQL_NOT_CONFIGURED. Never a DSN or secret value.';
