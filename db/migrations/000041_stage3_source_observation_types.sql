-- Stage 3 source-agnostic observation catalog types.
--
-- Git blobs and IMAP messages/attachments use the same SourceObject /
-- SourceVersion / Extraction / Evidence publication path as folder documents.
-- Their connector-owned identities are already bounded by the observation
-- contract; this migration only widens the immutable catalog enum and records
-- the source-scope contract versions that a deployment may qualify.  No source
-- is activated by this migration and no credential or raw locator is stored.

BEGIN;

ALTER TABLE public.source_scope_revision
    DROP CONSTRAINT source_scope_revision_scope_contract_version_check,
    ADD CONSTRAINT source_scope_revision_scope_contract_version_check
        CHECK (scope_contract_version IN ('1.2', 'postgresql-query-v1', 'git-v1', 'imap-v1'));

ALTER TABLE public.source_object
    DROP CONSTRAINT source_object_object_type_check,
    ADD CONSTRAINT source_object_object_type_check
        CHECK (object_type IN ('FILE', 'POSTGRESQL_QUERY_ROW', 'GIT_FILE', 'EMAIL', 'EMAIL_ATTACHMENT'));

COMMIT;
