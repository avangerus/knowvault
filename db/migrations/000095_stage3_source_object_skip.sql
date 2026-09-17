-- R3a-1 KV-A02: the durable, tenant-scoped, per-object typed skip ledger.
--
-- A sync run today collapses every skipped/quarantined object into the numeric
-- sync_run.quarantined counter. The connector already computes a typed,
-- content-free code per quarantined object (observation.Quarantine /
-- folder.QuarantineNotice), and the extraction phase quarantines objects with
-- no code at all. This table records one row per skipped object of one sync run
-- with a CHECK-closed reason code, so the workspace inventory can report the
-- skipped items and their reasons in addition to the readable rows.
--
-- The ledger is additive and append-only in practice: identity is
-- (organization_id, sync_run_id, source_scope_id, source_scope_revision,
-- external_id), so a re-run writes a fresh row set under its own sync run and
-- never rewrites history. DELETE is not granted.
--
-- The reason_code set is closed here and mirrored by Go validation in
-- internal/ingestion (sourceObjectSkipReason). It contains every quarantine
-- code the folder, git, mail and upload connectors compute today plus the
-- distinct extraction-phase code and one closed fallback for an unknown
-- connector code, so a new upstream code can never fail a whole sync run.

BEGIN;

CREATE TABLE public.source_object_skip (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    sync_run_id text NOT NULL,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL
        CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    external_id text NOT NULL CHECK (char_length(external_id) BETWEEN 1 AND 4096),
    reason_code text NOT NULL CHECK (reason_code IN (
        'FOLDER_SYMLINK_REJECTED',
        'FOLDER_NON_REGULAR',
        'FOLDER_OBJECT_OVERSIZED',
        'FOLDER_UNSUPPORTED_TYPE',
        'FOLDER_MEDIA_SIGNATURE_MISMATCH',
        'FOLDER_INVALID_UTF8',
        'TORN_READ_VERSION_MISMATCH',
        'FOLDER_ACL_UNKNOWN',
        'FOLDER_CONTAINMENT_VIOLATION',
        'GIT_UNSUPPORTED_MEDIA_TYPE',
        'GIT_BLOB_OVERSIZED',
        'GIT_INVALID_UTF8',
        'GIT_BLOB_ID_MISMATCH',
        'GIT_BLOB_READ_FAILED',
        'MAIL_MESSAGE_MALFORMED',
        'MAIL_MESSAGE_OVERSIZED',
        'MAIL_ATTACHMENT_OVERSIZED',
        'MAIL_ATTACHMENT_UNSUPPORTED_MEDIA_TYPE',
        'MAIL_ATTACHMENT_MALFORMED',
        'MAIL_MESSAGE_READ_FAILED',
        'UPLOAD_OBJECT_OVERSIZED',
        'INGEST_EXTRACTION_SKIPPED',
        'INGEST_SKIP_REASON_UNKNOWN'
    )),
    observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, sync_run_id, source_scope_id,
                 source_scope_revision, external_id),
    CONSTRAINT source_object_skip_sync_run_fk
        FOREIGN KEY (organization_id, sync_run_id)
        REFERENCES public.sync_run (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT source_object_skip_scope_revision_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision)
        ON DELETE RESTRICT
);

CREATE INDEX source_object_skip_workspace_lookup
    ON public.source_object_skip (organization_id, source_scope_id, source_scope_revision, external_id);

ALTER TABLE public.source_object_skip ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_object_skip FORCE ROW LEVEL SECURITY;
CREATE POLICY source_object_skip_tenant_isolation
    ON public.source_object_skip
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_object_skip
    FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT, INSERT, UPDATE ON public.source_object_skip TO knowvault_worker;
GRANT SELECT ON public.source_object_skip TO knowvault_app;

COMMIT;
