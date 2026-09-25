-- S3 card 2c: security hardening of ADR-0097's knowvault_source_sql.
--
-- The database role is the security boundary (ADR-0097 §3), so the server must
-- prove the query role is least privilege before any agent-authored statement
-- runs and remember that proof for the exact (connection revision, query
-- credential revision, registered projection) pair. This migration adds the two
-- schema pieces that make that proof enforceable and durable:
--
--   * public.source_query_credential_verification stores one content-free row
--     per source connection: the connection revision, the query-credential
--     revision, the registered-projection hash and the content-free role
--     digest the server proved. Any change to the connection revision or the
--     credential revision makes the row stale and forces a fresh proof; the
--     registration columns themselves are unchanged.
--   * the query credential reference can never equal the ingestion credential
--     reference, enforced for every writer: a same-row CHECK on the immutable
--     source_connection_revision.query_credential_reference column (000116) and
--     a trigger on the mutable public.source_query_credential table, which is
--     the runtime control of migration 000117.
--
-- No secret value is stored here: both references are opaque 'cred' ids and the
-- digest is a sha256 of server-owned catalogue facts, never a DSN, a password,
-- a relation name or a row.

BEGIN;

-- Query credential § ingestion separation — immutable revision column.
ALTER TABLE public.source_connection_revision
    ADD CONSTRAINT source_connection_revision_query_credential_distinct
        CHECK (
            query_credential_reference IS NULL
            OR query_credential_reference <> credential_reference
        );

-- Query credential § ingestion separation — mutable control table.
CREATE OR REPLACE FUNCTION app.source_query_credential_separation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.source_connection_revision AS revision
        WHERE revision.organization_id = NEW.organization_id
          AND revision.connection_id = NEW.connection_id
          AND revision.credential_reference = NEW.credential_reference
    ) THEN
        RAISE EXCEPTION 'the query credential must differ from the ingestion credential'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_query_credential_separation_guard
    BEFORE INSERT OR UPDATE ON public.source_query_credential
    FOR EACH ROW EXECUTE FUNCTION app.source_query_credential_separation_guard();

-- Query credential § least-privilege proof cache.
CREATE TABLE public.source_query_credential_verification (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    connection_id text NOT NULL,
    -- The exact connection revision the source scope is pinned to.
    connection_revision bigint NOT NULL CHECK (connection_revision BETWEEN 1 AND 9007199254740991),
    -- The exact credential control revision (000117's monotonic counter).
    credential_revision bigint NOT NULL CHECK (credential_revision BETWEEN 1 AND 9007199254740991),
    -- Content-free hash of the registered projection (schema, table, columns).
    scope_hash text NOT NULL CHECK (app.workspace_command_hash_is_valid(scope_hash)),
    -- Content-free digest of the proven role + projection.
    role_digest text NOT NULL CHECK (app.workspace_command_hash_is_valid(role_digest)),
    verified_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, connection_id),
    CONSTRAINT source_query_credential_verification_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id)
        ON DELETE RESTRICT
);

COMMENT ON TABLE public.source_query_credential_verification IS
    'ADR-0097 least-privilege proof cache: one content-free row per connection naming the connection revision, credential revision, projection hash and proven role digest. A stale row (either revision or the projection changed) forces a fresh proof before knowvault_source_sql may run. Never a DSN, secret, relation name or row.';

ALTER TABLE public.source_query_credential_verification ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.source_query_credential_verification FORCE ROW LEVEL SECURITY;
CREATE POLICY source_query_credential_verification_tenant_isolation
    ON public.source_query_credential_verification
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.source_query_credential_verification FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.source_query_credential_verification TO knowvault_app;

-- Audit § governed-query purpose. Card 2c records the bounded agent note that
-- describes what a SQL statement answers. It is an optional, closed-set member
-- of the governed-query vocabulary, so the metadata whitelist (last replaced by
-- 000069) is reissued with exactly one added key; every other key and the whole
-- function body are unchanged.
CREATE OR REPLACE FUNCTION app.audit_metadata_is_allowed(metadata jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT jsonb_typeof(metadata) = 'object'
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_object_keys(metadata) AS metadata_key
           WHERE metadata_key NOT IN (
               'workspace_revision', 'workspace_source_id',
               'source_scope_id', 'source_scope_revision',
               'scope_config_hash', 'access_mode', 'enabled',
               'source_connection_id', 'connector_job_id', 'sync_run_id',
               'question_run_id', 'model_run_id', 'citation_number',
               'manifest_hash', 'policy_revision', 'reason_codes',
               'remote_address_digest', 'user_agent_family',
               -- Authority command vocabulary (ADR-0053).
               'authority_operation', 'authority_result_id', 'authority_result_hash',
               'authority_parent_id', 'authority_parent_hash',
               'authority_revocation_id', 'authority_revocation_hash',
               'authority_reason_code', 'target_principal_id',
               'workspace_configuration_hash', 'confirmation_actor_grant_id',
               'confirmation_actor_grant_revision', 'confirmation_actor_grant_hash',
               'warning_version', 'warning_contract_hash', 'acknowledgement_code',
               -- Rotation vocabulary (ADR-0070).
               'rotation_domain', 'key_reference', 'key_version',
               -- Amendment vocabulary (ADR-0076).
               'answer_document_version', 'amendment_class',
               -- Connection trust verification vocabulary (ADR-0087 §2).
               'trust_verification_id', 'trust_verification_hash',
               -- Governed query attempt vocabulary (ADR-0089 §4, S3 card 2c).
               'governed_query_connection_id', 'governed_query_exposed_schema_revision',
               'governed_query_sql_hash', 'governed_query_cost_estimate',
               'governed_query_row_count', 'governed_query_result_digest',
               'governed_query_outcome', 'governed_query_purpose'
           )
       );
$$;

COMMIT;
