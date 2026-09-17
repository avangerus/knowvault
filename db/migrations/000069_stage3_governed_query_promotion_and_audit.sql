-- ADR-0089 §5 (promotion to a scheduled projection) and §4 (audit
-- vocabulary). This migration adds the durable, content-free promotion
-- record for internal/source/postgresqlquery/governedquery.PromoteToProjection
-- and extends the closed audit metadata key allowlist
-- (app.audit_metadata_is_allowed) with the governed-query attempt vocabulary,
-- following the exact cumulative-redefinition discipline every prior
-- extension of that function used (000009/000011/000019/000022/000057).

BEGIN;

CREATE TABLE public.governed_query_promotion (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    connection_id text NOT NULL,
    -- sql_hash is the only trace of the promoted SQL text kept here; the
    -- text itself is not this migration's concern (ADR-0089 §5: the operator
    -- becomes the projection's view author through the unmodified ADR-0078
    -- registration path, not through this record).
    sql_hash text NOT NULL CHECK (sql_hash ~ '^sha256:[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status = 'RECORDED_PENDING_INTEGRATION'),
    promoted_by text NOT NULL,
    promoted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT governed_query_promotion_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.governed_query_connection (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT governed_query_promotion_actor_fk
        FOREIGN KEY (organization_id, promoted_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION app.governed_query_promotion_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'governed_query_promotion is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER governed_query_promotion_immutable
BEFORE UPDATE OR DELETE ON public.governed_query_promotion
FOR EACH ROW EXECUTE FUNCTION app.governed_query_promotion_guard();

ALTER TABLE public.governed_query_promotion ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.governed_query_promotion FORCE ROW LEVEL SECURITY;
CREATE POLICY governed_query_promotion_tenant_isolation ON public.governed_query_promotion
    USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.governed_query_promotion FROM PUBLIC;
GRANT SELECT, INSERT ON public.governed_query_promotion TO knowvault_app;

-- ---------------------------------------------------------------------------
-- Audit metadata allowlist: add the governed-query attempt vocabulary
-- (ADR-0089 §4) to the closed key set. Every value stays content-free
-- (server-owned ids, hashes, counts, a fixed cost number and a closed
-- outcome code) -- never SQL text, row values or a raw database error.
-- ---------------------------------------------------------------------------

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
               -- Governed query attempt vocabulary (ADR-0089 §4).
               'governed_query_connection_id', 'governed_query_exposed_schema_revision',
               'governed_query_sql_hash', 'governed_query_cost_estimate',
               'governed_query_row_count', 'governed_query_result_digest',
               'governed_query_outcome'
           )
       );
$$;

COMMIT;
