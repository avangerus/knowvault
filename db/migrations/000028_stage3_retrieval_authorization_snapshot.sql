-- Stage 3 retrieval authorization snapshot persistence.
--
-- These relations are a durable provenance boundary only.  They do not make
-- OpenSearch, a model runtime or a search endpoint active.  Every row is
-- tenant-bound and immutable after capture; the final authorization decision
-- remains a PostgreSQL projection, never an index-side filter.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'runtime role knowvault_app must exist before this migration';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.retrieval_snapshot_error_codes_valid(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    item jsonb;
    code text;
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array'
       OR jsonb_array_length(value) > 32
       OR octet_length(value::text) > 4096 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value_item FROM jsonb_array_elements(value) AS row(value_item)
    LOOP
        IF jsonb_typeof(item) <> 'string' THEN RETURN false; END IF;
        code := item #>> '{}';
        IF code !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION app.retrieval_hmac_digest_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND value ~ '^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$';
$$;

-- The active-extraction pointer is already unique by (tenant, version).  This
-- redundant exact-child key lets retrieval entries carry a composite FK for
-- lineage without weakening that one-pointer invariant.
ALTER TABLE public.source_version_active_extraction
    ADD CONSTRAINT source_version_active_extraction_exact_child_key
    UNIQUE (organization_id, source_version_id, extraction_id);

CREATE TABLE public.question_corpus_snapshot (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    question_run_id text NOT NULL,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    access_mode text NOT NULL CHECK (access_mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')),
    scope_config_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(scope_config_hash)),
    connector_type text NOT NULL CHECK (connector_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE')),
    connector_version text NOT NULL CHECK (
        char_length(connector_version) BETWEEN 1 AND 128
        AND btrim(connector_version) = connector_version
        AND connector_version !~ '[[:cntrl:]]'
    ),
    health text NOT NULL CHECK (health IN ('HEALTHY', 'STALE', 'FAILED', 'UNKNOWN', 'DISABLED')),
    content_watermark bigint NOT NULL CHECK (content_watermark BETWEEN 0 AND 9007199254740991),
    last_successful_sync timestamptz,
    acl_fresh_at timestamptz,
    captured_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, question_run_id, source_scope_id, source_scope_revision),
    CONSTRAINT question_corpus_snapshot_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_corpus_snapshot_scope_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision)
        ON DELETE RESTRICT,
    CHECK (last_successful_sync IS NULL OR last_successful_sync <= captured_at),
    CHECK (acl_fresh_at IS NULL OR acl_fresh_at <= captured_at)
);

CREATE TABLE public.question_authorized_candidate_set (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    question_run_id text NOT NULL,
    schema_version text NOT NULL DEFAULT 'authorized-candidate-set-v1'
        CHECK (schema_version = 'authorized-candidate-set-v1'),
    candidate_count bigint NOT NULL CHECK (candidate_count BETWEEN 0 AND 9007199254740991),
    canonical_artifact_id text CHECK (
        canonical_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(canonical_artifact_id)
    ),
    candidate_set_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(candidate_set_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, question_run_id),
    CONSTRAINT question_candidate_set_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_candidate_set_artifact_fk
        FOREIGN KEY (organization_id, canonical_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE public.question_authorized_candidate (
    organization_id text NOT NULL,
    question_run_id text NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 1 AND 9007199254740991),
    evidence_fragment_id text NOT NULL,
    source_version_id text NOT NULL,
    extraction_id text NOT NULL,
    evidence_text_hash text NOT NULL CHECK (app.retrieval_hmac_digest_is_valid(evidence_text_hash)),
    exact_context_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(exact_context_hash)),
    authorization_grant_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(authorization_grant_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, question_run_id, ordinal),
    CONSTRAINT question_candidate_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_candidate_fragment_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_candidate_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_candidate_extraction_fk
        FOREIGN KEY (organization_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, id) ON DELETE RESTRICT
);

CREATE TABLE public.question_retrieval_context_entry (
    organization_id text NOT NULL,
    question_run_id text NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 1 AND 9007199254740991),
    source_object_id text NOT NULL,
    source_version_id text NOT NULL,
    source_version_state text NOT NULL CHECK (source_version_state IN ('PENDING', 'CURRENT', 'SUPERSEDED', 'DELETED', 'REDACTED')),
    source_version_retention_state text NOT NULL CHECK (source_version_retention_state IN ('ACTIVE', 'PURGING', 'PURGED')),
    source_version_queryable boolean NOT NULL,
    source_version_retention_fence bigint NOT NULL CHECK (source_version_retention_fence >= 0),
    extraction_id text NOT NULL,
    active_extraction_id text NOT NULL,
    activation_revision bigint NOT NULL CHECK (activation_revision >= 1),
    extraction_retention_state text NOT NULL CHECK (extraction_retention_state IN ('ACTIVE', 'PURGING', 'PURGED')),
    extraction_queryable boolean NOT NULL,
    extraction_retention_fence_at_start bigint NOT NULL CHECK (extraction_retention_fence_at_start >= 0),
    evidence_fragment_id text NOT NULL,
    extraction_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(extraction_profile_hash)),
    source_version_content_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(source_version_content_hash)),
    evidence_text_hash text NOT NULL CHECK (app.retrieval_hmac_digest_is_valid(evidence_text_hash)),
    anchor_hash text NOT NULL CHECK (app.retrieval_hmac_digest_is_valid(anchor_hash)),
    exact_context_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(exact_context_hash)),
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision >= 1),
    access_mode text NOT NULL CHECK (access_mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')),
    membership_state text NOT NULL CHECK (membership_state IN ('ACTIVE', 'MOVED', 'REMOVED')),
    policy_decision_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_decision_id)),
    policy_decision text NOT NULL CHECK (policy_decision IN ('ALLOW', 'DENY')),
    principal_set_snapshot_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(principal_set_snapshot_id)),
    principal_set_snapshot_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(principal_set_snapshot_hash)),
    principal_set_captured_at timestamptz NOT NULL,
    principal_set_expires_at timestamptz NOT NULL,
    authorized_at timestamptz NOT NULL,
    acl_snapshot_id text CHECK (acl_snapshot_id IS NULL OR app.stage2_opaque_id_is_valid(acl_snapshot_id)),
    acl_snapshot_hash text CHECK (acl_snapshot_hash IS NULL OR app.stage2_sha256_is_valid(acl_snapshot_hash)),
    acl_snapshot_status text CHECK (acl_snapshot_status IS NULL OR acl_snapshot_status IN ('RESOLVED', 'STALE', 'FAILED', 'UNKNOWN')),
    acl_resolved_at timestamptz,
    acl_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, question_run_id, ordinal),
    CONSTRAINT question_context_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_context_object_fk
        FOREIGN KEY (organization_id, source_object_id)
        REFERENCES public.source_object (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_context_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_context_extraction_fk
        FOREIGN KEY (organization_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_context_active_extraction_fk
        FOREIGN KEY (organization_id, source_version_id, active_extraction_id)
        REFERENCES public.source_version_active_extraction (organization_id, source_version_id, extraction_id)
        ON DELETE RESTRICT,
    CONSTRAINT question_context_fragment_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_context_scope_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT question_context_acl_fk
        FOREIGN KEY (organization_id, acl_snapshot_id)
        REFERENCES public.acl_snapshot (organization_id, id) ON DELETE RESTRICT,
    CHECK (principal_set_expires_at > principal_set_captured_at),
    CHECK (authorized_at >= principal_set_captured_at AND authorized_at < principal_set_expires_at),
    CHECK ((acl_snapshot_id IS NULL AND acl_snapshot_hash IS NULL AND acl_snapshot_status IS NULL
            AND acl_resolved_at IS NULL AND acl_expires_at IS NULL)
           OR (acl_snapshot_id IS NOT NULL AND acl_snapshot_hash IS NOT NULL
               AND acl_snapshot_status IS NOT NULL AND acl_resolved_at IS NOT NULL
               AND acl_expires_at IS NOT NULL AND acl_expires_at > acl_resolved_at
               AND acl_snapshot_status = 'RESOLVED')),
    CHECK ((access_mode = 'WORKSPACE_MANAGED'
            AND acl_snapshot_id IS NULL AND acl_snapshot_hash IS NULL
            AND acl_snapshot_status IS NULL AND acl_resolved_at IS NULL AND acl_expires_at IS NULL)
           OR (access_mode = 'SOURCE_ENFORCED' AND acl_snapshot_id IS NOT NULL)),
    CHECK (policy_decision = 'ALLOW'),
    CHECK (membership_state = 'ACTIVE'),
    CHECK (source_version_retention_state = 'ACTIVE' AND source_version_queryable),
    CHECK (extraction_retention_state = 'ACTIVE' AND extraction_queryable)
);

CREATE TABLE public.question_retrieval_authorization_snapshot (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    question_run_id text NOT NULL,
    schema_version text NOT NULL DEFAULT 'retrieval-authorization-snapshot-v1'
        CHECK (schema_version = 'retrieval-authorization-snapshot-v1'),
    captured_at timestamptz NOT NULL,
    pipeline_version text NOT NULL CHECK (char_length(pipeline_version) BETWEEN 1 AND 128 AND pipeline_version !~ '[[:cntrl:]]'),
    pipeline_profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(pipeline_profile_hash)),
    model_execution_plan_hash text CHECK (model_execution_plan_hash IS NULL OR app.stage2_sha256_is_valid(model_execution_plan_hash)),
    embedding_model_run_id text CHECK (embedding_model_run_id IS NULL OR app.stage2_opaque_id_is_valid(embedding_model_run_id)),
    embedding_output_hash text CHECK (embedding_output_hash IS NULL OR app.stage2_sha256_is_valid(embedding_output_hash)),
    authorized_candidate_set_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(authorized_candidate_set_hash)),
    reranking_model_run_id text CHECK (reranking_model_run_id IS NULL OR app.stage2_opaque_id_is_valid(reranking_model_run_id)),
    reranking_output_hash text CHECK (reranking_output_hash IS NULL OR app.stage2_sha256_is_valid(reranking_output_hash)),
    authorized_candidate_count bigint NOT NULL CHECK (authorized_candidate_count BETWEEN 0 AND 9007199254740991),
    context_count bigint NOT NULL CHECK (context_count BETWEEN 0 AND 9007199254740991),
    truncated boolean NOT NULL,
    truncation_reason text,
    error_codes_json jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (app.retrieval_snapshot_error_codes_valid(error_codes_json)),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 1048576),
    snapshot_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(snapshot_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, question_run_id),
    CONSTRAINT question_retrieval_snapshot_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CHECK ((truncated AND truncation_reason IS NOT NULL AND char_length(truncation_reason) BETWEEN 1 AND 128)
           OR (NOT truncated AND truncation_reason IS NULL)),
    CHECK ((embedding_model_run_id IS NULL) = (embedding_output_hash IS NULL)),
    CHECK ((reranking_model_run_id IS NULL) = (reranking_output_hash IS NULL))
);

CREATE INDEX question_corpus_snapshot_run_order
    ON public.question_corpus_snapshot (organization_id, question_run_id, source_scope_id, source_scope_revision);
CREATE INDEX question_authorized_candidate_evidence
    ON public.question_authorized_candidate (organization_id, evidence_fragment_id, question_run_id, ordinal);
CREATE INDEX question_context_evidence
    ON public.question_retrieval_context_entry (organization_id, evidence_fragment_id, question_run_id, ordinal);

CREATE OR REPLACE FUNCTION app.question_corpus_snapshot_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_row public.question_run%ROWTYPE;
    binding_row public.workspace_revision_source%ROWTYPE;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'question corpus snapshots are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'question corpus snapshot requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO run_row
      FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    IF NOT FOUND OR run_row.result_status NOT IN ('QUEUED', 'RUNNING')
       OR NEW.captured_at IS DISTINCT FROM run_row.started_at THEN
        RAISE EXCEPTION 'question corpus snapshot is outside the active question interval' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO binding_row
      FROM public.workspace_revision_source
     WHERE organization_id = NEW.organization_id
       AND workspace_id = run_row.workspace_id
       AND workspace_revision = run_row.workspace_revision
       AND source_scope_id = NEW.source_scope_id
       AND source_scope_revision = NEW.source_scope_revision
       AND scope_config_hash = NEW.scope_config_hash
       AND access_mode = NEW.access_mode
       AND enabled;
    IF NOT FOUND OR binding_row.source_scope_id IS DISTINCT FROM NEW.source_scope_id THEN
        RAISE EXCEPTION 'question corpus snapshot is not an exact enabled workspace binding' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.source_scope_revision scope_revision
        WHERE scope_revision.organization_id = NEW.organization_id
          AND scope_revision.source_scope_id = NEW.source_scope_id
          AND scope_revision.revision = NEW.source_scope_revision
          AND scope_revision.source_type = NEW.connector_type
    ) THEN
        RAISE EXCEPTION 'question corpus snapshot connector type is not authoritative' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_candidate_set_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    status_value text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'authorized candidate sets are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'authorized candidate set requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT result_status INTO status_value FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    IF status_value IS NULL OR status_value NOT IN ('QUEUED', 'RUNNING') THEN
        RAISE EXCEPTION 'authorized candidate set requires an active question run' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.organization_id IS DISTINCT FROM NEW.organization_id
           OR OLD.question_run_id IS DISTINCT FROM NEW.question_run_id
           OR OLD.schema_version IS DISTINCT FROM NEW.schema_version
           OR OLD.candidate_count IS DISTINCT FROM NEW.candidate_count
           OR OLD.candidate_set_hash IS DISTINCT FROM NEW.candidate_set_hash
           OR OLD.created_at IS DISTINCT FROM NEW.created_at
           OR OLD.canonical_artifact_id IS NOT NULL
           OR NEW.canonical_artifact_id IS NULL THEN
            RAISE EXCEPTION 'authorized candidate set identity is immutable and artifact binds once' USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_candidate_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    status_value text;
    fragment_version text;
    fragment_extraction text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'authorized candidates are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'authorized candidate requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT result_status INTO status_value FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    IF status_value IS NULL OR status_value NOT IN ('QUEUED', 'RUNNING') THEN
        RAISE EXCEPTION 'authorized candidate requires an active question run' USING ERRCODE = '42501';
    END IF;
    SELECT source_version_id, extraction_id INTO fragment_version, fragment_extraction
      FROM public.evidence_fragment
     WHERE organization_id = NEW.organization_id AND id = NEW.evidence_fragment_id;
    IF fragment_version IS NULL OR fragment_version IS DISTINCT FROM NEW.source_version_id
       OR fragment_extraction IS DISTINCT FROM NEW.extraction_id THEN
        RAISE EXCEPTION 'authorized candidate lineage does not match Evidence' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_context_entry_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_row public.question_run%ROWTYPE;
    object_id text;
    version_state text;
    version_content_hash text;
    version_retention_state text;
    version_queryable boolean;
    version_fence bigint;
    extraction_version text;
    extraction_profile_hash text;
    extraction_retention_state text;
    extraction_queryable boolean;
    extraction_fence bigint;
    active_extraction text;
    active_revision bigint;
    fragment_version text;
    fragment_extraction text;
    fragment_text_hash text;
    fragment_anchor_hash text;
    acl_object_id text;
    acl_version_id text;
    acl_mode text;
    acl_content_hash text;
    acl_status text;
    acl_resolved_at timestamptz;
    acl_expires_at timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'retrieval context entries are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'retrieval context entry requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO run_row FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    IF NOT FOUND OR run_row.result_status NOT IN ('QUEUED', 'RUNNING')
       OR NEW.authorized_at < run_row.started_at THEN
        RAISE EXCEPTION 'retrieval context entry is outside the active question interval' USING ERRCODE = '23514';
    END IF;
    SELECT version.source_object_id, version.state, version.content_hash,
           version_retention.state, version_retention.queryable, version_retention.retention_fence,
           extraction.source_version_id, extraction.profile_hash,
           extraction_retention.state, extraction_retention.queryable,
           extraction.retention_fence_at_start,
           active_extraction.extraction_id, active_extraction.activation_revision,
           fragment.source_version_id, fragment.extraction_id, fragment.text_hash, fragment.anchor_hash
      INTO object_id, version_state, version_content_hash, version_retention_state,
           version_queryable, version_fence, extraction_version, extraction_profile_hash,
           extraction_retention_state, extraction_queryable, extraction_fence,
           active_extraction, active_revision, fragment_version, fragment_extraction,
           fragment_text_hash, fragment_anchor_hash
      FROM public.evidence_fragment fragment
      JOIN public.source_version version
        ON version.organization_id = fragment.organization_id AND version.id = fragment.source_version_id
      JOIN public.source_version_retention version_retention
        ON version_retention.organization_id = version.organization_id
       AND version_retention.source_version_id = version.id
      JOIN public.source_extraction extraction
        ON extraction.organization_id = fragment.organization_id AND extraction.id = fragment.extraction_id
      JOIN public.source_extraction_retention extraction_retention
        ON extraction_retention.organization_id = extraction.organization_id
       AND extraction_retention.extraction_id = extraction.id
      JOIN public.source_version_active_extraction active_extraction
        ON active_extraction.organization_id = version.organization_id
       AND active_extraction.source_version_id = version.id
     WHERE fragment.organization_id = NEW.organization_id AND fragment.id = NEW.evidence_fragment_id;
    IF object_id IS NULL
       OR fragment_version IS DISTINCT FROM NEW.source_version_id
       OR fragment_extraction IS DISTINCT FROM NEW.extraction_id
       OR object_id IS DISTINCT FROM NEW.source_object_id
       OR version_state IS DISTINCT FROM NEW.source_version_state
       OR version_content_hash IS DISTINCT FROM NEW.source_version_content_hash
       OR version_retention_state IS DISTINCT FROM NEW.source_version_retention_state
       OR version_queryable IS DISTINCT FROM NEW.source_version_queryable
       OR version_fence IS DISTINCT FROM NEW.source_version_retention_fence
       OR extraction_version IS DISTINCT FROM NEW.source_version_id
       OR extraction_profile_hash IS DISTINCT FROM NEW.extraction_profile_hash
       OR extraction_retention_state IS DISTINCT FROM NEW.extraction_retention_state
       OR extraction_queryable IS DISTINCT FROM NEW.extraction_queryable
       OR extraction_fence IS DISTINCT FROM NEW.extraction_retention_fence_at_start
       OR active_extraction IS DISTINCT FROM NEW.active_extraction_id
       OR active_revision IS DISTINCT FROM NEW.activation_revision
       OR fragment_text_hash IS DISTINCT FROM NEW.evidence_text_hash
       OR fragment_anchor_hash IS DISTINCT FROM NEW.anchor_hash THEN
        RAISE EXCEPTION 'retrieval context entry does not exact-match current catalog projections' USING ERRCODE = '23514';
    END IF;
    IF NEW.access_mode = 'WORKSPACE_MANAGED'
       AND (NEW.acl_snapshot_id IS NOT NULL OR NEW.acl_snapshot_hash IS NOT NULL
            OR NEW.acl_snapshot_status IS NOT NULL OR NEW.acl_resolved_at IS NOT NULL
            OR NEW.acl_expires_at IS NOT NULL) THEN
        RAISE EXCEPTION 'workspace-managed retrieval context must not carry source ACL snapshot' USING ERRCODE = '23514';
    END IF;
    IF NEW.access_mode = 'SOURCE_ENFORCED'
       AND (NEW.acl_snapshot_id IS NULL OR NEW.acl_snapshot_hash IS NULL
            OR NEW.acl_snapshot_status <> 'RESOLVED'
            OR NEW.acl_resolved_at IS NULL OR NEW.acl_expires_at IS NULL
            OR NEW.acl_resolved_at > NEW.authorized_at
            OR NEW.acl_expires_at <= NEW.authorized_at) THEN
        RAISE EXCEPTION 'source-enforced retrieval context requires a current ACL snapshot' USING ERRCODE = '42501';
    END IF;
    IF NEW.access_mode = 'SOURCE_ENFORCED' THEN
        SELECT acl.source_object_id, acl.source_version_id, acl.mode,
               acl.content_hash, acl.status, acl.resolved_at, acl.expires_at
          INTO acl_object_id, acl_version_id, acl_mode, acl_content_hash,
               acl_status, acl_resolved_at, acl_expires_at
          FROM public.acl_snapshot AS acl
         WHERE acl.organization_id = NEW.organization_id
           AND acl.id = NEW.acl_snapshot_id;
        IF acl_object_id IS NULL
           OR acl_object_id IS DISTINCT FROM NEW.source_object_id
           OR acl_version_id IS DISTINCT FROM NEW.source_version_id
           OR acl_mode IS DISTINCT FROM 'SOURCE_ENFORCED'
           OR acl_content_hash IS DISTINCT FROM NEW.acl_snapshot_hash
           OR acl_status IS DISTINCT FROM 'RESOLVED'
           OR acl_resolved_at IS DISTINCT FROM NEW.acl_resolved_at
           OR acl_expires_at IS DISTINCT FROM NEW.acl_expires_at THEN
            RAISE EXCEPTION 'source-enforced retrieval context ACL does not exact-match trusted snapshot' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF NEW.principal_set_captured_at > NEW.authorized_at
       OR NEW.principal_set_expires_at <= NEW.authorized_at
       OR NEW.principal_set_captured_at > NEW.principal_set_expires_at THEN
        RAISE EXCEPTION 'retrieval context entry authorization snapshot is stale' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.source_object_scope membership
        JOIN public.workspace_revision_source binding
          ON binding.organization_id = membership.organization_id
         AND binding.source_scope_id = membership.source_scope_id
         AND binding.source_scope_revision = membership.source_scope_revision
        WHERE membership.organization_id = NEW.organization_id
          AND membership.source_object_id = NEW.source_object_id
          AND membership.source_scope_id = NEW.source_scope_id
          AND membership.source_scope_revision = NEW.source_scope_revision
          AND membership.membership_state = 'ACTIVE'
          AND binding.workspace_id = run_row.workspace_id
          AND binding.workspace_revision = run_row.workspace_revision
          AND binding.access_mode = NEW.access_mode
          AND binding.enabled
    ) THEN
        RAISE EXCEPTION 'retrieval context entry lacks an active workspace binding' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_retrieval_snapshot_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_row public.question_run%ROWTYPE;
    candidate_hash text;
    candidate_count bigint;
    context_count bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'retrieval authorization snapshots are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'retrieval authorization snapshot requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO run_row FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    IF NOT FOUND OR run_row.result_status NOT IN ('QUEUED', 'RUNNING')
       OR NEW.captured_at < run_row.started_at THEN
        RAISE EXCEPTION 'retrieval authorization snapshot is outside the active question interval' USING ERRCODE = '23514';
    END IF;
    SELECT candidate_set.candidate_set_hash, candidate_set.candidate_count
      INTO candidate_hash, candidate_count
      FROM public.question_authorized_candidate_set AS candidate_set
     WHERE candidate_set.organization_id = NEW.organization_id
       AND candidate_set.question_run_id = NEW.question_run_id;
    IF candidate_hash IS NULL OR candidate_hash IS DISTINCT FROM NEW.authorized_candidate_set_hash
       OR candidate_count IS DISTINCT FROM NEW.authorized_candidate_count THEN
        RAISE EXCEPTION 'retrieval snapshot candidate set is incomplete or mismatched' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO candidate_count
      FROM public.question_authorized_candidate
     WHERE organization_id = NEW.organization_id AND question_run_id = NEW.question_run_id;
    IF candidate_count IS DISTINCT FROM NEW.authorized_candidate_count THEN
        RAISE EXCEPTION 'retrieval snapshot candidate count is not complete' USING ERRCODE = '23514';
    END IF;
    SELECT count(*) INTO context_count
      FROM public.question_retrieval_context_entry
     WHERE organization_id = NEW.organization_id AND question_run_id = NEW.question_run_id;
    IF context_count IS DISTINCT FROM NEW.context_count THEN
        RAISE EXCEPTION 'retrieval snapshot context count is not complete' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_candidate_set_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    artifact_id text;
BEGIN
    -- A deferred INSERT trigger may fire after the owning row has been
    -- completed by the bind function.  Re-read the final row by its immutable
    -- key instead of trusting the transition image captured at INSERT time.
    SELECT candidate_set.canonical_artifact_id INTO artifact_id
      FROM public.question_authorized_candidate_set AS candidate_set
     WHERE candidate_set.organization_id = NEW.organization_id
       AND candidate_set.question_run_id = NEW.question_run_id;
    IF artifact_id IS NULL
       OR NOT EXISTS (
           SELECT 1 FROM public.encrypted_artifact artifact
            WHERE artifact.organization_id = NEW.organization_id
              AND artifact.id = artifact_id
              AND artifact.owner_table = 'question_authorized_candidate_set'
              AND artifact.owner_column = 'canonical_artifact_id'
              AND artifact.resource_type = 'AUTHORIZED_CANDIDATE_SET'
              AND artifact.resource_id = NEW.question_run_id
              AND artifact.field_name = 'CANONICAL_BYTES'
              AND artifact.purged_at IS NULL
       ) THEN
        RAISE EXCEPTION 'authorized candidate set artifact does not exactly own the row' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_corpus_snapshot_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_corpus_snapshot
FOR EACH ROW EXECUTE FUNCTION app.question_corpus_snapshot_guard();
CREATE TRIGGER question_candidate_set_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_authorized_candidate_set
FOR EACH ROW EXECUTE FUNCTION app.question_candidate_set_guard();
CREATE TRIGGER question_candidate_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_authorized_candidate
FOR EACH ROW EXECUTE FUNCTION app.question_candidate_guard();
CREATE TRIGGER question_context_entry_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_retrieval_context_entry
FOR EACH ROW EXECUTE FUNCTION app.question_context_entry_guard();
CREATE TRIGGER question_retrieval_snapshot_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_retrieval_authorization_snapshot
FOR EACH ROW EXECUTE FUNCTION app.question_retrieval_snapshot_guard();
CREATE CONSTRAINT TRIGGER question_candidate_set_artifact_exact
AFTER INSERT OR UPDATE ON public.question_authorized_candidate_set
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.question_candidate_set_artifact_guard();

CREATE OR REPLACE FUNCTION app.question_authorized_candidate_set_bind_canonical(
    p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user <> 'knowvault_app'
       OR p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'authorized candidate set artifact bind requires runtime tenant' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
        RAISE EXCEPTION 'resource id must equal question run id' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, aad_schema_version, owner_table, owner_column,
        resource_type, resource_id, field_name, cipher, ciphertext, size_bytes,
        nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version,
        aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'encrypted-artifact-aad-v1',
        'question_authorized_candidate_set', 'canonical_artifact_id',
        'AUTHORIZED_CANDIDATE_SET', p_resource_id, 'CANONICAL_BYTES',
        'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek,
        p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash,
        p_plaintext_hash
    );
    UPDATE public.question_authorized_candidate_set
       SET canonical_artifact_id = p_artifact_id
     WHERE organization_id = p_org AND question_run_id = p_owning_row_id
       AND canonical_artifact_id IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'authorized candidate set missing or already bound' USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_authorized_candidate_set_read_canonical(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea,
    wrapped_dek bytea, wrapped_dek_hash text, kek_reference text, kek_version bigint,
    aad_hash text, plaintext_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT artifact.resource_id, artifact.ciphertext, artifact.size_bytes,
           artifact.nonce, artifact.wrapped_dek, artifact.wrapped_dek_hash,
           artifact.kek_reference, artifact.kek_version, artifact.aad_hash,
           artifact.plaintext_hash
      FROM public.question_authorized_candidate_set candidate_set
      JOIN public.encrypted_artifact artifact
        ON artifact.organization_id = candidate_set.organization_id
       AND artifact.id = candidate_set.canonical_artifact_id
     WHERE candidate_set.organization_id = app.current_organization_id()
       AND candidate_set.question_run_id = p_owning_row_id
       AND artifact.purged_at IS NULL;
$$;

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'question_corpus_snapshot', 'question_authorized_candidate_set',
        'question_authorized_candidate', 'question_retrieval_context_entry',
        'question_retrieval_authorization_snapshot'
    ] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY %I ON public.%I USING (organization_id = app.current_organization_id()) WITH CHECK (organization_id = app.current_organization_id())',
            table_name || '_tenant_isolation', table_name
        );
    END LOOP;
END;
$$;

REVOKE ALL ON TABLE
    public.question_corpus_snapshot,
    public.question_authorized_candidate_set,
    public.question_authorized_candidate,
    public.question_retrieval_context_entry,
    public.question_retrieval_authorization_snapshot
FROM PUBLIC;

GRANT SELECT, INSERT ON TABLE
    public.question_corpus_snapshot,
    public.question_authorized_candidate_set,
    public.question_authorized_candidate,
    public.question_retrieval_context_entry,
    public.question_retrieval_authorization_snapshot
TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.retrieval_snapshot_error_codes_valid(jsonb),
    app.question_corpus_snapshot_guard(),
    app.question_candidate_set_guard(),
    app.question_candidate_guard(),
    app.question_context_entry_guard(),
    app.question_retrieval_snapshot_guard(),
    app.question_candidate_set_artifact_guard(),
    app.question_authorized_candidate_set_bind_canonical(text, text, text, text, bytea, integer, bytea,
        bytea, text, text, bigint, text, text),
    app.question_authorized_candidate_set_read_canonical(text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.retrieval_snapshot_error_codes_valid(jsonb),
    app.question_authorized_candidate_set_bind_canonical(text, text, text, text, bytea, integer, bytea,
        bytea, text, text, bigint, text, text),
    app.question_authorized_candidate_set_read_canonical(text)
TO knowvault_app;

COMMIT;
