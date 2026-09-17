-- Stage 2 catalog, extraction and Evidence (P2/I1/S1d).
--
-- Turns one allowed text file in a connected folder into versioned, exactly
-- anchored Evidence.  Introduces the SourceObject / SourceVersion /
-- SourceExtraction / EvidenceFragment relations the S1c connector deliberately
-- does not create, activates only the encrypted-artifact owner branches the
-- text path uses (source_object x3, evidence_fragment x3), and opens the scope
-- activation state machine (DRAFT -> SYNCING -> READY / FAILED) so a
-- SOURCE_SCOPE_SYNC worker can drive it under its lease.  No search, no Question
-- Run, no OpenSearch, no OCR/office/PDF.  See ADR-0058 and DATA_MODEL.md s4-5.
--
-- Sensitive source identities, locators, titles, Evidence text, anchors and
-- metadata live only inside encrypted_artifact via per-branch SECURITY DEFINER
-- bind/read functions.  Digest columns are organization-scoped HMAC lookups; raw
-- values are never stored as typed columns.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'runtime role knowvault_app must exist before this migration';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_worker') THEN
        RAISE EXCEPTION 'worker role knowvault_worker must exist before this migration';
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Shared validators
-- ---------------------------------------------------------------------------

-- external_version_key is either a connector-native token or a content-hash
-- surrogate; folder objects have no native version id and always use the hash
-- form.  DATA_MODEL.md s4.
CREATE OR REPLACE FUNCTION app.source_external_version_key_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    -- PostgreSQL POSIX regex caps a bounded repetition at 255.
    SELECT value IS NOT NULL
       AND (value ~ '^native:[^[:cntrl:]]{1,248}$'
            OR value ~ '^hash:sha256:[0-9a-f]{64}$');
$$;

-- ---------------------------------------------------------------------------
-- Catalog: SourceObject and revision-aware M:N membership
-- ---------------------------------------------------------------------------

CREATE TABLE public.source_object (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'object')),
    connection_id text NOT NULL,
    object_type text NOT NULL CHECK (object_type IN ('FILE')),
    digest_key_version bigint NOT NULL CHECK (digest_key_version BETWEEN 1 AND 999999999),
    external_object_id_digest text NOT NULL CHECK (
        app.source_keyed_digest_matches_version(external_object_id_digest, digest_key_version)
    ),
    canonical_locator_digest text NOT NULL CHECK (
        app.source_keyed_digest_matches_version(canonical_locator_digest, digest_key_version)
    ),
    external_object_id_artifact_id text CHECK (
        external_object_id_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(external_object_id_artifact_id)
    ),
    canonical_locator_artifact_id text CHECK (
        canonical_locator_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(canonical_locator_artifact_id)
    ),
    title_artifact_id text CHECK (
        title_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(title_artifact_id)
    ),
    current_version_id text,
    current_acl_snapshot_id text,
    lifecycle_state text NOT NULL DEFAULT 'ACTIVE' CHECK (lifecycle_state IN ('ACTIVE', 'DELETED')),
    queryable boolean NOT NULL DEFAULT false,
    first_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_object_connection_fk
        FOREIGN KEY (organization_id, connection_id)
        REFERENCES public.source_connection (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT source_object_locator_artifact_fk
        FOREIGN KEY (organization_id, canonical_locator_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_object_external_artifact_fk
        FOREIGN KEY (organization_id, external_object_id_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT source_object_title_artifact_fk
        FOREIGN KEY (organization_id, title_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    -- One SourceObject per (connection, external identity): overlapping scopes
    -- resolve to the same object.  VER-004.
    UNIQUE (organization_id, connection_id, digest_key_version, external_object_id_digest),
    UNIQUE (organization_id, id, connection_id),
    -- Needed so current_version_id can be an exact same-object pointer.
    UNIQUE (organization_id, id, current_version_id)
);

CREATE TABLE public.source_object_scope (
    organization_id text NOT NULL,
    source_object_id text NOT NULL,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    membership_state text NOT NULL DEFAULT 'ACTIVE' CHECK (membership_state IN ('ACTIVE', 'MOVED', 'REMOVED')),
    first_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    last_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    removed_at timestamptz,
    PRIMARY KEY (organization_id, source_object_id, source_scope_id, source_scope_revision),
    CONSTRAINT source_object_scope_object_fk
        FOREIGN KEY (organization_id, source_object_id)
        REFERENCES public.source_object (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT source_object_scope_revision_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision)
        ON DELETE RESTRICT,
    CHECK ((membership_state = 'REMOVED') = (removed_at IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- Catalog: immutable SourceVersion and its retention aggregate
-- ---------------------------------------------------------------------------

CREATE TABLE public.source_version (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'version')),
    source_object_id text NOT NULL,
    external_version_key text NOT NULL CHECK (app.source_external_version_key_is_valid(external_version_key)),
    content_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(content_hash)),
    source_updated_at timestamptz,
    observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    superseded_at timestamptz,
    deleted_at timestamptz,
    state text NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'CURRENT', 'SUPERSEDED', 'DELETED', 'REDACTED')),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_version_object_fk
        FOREIGN KEY (organization_id, source_object_id)
        REFERENCES public.source_object (organization_id, id) ON DELETE RESTRICT,
    -- Repeat of an identical version is idempotent.  VER-002 / invariant B.
    UNIQUE (organization_id, source_object_id, external_version_key),
    -- Needed so evidence_fragment and active-extraction can bind version+child.
    UNIQUE (organization_id, source_object_id, id)
);

-- At most one CURRENT version per object.  DATA_MODEL.md s4.
CREATE UNIQUE INDEX source_version_one_current
    ON public.source_version (organization_id, source_object_id)
    WHERE state = 'CURRENT';

-- source_object.current_version_id must point at an exact version of this object.
ALTER TABLE public.source_object
    ADD CONSTRAINT source_object_current_version_fk
    FOREIGN KEY (organization_id, id, current_version_id)
    REFERENCES public.source_version (organization_id, source_object_id, id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE public.source_version_retention (
    organization_id text NOT NULL,
    source_version_id text NOT NULL,
    state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'PURGING', 'PURGED')),
    queryable boolean NOT NULL DEFAULT true,
    extraction_allowed boolean NOT NULL DEFAULT true,
    retention_fence bigint NOT NULL DEFAULT 0 CHECK (retention_fence >= 0),
    purge_reason text,
    purged_at timestamptz,
    PRIMARY KEY (organization_id, source_version_id),
    CONSTRAINT source_version_retention_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------------
-- Extraction: immutable result, retention, atomic active pointer
-- ---------------------------------------------------------------------------

CREATE TABLE public.source_extraction (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'extraction')),
    source_version_id text NOT NULL,
    retention_fence_at_start bigint NOT NULL CHECK (retention_fence_at_start >= 0),
    canonical_format text NOT NULL
        CHECK (canonical_format IN ('TEXT', 'PDF', 'DOCX', 'PPTX', 'XLSX', 'EMAIL', 'HTML', 'OCR')),
    profile_json jsonb NOT NULL,
    profile_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(profile_hash)),
    extractor_name text NOT NULL CHECK (length(extractor_name) BETWEEN 1 AND 128),
    extractor_version text NOT NULL CHECK (length(extractor_version) BETWEEN 1 AND 64),
    extractor_artifact_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(extractor_artifact_hash)),
    normalization_version text NOT NULL CHECK (normalization_version = 'text-v1'),
    parser_profile_revision text NOT NULL CHECK (length(parser_profile_revision) BETWEEN 1 AND 64),
    ocr_used boolean NOT NULL DEFAULT false CHECK (ocr_used = false),
    ocr_model_id text CHECK (ocr_model_id IS NULL),
    ocr_model_revision text CHECK (ocr_model_revision IS NULL),
    ocr_artifact_hash text CHECK (ocr_artifact_hash IS NULL),
    ocr_profile_revision text CHECK (ocr_profile_revision IS NULL),
    evidence_set_hash text CHECK (evidence_set_hash IS NULL OR app.stage2_sha256_is_valid(evidence_set_hash)),
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED')),
    started_at timestamptz,
    completed_at timestamptz,
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT source_extraction_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT,
    UNIQUE (organization_id, source_version_id, id),
    CHECK (status <> 'SUCCEEDED' OR evidence_set_hash IS NOT NULL),
    CHECK (status NOT IN ('SUCCEEDED', 'FAILED') OR completed_at IS NOT NULL),
    CHECK (status <> 'FAILED' OR failure_code IS NOT NULL)
);

-- Only one activatable success per exact profile; a new run is allowed after a
-- terminal failure.  DATA_MODEL.md s4 / invariant C.
CREATE UNIQUE INDEX source_extraction_one_success_per_profile
    ON public.source_extraction (organization_id, source_version_id, profile_hash)
    WHERE status = 'SUCCEEDED';

CREATE TABLE public.source_extraction_retention (
    organization_id text NOT NULL,
    extraction_id text NOT NULL,
    state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'PURGING', 'PURGED')),
    queryable boolean NOT NULL DEFAULT true,
    purge_reason text,
    purged_at timestamptz,
    PRIMARY KEY (organization_id, extraction_id),
    CONSTRAINT source_extraction_retention_extraction_fk
        FOREIGN KEY (organization_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, id) ON DELETE RESTRICT
);

CREATE TABLE public.source_version_active_extraction (
    organization_id text NOT NULL,
    source_version_id text NOT NULL,
    extraction_id text NOT NULL,
    activation_revision bigint NOT NULL DEFAULT 1 CHECK (activation_revision >= 1),
    activated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, source_version_id),
    CONSTRAINT source_version_active_extraction_exact_fk
        FOREIGN KEY (organization_id, source_version_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, source_version_id, id)
        ON DELETE RESTRICT
);

-- ---------------------------------------------------------------------------
-- acl_snapshot: inert in S1d (WORKSPACE_MANAGED only); schema keeps S1e possible
-- ---------------------------------------------------------------------------

CREATE TABLE public.acl_snapshot (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'acl')),
    source_object_id text NOT NULL,
    source_version_id text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')),
    principal_tokens_artifact_id text CHECK (
        principal_tokens_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(principal_tokens_artifact_id)
    ),
    principal_token_digests_json jsonb,
    digest_key_version bigint CHECK (digest_key_version IS NULL OR digest_key_version BETWEEN 1 AND 999999999),
    resolved_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz,
    content_hash text CHECK (content_hash IS NULL OR app.stage2_sha256_is_valid(content_hash)),
    status text NOT NULL DEFAULT 'RESOLVED' CHECK (status IN ('RESOLVED', 'STALE', 'FAILED', 'UNKNOWN')),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT acl_snapshot_object_fk
        FOREIGN KEY (organization_id, source_object_id)
        REFERENCES public.source_object (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT acl_snapshot_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT
);

-- source_object.current_acl_snapshot_id points at an acl_snapshot of this object.
ALTER TABLE public.source_object
    ADD CONSTRAINT source_object_current_acl_fk
    FOREIGN KEY (organization_id, current_acl_snapshot_id)
    REFERENCES public.acl_snapshot (organization_id, id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

-- ---------------------------------------------------------------------------
-- Evidence: immutable fragments with encrypted text/anchor/metadata
-- ---------------------------------------------------------------------------

CREATE TABLE public.evidence_fragment (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'fragment')),
    source_version_id text NOT NULL,
    extraction_id text NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal BETWEEN 1 AND 9007199254740991),
    normalized_text_artifact_id text CHECK (
        normalized_text_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(normalized_text_artifact_id)
    ),
    text_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(text_hash)),
    token_count bigint NOT NULL CHECK (token_count >= 0),
    byte_count bigint NOT NULL CHECK (byte_count >= 1),
    anchor_artifact_id text CHECK (
        anchor_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(anchor_artifact_id)
    ),
    anchor_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(anchor_hash)),
    metadata_artifact_id text CHECK (
        metadata_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(metadata_artifact_id)
    ),
    extraction_confidence double precision CHECK (
        extraction_confidence IS NULL OR (extraction_confidence >= 0 AND extraction_confidence <= 1)
    ),
    language text CHECK (language IS NULL OR language ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    -- EvidenceFragment always binds an immutable SourceVersion and the exact
    -- immutable SourceExtraction of that version.  VER-001 / EVD-*.
    CONSTRAINT evidence_fragment_extraction_fk
        FOREIGN KEY (organization_id, source_version_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, source_version_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT evidence_fragment_text_artifact_fk
        FOREIGN KEY (organization_id, normalized_text_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT evidence_fragment_anchor_artifact_fk
        FOREIGN KEY (organization_id, anchor_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT evidence_fragment_metadata_artifact_fk
        FOREIGN KEY (organization_id, metadata_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    -- Closed, gap-free unique ordinal set per extraction.
    UNIQUE (organization_id, extraction_id, ordinal)
);

-- ---------------------------------------------------------------------------
-- Sync run bookkeeping
-- ---------------------------------------------------------------------------

CREATE TABLE public.sync_run (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'syncrun')),
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    job_id text NOT NULL,
    -- DATA_MODEL.md s5 mode set. S1d only runs FULL; the cursor columns exist for
    -- INCREMENTAL/RECONCILIATION (S1e) and stay NULL here.
    mode text NOT NULL CHECK (mode IN ('FULL', 'INCREMENTAL', 'RECONCILIATION')),
    status text NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'SUCCEEDED', 'FAILED')),
    cursor_before text,
    cursor_after text,
    -- Typed content-free counters are a physical refinement of DATA_MODEL's
    -- counters_json; the same aggregate facts, but each range-checked.
    objects_seen bigint NOT NULL DEFAULT 0 CHECK (objects_seen >= 0),
    objects_ingested bigint NOT NULL DEFAULT 0 CHECK (objects_ingested >= 0),
    versions_created bigint NOT NULL DEFAULT 0 CHECK (versions_created >= 0),
    evidence_published bigint NOT NULL DEFAULT 0 CHECK (evidence_published >= 0),
    quarantined bigint NOT NULL DEFAULT 0 CHECK (quarantined >= 0),
    started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    -- error_code is the safe operator-facing code; error_summary stays NULL in
    -- S1d and must never carry source content when populated later.
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    error_summary text,
    PRIMARY KEY (organization_id, id),
    CONSTRAINT sync_run_scope_revision_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT sync_run_job_fk
        FOREIGN KEY (organization_id, job_id)
        REFERENCES public.job (organization_id, id) ON DELETE RESTRICT,
    CHECK (status = 'RUNNING' OR completed_at IS NOT NULL),
    CHECK (status <> 'FAILED' OR error_code IS NOT NULL)
);

-- ---------------------------------------------------------------------------
-- Mutability guards (immutable identity, forward-only lifecycle)
-- ---------------------------------------------------------------------------

-- SourceObject identity is immutable; only lifecycle pointers, queryability,
-- last_seen and the one-time NULL->value artifact bindings may change.
CREATE OR REPLACE FUNCTION app.source_object_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_object deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.object_type IS DISTINCT FROM OLD.object_type
       OR NEW.digest_key_version IS DISTINCT FROM OLD.digest_key_version
       OR NEW.external_object_id_digest IS DISTINCT FROM OLD.external_object_id_digest
       OR NEW.canonical_locator_digest IS DISTINCT FROM OLD.canonical_locator_digest
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'source_object identity is immutable' USING ERRCODE = '55000';
    END IF;
    -- Artifact bindings are one-time NULL -> value only.
    IF (OLD.external_object_id_artifact_id IS NOT NULL AND NEW.external_object_id_artifact_id IS DISTINCT FROM OLD.external_object_id_artifact_id)
       OR (OLD.canonical_locator_artifact_id IS NOT NULL AND NEW.canonical_locator_artifact_id IS DISTINCT FROM OLD.canonical_locator_artifact_id)
       OR (OLD.title_artifact_id IS NOT NULL AND NEW.title_artifact_id IS DISTINCT FROM OLD.title_artifact_id) THEN
        RAISE EXCEPTION 'source_object artifact bindings are write-once' USING ERRCODE = '55000';
    END IF;
    IF NEW.lifecycle_state = 'ACTIVE' AND OLD.lifecycle_state = 'DELETED' THEN
        RAISE EXCEPTION 'source_object lifecycle does not resurrect' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- All three SourceObject artifact branches must exactly own the row by commit.
CREATE OR REPLACE FUNCTION app.source_object_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    ok boolean;
BEGIN
    -- The three EXISTS checks below are the completeness proof: each artifact is
    -- owned by exactly this row. They do not read NEW's artifact columns, which a
    -- deferred AFTER-INSERT snapshot would still show as NULL even after the bind
    -- functions have set them within the same transaction.
    SELECT bool_and(present) INTO ok FROM (
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'source_object' AND a.owner_column = 'canonical_locator_artifact_id'
              AND a.resource_type = 'SOURCE_LOCATOR' AND a.field_name = 'CANONICAL_LOCATOR'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL) AS present
        UNION ALL
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'source_object' AND a.owner_column = 'external_object_id_artifact_id'
              AND a.resource_type = 'SOURCE_OBJECT_ID' AND a.field_name = 'EXTERNAL_OBJECT_ID'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL)
        UNION ALL
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'source_object' AND a.owner_column = 'title_artifact_id'
              AND a.resource_type = 'SOURCE_TITLE' AND a.field_name = 'DISPLAY_TITLE'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL)
    ) checks;
    IF NOT ok THEN
        RAISE EXCEPTION 'source_object artifacts do not exactly own the row' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_object_scope_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_object_scope deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
       OR NEW.source_scope_id IS DISTINCT FROM OLD.source_scope_id
       OR NEW.source_scope_revision IS DISTINCT FROM OLD.source_scope_revision
       OR NEW.first_seen_at IS DISTINCT FROM OLD.first_seen_at THEN
        RAISE EXCEPTION 'source_object_scope identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.membership_state = 'REMOVED' AND NEW.membership_state <> 'REMOVED' THEN
        RAISE EXCEPTION 'source_object_scope membership does not un-remove' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_version_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_version deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
       OR NEW.external_version_key IS DISTINCT FROM OLD.external_version_key
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
       OR NEW.source_updated_at IS DISTINCT FROM OLD.source_updated_at
       OR NEW.observed_at IS DISTINCT FROM OLD.observed_at THEN
        RAISE EXCEPTION 'source_version content identity is immutable' USING ERRCODE = '55000';
    END IF;
    -- Lifecycle is forward-only: a version never returns to CURRENT once
    -- superseded/deleted, so a stale write cannot resurrect an old version.
    IF NOT (
        NEW.state = OLD.state
        OR (OLD.state = 'PENDING' AND NEW.state IN ('CURRENT', 'SUPERSEDED', 'DELETED', 'REDACTED'))
        OR (OLD.state = 'CURRENT' AND NEW.state IN ('SUPERSEDED', 'DELETED', 'REDACTED'))
        OR (OLD.state = 'SUPERSEDED' AND NEW.state IN ('DELETED', 'REDACTED'))
        OR (OLD.state = 'DELETED' AND NEW.state = 'REDACTED')
    ) THEN
        RAISE EXCEPTION 'source_version state transition is not permitted' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_retention_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION '% deletion requires tenant hard-delete state', TG_TABLE_NAME USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    -- Forward-only: a purge only advances state and (for versions) the fence.
    IF (OLD.state = 'PURGED' AND NEW.state <> 'PURGED')
       OR (OLD.state = 'PURGING' AND NEW.state = 'ACTIVE') THEN
        RAISE EXCEPTION '% retention does not reverse', TG_TABLE_NAME USING ERRCODE = '55000';
    END IF;
    IF TG_TABLE_NAME = 'source_version_retention' AND NEW.retention_fence < OLD.retention_fence THEN
        RAISE EXCEPTION 'retention fence never decreases' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_extraction_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_extraction deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.status IN ('SUCCEEDED', 'FAILED') THEN
        RAISE EXCEPTION 'source_extraction is immutable after terminal status' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.canonical_format IS DISTINCT FROM OLD.canonical_format
       OR NEW.profile_hash IS DISTINCT FROM OLD.profile_hash
       OR NEW.retention_fence_at_start IS DISTINCT FROM OLD.retention_fence_at_start
       OR NEW.normalization_version IS DISTINCT FROM OLD.normalization_version THEN
        RAISE EXCEPTION 'source_extraction profile identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.evidence_set_hash IS NOT NULL AND NEW.evidence_set_hash IS DISTINCT FROM OLD.evidence_set_hash THEN
        RAISE EXCEPTION 'evidence_set_hash is write-once' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- The active pointer may only reference a SUCCEEDED extraction of the same
-- version whose retention (and the version's) is ACTIVE/queryable; it advances
-- monotonically.  Invariant G.
CREATE OR REPLACE FUNCTION app.source_active_extraction_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    extraction_status text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source_version_active_extraction deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.activation_revision <= OLD.activation_revision THEN
        RAISE EXCEPTION 'active extraction pointer advances monotonically' USING ERRCODE = '55000';
    END IF;
    SELECT status INTO extraction_status FROM public.source_extraction
        WHERE organization_id = NEW.organization_id AND id = NEW.extraction_id
          AND source_version_id = NEW.source_version_id;
    IF extraction_status IS DISTINCT FROM 'SUCCEEDED' THEN
        RAISE EXCEPTION 'active extraction must be a SUCCEEDED extraction of the version' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.source_version_retention r
        WHERE r.organization_id = NEW.organization_id AND r.source_version_id = NEW.source_version_id
          AND r.state = 'ACTIVE' AND r.queryable) THEN
        RAISE EXCEPTION 'active extraction requires ACTIVE queryable version retention' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.source_extraction_retention r
        WHERE r.organization_id = NEW.organization_id AND r.extraction_id = NEW.extraction_id
          AND r.state = 'ACTIVE' AND r.queryable) THEN
        RAISE EXCEPTION 'active extraction requires ACTIVE queryable extraction retention' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- EvidenceFragment is immutable except for the one-time NULL -> value artifact
-- bindings performed inside its creation transaction.
CREATE OR REPLACE FUNCTION app.evidence_fragment_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'evidence_fragment deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
       OR NEW.extraction_id IS DISTINCT FROM OLD.extraction_id
       OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
       OR NEW.text_hash IS DISTINCT FROM OLD.text_hash
       OR NEW.token_count IS DISTINCT FROM OLD.token_count
       OR NEW.byte_count IS DISTINCT FROM OLD.byte_count
       OR NEW.anchor_hash IS DISTINCT FROM OLD.anchor_hash
       OR NEW.extraction_confidence IS DISTINCT FROM OLD.extraction_confidence
       OR NEW.language IS DISTINCT FROM OLD.language
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'evidence_fragment is immutable' USING ERRCODE = '55000';
    END IF;
    IF (OLD.normalized_text_artifact_id IS NOT NULL AND NEW.normalized_text_artifact_id IS DISTINCT FROM OLD.normalized_text_artifact_id)
       OR (OLD.anchor_artifact_id IS NOT NULL AND NEW.anchor_artifact_id IS DISTINCT FROM OLD.anchor_artifact_id)
       OR (OLD.metadata_artifact_id IS NOT NULL AND NEW.metadata_artifact_id IS DISTINCT FROM OLD.metadata_artifact_id) THEN
        RAISE EXCEPTION 'evidence_fragment artifact bindings are write-once' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

-- All three Evidence artifacts must exactly own the fragment by commit, and the
-- text/anchor artifacts must carry the fragment's content hashes.  EVD-002.
CREATE OR REPLACE FUNCTION app.evidence_fragment_artifact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    ok boolean;
BEGIN
    -- EXISTS-per-branch is the completeness proof (see source_object_artifact_guard).
    SELECT bool_and(present) INTO ok FROM (
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'normalized_text_artifact_id'
              AND a.resource_type = 'EVIDENCE_TEXT' AND a.field_name = 'NORMALIZED_TEXT'
              AND a.resource_id = NEW.id AND a.plaintext_hash = NEW.text_hash AND a.purged_at IS NULL) AS present
        UNION ALL
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'anchor_artifact_id'
              AND a.resource_type = 'EVIDENCE_ANCHOR' AND a.field_name = 'CANONICAL_ANCHOR'
              AND a.resource_id = NEW.id AND a.plaintext_hash = NEW.anchor_hash AND a.purged_at IS NULL)
        UNION ALL
        SELECT EXISTS (SELECT 1 FROM public.encrypted_artifact a
            WHERE a.organization_id = NEW.organization_id
              AND a.owner_table = 'evidence_fragment' AND a.owner_column = 'metadata_artifact_id'
              AND a.resource_type = 'EVIDENCE_METADATA' AND a.field_name = 'METADATA'
              AND a.resource_id = NEW.id AND a.purged_at IS NULL)
    ) checks;
    IF NOT ok THEN
        RAISE EXCEPTION 'evidence_fragment artifacts do not exactly own the fragment' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.sync_run_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'sync_run deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.status <> 'RUNNING' THEN
        RAISE EXCEPTION 'sync_run is immutable after terminal status' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.source_scope_id IS DISTINCT FROM OLD.source_scope_id
       OR NEW.source_scope_revision IS DISTINCT FROM OLD.source_scope_revision
       OR NEW.job_id IS DISTINCT FROM OLD.job_id
       OR NEW.mode IS DISTINCT FROM OLD.mode
       OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'sync_run identity is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_object_state_guard
    BEFORE UPDATE OR DELETE ON public.source_object
    FOR EACH ROW EXECUTE FUNCTION app.source_object_guard();
CREATE CONSTRAINT TRIGGER source_object_artifact_exact
    AFTER INSERT OR UPDATE ON public.source_object
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app.source_object_artifact_guard();
CREATE TRIGGER source_object_scope_state_guard
    BEFORE UPDATE OR DELETE ON public.source_object_scope
    FOR EACH ROW EXECUTE FUNCTION app.source_object_scope_guard();
CREATE TRIGGER source_version_state_guard
    BEFORE UPDATE OR DELETE ON public.source_version
    FOR EACH ROW EXECUTE FUNCTION app.source_version_guard();
CREATE TRIGGER source_version_retention_state_guard
    BEFORE UPDATE OR DELETE ON public.source_version_retention
    FOR EACH ROW EXECUTE FUNCTION app.source_retention_guard();
CREATE TRIGGER source_extraction_state_guard
    BEFORE UPDATE OR DELETE ON public.source_extraction
    FOR EACH ROW EXECUTE FUNCTION app.source_extraction_guard();
CREATE TRIGGER source_extraction_retention_state_guard
    BEFORE UPDATE OR DELETE ON public.source_extraction_retention
    FOR EACH ROW EXECUTE FUNCTION app.source_retention_guard();
CREATE TRIGGER source_active_extraction_state_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.source_version_active_extraction
    FOR EACH ROW EXECUTE FUNCTION app.source_active_extraction_guard();
CREATE TRIGGER evidence_fragment_state_guard
    BEFORE UPDATE OR DELETE ON public.evidence_fragment
    FOR EACH ROW EXECUTE FUNCTION app.evidence_fragment_guard();
CREATE CONSTRAINT TRIGGER evidence_fragment_artifact_exact
    AFTER INSERT OR UPDATE ON public.evidence_fragment
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION app.evidence_fragment_artifact_guard();
CREATE TRIGGER acl_snapshot_immutable
    BEFORE UPDATE OR DELETE ON public.acl_snapshot
    FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();
CREATE TRIGGER sync_run_state_guard
    BEFORE UPDATE OR DELETE ON public.sync_run
    FOR EACH ROW EXECUTE FUNCTION app.sync_run_guard();

-- ---------------------------------------------------------------------------
-- Trust projection and scope activation: open the data plane (SRC-014/015)
--
-- 000006/000007 shipped these projections DRAFT-only and deferred the
-- SYNCING/READY and VERIFIED transitions to "a subsequent accepted checkpoint".
-- S1d is that checkpoint for the folder path: it opens monotonic transitions
-- through guarded worker functions and nothing else.
-- ---------------------------------------------------------------------------

ALTER TABLE public.source_connection_trust_projection
    DROP CONSTRAINT source_connection_trust_projection_status_check,
    ADD CONSTRAINT source_connection_trust_projection_status_check
        CHECK (status IN ('DRAFT', 'VERIFIED', 'REVOKED', 'EXPIRED'));

DROP TRIGGER source_connection_trust_projection_immutable ON public.source_connection_trust_projection;

CREATE OR REPLACE FUNCTION app.source_trust_projection_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'trust projection deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.trust_record_id IS DISTINCT FROM OLD.trust_record_id
       OR NEW.revision IS DISTINCT FROM OLD.revision THEN
        RAISE EXCEPTION 'trust projection identity is immutable' USING ERRCODE = '55000';
    END IF;
    -- Monotonic: DRAFT -> VERIFIED; VERIFIED -> REVOKED/EXPIRED; terminal states final.
    IF OLD.status IN ('REVOKED', 'EXPIRED')
       OR (OLD.status = 'VERIFIED' AND NEW.status = 'DRAFT')
       OR (OLD.status = 'DRAFT' AND NEW.status IN ('REVOKED', 'EXPIRED')) THEN
        RAISE EXCEPTION 'trust projection transition is not permitted' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_connection_trust_projection_state_guard
    BEFORE UPDATE OR DELETE ON public.source_connection_trust_projection
    FOR EACH ROW EXECUTE FUNCTION app.source_trust_projection_guard();

ALTER TABLE public.source_scope_activation
    DROP CONSTRAINT source_scope_activation_status_check,
    DROP CONSTRAINT source_scope_activation_activated_at_check,
    ADD CONSTRAINT source_scope_activation_status_check
        CHECK (status IN ('DRAFT', 'SYNCING', 'READY', 'REVOKED', 'FAILED')),
    ADD CONSTRAINT source_scope_activation_activated_at_check
        CHECK (activated_at IS NULL OR status IN ('READY', 'REVOKED', 'FAILED'));

DROP TRIGGER source_scope_activation_immutable ON public.source_scope_activation;

CREATE OR REPLACE FUNCTION app.source_scope_activation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'scope activation deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.source_scope_id IS DISTINCT FROM OLD.source_scope_id
       OR NEW.source_scope_revision IS DISTINCT FROM OLD.source_scope_revision
       OR NEW.revision IS DISTINCT FROM OLD.revision THEN
        RAISE EXCEPTION 'scope activation identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'REVOKED'
       OR (OLD.status = 'DRAFT' AND NEW.status NOT IN ('DRAFT', 'SYNCING', 'REVOKED'))
       OR (OLD.status = 'SYNCING' AND NEW.status NOT IN ('SYNCING', 'READY', 'FAILED', 'REVOKED'))
       OR (OLD.status = 'READY' AND NEW.status NOT IN ('READY', 'SYNCING', 'REVOKED'))
       OR (OLD.status = 'FAILED' AND NEW.status NOT IN ('FAILED', 'SYNCING', 'REVOKED')) THEN
        RAISE EXCEPTION 'scope activation transition is not permitted' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER source_scope_activation_state_guard
    BEFORE UPDATE OR DELETE ON public.source_scope_activation
    FOR EACH ROW EXECUTE FUNCTION app.source_scope_activation_guard();

ALTER TABLE public.source_scope DROP CONSTRAINT source_scope_active_revision_check;

-- Replace the DRAFT-only parent guard so active_revision may be set forward to
-- an existing revision, preserving every other lineage rule from 000007.
CREATE OR REPLACE FUNCTION app.source_scope_parent_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (SELECT 1 FROM public.organization
                          WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')) THEN
            RAISE EXCEPTION 'source scope deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.discovered_scope_id IS DISTINCT FROM OLD.discovered_scope_id
       OR NEW.source_type IS DISTINCT FROM OLD.source_type
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.latest_revision < OLD.latest_revision THEN
        RAISE EXCEPTION 'source scope permits only forward latest lineage' USING ERRCODE = '55000';
    END IF;
    IF OLD.active_revision IS NOT NULL
       AND (NEW.active_revision IS NULL OR NEW.active_revision < OLD.active_revision) THEN
        RAISE EXCEPTION 'source scope active revision only advances' USING ERRCODE = '55000';
    END IF;
    IF NEW.active_revision IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM public.source_scope_revision
                       WHERE organization_id = NEW.organization_id
                         AND source_scope_id = NEW.id AND revision = NEW.active_revision) THEN
        RAISE EXCEPTION 'source scope active revision must resolve to an exact revision' USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- Fencing primitives (JOB-004 / invariant F)
-- ---------------------------------------------------------------------------

-- Locks the job row for the rest of the transaction and confirms the caller
-- still holds the exact live lease.  A stale epoch or lapsed deadline raises
-- and rolls back every fenced write in the transaction.
CREATE OR REPLACE FUNCTION app.lock_job_lease(p_job_id text, p_worker text, p_epoch bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM 1 FROM public.job
    WHERE organization_id = app.current_organization_id()
      AND id = p_job_id
      AND status = 'RUNNING'
      AND lease_owner = p_worker
      AND lease_epoch = p_epoch
      AND lease_deadline > now()
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'job lease is not current' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- Locks the version retention row and confirms it still permits derived writes
-- at the expected fence.  Invariant B/F, VER-008.
CREATE OR REPLACE FUNCTION app.assert_version_writable(p_version_id text, p_expected_fence bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM 1 FROM public.source_version_retention
    WHERE organization_id = app.current_organization_id()
      AND source_version_id = p_version_id
      AND state = 'ACTIVE'
      AND queryable
      AND extraction_allowed
      AND retention_fence = p_expected_fence
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'version retention does not permit derived writes at the expected fence' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Scope-resolution reads (SECURITY DEFINER; the worker resolves an activated
-- revision into a Scope without the runtime role touching encrypted_artifact)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_scope_sync_target(p_scope_id text, p_revision bigint)
RETURNS TABLE(
    connection_id text, connection_revision bigint, access_mode text, source_type text,
    scope_config_hash text, trust_profile_hash text,
    scope_config_resource_id text, trust_config_resource_id text,
    activation_status text, trust_verified boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.connection_id, r.connection_revision, r.access_mode, r.source_type,
           r.scope_config_hash, cr.trust_profile_hash,
           app.source_scope_revision_resource_id(r.organization_id, r.source_scope_id, r.revision),
           app.source_connection_revision_resource_id(r.organization_id, r.connection_id, r.connection_revision),
           act.status,
           EXISTS (
               SELECT 1 FROM public.source_connection_trust_record tr
               JOIN public.source_connection_trust_projection tp
                 ON tp.organization_id = tr.organization_id AND tp.trust_record_id = tr.id
               WHERE tr.organization_id = r.organization_id
                 AND tr.connection_id = r.connection_id
                 AND tr.connection_revision = r.connection_revision
                 AND tr.trust_profile_hash = cr.trust_profile_hash
                 AND tp.status = 'VERIFIED'
           )
    FROM public.source_scope_revision r
    JOIN public.source_connection_revision cr
      ON cr.organization_id = r.organization_id AND cr.connection_id = r.connection_id
     AND cr.revision = r.connection_revision AND cr.connector_type = r.source_type
    JOIN public.source_scope_activation act
      ON act.organization_id = r.organization_id AND act.source_scope_id = r.source_scope_id
     AND act.source_scope_revision = r.revision
    WHERE r.organization_id = app.current_organization_id()
      AND r.source_scope_id = p_scope_id AND r.revision = p_revision;
$$;

-- The sync worker targets the scope's latest management revision; the job
-- payload carries only the safe scope reference, never a revision integer.
CREATE OR REPLACE FUNCTION app.source_scope_pending_revision(p_scope_id text)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT latest_revision FROM public.source_scope
    WHERE organization_id = app.current_organization_id() AND id = p_scope_id;
$$;

CREATE OR REPLACE FUNCTION app.source_scope_config_read(p_resource_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.encrypted_artifact a
    WHERE a.organization_id = app.current_organization_id()
      AND a.resource_id = p_resource_id
      AND a.owner_table = 'source_scope_revision' AND a.owner_column = 'scope_config_artifact_id'
      AND a.resource_type = 'SOURCE_SCOPE_CONFIG' AND a.field_name = 'SCOPE_CONFIG'
      AND a.purged_at IS NULL;
$$;

CREATE OR REPLACE FUNCTION app.source_trust_config_read(p_resource_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.encrypted_artifact a
    WHERE a.organization_id = app.current_organization_id()
      AND a.resource_id = p_resource_id
      AND a.owner_table = 'source_connection_revision' AND a.owner_column = 'trust_profile_artifact_id'
      AND a.resource_type = 'SOURCE_TRUST_CONFIG' AND a.field_name = 'TRUST_CONFIG'
      AND a.purged_at IS NULL;
$$;

-- ---------------------------------------------------------------------------
-- Activation transitions driven by the sync worker under its lease
-- ---------------------------------------------------------------------------

-- Connection-trust verification (DRAFT->VERIFIED) is a control-plane / admin
-- authority action, not a runtime capability. No runtime role holds UPDATE on
-- source_connection_trust_projection (000006 grants only SELECT), so the trust
-- gate the sync worker checks in source_scope_begin_sync cannot be satisfied by
-- the worker itself: the transition guard exists for a future authority path,
-- but no SECURITY DEFINER setter is exposed here.

CREATE OR REPLACE FUNCTION app.source_scope_begin_sync(
    p_scope_id text, p_revision bigint, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    target record;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);
    SELECT * INTO target FROM app.source_scope_sync_target(p_scope_id, p_revision);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope revision not found' USING ERRCODE = 'P0002';
    END IF;
    IF NOT target.trust_verified THEN
        RAISE EXCEPTION 'scope activation requires VERIFIED connection trust' USING ERRCODE = '42501';
    END IF;
    UPDATE public.source_scope_activation
       SET status = 'SYNCING', changed_at = now(), activated_at = NULL
     WHERE organization_id = app.current_organization_id()
       AND source_scope_id = p_scope_id AND source_scope_revision = p_revision AND revision = 1
       AND status IN ('DRAFT', 'READY', 'FAILED', 'SYNCING');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope activation cannot begin sync from its current state' USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.source_scope_publish_ready(
    p_scope_id text, p_revision bigint, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);
    UPDATE public.source_scope_activation
       SET status = 'READY', changed_at = now(), activated_at = now()
     WHERE organization_id = app.current_organization_id()
       AND source_scope_id = p_scope_id AND source_scope_revision = p_revision AND revision = 1
       AND status = 'SYNCING';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope activation is not SYNCING' USING ERRCODE = '55000';
    END IF;
    UPDATE public.source_scope
       SET active_revision = p_revision
     WHERE organization_id = app.current_organization_id() AND id = p_scope_id
       AND (active_revision IS NULL OR active_revision <= p_revision);
END;
$$;

CREATE OR REPLACE FUNCTION app.source_scope_mark_failed(
    p_scope_id text, p_revision bigint, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);
    UPDATE public.source_scope_activation
       SET status = 'FAILED', changed_at = now(), activated_at = now()
     WHERE organization_id = app.current_organization_id()
       AND source_scope_id = p_scope_id AND source_scope_revision = p_revision AND revision = 1
       AND status = 'SYNCING';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'scope activation is not SYNCING' USING ERRCODE = '55000';
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Atomic publication of a version's active extraction (invariant G)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.source_version_publish_extraction(
    p_version_id text, p_extraction_id text, p_expected_evidence_set_hash text,
    p_make_current boolean, p_job_id text, p_worker text, p_epoch bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    org text := app.current_organization_id();
    extraction record;
    object_id text;
    fragment_count bigint;
    ordinal_min bigint;
    ordinal_max bigint;
    ordinal_distinct bigint;
BEGIN
    PERFORM app.lock_job_lease(p_job_id, p_worker, p_epoch);

    SELECT * INTO extraction FROM public.source_extraction
     WHERE organization_id = org AND id = p_extraction_id AND source_version_id = p_version_id;
    IF NOT FOUND OR extraction.status <> 'SUCCEEDED' THEN
        RAISE EXCEPTION 'publication requires a SUCCEEDED extraction of the version' USING ERRCODE = '23514';
    END IF;
    IF extraction.evidence_set_hash IS DISTINCT FROM p_expected_evidence_set_hash THEN
        RAISE EXCEPTION 'evidence_set_hash mismatch at publication' USING ERRCODE = '23514';
    END IF;

    PERFORM app.assert_version_writable(p_version_id, extraction.retention_fence_at_start);

    IF NOT EXISTS (SELECT 1 FROM public.source_extraction_retention
                   WHERE organization_id = org AND extraction_id = p_extraction_id
                     AND state = 'ACTIVE' AND queryable) THEN
        RAISE EXCEPTION 'publication requires ACTIVE queryable extraction retention' USING ERRCODE = '23514';
    END IF;

    -- Ordinal set must be closed, unique and gap-free (1..N).
    SELECT count(*), min(ordinal), max(ordinal), count(DISTINCT ordinal)
      INTO fragment_count, ordinal_min, ordinal_max, ordinal_distinct
      FROM public.evidence_fragment
     WHERE organization_id = org AND extraction_id = p_extraction_id;
    IF fragment_count = 0 OR ordinal_min <> 1 OR ordinal_max <> fragment_count OR ordinal_distinct <> fragment_count THEN
        RAISE EXCEPTION 'evidence ordinal set is not closed' USING ERRCODE = '23514';
    END IF;

    INSERT INTO public.source_version_active_extraction
        (organization_id, source_version_id, extraction_id, activation_revision, activated_at)
    VALUES (org, p_version_id, p_extraction_id, 1, now())
    ON CONFLICT (organization_id, source_version_id) DO UPDATE
        SET extraction_id = EXCLUDED.extraction_id,
            activation_revision = public.source_version_active_extraction.activation_revision + 1,
            activated_at = now();

    -- The current-version cutover is part of the same lease-fenced transaction,
    -- not a separate raw UPDATE: a stale worker can never make a version current
    -- or flip queryability. Only invoked for a newly created version; re-extraction
    -- of an already-current version leaves the version state untouched.
    IF p_make_current THEN
        SELECT source_object_id INTO object_id FROM public.source_version
         WHERE organization_id = org AND id = p_version_id;
        UPDATE public.source_version SET state = 'SUPERSEDED', superseded_at = now()
         WHERE organization_id = org AND source_object_id = object_id AND state = 'CURRENT' AND id <> p_version_id;
        UPDATE public.source_version SET state = 'CURRENT'
         WHERE organization_id = org AND id = p_version_id AND state = 'PENDING';
        UPDATE public.source_object SET current_version_id = p_version_id, queryable = true, last_seen_at = now()
         WHERE organization_id = org AND id = object_id;
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Owner-branch bind/read functions (invariant E)
-- ---------------------------------------------------------------------------

-- Emits the source_object bind/read pair for one owner column.
DO $$
DECLARE
    branch record;
BEGIN
    FOR branch IN
        SELECT * FROM (VALUES
            ('canonical_locator', 'canonical_locator_artifact_id', 'SOURCE_LOCATOR', 'CANONICAL_LOCATOR'),
            ('external_object_id', 'external_object_id_artifact_id', 'SOURCE_OBJECT_ID', 'EXTERNAL_OBJECT_ID'),
            ('title', 'title_artifact_id', 'SOURCE_TITLE', 'DISPLAY_TITLE')
        ) AS b(suffix, column_name, resource_type, field_name)
    LOOP
        EXECUTE format($f$
            CREATE FUNCTION app.source_object_bind_%1$s(
                p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
                p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
                p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
                p_aad_hash text, p_plaintext_hash text
            ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            BEGIN
                IF p_org IS DISTINCT FROM app.current_organization_id() THEN
                    RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
                END IF;
                IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
                    RAISE EXCEPTION 'resource id must equal the owning row id' USING ERRCODE = '23514';
                END IF;
                INSERT INTO public.encrypted_artifact (
                    organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
                    cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
                ) VALUES (
                    p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'source_object', %2$L, %3$L, p_resource_id, %4$L,
                    'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
                );
                UPDATE public.source_object SET %2$I = p_artifact_id
                    WHERE organization_id = p_org AND id = p_owning_row_id AND %2$I IS NULL;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'owning source_object missing or already bound' USING ERRCODE = '23514';
                END IF;
            END;
            $fn$
        $f$, branch.suffix, branch.column_name, branch.resource_type, branch.field_name);

        EXECUTE format($f$
            CREATE FUNCTION app.source_object_read_%1$s(p_owning_row_id text)
            RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
                wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
            LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
                SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
                       a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
                FROM public.source_object o
                JOIN public.encrypted_artifact a
                  ON a.organization_id = o.organization_id AND a.id = o.%2$I
                WHERE o.organization_id = app.current_organization_id()
                  AND o.id = p_owning_row_id AND a.purged_at IS NULL;
            $fn$
        $f$, branch.suffix, branch.column_name);
    END LOOP;
END;
$$;

-- Emits the evidence_fragment bind/read pair for one owner column.
DO $$
DECLARE
    branch record;
BEGIN
    FOR branch IN
        SELECT * FROM (VALUES
            ('normalized_text', 'normalized_text_artifact_id', 'EVIDENCE_TEXT', 'NORMALIZED_TEXT'),
            ('anchor', 'anchor_artifact_id', 'EVIDENCE_ANCHOR', 'CANONICAL_ANCHOR'),
            ('metadata', 'metadata_artifact_id', 'EVIDENCE_METADATA', 'METADATA')
        ) AS b(suffix, column_name, resource_type, field_name)
    LOOP
        EXECUTE format($f$
            CREATE FUNCTION app.evidence_fragment_bind_%1$s(
                p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
                p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
                p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
                p_aad_hash text, p_plaintext_hash text
            ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            BEGIN
                IF p_org IS DISTINCT FROM app.current_organization_id() THEN
                    RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
                END IF;
                IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
                    RAISE EXCEPTION 'resource id must equal the owning row id' USING ERRCODE = '23514';
                END IF;
                INSERT INTO public.encrypted_artifact (
                    organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
                    cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
                ) VALUES (
                    p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'evidence_fragment', %2$L, %3$L, p_resource_id, %4$L,
                    'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
                );
                UPDATE public.evidence_fragment SET %2$I = p_artifact_id
                    WHERE organization_id = p_org AND id = p_owning_row_id AND %2$I IS NULL;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'owning evidence_fragment missing or already bound' USING ERRCODE = '23514';
                END IF;
            END;
            $fn$
        $f$, branch.suffix, branch.column_name, branch.resource_type, branch.field_name);

        EXECUTE format($f$
            CREATE FUNCTION app.evidence_fragment_read_%1$s(p_owning_row_id text)
            RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
                wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
            LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
                SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
                       a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
                FROM public.evidence_fragment f
                JOIN public.encrypted_artifact a
                  ON a.organization_id = f.organization_id AND a.id = f.%2$I
                WHERE f.organization_id = app.current_organization_id()
                  AND f.id = p_owning_row_id AND a.purged_at IS NULL;
            $fn$
        $f$, branch.suffix, branch.column_name);
    END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- Evidence viewer authorization (invariant H, fail-closed, no existence oracle)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.evidence_fragment_readable(p_fragment_id text, p_workspace_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.evidence_fragment f
        JOIN public.source_version v
          ON v.organization_id = f.organization_id AND v.id = f.source_version_id
        JOIN public.source_object o
          ON o.organization_id = v.organization_id AND o.id = v.source_object_id
        JOIN public.source_version_retention vr
          ON vr.organization_id = v.organization_id AND vr.source_version_id = v.id
        JOIN public.source_extraction_retention er
          ON er.organization_id = f.organization_id AND er.extraction_id = f.extraction_id
        JOIN public.source_version_active_extraction ae
          ON ae.organization_id = f.organization_id AND ae.source_version_id = f.source_version_id
        JOIN public.source_object_scope os
          ON os.organization_id = o.organization_id AND os.source_object_id = o.id
        JOIN public.workspace w
          ON w.organization_id = f.organization_id AND w.id = p_workspace_id
        JOIN public.workspace_member wm
          ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
         AND wm.principal_id = app.current_principal_id()
         AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
        JOIN public.workspace_revision_source wrs
          ON wrs.organization_id = w.organization_id AND wrs.workspace_id = w.id
         AND wrs.workspace_revision = w.current_revision
         AND wrs.source_scope_id = os.source_scope_id
         AND wrs.source_scope_revision = os.source_scope_revision
         AND wrs.enabled
        JOIN public.workspace_managed_grant_confirmation c
          ON c.organization_id = w.organization_id AND c.workspace_id = w.id
         AND c.workspace_revision = w.current_revision
         AND c.source_scope_id = os.source_scope_id
         AND c.source_scope_revision = os.source_scope_revision
         AND c.access_mode = 'WORKSPACE_MANAGED'
        WHERE f.organization_id = app.current_organization_id()
          AND f.id = p_fragment_id
          AND o.lifecycle_state = 'ACTIVE'
          AND o.current_version_id = v.id
          AND v.state = 'CURRENT'
          AND vr.state = 'ACTIVE' AND vr.queryable
          AND er.state = 'ACTIVE' AND er.queryable
          AND ae.extraction_id = f.extraction_id
          AND os.membership_state = 'ACTIVE'
          AND wrs.access_mode = 'WORKSPACE_MANAGED'
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_managed_grant_revocation gr
              WHERE gr.organization_id = c.organization_id AND gr.confirmation_id = c.confirmation_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
              WHERE ar.organization_id = c.organization_id
                AND ar.grant_id = c.confirmation_actor_grant_id
          )
    );
$$;

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'source_object', 'source_object_scope', 'source_version', 'source_version_retention',
        'source_extraction', 'source_extraction_retention', 'source_version_active_extraction',
        'acl_snapshot', 'evidence_fragment', 'sync_run'
    ] LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tbl);
        EXECUTE format('CREATE POLICY %I ON public.%I USING (organization_id = app.current_organization_id())',
            tbl || '_tenant_isolation', tbl);
    END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- Grants: worker writes the catalog/evidence, app reads for the viewer.
-- No role holds direct DML on encrypted_artifact or the active-extraction
-- pointer; those move only through SECURITY DEFINER functions.
-- ---------------------------------------------------------------------------

REVOKE ALL ON TABLE
    public.source_object, public.source_object_scope, public.source_version,
    public.source_version_retention, public.source_extraction, public.source_extraction_retention,
    public.source_version_active_extraction, public.acl_snapshot, public.evidence_fragment,
    public.sync_run
FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE ON TABLE
    public.source_object, public.source_object_scope,
    public.source_version_retention, public.source_extraction, public.source_extraction_retention,
    public.acl_snapshot, public.evidence_fragment, public.sync_run
TO knowvault_worker;

-- source_version.state (the queryable-making lifecycle) is mutated only by the
-- SECURITY DEFINER publication function; the worker may create versions but not
-- UPDATE them, so a stale worker cannot flip a version to CURRENT out of band.
GRANT SELECT, INSERT ON TABLE public.source_version TO knowvault_worker;

GRANT SELECT ON TABLE public.source_version_active_extraction TO knowvault_worker;

GRANT SELECT ON TABLE
    public.source_object, public.source_object_scope, public.source_version,
    public.source_version_retention, public.source_extraction, public.source_extraction_retention,
    public.source_version_active_extraction, public.evidence_fragment
TO knowvault_app;

-- The worker also needs to read the (existing) scope control-plane rows.
GRANT SELECT ON TABLE
    public.source_scope, public.source_scope_revision, public.source_scope_activation,
    public.source_connection, public.source_connection_revision,
    public.source_connection_trust_record, public.source_connection_trust_projection
TO knowvault_worker;

REVOKE ALL ON FUNCTION
    app.source_external_version_key_is_valid(text),
    app.lock_job_lease(text, text, bigint),
    app.assert_version_writable(text, bigint),
    app.source_scope_sync_target(text, bigint),
    app.source_scope_pending_revision(text),
    app.source_scope_config_read(text),
    app.source_trust_config_read(text),
    app.source_scope_begin_sync(text, bigint, text, text, bigint),
    app.source_scope_publish_ready(text, bigint, text, text, bigint),
    app.source_scope_mark_failed(text, bigint, text, text, bigint),
    app.source_version_publish_extraction(text, text, text, boolean, text, text, bigint),
    app.evidence_fragment_readable(text, text)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.source_scope_sync_target(text, bigint),
    app.source_scope_pending_revision(text),
    app.source_scope_config_read(text),
    app.source_trust_config_read(text),
    app.source_scope_begin_sync(text, bigint, text, text, bigint),
    app.source_scope_publish_ready(text, bigint, text, text, bigint),
    app.source_scope_mark_failed(text, bigint, text, text, bigint),
    app.source_version_publish_extraction(text, text, text, boolean, text, text, bigint),
    app.lock_job_lease(text, text, bigint),
    app.assert_version_writable(text, bigint)
TO knowvault_worker;

GRANT EXECUTE ON FUNCTION app.evidence_fragment_readable(text, text) TO knowvault_app;

-- The worker inserts catalog/evidence rows whose CHECK constraints call these
-- shared validators; the executing role therefore needs EXECUTE on them.
GRANT EXECUTE ON FUNCTION
    app.source_generated_id_is_valid(text, text),
    app.stage2_opaque_id_is_valid(text),
    app.stage2_sha256_is_valid(text),
    app.source_keyed_digest_matches_version(text, bigint),
    app.source_external_version_key_is_valid(text)
TO knowvault_worker;

-- The sync worker records its scope-sync audit event inside the same publication
-- transaction (AUD-005). It gets the same append-only privileges the app role
-- has: INSERT on the event log (no UPDATE/DELETE) and the chain-head grants the
-- hash-chain trigger needs. The append-only and mutation guards from 000002 stay
-- in force for both roles.
-- S1d records a content-free audit event for each significant transition (object
-- ingested, version created, extraction activated). Each is a SOURCE_OBJECT
-- resource whose resource_id is the exact object/version/extraction id and whose
-- action distinguishes the transition, so no new resource_type is introduced and
-- the frozen audit-event contract enum is unchanged.
GRANT SELECT, INSERT ON TABLE public.audit_event TO knowvault_worker;
GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_chain_head TO knowvault_worker;
GRANT EXECUTE ON FUNCTION
    app.audit_opaque_id_is_valid(text),
    app.audit_metadata_is_allowed(jsonb),
    app.authority_audit_metadata_is_exact(text, text, jsonb)
TO knowvault_worker;

DO $$
DECLARE
    suffix text;
BEGIN
    FOREACH suffix IN ARRAY ARRAY['canonical_locator', 'external_object_id', 'title'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION app.source_object_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.source_object_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_worker', suffix);
        EXECUTE format('REVOKE ALL ON FUNCTION app.source_object_read_%1$s(text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.source_object_read_%1$s(text) TO knowvault_app, knowvault_worker', suffix);
    END LOOP;
    FOREACH suffix IN ARRAY ARRAY['normalized_text', 'anchor', 'metadata'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION app.evidence_fragment_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.evidence_fragment_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_worker', suffix);
        EXECUTE format('REVOKE ALL ON FUNCTION app.evidence_fragment_read_%1$s(text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.evidence_fragment_read_%1$s(text) TO knowvault_app, knowvault_worker', suffix);
    END LOOP;
END;
$$;

COMMIT;
