-- Stage 3 trusted access provenance for Question Run retrieval snapshots.
--
-- 000028 persisted the shape of a retrieval snapshot, but its principal and
-- policy columns were only opaque strings.  This migration installs the
-- server-owned facts those columns must reference.  The rows are append-only,
-- tenant bound and captured from the current PostgreSQL projections; a caller
-- cannot make an arbitrary ALLOW or principal-set hash authoritative.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_app') THEN
        RAISE EXCEPTION 'runtime role knowvault_app must exist before this migration';
    END IF;
END;
$$;

ALTER TABLE public.question_corpus_snapshot
    DROP CONSTRAINT question_corpus_snapshot_connector_type_check,
    ADD CONSTRAINT question_corpus_snapshot_connector_type_check
        CHECK (connector_type IN ('FOLDER', 'GIT', 'MAIL', 'SITE', 'POSTGRESQL_QUERY'));

CREATE OR REPLACE FUNCTION app.question_corpus_source_status(
    p_workspace_id text, p_source_scope_id text, p_source_scope_revision bigint
)
RETURNS TABLE(
    connector_type text,
    connector_version text,
    health text,
    content_watermark bigint,
    last_successful_sync timestamptz,
    trust_verified boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT scope.source_type,
           connection_revision.connector_version,
           CASE
               WHEN NOT trust_projection.trust_verified THEN 'UNKNOWN'
               WHEN sync.status = 'SUCCEEDED' THEN 'HEALTHY'
               WHEN sync.status = 'FAILED' THEN 'FAILED'
               WHEN sync.status = 'RUNNING' THEN 'STALE'
               ELSE 'UNKNOWN'
           END,
           CASE
               WHEN sync.cursor_after ~ '^[0-9]{1,16}$'
               THEN sync.cursor_after::bigint
               ELSE 0
           END,
           CASE WHEN sync.status = 'SUCCEEDED' THEN sync.completed_at ELSE NULL END,
           trust_projection.trust_verified
      FROM public.workspace_revision_source binding
      JOIN public.source_scope_revision scope
        ON scope.organization_id = binding.organization_id
       AND scope.source_scope_id = binding.source_scope_id
       AND scope.revision = binding.source_scope_revision
      JOIN public.source_connection_revision connection_revision
        ON connection_revision.organization_id = scope.organization_id
       AND connection_revision.connection_id = scope.connection_id
       AND connection_revision.revision = scope.connection_revision
      LEFT JOIN LATERAL (
          SELECT run.status, run.cursor_after, run.completed_at
            FROM public.sync_run run
           WHERE run.organization_id = scope.organization_id
             AND run.source_scope_id = scope.source_scope_id
             AND run.source_scope_revision = scope.revision
           ORDER BY run.started_at DESC, run.id DESC
           LIMIT 1
      ) sync ON true
      CROSS JOIN LATERAL (
          SELECT EXISTS (
              SELECT 1
                FROM public.source_connection_trust_record trust_record
                JOIN public.source_connection_trust_projection projection
                  ON projection.organization_id = trust_record.organization_id
                 AND projection.trust_record_id = trust_record.id
               WHERE trust_record.organization_id = scope.organization_id
                 AND trust_record.connection_id = scope.connection_id
                 AND trust_record.connection_revision = scope.connection_revision
                 AND trust_record.trust_profile_hash = connection_revision.trust_profile_hash
                 AND projection.status = 'VERIFIED'
                 AND trust_record.expires_at > transaction_timestamp()
          ) AS trust_verified
      ) trust_projection
     WHERE binding.organization_id = app.current_organization_id()
       AND binding.workspace_id = p_workspace_id
       AND binding.workspace_revision = (
           SELECT workspace.current_revision
             FROM public.workspace
            WHERE workspace.organization_id = binding.organization_id
              AND workspace.id = p_workspace_id
       )
       AND binding.source_scope_id = p_source_scope_id
       AND binding.source_scope_revision = p_source_scope_revision
       AND binding.enabled;
$$;

REVOKE ALL ON FUNCTION app.question_corpus_source_status(text, text, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_corpus_source_status(text, text, bigint) TO knowvault_app;

-- ACL rows intentionally have no direct runtime-table grant because they carry
-- provider subject digests.  Question retrieval needs only the current ACL
-- projection tuple, so expose that narrow projection through a server-owned
-- function instead of weakening the table boundary.
CREATE OR REPLACE FUNCTION app.question_acl_snapshot(p_source_object_id text)
RETURNS TABLE(
    id text,
    content_hash text,
    status text,
    resolved_at timestamptz,
    expires_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT acl.id, acl.content_hash, acl.status, acl.resolved_at, acl.expires_at
      FROM public.source_object object
      JOIN public.acl_snapshot acl
        ON acl.organization_id = object.organization_id
       AND acl.id = object.current_acl_snapshot_id
     WHERE object.organization_id = app.current_organization_id()
       AND object.id = p_source_object_id;
$$;

REVOKE ALL ON FUNCTION app.question_acl_snapshot(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_acl_snapshot(text) TO knowvault_app;

CREATE TABLE public.principal_set_snapshot (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    human_principal_id text NOT NULL,
    identity_provider_revision bigint NOT NULL DEFAULT 0
        CHECK (identity_provider_revision BETWEEN 0 AND 9007199254740991),
    session_revision bigint NOT NULL
        CHECK (session_revision BETWEEN 1 AND 9007199254740991),
    captured_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('RESOLVED', 'STALE', 'FAILED')),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 1048576),
    content_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(content_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, id, content_hash),
    CONSTRAINT principal_set_snapshot_principal_fk
        FOREIGN KEY (organization_id, human_principal_id)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > captured_at)
);

CREATE TABLE public.principal_set_snapshot_entry (
    organization_id text NOT NULL,
    principal_set_snapshot_id text NOT NULL,
    namespace text NOT NULL CHECK (
        char_length(namespace) BETWEEN 1 AND 256
        AND btrim(namespace) = namespace
        AND namespace !~ '[[:cntrl:]]'
    ),
    type text NOT NULL CHECK (type IN ('USER', 'GROUP', 'SERVICE', 'SPECIAL')),
    subject_digest text NOT NULL CHECK (app.retrieval_hmac_digest_is_valid(subject_digest)),
    digest_key_version bigint NOT NULL CHECK (digest_key_version BETWEEN 1 AND 999999999),
    provider_revision bigint NOT NULL CHECK (provider_revision BETWEEN 0 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, principal_set_snapshot_id, namespace, type, subject_digest, provider_revision),
    CONSTRAINT principal_set_snapshot_entry_snapshot_fk
        FOREIGN KEY (organization_id, principal_set_snapshot_id)
        REFERENCES public.principal_set_snapshot (organization_id, id) ON DELETE RESTRICT
);

CREATE TABLE public.policy_decision (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    actor_principal_id text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('question.run.create', 'question.run.read', 'question.evidence.read')),
    resource_type text NOT NULL CHECK (resource_type IN ('QUESTION_RUN', 'EVIDENCE_FRAGMENT')),
    resource_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(resource_id)),
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    policy_revision text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_revision)),
    policy_revision_number bigint NOT NULL CHECK (policy_revision_number BETWEEN 1 AND 9007199254740991),
    policy_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(policy_hash)),
    decision text NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    membership_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(membership_id)),
    membership_role text NOT NULL CHECK (membership_role IN ('OWNER', 'MANAGER', 'MEMBER', 'VIEWER', 'AUDITOR')),
    reason_codes_json jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (app.retrieval_snapshot_error_codes_valid(reason_codes_json)),
    principal_set_snapshot_id text NOT NULL,
    principal_set_snapshot_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(principal_set_snapshot_hash)),
    decided_at timestamptz NOT NULL,
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 1048576),
    decision_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(decision_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, id, decision_hash),
    CONSTRAINT policy_decision_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_decision_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_decision_policy_fk
        FOREIGN KEY (organization_id, policy_revision_number, policy_revision)
        REFERENCES public.organization_policy_revision (organization_id, revision, policy_revision_id)
        ON DELETE RESTRICT,
    CONSTRAINT policy_decision_principal_set_fk
        FOREIGN KEY (organization_id, principal_set_snapshot_id)
        REFERENCES public.principal_set_snapshot (organization_id, id) ON DELETE RESTRICT
);

-- One immutable link makes the exact identity/policy facts discoverable from a
-- Question Run without copying authority into every candidate row.
CREATE TABLE public.question_access_provenance (
    organization_id text NOT NULL,
    question_run_id text NOT NULL,
    policy_decision_id text NOT NULL,
    policy_revision_id text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision BETWEEN 1 AND 9007199254740991),
    policy_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(policy_hash)),
    principal_set_snapshot_id text NOT NULL,
    principal_set_snapshot_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(principal_set_snapshot_hash)),
    principal_id text NOT NULL,
    principal_status text NOT NULL CHECK (principal_status IN ('ACTIVE', 'DISABLED', 'DEPROVISIONED')),
    principal_session_revision bigint NOT NULL CHECK (principal_session_revision BETWEEN 1 AND 9007199254740991),
    membership_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(membership_id)),
    membership_role text NOT NULL CHECK (membership_role IN ('OWNER', 'MANAGER', 'MEMBER', 'VIEWER', 'AUDITOR')),
    captured_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    principal_canonical_bytes bytea NOT NULL CHECK (octet_length(principal_canonical_bytes) BETWEEN 1 AND 1048576),
    policy_canonical_bytes bytea NOT NULL CHECK (octet_length(policy_canonical_bytes) BETWEEN 1 AND 1048576),
    provenance_canonical_bytes bytea NOT NULL CHECK (octet_length(provenance_canonical_bytes) BETWEEN 1 AND 1048576),
    provenance_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(provenance_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, question_run_id),
    CONSTRAINT question_access_provenance_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_access_provenance_policy_fk
        FOREIGN KEY (organization_id, policy_decision_id)
        REFERENCES public.policy_decision (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_access_provenance_principal_set_fk
        FOREIGN KEY (organization_id, principal_set_snapshot_id)
        REFERENCES public.principal_set_snapshot (organization_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > captured_at)
);

CREATE INDEX principal_set_snapshot_entry_digest
    ON public.principal_set_snapshot_entry (organization_id, subject_digest);
CREATE INDEX policy_decision_question_resource
    ON public.policy_decision (organization_id, resource_type, resource_id, decided_at);

CREATE OR REPLACE FUNCTION app.principal_set_snapshot_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_status text;
    current_session bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'principal-set snapshots are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
       OR NEW.status <> 'RESOLVED'
       OR NEW.content_hash IS DISTINCT FROM 'sha256:' || encode(sha256(NEW.canonical_bytes), 'hex') THEN
        RAISE EXCEPTION 'principal-set snapshot is not a trusted resolved projection' USING ERRCODE = '42501';
    END IF;
    SELECT status, session_revision INTO current_status, current_session
      FROM public.principal
     WHERE organization_id = NEW.organization_id AND id = NEW.human_principal_id;
    IF NOT FOUND OR current_status <> 'ACTIVE' OR current_session IS DISTINCT FROM NEW.session_revision THEN
        RAISE EXCEPTION 'principal-set snapshot principal is stale' USING ERRCODE = '42501';
    END IF;
    IF NEW.identity_provider_revision > 0 AND NOT EXISTS (
        SELECT 1 FROM public.oidc_provider
         WHERE organization_id = NEW.organization_id
           AND status = 'ACTIVE'
           AND current_revision = NEW.identity_provider_revision
    ) THEN
        RAISE EXCEPTION 'principal-set snapshot provider revision is unknown' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.principal_set_snapshot_entry_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    snapshot_human_principal text;
    principal_type text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'principal-set snapshot entries are immutable' USING ERRCODE = '55000';
    END IF;
    SELECT snapshot.human_principal_id
      INTO snapshot_human_principal
      FROM public.principal_set_snapshot snapshot
     WHERE snapshot.organization_id = NEW.organization_id
       AND snapshot.id = NEW.principal_set_snapshot_id
       AND snapshot.status = 'RESOLVED'
       AND snapshot.expires_at > snapshot.captured_at;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
       OR snapshot_human_principal IS NULL THEN
        RAISE EXCEPTION 'principal-set entry has no resolved snapshot' USING ERRCODE = '42501';
    END IF;
    SELECT principal.type INTO principal_type
      FROM public.principal
     WHERE principal.organization_id = NEW.organization_id
       AND principal.id = snapshot_human_principal;
    IF principal_type IS NULL OR left(NEW.namespace, 5) <> 'oidc:' OR NOT EXISTS (
        SELECT 1
          FROM public.external_identity identity
          JOIN public.oidc_provider provider
            ON provider.organization_id = identity.organization_id
           AND provider.id = identity.provider_id
         WHERE identity.organization_id = NEW.organization_id
           AND identity.principal_id = snapshot_human_principal
           AND NEW.namespace = 'oidc:' || provider.id
           AND NEW.type = principal_type
           AND identity.external_subject_digest = NEW.subject_digest
           AND identity.digest_key_version = NEW.digest_key_version
           AND identity.status = 'ACTIVE'
           AND provider.status = 'ACTIVE'
           AND provider.current_revision = NEW.provider_revision
    ) THEN
        RAISE EXCEPTION 'principal-set entry does not match a current identity projection' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.policy_decision_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_policy bigint;
    current_hash text;
    snapshot_hash text;
    canonical jsonb;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'policy decisions are immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
       OR NEW.decision <> 'ALLOW'
       OR NEW.decision_hash IS DISTINCT FROM 'sha256:' || encode(sha256(NEW.canonical_bytes), 'hex') THEN
        RAISE EXCEPTION 'policy decision is not a trusted ALLOW projection' USING ERRCODE = '42501';
    END IF;
    BEGIN
        canonical := convert_from(NEW.canonical_bytes, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'policy decision canonical bytes are invalid' USING ERRCODE = '42501';
    END;
    IF canonical ->> 'schema_version' IS DISTINCT FROM 'question-policy-decision-v1'
       OR canonical ->> 'organization_id' IS DISTINCT FROM NEW.organization_id
       OR canonical ->> 'question_run_id' IS DISTINCT FROM NEW.resource_id
       OR canonical ->> 'workspace_id' IS DISTINCT FROM NEW.workspace_id
       OR (canonical ->> 'workspace_revision')::bigint IS DISTINCT FROM NEW.workspace_revision
       OR canonical ->> 'principal_id' IS DISTINCT FROM NEW.actor_principal_id
       OR canonical ->> 'membership_id' IS DISTINCT FROM NEW.membership_id
       OR canonical ->> 'membership_role' IS DISTINCT FROM NEW.membership_role
       OR canonical ->> 'policy_revision_id' IS DISTINCT FROM NEW.policy_revision
       OR (canonical ->> 'policy_revision')::bigint IS DISTINCT FROM NEW.policy_revision_number
       OR canonical ->> 'policy_hash' IS DISTINCT FROM NEW.policy_hash
       OR canonical ->> 'decision' IS DISTINCT FROM NEW.decision
       OR canonical ->> 'operation' IS DISTINCT FROM NEW.operation
       OR canonical ->> 'resource_type' IS DISTINCT FROM NEW.resource_type
       OR canonical ->> 'principal_set_snapshot_id' IS DISTINCT FROM NEW.principal_set_snapshot_id
       OR canonical ->> 'principal_set_snapshot_hash' IS DISTINCT FROM NEW.principal_set_snapshot_hash THEN
        RAISE EXCEPTION 'policy decision canonical projection does not exact-match columns' USING ERRCODE = '42501';
    END IF;
    SELECT organization.policy_revision, registry.policy_hash
      INTO current_policy, current_hash
      FROM public.organization organization
      JOIN public.organization_policy_revision registry
        ON registry.organization_id = organization.id
       AND registry.revision = organization.policy_revision
     WHERE organization.id = NEW.organization_id;
    IF NOT FOUND OR current_policy IS DISTINCT FROM NEW.policy_revision_number
       OR current_hash IS DISTINCT FROM NEW.policy_hash THEN
        RAISE EXCEPTION 'policy decision uses a stale policy revision' USING ERRCODE = '42501';
    END IF;
    SELECT content_hash INTO snapshot_hash
      FROM public.principal_set_snapshot
     WHERE organization_id = NEW.organization_id AND id = NEW.principal_set_snapshot_id
       AND status = 'RESOLVED';
    IF snapshot_hash IS NULL OR snapshot_hash IS DISTINCT FROM NEW.principal_set_snapshot_hash THEN
        RAISE EXCEPTION 'policy decision principal-set binding is not exact' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_access_provenance_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    run_row public.question_run%ROWTYPE;
    decision public.policy_decision%ROWTYPE;
    snapshot public.principal_set_snapshot%ROWTYPE;
    member_principal text;
    member_role text;
    current_principal_status text;
    run_found boolean := false;
    decision_found boolean := false;
    snapshot_found boolean := false;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'question access provenance is immutable' USING ERRCODE = '55000';
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'question access provenance requires the runtime tenant' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO run_row FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    run_found := FOUND;
    IF NOT run_found OR run_row.result_status NOT IN ('QUEUED', 'RUNNING')
       OR NEW.captured_at IS DISTINCT FROM run_row.started_at THEN
        RAISE EXCEPTION 'question access provenance is outside the active run interval' USING ERRCODE = '23514';
    END IF;
    SELECT * INTO decision FROM public.policy_decision
     WHERE organization_id = NEW.organization_id AND id = NEW.policy_decision_id;
    decision_found := FOUND;
    SELECT * INTO snapshot FROM public.principal_set_snapshot
     WHERE organization_id = NEW.organization_id AND id = NEW.principal_set_snapshot_id;
    snapshot_found := FOUND;
    IF NOT decision_found OR NOT snapshot_found OR decision.decision <> 'ALLOW'
       OR decision.operation <> 'question.evidence.read'
       OR decision.resource_type <> 'QUESTION_RUN'
       OR decision.resource_id IS DISTINCT FROM NEW.question_run_id
       OR decision.actor_principal_id IS DISTINCT FROM run_row.created_by
       OR decision.workspace_id IS DISTINCT FROM run_row.workspace_id
       OR decision.workspace_revision IS DISTINCT FROM run_row.workspace_revision
       OR decision.policy_revision IS DISTINCT FROM NEW.policy_revision_id
       OR decision.policy_revision_number IS DISTINCT FROM NEW.policy_revision
       OR decision.policy_hash IS DISTINCT FROM NEW.policy_hash
       OR decision.principal_set_snapshot_id IS DISTINCT FROM NEW.principal_set_snapshot_id
       OR decision.principal_set_snapshot_hash IS DISTINCT FROM NEW.principal_set_snapshot_hash
       OR decision.membership_id IS DISTINCT FROM NEW.membership_id
       OR decision.membership_role IS DISTINCT FROM NEW.membership_role
       OR snapshot.status <> 'RESOLVED'
       OR snapshot.human_principal_id IS DISTINCT FROM NEW.principal_id
       OR snapshot.session_revision IS DISTINCT FROM NEW.principal_session_revision
       OR NEW.principal_status IS DISTINCT FROM 'ACTIVE'
       OR NEW.policy_canonical_bytes IS DISTINCT FROM decision.canonical_bytes
       OR NEW.principal_canonical_bytes IS DISTINCT FROM snapshot.canonical_bytes
       OR NEW.provenance_hash IS DISTINCT FROM 'sha256:' || encode(sha256(NEW.provenance_canonical_bytes), 'hex')
       OR NEW.expires_at <= NEW.captured_at THEN
        RAISE EXCEPTION 'question access provenance projections do not exact-match' USING ERRCODE = '42501';
    END IF;
    SELECT member.principal_id, member.role INTO member_principal, member_role
      FROM public.workspace_member member
     WHERE member.organization_id = NEW.organization_id
       AND member.id = NEW.membership_id
       AND member.workspace_id = run_row.workspace_id
       AND member.removed_at IS NULL
       AND member.valid_from_revision <= run_row.workspace_revision
       AND (member.valid_to_revision IS NULL OR member.valid_to_revision >= run_row.workspace_revision);
    IF member_principal IS DISTINCT FROM NEW.principal_id OR member_role IS DISTINCT FROM NEW.membership_role THEN
        RAISE EXCEPTION 'question access provenance membership is not current' USING ERRCODE = '42501';
    END IF;
    SELECT principal.status INTO current_principal_status
      FROM public.principal principal
     WHERE principal.organization_id = NEW.organization_id
       AND principal.id = NEW.principal_id
       AND principal.session_revision = NEW.principal_session_revision;
    IF current_principal_status IS DISTINCT FROM NEW.principal_status THEN
        RAISE EXCEPTION 'question access provenance principal status is not current' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.question_context_authority_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    provenance public.question_access_provenance%ROWTYPE;
    decision public.policy_decision%ROWTYPE;
    snapshot public.principal_set_snapshot%ROWTYPE;
    current_session bigint;
    current_policy bigint;
    provenance_found boolean := false;
    decision_found boolean := false;
    snapshot_found boolean := false;
    run_workspace text;
    run_revision bigint;
    run_creator text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'retrieval context entries are immutable' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO provenance FROM public.question_access_provenance
     WHERE organization_id = NEW.organization_id AND question_run_id = NEW.question_run_id;
    provenance_found := FOUND;
    SELECT * INTO decision FROM public.policy_decision
     WHERE organization_id = NEW.organization_id AND id = NEW.policy_decision_id;
    decision_found := FOUND;
    SELECT * INTO snapshot FROM public.principal_set_snapshot
     WHERE organization_id = NEW.organization_id AND id = NEW.principal_set_snapshot_id;
    snapshot_found := FOUND;
    SELECT workspace_id, workspace_revision, created_by
      INTO run_workspace, run_revision, run_creator
      FROM public.question_run
     WHERE organization_id = NEW.organization_id AND id = NEW.question_run_id;
    IF NOT provenance_found OR NOT decision_found OR NOT snapshot_found
       OR provenance.policy_decision_id IS DISTINCT FROM NEW.policy_decision_id
       OR provenance.principal_set_snapshot_id IS DISTINCT FROM NEW.principal_set_snapshot_id
       OR provenance.principal_set_snapshot_hash IS DISTINCT FROM NEW.principal_set_snapshot_hash
       OR decision.decision <> 'ALLOW'
       OR decision.operation <> 'question.evidence.read'
       OR decision.resource_type <> 'QUESTION_RUN'
       OR decision.resource_id IS DISTINCT FROM NEW.question_run_id
       OR decision.actor_principal_id IS DISTINCT FROM run_creator
       OR decision.workspace_id IS DISTINCT FROM run_workspace
       OR decision.workspace_revision IS DISTINCT FROM run_revision
       OR decision.principal_set_snapshot_hash IS DISTINCT FROM NEW.principal_set_snapshot_hash
       OR snapshot.status <> 'RESOLVED'
       OR NEW.policy_decision <> 'ALLOW'
       OR NEW.authorized_at < provenance.captured_at
       OR NEW.authorized_at >= provenance.expires_at
       OR NEW.principal_set_captured_at IS DISTINCT FROM snapshot.captured_at
       OR NEW.principal_set_expires_at IS DISTINCT FROM snapshot.expires_at THEN
        RAISE EXCEPTION 'retrieval context authority is not an exact trusted decision' USING ERRCODE = '42501';
    END IF;
    SELECT session_revision INTO current_session
      FROM public.principal
     WHERE organization_id = NEW.organization_id AND id = snapshot.human_principal_id
       AND status = 'ACTIVE';
    SELECT policy_revision INTO current_policy
      FROM public.organization
     WHERE id = NEW.organization_id AND status = 'ACTIVE';
    IF current_session IS NULL OR current_session IS DISTINCT FROM snapshot.session_revision
       OR current_policy IS NULL OR current_policy IS DISTINCT FROM decision.policy_revision_number
       OR NOT EXISTS (
           SELECT 1 FROM public.workspace_member member
            WHERE member.organization_id = NEW.organization_id
              AND member.id = provenance.membership_id
              AND member.workspace_id = run_workspace
              AND member.principal_id = snapshot.human_principal_id
              AND member.role IN ('OWNER', 'MANAGER', 'MEMBER')
              AND member.removed_at IS NULL
              AND member.valid_from_revision <= run_revision
              AND (member.valid_to_revision IS NULL OR member.valid_to_revision >= run_revision)
       ) THEN
        RAISE EXCEPTION 'retrieval context authority was revoked or policy advanced' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER principal_set_snapshot_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.principal_set_snapshot
FOR EACH ROW EXECUTE FUNCTION app.principal_set_snapshot_guard();
CREATE TRIGGER principal_set_snapshot_entry_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.principal_set_snapshot_entry
FOR EACH ROW EXECUTE FUNCTION app.principal_set_snapshot_entry_guard();
CREATE TRIGGER policy_decision_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.policy_decision
FOR EACH ROW EXECUTE FUNCTION app.policy_decision_guard();
CREATE TRIGGER question_access_provenance_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_access_provenance
FOR EACH ROW EXECUTE FUNCTION app.question_access_provenance_guard();
CREATE TRIGGER question_context_authority_state_guard
BEFORE INSERT ON public.question_retrieval_context_entry
FOR EACH ROW EXECUTE FUNCTION app.question_context_authority_guard();

ALTER TABLE public.question_retrieval_context_entry
    ADD CONSTRAINT question_context_policy_decision_fk
    FOREIGN KEY (organization_id, policy_decision_id)
    REFERENCES public.policy_decision (organization_id, id) ON DELETE RESTRICT;
ALTER TABLE public.question_retrieval_context_entry
    ADD CONSTRAINT question_context_principal_set_fk
    FOREIGN KEY (organization_id, principal_set_snapshot_id)
    REFERENCES public.principal_set_snapshot (organization_id, id) ON DELETE RESTRICT;

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'principal_set_snapshot', 'principal_set_snapshot_entry',
        'policy_decision', 'question_access_provenance'
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
    public.principal_set_snapshot,
    public.principal_set_snapshot_entry,
    public.policy_decision,
    public.question_access_provenance
FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE
    public.principal_set_snapshot,
    public.principal_set_snapshot_entry,
    public.policy_decision,
    public.question_access_provenance
TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.principal_set_snapshot_guard(),
    app.principal_set_snapshot_entry_guard(),
    app.policy_decision_guard(),
    app.question_access_provenance_guard(),
    app.question_context_authority_guard()
FROM PUBLIC;

COMMIT;
