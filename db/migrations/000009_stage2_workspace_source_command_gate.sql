-- Stage 2 workspace-source configuration command proof gate.
--
-- This migration makes source binding configuration writable by the runtime
-- only as one exact, receipt-backed workspace revision.  It creates no source
-- activation, access grant, ingestion job or query authority.

BEGIN;

-- Audit may describe a completed binding projection, but only through the
-- closed seven-field, content-free vocabulary checked below.
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
               'remote_address_digest', 'user_agent_family'
           )
       );
$$;

ALTER TABLE public.audit_event
    DROP CONSTRAINT audit_event_resource_type_check;
ALTER TABLE public.audit_event
    ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
        'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
        'WORKSPACE_SOURCE', 'SOURCE_CONNECTION', 'SOURCE_SCOPE',
        'SOURCE_OBJECT', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
        'SIGNING_KEY', 'AUDIT_CHECKPOINT'
    ));

CREATE OR REPLACE FUNCTION app.workspace_source_audit_integer_is_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN jsonb_typeof(value) <> 'number' THEN false
        WHEN (value #>> '{}') !~ '^[1-9][0-9]{0,15}$' THEN false
        ELSE (value #>> '{}')::numeric <= 9007199254740991
    END;
$$;

CREATE OR REPLACE FUNCTION app.workspace_source_generated_id_is_valid(value text, prefix_value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE prefix_value
        WHEN 'binding' THEN value ~ '^binding_[0-7][0-9A-HJKMNP-TV-Z]{25}$'
        WHEN 'scope' THEN value ~ '^scope_[0-7][0-9A-HJKMNP-TV-Z]{25}$'
        ELSE false
    END;
$$;

-- 000008 could rely on the shared validator while the runtime was SELECT-only.
-- Runtime INSERT must not regain EXECUTE on that caller-prefix regex helper,
-- so replace the sole writable CHECK with this closed binding-only wrapper.
ALTER TABLE public.workspace_source
    DROP CONSTRAINT workspace_source_id_check,
    ADD CONSTRAINT workspace_source_id_closed_check CHECK (
        app.workspace_source_generated_id_is_valid(id, 'binding')
    );

CREATE OR REPLACE FUNCTION app.workspace_source_audit_projection_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    expected_enabled boolean;
BEGIN
    IF NEW.action IN ('workspace.source_added', 'workspace.source_removed') THEN
        expected_enabled := NEW.action = 'workspace.source_added';
        IF NEW.resource_type <> 'WORKSPACE_SOURCE'
           OR (NEW.outcome = 'SUCCESS' AND NEW.workspace_id IS NULL)
           OR NEW.policy_decision_id IS NOT NULL
           OR NEW.referenced_evidence_ids_json <> '[]'::jsonb
           OR (SELECT count(*) FROM jsonb_object_keys(NEW.metadata_json)) <> 7
           OR NOT (NEW.metadata_json ?& ARRAY[
                'workspace_revision', 'workspace_source_id',
                'source_scope_id', 'source_scope_revision',
                'scope_config_hash', 'access_mode', 'enabled'
           ])
           OR NOT app.workspace_source_audit_integer_is_valid(NEW.metadata_json -> 'workspace_revision')
           OR jsonb_typeof(NEW.metadata_json -> 'workspace_source_id') <> 'string'
           OR NOT app.workspace_source_generated_id_is_valid(NEW.metadata_json ->> 'workspace_source_id', 'binding')
           OR NEW.resource_id <> NEW.metadata_json ->> 'workspace_source_id'
           OR jsonb_typeof(NEW.metadata_json -> 'source_scope_id') <> 'string'
           OR NOT app.workspace_source_generated_id_is_valid(NEW.metadata_json ->> 'source_scope_id', 'scope')
           OR NOT app.workspace_source_audit_integer_is_valid(NEW.metadata_json -> 'source_scope_revision')
           OR jsonb_typeof(NEW.metadata_json -> 'scope_config_hash') <> 'string'
           OR NOT app.stage2_sha256_is_valid(NEW.metadata_json ->> 'scope_config_hash')
           OR jsonb_typeof(NEW.metadata_json -> 'access_mode') <> 'string'
           OR NEW.metadata_json ->> 'access_mode' NOT IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')
           OR jsonb_typeof(NEW.metadata_json -> 'enabled') <> 'boolean'
           OR (NEW.metadata_json ->> 'enabled')::boolean IS DISTINCT FROM expected_enabled THEN
            RAISE EXCEPTION 'workspace source audit projection is not exact'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.resource_type = 'WORKSPACE_SOURCE'
       OR NEW.metadata_json ? 'workspace_revision'
       OR NEW.metadata_json ? 'workspace_source_id'
       OR NEW.metadata_json ? 'scope_config_hash'
       OR NEW.metadata_json ? 'access_mode'
       OR NEW.metadata_json ? 'enabled' THEN
        RAISE EXCEPTION 'workspace source audit vocabulary is reserved'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_workspace_source_projection
BEFORE INSERT ON public.audit_event
FOR EACH ROW EXECUTE FUNCTION app.workspace_source_audit_projection_guard();

-- Extend the one existing primary proof receipt. Old command rows remain
-- gate-v1 and must keep every source-target field NULL. Only the four closed
-- constraints whose vocabularies change are replaced; all original receipt
-- hash, terminal-result, audit-ID and time invariants remain in place.
ALTER TABLE public.workspace_command_receipt
    ADD COLUMN source_expected_workspace_revision bigint CHECK (
        source_expected_workspace_revision IS NULL
        OR source_expected_workspace_revision BETWEEN 1 AND 9007199254740991
    ),
    ADD COLUMN source_expected_configuration_hash text CHECK (
        source_expected_configuration_hash IS NULL
        OR app.workspace_command_hash_is_valid(source_expected_configuration_hash)
    ),
    ADD COLUMN command_workspace_source_id text CHECK (
        command_workspace_source_id IS NULL
        OR app.workspace_source_generated_id_is_valid(command_workspace_source_id, 'binding')
    ),
    ADD COLUMN command_source_scope_id text CHECK (
        command_source_scope_id IS NULL
        OR app.workspace_source_generated_id_is_valid(command_source_scope_id, 'scope')
    ),
    ADD COLUMN command_source_scope_revision bigint CHECK (
        command_source_scope_revision IS NULL
        OR command_source_scope_revision BETWEEN 1 AND 9007199254740991
    ),
    ADD COLUMN command_scope_config_hash text CHECK (
        command_scope_config_hash IS NULL OR app.stage2_sha256_is_valid(command_scope_config_hash)
    ),
    ADD COLUMN command_access_mode text CHECK (
        command_access_mode IS NULL OR command_access_mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')
    );

ALTER TABLE public.workspace_command_receipt
    DROP CONSTRAINT workspace_command_receipt_gate_version_check,
    DROP CONSTRAINT workspace_command_receipt_command_resource_type_check,
    DROP CONSTRAINT workspace_command_receipt_operation_check,
    DROP CONSTRAINT workspace_command_receipt_check3;

ALTER TABLE public.workspace_command_receipt
    ADD CONSTRAINT workspace_command_receipt_gate_version_valid CHECK (gate_version IN (1, 2)),
    ADD CONSTRAINT workspace_command_receipt_resource_type_valid CHECK (
        command_resource_type IN ('WORKSPACE', 'WORKSPACE_MEMBER', 'WORKSPACE_SOURCE')
    ),
    ADD CONSTRAINT workspace_command_receipt_operation_valid CHECK (operation IN (
        'WORKSPACE_CREATE', 'WORKSPACE_UPDATE', 'WORKSPACE_ARCHIVE',
        'WORKSPACE_MEMBER_ADD', 'WORKSPACE_MEMBER_ROLE_CHANGE',
        'WORKSPACE_MEMBER_REMOVE', 'WORKSPACE_OWNERSHIP_TRANSFER',
        'WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE'
    )),
    ADD CONSTRAINT workspace_command_receipt_operation_shape CHECK (
        (operation = 'WORKSPACE_CREATE' AND gate_version = 1
            AND command_target_principal_id IS NULL AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE' AND command_resource_id = command_workspace_id)
        OR (operation IN ('WORKSPACE_UPDATE', 'WORKSPACE_ARCHIVE') AND gate_version = 1
            AND command_target_principal_id IS NULL AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE' AND command_resource_id = command_workspace_id)
        OR (operation IN ('WORKSPACE_MEMBER_ADD', 'WORKSPACE_MEMBER_ROLE_CHANGE') AND gate_version = 1
            AND command_target_principal_id IS NOT NULL
            AND command_target_role IN ('MANAGER', 'MEMBER', 'VIEWER', 'AUDITOR')
            AND command_resource_type = 'WORKSPACE_MEMBER')
        OR (operation = 'WORKSPACE_MEMBER_REMOVE' AND gate_version = 1
            AND command_target_principal_id IS NOT NULL AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE_MEMBER')
        OR (operation = 'WORKSPACE_OWNERSHIP_TRANSFER' AND gate_version = 1
            AND command_target_principal_id IS NOT NULL AND command_target_role = 'OWNER'
            AND command_resource_type = 'WORKSPACE' AND command_resource_id = command_workspace_id)
        OR (operation IN ('WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE') AND gate_version = 2
            AND command_target_principal_id IS NULL AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE_SOURCE'
            AND command_resource_id = command_workspace_source_id
            AND source_expected_workspace_revision IS NOT NULL
            AND source_expected_configuration_hash IS NOT NULL
            AND command_workspace_source_id IS NOT NULL
            AND command_source_scope_id IS NOT NULL
            AND command_source_scope_revision IS NOT NULL
            AND command_scope_config_hash IS NOT NULL
            AND command_access_mode IS NOT NULL)
    ),
    ADD CONSTRAINT workspace_command_receipt_non_source_fields_null CHECK (
        operation IN ('WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE')
        OR (source_expected_workspace_revision IS NULL
            AND source_expected_configuration_hash IS NULL
            AND command_workspace_source_id IS NULL
            AND command_source_scope_id IS NULL
            AND command_source_scope_revision IS NULL
            AND command_scope_config_hash IS NULL
            AND command_access_mode IS NULL)
    );

CREATE OR REPLACE FUNCTION app.workspace_command_receipt_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.actor_principal_id <> OLD.actor_principal_id
       OR NEW.idempotency_key_hash <> OLD.idempotency_key_hash
       OR NEW.gate_version <> OLD.gate_version
       OR NEW.command_workspace_id <> OLD.command_workspace_id
       OR NEW.command_target_principal_id IS DISTINCT FROM OLD.command_target_principal_id
       OR NEW.command_target_role IS DISTINCT FROM OLD.command_target_role
       OR NEW.command_resource_type <> OLD.command_resource_type
       OR NEW.command_resource_id <> OLD.command_resource_id
       OR NEW.operation <> OLD.operation
       OR NEW.canonical_request_hash <> OLD.canonical_request_hash
       OR NEW.source_expected_workspace_revision IS DISTINCT FROM OLD.source_expected_workspace_revision
       OR NEW.source_expected_configuration_hash IS DISTINCT FROM OLD.source_expected_configuration_hash
       OR NEW.command_workspace_source_id IS DISTINCT FROM OLD.command_workspace_source_id
       OR NEW.command_source_scope_id IS DISTINCT FROM OLD.command_source_scope_id
       OR NEW.command_source_scope_revision IS DISTINCT FROM OLD.command_source_scope_revision
       OR NEW.command_scope_config_hash IS DISTINCT FROM OLD.command_scope_config_hash
       OR NEW.command_access_mode IS DISTINCT FROM OLD.command_access_mode
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'workspace command receipt identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status <> 'PENDING' THEN
        RAISE EXCEPTION 'terminal workspace command receipt is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.status NOT IN ('SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')
       OR NEW.terminal_at <> transaction_timestamp() THEN
        RAISE EXCEPTION 'workspace command receipt must transition once to a terminal state' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.workspace_command_gate_expected_action(operation text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE operation
        WHEN 'WORKSPACE_CREATE' THEN 'workspace.created'
        WHEN 'WORKSPACE_UPDATE' THEN 'workspace.updated'
        WHEN 'WORKSPACE_ARCHIVE' THEN 'workspace.archived'
        WHEN 'WORKSPACE_MEMBER_ADD' THEN 'workspace.member_added'
        WHEN 'WORKSPACE_MEMBER_ROLE_CHANGE' THEN 'workspace.role_changed'
        WHEN 'WORKSPACE_MEMBER_REMOVE' THEN 'workspace.member_removed'
        WHEN 'WORKSPACE_OWNERSHIP_TRANSFER' THEN 'workspace.role_changed'
        WHEN 'WORKSPACE_SOURCE_ADD' THEN 'workspace.source_added'
        WHEN 'WORKSPACE_SOURCE_REMOVE' THEN 'workspace.source_removed'
        ELSE NULL
    END;
$$;

-- Compare two immutable relational projections.  Exactly zero differences is
-- required for ordinary commands; source commands may change only their one
-- declared stable binding row.
CREATE OR REPLACE FUNCTION app.workspace_source_projection_difference_count(
    expected_organization_id text,
    expected_workspace_id text,
    old_revision bigint,
    new_revision bigint,
    ignored_workspace_source_id text DEFAULT NULL
)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT count(*)
    FROM (
        SELECT COALESCE(old_row.workspace_source_id, new_row.workspace_source_id) AS binding_id
        FROM (
            SELECT * FROM public.workspace_revision_source
            WHERE organization_id = expected_organization_id
              AND workspace_id = expected_workspace_id
              AND workspace_revision = old_revision
        ) AS old_row
        FULL JOIN (
            SELECT * FROM public.workspace_revision_source
            WHERE organization_id = expected_organization_id
              AND workspace_id = expected_workspace_id
              AND workspace_revision = new_revision
        ) AS new_row
          ON new_row.organization_id = old_row.organization_id
         AND new_row.workspace_id = old_row.workspace_id
         AND new_row.workspace_source_id = old_row.workspace_source_id
        WHERE COALESCE(old_row.workspace_source_id, new_row.workspace_source_id) IS DISTINCT FROM ignored_workspace_source_id
          AND (old_row.workspace_source_id IS NULL OR new_row.workspace_source_id IS NULL
               OR old_row.source_scope_id IS DISTINCT FROM new_row.source_scope_id
               OR old_row.source_scope_revision IS DISTINCT FROM new_row.source_scope_revision
               OR old_row.scope_config_hash IS DISTINCT FROM new_row.scope_config_hash
               OR old_row.access_mode IS DISTINCT FROM new_row.access_mode
               OR old_row.enabled IS DISTINCT FROM new_row.enabled)
    ) AS differences;
$$;

CREATE OR REPLACE FUNCTION app.workspace_command_source_projection_validator()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    audit_row record;
    revision_created_at timestamptz;
    snapshot_created_at timestamptz;
    started_count integer;
    closed_count integer;
    previous_hash text;
    old_target record;
    new_target record;
    other_differences bigint;
    expected_enabled boolean;
    expected_audit_revision bigint;
    previous_canonical jsonb;
    result_canonical jsonb;
BEGIN
    IF NOT app.workspace_command_gate_runtime() OR NEW.status = 'PENDING' THEN
        RETURN NULL;
    END IF;

    -- The stage-1 terminal validator continues to own every ordinary command.
    -- This extra gate only proves that its new revision carried the complete
    -- source projection forward byte-for-byte (or remained empty at create).
    IF NEW.operation NOT IN ('WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE') THEN
        IF NEW.status <> 'SUCCESS' THEN
            RETURN NULL;
        END IF;
        IF NEW.result_workspace_revision = 1 THEN
            IF EXISTS (
                SELECT 1 FROM public.workspace_revision_source
                WHERE organization_id = NEW.organization_id
                  AND workspace_id = NEW.result_workspace_id
                  AND workspace_revision = 1
            ) THEN
                RAISE EXCEPTION 'workspace create cannot introduce source projection' USING ERRCODE = '23514';
            END IF;
        ELSIF app.workspace_source_projection_difference_count(
            NEW.organization_id, NEW.result_workspace_id,
            NEW.result_workspace_revision - 1, NEW.result_workspace_revision, NULL
        ) <> 0 THEN
            RAISE EXCEPTION 'ordinary workspace command changed source projection' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;

    expected_enabled := NEW.operation = 'WORKSPACE_SOURCE_ADD';
    expected_audit_revision := CASE
        WHEN NEW.status = 'SUCCESS' THEN NEW.result_workspace_revision
        ELSE NEW.source_expected_workspace_revision
    END;
    SELECT actor_type, actor_principal_id, action, resource_type, resource_id, workspace_id, outcome,
           error_code, policy_decision_id, referenced_evidence_ids_json, metadata_json
      INTO audit_row
      FROM public.audit_event
     WHERE organization_id = NEW.organization_id AND id = NEW.audit_event_id;
    IF NOT FOUND
       OR audit_row.actor_type <> 'HUMAN'
       OR audit_row.actor_principal_id IS DISTINCT FROM NEW.actor_principal_id
       OR audit_row.action <> app.workspace_command_gate_expected_action(NEW.operation)
       OR audit_row.resource_type <> 'WORKSPACE_SOURCE'
       OR audit_row.resource_id <> NEW.command_workspace_source_id
       OR audit_row.policy_decision_id IS NOT NULL
       OR audit_row.referenced_evidence_ids_json <> '[]'::jsonb
       OR audit_row.metadata_json <> jsonb_build_object(
            'workspace_revision', expected_audit_revision,
            'workspace_source_id', NEW.command_workspace_source_id,
            'source_scope_id', NEW.command_source_scope_id,
            'source_scope_revision', NEW.command_source_scope_revision,
            'scope_config_hash', NEW.command_scope_config_hash,
            'access_mode', NEW.command_access_mode,
            'enabled', expected_enabled
       ) THEN
        RAISE EXCEPTION 'workspace source command has unrelated audit projection' USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'DENIED' THEN
        IF audit_row.outcome <> 'DENIED' OR audit_row.error_code <> 'WORKSPACE_DENIED'
           OR (audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id) THEN
            RAISE EXCEPTION 'denied workspace source command has invalid audit binding' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    ELSIF NEW.status = 'NOT_FOUND' THEN
        IF audit_row.outcome <> 'DENIED' OR audit_row.error_code <> 'WORKSPACE_NOT_FOUND'
           OR (audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id) THEN
            RAISE EXCEPTION 'not-found workspace source command has invalid audit binding' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    ELSIF NEW.status = 'PRECONDITION_FAILED' THEN
        IF audit_row.outcome <> 'FAILED' OR audit_row.error_code <> 'WORKSPACE_REVISION_CONFLICT'
           OR (audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id) THEN
            RAISE EXCEPTION 'precondition-failed workspace source command has invalid audit binding' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    ELSIF NEW.status <> 'SUCCESS' OR audit_row.outcome <> 'SUCCESS' OR audit_row.error_code IS NOT NULL
       OR audit_row.workspace_id IS DISTINCT FROM NEW.command_workspace_id THEN
        RAISE EXCEPTION 'workspace source command has invalid terminal outcome' USING ERRCODE = '23514';
    END IF;

    IF NEW.result_workspace_id <> NEW.command_workspace_id THEN
        RAISE EXCEPTION 'workspace source command result targets wrong workspace' USING ERRCODE = '23514';
    END IF;
    SELECT revision.created_at, snapshot.created_at
      INTO revision_created_at, snapshot_created_at
      FROM public.workspace_revision AS revision
      JOIN public.workspace_revision_snapshot AS snapshot
        ON snapshot.organization_id = revision.organization_id
       AND snapshot.workspace_id = revision.workspace_id
       AND snapshot.revision = revision.revision
       AND snapshot.configuration_hash = revision.configuration_hash
     WHERE revision.organization_id = NEW.organization_id
       AND revision.workspace_id = NEW.result_workspace_id
       AND revision.revision = NEW.result_workspace_revision
       AND revision.configuration_hash = NEW.result_configuration_hash
       AND revision.created_by = NEW.actor_principal_id;
    IF NOT FOUND OR revision_created_at <> NEW.terminal_at OR snapshot_created_at <> NEW.terminal_at THEN
        RAISE EXCEPTION 'workspace source command lacks fresh exact revision snapshot' USING ERRCODE = '23514';
    END IF;
    IF NEW.result_workspace_revision <= 1 THEN
        IF NEW.operation <> 'WORKSPACE_CREATE' THEN
            RAISE EXCEPTION 'workspace source projection lacks a prior revision' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (
            SELECT 1 FROM public.workspace_revision_source
            WHERE organization_id = NEW.organization_id
              AND workspace_id = NEW.result_workspace_id
              AND workspace_revision = NEW.result_workspace_revision
        ) THEN
            RAISE EXCEPTION 'workspace create cannot introduce source projection' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;

    SELECT configuration_hash INTO previous_hash
    FROM public.workspace_revision_snapshot
    WHERE organization_id = NEW.organization_id
      AND workspace_id = NEW.result_workspace_id
      AND revision = NEW.result_workspace_revision - 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace source projection lacks prior snapshot' USING ERRCODE = '23514';
    END IF;

    SELECT count(*) INTO started_count FROM public.workspace_member
     WHERE organization_id = NEW.organization_id AND workspace_id = NEW.result_workspace_id
       AND valid_from_revision = NEW.result_workspace_revision;
    SELECT count(*) INTO closed_count FROM public.workspace_member
     WHERE organization_id = NEW.organization_id AND workspace_id = NEW.result_workspace_id
       AND valid_to_revision = NEW.result_workspace_revision;
    IF started_count <> 0 OR closed_count <> 0 THEN
        RAISE EXCEPTION 'workspace source command changed membership' USING ERRCODE = '23514';
    END IF;

    IF NEW.source_expected_workspace_revision <> NEW.result_workspace_revision - 1
       OR NEW.source_expected_configuration_hash <> previous_hash
       OR NEW.result_workspace_revision <> NEW.source_expected_workspace_revision + 1 THEN
        RAISE EXCEPTION 'workspace source command has stale base snapshot' USING ERRCODE = '23514';
    END IF;
    SELECT convert_from(previous.canonical_bytes, 'UTF8')::jsonb,
           convert_from(result.canonical_bytes, 'UTF8')::jsonb
      INTO previous_canonical, result_canonical
      FROM public.workspace_revision_snapshot AS previous
      JOIN public.workspace_revision_snapshot AS result
        ON result.organization_id = previous.organization_id
       AND result.workspace_id = previous.workspace_id
     WHERE previous.organization_id = NEW.organization_id
       AND previous.workspace_id = NEW.result_workspace_id
       AND previous.revision = NEW.source_expected_workspace_revision
       AND previous.configuration_hash = NEW.source_expected_configuration_hash
       AND result.revision = NEW.result_workspace_revision
       AND result.configuration_hash = NEW.result_configuration_hash;
    IF NOT FOUND
       OR previous_canonical ->> 'status' <> 'ACTIVE'
       OR result_canonical ->> 'status' <> 'ACTIVE' THEN
        RAISE EXCEPTION 'workspace source command requires ACTIVE base' USING ERRCODE = '23514';
    END IF;
    IF (previous_canonical - 'revision' - 'source_bindings')
          <> (result_canonical - 'revision' - 'source_bindings') THEN
        RAISE EXCEPTION 'workspace source command changed non-source configuration' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.workspace AS workspace
        WHERE workspace.organization_id = NEW.organization_id
          AND workspace.id = NEW.result_workspace_id
          AND workspace.current_revision = NEW.result_workspace_revision
          AND workspace.name = result_canonical ->> 'name'
          AND workspace.description = result_canonical ->> 'description'
          AND workspace.status = result_canonical ->> 'status'
          AND workspace.owner_principal_id = result_canonical ->> 'owner_principal_id'
          AND COALESCE(workspace.retention_policy_id, '') = result_canonical ->> 'retention_policy_id'
          AND workspace.updated_at = NEW.terminal_at
    ) THEN
        RAISE EXCEPTION 'workspace source command did not install exact mutable projection' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.source_scope_revision
        WHERE organization_id = NEW.organization_id
          AND source_scope_id = NEW.command_source_scope_id
          AND revision = NEW.command_source_scope_revision
          AND scope_config_hash = NEW.command_scope_config_hash
          AND access_mode = NEW.command_access_mode
    ) THEN
        RAISE EXCEPTION 'workspace source command has invalid scope tuple' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.workspace_source
        WHERE organization_id = NEW.organization_id
          AND workspace_id = NEW.command_workspace_id
          AND id = NEW.command_workspace_source_id
          AND source_scope_id = NEW.command_source_scope_id
    ) THEN
        RAISE EXCEPTION 'workspace source command lacks stable binding lineage' USING ERRCODE = '23514';
    END IF;

    SELECT * INTO old_target
    FROM public.workspace_revision_source
    WHERE organization_id = NEW.organization_id
      AND workspace_id = NEW.command_workspace_id
      AND workspace_revision = NEW.source_expected_workspace_revision
      AND workspace_source_id = NEW.command_workspace_source_id;
    SELECT * INTO new_target
    FROM public.workspace_revision_source
    WHERE organization_id = NEW.organization_id
      AND workspace_id = NEW.command_workspace_id
      AND workspace_revision = NEW.result_workspace_revision
      AND workspace_source_id = NEW.command_workspace_source_id;

    IF NOT FOUND
       OR new_target.source_scope_id <> NEW.command_source_scope_id
       OR new_target.source_scope_revision <> NEW.command_source_scope_revision
       OR new_target.scope_config_hash <> NEW.command_scope_config_hash
       OR new_target.access_mode <> NEW.command_access_mode
       OR new_target.enabled IS DISTINCT FROM expected_enabled THEN
        RAISE EXCEPTION 'workspace source command has wrong target projection' USING ERRCODE = '23514';
    END IF;

    IF NEW.operation = 'WORKSPACE_SOURCE_ADD' THEN
        IF old_target.workspace_source_id IS NOT NULL
           AND (old_target.source_scope_id <> NEW.command_source_scope_id
                OR old_target.source_scope_revision <> NEW.command_source_scope_revision
                OR old_target.scope_config_hash <> NEW.command_scope_config_hash
                OR old_target.access_mode <> NEW.command_access_mode
                OR old_target.enabled IS DISTINCT FROM false) THEN
            RAISE EXCEPTION 'workspace source add is not absent-or-disabled transition' USING ERRCODE = '23514';
        END IF;
    ELSIF old_target.workspace_source_id IS NULL
       OR old_target.source_scope_id <> NEW.command_source_scope_id
       OR old_target.source_scope_revision <> NEW.command_source_scope_revision
       OR old_target.scope_config_hash <> NEW.command_scope_config_hash
       OR old_target.access_mode <> NEW.command_access_mode
       OR old_target.enabled IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'workspace source remove is not enabled-to-disabled transition' USING ERRCODE = '23514';
    END IF;

    other_differences := app.workspace_source_projection_difference_count(
        NEW.organization_id, NEW.result_workspace_id,
        NEW.source_expected_workspace_revision, NEW.result_workspace_revision,
        NEW.command_workspace_source_id
    );
    IF other_differences <> 0 THEN
        RAISE EXCEPTION 'workspace source command changed undeclared bindings' USING ERRCODE = '23514';
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_command_source_projection_validator
AFTER UPDATE ON public.workspace_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_command_source_projection_validator();

-- The existing validator owns membership and audit binding.  Source commands
-- are validated by the exact projection validator above, so its old terminal
-- branch must not reject the newly closed operation values.  A BEFORE helper
-- cannot bypass that branch; replace only its source-command case by wrapping
-- the old trigger with a condition.
DROP TRIGGER workspace_command_receipt_terminal_validator ON public.workspace_command_receipt;
CREATE CONSTRAINT TRIGGER workspace_command_receipt_terminal_validator
AFTER UPDATE ON public.workspace_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.operation NOT IN ('WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE'))
EXECUTE FUNCTION app.workspace_command_receipt_terminal_validator();

CREATE OR REPLACE FUNCTION app.workspace_source_lineage_runtime_gate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.workspace_command_gate_runtime() AND NOT EXISTS (
        SELECT 1 FROM public.workspace_command_receipt AS receipt
        WHERE receipt.organization_id = NEW.organization_id
          AND receipt.actor_principal_id = NEW.added_by
          AND receipt.command_workspace_id = NEW.workspace_id
          AND receipt.command_workspace_source_id = NEW.id
          AND receipt.command_source_scope_id = NEW.source_scope_id
          AND receipt.command_source_scope_revision IS NOT NULL
          AND receipt.command_scope_config_hash IS NOT NULL
          AND receipt.command_access_mode IS NOT NULL
          AND receipt.result_workspace_revision = receipt.source_expected_workspace_revision + 1
          AND receipt.operation = 'WORKSPACE_SOURCE_ADD'
          AND receipt.status = 'SUCCESS'
          AND receipt.created_at = transaction_timestamp()
          AND receipt.terminal_at = transaction_timestamp()
          AND NEW.added_at = transaction_timestamp()
    ) THEN
        RAISE EXCEPTION 'workspace source lineage lacks fresh exact add receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_source_lineage_runtime_gate
AFTER INSERT ON public.workspace_source
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_source_lineage_runtime_gate();

CREATE OR REPLACE FUNCTION app.workspace_revision_source_runtime_gate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.workspace_command_gate_runtime()
       AND (NEW.created_at <> transaction_timestamp()
            OR NOT app.workspace_command_gate_fresh_success(
                NEW.organization_id, NEW.workspace_id, NEW.workspace_revision,
                NEW.workspace_configuration_hash, NULL
            )) THEN
        RAISE EXCEPTION 'workspace revision source lacks fresh successful command receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_revision_source_runtime_gate
AFTER INSERT ON public.workspace_revision_source
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_revision_source_runtime_gate();

-- Stage 000008 was read-only, so one membership policy was sufficient. Once
-- INSERT is granted, split read visibility from configuration authority:
-- MEMBER/VIEWER may inspect a binding but only an active OWNER/MANAGER may
-- create lineage or a revision projection. This does not grant source data.
DROP POLICY workspace_source_tenant_isolation ON public.workspace_source;
CREATE POLICY workspace_source_tenant_read ON public.workspace_source
    FOR SELECT USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_source.organization_id
              AND member.workspace_id = workspace_source.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );
CREATE POLICY workspace_source_controller_insert ON public.workspace_source
    FOR INSERT WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_source.organization_id
              AND member.workspace_id = workspace_source.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.role IN ('OWNER', 'MANAGER')
              AND member.removed_at IS NULL
        )
    );

DROP POLICY workspace_revision_source_tenant_isolation ON public.workspace_revision_source;
CREATE POLICY workspace_revision_source_tenant_read ON public.workspace_revision_source
    FOR SELECT USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_revision_source.organization_id
              AND member.workspace_id = workspace_revision_source.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );
CREATE POLICY workspace_revision_source_controller_insert ON public.workspace_revision_source
    FOR INSERT WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_revision_source.organization_id
              AND member.workspace_id = workspace_revision_source.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.role IN ('OWNER', 'MANAGER')
              AND (
                  member.removed_at IS NULL
                  OR member.valid_to_revision = workspace_revision_source.workspace_revision
              )
        )
    );

REVOKE ALL ON TABLE public.workspace_source, public.workspace_revision_source FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.workspace_source, public.workspace_revision_source TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.workspace_source_audit_integer_is_valid(jsonb),
    app.workspace_source_generated_id_is_valid(text, text),
    app.workspace_source_audit_projection_guard(),
    app.workspace_source_projection_difference_count(text, text, bigint, bigint, text),
    app.workspace_command_source_projection_validator(),
    app.workspace_source_lineage_runtime_gate(),
    app.workspace_revision_source_runtime_gate()
FROM PUBLIC;

-- Both are pure bounded validators required by CHECK/trigger expressions.
-- No mutating SECURITY DEFINER function is exposed to the runtime role.
GRANT EXECUTE ON FUNCTION
    app.audit_metadata_is_allowed(jsonb),
    app.workspace_source_generated_id_is_valid(text, text),
    app.workspace_source_audit_integer_is_valid(jsonb)
TO knowvault_app;

COMMIT;
