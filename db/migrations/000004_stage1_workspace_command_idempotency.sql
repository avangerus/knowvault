-- Stage 1: durable, actor-scoped idempotency for workspace commands.
--
-- A receipt never contains the raw Idempotency-Key. Its SHA-256 hash is scoped
-- by the actor in the primary key. The receipt first exists as PENDING inside
-- one write transaction, then becomes exactly one immutable terminal outcome.
-- A deferred trigger rejects a transaction that tries to commit a PENDING
-- reservation. Successful receipts reference an immutable canonical snapshot
-- of the exact workspace revision returned to the original caller.

BEGIN;

CREATE OR REPLACE FUNCTION app.current_principal_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN current_setting('app.principal_id', true) ~ '^[A-Za-z0-9_.:-]{3,128}$'
            THEN current_setting('app.principal_id', true)
        ELSE NULL
    END;
$$;

CREATE OR REPLACE FUNCTION app.workspace_command_hash_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND value ~ '^sha256:[0-9a-f]{64}$';
$$;

-- PostgreSQL requires a unique parent key for a composite FK that also
-- authenticates the expected configuration hash / audit event ID.
ALTER TABLE public.workspace_revision
    ADD CONSTRAINT workspace_revision_exact_configuration_unique
    UNIQUE (organization_id, workspace_id, revision, configuration_hash);

ALTER TABLE public.audit_event
    ADD CONSTRAINT audit_event_exact_organization_id_unique
    UNIQUE (organization_id, id);

CREATE TABLE public.workspace_revision_snapshot (
    organization_id text NOT NULL,
    workspace_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    configuration_hash text NOT NULL
        CHECK (app.workspace_command_hash_is_valid(configuration_hash)),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 1048576),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, revision),
    UNIQUE (organization_id, workspace_id, revision, configuration_hash),
    CONSTRAINT workspace_revision_snapshot_exact_revision_fk
        FOREIGN KEY (organization_id, workspace_id, revision, configuration_hash)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision, configuration_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE public.workspace_command_receipt (
    organization_id text NOT NULL,
    actor_principal_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(actor_principal_id)),
    idempotency_key_hash text NOT NULL
        CHECK (app.workspace_command_hash_is_valid(idempotency_key_hash)),
    -- Gate-v1 is a non-content command intent. It lets deferred validators
    -- bind the resulting revision and audit event without retaining a request
    -- body or a raw idempotency key.
    gate_version smallint NOT NULL DEFAULT 1 CHECK (gate_version = 1),
    command_workspace_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(command_workspace_id)),
    command_target_principal_id text CHECK (
        command_target_principal_id IS NULL OR app.audit_opaque_id_is_valid(command_target_principal_id)
    ),
    command_target_role text,
    command_resource_type text NOT NULL CHECK (command_resource_type IN ('WORKSPACE', 'WORKSPACE_MEMBER')),
    command_resource_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(command_resource_id)),
    operation text NOT NULL CHECK (operation IN (
        'WORKSPACE_CREATE',
        'WORKSPACE_UPDATE',
        'WORKSPACE_ARCHIVE',
        'WORKSPACE_MEMBER_ADD',
        'WORKSPACE_MEMBER_ROLE_CHANGE',
        'WORKSPACE_MEMBER_REMOVE',
        'WORKSPACE_OWNERSHIP_TRANSFER'
    )),
    canonical_request_hash text NOT NULL
        CHECK (app.workspace_command_hash_is_valid(canonical_request_hash)),
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')),
    result_workspace_id text,
    result_workspace_revision bigint,
    result_configuration_hash text,
    audit_event_id text,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    terminal_at timestamptz,
    PRIMARY KEY (organization_id, actor_principal_id, idempotency_key_hash),
    CONSTRAINT workspace_command_receipt_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_command_receipt_exact_result_fk
        FOREIGN KEY (organization_id, result_workspace_id, result_workspace_revision, result_configuration_hash)
        REFERENCES public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workspace_command_receipt_audit_event_fk
        FOREIGN KEY (organization_id, audit_event_id)
        REFERENCES public.audit_event (organization_id, id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (result_workspace_id IS NULL AND result_workspace_revision IS NULL AND result_configuration_hash IS NULL)
        OR (
            result_workspace_id IS NOT NULL
            AND result_workspace_revision IS NOT NULL
            AND result_workspace_revision > 0
            AND result_configuration_hash IS NOT NULL
            AND app.workspace_command_hash_is_valid(result_configuration_hash)
        )
    ),
    CHECK (
        (status = 'PENDING'
            AND result_workspace_id IS NULL
            AND result_workspace_revision IS NULL
            AND result_configuration_hash IS NULL
            AND audit_event_id IS NULL
            AND terminal_at IS NULL)
        OR (status = 'SUCCESS'
            AND result_workspace_id IS NOT NULL
            AND result_workspace_revision IS NOT NULL
            AND result_configuration_hash IS NOT NULL
            AND audit_event_id IS NOT NULL
            AND terminal_at IS NOT NULL)
        OR (status IN ('DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')
            AND result_workspace_id IS NULL
            AND result_workspace_revision IS NULL
            AND result_configuration_hash IS NULL
            AND audit_event_id IS NOT NULL
            AND terminal_at IS NOT NULL)
    ),
    CHECK (audit_event_id IS NULL OR app.audit_opaque_id_is_valid(audit_event_id)),
    CHECK (terminal_at IS NULL OR terminal_at >= created_at),
    CHECK (
        (operation = 'WORKSPACE_CREATE'
            AND command_target_principal_id IS NULL
            AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE'
            AND command_resource_id = command_workspace_id)
        OR (operation IN ('WORKSPACE_UPDATE', 'WORKSPACE_ARCHIVE')
            AND command_target_principal_id IS NULL
            AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE'
            AND command_resource_id = command_workspace_id)
        OR (operation IN ('WORKSPACE_MEMBER_ADD', 'WORKSPACE_MEMBER_ROLE_CHANGE')
            AND command_target_principal_id IS NOT NULL
            AND command_target_role IN ('MANAGER', 'MEMBER', 'VIEWER', 'AUDITOR')
            AND command_resource_type = 'WORKSPACE_MEMBER')
        OR (operation = 'WORKSPACE_MEMBER_REMOVE'
            AND command_target_principal_id IS NOT NULL
            AND command_target_role IS NULL
            AND command_resource_type = 'WORKSPACE_MEMBER')
        OR (operation = 'WORKSPACE_OWNERSHIP_TRANSFER'
            AND command_target_principal_id IS NOT NULL
            AND command_target_role = 'OWNER'
            AND command_resource_type = 'WORKSPACE'
            AND command_resource_id = command_workspace_id)
    )
);

CREATE UNIQUE INDEX workspace_command_receipt_one_success_per_revision
    ON public.workspace_command_receipt (
        organization_id, result_workspace_id, result_workspace_revision, result_configuration_hash
    )
    WHERE status = 'SUCCESS';

CREATE UNIQUE INDEX workspace_command_receipt_one_use_per_audit_event
    ON public.workspace_command_receipt (organization_id, audit_event_id)
    WHERE audit_event_id IS NOT NULL;

CREATE OR REPLACE FUNCTION app.workspace_command_receipt_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.status <> 'PENDING'
       OR NEW.result_workspace_id IS NOT NULL
       OR NEW.result_workspace_revision IS NOT NULL
       OR NEW.result_configuration_hash IS NOT NULL
       OR NEW.audit_event_id IS NOT NULL
       OR NEW.terminal_at IS NOT NULL THEN
        RAISE EXCEPTION 'workspace command receipt must begin pending' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_command_receipt_insert_guard
BEFORE INSERT ON public.workspace_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.workspace_command_receipt_insert_guard();

CREATE OR REPLACE FUNCTION app.workspace_revision_snapshot_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'workspace_revision_snapshot is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER workspace_revision_snapshot_no_mutation
BEFORE UPDATE OR DELETE ON public.workspace_revision_snapshot
FOR EACH ROW EXECUTE FUNCTION app.workspace_revision_snapshot_append_only();

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

CREATE TRIGGER workspace_command_receipt_terminal_guard
BEFORE UPDATE ON public.workspace_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.workspace_command_receipt_terminal_guard();

CREATE OR REPLACE FUNCTION app.workspace_command_receipt_no_pending_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    persisted_status text;
BEGIN
    SELECT status
    INTO persisted_status
    FROM public.workspace_command_receipt
    WHERE organization_id = NEW.organization_id
      AND actor_principal_id = NEW.actor_principal_id
      AND idempotency_key_hash = NEW.idempotency_key_hash;

    IF NOT FOUND OR persisted_status = 'PENDING' THEN
        RAISE EXCEPTION 'workspace command receipt cannot commit pending' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_command_receipt_requires_terminal
AFTER INSERT OR UPDATE ON public.workspace_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_command_receipt_no_pending_commit();

-- Runtime command gate -------------------------------------------------------
--
-- These functions are intentionally small assertion triggers, not a business
-- procedure.  They run deferred so the repository may reserve PENDING first,
-- write the domain aggregate, append audit and then seal the receipt.  They
-- are SECURITY DEFINER because a valid self-removal loses the caller's RLS
-- visibility before deferred checks execute.  They are never callable by the
-- runtime role; session_user is the original login role after SECURITY DEFINER
-- switches current_user to the migration owner.

CREATE OR REPLACE FUNCTION app.workspace_command_gate_runtime()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT session_user = 'knowvault_app';
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
        ELSE NULL
    END;
$$;

CREATE OR REPLACE FUNCTION app.workspace_command_gate_fresh_success(
    expected_organization_id text,
    expected_workspace_id text,
    expected_revision bigint,
    expected_configuration_hash text,
    expected_actor_principal_id text DEFAULT NULL
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.workspace_command_receipt AS receipt
        JOIN public.workspace_revision AS revision
          ON revision.organization_id = receipt.organization_id
         AND revision.workspace_id = receipt.result_workspace_id
         AND revision.revision = receipt.result_workspace_revision
         AND revision.configuration_hash = receipt.result_configuration_hash
        JOIN public.workspace_revision_snapshot AS snapshot
          ON snapshot.organization_id = receipt.organization_id
         AND snapshot.workspace_id = receipt.result_workspace_id
         AND snapshot.revision = receipt.result_workspace_revision
         AND snapshot.configuration_hash = receipt.result_configuration_hash
        WHERE receipt.organization_id = expected_organization_id
          AND receipt.status = 'SUCCESS'
          AND receipt.command_workspace_id = expected_workspace_id
          AND receipt.result_workspace_id = expected_workspace_id
          AND receipt.result_workspace_revision = expected_revision
          AND receipt.result_configuration_hash = expected_configuration_hash
          AND receipt.terminal_at = transaction_timestamp()
          AND revision.created_at = transaction_timestamp()
          AND snapshot.created_at = transaction_timestamp()
          AND (expected_actor_principal_id IS NULL OR receipt.actor_principal_id = expected_actor_principal_id)
    );
$$;

CREATE OR REPLACE FUNCTION app.workspace_command_receipt_terminal_validator()
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
BEGIN
    IF NOT app.workspace_command_gate_runtime() OR NEW.status = 'PENDING' THEN
        RETURN NULL;
    END IF;

    SELECT actor_type, actor_principal_id, action, resource_type, resource_id,
           workspace_id, outcome, error_code
      INTO audit_row
      FROM public.audit_event
     WHERE organization_id = NEW.organization_id
       AND id = NEW.audit_event_id;
    IF NOT FOUND
       OR audit_row.actor_type <> 'HUMAN'
       OR audit_row.actor_principal_id IS DISTINCT FROM NEW.actor_principal_id
       OR audit_row.action <> app.workspace_command_gate_expected_action(NEW.operation)
       OR audit_row.resource_type <> NEW.command_resource_type
       OR audit_row.resource_id <> NEW.command_resource_id THEN
        RAISE EXCEPTION 'workspace command receipt has unrelated audit event' USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'SUCCESS' THEN
        IF NEW.result_workspace_id <> NEW.command_workspace_id
           OR audit_row.workspace_id IS DISTINCT FROM NEW.result_workspace_id
           OR audit_row.outcome <> 'SUCCESS'
           OR audit_row.error_code IS NOT NULL THEN
            RAISE EXCEPTION 'successful workspace command has invalid audit/result binding' USING ERRCODE = '23514';
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
        IF NOT FOUND
           OR revision_created_at <> NEW.terminal_at
           OR snapshot_created_at <> NEW.terminal_at THEN
            RAISE EXCEPTION 'successful workspace command lacks fresh exact revision snapshot' USING ERRCODE = '23514';
        END IF;

        SELECT count(*) INTO started_count
          FROM public.workspace_member
         WHERE organization_id = NEW.organization_id
           AND workspace_id = NEW.result_workspace_id
           AND valid_from_revision = NEW.result_workspace_revision;
        SELECT count(*) INTO closed_count
          FROM public.workspace_member
         WHERE organization_id = NEW.organization_id
           AND workspace_id = NEW.result_workspace_id
           AND valid_to_revision = NEW.result_workspace_revision;

        IF NEW.operation = 'WORKSPACE_CREATE' THEN
            IF NEW.result_workspace_revision <> 1 OR started_count <> 1 OR closed_count <> 0
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace AS workspace
                    JOIN public.workspace_member AS member
                      ON member.organization_id = workspace.organization_id
                     AND member.workspace_id = workspace.id
                     AND member.valid_from_revision = 1
                     AND member.removed_at IS NULL
                   WHERE workspace.organization_id = NEW.organization_id
                     AND workspace.id = NEW.result_workspace_id
                     AND workspace.owner_principal_id = NEW.actor_principal_id
                     AND member.principal_id = NEW.actor_principal_id
                     AND member.role = 'OWNER'
               ) THEN
                RAISE EXCEPTION 'workspace create effect does not match command receipt' USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.operation = 'WORKSPACE_UPDATE' THEN
            IF started_count <> 0 OR closed_count <> 0 THEN
                RAISE EXCEPTION 'workspace update changed membership' USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.operation = 'WORKSPACE_ARCHIVE' THEN
            IF started_count <> 0 OR closed_count <> 0
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace
                     WHERE organization_id = NEW.organization_id
                       AND id = NEW.result_workspace_id
                       AND status = 'ARCHIVED'
               ) THEN
                RAISE EXCEPTION 'workspace archive effect does not match command receipt' USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.operation = 'WORKSPACE_MEMBER_ADD' THEN
            IF started_count <> 1 OR closed_count <> 0
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_from_revision = NEW.result_workspace_revision
                       AND principal_id = NEW.command_target_principal_id
                       AND role = NEW.command_target_role
                       AND added_by = NEW.actor_principal_id
               ) THEN
                RAISE EXCEPTION 'workspace member add effect does not match command receipt' USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.operation = 'WORKSPACE_MEMBER_REMOVE' THEN
            IF started_count <> 0 OR closed_count <> 1
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_to_revision = NEW.result_workspace_revision
                       AND principal_id = NEW.command_target_principal_id
               ) THEN
                RAISE EXCEPTION 'workspace member removal effect does not match command receipt' USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.operation = 'WORKSPACE_MEMBER_ROLE_CHANGE' THEN
            IF started_count <> 1 OR closed_count <> 1
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_from_revision = NEW.result_workspace_revision
                       AND principal_id = NEW.command_target_principal_id
                       AND role = NEW.command_target_role
                       AND added_by = NEW.actor_principal_id
               )
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_to_revision = NEW.result_workspace_revision
                       AND principal_id = NEW.command_target_principal_id
               ) THEN
                RAISE EXCEPTION 'workspace role change effect does not match command receipt' USING ERRCODE = '23514';
            END IF;
        ELSIF NEW.operation = 'WORKSPACE_OWNERSHIP_TRANSFER' THEN
            IF started_count <> 2 OR closed_count <> 2
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace
                     WHERE organization_id = NEW.organization_id
                       AND id = NEW.result_workspace_id
                       AND owner_principal_id = NEW.command_target_principal_id
               )
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_from_revision = NEW.result_workspace_revision
                       AND principal_id = NEW.command_target_principal_id
                       AND role = 'OWNER'
               )
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_from_revision = NEW.result_workspace_revision
                       AND principal_id = NEW.actor_principal_id
                       AND role = 'MANAGER'
               )
               OR NOT EXISTS (
                    SELECT 1 FROM public.workspace_member
                     WHERE organization_id = NEW.organization_id
                       AND workspace_id = NEW.result_workspace_id
                       AND valid_to_revision = NEW.result_workspace_revision
                       AND principal_id IN (NEW.command_target_principal_id, NEW.actor_principal_id)
               ) THEN
                RAISE EXCEPTION 'workspace ownership transfer effect does not match command receipt' USING ERRCODE = '23514';
            END IF;
        ELSE
            RAISE EXCEPTION 'workspace command operation is not gateable' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.status = 'DENIED' THEN
        IF audit_row.outcome <> 'DENIED' OR audit_row.error_code <> 'WORKSPACE_DENIED'
           OR (audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id) THEN
            RAISE EXCEPTION 'denied workspace command has invalid audit binding' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.status = 'PRECONDITION_FAILED' THEN
        IF audit_row.outcome <> 'FAILED' OR audit_row.error_code <> 'WORKSPACE_REVISION_CONFLICT'
           OR (audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id) THEN
            RAISE EXCEPTION 'precondition-failed workspace command has invalid audit binding' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.status = 'NOT_FOUND' THEN
        IF audit_row.outcome <> 'DENIED' OR audit_row.error_code <> 'WORKSPACE_NOT_FOUND'
           OR (audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id) THEN
            RAISE EXCEPTION 'not-found workspace command has invalid audit binding' USING ERRCODE = '23514';
        END IF;
    ELSE
        RAISE EXCEPTION 'workspace command receipt has invalid terminal status' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_command_receipt_terminal_validator
AFTER UPDATE ON public.workspace_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_command_receipt_terminal_validator();

CREATE OR REPLACE FUNCTION app.workspace_runtime_update_shape_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.workspace_command_gate_runtime()
       AND (NEW.id <> OLD.id
            OR NEW.organization_id <> OLD.organization_id
            OR NEW.created_at <> OLD.created_at
            OR NEW.current_revision <> OLD.current_revision + 1) THEN
        RAISE EXCEPTION 'workspace update must advance exactly one revision' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_runtime_update_shape_guard
BEFORE UPDATE ON public.workspace
FOR EACH ROW EXECUTE FUNCTION app.workspace_runtime_update_shape_guard();

CREATE OR REPLACE FUNCTION app.workspace_runtime_gate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    revision_hash text;
BEGIN
    IF NOT app.workspace_command_gate_runtime() THEN
        RETURN NULL;
    END IF;
    SELECT configuration_hash INTO revision_hash
      FROM public.workspace_revision
     WHERE organization_id = NEW.organization_id
       AND workspace_id = NEW.id
       AND revision = NEW.current_revision;
    IF NOT FOUND OR NOT app.workspace_command_gate_fresh_success(
        NEW.organization_id, NEW.id, NEW.current_revision, revision_hash
    ) THEN
        RAISE EXCEPTION 'workspace mutation lacks fresh successful command receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_runtime_requires_success_receipt
AFTER INSERT OR UPDATE ON public.workspace
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_runtime_gate();

CREATE OR REPLACE FUNCTION app.workspace_revision_runtime_no_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.workspace_command_gate_runtime() THEN
        RAISE EXCEPTION 'workspace_revision is append-only for runtime role' USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER workspace_revision_runtime_no_mutation
BEFORE UPDATE OR DELETE ON public.workspace_revision
FOR EACH ROW EXECUTE FUNCTION app.workspace_revision_runtime_no_mutation();

CREATE OR REPLACE FUNCTION app.workspace_revision_runtime_gate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.workspace_command_gate_runtime()
       AND NOT app.workspace_command_gate_fresh_success(
           NEW.organization_id, NEW.workspace_id, NEW.revision, NEW.configuration_hash, NEW.created_by
       ) THEN
        RAISE EXCEPTION 'workspace revision lacks fresh successful command receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_revision_runtime_requires_success_receipt
AFTER INSERT ON public.workspace_revision
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_revision_runtime_gate();

CREATE OR REPLACE FUNCTION app.workspace_revision_snapshot_runtime_gate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.workspace_command_gate_runtime()
       AND NOT app.workspace_command_gate_fresh_success(
           NEW.organization_id, NEW.workspace_id, NEW.revision, NEW.configuration_hash
       ) THEN
        RAISE EXCEPTION 'workspace revision snapshot lacks fresh successful command receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_revision_snapshot_runtime_requires_success_receipt
AFTER INSERT ON public.workspace_revision_snapshot
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_revision_snapshot_runtime_gate();

CREATE OR REPLACE FUNCTION app.workspace_member_runtime_shape_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_workspace_revision bigint;
BEGIN
    IF NOT app.workspace_command_gate_runtime() THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workspace_member delete is forbidden for runtime role' USING ERRCODE = '55000';
    END IF;
    SELECT current_revision INTO current_workspace_revision
      FROM public.workspace
     WHERE organization_id = NEW.organization_id AND id = NEW.workspace_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace member has no workspace revision' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.valid_from_revision <> current_workspace_revision THEN
            RAISE EXCEPTION 'workspace member insert must start at current revision' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.id <> OLD.id
       OR NEW.organization_id <> OLD.organization_id
       OR NEW.workspace_id <> OLD.workspace_id
       OR NEW.principal_id <> OLD.principal_id
       OR NEW.role <> OLD.role
       OR NEW.valid_from_revision <> OLD.valid_from_revision
       OR NEW.added_by <> OLD.added_by
       OR NEW.added_at <> OLD.added_at
       OR OLD.valid_to_revision IS NOT NULL
       OR OLD.removed_at IS NOT NULL
       OR NEW.valid_to_revision IS NULL
       OR NEW.removed_at IS NULL
       OR NEW.valid_to_revision <> current_workspace_revision THEN
        RAISE EXCEPTION 'workspace member update must only close at current revision' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_member_runtime_shape_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.workspace_member
FOR EACH ROW EXECUTE FUNCTION app.workspace_member_runtime_shape_guard();

CREATE OR REPLACE FUNCTION app.workspace_member_runtime_gate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    transition_revision bigint;
    transition_hash text;
BEGIN
    IF NOT app.workspace_command_gate_runtime() THEN
        RETURN NULL;
    END IF;
    transition_revision := CASE WHEN TG_OP = 'INSERT' THEN NEW.valid_from_revision ELSE NEW.valid_to_revision END;
    SELECT configuration_hash INTO transition_hash
      FROM public.workspace_revision
     WHERE organization_id = NEW.organization_id
       AND workspace_id = NEW.workspace_id
       AND revision = transition_revision;
    IF NOT FOUND OR NOT app.workspace_command_gate_fresh_success(
        NEW.organization_id, NEW.workspace_id, transition_revision, transition_hash
    ) THEN
        RAISE EXCEPTION 'workspace member mutation lacks fresh successful command receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_member_runtime_requires_success_receipt
AFTER INSERT OR UPDATE ON public.workspace_member
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_member_runtime_gate();

ALTER TABLE public.workspace_revision_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_revision_snapshot FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_revision_snapshot_tenant_isolation ON public.workspace_revision_snapshot
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1
            FROM public.workspace_member
            WHERE workspace_member.organization_id = workspace_revision_snapshot.organization_id
              AND workspace_member.workspace_id = workspace_revision_snapshot.workspace_id
              AND workspace_member.principal_id = app.current_principal_id()
              AND workspace_member.removed_at IS NULL
        )
    )
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1
            FROM public.workspace_member
            WHERE workspace_member.organization_id = workspace_revision_snapshot.organization_id
              AND workspace_member.workspace_id = workspace_revision_snapshot.workspace_id
              AND workspace_member.principal_id = app.current_principal_id()
              AND workspace_member.removed_at IS NULL
        )
    );

ALTER TABLE public.workspace_command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_command_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_command_receipt_actor_isolation ON public.workspace_command_receipt
    USING (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    )
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    );

REVOKE ALL ON TABLE public.workspace_revision_snapshot, public.workspace_command_receipt FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE public.workspace_revision_snapshot TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.workspace_command_receipt TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.current_principal_id(),
    app.workspace_command_hash_is_valid(text),
    app.workspace_command_receipt_insert_guard(),
    app.workspace_revision_snapshot_append_only(),
    app.workspace_command_receipt_terminal_guard(),
    app.workspace_command_receipt_no_pending_commit(),
    app.workspace_command_gate_runtime(),
    app.workspace_command_gate_expected_action(text),
    app.workspace_command_gate_fresh_success(text, text, bigint, text, text),
    app.workspace_command_receipt_terminal_validator(),
    app.workspace_runtime_update_shape_guard(),
    app.workspace_runtime_gate(),
    app.workspace_revision_runtime_no_mutation(),
    app.workspace_revision_runtime_gate(),
    app.workspace_revision_snapshot_runtime_gate(),
    app.workspace_member_runtime_shape_guard(),
    app.workspace_member_runtime_gate()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    app.current_principal_id(),
    app.workspace_command_hash_is_valid(text)
TO knowvault_app;

COMMIT;
