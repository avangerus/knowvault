-- Stage 3 conversation lifecycle command receipt.
--
-- Archive is a server-owned, actor-scoped command.  The receipt keeps only
-- opaque ids and hashes, is completed in the same transaction as the
-- conversation update and audit event, and cannot be left PENDING at commit.

BEGIN;

ALTER TABLE public.audit_event DROP CONSTRAINT audit_event_resource_type_check;
ALTER TABLE public.audit_event ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
    'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
    'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
    'SOURCE_CONNECTION', 'SOURCE_SCOPE', 'SOURCE_OBJECT',
    'CONVERSATION', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
    'SIGNING_KEY', 'AUDIT_CHECKPOINT', 'CRYPTO_KEY', 'ANSWER_DOCUMENT'
));

CREATE TABLE public.conversation_command_receipt (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    actor_principal_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(actor_principal_id)),
    idempotency_key_hash text NOT NULL
        CHECK (app.stage2_sha256_is_valid(idempotency_key_hash)),
    conversation_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(conversation_id)),
    workspace_id text NOT NULL
        CHECK (app.stage2_opaque_id_is_valid(workspace_id)),
    workspace_revision bigint NOT NULL
        CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    operation text NOT NULL CHECK (operation = 'ARCHIVE'),
    canonical_request_hash text NOT NULL
        CHECK (app.stage2_sha256_is_valid(canonical_request_hash)),
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'DENIED', 'NOT_FOUND')),
    audit_event_id text
        CHECK (audit_event_id IS NULL OR app.stage2_opaque_id_is_valid(audit_event_id)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    terminal_at timestamptz,
    PRIMARY KEY (organization_id, actor_principal_id, idempotency_key_hash),
    CONSTRAINT conversation_command_receipt_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT conversation_command_receipt_conversation_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id, workspace_revision)
        REFERENCES public.conversation (organization_id, id, workspace_id, workspace_revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_command_receipt_audit_fk
        FOREIGN KEY (organization_id, audit_event_id)
        REFERENCES public.audit_event (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT conversation_command_receipt_state_shape CHECK (
        (status = 'PENDING' AND audit_event_id IS NULL AND terminal_at IS NULL)
        OR (status IN ('SUCCESS', 'DENIED', 'NOT_FOUND') AND audit_event_id IS NOT NULL AND terminal_at IS NOT NULL)
    ),
    CONSTRAINT conversation_command_receipt_terminal_order CHECK (
        terminal_at IS NULL OR terminal_at >= created_at
    )
);

CREATE INDEX conversation_command_receipt_conversation
    ON public.conversation_command_receipt (organization_id, conversation_id, created_at DESC);

CREATE OR REPLACE FUNCTION app.conversation_command_receipt_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.status <> 'PENDING' OR NEW.audit_event_id IS NOT NULL OR NEW.terminal_at IS NOT NULL THEN
        RAISE EXCEPTION 'conversation command receipt must begin pending' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_command_receipt_insert_guard
BEFORE INSERT ON public.conversation_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.conversation_command_receipt_insert_guard();

CREATE OR REPLACE FUNCTION app.conversation_command_receipt_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.actor_principal_id <> OLD.actor_principal_id
       OR NEW.idempotency_key_hash <> OLD.idempotency_key_hash
       OR NEW.conversation_id <> OLD.conversation_id
       OR NEW.workspace_id <> OLD.workspace_id
       OR NEW.workspace_revision <> OLD.workspace_revision
       OR NEW.operation <> OLD.operation
       OR NEW.canonical_request_hash <> OLD.canonical_request_hash
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'conversation command receipt identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status <> 'PENDING'
       OR NEW.status NOT IN ('SUCCESS', 'DENIED', 'NOT_FOUND')
       OR NEW.terminal_at <> transaction_timestamp() THEN
        RAISE EXCEPTION 'conversation command receipt must transition once to a terminal state' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_command_receipt_terminal_guard
BEFORE UPDATE ON public.conversation_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.conversation_command_receipt_terminal_guard();

CREATE OR REPLACE FUNCTION app.conversation_command_receipt_no_pending_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    persisted_status text;
BEGIN
    SELECT status INTO persisted_status
      FROM public.conversation_command_receipt
     WHERE organization_id = NEW.organization_id
       AND actor_principal_id = NEW.actor_principal_id
       AND idempotency_key_hash = NEW.idempotency_key_hash;
    IF NOT FOUND OR persisted_status = 'PENDING' THEN
        RAISE EXCEPTION 'conversation command receipt cannot commit pending' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER conversation_command_receipt_requires_terminal
AFTER INSERT OR UPDATE ON public.conversation_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.conversation_command_receipt_no_pending_commit();

ALTER TABLE public.conversation_command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation_command_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY conversation_command_receipt_actor ON public.conversation_command_receipt
USING (
    organization_id = app.current_organization_id()
    AND actor_principal_id = app.current_principal_id()
)
WITH CHECK (
    organization_id = app.current_organization_id()
    AND actor_principal_id = app.current_principal_id()
);

REVOKE ALL ON TABLE public.conversation_command_receipt FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.conversation_command_receipt TO knowvault_app;
REVOKE ALL ON FUNCTION app.conversation_command_receipt_insert_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.conversation_command_receipt_terminal_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.conversation_command_receipt_no_pending_commit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.conversation_command_receipt_insert_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.conversation_command_receipt_terminal_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.conversation_command_receipt_no_pending_commit() TO knowvault_app;

COMMIT;
