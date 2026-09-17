-- Stage 1: minimal append-only, tenant-scoped audit foundation.
--
-- Event bodies are canonicalized and hashed by the audit runtime before they
-- reach this schema. This migration makes the append-only and per-organization
-- chain properties authoritative at the database boundary as well.

BEGIN;

CREATE OR REPLACE FUNCTION app.audit_opaque_id_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND char_length(value) BETWEEN 1 AND 256
       AND btrim(value) = value
       AND value !~ '[[:cntrl:]]';
$$;

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
               'source_scope_id',
               'source_scope_revision',
               'source_connection_id',
               'connector_job_id',
               'sync_run_id',
               'question_run_id',
               'model_run_id',
               'citation_number',
               'manifest_hash',
               'policy_revision',
               'reason_codes',
               'remote_address_digest',
               'user_agent_family'
           )
       );
$$;

CREATE TABLE public.audit_chain_head (
    organization_id text PRIMARY KEY
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    last_sequence bigint NOT NULL DEFAULT 0
        CHECK (last_sequence >= 0 AND last_sequence <= 9007199254740991),
    last_event_hash text NOT NULL DEFAULT ('sha256:' || repeat('0', 64))
        CHECK (last_event_hash ~ '^sha256:[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE public.audit_event (
    id text PRIMARY KEY CHECK (app.audit_opaque_id_is_valid(id)),
    schema_version text NOT NULL DEFAULT 'audit-event-v1'
        CHECK (schema_version = 'audit-event-v1'),
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL
        CHECK (sequence BETWEEN 1 AND 9007199254740991),
    workspace_id text,
    actor_type text NOT NULL
        CHECK (actor_type IN ('HUMAN', 'SERVICE', 'CONNECTOR', 'SYSTEM')),
    actor_principal_id text,
    on_behalf_of_principal_id text,
    action text NOT NULL
        CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    resource_type text NOT NULL
        CHECK (resource_type IN (
            'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
            'SOURCE_CONNECTION', 'SOURCE_SCOPE', 'SOURCE_OBJECT',
            'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
            'SIGNING_KEY', 'AUDIT_CHECKPOINT'
        )),
    resource_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(resource_id)),
    request_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(request_id)),
    policy_decision_id text,
    outcome text NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILED')),
    error_code text,
    referenced_evidence_ids_json jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (
            jsonb_typeof(referenced_evidence_ids_json) = 'array'
            AND jsonb_array_length(referenced_evidence_ids_json) <= 128
        ),
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (app.audit_metadata_is_allowed(metadata_json)),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) > 0),
    previous_event_hash text NOT NULL
        CHECK (previous_event_hash ~ '^sha256:[0-9a-f]{64}$'),
    event_hash text NOT NULL
        CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    CONSTRAINT audit_event_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT audit_event_actor_principal_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT audit_event_on_behalf_principal_fk
        FOREIGN KEY (organization_id, on_behalf_of_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CHECK (workspace_id IS NULL OR app.audit_opaque_id_is_valid(workspace_id)),
    CHECK (actor_principal_id IS NULL OR app.audit_opaque_id_is_valid(actor_principal_id)),
    CHECK (on_behalf_of_principal_id IS NULL OR app.audit_opaque_id_is_valid(on_behalf_of_principal_id)),
    CHECK (policy_decision_id IS NULL OR app.audit_opaque_id_is_valid(policy_decision_id)),
    CHECK (
        (actor_type = 'SYSTEM' AND actor_principal_id IS NULL)
        OR (actor_type <> 'SYSTEM' AND actor_principal_id IS NOT NULL)
    ),
    CHECK (
        (outcome = 'SUCCESS' AND error_code IS NULL)
        OR (outcome <> 'SUCCESS' AND error_code ~ '^[A-Z][A-Z0-9_]{1,127}$')
    ),
    UNIQUE (organization_id, sequence),
    UNIQUE (organization_id, event_hash)
);

CREATE INDEX audit_event_organization_occurred_at
    ON public.audit_event (organization_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION app.audit_chain_head_mutation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    -- A chain-head change is valid only when nested under the audit-event
    -- append trigger. This prevents accidental direct rewrites by the runtime
    -- role even though it needs table privileges for the trigger's SQL.
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'audit chain head is maintained only by audit_event append'
            USING ERRCODE = '55000';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER audit_chain_head_append_only
BEFORE INSERT OR UPDATE OR DELETE ON public.audit_chain_head
FOR EACH ROW EXECUTE FUNCTION app.audit_chain_head_mutation_guard();

CREATE OR REPLACE FUNCTION app.audit_event_append_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    chain_head public.audit_chain_head%ROWTYPE;
    zero_hash constant text := 'sha256:' || repeat('0', 64);
BEGIN
    -- The insert is safe under contention: one transaction establishes the
    -- genesis row, then every append locks the same row before assigning the
    -- next link. A failed event insert rolls this update back with it.
    INSERT INTO public.audit_chain_head (organization_id, last_sequence, last_event_hash)
    VALUES (NEW.organization_id, 0, zero_hash)
    ON CONFLICT (organization_id) DO NOTHING;

    SELECT *
    INTO chain_head
    FROM public.audit_chain_head
    WHERE organization_id = NEW.organization_id
    FOR UPDATE;

    IF NEW.sequence <> chain_head.last_sequence + 1 THEN
        RAISE EXCEPTION 'audit sequence does not continue chain head'
            USING ERRCODE = '40001';
    END IF;

    IF NEW.previous_event_hash <> chain_head.last_event_hash THEN
        RAISE EXCEPTION 'audit previous hash does not match chain head'
            USING ERRCODE = '40001';
    END IF;

    UPDATE public.audit_chain_head
    SET last_sequence = NEW.sequence,
        last_event_hash = NEW.event_hash,
        updated_at = transaction_timestamp()
    WHERE organization_id = NEW.organization_id;

    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_chain_append
BEFORE INSERT ON public.audit_event
FOR EACH ROW EXECUTE FUNCTION app.audit_event_append_chain();

CREATE OR REPLACE FUNCTION app.audit_event_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'audit_event is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_event_no_mutation
BEFORE UPDATE OR DELETE ON public.audit_event
FOR EACH ROW EXECUTE FUNCTION app.audit_event_append_only();

ALTER TABLE public.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_tenant_isolation ON public.audit_event
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.audit_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_chain_head FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_chain_head_tenant_isolation ON public.audit_chain_head
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.audit_event, public.audit_chain_head FROM PUBLIC;
-- audit_event itself has no UPDATE or DELETE grant. audit_chain_head grants
-- exist only so the event trigger can atomically maintain the head; its guard
-- rejects direct mutations.
GRANT SELECT, INSERT ON TABLE public.audit_event TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_chain_head TO knowvault_app;

REVOKE ALL ON FUNCTION app.audit_opaque_id_is_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_metadata_is_allowed(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_chain_head_mutation_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_event_append_chain() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_event_append_only() FROM PUBLIC;
-- CHECK constraints execute in the inserting role, so only their pure
-- validators are callable by the runtime role. Trigger functions remain
-- non-callable application internals.
GRANT EXECUTE ON FUNCTION app.audit_opaque_id_is_valid(text) TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.audit_metadata_is_allowed(jsonb) TO knowvault_app;

COMMIT;
