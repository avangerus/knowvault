-- Stage 4 / S2 card A (ADR-0098, S2-MODEL-CONTEXT-DESIGN.md "Migration 000112
-- (pattern: 000094)"): the durable, tenant-scoped, versioned WorkspaceModelContext
-- a workspace's explicit description, answer rules, glossary and source/table/
-- column notes.
--
-- workspace_model_context_version is the immutable, append-only history: one
-- row per issued version, keyed by (organization_id, workspace_id, version).
-- workspace_model_context is the pointer to the current version; it only ever
-- moves forward (ADR-0098 decision 1: "every revision is immutable") and its
-- (current_version, current_hash) pair is foreign-keyed to an exact version
-- row, so the pointer can never name a hash that does not match the version it
-- claims to point at.
--
-- RLS splits read from write exactly like 000009's workspace_source policies:
-- any active workspace member (OWNER, MANAGER, MEMBER, VIEWER, AUDITOR, or a
-- SERVICE credential added as a MEMBER per 000067) may SELECT, while only an
-- active OWNER or MANAGER may INSERT a version or move the pointer. DELETE is
-- granted to nobody: a revision is retired only by being superseded, never
-- removed.
--
-- workspace_model_context_command is the actor-scoped Idempotency-Key ledger
-- for the three mutating commands (save, restore, accept-proposal), mirroring
-- 000004's discipline: only the SHA-256 of the raw key is stored, scoped by
-- the actor, and a replay with a different request is a conflict rather than
-- a silent second version.

BEGIN;

CREATE TABLE public.workspace_model_context_version (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    version bigint NOT NULL CHECK (version BETWEEN 1 AND 9007199254740991),
    document jsonb NOT NULL CHECK (octet_length(convert_to(document::text, 'UTF8')) <= 524288),
    content_hash text NOT NULL CHECK (app.workspace_command_hash_is_valid(content_hash)),
    parent_version bigint CHECK (parent_version IS NULL OR parent_version BETWEEN 1 AND 9007199254740991),
    change_kind text NOT NULL CHECK (change_kind IN ('EDIT', 'PROPOSAL_ACCEPTED', 'RESTORE')),
    -- The proposal id format mirrors internal/workspacecontext.proposalPrefix
    -- ("ctxprop"); the row that owns it (workspace_context_proposal) is card
    -- E's migration 000113, applied after this one, so only the shape is
    -- fixed here. Card E may add the FK once its table exists.
    proposal_id text CHECK (proposal_id IS NULL OR proposal_id ~ '^ctxprop_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    restored_from_version bigint CHECK (restored_from_version IS NULL OR restored_from_version BETWEEN 1 AND 9007199254740991),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, version),
    UNIQUE (organization_id, workspace_id, version, content_hash),
    CONSTRAINT workspace_model_context_version_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_model_context_version_creator_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_model_context_version_parent_fk
        FOREIGN KEY (organization_id, workspace_id, parent_version)
        REFERENCES public.workspace_model_context_version (organization_id, workspace_id, version)
        ON DELETE RESTRICT,
    -- A linear history: version 1 has no parent, every later version's parent
    -- is exactly its predecessor. There is no branching.
    CONSTRAINT workspace_model_context_version_parent_linear CHECK (
        (version = 1 AND parent_version IS NULL) OR (version > 1 AND parent_version = version - 1)
    ),
    -- Only a RESTORE carries restored_from_version, and only PROPOSAL_ACCEPTED
    -- carries proposal_id; the two vocabularies never mix.
    CONSTRAINT workspace_model_context_version_kind_shape CHECK (
        (change_kind = 'RESTORE') = (restored_from_version IS NOT NULL)
        AND (change_kind = 'PROPOSAL_ACCEPTED') = (proposal_id IS NOT NULL)
    )
);

CREATE INDEX workspace_model_context_version_workspace
    ON public.workspace_model_context_version (organization_id, workspace_id, version DESC);

-- Every version row is permanently immutable once written: no UPDATE, no
-- DELETE, ever.
CREATE OR REPLACE FUNCTION app.workspace_model_context_version_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'workspace model context versions are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER workspace_model_context_version_immutable
BEFORE UPDATE OR DELETE ON public.workspace_model_context_version
FOR EACH ROW EXECUTE FUNCTION app.workspace_model_context_version_guard();

CREATE TABLE public.workspace_model_context (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    current_version bigint NOT NULL CHECK (current_version BETWEEN 1 AND 9007199254740991),
    current_hash text NOT NULL CHECK (app.workspace_command_hash_is_valid(current_hash)),
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id),
    CONSTRAINT workspace_model_context_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_model_context_updater_fk
        FOREIGN KEY (organization_id, updated_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    -- The pointer can only ever name a version row whose own stored hash is
    -- exactly current_hash: it can never point at a hash mismatch.
    CONSTRAINT workspace_model_context_current_fk
        FOREIGN KEY (organization_id, workspace_id, current_version, current_hash)
        REFERENCES public.workspace_model_context_version (organization_id, workspace_id, version, content_hash)
        ON DELETE RESTRICT
);

-- The pointer never moves backward and its identity columns are frozen; it is
-- never deleted (a workspace without a context simply has no row -- REST
-- projects that as version 0 with an empty document).
CREATE OR REPLACE FUNCTION app.workspace_model_context_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workspace model context pointer is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.current_version <= OLD.current_version THEN
        RAISE EXCEPTION 'workspace model context version is monotonic' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id <> OLD.organization_id OR NEW.workspace_id <> OLD.workspace_id THEN
        RAISE EXCEPTION 'workspace model context identity is immutable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_model_context_immutable
BEFORE UPDATE OR DELETE ON public.workspace_model_context
FOR EACH ROW EXECUTE FUNCTION app.workspace_model_context_guard();

CREATE TABLE public.workspace_model_context_command (
    organization_id text NOT NULL,
    workspace_id text NOT NULL,
    actor_principal_id text NOT NULL,
    idempotency_key_hash text NOT NULL CHECK (idempotency_key_hash ~ '^sha256:[0-9a-f]{64}$'),
    request_hash text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
    result_version bigint NOT NULL CHECK (result_version BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, actor_principal_id, idempotency_key_hash),
    CONSTRAINT workspace_model_context_command_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_model_context_command_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_model_context_command_result_fk
        FOREIGN KEY (organization_id, workspace_id, result_version)
        REFERENCES public.workspace_model_context_version (organization_id, workspace_id, version)
        ON DELETE RESTRICT
);

ALTER TABLE public.workspace_model_context_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_model_context_version FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_model_context_version_read ON public.workspace_model_context_version
    FOR SELECT USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_model_context_version.organization_id
              AND member.workspace_id = workspace_model_context_version.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );
CREATE POLICY workspace_model_context_version_write ON public.workspace_model_context_version
    FOR INSERT WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_model_context_version.organization_id
              AND member.workspace_id = workspace_model_context_version.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.role IN ('OWNER', 'MANAGER')
              AND member.removed_at IS NULL
        )
    );

ALTER TABLE public.workspace_model_context ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_model_context FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_model_context_read ON public.workspace_model_context
    FOR SELECT USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_model_context.organization_id
              AND member.workspace_id = workspace_model_context.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );
CREATE POLICY workspace_model_context_insert ON public.workspace_model_context
    FOR INSERT WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_model_context.organization_id
              AND member.workspace_id = workspace_model_context.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.role IN ('OWNER', 'MANAGER')
              AND member.removed_at IS NULL
        )
    );
CREATE POLICY workspace_model_context_update ON public.workspace_model_context
    FOR UPDATE USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_model_context.organization_id
              AND member.workspace_id = workspace_model_context.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.role IN ('OWNER', 'MANAGER')
              AND member.removed_at IS NULL
        )
    ) WITH CHECK (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_model_context.organization_id
              AND member.workspace_id = workspace_model_context.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.role IN ('OWNER', 'MANAGER')
              AND member.removed_at IS NULL
        )
    );

ALTER TABLE public.workspace_model_context_command ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_model_context_command FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_model_context_command_isolation ON public.workspace_model_context_command
    USING (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    )
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    );

REVOKE ALL ON TABLE public.workspace_model_context_version, public.workspace_model_context, public.workspace_model_context_command
    FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT, INSERT ON TABLE public.workspace_model_context_version TO knowvault_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.workspace_model_context TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.workspace_model_context_command TO knowvault_app;

REVOKE ALL ON FUNCTION
    app.workspace_model_context_version_guard(), app.workspace_model_context_guard()
FROM PUBLIC;

-- S2-CONTRACT.md "Audit actions": two new content-free resource types, kept
-- in the closed CHECK the way every prior vocabulary addition did (latest at
-- 000072_stage3_search_profile_revisions.sql).
ALTER TABLE public.audit_event
    DROP CONSTRAINT audit_event_resource_type_check,
    ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
        'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
        'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
        'SOURCE_CONNECTION', 'SOURCE_SCOPE', 'SOURCE_OBJECT',
        'CONVERSATION', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
        'SIGNING_KEY', 'AUDIT_CHECKPOINT', 'CRYPTO_KEY', 'ANSWER_DOCUMENT',
        'GOVERNED_QUERY_ATTEMPT', 'SEARCH_PROFILE',
        'WORKSPACE_MODEL_CONTEXT', 'WORKSPACE_CONTEXT_PROPOSAL'
    ));

COMMIT;
