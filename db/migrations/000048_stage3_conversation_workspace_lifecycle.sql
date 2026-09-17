-- Stage 3 durable workspace-scoped conversation substrate.
--
-- A conversation stores only opaque metadata and server-owned Question Run
-- references.  Question/answer bytes remain under the existing encrypted
-- artifact owners.  Every row is revision-bound and the retention fence hides
-- the graph before any later physical purge.

BEGIN;

-- The composite key gives a conversation turn an exact Question Run workspace
-- and revision binding without introducing a second tenant identity.
ALTER TABLE public.question_run
    ADD CONSTRAINT question_run_conversation_workspace_revision_uq
    UNIQUE (organization_id, workspace_id, workspace_revision, id);

CREATE TABLE public.conversation (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    workspace_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(workspace_id)),
    workspace_revision bigint NOT NULL
        CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    created_by text NOT NULL CHECK (app.stage2_opaque_id_is_valid(created_by)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    archived_at timestamptz,
    PRIMARY KEY (organization_id, id),
    CONSTRAINT conversation_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT conversation_workspace_revision_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_creator_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT conversation_binding_uq
        UNIQUE (organization_id, id, workspace_id, workspace_revision)
);

CREATE INDEX conversation_workspace_created
    ON public.conversation (organization_id, workspace_id, created_at DESC, id DESC);

CREATE TABLE public.conversation_turn (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    conversation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(conversation_id)),
    workspace_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(workspace_id)),
    workspace_revision bigint NOT NULL
        CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    turn_index bigint NOT NULL CHECK (turn_index > 0),
    question_run_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(question_run_id)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT conversation_turn_conversation_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id, workspace_revision)
        REFERENCES public.conversation (organization_id, id, workspace_id, workspace_revision)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_turn_workspace_revision_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_turn_question_run_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision, question_run_id)
        REFERENCES public.question_run (organization_id, workspace_id, workspace_revision, id)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_turn_order_uq
        UNIQUE (organization_id, conversation_id, turn_index)
);

CREATE INDEX conversation_turn_workspace_created
    ON public.conversation_turn (organization_id, workspace_id, created_at DESC, id DESC);

CREATE TABLE public.conversation_retention (
    organization_id text NOT NULL
        CHECK (char_length(organization_id) BETWEEN 3 AND 128 AND organization_id !~ '[[:cntrl:]]'),
    conversation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(conversation_id)),
    workspace_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(workspace_id)),
    workspace_revision bigint NOT NULL
        CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    state text NOT NULL DEFAULT 'ACTIVE'
        CHECK (state IN ('ACTIVE', 'PURGING', 'PURGED')),
    disclosure_allowed boolean NOT NULL DEFAULT true,
    retention_fence bigint NOT NULL DEFAULT 0 CHECK (retention_fence >= 0),
    purge_reason text
        CHECK (purge_reason IS NULL OR
               (char_length(purge_reason) BETWEEN 1 AND 4096 AND purge_reason !~ '[[:cntrl:]]')),
    purge_started_at timestamptz,
    purged_at timestamptz,
    PRIMARY KEY (organization_id, conversation_id),
    CONSTRAINT conversation_retention_conversation_fk
        FOREIGN KEY (organization_id, conversation_id, workspace_id, workspace_revision)
        REFERENCES public.conversation (organization_id, id, workspace_id, workspace_revision)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_retention_workspace_revision_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision)
        REFERENCES public.workspace_revision (organization_id, workspace_id, revision)
        ON DELETE RESTRICT,
    CONSTRAINT conversation_retention_shape_check CHECK (
        (state = 'ACTIVE' AND disclosure_allowed = true AND purge_started_at IS NULL AND purged_at IS NULL)
        OR (state = 'PURGING' AND disclosure_allowed = false AND purge_started_at IS NOT NULL AND purged_at IS NULL)
        OR (state = 'PURGED' AND disclosure_allowed = false AND purge_started_at IS NOT NULL AND purged_at IS NOT NULL)
    ),
    CONSTRAINT conversation_retention_purge_order_check CHECK (
        purged_at IS NULL OR (purge_started_at IS NOT NULL AND purged_at >= purge_started_at)
    )
);

CREATE INDEX conversation_retention_workspace_state
    ON public.conversation_retention (organization_id, workspace_id, state, conversation_id);

CREATE OR REPLACE FUNCTION app.conversation_immutable_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_app'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR NEW.created_by IS DISTINCT FROM app.current_principal_id()
           OR NOT EXISTS (
               SELECT 1
                 FROM public.workspace AS workspace
                 JOIN public.workspace_member AS member
                   ON member.organization_id = workspace.organization_id
                  AND member.workspace_id = workspace.id
                WHERE workspace.organization_id = NEW.organization_id
                  AND workspace.id = NEW.workspace_id
                  AND workspace.status = 'ACTIVE'
                  AND member.principal_id = NEW.created_by
                  AND member.removed_at IS NULL
                  AND member.valid_from_revision <= NEW.workspace_revision
                  AND (member.valid_to_revision IS NULL OR member.valid_to_revision > NEW.workspace_revision)
           ) THEN
            RAISE EXCEPTION 'conversation requires the current active workspace member' USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.id IS DISTINCT FROM OLD.id
           OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
           OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision
           OR NEW.created_by IS DISTINCT FROM OLD.created_by
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'conversation workspace binding is immutable' USING ERRCODE = '23514';
        END IF;
        IF OLD.archived_at IS NOT NULL
           AND NEW.archived_at IS DISTINCT FROM OLD.archived_at THEN
            RAISE EXCEPTION 'conversation archive timestamp is immutable' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_immutable_binding_guard
BEFORE INSERT OR UPDATE ON public.conversation
FOR EACH ROW EXECUTE FUNCTION app.conversation_immutable_binding_guard();

CREATE OR REPLACE FUNCTION app.conversation_retention_required()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = NEW.organization_id
           AND retention.conversation_id = NEW.id
           AND retention.workspace_id = NEW.workspace_id
           AND retention.workspace_revision = NEW.workspace_revision
    ) THEN
        RAISE EXCEPTION 'conversation requires an initial retention row' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER conversation_retention_required
AFTER INSERT ON public.conversation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.conversation_retention_required();

CREATE OR REPLACE FUNCTION app.conversation_turn_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'conversation turns are append-only' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision
       OR NEW.turn_index IS DISTINCT FROM OLD.turn_index
       OR NEW.question_run_id IS DISTINCT FROM OLD.question_run_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'conversation turn binding is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_turn_append_only_guard
BEFORE UPDATE OR DELETE ON public.conversation_turn
FOR EACH ROW EXECUTE FUNCTION app.conversation_turn_append_only_guard();

CREATE OR REPLACE FUNCTION app.conversation_retention_lifecycle_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, app
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_app'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR NEW.state <> 'ACTIVE'
           OR NOT NEW.disclosure_allowed
           OR NEW.retention_fence <> 0
           OR NEW.purge_started_at IS NOT NULL
           OR NEW.purged_at IS NOT NULL THEN
            RAISE EXCEPTION 'conversation retention must start ACTIVE and disclosed' USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'conversation retention rows cannot be deleted' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(
                pg_catalog.format('%s:%s:%s', OLD.organization_id, OLD.workspace_id, OLD.conversation_id),
                0
            )
        );
        IF session_user <> 'knowvault_purger' THEN
            RAISE EXCEPTION 'conversation retention lifecycle requires the purger role' USING ERRCODE = '42501';
        END IF;
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
           OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
           OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision THEN
            RAISE EXCEPTION 'conversation retention workspace binding is immutable' USING ERRCODE = '23514';
        END IF;
        IF NEW.retention_fence < OLD.retention_fence THEN
            RAISE EXCEPTION 'conversation retention fence cannot move backwards' USING ERRCODE = '23514';
        END IF;
        IF NEW.state IS DISTINCT FROM OLD.state
           AND NEW.retention_fence <= OLD.retention_fence THEN
            RAISE EXCEPTION 'conversation retention state transition must advance the fence' USING ERRCODE = '23514';
        END IF;
        IF OLD.disclosure_allowed = false AND NEW.disclosure_allowed = true THEN
            RAISE EXCEPTION 'conversation retention disclosure cannot be reopened' USING ERRCODE = '23514';
        END IF;
        IF OLD.state = 'ACTIVE' AND NEW.state = 'PURGED' THEN
            RAISE EXCEPTION 'conversation retention must enter PURGING before PURGED' USING ERRCODE = '23514';
        END IF;
        IF OLD.state = 'PURGING' AND NEW.state = 'ACTIVE' THEN
            RAISE EXCEPTION 'conversation retention cannot leave PURGING for ACTIVE' USING ERRCODE = '23514';
        END IF;
        IF OLD.state = 'PURGED' AND NEW.state <> 'PURGED' THEN
            RAISE EXCEPTION 'purged conversation retention cannot be resurrected' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_retention_lifecycle_guard
BEFORE UPDATE OR DELETE ON public.conversation_retention
FOR EACH ROW EXECUTE FUNCTION app.conversation_retention_lifecycle_guard();

CREATE OR REPLACE FUNCTION app.conversation_retention_archive_guard(
    p_organization_id text,
    p_workspace_id text,
    p_conversation_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    retention_is_disclosed boolean;
BEGIN
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RETURN false;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            pg_catalog.format('%s:%s:%s', p_organization_id, p_workspace_id, p_conversation_id),
            0
        )
    );
    SELECT retention.state = 'ACTIVE' AND retention.disclosure_allowed
      INTO retention_is_disclosed
      FROM public.conversation_retention AS retention
     WHERE retention.organization_id = p_organization_id
       AND retention.workspace_id = p_workspace_id
       AND retention.conversation_id = p_conversation_id
     FOR UPDATE;
    RETURN COALESCE(retention_is_disclosed, false);
END;
$$;

ALTER TABLE public.conversation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation FORCE ROW LEVEL SECURITY;
CREATE POLICY conversation_member_read ON public.conversation
FOR SELECT
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status NOT IN ('ARCHIVED', 'DELETING', 'DELETED')
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation.organization_id
           AND retention.conversation_id = conversation.id
           AND retention.workspace_id = conversation.workspace_id
           AND retention.workspace_revision = conversation.workspace_revision
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
);
CREATE POLICY conversation_member_insert ON public.conversation
FOR INSERT
WITH CHECK (
    organization_id = app.current_organization_id()
    AND archived_at IS NULL
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation.workspace_revision)
    )
);
CREATE POLICY conversation_member_update ON public.conversation
FOR UPDATE
USING (
    organization_id = app.current_organization_id()
    AND archived_at IS NULL
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation.workspace_revision)
    )
)
WITH CHECK (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation.organization_id
           AND workspace.id = conversation.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation.workspace_revision)
    )
);

ALTER TABLE public.conversation_turn ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation_turn FORCE ROW LEVEL SECURITY;
CREATE POLICY conversation_turn_member_read ON public.conversation_turn
FOR SELECT
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_turn.organization_id
           AND member.workspace_id = conversation_turn.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_turn.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_turn.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation AS parent
         WHERE parent.organization_id = conversation_turn.organization_id
           AND parent.id = conversation_turn.conversation_id
           AND parent.workspace_id = conversation_turn.workspace_id
           AND parent.workspace_revision = conversation_turn.workspace_revision
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation_turn.organization_id
           AND retention.conversation_id = conversation_turn.conversation_id
           AND retention.workspace_id = conversation_turn.workspace_id
           AND retention.workspace_revision = conversation_turn.workspace_revision
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
);
CREATE POLICY conversation_turn_member_insert ON public.conversation_turn
FOR INSERT
WITH CHECK (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_turn.organization_id
           AND member.workspace_id = conversation_turn.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_turn.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_turn.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation AS parent
         WHERE parent.organization_id = conversation_turn.organization_id
           AND parent.id = conversation_turn.conversation_id
           AND parent.workspace_id = conversation_turn.workspace_id
           AND parent.workspace_revision = conversation_turn.workspace_revision
           AND parent.archived_at IS NULL
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation_turn.organization_id
           AND retention.conversation_id = conversation_turn.conversation_id
           AND retention.workspace_id = conversation_turn.workspace_id
           AND retention.workspace_revision = conversation_turn.workspace_revision
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
);
CREATE POLICY conversation_turn_member_update ON public.conversation_turn
FOR UPDATE
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace_member AS member
         WHERE member.organization_id = conversation_turn.organization_id
           AND member.workspace_id = conversation_turn.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_turn.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_turn.workspace_revision)
    )
    AND EXISTS (
        SELECT 1
          FROM public.conversation_retention AS retention
         WHERE retention.organization_id = conversation_turn.organization_id
           AND retention.conversation_id = conversation_turn.conversation_id
           AND retention.workspace_id = conversation_turn.workspace_id
           AND retention.workspace_revision = conversation_turn.workspace_revision
           AND retention.state = 'ACTIVE'
           AND retention.disclosure_allowed
    )
)
WITH CHECK (false);

ALTER TABLE public.conversation_retention ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversation_retention FORCE ROW LEVEL SECURITY;
CREATE POLICY conversation_retention_member_read ON public.conversation_retention
FOR SELECT TO knowvault_app
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation_retention.organization_id
           AND workspace.id = conversation_retention.workspace_id
           AND workspace.status NOT IN ('ARCHIVED', 'DELETING', 'DELETED')
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_retention.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_retention.workspace_revision)
    )
);
CREATE POLICY conversation_retention_member_insert ON public.conversation_retention
FOR INSERT TO knowvault_app
WITH CHECK (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1
          FROM public.workspace AS workspace
          JOIN public.workspace_member AS member
            ON member.organization_id = workspace.organization_id
           AND member.workspace_id = workspace.id
         WHERE workspace.organization_id = conversation_retention.organization_id
           AND workspace.id = conversation_retention.workspace_id
           AND workspace.status = 'ACTIVE'
           AND member.principal_id = app.current_principal_id()
           AND member.removed_at IS NULL
           AND member.valid_from_revision <= conversation_retention.workspace_revision
           AND (member.valid_to_revision IS NULL OR member.valid_to_revision > conversation_retention.workspace_revision)
    )
);
CREATE POLICY conversation_retention_member_update ON public.conversation_retention
FOR UPDATE TO knowvault_purger
USING (
    organization_id = app.current_organization_id()
)
WITH CHECK (
    organization_id = app.current_organization_id()
);
CREATE POLICY conversation_retention_purger_read ON public.conversation_retention
FOR SELECT TO knowvault_purger
USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.conversation, public.conversation_turn, public.conversation_retention FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.conversation TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.conversation_turn TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.conversation_retention TO knowvault_app;
GRANT SELECT, UPDATE ON TABLE public.conversation_retention TO knowvault_purger;

REVOKE ALL ON FUNCTION app.conversation_immutable_binding_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.conversation_turn_append_only_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.conversation_retention_lifecycle_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.conversation_retention_archive_guard(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.conversation_immutable_binding_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.conversation_turn_append_only_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.conversation_retention_lifecycle_guard() TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.conversation_retention_archive_guard(text, text, text) TO knowvault_app;
-- PostgreSQL evaluates CHECK expressions on a purger UPDATE as well as on an
-- app INSERT.  The purger receives only this pure id validator; it gains no
-- application data access or tenant-bypass capability.
GRANT EXECUTE ON FUNCTION app.stage2_opaque_id_is_valid(text) TO knowvault_purger;

COMMIT;
