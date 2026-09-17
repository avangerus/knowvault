-- Stage 3: physically purge encrypted conversation-owned content.
--
-- Conversation rows, turns, Question Runs and citations remain as opaque,
-- immutable tombstones.  Their decryptable artifacts do not: after the
-- purger commits ACTIVE -> PURGING, this migration-owned control-plane
-- operation erases ciphertext and wrapped DEKs for every artifact reachable
-- from the conversation.  The source Evidence graph is deliberately not in
-- this ownership set; it has its own source-version retention authority.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'knowvault_purger') THEN
        RAISE EXCEPTION 'trusted purge role knowvault_purger must exist before this migration';
    END IF;
END;
$$;

-- Fail-close transition for one conversation.  The tenant and role checks are
-- inside the SECURITY DEFINER function because the owner bypasses RLS.  The
-- fence is a compare-and-swap value observed by the caller, so a stale purge
-- command cannot revoke a newer conversation state.
CREATE OR REPLACE FUNCTION app.conversation_begin_purge(
    p_organization_id text,
    p_workspace_id text,
    p_conversation_id text,
    p_reason text,
    p_expected_fence bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    current_state text;
    current_fence bigint;
    new_fence bigint;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'conversation purge requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;
    IF p_reason IS NULL OR btrim(p_reason) = '' OR p_reason !~ '^[A-Z][A-Z0-9_]{2,63}$' THEN
        RAISE EXCEPTION 'purge reason must be a safe operator code' USING ERRCODE = '22023';
    END IF;
    IF p_expected_fence < 0 THEN
        RAISE EXCEPTION 'purge fence must be non-negative' USING ERRCODE = '22023';
    END IF;

    SELECT retention.state, retention.retention_fence
      INTO current_state, current_fence
      FROM public.conversation_retention AS retention
     WHERE retention.organization_id = p_organization_id
       AND retention.workspace_id = p_workspace_id
       AND retention.conversation_id = p_conversation_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation retention not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'conversation purge may begin only from ACTIVE retention' USING ERRCODE = '55000';
    END IF;
    IF current_fence <> p_expected_fence THEN
        RAISE EXCEPTION 'conversation purge fence CAS failed' USING ERRCODE = '40001';
    END IF;

    new_fence := current_fence + 1;
    UPDATE public.conversation_retention
       SET retention_fence = new_fence,
           state = 'PURGING',
           disclosure_allowed = false,
           purge_reason = p_reason,
           purge_started_at = clock_timestamp()
     WHERE organization_id = p_organization_id
       AND workspace_id = p_workspace_id
       AND conversation_id = p_conversation_id;

    -- Close every bound Question Run retention row in the same fail-close
    -- transaction.  A missing legacy row is not manufactured here; the
    -- immutable run/citation tombstones are still covered by cleanup below.
    UPDATE public.question_run_retention AS retention
       SET state = 'PURGING',
           disclosure_allowed = false,
           purge_reason = 'CONVERSATION_PURGE',
           purge_started_at = COALESCE(retention.purge_started_at, clock_timestamp())
      FROM public.question_run AS run
     WHERE run.organization_id = p_organization_id
       AND run.workspace_id = p_workspace_id
       AND run.conversation_id = p_conversation_id
       AND retention.organization_id = run.organization_id
       AND retention.question_run_id = run.id
       AND retention.state = 'ACTIVE';

    RETURN new_fence;
END;
$$;

-- Irreversible, idempotently resumable cleanup.  It only accepts a committed
-- PURGING/PURGED conversation and only touches exact encrypted owner branches
-- whose Question Run/citation rows bind to that conversation.
CREATE OR REPLACE FUNCTION app.conversation_purge_cleanup(
    p_organization_id text,
    p_workspace_id text,
    p_conversation_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    current_state text;
    purged_count bigint := 0;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'conversation purge requires the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'purge tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;

    SELECT retention.state
      INTO current_state
      FROM public.conversation_retention AS retention
     WHERE retention.organization_id = p_organization_id
       AND retention.workspace_id = p_workspace_id
       AND retention.conversation_id = p_conversation_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation retention not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_state = 'ACTIVE' THEN
        RAISE EXCEPTION 'conversation cleanup requires PURGING retention' USING ERRCODE = '55000';
    END IF;
    IF current_state = 'PURGED' THEN
        RETURN 0;
    END IF;

    -- Every Question Run-owned field is enumerated by its closed owner tuple;
    -- citations use their own opaque id, and the authorized candidate set is
    -- keyed by its owning run.  No model or caller can supply an SQL selector.
    WITH bound_runs AS MATERIALIZED (
        SELECT run.id
          FROM public.question_run AS run
         WHERE run.organization_id = p_organization_id
           AND run.workspace_id = p_workspace_id
           AND run.conversation_id = p_conversation_id
    ),
    bound_citations AS MATERIALIZED (
        SELECT citation.id
          FROM public.question_citation AS citation
          JOIN bound_runs AS run ON run.id = citation.question_run_id
         WHERE citation.organization_id = p_organization_id
    ),
    cleaned AS (
        UPDATE public.encrypted_artifact AS artifact
           SET ciphertext = NULL,
               wrapped_dek = NULL,
               purged_at = clock_timestamp()
         WHERE artifact.organization_id = p_organization_id
           AND artifact.purged_at IS NULL
           AND (
               (artifact.owner_table = 'question_run'
                AND artifact.owner_column IN (
                    'question_text_artifact_id', 'answer_markdown_artifact_id',
                    'answer_structured_artifact_id', 'manifest_content_artifact_id'
                )
                AND artifact.resource_id IN (SELECT id FROM bound_runs))
               OR
               (artifact.owner_table = 'question_citation'
                AND artifact.owner_column IN (
                    'cited_excerpt_artifact_id', 'anchor_artifact_id', 'deep_link_artifact_id'
                )
                AND artifact.resource_id IN (SELECT id FROM bound_citations))
               OR
               (artifact.owner_table = 'question_authorized_candidate_set'
                AND artifact.owner_column = 'canonical_artifact_id'
                AND artifact.resource_id IN (SELECT id FROM bound_runs))
           )
        RETURNING 1
    )
    SELECT count(*) INTO purged_count FROM cleaned;

    -- Keep metadata as opaque tombstones but make the run retention terminal.
    -- The two updates preserve the explicit ACTIVE -> PURGING -> PURGED shape
    -- even when a cleanup worker is recovering a partially completed run.
    UPDATE public.question_run_retention AS retention
       SET state = 'PURGING',
           disclosure_allowed = false,
           purge_reason = COALESCE(retention.purge_reason, 'CONVERSATION_PURGE'),
           purge_started_at = COALESCE(retention.purge_started_at, clock_timestamp())
      FROM public.question_run AS run
     WHERE run.organization_id = p_organization_id
       AND run.workspace_id = p_workspace_id
       AND run.conversation_id = p_conversation_id
       AND retention.organization_id = run.organization_id
       AND retention.question_run_id = run.id
       AND retention.state = 'ACTIVE';

    UPDATE public.question_run_retention AS retention
       SET state = 'PURGED',
           disclosure_allowed = false,
           purged_at = COALESCE(retention.purged_at, clock_timestamp())
      FROM public.question_run AS run
     WHERE run.organization_id = p_organization_id
       AND run.workspace_id = p_workspace_id
       AND run.conversation_id = p_conversation_id
       AND retention.organization_id = run.organization_id
       AND retention.question_run_id = run.id
       AND retention.state = 'PURGING';

    -- Completion is fail-closed: an unexpected active conversation-owned
    -- artifact blocks PURGED rather than silently claiming a complete purge.
    IF EXISTS (
        SELECT 1
          FROM public.encrypted_artifact AS artifact
         WHERE artifact.organization_id = p_organization_id
           AND artifact.purged_at IS NULL
           AND (
               (artifact.owner_table = 'question_run'
                AND artifact.owner_column IN (
                    'question_text_artifact_id', 'answer_markdown_artifact_id',
                    'answer_structured_artifact_id', 'manifest_content_artifact_id'
                )
                AND EXISTS (
                    SELECT 1 FROM public.question_run AS run
                     WHERE run.organization_id = p_organization_id
                       AND run.workspace_id = p_workspace_id
                       AND run.conversation_id = p_conversation_id
                       AND run.id = artifact.resource_id
                ))
               OR
               (artifact.owner_table = 'question_citation'
                AND artifact.owner_column IN (
                    'cited_excerpt_artifact_id', 'anchor_artifact_id', 'deep_link_artifact_id'
                )
                AND EXISTS (
                    SELECT 1
                      FROM public.question_citation AS citation
                      JOIN public.question_run AS run
                        ON run.organization_id = citation.organization_id
                       AND run.id = citation.question_run_id
                     WHERE citation.organization_id = p_organization_id
                       AND citation.id = artifact.resource_id
                       AND run.workspace_id = p_workspace_id
                       AND run.conversation_id = p_conversation_id
                ))
               OR
               (artifact.owner_table = 'question_authorized_candidate_set'
                AND artifact.owner_column = 'canonical_artifact_id'
                AND EXISTS (
                    SELECT 1 FROM public.question_run AS run
                     WHERE run.organization_id = p_organization_id
                       AND run.workspace_id = p_workspace_id
                       AND run.conversation_id = p_conversation_id
                       AND run.id = artifact.resource_id
                ))
           )
    ) THEN
        RAISE EXCEPTION 'conversation cleanup blocked: decryptable content remains' USING ERRCODE = '55000';
    END IF;

    UPDATE public.conversation_retention
       SET state = 'PURGED',
           disclosure_allowed = false,
           retention_fence = retention_fence + 1,
           purged_at = COALESCE(purged_at, clock_timestamp())
     WHERE organization_id = p_organization_id
       AND workspace_id = p_workspace_id
       AND conversation_id = p_conversation_id
       AND state = 'PURGING';

    RETURN purged_count;
END;
$$;

REVOKE ALL ON FUNCTION
    app.conversation_begin_purge(text, text, text, text, bigint),
    app.conversation_purge_cleanup(text, text, text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    app.conversation_begin_purge(text, text, text, text, bigint),
    app.conversation_purge_cleanup(text, text, text)
TO knowvault_purger;

-- The SQL functions own the data mutation.  The purger adapter only reads the
-- fenced state and appends a content-free audit event, so no table write grant
-- is added to the trusted role.
GRANT USAGE ON SCHEMA app, public TO knowvault_purger;
GRANT SELECT ON TABLE public.conversation_retention TO knowvault_purger;
GRANT EXECUTE ON FUNCTION app.current_organization_id() TO knowvault_purger;

COMMIT;
