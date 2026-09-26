-- Stage 4 (S2 card E, ADR-0098 decision 4): the deterministic proposer's
-- durable state. A PROPOSED glossary change derived by the heuristic-v1
-- detector from a completed question run, its evidence (opaque run/
-- conversation/turn references, no text), and the cross-run bookkeeping the
-- NEW_TERM signal needs to require "at least two distinct runs" before a
-- token is ever proposed.
--
-- workspace_context_proposal never becomes evidence and never changes the
-- tool catalog, read-only transactions or authorization (ADR-0098 decision
-- 3); it only records a candidate glossary edit that takes effect exclusively
-- through an explicit, audited OWNER/MANAGER decision (S2-CONTRACT.md
-- "Proposals"). It carries no organization/workspace assumption beyond the
-- ones migration 000001 already established; it does not depend on card A's
-- 000112 (workspace_model_context/_version), so this migration can apply and
-- be tested standalone.

BEGIN;

-- workspace_context_proposal ---------------------------------------------
--
-- candidate_term/candidate_term_key/suggested_text are the only "text" this
-- table carries (S2-MODEL-CONTEXT-DESIGN.md "A proposal's text ... erased
-- when those conversations are purged"); the withdrawal shape check below
-- requires all three NULL exactly when WITHDRAWN, and app.conversation_
-- purge_cleanup (extended at the end of this migration) is the only writer
-- that ever nulls them. target_term_id is a reference, not text, and is
-- deliberately left intact by a withdrawal.
CREATE TABLE public.workspace_context_proposal (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (id ~ '^ctxprop_[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    workspace_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('NEW_TERM', 'SYNONYM', 'DEFINITION_CORRECTION')),
    candidate_term text
        CHECK (candidate_term IS NULL OR (char_length(candidate_term) BETWEEN 1 AND 80 AND candidate_term !~ '[[:cntrl:]]')),
    -- candidate_term_key is candidate_term case-folded (NFC, lower, ё->е) by
    -- the caller, exactly as workspacecontext.MatchTerms folds a candidate:
    -- the dedup index below compares this column, never candidate_term
    -- itself, so "МНО" and "мно" collide as the same open proposal.
    candidate_term_key text
        CHECK (candidate_term_key IS NULL OR (char_length(candidate_term_key) BETWEEN 1 AND 80 AND candidate_term_key !~ '[[:cntrl:]]')),
    target_term_id text CHECK (target_term_id IS NULL OR app.stage2_opaque_id_is_valid(target_term_id)),
    suggested_text text
        CHECK (suggested_text IS NULL OR (char_length(suggested_text) <= 300 AND suggested_text !~ '[[:cntrl:]]')),
    status text NOT NULL DEFAULT 'PROPOSED'
        CHECK (status IN ('PROPOSED', 'ACCEPTED', 'REJECTED', 'WITHDRAWN')),
    occurrences integer NOT NULL DEFAULT 1 CHECK (occurrences BETWEEN 1 AND 2147483647),
    detector_version text NOT NULL
        CHECK (char_length(detector_version) BETWEEN 1 AND 64 AND detector_version !~ '[[:cntrl:]]'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    decided_by text,
    decided_at timestamptz,
    decided_version bigint CHECK (decided_version IS NULL OR decided_version BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT workspace_context_proposal_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_context_proposal_decider_fk
        FOREIGN KEY (organization_id, decided_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    -- A proposal's target reference is closed by kind: NEW_TERM introduces a
    -- term and has none; SYNONYM and DEFINITION_CORRECTION always point at
    -- one. This holds in every status, including WITHDRAWN.
    CONSTRAINT workspace_context_proposal_kind_shape CHECK (
        (kind = 'NEW_TERM' AND target_term_id IS NULL)
        OR (kind IN ('SYNONYM', 'DEFINITION_CORRECTION') AND target_term_id IS NOT NULL)
    ),
    -- The decision fields' shape is exact per status: PROPOSED has none;
    -- WITHDRAWN is a system transition (no decided_by) with its text nulled;
    -- REJECTED is a person's decision with no minted version; ACCEPTED is a
    -- person's decision that minted one.
    CONSTRAINT workspace_context_proposal_decision_shape CHECK (
        (status = 'PROPOSED'
         AND decided_by IS NULL AND decided_at IS NULL AND decided_version IS NULL)
        OR (status = 'WITHDRAWN'
            AND decided_by IS NULL AND decided_at IS NOT NULL AND decided_version IS NULL
            AND candidate_term IS NULL AND candidate_term_key IS NULL AND suggested_text IS NULL)
        OR (status = 'REJECTED'
            AND decided_by IS NOT NULL AND decided_at IS NOT NULL AND decided_version IS NULL)
        OR (status = 'ACCEPTED'
            AND decided_by IS NOT NULL AND decided_at IS NOT NULL AND decided_version IS NOT NULL)
    )
);

-- "a dedup unique index while PROPOSED" (S2-MODEL-CONTEXT-DESIGN.md
-- migration 000113). COALESCE folds NEW_TERM's always-NULL target_term_id to
-- '' so two NEW_TERM proposals for the same folded candidate still collide;
-- Postgres would otherwise treat every NULL as distinct.
CREATE UNIQUE INDEX workspace_context_proposal_dedup_while_proposed
    ON public.workspace_context_proposal (
        organization_id, workspace_id, kind, candidate_term_key, (COALESCE(target_term_id, ''))
    )
    WHERE status = 'PROPOSED';

CREATE INDEX workspace_context_proposal_workspace_status
    ON public.workspace_context_proposal (organization_id, workspace_id, status, created_at DESC, id DESC);

ALTER TABLE public.workspace_context_proposal ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_context_proposal FORCE ROW LEVEL SECURITY;

-- "SELECT for OWNER and MANAGER only" (S2-MODEL-CONTEXT-DESIGN.md,
-- S2-CONTRACT.md "Proposals (OWNER and MANAGER only; others get 404)").
CREATE POLICY workspace_context_proposal_owner_manager_read ON public.workspace_context_proposal
FOR SELECT TO knowvault_app
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1 FROM public.workspace_member AS member
         WHERE member.organization_id = workspace_context_proposal.organization_id
           AND member.workspace_id = workspace_context_proposal.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.role IN ('OWNER', 'MANAGER')
           AND member.removed_at IS NULL
    )
);
-- The proposer (heuristic-v1, card E) is the only creator of new proposals
-- and the only bumper of occurrences; it runs as a system actor after a
-- completed run, never on behalf of a member request. It writes through
-- app.workspace_context_proposal_record (a SECURITY DEFINER function,
-- defined after every table below) rather than through an INSERT/UPDATE RLS
-- policy: the system actor is never a workspace member, so a member-gated
-- policy could not both let it write and keep this table's SELECT
-- OWNER/MANAGER-only, and an ungated INSERT/UPDATE policy would let any
-- knowvault_app-authenticated request forge a proposal or its occurrences
-- count merely by asserting the right organization_id. No INSERT or UPDATE
-- privilege is granted to knowvault_app on this table at all (below); the
-- function bypasses that grant as its own owner, exactly as app.
-- conversation_purge_request_enqueue and app.metric_definition_* already do
-- for their own trusted, non-member-scoped writes.
--
-- Deciding (accept/reject) is the one write this table's own OWNER/MANAGER
-- caller performs directly: the REST/tool-parity handler resolves the
-- accepting/rejecting principal, and this policy requires the update to
-- originate from a transaction whose current principal is OWNER/MANAGER,
-- consistent with SELECT. Withdrawal from purge cleanup runs inside a
-- different SECURITY DEFINER function owned outside RLS, so it is
-- unaffected by this policy (see app.conversation_purge_cleanup below).
CREATE POLICY workspace_context_proposal_owner_manager_write ON public.workspace_context_proposal
FOR UPDATE TO knowvault_app
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1 FROM public.workspace_member AS member
         WHERE member.organization_id = workspace_context_proposal.organization_id
           AND member.workspace_id = workspace_context_proposal.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.role IN ('OWNER', 'MANAGER')
           AND member.removed_at IS NULL
    )
)
WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.workspace_context_proposal FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT, UPDATE ON TABLE public.workspace_context_proposal TO knowvault_app;

-- workspace_context_proposal_evidence --------------------------------------
--
-- "(proposal_id, question_run_id, conversation_id, turn_id, signal), at most
-- 20 rows per proposal, no text" (S2-MODEL-CONTEXT-DESIGN.md migration
-- 000113). organization_id/workspace_id are added for direct tenant scoping
-- (TEN-001) and RLS/purge without a join back through the proposal row.
CREATE TABLE public.workspace_context_proposal_evidence (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    proposal_id text NOT NULL,
    question_run_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(question_run_id)),
    conversation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(conversation_id)),
    turn_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(turn_id)),
    signal text NOT NULL CHECK (signal IN ('NEW_TERM', 'SYNONYM', 'DEFINITION_CORRECTION')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, proposal_id, question_run_id, conversation_id, turn_id, signal),
    CONSTRAINT workspace_context_proposal_evidence_proposal_fk
        FOREIGN KEY (organization_id, proposal_id)
        REFERENCES public.workspace_context_proposal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_context_proposal_evidence_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    -- question_run rows are immutable tombstones (never physically deleted;
    -- only their decryptable content is purged), so this FK never blocks a
    -- purge and never needs an ON DELETE action.
    CONSTRAINT workspace_context_proposal_evidence_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id)
        ON DELETE RESTRICT
);

-- Purging a conversation deletes by this column directly; see
-- app.conversation_purge_cleanup below.
CREATE INDEX workspace_context_proposal_evidence_conversation
    ON public.workspace_context_proposal_evidence (organization_id, conversation_id);
CREATE INDEX workspace_context_proposal_evidence_proposal
    ON public.workspace_context_proposal_evidence (organization_id, proposal_id);

ALTER TABLE public.workspace_context_proposal_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_context_proposal_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_context_proposal_evidence_owner_manager_read ON public.workspace_context_proposal_evidence
FOR SELECT TO knowvault_app
USING (
    organization_id = app.current_organization_id()
    AND EXISTS (
        SELECT 1 FROM public.workspace_member AS member
         WHERE member.organization_id = workspace_context_proposal_evidence.organization_id
           AND member.workspace_id = workspace_context_proposal_evidence.workspace_id
           AND member.principal_id = app.current_principal_id()
           AND member.role IN ('OWNER', 'MANAGER')
           AND member.removed_at IS NULL
    )
);
-- Every evidence write (add, and the purge cleanup's delete) goes through a
-- SECURITY DEFINER function for the same reason as workspace_context_
-- proposal above: the system proposer is never a workspace member, and this
-- table's own SELECT policy is OWNER/MANAGER-only, so it cannot itself
-- count existing evidence rows to enforce the 20-per-proposal cap. No
-- INSERT privilege is granted to knowvault_app on this table at all.
REVOKE ALL ON TABLE public.workspace_context_proposal_evidence FROM PUBLIC, knowvault_app, knowvault_worker;
GRANT SELECT ON TABLE public.workspace_context_proposal_evidence TO knowvault_app;

-- workspace_context_term_sighting ------------------------------------------
--
-- Cross-run bookkeeping the NEW_TERM signal needs to require "an unknown
-- non-stop-list token queued after at least two distinct runs"
-- (S2-MODEL-CONTEXT-DESIGN.md "Proposer"): one row per distinct folded token
-- ever seen unmatched in a workspace, counting how many distinct runs have
-- seen it. It is never read outside this package and carries no evidence
-- text of its own beyond the folded token. distinct_run_count is
-- deliberately uncapped (a promoted-then-rejected token must be able to
-- resurface): only proposal creation itself is bounded, by the 200-per-
-- workspace and 3-per-run limits enforced in application code.
CREATE TABLE public.workspace_context_term_sighting (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    workspace_id text NOT NULL,
    token_key text NOT NULL
        CHECK (char_length(token_key) BETWEEN 1 AND 80 AND token_key !~ '[[:cntrl:]]'),
    distinct_run_count integer NOT NULL DEFAULT 1 CHECK (distinct_run_count BETWEEN 1 AND 2147483647),
    last_question_run_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(last_question_run_id)),
    last_seen_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, workspace_id, token_key),
    CONSTRAINT workspace_context_term_sighting_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT
);

-- Pure internal bookkeeping for the system proposer only, read and written
-- exclusively through app.workspace_context_term_sighting_record (a
-- SECURITY DEFINER function, defined below): RLS is forced with no policy
-- at all, and no privilege is granted to knowvault_app on this table
-- directly, so the only path to it is that function.
ALTER TABLE public.workspace_context_term_sighting ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_context_term_sighting FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.workspace_context_term_sighting FROM PUBLIC, knowvault_app, knowvault_worker;

-- The proposer's trusted writes -------------------------------------------
--
-- Three SECURITY DEFINER functions are the only way knowvault_app writes
-- workspace_context_proposal, workspace_context_proposal_evidence or
-- workspace_context_term_sighting from the system (heuristic-v1) path: as
-- their own owner they bypass RLS entirely, so they re-derive the one check
-- that still applies to a trusted, non-member-scoped system write (the
-- caller's own tenant) instead of relying on the member-gated policies
-- above, which the system principal (never a workspace member) cannot pass.
-- This is the same shape as app.conversation_purge_request_enqueue and
-- app.metric_definition_* elsewhere in this schema.

-- Dedup-bumps an existing PROPOSED proposal matching
-- (workspace_id, kind, candidate_term_key, target_term_id), or creates one
-- with p_new_id (subject to the 200-open-per-workspace cap: "beyond that,
-- only counters grow" — returns NULL rather than raising, since hitting the
-- cap is an expected product outcome, not a failure). Returns the recorded
-- proposal's id, or NULL when the cap silently skipped creation.
CREATE OR REPLACE FUNCTION app.workspace_context_proposal_record(
    p_organization_id text,
    p_workspace_id text,
    p_new_id text,
    p_kind text,
    p_candidate_term text,
    p_candidate_term_key text,
    p_target_term_id text,
    p_suggested_text text,
    p_detector_version text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    existing_id text;
    open_count integer;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'workspace context proposal recording requires the application role' USING ERRCODE = '42501';
    END IF;
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'workspace context proposal tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;

    SELECT proposal.id INTO existing_id
      FROM public.workspace_context_proposal AS proposal
     WHERE proposal.organization_id = p_organization_id
       AND proposal.workspace_id = p_workspace_id
       AND proposal.kind = p_kind
       AND proposal.candidate_term_key = p_candidate_term_key
       AND COALESCE(proposal.target_term_id, '') = COALESCE(p_target_term_id, '')
       AND proposal.status = 'PROPOSED'
     FOR UPDATE;

    IF existing_id IS NOT NULL THEN
        UPDATE public.workspace_context_proposal
           SET occurrences = occurrences + 1
         WHERE organization_id = p_organization_id AND id = existing_id;
        RETURN existing_id;
    END IF;

    SELECT count(*) INTO open_count
      FROM public.workspace_context_proposal
     WHERE organization_id = p_organization_id AND workspace_id = p_workspace_id AND status = 'PROPOSED';
    IF open_count >= 200 THEN
        RETURN NULL;
    END IF;

    INSERT INTO public.workspace_context_proposal (
        organization_id, id, workspace_id, kind, candidate_term, candidate_term_key,
        target_term_id, suggested_text, status, occurrences, detector_version
    ) VALUES (
        p_organization_id, p_new_id, p_workspace_id, p_kind, p_candidate_term, p_candidate_term_key,
        p_target_term_id, p_suggested_text, 'PROPOSED', 1, p_detector_version
    );
    RETURN p_new_id;
END;
$$;

-- Records one evidence row for p_proposal_id, subject to the
-- 20-rows-per-proposal cap (returns without inserting, no error, when
-- already at the cap). ON CONFLICT DO NOTHING makes re-observing the exact
-- same (proposal, run, conversation, turn, signal) tuple idempotent.
CREATE OR REPLACE FUNCTION app.workspace_context_proposal_evidence_record(
    p_organization_id text,
    p_workspace_id text,
    p_proposal_id text,
    p_question_run_id text,
    p_conversation_id text,
    p_turn_id text,
    p_signal text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    evidence_count integer;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'workspace context proposal evidence requires the application role' USING ERRCODE = '42501';
    END IF;
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'workspace context proposal evidence tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;

    SELECT count(*) INTO evidence_count
      FROM public.workspace_context_proposal_evidence
     WHERE organization_id = p_organization_id AND proposal_id = p_proposal_id;
    IF evidence_count >= 20 THEN
        RETURN;
    END IF;

    INSERT INTO public.workspace_context_proposal_evidence (
        organization_id, workspace_id, proposal_id, question_run_id, conversation_id, turn_id, signal
    ) VALUES (
        p_organization_id, p_workspace_id, p_proposal_id, p_question_run_id, p_conversation_id, p_turn_id, p_signal
    )
    ON CONFLICT DO NOTHING;
END;
$$;

-- Records one distinct-run sighting of p_token_key and reports whether it
-- has now been seen in at least two distinct runs ("queued after at least
-- two distinct runs" — the NEW_TERM promotion gate). The same run id
-- reported twice is not double-counted.
CREATE OR REPLACE FUNCTION app.workspace_context_term_sighting_record(
    p_organization_id text,
    p_workspace_id text,
    p_token_key text,
    p_question_run_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $$
DECLARE
    current_count integer;
    last_run text;
BEGIN
    IF session_user <> 'knowvault_app' THEN
        RAISE EXCEPTION 'workspace context term sighting requires the application role' USING ERRCODE = '42501';
    END IF;
    IF p_organization_id IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'workspace context term sighting tenant must match the session tenant' USING ERRCODE = '42501';
    END IF;

    SELECT sighting.distinct_run_count, sighting.last_question_run_id
      INTO current_count, last_run
      FROM public.workspace_context_term_sighting AS sighting
     WHERE sighting.organization_id = p_organization_id
       AND sighting.workspace_id = p_workspace_id
       AND sighting.token_key = p_token_key
     FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO public.workspace_context_term_sighting (
            organization_id, workspace_id, token_key, distinct_run_count, last_question_run_id
        ) VALUES (p_organization_id, p_workspace_id, p_token_key, 1, p_question_run_id);
        RETURN false;
    END IF;

    IF last_run = p_question_run_id THEN
        RETURN current_count >= 2;
    END IF;

    current_count := current_count + 1;
    UPDATE public.workspace_context_term_sighting
       SET distinct_run_count = current_count, last_question_run_id = p_question_run_id, last_seen_at = transaction_timestamp()
     WHERE organization_id = p_organization_id AND workspace_id = p_workspace_id AND token_key = p_token_key;
    RETURN current_count >= 2;
END;
$$;

REVOKE ALL ON FUNCTION
    app.workspace_context_proposal_record(text, text, text, text, text, text, text, text, text),
    app.workspace_context_proposal_evidence_record(text, text, text, text, text, text, text),
    app.workspace_context_term_sighting_record(text, text, text, text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    app.workspace_context_proposal_record(text, text, text, text, text, text, text, text, text),
    app.workspace_context_proposal_evidence_record(text, text, text, text, text, text, text),
    app.workspace_context_term_sighting_record(text, text, text, text)
TO knowvault_app;

-- Purge integration ---------------------------------------------------------
--
-- "Purging a conversation removes its evidence rows. A proposal left without
-- evidence becomes WITHDRAWN with its text nulled" (S2-MODEL-CONTEXT-
-- DESIGN.md migration 000113). app.conversation_purge_cleanup (000054) is
-- the sole, already-fenced, idempotently-resumable owner of "purge this
-- conversation's decryptable content"; this migration widens that same
-- function (CREATE OR REPLACE, same signature, same SECURITY DEFINER owner)
-- by appending this table's cleanup as its last step, strictly after every
-- pre-existing statement, so the original encrypted-artifact behavior this
-- function already proved is unchanged. It is additive only: the function's
-- role check, fenced state machine, and fail-closed completion gate above
-- this point are untouched.
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
    affected_proposal_ids text[];
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

    -- S2 card E addition: remove this conversation's proposal evidence, then
    -- withdraw (and null the text of) any proposal left with none. A
    -- proposal already ACCEPTED, REJECTED or WITHDRAWN is a terminal,
    -- already-decided outcome and is left exactly as it is.
    --
    -- This is deliberately three separate statements, not one WITH chain: a
    -- single data-modifying CTE query has one snapshot for the whole
    -- statement, so a NOT EXISTS subquery against workspace_context_
    -- proposal_evidence in the same statement as the DELETE would still see
    -- the about-to-be-deleted rows and never fire. Capturing the affected
    -- ids before the DELETE, as its own prior statement, and evaluating
    -- "any evidence left" in the UPDATE as a later statement avoids that:
    -- each statement in this function sees every earlier statement's
    -- already-applied effect within the same transaction.
    SELECT array_agg(DISTINCT evidence.proposal_id) INTO affected_proposal_ids
      FROM public.workspace_context_proposal_evidence AS evidence
     WHERE evidence.organization_id = p_organization_id
       AND evidence.workspace_id = p_workspace_id
       AND evidence.conversation_id = p_conversation_id;

    DELETE FROM public.workspace_context_proposal_evidence AS evidence
     WHERE evidence.organization_id = p_organization_id
       AND evidence.workspace_id = p_workspace_id
       AND evidence.conversation_id = p_conversation_id;

    IF affected_proposal_ids IS NOT NULL THEN
        UPDATE public.workspace_context_proposal AS proposal
           SET status = 'WITHDRAWN',
               candidate_term = NULL,
               candidate_term_key = NULL,
               suggested_text = NULL,
               decided_at = clock_timestamp()
         WHERE proposal.organization_id = p_organization_id
           AND proposal.id = ANY (affected_proposal_ids)
           AND proposal.status = 'PROPOSED'
           AND NOT EXISTS (
               SELECT 1 FROM public.workspace_context_proposal_evidence AS remaining
                WHERE remaining.organization_id = p_organization_id
                  AND remaining.proposal_id = proposal.id
           );
    END IF;

    RETURN purged_count;
END;
$$;

REVOKE ALL ON FUNCTION app.conversation_purge_cleanup(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.conversation_purge_cleanup(text, text, text) TO knowvault_purger;

COMMIT;
