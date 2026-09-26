-- Stage 3 answer feedback (R1.S10.s1.T4).
--
-- One workspace member holds exactly one *current* correctness mark on one
-- terminal, answered Question Run: CORRECT, or INCORRECT with a mandatory
-- free-text comment. The mark can be changed; changing it updates the same
-- row rather than appending a new one, because the product need is "the
-- current mark", not a history of past marks. The comment is user content
-- and is envelope-encrypted exactly like the question text and answer body
-- (ENCRYPTION.md); it is never a plain column and never enters the audit
-- event, which records only the run, the verdict and whether a comment is
-- present.
--
-- Visibility follows the answer: a feedback row is readable only by a
-- principal who could still read the Question Run it marks (the same
-- workspace-membership boundary FORCE ROW LEVEL SECURITY already applies to
-- question_run/question_citation), plus the workspace OWNER/MANAGER, who may
-- read every member's feedback for the error-review report. Only the
-- feedback's own author may write it.

BEGIN;

CREATE TABLE public.question_feedback (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    question_run_id text NOT NULL,
    workspace_id text NOT NULL,
    created_by text NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('CORRECT', 'INCORRECT')),
    comment_artifact_id text CHECK (
        comment_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(comment_artifact_id)
    ),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    -- "One current mark per user per answer": a resubmission updates this
    -- exact row through ON CONFLICT, never inserts a second one.
    UNIQUE (organization_id, question_run_id, created_by),
    CONSTRAINT question_feedback_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_feedback_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_feedback_creator_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT
);

COMMENT ON TABLE public.question_feedback IS
    'One current CORRECT/INCORRECT mark per (question_run, created_by); comment_artifact_id is the encrypted free-text comment -- mandatory when verdict is INCORRECT, optional but stored when given for CORRECT';
COMMENT ON COLUMN public.question_feedback.comment_artifact_id IS
    'encrypted_artifact owner branch (question_feedback, comment_artifact_id, QUESTION_FEEDBACK, COMMENT_TEXT); replaceable, unlike the write-once question_run/question_citation branches, because the mark and its comment can change';

CREATE INDEX question_feedback_run_idx
    ON public.question_feedback (organization_id, question_run_id);
CREATE INDEX question_feedback_workspace_idx
    ON public.question_feedback (organization_id, workspace_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 1. Identity/shape guard. The row's identity (who, which run, which
--    workspace) is immutable; only verdict, comment_artifact_id and
--    updated_at may move, and only forward in time. Deletes are rejected
--    outright: a changed mind is a new UPDATE, not the loss of a mark.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.question_feedback_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'question feedback is immutable identity; retract by changing the mark' USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_app'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR NEW.created_by IS DISTINCT FROM app.current_principal_id()
           OR NOT app.question_run_readable(NEW.question_run_id, NEW.workspace_id)
           OR NOT EXISTS (
               SELECT 1 FROM public.question_run run
               WHERE run.organization_id = NEW.organization_id
                 AND run.id = NEW.question_run_id
                 AND run.workspace_id = NEW.workspace_id
                 AND run.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE')
           ) THEN
            RAISE EXCEPTION 'question feedback requires a readable, answered question run' USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    -- UPDATE: only the author, and only while still able to read the run.
    IF session_user <> 'knowvault_app'
       OR OLD.created_by IS DISTINCT FROM app.current_principal_id()
       OR NOT app.question_run_readable(OLD.question_run_id, OLD.workspace_id) THEN
        RAISE EXCEPTION 'question feedback update is restricted to its current author' USING ERRCODE = '42501';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.question_run_id IS DISTINCT FROM OLD.question_run_id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'question feedback identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'question feedback updated_at cannot move backwards' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_feedback_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_feedback
FOR EACH ROW EXECUTE FUNCTION app.question_feedback_guard();

-- ---------------------------------------------------------------------------
-- 2. Encrypted comment branch. Unlike the generic write-once bind pattern
--    used for question_run/question_citation artifacts, the comment must be
--    replaceable: bind is an unconditional overwrite of the owning row's
--    column, guarded only by tenant and resource-id match. The AAD owner
--    tuple (table, column, resource_type, field, resource_id) never changes
--    across a replacement, only the ciphertext does, so no other tenant/row
--    linkage is possible even though the column is mutable.
-- ---------------------------------------------------------------------------

CREATE FUNCTION app.question_feedback_bind_comment(
    p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
    p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
    p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
    p_aad_hash text, p_plaintext_hash text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
        RAISE EXCEPTION 'resource id must equal the owning row id' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.question_feedback feedback
        WHERE feedback.organization_id = p_org AND feedback.id = p_owning_row_id
          AND feedback.created_by = app.current_principal_id()
    ) THEN
        RAISE EXCEPTION 'question feedback row missing or not owned by the caller' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.encrypted_artifact (
        organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
        cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
    ) VALUES (
        p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'question_feedback', 'comment_artifact_id', 'QUESTION_FEEDBACK', p_resource_id, 'COMMENT_TEXT',
        'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
    );
    UPDATE public.question_feedback SET comment_artifact_id = p_artifact_id
     WHERE organization_id = p_org AND id = p_owning_row_id;
END;
$$;

-- The Go authorize closure re-checks this too (defense in depth), but a
-- SECURITY DEFINER read function bypasses RLS entirely, so the actual
-- boundary has to live here: only the feedback's own author or a current
-- OWNER/MANAGER of its workspace may decrypt the comment.
CREATE FUNCTION app.question_feedback_read_comment(p_owning_row_id text)
RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
    wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
           a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
    FROM public.question_feedback owner_row
    JOIN public.encrypted_artifact a
      ON a.organization_id = owner_row.organization_id AND a.id = owner_row.comment_artifact_id
    WHERE owner_row.organization_id = app.current_organization_id()
      AND owner_row.id = p_owning_row_id AND a.purged_at IS NULL
      AND (
          owner_row.created_by = app.current_principal_id()
          OR EXISTS (
              SELECT 1 FROM public.workspace_member manager
              WHERE manager.organization_id = owner_row.organization_id
                AND manager.workspace_id = owner_row.workspace_id
                AND manager.principal_id = app.current_principal_id()
                AND manager.removed_at IS NULL
                AND manager.role IN ('OWNER', 'MANAGER')
          )
      );
$$;

-- Idempotency support: the caller must compare a candidate comment's hash
-- against whatever is currently stored before deciding whether a resubmission
-- is a true no-op, but application Go code must never name
-- public.encrypted_artifact directly (POKA_YOKE: architecture guard scans
-- cmd/ and internal/ for that literal token). This narrow read exposes only
-- the content-free plaintext_hash, restricted to the feedback's own author.
CREATE FUNCTION app.question_feedback_previous_comment_hash(p_owning_row_id text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT a.plaintext_hash
    FROM public.question_feedback owner_row
    JOIN public.encrypted_artifact a
      ON a.organization_id = owner_row.organization_id AND a.id = owner_row.comment_artifact_id
    WHERE owner_row.organization_id = app.current_organization_id()
      AND owner_row.id = p_owning_row_id
      AND owner_row.created_by = app.current_principal_id();
$$;

REVOKE ALL ON FUNCTION app.question_feedback_bind_comment(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_feedback_bind_comment(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app;
REVOKE ALL ON FUNCTION app.question_feedback_read_comment(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_feedback_read_comment(text) TO knowvault_app;
REVOKE ALL ON FUNCTION app.question_feedback_previous_comment_hash(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_feedback_previous_comment_hash(text) TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 2b. Replacing or clearing a comment (a changed mark, or a changed comment
--     under the same verdict) must not leave the previous ciphertext
--     decryptable. It cannot be erased synchronously by this same INSERT/
--     UPDATE, though: migration 000019's encrypted_artifact state-guard
--     trigger unconditionally rejects ANY mutation of that table by
--     session_user = 'knowvault_app' (the runtime role every ordinary web
--     request runs as) -- by design, so a compromised or buggy request
--     handler can never scrub evidence. Only the privileged knowvault_purger
--     role, which the web-facing server process never holds (only cmd/purger
--     does), may perform that tombstone UPDATE.
--
--     The caller therefore enqueues the previous artifact id in the SAME
--     transaction as the rebind/clear (a plain, RLS-scoped table INSERT,
--     exactly like every other content the app role writes); the already-
--     running purger process (internal/purge.Runner, cmd/purger) drains this
--     queue every tick and performs the actual tombstone UPDATE under its own
--     role, the same shape migration 000123's widened conversation_purge_
--     cleanup and the source/conversation retention purges already use. This
--     is the closest compliant equivalent to "erased in the same
--     transaction" available under the existing role boundary: the decision
--     to erase is atomic with the edit, and the erasure itself follows within
--     one purger poll interval, never left to an unbounded background sweep.
-- ---------------------------------------------------------------------------

CREATE TABLE public.question_feedback_comment_purge_queue (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    artifact_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(artifact_id)),
    enqueued_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, artifact_id)
);

COMMENT ON TABLE public.question_feedback_comment_purge_queue IS
    'Superseded question_feedback comment artifacts awaiting the privileged tombstone the knowvault_app role cannot perform itself; drained by the purger process';

ALTER TABLE public.question_feedback_comment_purge_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_feedback_comment_purge_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY question_feedback_comment_purge_queue_tenant ON public.question_feedback_comment_purge_queue
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

-- No table grant reaches the application role at all: enqueue is possible
-- only through the SECURITY DEFINER function below, which proves ownership
-- first. A stray direct INSERT (or a bug reusing a raw connection) has no
-- privilege to fall back on.
REVOKE ALL ON TABLE public.question_feedback_comment_purge_queue FROM PUBLIC;
GRANT SELECT, DELETE ON TABLE public.question_feedback_comment_purge_queue TO knowvault_purger;

-- Enqueue: app-role only, and only for an artifact that is provably a
-- comment_artifact_id-branch artifact of the caller's OWN feedback row --
-- never an arbitrary artifact id (question text, Evidence, another
-- member's comment). It also refuses to enqueue the row's CURRENT comment
-- artifact: only a superseded one may ever be queued, so the drain below can
-- never race a still-referenced comment out from under a concurrent read.
CREATE FUNCTION app.question_feedback_enqueue_comment_purge(p_org text, p_owning_row_id text, p_artifact_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF session_user <> 'knowvault_app' OR p_org IS DISTINCT FROM app.current_organization_id() THEN
        RAISE EXCEPTION 'feedback comment purge enqueue is restricted to the application role for its own tenant' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.question_feedback feedback
        WHERE feedback.organization_id = p_org AND feedback.id = p_owning_row_id
          AND feedback.created_by = app.current_principal_id()
    ) THEN
        RAISE EXCEPTION 'question feedback row missing or not owned by the caller' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.encrypted_artifact artifact
        WHERE artifact.organization_id = p_org AND artifact.id = p_artifact_id
          AND artifact.owner_table = 'question_feedback' AND artifact.owner_column = 'comment_artifact_id'
          AND artifact.resource_id = p_owning_row_id
    ) THEN
        RAISE EXCEPTION 'artifact is not a comment of the caller''s own feedback row' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.question_feedback feedback
        WHERE feedback.organization_id = p_org AND feedback.comment_artifact_id = p_artifact_id
    ) THEN
        RAISE EXCEPTION 'cannot enqueue a feedback row''s current comment artifact for purge' USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.question_feedback_comment_purge_queue (organization_id, artifact_id)
    VALUES (p_org, p_artifact_id)
    ON CONFLICT (organization_id, artifact_id) DO NOTHING;
END;
$$;

-- Drain: purger-role only. One call tombstones up to p_limit queued
-- artifacts across every tenant -- the purger process is already the sole
-- trusted tenant-wide operator for this kind of reconciliation sweep, exactly
-- like the existing conversation/source-version purge queues it drains in
-- the same poll tick (internal/purge.Runner). The UPDATE repeats the exact
-- same owner-branch and "not anyone's current comment" checks the enqueue
-- function already proved, so this function alone -- even if some future
-- caller enqueued a row some other way -- can never erase a text/Evidence/
-- other-branch artifact or one a feedback row still points to.
CREATE FUNCTION app.question_feedback_process_comment_purge_queue(p_limit integer)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    purged_count bigint := 0;
    item record;
BEGIN
    IF session_user <> 'knowvault_purger' THEN
        RAISE EXCEPTION 'feedback comment purge processing is restricted to the purger role' USING ERRCODE = '42501';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'feedback comment purge limit is out of range' USING ERRCODE = '22023';
    END IF;

    FOR item IN
        SELECT organization_id, artifact_id
        FROM public.question_feedback_comment_purge_queue
        ORDER BY enqueued_at
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    LOOP
        UPDATE public.encrypted_artifact AS artifact
           SET ciphertext = NULL, wrapped_dek = NULL, purged_at = clock_timestamp()
         WHERE artifact.organization_id = item.organization_id AND artifact.id = item.artifact_id
           AND artifact.owner_table = 'question_feedback' AND artifact.owner_column = 'comment_artifact_id'
           AND artifact.purged_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM public.question_feedback feedback
               WHERE feedback.organization_id = artifact.organization_id
                 AND feedback.comment_artifact_id = artifact.id
           );
        IF FOUND THEN
            purged_count := purged_count + 1;
        END IF;
        DELETE FROM public.question_feedback_comment_purge_queue
         WHERE organization_id = item.organization_id AND artifact_id = item.artifact_id;
    END LOOP;

    RETURN purged_count;
END;
$$;

REVOKE ALL ON FUNCTION app.question_feedback_enqueue_comment_purge(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_feedback_enqueue_comment_purge(text, text, text) TO knowvault_app;
REVOKE ALL ON FUNCTION app.question_feedback_process_comment_purge_queue(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.question_feedback_process_comment_purge_queue(integer) TO knowvault_purger;

-- ---------------------------------------------------------------------------
-- 3. Row security. SELECT is readable by the row's own author (while still
--    able to read the run) and by the current workspace OWNER/MANAGER (the
--    error-review report); INSERT/UPDATE is restricted to the author. There
--    is no DELETE grant: the row is retract-by-update only.
-- ---------------------------------------------------------------------------

ALTER TABLE public.question_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_feedback FORCE ROW LEVEL SECURITY;

-- Both branches require app.question_run_readable: the manager's error-review
-- read is authorized to see every member's mark, but never one on an answer
-- that is not itself currently readable (purged or disclosure-revoked) --
-- exactly the same readability rule the row's own author is held to.
CREATE POLICY question_feedback_read ON public.question_feedback
    FOR SELECT
    USING (
        organization_id = app.current_organization_id()
        AND app.question_run_readable(question_run_id, workspace_id)
        AND (
            created_by = app.current_principal_id()
            OR EXISTS (
                SELECT 1 FROM public.workspace_member manager
                WHERE manager.organization_id = question_feedback.organization_id
                  AND manager.workspace_id = question_feedback.workspace_id
                  AND manager.principal_id = app.current_principal_id()
                  AND manager.removed_at IS NULL
                  AND manager.role IN ('OWNER', 'MANAGER')
            )
        )
    );

CREATE POLICY question_feedback_write ON public.question_feedback
    FOR INSERT
    WITH CHECK (organization_id = app.current_organization_id() AND created_by = app.current_principal_id());

CREATE POLICY question_feedback_update ON public.question_feedback
    FOR UPDATE
    USING (organization_id = app.current_organization_id() AND created_by = app.current_principal_id())
    WITH CHECK (organization_id = app.current_organization_id() AND created_by = app.current_principal_id());

REVOKE ALL ON TABLE public.question_feedback FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.question_feedback TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4. The audit event resource_type vocabulary gains QUESTION_FEEDBACK, and the
--    metadata_json allowed-key vocabulary gains the two feedback fields.
--    Action strings are already open-shaped (a dotted lowercase regex on
--    `action`), so no separate vocabulary change is needed there.
-- ---------------------------------------------------------------------------

ALTER TABLE public.audit_event
    DROP CONSTRAINT audit_event_resource_type_check,
    ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
        'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
        'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
        'SOURCE_CONNECTION', 'SOURCE_SCOPE', 'SOURCE_OBJECT',
        'CONVERSATION', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
        'SIGNING_KEY', 'AUDIT_CHECKPOINT', 'CRYPTO_KEY', 'ANSWER_DOCUMENT',
        'GOVERNED_QUERY_ATTEMPT', 'SEARCH_PROFILE',
        'WORKSPACE_MODEL_CONTEXT', 'WORKSPACE_CONTEXT_PROPOSAL', 'QUESTION_FEEDBACK'
    ));

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
               'remote_address_digest', 'user_agent_family',
               -- Authority command vocabulary (ADR-0053).
               'authority_operation', 'authority_result_id', 'authority_result_hash',
               'authority_parent_id', 'authority_parent_hash',
               'authority_revocation_id', 'authority_revocation_hash',
               'authority_reason_code', 'target_principal_id',
               'workspace_configuration_hash', 'confirmation_actor_grant_id',
               'confirmation_actor_grant_revision', 'confirmation_actor_grant_hash',
               'warning_version', 'warning_contract_hash', 'acknowledgement_code',
               -- Rotation vocabulary (ADR-0070).
               'rotation_domain', 'key_reference', 'key_version',
               -- Amendment vocabulary (ADR-0076).
               'answer_document_version', 'amendment_class',
               -- Connection trust verification vocabulary (ADR-0087 §2).
               'trust_verification_id', 'trust_verification_hash',
               -- Governed query attempt vocabulary (ADR-0089 §4, S3 card 2c).
               'governed_query_connection_id', 'governed_query_exposed_schema_revision',
               'governed_query_sql_hash', 'governed_query_cost_estimate',
               'governed_query_row_count', 'governed_query_result_digest',
               'governed_query_outcome', 'governed_query_purpose',
               -- Answer feedback vocabulary (R1.S10.s1.T4): the closed verdict
               -- and whether a comment is attached, never the comment text.
               'feedback_verdict', 'feedback_has_comment'
           )
       );
$$;

COMMIT;
