-- R1.S10.s1.T4 follow-up (independent review).
--
-- Two forward-only widenings, in the same shape every earlier owner branch
-- and every earlier conversation-purge widening used:
--
-- 1. The AAD owner inventory is closed. This forward definition preserves
--    every earlier branch (000090's 27, which already forward-preserved
--    000005's original 26) and adds exactly one owner for the answer
--    feedback comment. Migrations 000005 and 000090 are already applied in
--    every deployed environment and are never edited: ApplyMigrations
--    (internal/operator/bootstrap.go, migration_checksum.go) rejects any
--    deployment whose recorded checksum for an applied migration no longer
--    matches its bytes.
--
-- 2. "Purging a conversation removes its evidence rows" (S2-MODEL-CONTEXT-
--    DESIGN.md; 000113 widened this the same way for workspace context
--    proposals) must also remove the decryptable comment of any answer
--    feedback on a purged conversation's runs -- a purged answer's own
--    feedback comment is exactly the kind of content this function already
--    exists to make undecryptable. app.conversation_purge_cleanup is the
--    sole, already-fenced, idempotently-resumable owner of that operation;
--    this migration widens that same function (CREATE OR REPLACE, same
--    signature, same SECURITY DEFINER owner) by adding the feedback-comment
--    branch to its existing cleanup and to its own "decryptable content
--    remains" completion gate, strictly additive to every statement 000113
--    already proved.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc proc
        JOIN pg_catalog.pg_namespace ns ON ns.oid = proc.pronamespace
        WHERE ns.nspname = 'app' AND proc.proname = 'conversation_purge_cleanup'
    ) THEN
        RAISE EXCEPTION 'app.conversation_purge_cleanup must already exist (000054/000113)' USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app.encrypted_artifact_owner_is_valid(
    owner_table_value text,
    owner_column_value text,
    resource_type_value text,
    field_value text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT (owner_table_value, owner_column_value, resource_type_value, field_value) IN (
        ('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT'),
        ('source_connection_revision', 'trust_profile_artifact_id', 'SOURCE_TRUST_CONFIG', 'TRUST_CONFIG'),
        ('source_discovery_result', 'metadata_artifact_id', 'SOURCE_DISCOVERY_RESULT', 'DISCOVERY_METADATA'),
        ('source_discovered_scope', 'identity_artifact_id', 'SOURCE_SCOPE_IDENTITY', 'EXTERNAL_SCOPE_IDENTITY'),
        ('source_discovered_scope', 'display_metadata_artifact_id', 'SOURCE_SCOPE_METADATA', 'DISPLAY_METADATA'),
        ('source_scope_revision', 'scope_config_artifact_id', 'SOURCE_SCOPE_CONFIG', 'SCOPE_CONFIG'),
        ('source_object', 'external_object_id_artifact_id', 'SOURCE_OBJECT_ID', 'EXTERNAL_OBJECT_ID'),
        ('source_object', 'canonical_locator_artifact_id', 'SOURCE_LOCATOR', 'CANONICAL_LOCATOR'),
        ('source_object', 'title_artifact_id', 'SOURCE_TITLE', 'DISPLAY_TITLE'),
        ('acl_snapshot', 'principal_tokens_artifact_id', 'ACL_PRINCIPAL_SET', 'PRINCIPAL_TOKENS'),
        ('evidence_fragment', 'normalized_text_artifact_id', 'EVIDENCE_TEXT', 'NORMALIZED_TEXT'),
        ('evidence_fragment', 'anchor_artifact_id', 'EVIDENCE_ANCHOR', 'CANONICAL_ANCHOR'),
        ('evidence_fragment', 'metadata_artifact_id', 'EVIDENCE_METADATA', 'METADATA'),
        ('search_chunk', 'search_text_artifact_id', 'SEARCH_CHUNK_TEXT', 'NORMALIZED_TEXT'),
        ('question_run', 'question_text_artifact_id', 'QUESTION_RUN', 'QUESTION_TEXT'),
        ('question_run', 'answer_markdown_artifact_id', 'QUESTION_RUN', 'ANSWER_MARKDOWN'),
        ('question_run', 'answer_structured_artifact_id', 'QUESTION_RUN', 'ANSWER_STRUCTURED'),
        ('question_run', 'manifest_content_artifact_id', 'MANIFEST_CONTENT', 'CANONICAL_BYTES'),
        ('question_authorized_candidate_set', 'canonical_artifact_id', 'AUTHORIZED_CANDIDATE_SET', 'CANONICAL_BYTES'),
        ('question_model_execution_plan', 'canonical_artifact_id', 'MODEL_EXECUTION_PLAN', 'CANONICAL_BYTES'),
        ('question_claim', 'text_artifact_id', 'CLAIM_TEXT', 'CLAIM_TEXT'),
        ('claim_deterministic_validation_artifact', 'output_artifact_id', 'DETERMINISTIC_VALIDATION', 'VALIDATION_OUTPUT'),
        ('question_citation', 'cited_excerpt_artifact_id', 'CITED_EXCERPT', 'EXACT_TEXT'),
        ('question_citation', 'anchor_artifact_id', 'CITATION_ANCHOR', 'CANONICAL_ANCHOR'),
        ('question_citation', 'deep_link_artifact_id', 'SOURCE_DEEPLINK', 'DEEPLINK'),
        ('model_run_artifact', 'input_artifact_id', 'MODEL_ARTIFACT', 'CANONICAL_INPUT'),
        ('model_run_artifact', 'output_artifact_id', 'MODEL_ARTIFACT', 'CANONICAL_OUTPUT'),
        ('question_feedback', 'comment_artifact_id', 'QUESTION_FEEDBACK', 'COMMENT_TEXT')
    );
$$;

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
    -- R1.S10.s1.T4: every feedback row (any member's mark) on any run bound
    -- to this conversation. The feedback row itself is not deleted -- only
    -- the encrypted comment it may point at, exactly like a citation row
    -- survives while its excerpt/anchor/deep-link artifacts are purged.
    bound_feedback AS MATERIALIZED (
        SELECT feedback.id
          FROM public.question_feedback AS feedback
          JOIN bound_runs AS run ON run.id = feedback.question_run_id
         WHERE feedback.organization_id = p_organization_id
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
               OR
               (artifact.owner_table = 'question_feedback'
                AND artifact.owner_column = 'comment_artifact_id'
                AND artifact.resource_id IN (SELECT id FROM bound_feedback))
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
               OR
               (artifact.owner_table = 'question_feedback'
                AND artifact.owner_column = 'comment_artifact_id'
                AND EXISTS (
                    SELECT 1
                      FROM public.question_feedback AS feedback
                      JOIN public.question_run AS run
                        ON run.organization_id = feedback.organization_id
                       AND run.id = feedback.question_run_id
                     WHERE feedback.organization_id = p_organization_id
                       AND feedback.id = artifact.resource_id
                       AND run.workspace_id = p_workspace_id
                       AND run.conversation_id = p_conversation_id
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
