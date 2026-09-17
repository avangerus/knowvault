-- Stage 3 live extractive Question Run surface.
--
-- This migration deliberately activates only the deterministic extractive mode.
-- It does not create a model runtime, search index or arbitrary SQL surface. A
-- run is an immutable, workspace-scoped aggregate; content is still carried by
-- the existing encrypted-artifact owner branches and every citation resolves
-- through the existing Evidence gate.

BEGIN;

CREATE TABLE public.question_run (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    created_by text NOT NULL,
    question_text_artifact_id text CHECK (
        question_text_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(question_text_artifact_id)
    ),
    question_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(question_hash)),
    answer_mode text NOT NULL CHECK (answer_mode IN ('EXTRACTIVE', 'GENERATIVE')),
    verification_method text NOT NULL CHECK (verification_method IN ('BYTE_EXACT_CITATION', 'SEMANTIC_VERIFIER')),
    result_status text NOT NULL DEFAULT 'QUEUED'
        CHECK (result_status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'INSUFFICIENT_EVIDENCE', 'FAILED', 'CANCELLED')),
    corpus_status text NOT NULL DEFAULT 'COMPLETE' CHECK (corpus_status IN ('COMPLETE', 'PARTIAL')),
    started_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    completed_at timestamptz,
    answer_markdown_artifact_id text CHECK (
        answer_markdown_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(answer_markdown_artifact_id)
    ),
    answer_structured_artifact_id text CHECK (
        answer_structured_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(answer_structured_artifact_id)
    ),
    answer_hash text CHECK (answer_hash IS NULL OR app.stage2_sha256_is_valid(answer_hash)),
    workspace_scope_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(workspace_scope_hash)),
    context_pack_hash text CHECK (context_pack_hash IS NULL OR app.stage2_sha256_is_valid(context_pack_hash)),
    retrieval_version text NOT NULL DEFAULT 'extractive-v1'
        CHECK (char_length(retrieval_version) BETWEEN 1 AND 128 AND retrieval_version !~ '[[:cntrl:]]'),
    policy_revision text NOT NULL CHECK (char_length(policy_revision) BETWEEN 1 AND 128 AND policy_revision !~ '[[:cntrl:]]'),
    manifest_content_artifact_id text CHECK (
        manifest_content_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(manifest_content_artifact_id)
    ),
    manifest_signing_bytes bytea,
    manifest_hash text CHECK (manifest_hash IS NULL OR app.stage2_sha256_is_valid(manifest_hash)),
    manifest_signature_json jsonb,
    supersedes_question_run_id text,
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT question_run_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_run_creator_fk
        FOREIGN KEY (organization_id, created_by)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_run_question_artifact_fk
        FOREIGN KEY (organization_id, question_text_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT question_run_answer_artifact_fk
        FOREIGN KEY (organization_id, answer_markdown_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT question_run_structured_artifact_fk
        FOREIGN KEY (organization_id, answer_structured_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT question_run_manifest_artifact_fk
        FOREIGN KEY (organization_id, manifest_content_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT question_run_mode_pair_check CHECK (
        (answer_mode = 'EXTRACTIVE' AND verification_method = 'BYTE_EXACT_CITATION')
        OR (answer_mode = 'GENERATIVE' AND verification_method = 'SEMANTIC_VERIFIER')
    ),
    CONSTRAINT question_run_terminal_shape_check CHECK (
        (result_status IN ('QUEUED', 'RUNNING') AND completed_at IS NULL)
        OR (result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE', 'FAILED', 'CANCELLED') AND completed_at IS NOT NULL)
    ),
    CONSTRAINT question_run_answer_shape_check CHECK (
        (result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE') AND answer_hash IS NOT NULL)
        OR (result_status IN ('QUEUED', 'RUNNING', 'FAILED', 'CANCELLED'))
    )
);

CREATE INDEX question_run_workspace_created
    ON public.question_run (organization_id, workspace_id, created_at DESC, id DESC);

CREATE TABLE public.question_run_retention (
    organization_id text NOT NULL,
    question_run_id text NOT NULL,
    state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'PURGING', 'PURGED')),
    disclosure_allowed boolean NOT NULL DEFAULT true,
    retention_fence bigint NOT NULL DEFAULT 0 CHECK (retention_fence >= 0),
    purge_reason text,
    purge_started_at timestamptz,
    purged_at timestamptz,
    PRIMARY KEY (organization_id, question_run_id),
    CONSTRAINT question_run_retention_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_run_retention_shape_check CHECK (
        (state = 'ACTIVE' AND disclosure_allowed = true AND purge_started_at IS NULL AND purged_at IS NULL)
        OR (state = 'PURGING' AND disclosure_allowed = false AND purge_started_at IS NOT NULL AND purged_at IS NULL)
        OR (state = 'PURGED' AND disclosure_allowed = false AND purge_started_at IS NOT NULL AND purged_at IS NOT NULL)
    )
);

CREATE TABLE public.question_idempotency (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    actor_principal_id text NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 32 AND 256 AND idempotency_key !~ '[[:cntrl:][:space:]]'),
    canonical_request_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(canonical_request_hash)),
    workspace_id text NOT NULL,
    question_run_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, actor_principal_id, idempotency_key),
    CONSTRAINT question_idempotency_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_idempotency_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_idempotency_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id) ON DELETE RESTRICT
);

CREATE TABLE public.question_citation (
    organization_id text NOT NULL,
    id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
    question_run_id text NOT NULL,
    citation_number bigint NOT NULL CHECK (citation_number BETWEEN 1 AND 9007199254740991),
    source_object_id text NOT NULL,
    source_version_id text NOT NULL,
    extraction_id text NOT NULL,
    evidence_fragment_id text NOT NULL,
    cited_excerpt_artifact_id text CHECK (
        cited_excerpt_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(cited_excerpt_artifact_id)
    ),
    source_version_content_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(source_version_content_hash)),
    evidence_text_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(evidence_text_hash)),
    cited_excerpt_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(cited_excerpt_hash)),
    anchor_artifact_id text CHECK (
        anchor_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(anchor_artifact_id)
    ),
    deep_link_artifact_id text CHECK (
        deep_link_artifact_id IS NULL OR app.stage2_opaque_id_is_valid(deep_link_artifact_id)
    ),
    state_at_generation text NOT NULL DEFAULT 'ACTIVE'
        CHECK (state_at_generation IN ('ACTIVE', 'REDACTED', 'PURGED')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    UNIQUE (organization_id, question_run_id, citation_number),
    CONSTRAINT question_citation_run_fk
        FOREIGN KEY (organization_id, question_run_id)
        REFERENCES public.question_run (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_citation_object_fk
        FOREIGN KEY (organization_id, source_object_id)
        REFERENCES public.source_object (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_citation_version_fk
        FOREIGN KEY (organization_id, source_version_id)
        REFERENCES public.source_version (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_citation_extraction_fk
        FOREIGN KEY (organization_id, extraction_id)
        REFERENCES public.source_extraction (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_citation_fragment_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE RESTRICT,
    CONSTRAINT question_citation_excerpt_artifact_fk
        FOREIGN KEY (organization_id, cited_excerpt_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT question_citation_anchor_artifact_fk
        FOREIGN KEY (organization_id, anchor_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT question_citation_deep_link_artifact_fk
        FOREIGN KEY (organization_id, deep_link_artifact_id)
        REFERENCES public.encrypted_artifact (organization_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE OR REPLACE FUNCTION app.question_run_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'question runs are immutable' USING ERRCODE = '55000';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF session_user <> 'knowvault_app'
           OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
           OR NEW.created_by IS DISTINCT FROM app.current_principal_id()
           OR NOT EXISTS (
               SELECT 1 FROM public.workspace_member member
               JOIN public.workspace workspace
                 ON workspace.organization_id = member.organization_id
                AND workspace.id = member.workspace_id
               WHERE member.organization_id = NEW.organization_id
                 AND member.workspace_id = NEW.workspace_id
                 AND member.principal_id = NEW.created_by
                 AND member.removed_at IS NULL
                 AND member.role IN ('OWNER', 'MANAGER', 'MEMBER')
                 AND workspace.status = 'ACTIVE'
           ) THEN
            RAISE EXCEPTION 'question run requires an active workspace asker' USING ERRCODE = '42501';
        END IF;
        IF NEW.result_status NOT IN ('QUEUED', 'RUNNING') THEN
            RAISE EXCEPTION 'question run must start queued or running' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE', 'FAILED', 'CANCELLED') THEN
        RAISE EXCEPTION 'terminal question runs are immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
       OR NEW.workspace_revision IS DISTINCT FROM OLD.workspace_revision
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR (OLD.question_text_artifact_id IS NOT NULL AND NEW.question_text_artifact_id IS DISTINCT FROM OLD.question_text_artifact_id)
       OR NEW.question_hash IS DISTINCT FROM OLD.question_hash
       OR NEW.answer_mode IS DISTINCT FROM OLD.answer_mode
       OR NEW.verification_method IS DISTINCT FROM OLD.verification_method
       OR NEW.started_at IS DISTINCT FROM OLD.started_at
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.workspace_scope_hash IS DISTINCT FROM OLD.workspace_scope_hash
       OR NEW.retrieval_version IS DISTINCT FROM OLD.retrieval_version
       OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
       OR NEW.supersedes_question_run_id IS DISTINCT FROM OLD.supersedes_question_run_id THEN
        RAISE EXCEPTION 'question run identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.result_status = 'QUEUED' AND OLD.result_status <> 'QUEUED' THEN
        RAISE EXCEPTION 'question run status cannot move backwards' USING ERRCODE = '23514';
    END IF;
    IF NEW.result_status = 'RUNNING' AND OLD.result_status NOT IN ('QUEUED', 'RUNNING') THEN
        RAISE EXCEPTION 'question run status cannot move backwards' USING ERRCODE = '23514';
    END IF;
    IF OLD.answer_markdown_artifact_id IS NOT NULL AND NEW.answer_markdown_artifact_id IS DISTINCT FROM OLD.answer_markdown_artifact_id THEN
        RAISE EXCEPTION 'answer markdown artifact is write-once' USING ERRCODE = '55000';
    END IF;
    IF OLD.answer_structured_artifact_id IS NOT NULL AND NEW.answer_structured_artifact_id IS DISTINCT FROM OLD.answer_structured_artifact_id THEN
        RAISE EXCEPTION 'answer structured artifact is write-once' USING ERRCODE = '55000';
    END IF;
    IF OLD.manifest_content_artifact_id IS NOT NULL AND NEW.manifest_content_artifact_id IS DISTINCT FROM OLD.manifest_content_artifact_id THEN
        RAISE EXCEPTION 'manifest artifact is write-once' USING ERRCODE = '55000';
    END IF;
    IF NEW.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE')
       AND (NEW.answer_markdown_artifact_id IS NULL OR NEW.answer_structured_artifact_id IS NULL
            OR NEW.context_pack_hash IS NULL OR NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION 'terminal question run is missing answer artifacts' USING ERRCODE = '23514';
    END IF;
    IF NEW.result_status = 'FAILED' AND (NEW.failure_code IS NULL OR NEW.completed_at IS NULL) THEN
        RAISE EXCEPTION 'failed question run is missing failure state' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_run_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_run
FOR EACH ROW EXECUTE FUNCTION app.question_run_guard();

CREATE OR REPLACE FUNCTION app.question_citation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'question citations are immutable' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.id IS DISTINCT FROM OLD.id
           OR NEW.question_run_id IS DISTINCT FROM OLD.question_run_id
           OR NEW.citation_number IS DISTINCT FROM OLD.citation_number
           OR NEW.source_object_id IS DISTINCT FROM OLD.source_object_id
           OR NEW.source_version_id IS DISTINCT FROM OLD.source_version_id
           OR NEW.extraction_id IS DISTINCT FROM OLD.extraction_id
           OR NEW.evidence_fragment_id IS DISTINCT FROM OLD.evidence_fragment_id
           OR NEW.source_version_content_hash IS DISTINCT FROM OLD.source_version_content_hash
           OR NEW.evidence_text_hash IS DISTINCT FROM OLD.evidence_text_hash
           OR NEW.cited_excerpt_hash IS DISTINCT FROM OLD.cited_excerpt_hash
           OR NEW.state_at_generation IS DISTINCT FROM OLD.state_at_generation
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'question citation identity is immutable' USING ERRCODE = '55000';
        END IF;
        IF OLD.cited_excerpt_artifact_id IS NOT NULL AND NEW.cited_excerpt_artifact_id IS DISTINCT FROM OLD.cited_excerpt_artifact_id THEN
            RAISE EXCEPTION 'citation excerpt artifact is write-once' USING ERRCODE = '55000';
        END IF;
        IF OLD.anchor_artifact_id IS NOT NULL AND NEW.anchor_artifact_id IS DISTINCT FROM OLD.anchor_artifact_id THEN
            RAISE EXCEPTION 'citation anchor artifact is write-once' USING ERRCODE = '55000';
        END IF;
        IF OLD.deep_link_artifact_id IS NOT NULL AND NEW.deep_link_artifact_id IS DISTINCT FROM OLD.deep_link_artifact_id THEN
            RAISE EXCEPTION 'citation link artifact is write-once' USING ERRCODE = '55000';
        END IF;
        RETURN NEW;
    END IF;
    IF session_user <> 'knowvault_app'
       OR NEW.organization_id IS DISTINCT FROM app.current_organization_id()
       OR NOT EXISTS (
           SELECT 1 FROM public.question_run run
           WHERE run.organization_id = NEW.organization_id
             AND run.id = NEW.question_run_id
             AND run.result_status IN ('QUEUED', 'RUNNING')
       ) THEN
        RAISE EXCEPTION 'citation requires an active question run' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER question_citation_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.question_citation
FOR EACH ROW EXECUTE FUNCTION app.question_citation_guard();

CREATE OR REPLACE FUNCTION app.question_run_readable(p_question_run_id text, p_workspace_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.question_run run
        JOIN public.workspace workspace
          ON workspace.organization_id = run.organization_id AND workspace.id = run.workspace_id
        JOIN public.workspace_member member
          ON member.organization_id = run.organization_id AND member.workspace_id = run.workspace_id
         AND member.principal_id = app.current_principal_id() AND member.removed_at IS NULL
        JOIN public.question_run_retention retention
          ON retention.organization_id = run.organization_id AND retention.question_run_id = run.id
        WHERE run.organization_id = app.current_organization_id()
          AND run.id = p_question_run_id
          AND run.workspace_id = p_workspace_id
          AND workspace.status IN ('ACTIVE', 'READ_ONLY', 'ARCHIVED')
          AND retention.state = 'ACTIVE'
          AND retention.disclosure_allowed
          AND NOT EXISTS (
              SELECT 1
              FROM public.question_citation citation
              WHERE citation.organization_id = run.organization_id
                AND citation.question_run_id = run.id
                AND NOT app.evidence_fragment_readable(citation.evidence_fragment_id, run.workspace_id)
          )
    );
$$;

-- The runtime role can see only the tenant's workspace members' rows. Content
-- disclosure still requires the explicit question_run_readable gate above.
ALTER TABLE public.question_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_run FORCE ROW LEVEL SECURITY;
CREATE POLICY question_run_tenant_membership ON public.question_run
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member member
            WHERE member.organization_id = question_run.organization_id
              AND member.workspace_id = question_run.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    )
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.question_run_retention ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_run_retention FORCE ROW LEVEL SECURITY;
CREATE POLICY question_run_retention_tenant ON public.question_run_retention
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

ALTER TABLE public.question_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_idempotency FORCE ROW LEVEL SECURITY;
CREATE POLICY question_idempotency_tenant ON public.question_idempotency
    USING (organization_id = app.current_organization_id() AND actor_principal_id = app.current_principal_id())
    WITH CHECK (organization_id = app.current_organization_id() AND actor_principal_id = app.current_principal_id());

ALTER TABLE public.question_citation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.question_citation FORCE ROW LEVEL SECURITY;
CREATE POLICY question_citation_membership ON public.question_citation
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.question_run run
            JOIN public.workspace_member member
              ON member.organization_id = run.organization_id AND member.workspace_id = run.workspace_id
             AND member.principal_id = app.current_principal_id() AND member.removed_at IS NULL
            WHERE run.organization_id = question_citation.organization_id
              AND run.id = question_citation.question_run_id
        )
    )
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.question_run, public.question_run_retention,
    public.question_idempotency, public.question_citation FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.question_run TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.question_run_retention TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.question_idempotency TO knowvault_app;
GRANT SELECT, INSERT ON TABLE public.question_citation TO knowvault_app;
GRANT EXECUTE ON FUNCTION app.question_run_readable(text, text) TO knowvault_app;

-- Every encrypted owner branch is explicit and uses the same 13-argument
-- SECURITY DEFINER protocol as the existing source/Evidence branches. The
-- question and citation repositories activate only these exact selectors.
DO $$
DECLARE
    branch record;
BEGIN
    FOR branch IN
        SELECT * FROM (VALUES
            ('question_text', 'question_text_artifact_id', 'QUESTION_RUN', 'QUESTION_TEXT', 'question_run'),
            ('answer_markdown', 'answer_markdown_artifact_id', 'QUESTION_RUN', 'ANSWER_MARKDOWN', 'question_run'),
            ('answer_structured', 'answer_structured_artifact_id', 'QUESTION_RUN', 'ANSWER_STRUCTURED', 'question_run'),
            ('manifest_content', 'manifest_content_artifact_id', 'MANIFEST_CONTENT', 'CANONICAL_BYTES', 'question_run'),
            ('cited_excerpt', 'cited_excerpt_artifact_id', 'CITED_EXCERPT', 'EXACT_TEXT', 'question_citation'),
            ('anchor', 'anchor_artifact_id', 'CITATION_ANCHOR', 'CANONICAL_ANCHOR', 'question_citation'),
            ('deep_link', 'deep_link_artifact_id', 'SOURCE_DEEPLINK', 'DEEPLINK', 'question_citation')
        ) AS b(suffix, column_name, resource_type, field_name, owner_table)
    LOOP
        EXECUTE format($f$
            CREATE FUNCTION app.%1$s_bind_%2$s(
                p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
                p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
                p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
                p_aad_hash text, p_plaintext_hash text
            ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
            BEGIN
                IF p_org IS DISTINCT FROM app.current_organization_id() THEN
                    RAISE EXCEPTION 'tenant mismatch' USING ERRCODE = '42501';
                END IF;
                IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
                    RAISE EXCEPTION 'resource id must equal the owning row id' USING ERRCODE = '23514';
                END IF;
                INSERT INTO public.encrypted_artifact (
                    organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
                    cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
                ) VALUES (
                    p_org, p_artifact_id, 'encrypted-artifact-aad-v1', %5$L, %3$L, %4$L, p_resource_id, %6$L,
                    'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
                );
                UPDATE public.%5$I SET %3$I = p_artifact_id
                 WHERE organization_id = p_org AND id = p_owning_row_id AND %3$I IS NULL;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'owning row missing or already bound' USING ERRCODE = '23514';
                END IF;
            END;
            $fn$
        $f$, branch.owner_table, branch.suffix, branch.column_name, branch.resource_type, branch.owner_table, branch.field_name);

        EXECUTE format($f$
            CREATE FUNCTION app.%1$s_read_%2$s(p_owning_row_id text)
            RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
                wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
            LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
                SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
                       a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
                FROM public.%3$I owner_row
                JOIN public.encrypted_artifact a
                  ON a.organization_id = owner_row.organization_id AND a.id = owner_row.%4$I
                WHERE owner_row.organization_id = app.current_organization_id()
                  AND owner_row.id = p_owning_row_id AND a.purged_at IS NULL;
            $fn$
        $f$, branch.owner_table, branch.suffix, branch.owner_table, branch.column_name);
    END LOOP;
END;
$$;

DO $$
DECLARE
    suffix text;
    owner_table text;
BEGIN
    FOREACH suffix IN ARRAY ARRAY['question_text', 'answer_markdown', 'answer_structured', 'manifest_content'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION app.question_run_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.question_run_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app', suffix);
        EXECUTE format('REVOKE ALL ON FUNCTION app.question_run_read_%1$s(text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.question_run_read_%1$s(text) TO knowvault_app', suffix);
    END LOOP;
    FOREACH suffix IN ARRAY ARRAY['cited_excerpt', 'anchor', 'deep_link'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION app.question_citation_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.question_citation_bind_%1$s(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app', suffix);
        EXECUTE format('REVOKE ALL ON FUNCTION app.question_citation_read_%1$s(text) FROM PUBLIC', suffix);
        EXECUTE format('GRANT EXECUTE ON FUNCTION app.question_citation_read_%1$s(text) TO knowvault_app', suffix);
    END LOOP;
    PERFORM owner_table;
END;
$$;

COMMIT;
