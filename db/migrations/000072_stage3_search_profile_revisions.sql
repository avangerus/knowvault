-- 000072: search profile revisions (EMB-1).
--
-- Until now a tenant had exactly one durable retrieval profile row
-- (PRIMARY KEY (organization_id)) whose embedding identity and index
-- generation were immutable for the lifetime of the tenant.  That made the
-- lexical-only bootstrap profile a terminal state: mounting a real embedding
-- channel afterwards could only fail closed, because
-- search.Repository.EnsureMountedProfile found an ACTIVE row for another
-- vector space and had nowhere to put the new one.  An operator's only
-- remaining option was hand-written SQL, which PRODUCT_CONSTITUTION section 7
-- forbids on every surface.
--
-- This migration makes the profile an append-only sequence of revisions:
--   * PRIMARY KEY (organization_id, activation_revision) -- a revision row is
--     still immutable in identity; a new vector space is a NEW row.
--   * at most one ACTIVE and at most one STAGING revision per tenant, enforced
--     by partial unique indexes rather than by application code.
--   * one added terminal status, SUPERSEDED, so the cutover STAGING -> ACTIVE
--     can retire the previous ACTIVE revision. Status transitions stay
--     one-way: STAGING -> ACTIVE | FAILED, ACTIVE -> SUPERSEDED. Nothing
--     leaves FAILED or SUPERSEDED, and a revision is superseded only when a
--     staged successor exists, so a tenant can never be left without a
--     readable profile (fail-closed retrieval is unchanged: no ACTIVE
--     revision still means no answers).
--
-- SRCH-010/SRCH-011 are preserved: query and corpus vectors still belong to
-- one exact embedding profile hash, and the profile hash is still immutable
-- inside a revision. Re-embedding the corpus for a new revision is the
-- explicit, resumable worker pass driven by the staged revision below; the old
-- revision stays readable until its successor is activated.

BEGIN;

-- 1. Append-only revision identity ------------------------------------------
--
-- The old PRIMARY KEY (organization_id) and UNIQUE (organization_id,
-- index_generation) both encode "one profile per tenant". Drop them by
-- catalogue lookup: their generated names are truncated at the identifier
-- limit and are not portable to write out literally.
DO $guard$
DECLARE
    dropped_name text;
BEGIN
    FOR dropped_name IN
        SELECT conname
          FROM pg_catalog.pg_constraint
         WHERE conrelid = 'public.organization_search_profile'::regclass
           AND contype IN ('p', 'u')
    LOOP
        EXECUTE format('ALTER TABLE public.organization_search_profile DROP CONSTRAINT %I', dropped_name);
    END LOOP;
END;
$guard$;

ALTER TABLE public.organization_search_profile
    ADD CONSTRAINT organization_search_profile_pkey
        PRIMARY KEY (organization_id, activation_revision);

ALTER TABLE public.organization_search_profile
    DROP CONSTRAINT IF EXISTS organization_search_profile_status_check,
    DROP CONSTRAINT IF EXISTS organization_search_profile_check;

ALTER TABLE public.organization_search_profile
    ADD CONSTRAINT organization_search_profile_status_check
        CHECK (status IN ('STAGING', 'ACTIVE', 'FAILED', 'SUPERSEDED')),
    ADD CONSTRAINT organization_search_profile_activation_stamp
        CHECK ((status IN ('ACTIVE', 'SUPERSEDED')) = (activated_at IS NOT NULL));

-- Exactly one readable revision and at most one revision being built.
CREATE UNIQUE INDEX organization_search_profile_single_active
    ON public.organization_search_profile (organization_id)
    WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX organization_search_profile_single_staging
    ON public.organization_search_profile (organization_id)
    WHERE status = 'STAGING';
CREATE INDEX organization_search_profile_revision_lookup
    ON public.organization_search_profile (organization_id, activation_revision DESC);

-- 2. Revision-aware state guard ---------------------------------------------
CREATE OR REPLACE FUNCTION app.organization_search_profile_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF session_user = 'knowvault_app'
           OR NOT EXISTS (
               SELECT 1 FROM public.organization
               WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
           ) THEN
            RAISE EXCEPTION 'organization_search_profile deletion requires tenant hard-delete state' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'INSERT' THEN
        -- A STAGING revision is an operator REQUEST: it is never read by any
        -- query and indexes nothing until the worker has rebuilt the corpus
        -- under it, so the runtime role may append one (through
        -- app.stage_search_profile_revision, which is the only surface that
        -- may name a profile identity). Every readable status stays
        -- worker-only, so nothing the runtime can write changes what an
        -- answer is retrieved from.
        IF NEW.status = 'STAGING' THEN
            IF session_user NOT IN ('knowvault_app', 'knowvault_worker') THEN
                RAISE EXCEPTION 'organization_search_profile staging requires a runtime role' USING ERRCODE = '42501';
            END IF;
        ELSIF session_user <> 'knowvault_worker' THEN
            RAISE EXCEPTION 'organization_search_profile creation requires worker role' USING ERRCODE = '42501';
        END IF;
        IF EXISTS (
            SELECT 1 FROM public.organization_search_profile
             WHERE organization_id = NEW.organization_id
               AND activation_revision >= NEW.activation_revision
        ) THEN
            RAISE EXCEPTION 'search profile revisions are append-only' USING ERRCODE = '23514';
        END IF;
        -- The first revision of a tenant is provisioned directly from the
        -- administrator-owned mount. Every later vector space must be staged
        -- and re-indexed before it can serve a query.
        IF NEW.status <> 'STAGING'
           AND EXISTS (
               SELECT 1 FROM public.organization_search_profile
                WHERE organization_id = NEW.organization_id
           ) THEN
            RAISE EXCEPTION 'a later search profile revision must be staged before activation' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF session_user <> 'knowvault_worker'
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.embedding_profile_id IS DISTINCT FROM OLD.embedding_profile_id
       OR NEW.embedding_profile_hash IS DISTINCT FROM OLD.embedding_profile_hash
       OR NEW.index_generation IS DISTINCT FROM OLD.index_generation
       OR NEW.activation_revision IS DISTINCT FROM OLD.activation_revision
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at)
       OR NEW.generation_fence < OLD.generation_fence
       OR NEW.catalog_snapshot_watermark < OLD.catalog_snapshot_watermark
       OR NEW.outbox_applied_sequence < OLD.outbox_applied_sequence THEN
        RAISE EXCEPTION 'organization_search_profile identity or watermarks are immutable/monotonic' USING ERRCODE = '55000';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       AND NOT (
            (OLD.status = 'STAGING' AND NEW.status IN ('ACTIVE', 'FAILED'))
         OR (OLD.status = 'ACTIVE' AND NEW.status = 'SUPERSEDED')
       ) THEN
        RAISE EXCEPTION 'organization_search_profile status does not reverse' USING ERRCODE = '23514';
    END IF;
    IF NEW.status IN ('ACTIVE', 'SUPERSEDED') AND NEW.activated_at IS NULL THEN
        RAISE EXCEPTION 'active search profile requires activation timestamp' USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'ACTIVE' AND NEW.status = 'SUPERSEDED'
       AND NOT EXISTS (
           SELECT 1 FROM public.organization_search_profile
            WHERE organization_id = OLD.organization_id
              AND status = 'STAGING'
              AND activation_revision > OLD.activation_revision
       ) THEN
        RAISE EXCEPTION 'a search profile revision is superseded only by a staged successor' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;


-- 3. The one typed operator command ------------------------------------------
--
-- app.stage_search_profile_revision is the only surface on which a profile
-- identity may be named. It is SECURITY DEFINER so the runtime never needs a
-- direct write grant on the revision table, and it is idempotent by
-- construction: an identical staged revision, or an active revision that
-- already names the requested profile, is returned instead of appending a
-- second one. The worker that mounts the same profile picks the staged
-- revision up on its next poll tick, re-indexes the corpus and performs the
-- cutover; a staged revision whose identity does not match the worker mount is
-- left untouched, so a drifted runtime can never move a tenant onto a vector
-- space no indexer owns.
CREATE OR REPLACE FUNCTION app.stage_search_profile_revision(
    p_profile_id text,
    p_profile_hash text,
    p_generation bigint,
    p_generation_fence bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $stage$
DECLARE
    organization_value text;
    staged_revision bigint;
    staged_profile_id text;
    staged_profile_hash text;
    active_revision bigint;
    active_profile_id text;
    active_profile_hash text;
    active_generation bigint;
    active_fence bigint;
    next_revision bigint;
BEGIN
    IF session_user NOT IN ('knowvault_app', 'knowvault_worker') THEN
        RAISE EXCEPTION 'search profile revision requires a runtime role' USING ERRCODE = '42501';
    END IF;
    organization_value := app.current_organization_id();
    IF organization_value IS NULL THEN
        RAISE EXCEPTION 'search profile revision requires a tenant context' USING ERRCODE = '42501';
    END IF;
    IF NOT app.stage2_opaque_id_is_valid(p_profile_id)
       OR NOT app.stage2_sha256_is_valid(p_profile_hash)
       OR p_generation IS NULL OR p_generation < 1 OR p_generation > 9007199254740991
       OR p_generation_fence IS NULL OR p_generation_fence < 1 OR p_generation_fence > 9007199254740991 THEN
        RAISE EXCEPTION 'search profile revision identity is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.organization
     WHERE id = organization_value AND status = 'ACTIVE'
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search profile revision requires an active tenant' USING ERRCODE = '55000';
    END IF;

    SELECT activation_revision, embedding_profile_id, embedding_profile_hash
      INTO staged_revision, staged_profile_id, staged_profile_hash
      FROM public.organization_search_profile
     WHERE organization_id = organization_value AND status = 'STAGING'
     FOR UPDATE;
    IF FOUND THEN
        IF staged_profile_id IS DISTINCT FROM p_profile_id
           OR staged_profile_hash IS DISTINCT FROM p_profile_hash THEN
            RAISE EXCEPTION 'another search profile revision is already staged' USING ERRCODE = '23514';
        END IF;
        RETURN staged_revision;
    END IF;

    SELECT activation_revision, embedding_profile_id, embedding_profile_hash,
           index_generation, generation_fence
      INTO active_revision, active_profile_id, active_profile_hash,
           active_generation, active_fence
      FROM public.organization_search_profile
     WHERE organization_id = organization_value AND status = 'ACTIVE'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'search profile revision requires an active revision' USING ERRCODE = '55000';
    END IF;
    IF active_generation <> p_generation OR active_fence <> p_generation_fence THEN
        RAISE EXCEPTION 'search profile revision generation does not match the mounted index' USING ERRCODE = '23514';
    END IF;
    IF active_profile_id IS NOT DISTINCT FROM p_profile_id
       AND active_profile_hash IS NOT DISTINCT FROM p_profile_hash THEN
        RETURN active_revision;
    END IF;

    SELECT coalesce(max(activation_revision), 0) + 1 INTO next_revision
      FROM public.organization_search_profile
     WHERE organization_id = organization_value;
    INSERT INTO public.organization_search_profile
        (organization_id, embedding_profile_id, embedding_profile_hash,
         index_generation, activation_revision, generation_fence,
         catalog_snapshot_watermark, outbox_applied_sequence, status)
    VALUES (organization_value, p_profile_id, p_profile_hash, p_generation,
            next_revision, p_generation_fence, 0, 0, 'STAGING');
    RETURN next_revision;
END;
$stage$;

REVOKE ALL ON FUNCTION app.stage_search_profile_revision(text, text, bigint, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.stage_search_profile_revision(text, text, bigint, bigint)
    TO knowvault_app, knowvault_worker;

-- 4. Audit resource vocabulary ------------------------------------------------
--
-- public.audit_event.resource_type is a closed CHECK list, and two contracts
-- that already exist in Go were never added to it:
--
--   * GOVERNED_QUERY_ATTEMPT (ADR-0089 §4, migration 000069 added only the
--     metadata vocabulary). Every governed model-authored SQL attempt appends
--     its audit event inside the same transaction as the attempt itself, so
--     the missing value did not merely lose the journal entry -- it rolled the
--     whole attempt back, which is what made :ask fail intermittently and its
--     audit assertion fail always.
--   * SEARCH_PROFILE, the EMB-1 vocabulary added above.
--
-- The list stays closed: this adds exactly the two reserved values and nothing
-- else, so an unknown resource type is still rejected by the database.
ALTER TABLE public.audit_event
    DROP CONSTRAINT audit_event_resource_type_check,
    ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
        'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
        'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
        'SOURCE_CONNECTION', 'SOURCE_SCOPE', 'SOURCE_OBJECT',
        'CONVERSATION', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
        'SIGNING_KEY', 'AUDIT_CHECKPOINT', 'CRYPTO_KEY', 'ANSWER_DOCUMENT',
        'GOVERNED_QUERY_ATTEMPT', 'SEARCH_PROFILE'
    ));

COMMIT;
