-- Stage 2 workspace-managed confirmation authority foundation (ADR-0052).
--
-- This checkpoint is strictly an inert persistence foundation. It creates no
-- runtime write authority: knowvault_app receives SELECT only on every table
-- introduced here. No API, repository command, receipt, audit event, outbox
-- event, activation, connector job, ingestion, retrieval or search authority
-- is introduced. A confirmation row alone activates nothing.
--
-- Canonical hash boundary: this checkpoint does not implement a second,
-- self-made JCS engine inside PostgreSQL. Every *_hash column here is a
-- closed relational projection plus a SHA-256 *format* check and an exact
-- child-to-parent hash foreign key; PostgreSQL never recomputes a JCS byte
-- form from typed fields. Exact field-to-JCS-hash validation remains a
-- mandatory gate of the next Go authority-command checkpoint, which must
-- recompute the canonical bytes/hash in Go, hold a fresh idempotent command
-- receipt, and append a matching audit event in the same transaction before
-- any authority row is ever inserted by application code. Until that
-- checkpoint lands, knowvault_app has SELECT only on every table below, and
-- issuing INSERT here without JCS validation, a receipt and an audit event is
-- forbidden. This migration performs its own bootstrap inserts (the seeded
-- warning contract row) only because it runs as the trusted migration owner,
-- never as knowvault_app.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Canonical authority timestamps (authority-timestamp-v1).
-- ---------------------------------------------------------------------------

-- Exactly `YYYY-MM-DDTHH:MM:SSZ`: four digit year, mandatory seconds, no
-- fractional seconds, no leap second (seconds bounded 00-59), no offset other
-- than the literal `Z`. Calendar validity (e.g. rejecting 02-30) is checked by
-- the timestamptz cast below, which also rejects any value the regex missed.
CREATE OR REPLACE FUNCTION app.authority_timestamp_v1_is_valid(value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    parsed timestamptz;
    serialized text;
BEGIN
    IF value IS NULL OR value !~ (
        '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])' ||
        'T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
    ) THEN
        RETURN false;
    END IF;
    BEGIN
        parsed := value::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    -- Parse/UTC-serialize round trip must reproduce the exact same bytes.
    serialized := to_char(parsed AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
    RETURN serialized = value;
END;
$$;

-- Returns NULL for any value that is not an exact authority-timestamp-v1
-- string, so callers can compare epoch seconds without ever raising on a
-- malformed value (format is independently rejected by column CHECKs).
CREATE OR REPLACE FUNCTION app.authority_timestamp_v1_to_epoch(value text)
RETURNS bigint
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN value IS NULL OR NOT app.authority_timestamp_v1_is_valid(value) THEN NULL
        ELSE extract(epoch FROM value::timestamptz)::bigint
    END;
$$;

CREATE OR REPLACE FUNCTION app.authority_transaction_epoch()
RETURNS bigint
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT extract(epoch FROM date_trunc('second', transaction_timestamp()))::bigint;
$$;

-- ---------------------------------------------------------------------------
-- 2. Policy revision bridge.
-- ---------------------------------------------------------------------------

-- organization.policy_revision is the monotonic safe-integer ordinal counter.
-- This bounds it to the same closed JCS-safe integer range as every other
-- canonical numeric field; it does not change any existing organization row,
-- since the Stage 1 default and every seeded test value is already 1.
ALTER TABLE public.organization
    ADD CONSTRAINT organization_policy_revision_safe_integer
    CHECK (policy_revision BETWEEN 1 AND 9007199254740991);

CREATE TABLE public.organization_policy_revision (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    policy_revision_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_revision_id)),
    policy_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(policy_hash)),
    activated_at text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(activated_at)),
    activated_by text NOT NULL,
    PRIMARY KEY (organization_id, revision),
    UNIQUE (organization_id, policy_revision_id),
    UNIQUE (organization_id, policy_hash),
    UNIQUE (organization_id, revision, policy_revision_id),
    CONSTRAINT organization_policy_revision_actor_fk
        FOREIGN KEY (organization_id, activated_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT
);

-- Append-only monotonic ordinal. The accepted contract requires monotonic
-- order only; it never promises a contiguous "previous + 1" sequence, so gaps
-- (e.g. registering revision 7 straight after revision 1) are allowed. The
-- very first registered row for an organization must match the existing
-- numeric organization.policy_revision counter exactly; nothing is ever
-- synthesized from it. Every following row must be strictly greater than the
-- current maximum: no repeat, no decrease, no insertion below the max.
CREATE OR REPLACE FUNCTION app.organization_policy_revision_sequence_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    existing_max bigint;
    current_counter bigint;
BEGIN
    SELECT max(revision) INTO existing_max
    FROM public.organization_policy_revision
    WHERE organization_id = NEW.organization_id;

    IF existing_max IS NULL THEN
        SELECT policy_revision INTO current_counter
        FROM public.organization
        WHERE id = NEW.organization_id;
        IF NOT FOUND OR NEW.revision <> current_counter THEN
            RAISE EXCEPTION 'first organization policy registry row must equal the current policy counter'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.revision <= existing_max THEN
        RAISE EXCEPTION 'organization policy registry ordinal must strictly increase'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_policy_revision_sequence_exact
BEFORE INSERT ON public.organization_policy_revision
FOR EACH ROW EXECUTE FUNCTION app.organization_policy_revision_sequence_guard();

CREATE TRIGGER organization_policy_revision_immutable
BEFORE UPDATE OR DELETE ON public.organization_policy_revision
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

-- knowvault_app can never change organization.policy_revision; any other actor
-- (migration/policy owner) may only advance it (never decrease it) to an
-- already-registered exact registry revision. No implicit padding/formatting
-- of the number into an ID ever happens here.
CREATE OR REPLACE FUNCTION app.organization_policy_revision_change_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.policy_revision IS DISTINCT FROM OLD.policy_revision THEN
        IF session_user = 'knowvault_app' THEN
            RAISE EXCEPTION 'runtime role cannot change organization policy revision'
                USING ERRCODE = '55000';
        END IF;
        IF NEW.policy_revision < OLD.policy_revision THEN
            RAISE EXCEPTION 'organization policy revision cannot decrease'
                USING ERRCODE = '55000';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM public.organization_policy_revision
            WHERE organization_id = NEW.id AND revision = NEW.policy_revision
        ) THEN
            RAISE EXCEPTION 'organization policy revision must match an existing registry revision'
                USING ERRCODE = '23503';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER organization_policy_revision_change_exact
BEFORE UPDATE ON public.organization
FOR EACH ROW EXECUTE FUNCTION app.organization_policy_revision_change_guard();

ALTER TABLE public.organization_policy_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_policy_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_policy_revision_tenant_isolation ON public.organization_policy_revision
    USING (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.organization_policy_revision FROM PUBLIC;
GRANT SELECT ON TABLE public.organization_policy_revision TO knowvault_app;

-- One closed insert guard shared by every authority relation that carries a
-- policy_revision_number: the value must exact-match organization.policy_
-- revision at the moment of INSERT. This is deliberately independent of what
-- policy a *parent* row referenced: a stale confirmation or grant may still
-- be revoked (the revocation's own parent FK may point at an old registry
-- row), but the revocation row's own policy provenance must always be
-- current. The opaque policy_revision_id itself continues to be validated by
-- the composite FK into organization_policy_revision.
CREATE OR REPLACE FUNCTION app.authority_current_policy_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_policy bigint;
BEGIN
    SELECT policy_revision INTO current_policy
    FROM public.organization
    WHERE id = NEW.organization_id;
    IF NOT FOUND OR current_policy <> NEW.policy_revision_number THEN
        RAISE EXCEPTION '% requires the current organization policy revision', TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Protected warning registry.
-- ---------------------------------------------------------------------------

CREATE TABLE public.workspace_managed_warning_contract (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    schema_version text NOT NULL CHECK (
        char_length(schema_version) BETWEEN 1 AND 128
    ),
    warning_version text NOT NULL CHECK (
        char_length(warning_version) BETWEEN 1 AND 128
    ),
    access_mode text NOT NULL CHECK (access_mode = 'WORKSPACE_MANAGED'),
    risk_codes_json jsonb NOT NULL,
    acknowledgement_code text NOT NULL CHECK (
        char_length(acknowledgement_code) BETWEEN 1 AND 256
    ),
    canonical_bytes bytea NOT NULL,
    warning_contract_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(warning_contract_hash)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (warning_version, warning_contract_hash),
    CHECK (warning_contract_hash = 'sha256:' || encode(sha256(canonical_bytes), 'hex')),
    CHECK (
        revision <> 1
        OR (
            warning_contract_hash = 'sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d'
            AND schema_version = 'workspace-managed-warning-contract-v1'
            AND warning_version = 'workspace-managed-risk-v1'
            AND acknowledgement_code = 'WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL'
        )
    )
);

INSERT INTO public.workspace_managed_warning_contract (
    revision, schema_version, warning_version, access_mode, risk_codes_json,
    acknowledgement_code, canonical_bytes, warning_contract_hash
) VALUES (
    1, 'workspace-managed-warning-contract-v1', 'workspace-managed-risk-v1', 'WORKSPACE_MANAGED',
    '["SOURCE_NATIVE_ACL_NOT_ENFORCED","WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"]'::jsonb,
    'WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL',
    convert_to(
        '{"access_mode":"WORKSPACE_MANAGED","acknowledgement_code":"WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",' ||
        '"risk_codes":["SOURCE_NATIVE_ACL_NOT_ENFORCED","WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"],' ||
        '"schema_version":"workspace-managed-warning-contract-v1","warning_version":"workspace-managed-risk-v1"}',
        'UTF8'
    ),
    'sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d'
);

DO $$
DECLARE
    computed_hash text;
BEGIN
    SELECT 'sha256:' || encode(sha256(canonical_bytes), 'hex') INTO computed_hash
    FROM public.workspace_managed_warning_contract WHERE revision = 1;
    IF computed_hash <> 'sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d' THEN
        RAISE EXCEPTION 'workspace managed warning contract v1 canonical bytes hash mismatch: %', computed_hash;
    END IF;
END;
$$;

-- Absolutely immutable after seed. A future migration introducing v2 would
-- need to explicitly drop and recreate this trigger; this checkpoint never
-- allows it implicitly.
CREATE OR REPLACE FUNCTION app.workspace_managed_warning_contract_immutable_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'workspace managed warning contract registry is immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER workspace_managed_warning_contract_immutable
BEFORE INSERT OR UPDATE OR DELETE ON public.workspace_managed_warning_contract
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_warning_contract_immutable_guard();

-- Current warning is defined as the registry row with the maximum revision.
-- STABLE (not IMMUTABLE): a future privileged migration may register a higher
-- revision, so the result is not fixed for the lifetime of the database, only
-- within one statement/transaction.
CREATE OR REPLACE FUNCTION app.workspace_managed_warning_contract_current_revision()
RETURNS bigint
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $$
    SELECT max(revision) FROM public.workspace_managed_warning_contract;
$$;

REVOKE ALL ON TABLE public.workspace_managed_warning_contract FROM PUBLIC;
GRANT SELECT ON TABLE public.workspace_managed_warning_contract TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4A. Workspace source confirmation actor grant.
-- ---------------------------------------------------------------------------

-- grant_id/confirmation_id/revocation_id are opaque IDs per ADR-0052 and the
-- canonical fixtures (e.g. "confirm-grant-admin", "wmc_projects_3"): they are
-- explicitly NOT part of the source connection/scope/binding ULID-shaped
-- generated-ID contract, so every authority ID column below uses the general
-- opaque-ID validator rather than app.source_generated_id_is_valid. A future
-- repository may still choose to generate stricter server IDs; this
-- persistence contract must not silently narrow the canonical schema.
CREATE TABLE public.workspace_source_confirmation_actor_grant (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    grant_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(grant_id)),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    workspace_id text NOT NULL,
    principal_id text NOT NULL,
    permission text NOT NULL CHECK (permission = 'workspace.source.confirm'),
    valid_from text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(valid_from)),
    valid_until text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(valid_until)),
    policy_revision_number bigint NOT NULL CHECK (policy_revision_number BETWEEN 1 AND 9007199254740991),
    policy_revision text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_revision)),
    grant_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(grant_hash)),
    granted_by text NOT NULL,
    granted_at text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(granted_at)),
    PRIMARY KEY (organization_id, grant_id, revision),
    UNIQUE (organization_id, grant_id, revision, grant_hash),
    UNIQUE (
        organization_id, workspace_id, grant_id, revision, grant_hash,
        principal_id, policy_revision_number, policy_revision
    ),
    CONSTRAINT workspace_source_confirmation_actor_grant_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_confirmation_actor_grant_principal_fk
        FOREIGN KEY (organization_id, principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_confirmation_actor_grant_granted_by_fk
        FOREIGN KEY (organization_id, granted_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_confirmation_actor_grant_policy_fk
        FOREIGN KEY (organization_id, policy_revision_number, policy_revision)
        REFERENCES public.organization_policy_revision (organization_id, revision, policy_revision_id)
        ON DELETE RESTRICT,
    CHECK (
        app.authority_timestamp_v1_to_epoch(granted_at) IS NOT NULL
        AND app.authority_timestamp_v1_to_epoch(valid_from) IS NOT NULL
        AND app.authority_timestamp_v1_to_epoch(valid_until) IS NOT NULL
        AND app.authority_timestamp_v1_to_epoch(granted_at) <= app.authority_timestamp_v1_to_epoch(valid_from)
        AND app.authority_timestamp_v1_to_epoch(valid_from) < app.authority_timestamp_v1_to_epoch(valid_until)
    )
);

CREATE OR REPLACE FUNCTION app.workspace_source_confirmation_actor_grant_temporal_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF app.authority_timestamp_v1_to_epoch(NEW.granted_at) > app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'workspace source confirmation actor grant cannot be granted in the future'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_source_confirmation_actor_grant_temporal_exact
BEFORE INSERT ON public.workspace_source_confirmation_actor_grant
FOR EACH ROW EXECUTE FUNCTION app.workspace_source_confirmation_actor_grant_temporal_guard();

CREATE TRIGGER workspace_source_confirmation_actor_grant_current_policy_exact
BEFORE INSERT ON public.workspace_source_confirmation_actor_grant
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();

CREATE TRIGGER workspace_source_confirmation_actor_grant_immutable
BEFORE UPDATE OR DELETE ON public.workspace_source_confirmation_actor_grant
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.workspace_source_confirmation_actor_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_source_confirmation_actor_grant FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_source_confirmation_actor_grant_tenant_isolation
    ON public.workspace_source_confirmation_actor_grant
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_source_confirmation_actor_grant.organization_id
              AND member.workspace_id = workspace_source_confirmation_actor_grant.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );

REVOKE ALL ON TABLE public.workspace_source_confirmation_actor_grant FROM PUBLIC;
GRANT SELECT ON TABLE public.workspace_source_confirmation_actor_grant TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4B. Workspace source confirmation actor grant revocation.
-- ---------------------------------------------------------------------------

CREATE TABLE public.workspace_source_confirmation_actor_grant_revocation (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    revocation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(revocation_id)),
    confirmation_actor_grant_revocation_hash text NOT NULL CHECK (
        app.stage2_sha256_is_valid(confirmation_actor_grant_revocation_hash)
    ),
    grant_id text NOT NULL,
    grant_revision bigint NOT NULL CHECK (grant_revision BETWEEN 1 AND 9007199254740991),
    grant_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(grant_hash)),
    revoked_by text NOT NULL,
    revoked_at text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(revoked_at)),
    reason_code text NOT NULL CHECK (reason_code = 'AUTHORITY_REVOKED'),
    policy_revision_number bigint NOT NULL CHECK (policy_revision_number BETWEEN 1 AND 9007199254740991),
    policy_revision text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_revision)),
    PRIMARY KEY (organization_id, revocation_id),
    UNIQUE (organization_id, revocation_id, confirmation_actor_grant_revocation_hash),
    UNIQUE (organization_id, grant_id, grant_revision),
    CONSTRAINT workspace_source_confirmation_actor_grant_revocation_grant_fk
        FOREIGN KEY (organization_id, grant_id, grant_revision, grant_hash)
        REFERENCES public.workspace_source_confirmation_actor_grant (organization_id, grant_id, revision, grant_hash)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_confirmation_actor_grant_revocation_actor_fk
        FOREIGN KEY (organization_id, revoked_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_confirmation_actor_grant_revocation_policy_fk
        FOREIGN KEY (organization_id, policy_revision_number, policy_revision)
        REFERENCES public.organization_policy_revision (organization_id, revision, policy_revision_id)
        ON DELETE RESTRICT
);

-- Serializes with every other confirmation/revocation/source command on the
-- same workspace row: the exact parent grant tells us the workspace, and the
-- FOR UPDATE lock is held before the revocation is validated or inserted, so
-- a concurrent confirmation attempt against the same grant/tuple cannot race
-- past this revocation (or vice versa).
CREATE OR REPLACE FUNCTION app.actor_grant_revocation_temporal_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    parent_granted_at text;
    parent_workspace_id text;
    locked_workspace_id text;
    revoked_epoch bigint;
BEGIN
    SELECT granted_at, workspace_id INTO parent_granted_at, parent_workspace_id
    FROM public.workspace_source_confirmation_actor_grant
    WHERE organization_id = NEW.organization_id
      AND grant_id = NEW.grant_id
      AND revision = NEW.grant_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace source confirmation actor grant revocation lacks its exact grant'
            USING ERRCODE = '23503';
    END IF;

    SELECT id INTO locked_workspace_id
    FROM public.workspace
    WHERE organization_id = NEW.organization_id AND id = parent_workspace_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace source confirmation actor grant revocation lacks its exact parent workspace'
            USING ERRCODE = '23503';
    END IF;

    revoked_epoch := app.authority_timestamp_v1_to_epoch(NEW.revoked_at);
    IF revoked_epoch IS NULL
       OR revoked_epoch < app.authority_timestamp_v1_to_epoch(parent_granted_at)
       OR revoked_epoch > app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'workspace source confirmation actor grant revocation has an invalid revoked_at'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER actor_grant_revocation_temporal_exact
BEFORE INSERT ON public.workspace_source_confirmation_actor_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.actor_grant_revocation_temporal_guard();

CREATE TRIGGER workspace_source_confirmation_actor_grant_revocation_current_policy_exact
BEFORE INSERT ON public.workspace_source_confirmation_actor_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();

CREATE TRIGGER workspace_source_confirmation_actor_grant_revocation_immutable
BEFORE UPDATE OR DELETE ON public.workspace_source_confirmation_actor_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.workspace_source_confirmation_actor_grant_revocation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_source_confirmation_actor_grant_revocation FORCE ROW LEVEL SECURITY;
CREATE POLICY actor_grant_revocation_tenant_isolation
    ON public.workspace_source_confirmation_actor_grant_revocation
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1
            FROM public.workspace_source_confirmation_actor_grant AS grant_row
            JOIN public.workspace_member AS member
              ON member.organization_id = grant_row.organization_id
             AND member.workspace_id = grant_row.workspace_id
             AND member.principal_id = app.current_principal_id()
             AND member.removed_at IS NULL
            WHERE grant_row.organization_id = workspace_source_confirmation_actor_grant_revocation.organization_id
              AND grant_row.grant_id = workspace_source_confirmation_actor_grant_revocation.grant_id
              AND grant_row.revision = workspace_source_confirmation_actor_grant_revocation.grant_revision
        )
    );

REVOKE ALL ON TABLE public.workspace_source_confirmation_actor_grant_revocation FROM PUBLIC;
GRANT SELECT ON TABLE public.workspace_source_confirmation_actor_grant_revocation TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4C. Workspace managed grant confirmation.
-- ---------------------------------------------------------------------------

-- Needed as the exact composite FK parent key for the confirmed target
-- binding: organization, workspace, workspace revision, workspace
-- configuration hash, workspace_source binding ID, source scope ID/revision/
-- hash and access mode. This UNIQUE constraint does *not* itself pin
-- enabled=true — "currently enabled" is not part of any static uniqueness
-- key here. Whether the matched row is enabled is checked dynamically, at
-- INSERT time, by the exact_guard trigger below (and re-checked by the
-- derived-live validator), never baked into this constraint. Semantics of
-- workspace_revision_source are otherwise untouched; only this additional
-- unique constraint is added.
ALTER TABLE public.workspace_revision_source
    ADD CONSTRAINT workspace_revision_source_exact_confirmation_target_key
    UNIQUE (
        organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
        workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode
    );

CREATE TABLE public.workspace_managed_grant_confirmation (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    confirmation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(confirmation_id)),
    confirmation_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(confirmation_hash)),
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    workspace_configuration_hash text NOT NULL CHECK (app.workspace_command_hash_is_valid(workspace_configuration_hash)),
    workspace_source_id text NOT NULL,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    scope_config_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(scope_config_hash)),
    access_mode text NOT NULL CHECK (access_mode = 'WORKSPACE_MANAGED'),
    confirmation_actor_grant_id text NOT NULL,
    confirmation_actor_grant_revision bigint NOT NULL CHECK (confirmation_actor_grant_revision BETWEEN 1 AND 9007199254740991),
    confirmation_actor_grant_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(confirmation_actor_grant_hash)),
    warning_version text NOT NULL CHECK (warning_version = 'workspace-managed-risk-v1'),
    warning_contract_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(warning_contract_hash)),
    acknowledgement_code text NOT NULL CHECK (
        acknowledgement_code = 'WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL'
    ),
    confirmed_by text NOT NULL,
    confirmed_at text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(confirmed_at)),
    policy_revision_number bigint NOT NULL CHECK (policy_revision_number BETWEEN 1 AND 9007199254740991),
    policy_revision text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_revision)),
    PRIMARY KEY (organization_id, confirmation_id),
    UNIQUE (organization_id, confirmation_id, confirmation_hash),
    UNIQUE (organization_id, confirmation_hash),
    CONSTRAINT workspace_managed_grant_confirmation_workspace_snapshot_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_revision, workspace_configuration_hash)
        REFERENCES public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workspace_managed_grant_confirmation_binding_fk
        FOREIGN KEY (organization_id, workspace_id, workspace_source_id, source_scope_id)
        REFERENCES public.workspace_source (organization_id, workspace_id, id, source_scope_id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_grant_confirmation_scope_revision_fk
        FOREIGN KEY (organization_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode)
        REFERENCES public.source_scope_revision (organization_id, source_scope_id, revision, scope_config_hash, access_mode)
        ON DELETE RESTRICT,
    -- Exact target binding: organization, workspace, workspace revision,
    -- workspace configuration hash, workspace_source binding, source scope
    -- ID/revision/hash and access mode must all agree with one exact
    -- workspace_revision_source row. enabled=true is intentionally excluded
    -- from this FK (see the comment above the UNIQUE parent key) and is
    -- re-checked dynamically by the exact_guard trigger below.
    CONSTRAINT workspace_managed_grant_confirmation_target_fk
        FOREIGN KEY (
            organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
            workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode
        )
        REFERENCES public.workspace_revision_source (
            organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
            workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode
        )
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_grant_confirmation_grant_fk
        FOREIGN KEY (
            organization_id, workspace_id, confirmation_actor_grant_id,
            confirmation_actor_grant_revision, confirmation_actor_grant_hash,
            confirmed_by, policy_revision_number, policy_revision
        )
        REFERENCES public.workspace_source_confirmation_actor_grant (
            organization_id, workspace_id, grant_id, revision, grant_hash,
            principal_id, policy_revision_number, policy_revision
        )
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_grant_confirmation_policy_fk
        FOREIGN KEY (organization_id, policy_revision_number, policy_revision)
        REFERENCES public.organization_policy_revision (organization_id, revision, policy_revision_id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_grant_confirmation_warning_fk
        FOREIGN KEY (warning_version, warning_contract_hash)
        REFERENCES public.workspace_managed_warning_contract (warning_version, warning_contract_hash)
        ON DELETE RESTRICT
);

-- Re-validates every dynamic ("current") invariant that cannot be expressed as
-- a plain FK: current workspace revision, current warning registry revision
-- (the warning FK alone only proves the referenced row exists *historically*,
-- not that it is still the current one), the target binding's
-- enabled/WORKSPACE_MANAGED state, the actor grant's validity window against
-- both confirmed_at *and* the live server transaction second (so an expired
-- or not-yet-started grant can never be used to backdate a new confirmation
-- into its historical window), the grant not being revoked, and confirmed_at
-- not being in the future. The organization's current-policy invariant is
-- enforced by the one shared app.authority_current_policy_guard() BEFORE
-- INSERT trigger installed below, not duplicated here.
CREATE OR REPLACE FUNCTION app.workspace_managed_grant_confirmation_exact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    grant_row public.workspace_source_confirmation_actor_grant%ROWTYPE;
    binding_row public.workspace_revision_source%ROWTYPE;
    workspace_current_revision bigint;
    confirmed_at_epoch bigint;
    now_epoch bigint;
BEGIN
    now_epoch := app.authority_transaction_epoch();
    confirmed_at_epoch := app.authority_timestamp_v1_to_epoch(NEW.confirmed_at);
    IF confirmed_at_epoch IS NULL OR confirmed_at_epoch > now_epoch THEN
        RAISE EXCEPTION 'workspace managed confirmation confirmed_at is not a valid past authority timestamp'
            USING ERRCODE = '23514';
    END IF;

    SELECT current_revision INTO workspace_current_revision
    FROM public.workspace
    WHERE organization_id = NEW.organization_id AND id = NEW.workspace_id;
    IF NOT FOUND OR workspace_current_revision <> NEW.workspace_revision THEN
        RAISE EXCEPTION 'workspace managed confirmation requires the current workspace revision'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO binding_row
    FROM public.workspace_revision_source
    WHERE organization_id = NEW.organization_id
      AND workspace_id = NEW.workspace_id
      AND workspace_revision = NEW.workspace_revision
      AND workspace_source_id = NEW.workspace_source_id;
    IF NOT FOUND OR NOT binding_row.enabled OR binding_row.access_mode <> 'WORKSPACE_MANAGED' THEN
        RAISE EXCEPTION 'workspace managed confirmation target binding must be enabled and workspace managed'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.workspace_managed_warning_contract
        WHERE revision = app.workspace_managed_warning_contract_current_revision()
          AND warning_version = NEW.warning_version
          AND warning_contract_hash = NEW.warning_contract_hash
    ) THEN
        RAISE EXCEPTION 'workspace managed confirmation warning is not the current registry revision'
            USING ERRCODE = '23514';
    END IF;

    SELECT * INTO grant_row
    FROM public.workspace_source_confirmation_actor_grant
    WHERE organization_id = NEW.organization_id
      AND grant_id = NEW.confirmation_actor_grant_id
      AND revision = NEW.confirmation_actor_grant_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace managed confirmation lacks its exact actor grant'
            USING ERRCODE = '23503';
    END IF;
    -- Both the historical confirmed_at *and* the live server transaction
    -- second must fall inside the grant's [valid_from, valid_until) window.
    -- Without the second condition, an expired or not-yet-started grant
    -- could still be used to mint a brand new confirmation dated with a
    -- backdated confirmed_at inside its old window; grant expiry must be a
    -- real fail-closed gate on new confirmations, not just a historical
    -- provenance field.
    IF app.authority_timestamp_v1_to_epoch(grant_row.granted_at) > app.authority_timestamp_v1_to_epoch(grant_row.valid_from)
       OR app.authority_timestamp_v1_to_epoch(grant_row.valid_from) > confirmed_at_epoch
       OR confirmed_at_epoch >= app.authority_timestamp_v1_to_epoch(grant_row.valid_until)
       OR now_epoch < app.authority_timestamp_v1_to_epoch(grant_row.valid_from)
       OR now_epoch >= app.authority_timestamp_v1_to_epoch(grant_row.valid_until) THEN
        RAISE EXCEPTION 'workspace managed confirmation violates its actor grant validity window'
            USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation
        WHERE organization_id = NEW.organization_id
          AND grant_id = NEW.confirmation_actor_grant_id
          AND grant_revision = NEW.confirmation_actor_grant_revision
    ) THEN
        RAISE EXCEPTION 'workspace managed confirmation actor grant is revoked'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_managed_grant_confirmation_exact_guard
AFTER INSERT ON public.workspace_managed_grant_confirmation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_grant_confirmation_exact_guard();

-- Deferred concurrency validator: at most one derived-live confirmation may
-- exist for one exact organization/workspace/revision/configuration-hash,
-- binding, scope ID/revision/hash, access mode, policy and warning tuple.
-- Serializes under the workspace row lock so two concurrent grants cannot
-- both commit an ambiguous live join; every field of the derived-live tuple
-- is matched explicitly below (never implied only by workspace_source_id),
-- the target binding's enabled/access_mode is re-joined dynamically, the
-- warning contract is re-joined to prove it is still the current registry
-- row, and both revocation relations are considered.
CREATE OR REPLACE FUNCTION app.workspace_managed_grant_confirmation_derived_live_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    locked_workspace_id text;
    current_workspace_revision bigint;
    live_count bigint;
BEGIN
    SELECT id, current_revision INTO locked_workspace_id, current_workspace_revision
    FROM public.workspace
    WHERE organization_id = NEW.organization_id AND id = NEW.workspace_id
    FOR UPDATE;

    IF current_workspace_revision IS DISTINCT FROM NEW.workspace_revision THEN
        RETURN NULL;
    END IF;

    SELECT count(*) INTO live_count
    FROM public.workspace_managed_grant_confirmation AS confirmation
    JOIN public.workspace_revision_source AS binding
      ON binding.organization_id = confirmation.organization_id
     AND binding.workspace_id = confirmation.workspace_id
     AND binding.workspace_revision = confirmation.workspace_revision
     AND binding.workspace_configuration_hash = confirmation.workspace_configuration_hash
     AND binding.workspace_source_id = confirmation.workspace_source_id
     AND binding.source_scope_id = confirmation.source_scope_id
     AND binding.source_scope_revision = confirmation.source_scope_revision
     AND binding.scope_config_hash = confirmation.scope_config_hash
     AND binding.access_mode = confirmation.access_mode
     AND binding.enabled
    JOIN public.workspace_managed_warning_contract AS warning
      ON warning.warning_version = confirmation.warning_version
     AND warning.warning_contract_hash = confirmation.warning_contract_hash
     AND warning.revision = app.workspace_managed_warning_contract_current_revision()
    WHERE confirmation.organization_id = NEW.organization_id
      AND confirmation.workspace_id = NEW.workspace_id
      AND confirmation.workspace_revision = current_workspace_revision
      AND confirmation.workspace_configuration_hash = NEW.workspace_configuration_hash
      AND confirmation.workspace_source_id = NEW.workspace_source_id
      AND confirmation.source_scope_id = NEW.source_scope_id
      AND confirmation.source_scope_revision = NEW.source_scope_revision
      AND confirmation.scope_config_hash = NEW.scope_config_hash
      AND confirmation.access_mode = NEW.access_mode
      AND confirmation.policy_revision_number = NEW.policy_revision_number
      AND confirmation.policy_revision = NEW.policy_revision
      AND confirmation.warning_version = NEW.warning_version
      AND confirmation.warning_contract_hash = NEW.warning_contract_hash
      AND NOT EXISTS (
          SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
          WHERE revocation.organization_id = confirmation.organization_id
            AND revocation.confirmation_id = confirmation.confirmation_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS grant_revocation
          WHERE grant_revocation.organization_id = confirmation.organization_id
            AND grant_revocation.grant_id = confirmation.confirmation_actor_grant_id
            AND grant_revocation.grant_revision = confirmation.confirmation_actor_grant_revision
      );

    IF live_count > 1 THEN
        RAISE EXCEPTION 'workspace managed confirmation tuple has more than one derived-live confirmation'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_managed_grant_confirmation_derived_live_exact
AFTER INSERT ON public.workspace_managed_grant_confirmation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_grant_confirmation_derived_live_guard();

CREATE TRIGGER workspace_managed_grant_confirmation_current_policy_exact
BEFORE INSERT ON public.workspace_managed_grant_confirmation
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();

CREATE TRIGGER workspace_managed_grant_confirmation_immutable
BEFORE UPDATE OR DELETE ON public.workspace_managed_grant_confirmation
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.workspace_managed_grant_confirmation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_managed_grant_confirmation FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_managed_grant_confirmation_tenant_isolation
    ON public.workspace_managed_grant_confirmation
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_managed_grant_confirmation.organization_id
              AND member.workspace_id = workspace_managed_grant_confirmation.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );

REVOKE ALL ON TABLE public.workspace_managed_grant_confirmation FROM PUBLIC;
GRANT SELECT ON TABLE public.workspace_managed_grant_confirmation TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4D. Workspace managed grant revocation.
-- ---------------------------------------------------------------------------

CREATE TABLE public.workspace_managed_grant_revocation (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    revocation_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(revocation_id)),
    workspace_managed_confirmation_revocation_hash text NOT NULL CHECK (
        app.stage2_sha256_is_valid(workspace_managed_confirmation_revocation_hash)
    ),
    confirmation_id text NOT NULL,
    confirmation_hash text NOT NULL CHECK (app.stage2_sha256_is_valid(confirmation_hash)),
    revoked_by text NOT NULL,
    revoked_at text NOT NULL CHECK (app.authority_timestamp_v1_is_valid(revoked_at)),
    reason_code text NOT NULL CHECK (reason_code = 'ACCESS_REVOKED'),
    policy_revision_number bigint NOT NULL CHECK (policy_revision_number BETWEEN 1 AND 9007199254740991),
    policy_revision text NOT NULL CHECK (app.stage2_opaque_id_is_valid(policy_revision)),
    PRIMARY KEY (organization_id, revocation_id),
    UNIQUE (organization_id, revocation_id, workspace_managed_confirmation_revocation_hash),
    UNIQUE (organization_id, confirmation_id),
    CONSTRAINT workspace_managed_grant_revocation_confirmation_fk
        FOREIGN KEY (organization_id, confirmation_id, confirmation_hash)
        REFERENCES public.workspace_managed_grant_confirmation (organization_id, confirmation_id, confirmation_hash)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_grant_revocation_actor_fk
        FOREIGN KEY (organization_id, revoked_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_grant_revocation_policy_fk
        FOREIGN KEY (organization_id, policy_revision_number, policy_revision)
        REFERENCES public.organization_policy_revision (organization_id, revision, policy_revision_id)
        ON DELETE RESTRICT
);

-- Revocation never requires the confirmed workspace revision to still be
-- current: a stale confirmation may always be revoked. It still serializes
-- with confirmation/source commands on the same workspace row: the exact
-- parent confirmation tells us the workspace, and the FOR UPDATE lock is
-- held before this revocation is validated or inserted.
CREATE OR REPLACE FUNCTION app.workspace_managed_grant_revocation_temporal_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    parent_confirmed_at text;
    parent_workspace_id text;
    locked_workspace_id text;
    revoked_epoch bigint;
BEGIN
    SELECT confirmed_at, workspace_id INTO parent_confirmed_at, parent_workspace_id
    FROM public.workspace_managed_grant_confirmation
    WHERE organization_id = NEW.organization_id
      AND confirmation_id = NEW.confirmation_id
      AND confirmation_hash = NEW.confirmation_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace managed confirmation revocation lacks its exact confirmation'
            USING ERRCODE = '23503';
    END IF;

    SELECT id INTO locked_workspace_id
    FROM public.workspace
    WHERE organization_id = NEW.organization_id AND id = parent_workspace_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace managed confirmation revocation lacks its exact parent workspace'
            USING ERRCODE = '23503';
    END IF;

    revoked_epoch := app.authority_timestamp_v1_to_epoch(NEW.revoked_at);
    IF revoked_epoch IS NULL
       OR revoked_epoch < app.authority_timestamp_v1_to_epoch(parent_confirmed_at)
       OR revoked_epoch > app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'workspace managed confirmation revocation has an invalid revoked_at'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_managed_grant_revocation_temporal_exact
BEFORE INSERT ON public.workspace_managed_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_grant_revocation_temporal_guard();

CREATE TRIGGER workspace_managed_grant_revocation_current_policy_exact
BEFORE INSERT ON public.workspace_managed_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();

CREATE TRIGGER workspace_managed_grant_revocation_immutable
BEFORE UPDATE OR DELETE ON public.workspace_managed_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.workspace_managed_grant_revocation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_managed_grant_revocation FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_managed_grant_revocation_tenant_isolation
    ON public.workspace_managed_grant_revocation
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1
            FROM public.workspace_managed_grant_confirmation AS confirmation
            JOIN public.workspace_member AS member
              ON member.organization_id = confirmation.organization_id
             AND member.workspace_id = confirmation.workspace_id
             AND member.principal_id = app.current_principal_id()
             AND member.removed_at IS NULL
            WHERE confirmation.organization_id = workspace_managed_grant_revocation.organization_id
              AND confirmation.confirmation_id = workspace_managed_grant_revocation.confirmation_id
        )
    );

REVOKE ALL ON TABLE public.workspace_managed_grant_revocation FROM PUBLIC;
GRANT SELECT ON TABLE public.workspace_managed_grant_revocation TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 5. Lock down every helper/trigger function introduced above.
-- ---------------------------------------------------------------------------

REVOKE ALL ON FUNCTION
    app.authority_timestamp_v1_is_valid(text),
    app.authority_timestamp_v1_to_epoch(text),
    app.authority_transaction_epoch(),
    app.organization_policy_revision_sequence_guard(),
    app.organization_policy_revision_change_guard(),
    app.authority_current_policy_guard(),
    app.workspace_managed_warning_contract_immutable_guard(),
    app.workspace_managed_warning_contract_current_revision(),
    app.workspace_source_confirmation_actor_grant_temporal_guard(),
    app.actor_grant_revocation_temporal_guard(),
    app.workspace_managed_grant_confirmation_exact_guard(),
    app.workspace_managed_grant_confirmation_derived_live_guard(),
    app.workspace_managed_grant_revocation_temporal_guard()
FROM PUBLIC;

COMMIT;
