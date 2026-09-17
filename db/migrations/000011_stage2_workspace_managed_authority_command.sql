-- Stage 2 workspace-managed authority command boundary (ADR-0053 + ADR-0052).
--
-- Migration 000010 shipped the four confirmation-authority relations as inert
-- persistence: knowvault_app could read them but could not insert a single
-- row. This migration installs the receipt boundary that ADR-0053 froze, and
-- only then opens a single, exactly-gated INSERT path.
--
-- Canonical hash boundary. This migration does not implement a second,
-- hand-written JCS engine inside PostgreSQL, and it must never be described as
-- one. Go remains the sole authority for exact RFC 8785 canonicality: it
-- builds the canonical bytes and derives the hash. PostgreSQL independently
-- proves three complementary facts about what Go actually stored:
--   * the stored hash equals SHA-256 of exactly the stored bytes;
--   * the stored JSON's field set and types are exactly the closed contract;
--   * every JSON field exact-matches its relational column projection.
-- A byte string that is semantically equivalent but not canonical is rejected
-- by the Go boundary, not here; PostgreSQL never re-derives canonical bytes
-- from typed fields.
--
-- Receipt family. The authority receipt is deliberately a separate relation
-- from workspace_command_receipt: an authority command never creates a
-- WorkspaceRevision, so reusing the workspace receipt family would bind two
-- unrelated result contracts into one namespace. workspace_command_receipt is
-- not extended by this migration.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Fail-closed upgrade gate.
-- ---------------------------------------------------------------------------

-- ADR-0053: "Migration 000011 must fail closed if it finds authority rows
-- created before this receipt boundary: declaring them trusted automatically
-- or silently backfilling receipts is forbidden."
--
-- Every one of the four relations below was created by 000010 with SELECT-only
-- runtime privileges, so any row that exists here predates the receipt
-- boundary by construction: there is no receipt it could be bound to and no
-- honest way to invent one. The whole migration aborts and rolls back; it does
-- not backfill, does not synthesize a receipt, and does not declare the rows
-- trusted.
-- Migration owner gate.
--
-- Every gate below that must see rows the caller cannot — the receipt resolver,
-- the result binding, the audit binding — is SECURITY DEFINER and therefore
-- runs as this migration's owner. All four authority relations and the receipt
-- carry FORCE ROW LEVEL SECURITY, which applies to a table's owner too. An
-- owner that is neither SUPERUSER nor BYPASSRLS would therefore silently see
-- *fewer* rows inside those gates: the receipt resolver would not find the
-- receipt, and the result binding would count zero authority rows and conclude
-- a SUCCESS bound none. Those gates would not fail loudly — they would weaken.
--
-- The fail-closed check below also depends on this: a non-bypassing owner would
-- count zero pre-receipt authority rows and wave the upgrade through.
--
-- So the property is a precondition of this migration, not an incidental
-- deployment detail, and it is asserted here rather than assumed.
DO $$
DECLARE
    owner_bypasses_rls boolean;
BEGIN
    SELECT rolsuper OR rolbypassrls
    INTO owner_bypasses_rls
    FROM pg_catalog.pg_roles
    WHERE rolname = current_user;

    IF NOT FOUND OR NOT owner_bypasses_rls THEN
        RAISE EXCEPTION
            'workspace-managed authority migration owner % is neither SUPERUSER nor BYPASSRLS; its SECURITY DEFINER gates would silently under-count rows under FORCE ROW LEVEL SECURITY',
            current_user
            USING ERRCODE = '55000';
    END IF;
END;
$$;

DO $$
DECLARE
    pre_receipt_rows bigint;
BEGIN
    SELECT
        (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant)
      + (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant_revocation)
      + (SELECT count(*) FROM public.workspace_managed_grant_confirmation)
      + (SELECT count(*) FROM public.workspace_managed_grant_revocation)
    INTO pre_receipt_rows;

    IF pre_receipt_rows > 0 THEN
        RAISE EXCEPTION
            'workspace-managed authority upgrade found % pre-receipt authority row(s); refusing to declare them trusted or backfill receipts',
            pre_receipt_rows
            USING ERRCODE = '55000';
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Canonical byte/hash helpers.
-- ---------------------------------------------------------------------------

-- Proves hash == SHA-256(exact stored bytes). This is a format-and-binding
-- check over bytes Go produced, never a re-derivation of those bytes.
CREATE OR REPLACE FUNCTION app.authority_canonical_hash_matches(canonical bytea, expected_hash text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT canonical IS NOT NULL
       AND expected_hash IS NOT NULL
       AND expected_hash = 'sha256:' || encode(sha256(canonical), 'hex');
$$;

-- Parses stored canonical bytes as JSON. Returns NULL for anything that is not
-- a JSON object, so callers compare projections without ever raising.
CREATE OR REPLACE FUNCTION app.authority_canonical_object(canonical bytea)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    parsed jsonb;
BEGIN
    BEGIN
        parsed := convert_from(canonical, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
    IF jsonb_typeof(parsed) <> 'object' THEN
        RETURN NULL;
    END IF;
    RETURN parsed;
END;
$$;

-- Exact closed field set: the object's key set must equal `expected` exactly.
-- A missing key, an extra key and a renamed key are all rejected.
CREATE OR REPLACE FUNCTION app.authority_object_key_set_is_exact(document jsonb, expected text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
-- coalesce() is load-bearing: array_agg() over an empty set returns NULL, not
-- an empty array, so an empty JSON object would otherwise make this return
-- NULL. A caller writing `IF NOT <this> THEN RAISE` does not fire on NULL,
-- which would silently wave the empty object past the closed-field-set gate.
AS $$
    SELECT document IS NOT NULL
       AND coalesce((
           SELECT array_agg(key ORDER BY key)
           FROM jsonb_object_keys(document) AS key
       ), ARRAY[]::text[]) = coalesce((
           SELECT array_agg(key ORDER BY key)
           FROM unnest(expected) AS key
       ), ARRAY[]::text[]);
$$;

-- Typed accessors. Each returns NULL unless the JSON value is present *and* of
-- the exact expected JSON type, so a string "7" can never satisfy an integer
-- projection and a number can never satisfy a string projection.
CREATE OR REPLACE FUNCTION app.authority_json_text(document jsonb, key text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN document ? key AND jsonb_typeof(document -> key) = 'string'
            THEN document ->> key
        ELSE NULL
    END;
$$;

CREATE OR REPLACE FUNCTION app.authority_json_integer(document jsonb, key text)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    raw jsonb;
    numeric_value numeric;
BEGIN
    IF document IS NULL OR NOT (document ? key) THEN
        RETURN NULL;
    END IF;
    raw := document -> key;
    IF jsonb_typeof(raw) <> 'number' THEN
        RETURN NULL;
    END IF;
    numeric_value := raw::text::numeric;
    -- Closed JCS-safe integer domain: no fraction, no exponent drift.
    IF numeric_value <> trunc(numeric_value)
       OR numeric_value < -9007199254740991
       OR numeric_value > 9007199254740991 THEN
        RETURN NULL;
    END IF;
    RETURN numeric_value::bigint;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Authority command receipt.
-- ---------------------------------------------------------------------------

-- A separate receipt family from workspace_command_receipt (ADR-0053).
--
-- Namespace: (organization_id, actor_principal_id, idempotency_key_hash),
-- where organization_id is ALWAYS the trusted AccessContext organization and
-- never request.organization_id. request_organization_id below is stored only
-- as the canonical projection of the request body; it is inert data, it is
-- deliberately NOT constrained to equal organization_id (a cross-tenant
-- command legitimately terminates NOT_FOUND with a trusted-tenant receipt
-- whose request names a foreign organization), and nothing in this schema ever
-- selects a tenant, an RLS context or a namespace from it.
CREATE TABLE public.workspace_managed_authority_command_receipt (
    organization_id text NOT NULL,
    actor_principal_id text NOT NULL CHECK (app.audit_opaque_id_is_valid(actor_principal_id)),
    idempotency_key_hash text NOT NULL
        CHECK (app.workspace_command_hash_is_valid(idempotency_key_hash)),

    -- Reserved before any authorization decision is evaluated, so every
    -- terminal outcome has one. It identifies the receipt, not the request,
    -- and therefore never enters the request canonical bytes or request hash.
    command_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(command_id)),

    operation text NOT NULL CHECK (operation IN (
        'WORKSPACE_CONFIRMATION_GRANT_ISSUE',
        'WORKSPACE_CONFIRMATION_GRANT_REVOKE',
        'WORKSPACE_MANAGED_CONFIRM',
        'WORKSPACE_MANAGED_CONFIRM_REVOKE'
    )),

    canonical_request_bytes bytea NOT NULL
        CHECK (octet_length(canonical_request_bytes) BETWEEN 1 AND 65536),
    canonical_request_hash text NOT NULL
        CHECK (app.workspace_command_hash_is_valid(canonical_request_hash)),
    CONSTRAINT workspace_managed_authority_command_receipt_request_hash_exact
        CHECK (app.authority_canonical_hash_matches(canonical_request_bytes, canonical_request_hash)),

    -- Closed, typed, operation-specific request projection. There is no
    -- generic intent JSON column here and no unconstrained nullable union: the
    -- exhaustive per-operation CHECK below pins exactly which columns are
    -- non-null for each operation and forces every other column to NULL.
    request_organization_id text NOT NULL,
    request_workspace_id text NOT NULL,
    request_expected_policy_revision text NOT NULL,

    -- WORKSPACE_CONFIRMATION_GRANT_ISSUE only.
    request_expected_workspace_revision bigint
        CHECK (request_expected_workspace_revision IS NULL
               OR request_expected_workspace_revision BETWEEN 1 AND 9007199254740991),
    request_expected_workspace_configuration_hash text
        CHECK (request_expected_workspace_configuration_hash IS NULL
               OR app.stage2_sha256_is_valid(request_expected_workspace_configuration_hash)),
    request_target_principal_id text,
    request_ttl_seconds bigint
        CHECK (request_ttl_seconds IS NULL OR request_ttl_seconds BETWEEN 60 AND 86400),

    -- WORKSPACE_CONFIRMATION_GRANT_REVOKE only.
    request_grant_id text,
    request_grant_revision bigint
        CHECK (request_grant_revision IS NULL
               OR request_grant_revision BETWEEN 1 AND 9007199254740991),
    request_grant_hash text
        CHECK (request_grant_hash IS NULL OR app.stage2_sha256_is_valid(request_grant_hash)),

    -- WORKSPACE_MANAGED_CONFIRM only.
    request_workspace_revision bigint
        CHECK (request_workspace_revision IS NULL
               OR request_workspace_revision BETWEEN 1 AND 9007199254740991),
    request_workspace_configuration_hash text
        CHECK (request_workspace_configuration_hash IS NULL
               OR app.stage2_sha256_is_valid(request_workspace_configuration_hash)),
    request_workspace_source_id text,
    request_source_scope_id text,
    request_source_scope_revision bigint
        CHECK (request_source_scope_revision IS NULL
               OR request_source_scope_revision BETWEEN 1 AND 9007199254740991),
    request_scope_config_hash text
        CHECK (request_scope_config_hash IS NULL OR app.stage2_sha256_is_valid(request_scope_config_hash)),
    request_access_mode text
        CHECK (request_access_mode IS NULL OR request_access_mode = 'WORKSPACE_MANAGED'),
    request_confirmation_actor_grant_id text,
    request_confirmation_actor_grant_revision bigint
        CHECK (request_confirmation_actor_grant_revision IS NULL
               OR request_confirmation_actor_grant_revision BETWEEN 1 AND 9007199254740991),
    request_confirmation_actor_grant_hash text
        CHECK (request_confirmation_actor_grant_hash IS NULL
               OR app.stage2_sha256_is_valid(request_confirmation_actor_grant_hash)),
    request_warning_version text
        CHECK (request_warning_version IS NULL OR request_warning_version = 'workspace-managed-risk-v1'),
    request_warning_contract_hash text
        CHECK (request_warning_contract_hash IS NULL
               OR app.stage2_sha256_is_valid(request_warning_contract_hash)),
    request_acknowledgement_code text
        CHECK (request_acknowledgement_code IS NULL
               OR request_acknowledgement_code = 'WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL'),

    -- WORKSPACE_MANAGED_CONFIRM_REVOKE only.
    request_confirmation_id text,
    request_confirmation_hash text
        CHECK (request_confirmation_hash IS NULL OR app.stage2_sha256_is_valid(request_confirmation_hash)),

    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')),

    -- Result identity exists only for SUCCESS. The canonical result bytes
    -- themselves live next to the authority row; the receipt carries the exact
    -- reference to them.
    result_authority_id text
        CHECK (result_authority_id IS NULL OR app.stage2_opaque_id_is_valid(result_authority_id)),
    result_authority_hash text
        CHECK (result_authority_hash IS NULL OR app.stage2_sha256_is_valid(result_authority_hash)),

    audit_event_id text CHECK (audit_event_id IS NULL OR app.audit_opaque_id_is_valid(audit_event_id)),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    terminal_at timestamptz,

    PRIMARY KEY (organization_id, actor_principal_id, idempotency_key_hash),

    -- command_id is unique within the tenant and is the audit resource ID for
    -- every terminal outcome.
    CONSTRAINT workspace_managed_authority_command_receipt_command_unique
        UNIQUE (organization_id, command_id),

    CONSTRAINT workspace_managed_authority_command_receipt_actor_fk
        FOREIGN KEY (organization_id, actor_principal_id)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_managed_authority_command_receipt_audit_event_fk
        FOREIGN KEY (organization_id, audit_event_id)
        REFERENCES public.audit_event (organization_id, id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,

    CHECK (terminal_at IS NULL OR terminal_at >= created_at),

    -- Status shape. PENDING carries no result and no audit event; every
    -- terminal outcome carries exactly one audit event; only SUCCESS carries a
    -- result identity.
    CONSTRAINT workspace_managed_authority_command_receipt_status_shape CHECK (
        (status = 'PENDING'
            AND result_authority_id IS NULL
            AND result_authority_hash IS NULL
            AND audit_event_id IS NULL
            AND terminal_at IS NULL)
        OR (status = 'SUCCESS'
            AND result_authority_id IS NOT NULL
            AND result_authority_hash IS NOT NULL
            AND audit_event_id IS NOT NULL
            AND terminal_at IS NOT NULL)
        OR (status IN ('DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')
            AND result_authority_id IS NULL
            AND result_authority_hash IS NULL
            AND audit_event_id IS NOT NULL
            AND terminal_at IS NOT NULL)
    ),

    -- request_organization_id is the canonical projection of the request body,
    -- never a tenant selector — but "inert" is not the same as "unconstrained".
    -- ADR-0053 makes a cross-tenant reference always NOT_FOUND and never
    -- DENIED, so NOT_FOUND is the one terminal where a trusted-tenant receipt
    -- may legitimately carry a request naming a foreign organization. PENDING
    -- is reserved before any authorization decision is evaluated, so it must be
    -- allowed to hold that request too — that reservation is exactly what
    -- becomes the NOT_FOUND receipt.
    --
    -- Every other status asserts a tenant-bound fact: SUCCESS created a row in
    -- the trusted tenant, and DENIED and PRECONDITION_FAILED evaluated a role
    -- or a precondition against it. A receipt binding hash-verified canonical
    -- bytes that disclaim that tenant would contradict its own terminal.
    CONSTRAINT workspace_managed_authority_command_receipt_request_tenant CHECK (
        status IN ('PENDING', 'NOT_FOUND')
        OR request_organization_id = organization_id
    ),

    -- Exhaustive closed projection per operation. Every operation pins its own
    -- exact non-null field set and forces every field of every other operation
    -- to NULL, so one idempotency key can never be reused for a different
    -- operation shape and no nullable union is left unconstrained.
    CONSTRAINT workspace_managed_authority_command_receipt_projection_exact CHECK (
        (operation = 'WORKSPACE_CONFIRMATION_GRANT_ISSUE'
            AND request_expected_workspace_revision IS NOT NULL
            AND request_expected_workspace_configuration_hash IS NOT NULL
            AND request_target_principal_id IS NOT NULL
            AND request_ttl_seconds IS NOT NULL
            AND request_grant_id IS NULL
            AND request_grant_revision IS NULL
            AND request_grant_hash IS NULL
            AND request_workspace_revision IS NULL
            AND request_workspace_configuration_hash IS NULL
            AND request_workspace_source_id IS NULL
            AND request_source_scope_id IS NULL
            AND request_source_scope_revision IS NULL
            AND request_scope_config_hash IS NULL
            AND request_access_mode IS NULL
            AND request_confirmation_actor_grant_id IS NULL
            AND request_confirmation_actor_grant_revision IS NULL
            AND request_confirmation_actor_grant_hash IS NULL
            AND request_warning_version IS NULL
            AND request_warning_contract_hash IS NULL
            AND request_acknowledgement_code IS NULL
            AND request_confirmation_id IS NULL
            AND request_confirmation_hash IS NULL)
        OR (operation = 'WORKSPACE_CONFIRMATION_GRANT_REVOKE'
            AND request_grant_id IS NOT NULL
            AND request_grant_revision IS NOT NULL
            AND request_grant_hash IS NOT NULL
            AND request_expected_workspace_revision IS NULL
            AND request_expected_workspace_configuration_hash IS NULL
            AND request_target_principal_id IS NULL
            AND request_ttl_seconds IS NULL
            AND request_workspace_revision IS NULL
            AND request_workspace_configuration_hash IS NULL
            AND request_workspace_source_id IS NULL
            AND request_source_scope_id IS NULL
            AND request_source_scope_revision IS NULL
            AND request_scope_config_hash IS NULL
            AND request_access_mode IS NULL
            AND request_confirmation_actor_grant_id IS NULL
            AND request_confirmation_actor_grant_revision IS NULL
            AND request_confirmation_actor_grant_hash IS NULL
            AND request_warning_version IS NULL
            AND request_warning_contract_hash IS NULL
            AND request_acknowledgement_code IS NULL
            AND request_confirmation_id IS NULL
            AND request_confirmation_hash IS NULL)
        OR (operation = 'WORKSPACE_MANAGED_CONFIRM'
            AND request_workspace_revision IS NOT NULL
            AND request_workspace_configuration_hash IS NOT NULL
            AND request_workspace_source_id IS NOT NULL
            AND request_source_scope_id IS NOT NULL
            AND request_source_scope_revision IS NOT NULL
            AND request_scope_config_hash IS NOT NULL
            AND request_access_mode IS NOT NULL
            AND request_confirmation_actor_grant_id IS NOT NULL
            AND request_confirmation_actor_grant_revision IS NOT NULL
            AND request_confirmation_actor_grant_hash IS NOT NULL
            AND request_warning_version IS NOT NULL
            AND request_warning_contract_hash IS NOT NULL
            AND request_acknowledgement_code IS NOT NULL
            AND request_expected_workspace_revision IS NULL
            AND request_expected_workspace_configuration_hash IS NULL
            AND request_target_principal_id IS NULL
            AND request_ttl_seconds IS NULL
            AND request_grant_id IS NULL
            AND request_grant_revision IS NULL
            AND request_grant_hash IS NULL
            AND request_confirmation_id IS NULL
            AND request_confirmation_hash IS NULL)
        OR (operation = 'WORKSPACE_MANAGED_CONFIRM_REVOKE'
            AND request_confirmation_id IS NOT NULL
            AND request_confirmation_hash IS NOT NULL
            AND request_expected_workspace_revision IS NULL
            AND request_expected_workspace_configuration_hash IS NULL
            AND request_target_principal_id IS NULL
            AND request_ttl_seconds IS NULL
            AND request_grant_id IS NULL
            AND request_grant_revision IS NULL
            AND request_grant_hash IS NULL
            AND request_workspace_revision IS NULL
            AND request_workspace_configuration_hash IS NULL
            AND request_workspace_source_id IS NULL
            AND request_source_scope_id IS NULL
            AND request_source_scope_revision IS NULL
            AND request_scope_config_hash IS NULL
            AND request_access_mode IS NULL
            AND request_confirmation_actor_grant_id IS NULL
            AND request_confirmation_actor_grant_revision IS NULL
            AND request_confirmation_actor_grant_hash IS NULL
            AND request_warning_version IS NULL
            AND request_warning_contract_hash IS NULL
            AND request_acknowledgement_code IS NULL)
    )
);

-- One audit event belongs to exactly one receipt.
CREATE UNIQUE INDEX workspace_managed_authority_receipt_one_audit_event
    ON public.workspace_managed_authority_command_receipt (organization_id, audit_event_id)
    WHERE audit_event_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3.1. Receipt canonical request projection.
-- ---------------------------------------------------------------------------

-- Proves that the stored canonical request bytes are the exact closed envelope
-- of the stored operation, and that every JSON request field exact-matches its
-- typed relational column. Go proved RFC 8785 canonicality of these bytes and
-- derived the hash; this gate proves the relational projection cannot drift
-- away from the bytes that were hashed.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_projection_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    envelope jsonb;
    request jsonb;
    expected_keys text[];
BEGIN
    envelope := app.authority_canonical_object(NEW.canonical_request_bytes);
    IF envelope IS NULL
       OR NOT app.authority_object_key_set_is_exact(envelope, ARRAY['schema_version', 'operation', 'request'])
       OR app.authority_json_text(envelope, 'schema_version') IS DISTINCT FROM 'workspace-managed-authority-command-v1'
       OR app.authority_json_text(envelope, 'operation') IS DISTINCT FROM NEW.operation THEN
        RAISE EXCEPTION 'authority receipt canonical envelope is not the exact closed contract'
            USING ERRCODE = '23514';
    END IF;

    IF jsonb_typeof(envelope -> 'request') <> 'object' THEN
        RAISE EXCEPTION 'authority receipt canonical request is not an object' USING ERRCODE = '23514';
    END IF;
    request := envelope -> 'request';

    expected_keys := CASE NEW.operation
        WHEN 'WORKSPACE_CONFIRMATION_GRANT_ISSUE' THEN ARRAY[
            'organization_id', 'workspace_id', 'expected_workspace_revision',
            'expected_workspace_configuration_hash', 'target_principal_id',
            'ttl_seconds', 'expected_policy_revision']
        WHEN 'WORKSPACE_CONFIRMATION_GRANT_REVOKE' THEN ARRAY[
            'organization_id', 'workspace_id', 'grant_id', 'grant_revision',
            'grant_hash', 'expected_policy_revision']
        WHEN 'WORKSPACE_MANAGED_CONFIRM' THEN ARRAY[
            'organization_id', 'workspace_id', 'workspace_revision',
            'workspace_configuration_hash', 'workspace_source_id', 'source_scope_id',
            'source_scope_revision', 'scope_config_hash', 'access_mode',
            'confirmation_actor_grant_id', 'confirmation_actor_grant_revision',
            'confirmation_actor_grant_hash', 'warning_version', 'warning_contract_hash',
            'acknowledgement_code', 'expected_policy_revision']
        WHEN 'WORKSPACE_MANAGED_CONFIRM_REVOKE' THEN ARRAY[
            'organization_id', 'workspace_id', 'confirmation_id',
            'confirmation_hash', 'expected_policy_revision']
    END;

    IF NOT app.authority_object_key_set_is_exact(request, expected_keys) THEN
        RAISE EXCEPTION 'authority receipt canonical request field set is not exact for %', NEW.operation
            USING ERRCODE = '23514';
    END IF;

    -- Fields common to all four operations.
    IF app.authority_json_text(request, 'organization_id') IS DISTINCT FROM NEW.request_organization_id
       OR app.authority_json_text(request, 'workspace_id') IS DISTINCT FROM NEW.request_workspace_id
       OR app.authority_json_text(request, 'expected_policy_revision')
           IS DISTINCT FROM NEW.request_expected_policy_revision THEN
        RAISE EXCEPTION 'authority receipt canonical request does not match its relational projection'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.operation = 'WORKSPACE_CONFIRMATION_GRANT_ISSUE' THEN
        IF app.authority_json_integer(request, 'expected_workspace_revision')
               IS DISTINCT FROM NEW.request_expected_workspace_revision
           OR app.authority_json_text(request, 'expected_workspace_configuration_hash')
               IS DISTINCT FROM NEW.request_expected_workspace_configuration_hash
           OR app.authority_json_text(request, 'target_principal_id')
               IS DISTINCT FROM NEW.request_target_principal_id
           OR app.authority_json_integer(request, 'ttl_seconds') IS DISTINCT FROM NEW.request_ttl_seconds THEN
            RAISE EXCEPTION 'authority receipt grant-issue projection does not match canonical request'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.operation = 'WORKSPACE_CONFIRMATION_GRANT_REVOKE' THEN
        IF app.authority_json_text(request, 'grant_id') IS DISTINCT FROM NEW.request_grant_id
           OR app.authority_json_integer(request, 'grant_revision') IS DISTINCT FROM NEW.request_grant_revision
           OR app.authority_json_text(request, 'grant_hash') IS DISTINCT FROM NEW.request_grant_hash THEN
            RAISE EXCEPTION 'authority receipt grant-revoke projection does not match canonical request'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.operation = 'WORKSPACE_MANAGED_CONFIRM' THEN
        IF app.authority_json_integer(request, 'workspace_revision') IS DISTINCT FROM NEW.request_workspace_revision
           OR app.authority_json_text(request, 'workspace_configuration_hash')
               IS DISTINCT FROM NEW.request_workspace_configuration_hash
           OR app.authority_json_text(request, 'workspace_source_id') IS DISTINCT FROM NEW.request_workspace_source_id
           OR app.authority_json_text(request, 'source_scope_id') IS DISTINCT FROM NEW.request_source_scope_id
           OR app.authority_json_integer(request, 'source_scope_revision')
               IS DISTINCT FROM NEW.request_source_scope_revision
           OR app.authority_json_text(request, 'scope_config_hash') IS DISTINCT FROM NEW.request_scope_config_hash
           OR app.authority_json_text(request, 'access_mode') IS DISTINCT FROM NEW.request_access_mode
           OR app.authority_json_text(request, 'confirmation_actor_grant_id')
               IS DISTINCT FROM NEW.request_confirmation_actor_grant_id
           OR app.authority_json_integer(request, 'confirmation_actor_grant_revision')
               IS DISTINCT FROM NEW.request_confirmation_actor_grant_revision
           OR app.authority_json_text(request, 'confirmation_actor_grant_hash')
               IS DISTINCT FROM NEW.request_confirmation_actor_grant_hash
           OR app.authority_json_text(request, 'warning_version') IS DISTINCT FROM NEW.request_warning_version
           OR app.authority_json_text(request, 'warning_contract_hash')
               IS DISTINCT FROM NEW.request_warning_contract_hash
           OR app.authority_json_text(request, 'acknowledgement_code')
               IS DISTINCT FROM NEW.request_acknowledgement_code THEN
            RAISE EXCEPTION 'authority receipt confirm projection does not match canonical request'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF app.authority_json_text(request, 'confirmation_id') IS DISTINCT FROM NEW.request_confirmation_id
           OR app.authority_json_text(request, 'confirmation_hash') IS DISTINCT FROM NEW.request_confirmation_hash THEN
            RAISE EXCEPTION 'authority receipt confirm-revoke projection does not match canonical request'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_managed_authority_command_receipt_projection_exact
BEFORE INSERT ON public.workspace_managed_authority_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_projection_guard();

-- Every receipt begins PENDING with no result, no audit event and no terminal
-- timestamp: a caller can never insert a pre-terminalized receipt.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.status <> 'PENDING'
       OR NEW.result_authority_id IS NOT NULL
       OR NEW.result_authority_hash IS NOT NULL
       OR NEW.audit_event_id IS NOT NULL
       OR NEW.terminal_at IS NOT NULL THEN
        RAISE EXCEPTION 'workspace managed authority receipt must begin pending' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_managed_authority_command_receipt_insert_guard
BEFORE INSERT ON public.workspace_managed_authority_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_insert_guard();

-- Receipt identity, canonical request bytes/hash, operation and the whole
-- request projection are immutable; a terminal receipt can never be rewritten;
-- and PENDING may transition exactly once, to exactly one terminal status.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_terminal_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.organization_id <> OLD.organization_id
       OR NEW.actor_principal_id <> OLD.actor_principal_id
       OR NEW.idempotency_key_hash <> OLD.idempotency_key_hash
       OR NEW.command_id <> OLD.command_id
       OR NEW.operation <> OLD.operation
       OR NEW.canonical_request_bytes <> OLD.canonical_request_bytes
       OR NEW.canonical_request_hash <> OLD.canonical_request_hash
       OR NEW.request_organization_id <> OLD.request_organization_id
       OR NEW.request_workspace_id <> OLD.request_workspace_id
       OR NEW.request_expected_policy_revision <> OLD.request_expected_policy_revision
       OR NEW.request_expected_workspace_revision IS DISTINCT FROM OLD.request_expected_workspace_revision
       OR NEW.request_expected_workspace_configuration_hash IS DISTINCT FROM OLD.request_expected_workspace_configuration_hash
       OR NEW.request_target_principal_id IS DISTINCT FROM OLD.request_target_principal_id
       OR NEW.request_ttl_seconds IS DISTINCT FROM OLD.request_ttl_seconds
       OR NEW.request_grant_id IS DISTINCT FROM OLD.request_grant_id
       OR NEW.request_grant_revision IS DISTINCT FROM OLD.request_grant_revision
       OR NEW.request_grant_hash IS DISTINCT FROM OLD.request_grant_hash
       OR NEW.request_workspace_revision IS DISTINCT FROM OLD.request_workspace_revision
       OR NEW.request_workspace_configuration_hash IS DISTINCT FROM OLD.request_workspace_configuration_hash
       OR NEW.request_workspace_source_id IS DISTINCT FROM OLD.request_workspace_source_id
       OR NEW.request_source_scope_id IS DISTINCT FROM OLD.request_source_scope_id
       OR NEW.request_source_scope_revision IS DISTINCT FROM OLD.request_source_scope_revision
       OR NEW.request_scope_config_hash IS DISTINCT FROM OLD.request_scope_config_hash
       OR NEW.request_access_mode IS DISTINCT FROM OLD.request_access_mode
       OR NEW.request_confirmation_actor_grant_id IS DISTINCT FROM OLD.request_confirmation_actor_grant_id
       OR NEW.request_confirmation_actor_grant_revision IS DISTINCT FROM OLD.request_confirmation_actor_grant_revision
       OR NEW.request_confirmation_actor_grant_hash IS DISTINCT FROM OLD.request_confirmation_actor_grant_hash
       OR NEW.request_warning_version IS DISTINCT FROM OLD.request_warning_version
       OR NEW.request_warning_contract_hash IS DISTINCT FROM OLD.request_warning_contract_hash
       OR NEW.request_acknowledgement_code IS DISTINCT FROM OLD.request_acknowledgement_code
       OR NEW.request_confirmation_id IS DISTINCT FROM OLD.request_confirmation_id
       OR NEW.request_confirmation_hash IS DISTINCT FROM OLD.request_confirmation_hash
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'workspace managed authority receipt identity is immutable' USING ERRCODE = '55000';
    END IF;

    IF OLD.status <> 'PENDING' THEN
        RAISE EXCEPTION 'terminal workspace managed authority receipt is immutable' USING ERRCODE = '55000';
    END IF;

    IF NEW.status NOT IN ('SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED')
       OR NEW.terminal_at <> transaction_timestamp() THEN
        RAISE EXCEPTION 'workspace managed authority receipt must transition once to a terminal state'
            USING ERRCODE = '55000';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_managed_authority_command_receipt_terminal_guard
BEFORE UPDATE ON public.workspace_managed_authority_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_terminal_guard();

-- A receipt is append-only for the runtime and for every ordinary path: the
-- audit trail of an authority command must not be erasable by the role that
-- issued it. Tenant hard-delete is the one exception, on exactly the terms the
-- rest of Stage 2 already uses (app.source_immutable_or_hard_delete_guard):
-- never as knowvault_app, and only once the organization has entered DELETING
-- or DELETED. Child-first ordering is structural rather than asserted here —
-- each authority relation references the receipt with ON DELETE RESTRICT, so a
-- receipt cannot be removed while any authority row still names its command.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_no_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF session_user = 'knowvault_app'
       OR NOT EXISTS (
           SELECT 1 FROM public.organization
           WHERE id = OLD.organization_id AND status IN ('DELETING', 'DELETED')
       ) THEN
        RAISE EXCEPTION 'workspace managed authority receipt is append-only outside tenant hard-delete'
            USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER workspace_managed_authority_command_receipt_no_delete
BEFORE DELETE ON public.workspace_managed_authority_command_receipt
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_no_delete();

-- A PENDING reservation can never survive commit.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_no_pending_commit()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    persisted_status text;
BEGIN
    SELECT status
    INTO persisted_status
    FROM public.workspace_managed_authority_command_receipt
    WHERE organization_id = NEW.organization_id
      AND actor_principal_id = NEW.actor_principal_id
      AND idempotency_key_hash = NEW.idempotency_key_hash;

    IF NOT FOUND OR persisted_status = 'PENDING' THEN
        RAISE EXCEPTION 'workspace managed authority receipt cannot commit pending' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_managed_authority_command_receipt_requires_terminal
AFTER INSERT OR UPDATE ON public.workspace_managed_authority_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_no_pending_commit();

-- ---------------------------------------------------------------------------
-- 3.2. Receipt RLS and privileges.
-- ---------------------------------------------------------------------------

ALTER TABLE public.workspace_managed_authority_command_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_managed_authority_command_receipt FORCE ROW LEVEL SECURITY;

-- A receipt is readable only by the exact actor who owns it, inside the
-- trusted tenant. Cross-tenant and cross-actor reads are invisible, so a
-- receipt never becomes an existence oracle for another actor's command.
CREATE POLICY workspace_managed_authority_command_receipt_actor_read
    ON public.workspace_managed_authority_command_receipt
    FOR SELECT
    USING (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    );

-- Reservation and terminalization stay inside the trusted tenant and the
-- acting principal. request_organization_id is deliberately absent here: the
-- request body never selects the RLS context.
CREATE POLICY workspace_managed_authority_command_receipt_actor_insert
    ON public.workspace_managed_authority_command_receipt
    FOR INSERT
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    );

CREATE POLICY workspace_managed_authority_command_receipt_actor_terminalize
    ON public.workspace_managed_authority_command_receipt
    FOR UPDATE
    USING (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    )
    WITH CHECK (
        organization_id = app.current_organization_id()
        AND actor_principal_id = app.current_principal_id()
    );

REVOKE ALL ON TABLE public.workspace_managed_authority_command_receipt FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE public.workspace_managed_authority_command_receipt TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 4. Authority row binding.
-- ---------------------------------------------------------------------------

-- Each of the four authority relations gains the exact command/receipt
-- linkage and the stored canonical result bytes whose SHA-256 must equal the
-- hash column that 000010 already carried.
ALTER TABLE public.workspace_source_confirmation_actor_grant
    ADD COLUMN command_id text NOT NULL,
    ADD COLUMN canonical_bytes bytea NOT NULL,
    ADD CONSTRAINT workspace_source_confirmation_actor_grant_command_unique
        UNIQUE (organization_id, command_id),
    ADD CONSTRAINT workspace_source_confirmation_actor_grant_receipt_fk
        FOREIGN KEY (organization_id, command_id)
        REFERENCES public.workspace_managed_authority_command_receipt (organization_id, command_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT workspace_source_confirmation_actor_grant_canonical_hash_exact
        CHECK (app.authority_canonical_hash_matches(canonical_bytes, grant_hash)),
    ADD CONSTRAINT workspace_source_confirmation_actor_grant_canonical_bounded
        CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 65536);

ALTER TABLE public.workspace_source_confirmation_actor_grant_revocation
    ADD COLUMN command_id text NOT NULL,
    ADD COLUMN canonical_bytes bytea NOT NULL,
    ADD CONSTRAINT actor_grant_revocation_command_unique
        UNIQUE (organization_id, command_id),
    ADD CONSTRAINT actor_grant_revocation_receipt_fk
        FOREIGN KEY (organization_id, command_id)
        REFERENCES public.workspace_managed_authority_command_receipt (organization_id, command_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT actor_grant_revocation_canonical_hash_exact
        CHECK (app.authority_canonical_hash_matches(canonical_bytes, confirmation_actor_grant_revocation_hash)),
    ADD CONSTRAINT actor_grant_revocation_canonical_bounded
        CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 65536);

ALTER TABLE public.workspace_managed_grant_confirmation
    ADD COLUMN command_id text NOT NULL,
    ADD COLUMN canonical_bytes bytea NOT NULL,
    ADD CONSTRAINT workspace_managed_grant_confirmation_command_unique
        UNIQUE (organization_id, command_id),
    ADD CONSTRAINT workspace_managed_grant_confirmation_receipt_fk
        FOREIGN KEY (organization_id, command_id)
        REFERENCES public.workspace_managed_authority_command_receipt (organization_id, command_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT workspace_managed_grant_confirmation_canonical_hash_exact
        CHECK (app.authority_canonical_hash_matches(canonical_bytes, confirmation_hash)),
    ADD CONSTRAINT workspace_managed_grant_confirmation_canonical_bounded
        CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 65536);

ALTER TABLE public.workspace_managed_grant_revocation
    ADD COLUMN command_id text NOT NULL,
    ADD COLUMN canonical_bytes bytea NOT NULL,
    ADD CONSTRAINT workspace_managed_grant_revocation_command_unique
        UNIQUE (organization_id, command_id),
    ADD CONSTRAINT workspace_managed_grant_revocation_receipt_fk
        FOREIGN KEY (organization_id, command_id)
        REFERENCES public.workspace_managed_authority_command_receipt (organization_id, command_id)
        ON DELETE RESTRICT,
    ADD CONSTRAINT workspace_managed_grant_revocation_canonical_hash_exact
        CHECK (app.authority_canonical_hash_matches(canonical_bytes, workspace_managed_confirmation_revocation_hash)),
    ADD CONSTRAINT workspace_managed_grant_revocation_canonical_bounded
        CHECK (octet_length(canonical_bytes) BETWEEN 1 AND 65536);

-- ---------------------------------------------------------------------------
-- 4.1. Exact receipt gate.
-- ---------------------------------------------------------------------------

-- Resolves the one receipt an authority INSERT is allowed to rely on and
-- proves it is exact and fresh: same tenant, same actor, same command_id, same
-- operation, and still PENDING. A terminal receipt, another actor's receipt,
-- another tenant's receipt or a receipt of a different operation can never
-- authorize an authority row.
--
-- SECURITY DEFINER because the gate must read the receipt independently of the
-- caller's row-level visibility. It returns the whole receipt row, including
-- canonical_request_bytes and idempotency_key_hash, so it is deliberately
-- never granted to the runtime role: only the SECURITY DEFINER trigger guards
-- below call it, and they return a verdict rather than any receipt content.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_fresh_receipt(
    expected_organization_id text,
    expected_command_id text,
    expected_operation text,
    expected_actor_principal_id text
)
RETURNS public.workspace_managed_authority_command_receipt
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
    receipt public.workspace_managed_authority_command_receipt%ROWTYPE;
BEGIN
    SELECT *
    INTO receipt
    FROM public.workspace_managed_authority_command_receipt
    WHERE organization_id = expected_organization_id
      AND command_id = expected_command_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'authority row requires an exact command receipt in the same transaction'
            USING ERRCODE = '23514';
    END IF;
    IF receipt.status <> 'PENDING' THEN
        RAISE EXCEPTION 'authority row requires a fresh pending receipt, not a terminal one'
            USING ERRCODE = '23514';
    END IF;
    IF receipt.operation <> expected_operation THEN
        RAISE EXCEPTION 'authority row operation % does not match its receipt operation %',
            expected_operation, receipt.operation
            USING ERRCODE = '23514';
    END IF;
    IF receipt.actor_principal_id <> expected_actor_principal_id THEN
        RAISE EXCEPTION 'authority row actor does not match its receipt actor' USING ERRCODE = '23514';
    END IF;
    RETURN receipt;
END;
$$;

-- Grant issue gate: exact fresh receipt, exact request projection, and the
-- exact JSON-to-column projection of the stored canonical grant bytes.
CREATE OR REPLACE FUNCTION app.workspace_source_confirmation_actor_grant_receipt_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    receipt public.workspace_managed_authority_command_receipt%ROWTYPE;
    document jsonb;
    current_revision bigint;
    current_configuration_hash text;
BEGIN
    receipt := app.workspace_managed_authority_fresh_receipt(
        NEW.organization_id, NEW.command_id, 'WORKSPACE_CONFIRMATION_GRANT_ISSUE', NEW.granted_by);

    -- Exact operation-specific request projection.
    IF receipt.request_workspace_id <> NEW.workspace_id
       OR receipt.request_target_principal_id <> NEW.principal_id
       OR receipt.request_expected_policy_revision <> NEW.policy_revision
       OR receipt.request_ttl_seconds <> (
              app.authority_timestamp_v1_to_epoch(NEW.valid_until)
              - app.authority_timestamp_v1_to_epoch(NEW.valid_from)) THEN
        RAISE EXCEPTION 'actor grant does not match its receipt request projection' USING ERRCODE = '23514';
    END IF;

    -- The grant-issue request is optimistic: it names the WorkspaceRevision and
    -- configuration hash it expects to be current. Storing those in the receipt
    -- and never applying them would make the precondition decorative, so they
    -- are enforced here against the workspace itself. Both revoke operations
    -- deliberately carry no such expectation — a stale parent must stay
    -- revocable — so neither has an equivalent check.
    SELECT workspace.current_revision, revision.configuration_hash
    INTO current_revision, current_configuration_hash
    FROM public.workspace AS workspace
    JOIN public.workspace_revision AS revision
      ON revision.organization_id = workspace.organization_id
     AND revision.workspace_id = workspace.id
     AND revision.revision = workspace.current_revision
    WHERE workspace.organization_id = NEW.organization_id AND workspace.id = NEW.workspace_id
    FOR SHARE OF workspace;

    IF NOT FOUND
       OR receipt.request_expected_workspace_revision <> current_revision
       OR receipt.request_expected_workspace_configuration_hash <> current_configuration_hash THEN
        RAISE EXCEPTION 'actor grant expected workspace revision or configuration hash is not current'
            USING ERRCODE = '23514';
    END IF;

    -- Server-owned derivation fixed by ADR-0053, including the single
    -- transaction-second: granted_at is the command's one server clock reading,
    -- valid_from equals it, and valid_until is it plus ttl_seconds.
    IF NEW.revision <> 1
       OR NEW.permission <> 'workspace.source.confirm'
       OR NEW.valid_from <> NEW.granted_at
       OR app.authority_timestamp_v1_to_epoch(NEW.granted_at) <> app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'actor grant server-owned derivation is not the exact contract' USING ERRCODE = '23514';
    END IF;

    document := app.authority_canonical_object(NEW.canonical_bytes);
    IF NOT app.authority_object_key_set_is_exact(document, ARRAY[
        'schema_version', 'grant_id', 'revision', 'organization_id', 'workspace_id',
        'principal_id', 'permission', 'valid_from', 'valid_until', 'policy_revision',
        'granted_by', 'granted_at']) THEN
        RAISE EXCEPTION 'actor grant canonical field set is not exact' USING ERRCODE = '23514';
    END IF;
    IF app.authority_json_text(document, 'schema_version')
           IS DISTINCT FROM 'workspace-source-confirmation-grant-v1'
       OR app.authority_json_text(document, 'grant_id') IS DISTINCT FROM NEW.grant_id
       OR app.authority_json_integer(document, 'revision') IS DISTINCT FROM NEW.revision
       OR app.authority_json_text(document, 'organization_id') IS DISTINCT FROM NEW.organization_id
       OR app.authority_json_text(document, 'workspace_id') IS DISTINCT FROM NEW.workspace_id
       OR app.authority_json_text(document, 'principal_id') IS DISTINCT FROM NEW.principal_id
       OR app.authority_json_text(document, 'permission') IS DISTINCT FROM NEW.permission
       OR app.authority_json_text(document, 'valid_from') IS DISTINCT FROM NEW.valid_from
       OR app.authority_json_text(document, 'valid_until') IS DISTINCT FROM NEW.valid_until
       OR app.authority_json_text(document, 'policy_revision') IS DISTINCT FROM NEW.policy_revision
       OR app.authority_json_text(document, 'granted_by') IS DISTINCT FROM NEW.granted_by
       OR app.authority_json_text(document, 'granted_at') IS DISTINCT FROM NEW.granted_at THEN
        RAISE EXCEPTION 'actor grant canonical bytes do not match their relational projection'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_source_confirmation_actor_grant_receipt_gate
BEFORE INSERT ON public.workspace_source_confirmation_actor_grant
FOR EACH ROW EXECUTE FUNCTION app.workspace_source_confirmation_actor_grant_receipt_guard();

-- Grant revoke gate.
CREATE OR REPLACE FUNCTION app.actor_grant_revocation_receipt_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    receipt public.workspace_managed_authority_command_receipt%ROWTYPE;
    document jsonb;
    parent_workspace_id text;
BEGIN
    receipt := app.workspace_managed_authority_fresh_receipt(
        NEW.organization_id, NEW.command_id, 'WORKSPACE_CONFIRMATION_GRANT_REVOKE', NEW.revoked_by);

    SELECT workspace_id
    INTO parent_workspace_id
    FROM public.workspace_source_confirmation_actor_grant
    WHERE organization_id = NEW.organization_id
      AND grant_id = NEW.grant_id
      AND revision = NEW.grant_revision;

    IF NOT FOUND OR receipt.request_workspace_id <> parent_workspace_id
       OR receipt.request_grant_id <> NEW.grant_id
       OR receipt.request_grant_revision <> NEW.grant_revision
       OR receipt.request_grant_hash <> NEW.grant_hash
       OR receipt.request_expected_policy_revision <> NEW.policy_revision THEN
        RAISE EXCEPTION 'actor grant revocation does not match its receipt request projection'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.reason_code <> 'AUTHORITY_REVOKED'
       OR app.authority_timestamp_v1_to_epoch(NEW.revoked_at) <> app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'actor grant revocation reason code or transaction second is not the exact contract'
            USING ERRCODE = '23514';
    END IF;

    document := app.authority_canonical_object(NEW.canonical_bytes);
    IF NOT app.authority_object_key_set_is_exact(document, ARRAY[
        'schema_version', 'revocation_id', 'organization_id', 'grant_id', 'grant_revision',
        'grant_hash', 'revoked_by', 'revoked_at', 'reason_code', 'policy_revision']) THEN
        RAISE EXCEPTION 'actor grant revocation canonical field set is not exact' USING ERRCODE = '23514';
    END IF;
    IF app.authority_json_text(document, 'schema_version')
           IS DISTINCT FROM 'workspace-source-confirmation-grant-revocation-v1'
       OR app.authority_json_text(document, 'revocation_id') IS DISTINCT FROM NEW.revocation_id
       OR app.authority_json_text(document, 'organization_id') IS DISTINCT FROM NEW.organization_id
       OR app.authority_json_text(document, 'grant_id') IS DISTINCT FROM NEW.grant_id
       OR app.authority_json_integer(document, 'grant_revision') IS DISTINCT FROM NEW.grant_revision
       OR app.authority_json_text(document, 'grant_hash') IS DISTINCT FROM NEW.grant_hash
       OR app.authority_json_text(document, 'revoked_by') IS DISTINCT FROM NEW.revoked_by
       OR app.authority_json_text(document, 'revoked_at') IS DISTINCT FROM NEW.revoked_at
       OR app.authority_json_text(document, 'reason_code') IS DISTINCT FROM NEW.reason_code
       OR app.authority_json_text(document, 'policy_revision') IS DISTINCT FROM NEW.policy_revision THEN
        RAISE EXCEPTION 'actor grant revocation canonical bytes do not match their relational projection'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER actor_grant_revocation_receipt_gate
BEFORE INSERT ON public.workspace_source_confirmation_actor_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.actor_grant_revocation_receipt_guard();

-- Managed confirm gate.
CREATE OR REPLACE FUNCTION app.workspace_managed_grant_confirmation_receipt_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    receipt public.workspace_managed_authority_command_receipt%ROWTYPE;
    document jsonb;
BEGIN
    receipt := app.workspace_managed_authority_fresh_receipt(
        NEW.organization_id, NEW.command_id, 'WORKSPACE_MANAGED_CONFIRM', NEW.confirmed_by);

    IF receipt.request_workspace_id <> NEW.workspace_id
       OR receipt.request_workspace_revision <> NEW.workspace_revision
       OR receipt.request_workspace_configuration_hash <> NEW.workspace_configuration_hash
       OR receipt.request_workspace_source_id <> NEW.workspace_source_id
       OR receipt.request_source_scope_id <> NEW.source_scope_id
       OR receipt.request_source_scope_revision <> NEW.source_scope_revision
       OR receipt.request_scope_config_hash <> NEW.scope_config_hash
       OR receipt.request_access_mode <> NEW.access_mode
       OR receipt.request_confirmation_actor_grant_id <> NEW.confirmation_actor_grant_id
       OR receipt.request_confirmation_actor_grant_revision <> NEW.confirmation_actor_grant_revision
       OR receipt.request_confirmation_actor_grant_hash <> NEW.confirmation_actor_grant_hash
       OR receipt.request_warning_version <> NEW.warning_version
       OR receipt.request_warning_contract_hash <> NEW.warning_contract_hash
       OR receipt.request_acknowledgement_code <> NEW.acknowledgement_code
       OR receipt.request_expected_policy_revision <> NEW.policy_revision THEN
        RAISE EXCEPTION 'managed confirmation does not match its receipt request projection'
            USING ERRCODE = '23514';
    END IF;

    -- confirmed_at is the command's one server clock reading. 000010 already
    -- bounds it to the past and to the grant's validity window; this pins it to
    -- the exact transaction-second, so a command cannot spread its server-owned
    -- timestamps across several seconds or borrow an earlier one.
    IF app.authority_timestamp_v1_to_epoch(NEW.confirmed_at) <> app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'managed confirmation confirmed_at is not the command transaction second'
            USING ERRCODE = '23514';
    END IF;

    document := app.authority_canonical_object(NEW.canonical_bytes);
    IF NOT app.authority_object_key_set_is_exact(document, ARRAY[
        'schema_version', 'confirmation_id', 'organization_id', 'workspace_id',
        'workspace_revision', 'workspace_configuration_hash', 'workspace_source_id',
        'source_scope_id', 'source_scope_revision', 'scope_config_hash', 'access_mode',
        'confirmation_actor_grant_id', 'confirmation_actor_grant_revision',
        'confirmation_actor_grant_hash', 'warning_version', 'warning_contract_hash',
        'acknowledgement_code', 'confirmed_by', 'confirmed_at', 'policy_revision']) THEN
        RAISE EXCEPTION 'managed confirmation canonical field set is not exact' USING ERRCODE = '23514';
    END IF;
    IF app.authority_json_text(document, 'schema_version')
           IS DISTINCT FROM 'workspace-managed-confirmation-v1'
       OR app.authority_json_text(document, 'confirmation_id') IS DISTINCT FROM NEW.confirmation_id
       OR app.authority_json_text(document, 'organization_id') IS DISTINCT FROM NEW.organization_id
       OR app.authority_json_text(document, 'workspace_id') IS DISTINCT FROM NEW.workspace_id
       OR app.authority_json_integer(document, 'workspace_revision') IS DISTINCT FROM NEW.workspace_revision
       OR app.authority_json_text(document, 'workspace_configuration_hash')
           IS DISTINCT FROM NEW.workspace_configuration_hash
       OR app.authority_json_text(document, 'workspace_source_id') IS DISTINCT FROM NEW.workspace_source_id
       OR app.authority_json_text(document, 'source_scope_id') IS DISTINCT FROM NEW.source_scope_id
       OR app.authority_json_integer(document, 'source_scope_revision')
           IS DISTINCT FROM NEW.source_scope_revision
       OR app.authority_json_text(document, 'scope_config_hash') IS DISTINCT FROM NEW.scope_config_hash
       OR app.authority_json_text(document, 'access_mode') IS DISTINCT FROM NEW.access_mode
       OR app.authority_json_text(document, 'confirmation_actor_grant_id')
           IS DISTINCT FROM NEW.confirmation_actor_grant_id
       OR app.authority_json_integer(document, 'confirmation_actor_grant_revision')
           IS DISTINCT FROM NEW.confirmation_actor_grant_revision
       OR app.authority_json_text(document, 'confirmation_actor_grant_hash')
           IS DISTINCT FROM NEW.confirmation_actor_grant_hash
       OR app.authority_json_text(document, 'warning_version') IS DISTINCT FROM NEW.warning_version
       OR app.authority_json_text(document, 'warning_contract_hash')
           IS DISTINCT FROM NEW.warning_contract_hash
       OR app.authority_json_text(document, 'acknowledgement_code')
           IS DISTINCT FROM NEW.acknowledgement_code
       OR app.authority_json_text(document, 'confirmed_by') IS DISTINCT FROM NEW.confirmed_by
       OR app.authority_json_text(document, 'confirmed_at') IS DISTINCT FROM NEW.confirmed_at
       OR app.authority_json_text(document, 'policy_revision') IS DISTINCT FROM NEW.policy_revision THEN
        RAISE EXCEPTION 'managed confirmation canonical bytes do not match their relational projection'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_managed_grant_confirmation_receipt_gate
BEFORE INSERT ON public.workspace_managed_grant_confirmation
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_grant_confirmation_receipt_guard();

-- Confirmation revoke gate.
CREATE OR REPLACE FUNCTION app.workspace_managed_grant_revocation_receipt_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    receipt public.workspace_managed_authority_command_receipt%ROWTYPE;
    document jsonb;
    parent_workspace_id text;
BEGIN
    receipt := app.workspace_managed_authority_fresh_receipt(
        NEW.organization_id, NEW.command_id, 'WORKSPACE_MANAGED_CONFIRM_REVOKE', NEW.revoked_by);

    SELECT workspace_id
    INTO parent_workspace_id
    FROM public.workspace_managed_grant_confirmation
    WHERE organization_id = NEW.organization_id
      AND confirmation_id = NEW.confirmation_id;

    IF NOT FOUND OR receipt.request_workspace_id <> parent_workspace_id
       OR receipt.request_confirmation_id <> NEW.confirmation_id
       OR receipt.request_confirmation_hash <> NEW.confirmation_hash
       OR receipt.request_expected_policy_revision <> NEW.policy_revision THEN
        RAISE EXCEPTION 'managed confirmation revocation does not match its receipt request projection'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.reason_code <> 'ACCESS_REVOKED'
       OR app.authority_timestamp_v1_to_epoch(NEW.revoked_at) <> app.authority_transaction_epoch() THEN
        RAISE EXCEPTION 'managed confirmation revocation reason code or transaction second is not the exact contract'
            USING ERRCODE = '23514';
    END IF;

    document := app.authority_canonical_object(NEW.canonical_bytes);
    IF NOT app.authority_object_key_set_is_exact(document, ARRAY[
        'schema_version', 'revocation_id', 'organization_id', 'confirmation_id',
        'confirmation_hash', 'revoked_by', 'revoked_at', 'reason_code', 'policy_revision']) THEN
        RAISE EXCEPTION 'managed confirmation revocation canonical field set is not exact'
            USING ERRCODE = '23514';
    END IF;
    IF app.authority_json_text(document, 'schema_version')
           IS DISTINCT FROM 'workspace-managed-confirmation-revocation-v1'
       OR app.authority_json_text(document, 'revocation_id') IS DISTINCT FROM NEW.revocation_id
       OR app.authority_json_text(document, 'organization_id') IS DISTINCT FROM NEW.organization_id
       OR app.authority_json_text(document, 'confirmation_id') IS DISTINCT FROM NEW.confirmation_id
       OR app.authority_json_text(document, 'confirmation_hash') IS DISTINCT FROM NEW.confirmation_hash
       OR app.authority_json_text(document, 'revoked_by') IS DISTINCT FROM NEW.revoked_by
       OR app.authority_json_text(document, 'revoked_at') IS DISTINCT FROM NEW.revoked_at
       OR app.authority_json_text(document, 'reason_code') IS DISTINCT FROM NEW.reason_code
       OR app.authority_json_text(document, 'policy_revision') IS DISTINCT FROM NEW.policy_revision THEN
        RAISE EXCEPTION 'managed confirmation revocation canonical bytes do not match their relational projection'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER workspace_managed_grant_revocation_receipt_gate
BEFORE INSERT ON public.workspace_managed_grant_revocation
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_grant_revocation_receipt_guard();

-- ---------------------------------------------------------------------------
-- 4.2. SUCCESS receipt binds exactly one authority row.
-- ---------------------------------------------------------------------------

-- Deferred: the repository reserves PENDING, inserts the authority row,
-- appends audit and only then terminalizes the receipt. At commit, a SUCCESS
-- receipt must name exactly one authority row of its own operation, with the
-- exact result ID and hash; a non-SUCCESS terminal receipt must name none.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_result_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    bound_rows bigint;
BEGIN
    IF NEW.status = 'PENDING' THEN
        RETURN NULL;
    END IF;

    SELECT
        (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant AS row
          WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id
            AND NEW.operation = 'WORKSPACE_CONFIRMATION_GRANT_ISSUE'
            AND row.grant_id = NEW.result_authority_id AND row.grant_hash = NEW.result_authority_hash)
      + (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant_revocation AS row
          WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id
            AND NEW.operation = 'WORKSPACE_CONFIRMATION_GRANT_REVOKE'
            AND row.revocation_id = NEW.result_authority_id
            AND row.confirmation_actor_grant_revocation_hash = NEW.result_authority_hash)
      + (SELECT count(*) FROM public.workspace_managed_grant_confirmation AS row
          WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id
            AND NEW.operation = 'WORKSPACE_MANAGED_CONFIRM'
            AND row.confirmation_id = NEW.result_authority_id
            AND row.confirmation_hash = NEW.result_authority_hash)
      + (SELECT count(*) FROM public.workspace_managed_grant_revocation AS row
          WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id
            AND NEW.operation = 'WORKSPACE_MANAGED_CONFIRM_REVOKE'
            AND row.revocation_id = NEW.result_authority_id
            AND row.workspace_managed_confirmation_revocation_hash = NEW.result_authority_hash)
    INTO bound_rows;

    IF NEW.status = 'SUCCESS' AND bound_rows <> 1 THEN
        RAISE EXCEPTION 'successful authority receipt must bind exactly one authority row of its own operation, found %',
            bound_rows
            USING ERRCODE = '23514';
    END IF;

    IF NEW.status <> 'SUCCESS' THEN
        SELECT
            (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant AS row
              WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id)
          + (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant_revocation AS row
              WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id)
          + (SELECT count(*) FROM public.workspace_managed_grant_confirmation AS row
              WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id)
          + (SELECT count(*) FROM public.workspace_managed_grant_revocation AS row
              WHERE row.organization_id = NEW.organization_id AND row.command_id = NEW.command_id)
        INTO bound_rows;
        IF bound_rows <> 0 THEN
            RAISE EXCEPTION 'failed authority receipt must bind zero authority rows, found %', bound_rows
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_managed_authority_command_receipt_result_binding
AFTER INSERT OR UPDATE ON public.workspace_managed_authority_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_result_binding();

-- ---------------------------------------------------------------------------
-- 5. Authority-metadata visibility and INSERT privileges.
-- ---------------------------------------------------------------------------

-- ADR-0053 widens authority-metadata visibility beyond plain workspace
-- membership, for authority metadata ONLY. This predicate never appears in any
-- source-content, evidence or retrieval policy: it grants no content access.
CREATE OR REPLACE FUNCTION app.authority_metadata_is_visible(
    row_organization_id text,
    row_workspace_id text,
    self_principal_ids text[]
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT row_organization_id = app.current_organization_id()
       AND (
           -- Existing membership visibility, preserved for retrieval.
           EXISTS (
               SELECT 1 FROM public.workspace_member AS member
               WHERE member.organization_id = row_organization_id
                 AND member.workspace_id = row_workspace_id
                 AND member.principal_id = app.current_principal_id()
                 AND member.removed_at IS NULL
           )
           -- Organization OWNER/ADMIN authority metadata visibility.
           OR EXISTS (
               SELECT 1 FROM public.organization_role_assignment AS assignment
               WHERE assignment.organization_id = row_organization_id
                 AND assignment.principal_id = app.current_principal_id()
                 AND assignment.role IN ('OWNER', 'ADMIN')
                 AND assignment.revoked_at IS NULL
           )
           -- Exact self-grant / self-confirmation principal.
           OR app.current_principal_id() = ANY (self_principal_ids)
       );
$$;

-- The four authority relations keep FORCE RLS. Their tenant-isolation policy
-- is replaced by an explicit read policy (existing membership visibility plus
-- the ADR-0053 authority-metadata visibility) and an explicit INSERT policy.
-- INSERT WITH CHECK is deliberately only a tenant fence: the exact
-- receipt/actor/operation/projection proof is the BEFORE INSERT gate above,
-- and it is not weakened by this policy. No UPDATE or DELETE policy exists, so
-- the runtime role has no row it may ever mutate or remove.

DROP POLICY workspace_source_confirmation_actor_grant_tenant_isolation
    ON public.workspace_source_confirmation_actor_grant;
CREATE POLICY workspace_source_confirmation_actor_grant_authority_read
    ON public.workspace_source_confirmation_actor_grant
    FOR SELECT
    -- Self-visibility is the exact grant principal only. The issuer
    -- (granted_by) is deliberately absent: ADR-0053 gives an issuer access
    -- through their current Organization OWNER/ADMIN role, not through a
    -- personal disjunct. Adding granted_by here would keep a former issuer who
    -- lost that role able to distinguish DENIED from NOT_FOUND, which is a
    -- narrow existence oracle.
    USING (app.authority_metadata_is_visible(
        organization_id, workspace_id, ARRAY[principal_id]));
CREATE POLICY workspace_source_confirmation_actor_grant_receipt_insert
    ON public.workspace_source_confirmation_actor_grant
    FOR INSERT
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY actor_grant_revocation_tenant_isolation
    ON public.workspace_source_confirmation_actor_grant_revocation;
CREATE POLICY actor_grant_revocation_authority_read
    ON public.workspace_source_confirmation_actor_grant_revocation
    FOR SELECT
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1
            FROM public.workspace_source_confirmation_actor_grant AS parent
            WHERE parent.organization_id = workspace_source_confirmation_actor_grant_revocation.organization_id
              AND parent.grant_id = workspace_source_confirmation_actor_grant_revocation.grant_id
              AND parent.revision = workspace_source_confirmation_actor_grant_revocation.grant_revision
              AND app.authority_metadata_is_visible(
                  parent.organization_id, parent.workspace_id,
                  ARRAY[parent.principal_id])
        )
    );
CREATE POLICY actor_grant_revocation_receipt_insert
    ON public.workspace_source_confirmation_actor_grant_revocation
    FOR INSERT
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY workspace_managed_grant_confirmation_tenant_isolation
    ON public.workspace_managed_grant_confirmation;
CREATE POLICY workspace_managed_grant_confirmation_authority_read
    ON public.workspace_managed_grant_confirmation
    FOR SELECT
    USING (app.authority_metadata_is_visible(
        organization_id, workspace_id, ARRAY[confirmed_by]));
CREATE POLICY workspace_managed_grant_confirmation_receipt_insert
    ON public.workspace_managed_grant_confirmation
    FOR INSERT
    WITH CHECK (organization_id = app.current_organization_id());

DROP POLICY workspace_managed_grant_revocation_tenant_isolation
    ON public.workspace_managed_grant_revocation;
CREATE POLICY workspace_managed_grant_revocation_authority_read
    ON public.workspace_managed_grant_revocation
    FOR SELECT
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1
            FROM public.workspace_managed_grant_confirmation AS parent
            WHERE parent.organization_id = workspace_managed_grant_revocation.organization_id
              AND parent.confirmation_id = workspace_managed_grant_revocation.confirmation_id
              AND app.authority_metadata_is_visible(
                  parent.organization_id, parent.workspace_id,
                  ARRAY[parent.confirmed_by])
        )
    );
CREATE POLICY workspace_managed_grant_revocation_receipt_insert
    ON public.workspace_managed_grant_revocation
    FOR INSERT
    WITH CHECK (organization_id = app.current_organization_id());

-- INSERT only. UPDATE/DELETE are never granted: 000010 already installed the
-- append-only immutability triggers, and withholding the privilege keeps the
-- runtime role from even attempting a mutation.
GRANT INSERT ON TABLE public.workspace_source_confirmation_actor_grant TO knowvault_app;
GRANT INSERT ON TABLE public.workspace_source_confirmation_actor_grant_revocation TO knowvault_app;
GRANT INSERT ON TABLE public.workspace_managed_grant_confirmation TO knowvault_app;
GRANT INSERT ON TABLE public.workspace_managed_grant_revocation TO knowvault_app;

-- ---------------------------------------------------------------------------
-- 6. Authority audit contract.
-- ---------------------------------------------------------------------------

-- ADR-0053: "A later migration adds WORKSPACE_AUTHORITY_COMMAND to the
-- resource-type enum and these four actions to the action registry." This is
-- that migration.
ALTER TABLE public.audit_event
    DROP CONSTRAINT audit_event_resource_type_check;
ALTER TABLE public.audit_event
    ADD CONSTRAINT audit_event_resource_type_check CHECK (resource_type IN (
        'ORGANIZATION', 'IDENTITY', 'WORKSPACE', 'WORKSPACE_MEMBER',
        'WORKSPACE_SOURCE', 'WORKSPACE_AUTHORITY_COMMAND',
        'SOURCE_CONNECTION', 'SOURCE_SCOPE',
        'SOURCE_OBJECT', 'QUESTION_RUN', 'CITATION', 'MODEL_RUN', 'POLICY',
        'SIGNING_KEY', 'AUDIT_CHECKPOINT'
    ));

-- The authority audit vocabulary is content-free: operation, server-owned
-- result/parent/revocation IDs and hashes, the trusted target tuple and the
-- policy revision. No title, path, content, warning text, credential, prompt,
-- answer, evidence, request canonical bytes, request hash or raw
-- Idempotency-Key is representable here.
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
               'warning_version', 'warning_contract_hash', 'acknowledgement_code'
           )
       );
$$;

-- 000009 reserved the workspace-source metadata vocabulary to
-- workspace.source_added/removed events. WORKSPACE_MANAGED_CONFIRM legitimately
-- shares part of that vocabulary (workspace_revision, workspace_source_id,
-- scope_config_hash, access_mode), so the reserved-vocabulary branch is
-- narrowed to exempt authority events. The workspace-source projection itself
-- is otherwise untouched, and 'enabled' remains exclusive to it: no authority
-- metadata set below contains it.
CREATE OR REPLACE FUNCTION app.workspace_source_audit_projection_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    expected_enabled boolean;
BEGIN
    IF NEW.action IN ('workspace.source_added', 'workspace.source_removed') THEN
        expected_enabled := NEW.action = 'workspace.source_added';
        IF NEW.resource_type <> 'WORKSPACE_SOURCE'
           OR (NEW.outcome = 'SUCCESS' AND NEW.workspace_id IS NULL)
           OR NEW.policy_decision_id IS NOT NULL
           OR NEW.referenced_evidence_ids_json <> '[]'::jsonb
           OR (SELECT count(*) FROM jsonb_object_keys(NEW.metadata_json)) <> 7
           OR NOT (NEW.metadata_json ?& ARRAY[
                'workspace_revision', 'workspace_source_id',
                'source_scope_id', 'source_scope_revision',
                'scope_config_hash', 'access_mode', 'enabled'
           ])
           OR NOT app.workspace_source_audit_integer_is_valid(NEW.metadata_json -> 'workspace_revision')
           OR jsonb_typeof(NEW.metadata_json -> 'workspace_source_id') <> 'string'
           OR NOT app.workspace_source_generated_id_is_valid(NEW.metadata_json ->> 'workspace_source_id', 'binding')
           OR NEW.resource_id <> NEW.metadata_json ->> 'workspace_source_id'
           OR jsonb_typeof(NEW.metadata_json -> 'source_scope_id') <> 'string'
           OR NOT app.workspace_source_generated_id_is_valid(NEW.metadata_json ->> 'source_scope_id', 'scope')
           OR NOT app.workspace_source_audit_integer_is_valid(NEW.metadata_json -> 'source_scope_revision')
           OR jsonb_typeof(NEW.metadata_json -> 'scope_config_hash') <> 'string'
           OR NOT app.stage2_sha256_is_valid(NEW.metadata_json ->> 'scope_config_hash')
           OR jsonb_typeof(NEW.metadata_json -> 'access_mode') <> 'string'
           OR NEW.metadata_json ->> 'access_mode' NOT IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')
           OR jsonb_typeof(NEW.metadata_json -> 'enabled') <> 'boolean'
           OR (NEW.metadata_json ->> 'enabled')::boolean IS DISTINCT FROM expected_enabled THEN
            RAISE EXCEPTION 'workspace source audit projection is not exact'
                USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.resource_type <> 'WORKSPACE_AUTHORITY_COMMAND'
      AND (NEW.resource_type = 'WORKSPACE_SOURCE'
           OR NEW.metadata_json ? 'workspace_revision'
           OR NEW.metadata_json ? 'workspace_source_id'
           OR NEW.metadata_json ? 'scope_config_hash'
           OR NEW.metadata_json ? 'access_mode'
           OR NEW.metadata_json ? 'enabled') THEN
        RAISE EXCEPTION 'workspace source audit vocabulary is reserved'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.authority_audit_action_for_operation(operation text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE operation
        WHEN 'WORKSPACE_CONFIRMATION_GRANT_ISSUE' THEN 'workspace.source_confirmation_grant_issued'
        WHEN 'WORKSPACE_CONFIRMATION_GRANT_REVOKE' THEN 'workspace.source_confirmation_grant_revoked'
        WHEN 'WORKSPACE_MANAGED_CONFIRM' THEN 'workspace.source_confirmed'
        WHEN 'WORKSPACE_MANAGED_CONFIRM_REVOKE' THEN 'workspace.source_confirmation_revoked'
        ELSE NULL
    END;
$$;

CREATE OR REPLACE FUNCTION app.authority_audit_operation_for_action(action text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE action
        WHEN 'workspace.source_confirmation_grant_issued' THEN 'WORKSPACE_CONFIRMATION_GRANT_ISSUE'
        WHEN 'workspace.source_confirmation_grant_revoked' THEN 'WORKSPACE_CONFIRMATION_GRANT_REVOKE'
        WHEN 'workspace.source_confirmed' THEN 'WORKSPACE_MANAGED_CONFIRM'
        WHEN 'workspace.source_confirmation_revoked' THEN 'WORKSPACE_MANAGED_CONFIRM_REVOKE'
        ELSE NULL
    END;
$$;

-- Receipt status maps to audit outcome and error code exhaustively and without
-- exception (ADR-0053). NOT_FOUND deliberately collapses onto outcome DENIED so
-- a hidden workspace stays indistinguishable from an insufficient role in the
-- audit trail itself; the finer distinction lives only in the error code.
CREATE OR REPLACE FUNCTION app.authority_audit_outcome_for_status(status text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE status
        WHEN 'SUCCESS' THEN 'SUCCESS'
        WHEN 'DENIED' THEN 'DENIED'
        WHEN 'NOT_FOUND' THEN 'DENIED'
        WHEN 'PRECONDITION_FAILED' THEN 'FAILED'
        ELSE NULL
    END;
$$;

CREATE OR REPLACE FUNCTION app.authority_audit_error_code_for_status(status text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE status
        WHEN 'SUCCESS' THEN NULL
        WHEN 'DENIED' THEN 'WORKSPACE_AUTHORITY_DENIED'
        WHEN 'NOT_FOUND' THEN 'WORKSPACE_AUTHORITY_NOT_FOUND'
        WHEN 'PRECONDITION_FAILED' THEN 'WORKSPACE_AUTHORITY_PRECONDITION_FAILED'
        ELSE NULL
    END;
$$;

-- Closed metadata set per action and outcome. A failure carries exactly one
-- key, because nothing else was proven current at the point of failure.
CREATE OR REPLACE FUNCTION app.authority_audit_metadata_is_exact(
    action text, outcome text, metadata jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
-- An unknown action resolves to NULL expected keys, and NULL must mean "no",
-- not "anything goes": app.authority_object_key_set_is_exact() coalesces a NULL
-- expectation into the empty set, which an empty metadata object would satisfy.
-- The explicit NOT NULL test below keeps this CHECK a real second line of
-- defence behind the BEFORE INSERT action/resource pairing gate.
AS $$
    SELECT resolved.expected_keys IS NOT NULL
       AND app.authority_object_key_set_is_exact(metadata, resolved.expected_keys)
    FROM (SELECT CASE
        WHEN outcome <> 'SUCCESS' THEN ARRAY['authority_operation']
        WHEN action = 'workspace.source_confirmation_grant_issued' THEN ARRAY[
            'authority_operation', 'authority_result_id', 'authority_result_hash',
            'target_principal_id', 'policy_revision']
        WHEN action IN (
            'workspace.source_confirmation_grant_revoked',
            'workspace.source_confirmation_revoked') THEN ARRAY[
            'authority_operation', 'authority_parent_id', 'authority_parent_hash',
            'authority_revocation_id', 'authority_revocation_hash',
            'authority_reason_code', 'policy_revision']
        WHEN action = 'workspace.source_confirmed' THEN ARRAY[
            'authority_operation', 'authority_result_id', 'authority_result_hash',
            'workspace_revision', 'workspace_configuration_hash', 'workspace_source_id',
            'source_scope_id', 'source_scope_revision', 'scope_config_hash', 'access_mode',
            'confirmation_actor_grant_id', 'confirmation_actor_grant_revision',
            'confirmation_actor_grant_hash', 'warning_version', 'warning_contract_hash',
            'acknowledgement_code', 'policy_revision']
        ELSE NULL
    END AS expected_keys) AS resolved;
$$;

ALTER TABLE public.audit_event
    ADD CONSTRAINT audit_event_authority_metadata_exact CHECK (
        resource_type <> 'WORKSPACE_AUTHORITY_COMMAND'
        OR app.authority_audit_metadata_is_exact(action, outcome, metadata_json)
    );

-- Exact authority audit shape. Everything here is fixed by ADR-0053 for all
-- four actions on every terminal outcome.
CREATE OR REPLACE FUNCTION app.authority_audit_projection_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    operation text;
BEGIN
    operation := app.authority_audit_operation_for_action(NEW.action);

    -- The four authority actions and the WORKSPACE_AUTHORITY_COMMAND resource
    -- type are a strict one-to-one pair: neither may appear without the other.
    IF (operation IS NULL) <> (NEW.resource_type <> 'WORKSPACE_AUTHORITY_COMMAND') THEN
        RAISE EXCEPTION 'authority audit action and resource type must agree' USING ERRCODE = '23514';
    END IF;

    IF operation IS NULL THEN
        -- The authority vocabulary is reserved, exactly as 000009 reserved the
        -- workspace-source vocabulary to its own two actions. Without this an
        -- unrelated event could carry authority_operation or a result hash and
        -- the closed per-action sets would only constrain the four actions that
        -- already declare themselves. The Go validator refuses the same shape
        -- (audit.hasAuthorityMetadata); the two must not disagree.
        IF NEW.metadata_json ?| ARRAY[
            'authority_operation', 'authority_result_id', 'authority_result_hash',
            'authority_parent_id', 'authority_parent_hash', 'authority_revocation_id',
            'authority_revocation_hash', 'authority_reason_code', 'target_principal_id',
            'workspace_configuration_hash', 'confirmation_actor_grant_id',
            'confirmation_actor_grant_revision', 'confirmation_actor_grant_hash',
            'warning_version', 'warning_contract_hash', 'acknowledgement_code'
        ] THEN
            RAISE EXCEPTION 'workspace-managed authority audit vocabulary is reserved'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.actor_type <> 'HUMAN'
       OR NEW.actor_principal_id IS NULL
       OR NEW.on_behalf_of_principal_id IS NOT NULL
       OR NEW.policy_decision_id IS NOT NULL
       OR NEW.referenced_evidence_ids_json <> '[]'::jsonb THEN
        RAISE EXCEPTION 'authority audit event shape is not the exact contract' USING ERRCODE = '23514';
    END IF;

    -- Outcome/error-code pairing, exhaustive and without exception. This is the
    -- whole status-to-outcome contract on the audit side; the receipt half is
    -- proved by the deferred receipt/audit binding, which is the only place
    -- that can see receipt.status at all.
    IF NOT (
        (NEW.outcome = 'SUCCESS' AND NEW.error_code IS NULL)
        OR (NEW.outcome = 'DENIED' AND NEW.error_code IN (
               'WORKSPACE_AUTHORITY_DENIED', 'WORKSPACE_AUTHORITY_NOT_FOUND'))
        OR (NEW.outcome = 'FAILED' AND NEW.error_code = 'WORKSPACE_AUTHORITY_PRECONDITION_FAILED')
    ) THEN
        RAISE EXCEPTION 'authority audit outcome/error code pairing is not the exact contract'
            USING ERRCODE = '23514';
    END IF;

    -- NOT_FOUND must never leak a workspace ID through the one path a caller
    -- cannot avoid seeing.
    IF NEW.error_code = 'WORKSPACE_AUTHORITY_NOT_FOUND' AND NEW.workspace_id IS NOT NULL THEN
        RAISE EXCEPTION 'authority audit NOT_FOUND must not name a workspace' USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'SUCCESS' AND NEW.workspace_id IS NULL THEN
        RAISE EXCEPTION 'successful authority audit must name its workspace' USING ERRCODE = '23514';
    END IF;
    IF NEW.error_code = 'WORKSPACE_AUTHORITY_PRECONDITION_FAILED' AND NEW.workspace_id IS NULL THEN
        RAISE EXCEPTION 'authority audit PRECONDITION_FAILED must name its workspace' USING ERRCODE = '23514';
    END IF;

    IF app.authority_json_text(NEW.metadata_json, 'authority_operation') IS DISTINCT FROM operation THEN
        RAISE EXCEPTION 'authority audit metadata operation does not match its action' USING ERRCODE = '23514';
    END IF;

    IF NEW.outcome = 'SUCCESS' THEN
        IF NEW.action = 'workspace.source_confirmation_grant_revoked'
           AND app.authority_json_text(NEW.metadata_json, 'authority_reason_code')
               IS DISTINCT FROM 'AUTHORITY_REVOKED' THEN
            RAISE EXCEPTION 'grant revocation audit reason code is not the fixed contract'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.action = 'workspace.source_confirmation_revoked'
           AND app.authority_json_text(NEW.metadata_json, 'authority_reason_code')
               IS DISTINCT FROM 'ACCESS_REVOKED' THEN
            RAISE EXCEPTION 'confirmation revocation audit reason code is not the fixed contract'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.action = 'workspace.source_confirmed'
           AND app.authority_json_text(NEW.metadata_json, 'access_mode') IS DISTINCT FROM 'WORKSPACE_MANAGED' THEN
            RAISE EXCEPTION 'confirmation audit access mode is not the fixed contract' USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_authority_projection
BEFORE INSERT ON public.audit_event
FOR EACH ROW EXECUTE FUNCTION app.authority_audit_projection_guard();

-- Exact receipt -> audit binding, deferred because ADR-0053 orders the
-- transaction as: append the audit event while the receipt is still PENDING,
-- then terminalize the receipt. At commit the pair must agree exactly.
CREATE OR REPLACE FUNCTION app.workspace_managed_authority_receipt_audit_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    event public.audit_event%ROWTYPE;
BEGIN
    IF NEW.status = 'PENDING' THEN
        RETURN NULL;
    END IF;

    SELECT * INTO event
    FROM public.audit_event
    WHERE organization_id = NEW.organization_id AND id = NEW.audit_event_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'terminal authority receipt must bind one audit event' USING ERRCODE = '23514';
    END IF;

    IF event.resource_type <> 'WORKSPACE_AUTHORITY_COMMAND'
       OR event.resource_id <> NEW.command_id
       OR event.action IS DISTINCT FROM app.authority_audit_action_for_operation(NEW.operation)
       OR event.outcome IS DISTINCT FROM app.authority_audit_outcome_for_status(NEW.status)
       OR event.error_code IS DISTINCT FROM app.authority_audit_error_code_for_status(NEW.status)
       OR event.actor_principal_id IS DISTINCT FROM NEW.actor_principal_id THEN
        RAISE EXCEPTION 'authority receipt and its audit event do not agree exactly'
            USING ERRCODE = '23514';
    END IF;

    -- AuditEvent.workspace_id follows its own exhaustive rule, distinct from
    -- resource_id: exact on SUCCESS and PRECONDITION_FAILED, always null on
    -- NOT_FOUND, and on DENIED exact only when same-tenant visibility was
    -- already established (so either value is contract-legal there).
    IF NEW.status IN ('SUCCESS', 'PRECONDITION_FAILED')
       AND event.workspace_id IS DISTINCT FROM NEW.request_workspace_id THEN
        RAISE EXCEPTION 'authority audit workspace_id must be the exact workspace on %', NEW.status
            USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'NOT_FOUND' AND event.workspace_id IS NOT NULL THEN
        RAISE EXCEPTION 'authority audit workspace_id must be null on NOT_FOUND' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'DENIED'
       AND event.workspace_id IS NOT NULL
       AND event.workspace_id <> NEW.request_workspace_id THEN
        RAISE EXCEPTION 'authority audit workspace_id must be null or the exact workspace on DENIED'
            USING ERRCODE = '23514';
    END IF;

    -- The operation is the one key every outcome carries, and it is the
    -- receipt's operation rather than anything the caller chose.
    IF app.authority_json_text(event.metadata_json, 'authority_operation') IS DISTINCT FROM NEW.operation THEN
        RAISE EXCEPTION 'authority audit metadata operation does not match its receipt' USING ERRCODE = '23514';
    END IF;

    IF NEW.status = 'SUCCESS' THEN
        PERFORM app.authority_audit_metadata_matches_row(NEW.organization_id, NEW.command_id,
            NEW.operation, event.metadata_json);
    END IF;

    RETURN NULL;
END;
$$;

-- Exact SUCCESS metadata binding.
--
-- The closed per-action key set proves only the *shape* of the metadata. On its
-- own that leaves the values free: a command could persist grant A and describe
-- grant B in the audit trail with a structurally perfect metadata set — right
-- keys, right types, right hash format, right operation — and nothing would
-- notice. ADR-0053 requires SUCCESS metadata to come from trusted persisted
-- result and parent projections, never from the unverified request, so every
-- value is re-read here from the row that was actually written and compared
-- field for field. This runs deferred, at commit, because that is the first
-- point at which both the authority row and the audit event exist.
CREATE OR REPLACE FUNCTION app.authority_audit_metadata_matches_row(
    expected_organization_id text,
    expected_command_id text,
    expected_operation text,
    metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    grant_row public.workspace_source_confirmation_actor_grant%ROWTYPE;
    grant_revocation public.workspace_source_confirmation_actor_grant_revocation%ROWTYPE;
    confirmation public.workspace_managed_grant_confirmation%ROWTYPE;
    confirmation_revocation public.workspace_managed_grant_revocation%ROWTYPE;
    parent_grant public.workspace_source_confirmation_actor_grant%ROWTYPE;
    parent_confirmation public.workspace_managed_grant_confirmation%ROWTYPE;
BEGIN
    IF expected_operation = 'WORKSPACE_CONFIRMATION_GRANT_ISSUE' THEN
        SELECT * INTO grant_row FROM public.workspace_source_confirmation_actor_grant
        WHERE organization_id = expected_organization_id AND command_id = expected_command_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'successful grant issue has no authority row to describe' USING ERRCODE = '23514';
        END IF;
        IF app.authority_json_text(metadata, 'authority_result_id') IS DISTINCT FROM grant_row.grant_id
           OR app.authority_json_text(metadata, 'authority_result_hash') IS DISTINCT FROM grant_row.grant_hash
           OR app.authority_json_text(metadata, 'target_principal_id') IS DISTINCT FROM grant_row.principal_id
           OR app.authority_json_text(metadata, 'policy_revision') IS DISTINCT FROM grant_row.policy_revision THEN
            RAISE EXCEPTION 'grant issue audit metadata does not match the created grant' USING ERRCODE = '23514';
        END IF;

    ELSIF expected_operation = 'WORKSPACE_CONFIRMATION_GRANT_REVOKE' THEN
        SELECT * INTO grant_revocation FROM public.workspace_source_confirmation_actor_grant_revocation
        WHERE organization_id = expected_organization_id AND command_id = expected_command_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'successful grant revoke has no authority row to describe' USING ERRCODE = '23514';
        END IF;
        SELECT * INTO parent_grant FROM public.workspace_source_confirmation_actor_grant
        WHERE organization_id = expected_organization_id
          AND grant_id = grant_revocation.grant_id
          AND revision = grant_revocation.grant_revision;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'grant revocation has no parent grant to describe' USING ERRCODE = '23514';
        END IF;
        IF app.authority_json_text(metadata, 'authority_parent_id') IS DISTINCT FROM parent_grant.grant_id
           OR app.authority_json_text(metadata, 'authority_parent_hash') IS DISTINCT FROM parent_grant.grant_hash
           OR app.authority_json_text(metadata, 'authority_revocation_id')
               IS DISTINCT FROM grant_revocation.revocation_id
           OR app.authority_json_text(metadata, 'authority_revocation_hash')
               IS DISTINCT FROM grant_revocation.confirmation_actor_grant_revocation_hash
           OR app.authority_json_text(metadata, 'authority_reason_code') IS DISTINCT FROM grant_revocation.reason_code
           OR app.authority_json_text(metadata, 'policy_revision') IS DISTINCT FROM grant_revocation.policy_revision THEN
            RAISE EXCEPTION 'grant revoke audit metadata does not match the created revocation' USING ERRCODE = '23514';
        END IF;

    ELSIF expected_operation = 'WORKSPACE_MANAGED_CONFIRM' THEN
        SELECT * INTO confirmation FROM public.workspace_managed_grant_confirmation
        WHERE organization_id = expected_organization_id AND command_id = expected_command_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'successful confirm has no authority row to describe' USING ERRCODE = '23514';
        END IF;
        IF app.authority_json_text(metadata, 'authority_result_id') IS DISTINCT FROM confirmation.confirmation_id
           OR app.authority_json_text(metadata, 'authority_result_hash')
               IS DISTINCT FROM confirmation.confirmation_hash
           OR app.authority_json_integer(metadata, 'workspace_revision')
               IS DISTINCT FROM confirmation.workspace_revision
           OR app.authority_json_text(metadata, 'workspace_configuration_hash')
               IS DISTINCT FROM confirmation.workspace_configuration_hash
           OR app.authority_json_text(metadata, 'workspace_source_id')
               IS DISTINCT FROM confirmation.workspace_source_id
           OR app.authority_json_text(metadata, 'source_scope_id') IS DISTINCT FROM confirmation.source_scope_id
           OR app.authority_json_integer(metadata, 'source_scope_revision')
               IS DISTINCT FROM confirmation.source_scope_revision
           OR app.authority_json_text(metadata, 'scope_config_hash') IS DISTINCT FROM confirmation.scope_config_hash
           OR app.authority_json_text(metadata, 'access_mode') IS DISTINCT FROM confirmation.access_mode
           OR app.authority_json_text(metadata, 'confirmation_actor_grant_id')
               IS DISTINCT FROM confirmation.confirmation_actor_grant_id
           OR app.authority_json_integer(metadata, 'confirmation_actor_grant_revision')
               IS DISTINCT FROM confirmation.confirmation_actor_grant_revision
           OR app.authority_json_text(metadata, 'confirmation_actor_grant_hash')
               IS DISTINCT FROM confirmation.confirmation_actor_grant_hash
           OR app.authority_json_text(metadata, 'warning_version') IS DISTINCT FROM confirmation.warning_version
           OR app.authority_json_text(metadata, 'warning_contract_hash')
               IS DISTINCT FROM confirmation.warning_contract_hash
           OR app.authority_json_text(metadata, 'acknowledgement_code')
               IS DISTINCT FROM confirmation.acknowledgement_code
           OR app.authority_json_text(metadata, 'policy_revision') IS DISTINCT FROM confirmation.policy_revision THEN
            RAISE EXCEPTION 'confirm audit metadata does not match the created confirmation' USING ERRCODE = '23514';
        END IF;

    ELSE
        SELECT * INTO confirmation_revocation FROM public.workspace_managed_grant_revocation
        WHERE organization_id = expected_organization_id AND command_id = expected_command_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'successful confirm revoke has no authority row to describe' USING ERRCODE = '23514';
        END IF;
        SELECT * INTO parent_confirmation FROM public.workspace_managed_grant_confirmation
        WHERE organization_id = expected_organization_id
          AND confirmation_id = confirmation_revocation.confirmation_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'confirmation revocation has no parent confirmation to describe' USING ERRCODE = '23514';
        END IF;
        IF app.authority_json_text(metadata, 'authority_parent_id')
               IS DISTINCT FROM parent_confirmation.confirmation_id
           OR app.authority_json_text(metadata, 'authority_parent_hash')
               IS DISTINCT FROM parent_confirmation.confirmation_hash
           OR app.authority_json_text(metadata, 'authority_revocation_id')
               IS DISTINCT FROM confirmation_revocation.revocation_id
           OR app.authority_json_text(metadata, 'authority_revocation_hash')
               IS DISTINCT FROM confirmation_revocation.workspace_managed_confirmation_revocation_hash
           OR app.authority_json_text(metadata, 'authority_reason_code')
               IS DISTINCT FROM confirmation_revocation.reason_code
           OR app.authority_json_text(metadata, 'policy_revision')
               IS DISTINCT FROM confirmation_revocation.policy_revision THEN
            RAISE EXCEPTION 'confirm revoke audit metadata does not match the created revocation'
                USING ERRCODE = '23514';
        END IF;
    END IF;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_managed_authority_receipt_audit_binding
AFTER INSERT OR UPDATE ON public.workspace_managed_authority_command_receipt
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_authority_receipt_audit_binding();

-- The reverse direction: an authority audit event is never orphaned. Exactly
-- one terminal receipt must claim it, which is what makes "one audit event per
-- terminal receipt, and none for PENDING, invalid requests, idempotency
-- conflicts or replays" enforceable rather than merely intended.
CREATE OR REPLACE FUNCTION app.authority_audit_event_is_claimed()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    claiming_receipts bigint;
BEGIN
    IF NEW.resource_type <> 'WORKSPACE_AUTHORITY_COMMAND' THEN
        RETURN NULL;
    END IF;

    SELECT count(*)
    INTO claiming_receipts
    FROM public.workspace_managed_authority_command_receipt AS receipt
    WHERE receipt.organization_id = NEW.organization_id
      AND receipt.audit_event_id = NEW.id
      AND receipt.status <> 'PENDING';

    IF claiming_receipts <> 1 THEN
        RAISE EXCEPTION 'authority audit event must be claimed by exactly one terminal receipt, found %',
            claiming_receipts
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER audit_event_authority_is_claimed
AFTER INSERT ON public.audit_event
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.authority_audit_event_is_claimed();

-- ---------------------------------------------------------------------------
-- 7. Commit-time current policy and warning protection.
-- ---------------------------------------------------------------------------

-- ADR-0053: "a policy or warning advance between reservation and commit must
-- roll back and fail closed."
--
-- 000010's app.authority_current_policy_guard() runs BEFORE INSERT only, so it
-- proves the policy was current at INSERT time, not at commit time. An
-- organization policy advance committed by a concurrent transaction between
-- the authority INSERT and this transaction's commit would otherwise leave a
-- row claiming a policy revision that is no longer current. This deferred gate
-- re-reads the same projection at commit and fails the whole transaction
-- closed; it never switches an already-chosen terminal branch to another
-- status, it only rolls back.
CREATE OR REPLACE FUNCTION app.authority_current_policy_deferred_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    current_policy bigint;
BEGIN
    -- FOR SHARE is load-bearing, not decoration. A plain SELECT here closes
    -- nothing: under REPEATABLE READ or SERIALIZABLE it reads this
    -- transaction's snapshot, so a concurrent policy advance is invisible and
    -- the gate degrades into a silent no-op; and even under READ COMMITTED an
    -- advance that commits after this trigger fires but before we do would slip
    -- through. The share lock blocks a concurrent
    -- `UPDATE organization SET policy_revision` until this transaction ends, and
    -- under the stricter isolation levels it raises a serialization failure
    -- instead of reading stale data. Either way the whole transaction fails
    -- closed, which is what ADR-0053 requires.
    SELECT policy_revision INTO current_policy
    FROM public.organization
    WHERE id = NEW.organization_id
    FOR SHARE;

    IF NOT FOUND OR current_policy <> NEW.policy_revision_number THEN
        RAISE EXCEPTION '% lost the current organization policy revision before commit', TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_source_confirmation_actor_grant_policy_at_commit
AFTER INSERT ON public.workspace_source_confirmation_actor_grant
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_deferred_guard();

CREATE CONSTRAINT TRIGGER actor_grant_revocation_policy_at_commit
AFTER INSERT ON public.workspace_source_confirmation_actor_grant_revocation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_deferred_guard();

CREATE CONSTRAINT TRIGGER workspace_managed_grant_confirmation_policy_at_commit
AFTER INSERT ON public.workspace_managed_grant_confirmation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_deferred_guard();

CREATE CONSTRAINT TRIGGER workspace_managed_grant_revocation_policy_at_commit
AFTER INSERT ON public.workspace_managed_grant_revocation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_deferred_guard();

-- A confirmation additionally binds the warning registry head. 000010's
-- derived-live validator already re-checks the current warning revision at
-- commit for confirmations, so this gate adds the one projection it does not
-- cover: the exact warning tuple must still be the registry head.
CREATE OR REPLACE FUNCTION app.workspace_managed_confirmation_warning_at_commit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    head_version text;
    head_hash text;
BEGIN
    -- 000010's confirmation exact guard already re-reads the warning head at
    -- commit, so the re-read below is not what this gate adds. What it adds is
    -- the pair below: a lock that stops an advance landing between the check
    -- and the commit, and an isolation assertion without which that lock would
    -- be serializing a re-read that cannot observe the advance anyway.
    --
    -- The warning registry is global and append-only, so its head is
    -- max(revision) rather than a row anyone can lock. `SELECT ... FOR SHARE` on
    -- the current head would therefore prove nothing: it cannot block the INSERT
    -- of a *new* revision, which is exactly how the head moves.
    --
    -- While 000010's immutability guard stands the head cannot move at all and
    -- no runtime race exists to win. This gate is what keeps the invariant true
    -- for the future migration that drops that guard to introduce a v2
    -- contract, which is the one writer the protocol permits.
    --
    -- SHARE is the minimal table-level mode that conflicts with the ROW
    -- EXCLUSIVE an INSERT takes, while remaining self-compatible so concurrent
    -- confirmations never block each other. Taking it here serializes the two
    -- directions of the race:
    --   * an advance already in flight holds ROW EXCLUSIVE, so this lock waits
    --     for it, and the re-read below then sees the new head and fails closed;
    --   * an advance that has not started yet is blocked until this transaction
    --     commits, so it cannot slip in between this check and commit.
    -- An advance that lands strictly after this command commits is not a race:
    -- ADR-0052 derives staleness from the current registry rather than
    -- rewriting historical confirmation provenance.
    --
    -- Introducing a mutable warning head to make this lockable would need its
    -- own ADR, so this checkpoint serializes instead.
    -- The lock serializes the writer, but it cannot advance this transaction's
    -- snapshot. Under REPEATABLE READ or SERIALIZABLE the re-read below would
    -- see the pre-advance snapshot and pass — the same silent no-op the policy
    -- gate avoids with FOR SHARE, which is unavailable here because the head is
    -- not a row. The policy gate fails closed under those levels on its own
    -- (a locked row updated by a committed transaction raises 40001); this gate
    -- has no row to lock and so no such signal, and would degrade silently.
    -- It therefore asserts its own precondition instead of assuming it.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION
            'workspace managed confirmations require READ COMMITTED: the warning contract head is not a lockable row, so a snapshot-bound re-read cannot observe an advance'
            USING ERRCODE = '55000';
    END IF;

    LOCK TABLE public.workspace_managed_warning_contract IN SHARE MODE;

    SELECT warning_version, warning_contract_hash
    INTO head_version, head_hash
    FROM public.workspace_managed_warning_contract
    WHERE revision = app.workspace_managed_warning_contract_current_revision();

    IF NOT FOUND
       OR head_version IS DISTINCT FROM NEW.warning_version
       OR head_hash IS DISTINCT FROM NEW.warning_contract_hash THEN
        RAISE EXCEPTION 'workspace managed confirmation lost the current warning contract before commit'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_managed_grant_confirmation_warning_at_commit
AFTER INSERT ON public.workspace_managed_grant_confirmation
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_managed_confirmation_warning_at_commit();

-- ---------------------------------------------------------------------------
-- 8. Lock down every helper/trigger function introduced above.
-- ---------------------------------------------------------------------------

-- No PUBLIC privileges, and no EXECUTE for the runtime role on any mutating or
-- gate function: knowvault_app reaches these only implicitly, as triggers the
-- database fires on its behalf. There is no generic mutating SECURITY DEFINER
-- tool here — every SECURITY DEFINER function above is a closed assertion that
-- returns a verdict and mutates nothing.
REVOKE ALL ON FUNCTION
    app.authority_canonical_hash_matches(bytea, text),
    app.authority_canonical_object(bytea),
    app.authority_object_key_set_is_exact(jsonb, text[]),
    app.authority_json_text(jsonb, text),
    app.authority_json_integer(jsonb, text),
    app.workspace_managed_authority_receipt_projection_guard(),
    app.workspace_managed_authority_receipt_insert_guard(),
    app.workspace_managed_authority_receipt_terminal_guard(),
    app.workspace_managed_authority_receipt_no_delete(),
    app.workspace_managed_authority_receipt_no_pending_commit(),
    app.workspace_managed_authority_fresh_receipt(text, text, text, text),
    app.workspace_source_confirmation_actor_grant_receipt_guard(),
    app.actor_grant_revocation_receipt_guard(),
    app.workspace_managed_grant_confirmation_receipt_guard(),
    app.workspace_managed_grant_revocation_receipt_guard(),
    app.workspace_managed_authority_receipt_result_binding(),
    app.authority_metadata_is_visible(text, text, text[]),
    app.authority_audit_action_for_operation(text),
    app.authority_audit_operation_for_action(text),
    app.authority_audit_outcome_for_status(text),
    app.authority_audit_error_code_for_status(text),
    app.authority_audit_metadata_is_exact(text, text, jsonb),
    app.authority_audit_projection_guard(),
    app.workspace_managed_authority_receipt_audit_binding(),
    app.authority_audit_metadata_matches_row(text, text, text, jsonb),
    app.authority_audit_event_is_claimed(),
    app.authority_current_policy_deferred_guard(),
    app.workspace_managed_confirmation_warning_at_commit()
FROM PUBLIC;

-- The RLS read policies above call app.authority_metadata_is_visible() as the
-- runtime role, so it needs EXECUTE. It is a read-only STABLE predicate that
-- returns a boolean and mutates nothing.
GRANT EXECUTE ON FUNCTION app.authority_metadata_is_visible(text, text, text[]) TO knowvault_app;

-- A CHECK constraint is evaluated as the *inserting* role, so every function
-- reachable from a CHECK on a table knowvault_app may now INSERT into needs
-- EXECUTE for that role — SECURITY DEFINER does not help a CHECK helper.
-- Until this migration the runtime role had SELECT only on the four authority
-- relations, so these CHECKs never fired for it and the missing grants were
-- invisible.
--
-- Each of these is a pure, read-only, IMMUTABLE validator that takes scalars
-- and returns a verdict. None of them mutates anything, and none of them is a
-- gate: the receipt/actor/operation proof lives in the trigger guards above,
-- which stay unreachable to the runtime role. This is deliberately not a
-- blanket EXECUTE on the new helper surface — the JSON projection helpers and
-- app.workspace_managed_authority_fresh_receipt() remain revoked, because the
-- guards that call them are SECURITY DEFINER and resolve them as the owner.
GRANT EXECUTE ON FUNCTION
    app.authority_canonical_hash_matches(bytea, text),
    app.authority_timestamp_v1_is_valid(text),
    app.authority_timestamp_v1_to_epoch(text)
TO knowvault_app;

-- Reachable from the audit_event metadata CHECK, so the inserting role needs
-- EXECUTE for the same reason as the validators above. It is SECURITY DEFINER
-- purely so its one nested helper, app.authority_object_key_set_is_exact(),
-- resolves as the owner and can stay revoked from the runtime role. It reads
-- nothing, writes nothing and returns a boolean.
GRANT EXECUTE ON FUNCTION app.authority_audit_metadata_is_exact(text, text, jsonb) TO knowvault_app;

COMMIT;
