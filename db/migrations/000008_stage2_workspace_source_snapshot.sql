-- Stage 2 inert workspace-source snapshot.
--
-- A binding row is configuration provenance only.  This checkpoint creates no
-- grant confirmation, activation, connector job, ingestion or query authority.

BEGIN;

ALTER TABLE public.source_scope_revision
    ADD CONSTRAINT source_scope_revision_exact_binding_key
    UNIQUE (
        organization_id, source_scope_id, revision,
        scope_config_hash, access_mode
    );

CREATE TABLE public.workspace_source (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    id text NOT NULL CHECK (app.source_generated_id_is_valid(id, 'binding')),
    workspace_id text NOT NULL,
    source_scope_id text NOT NULL,
    added_by text NOT NULL,
    added_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, id),
    CONSTRAINT workspace_source_workspace_fk
        FOREIGN KEY (organization_id, workspace_id)
        REFERENCES public.workspace (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_scope_fk
        FOREIGN KEY (organization_id, source_scope_id)
        REFERENCES public.source_scope (organization_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT workspace_source_actor_fk
        FOREIGN KEY (organization_id, added_by)
        REFERENCES public.principal (organization_id, id)
        ON DELETE RESTRICT,
    UNIQUE (organization_id, workspace_id, id, source_scope_id),
    UNIQUE (organization_id, workspace_id, source_scope_id)
);

CREATE TABLE public.workspace_revision_source (
    organization_id text NOT NULL,
    workspace_id text NOT NULL,
    workspace_revision bigint NOT NULL
        CHECK (workspace_revision BETWEEN 1 AND 9007199254740991),
    workspace_configuration_hash text NOT NULL
        CHECK (app.workspace_command_hash_is_valid(workspace_configuration_hash)),
    workspace_source_id text NOT NULL,
    source_scope_id text NOT NULL,
    source_scope_revision bigint NOT NULL
        CHECK (source_scope_revision BETWEEN 1 AND 9007199254740991),
    scope_config_hash text NOT NULL
        CHECK (app.stage2_sha256_is_valid(scope_config_hash)),
    access_mode text NOT NULL
        CHECK (access_mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')),
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (
        organization_id, workspace_id, workspace_revision, workspace_source_id
    ),
    CONSTRAINT workspace_revision_source_exact_workspace_snapshot_fk
        FOREIGN KEY (
            organization_id, workspace_id, workspace_revision,
            workspace_configuration_hash
        ) REFERENCES public.workspace_revision_snapshot (
            organization_id, workspace_id, revision, configuration_hash
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT workspace_revision_source_exact_binding_fk
        FOREIGN KEY (
            organization_id, workspace_id, workspace_source_id, source_scope_id
        ) REFERENCES public.workspace_source (
            organization_id, workspace_id, id, source_scope_id
        ) ON DELETE RESTRICT,
    CONSTRAINT workspace_revision_source_exact_scope_revision_fk
        FOREIGN KEY (
            organization_id, source_scope_id, source_scope_revision,
            scope_config_hash, access_mode
        ) REFERENCES public.source_scope_revision (
            organization_id, source_scope_id, revision,
            scope_config_hash, access_mode
        ) ON DELETE RESTRICT,
    UNIQUE (
        organization_id, workspace_id, workspace_revision, source_scope_id
    )
);

CREATE OR REPLACE FUNCTION app.workspace_source_snapshot_exact_guard()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    target_organization_id text;
    target_workspace_id text;
    target_workspace_revision bigint;
    snapshot_row public.workspace_revision_snapshot%ROWTYPE;
    canonical_document jsonb;
    expected_bindings jsonb;
    actual_bindings jsonb;
BEGIN
    target_organization_id := COALESCE(NEW.organization_id, OLD.organization_id);
    target_workspace_id := COALESCE(NEW.workspace_id, OLD.workspace_id);
    IF TG_TABLE_NAME = 'workspace_revision_snapshot' THEN
        target_workspace_revision := COALESCE(NEW.revision, OLD.revision);
    ELSE
        target_workspace_revision := COALESCE(NEW.workspace_revision, OLD.workspace_revision);
    END IF;

    -- Forward-FK tenant hard deletion may remove the relational projection
    -- before the historical canonical snapshot is purged by its own owner.
    IF TG_OP = 'DELETE' AND EXISTS (
        SELECT 1 FROM public.organization
        WHERE id = target_organization_id AND status IN ('DELETING', 'DELETED')
    ) THEN
        RETURN NULL;
    END IF;

    SELECT * INTO snapshot_row
    FROM public.workspace_revision_snapshot
    WHERE organization_id = target_organization_id
      AND workspace_id = target_workspace_id
      AND revision = target_workspace_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'workspace source snapshot lacks exact workspace revision snapshot'
            USING ERRCODE = '23503';
    END IF;

    BEGIN
        canonical_document := convert_from(snapshot_row.canonical_bytes, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'workspace source snapshot canonical bytes are invalid JSON'
            USING ERRCODE = '23514';
    END;

    expected_bindings := canonical_document -> 'source_bindings';
    IF canonical_document ->> 'schema_version' <> 'workspace-configuration-v1'
       OR canonical_document ->> 'organization_id' <> target_organization_id
       OR canonical_document ->> 'workspace_id' <> target_workspace_id
       OR (canonical_document ->> 'revision')::bigint <> target_workspace_revision
       OR jsonb_typeof(expected_bindings) <> 'array' THEN
        RAISE EXCEPTION 'workspace source snapshot canonical identity is invalid'
            USING ERRCODE = '23514';
    END IF;

    SELECT COALESCE(
        jsonb_agg(
            jsonb_build_object(
                'source_scope_id', source_scope_id,
                'source_scope_revision', source_scope_revision,
                'scope_config_hash', scope_config_hash,
                'enabled', enabled
            ) ORDER BY source_scope_id
        ),
        '[]'::jsonb
    ) INTO actual_bindings
    FROM public.workspace_revision_source
    WHERE organization_id = target_organization_id
      AND workspace_id = target_workspace_id
      AND workspace_revision = target_workspace_revision
      AND workspace_configuration_hash = snapshot_row.configuration_hash;

    IF expected_bindings <> actual_bindings THEN
        RAISE EXCEPTION 'workspace source rows do not exactly equal canonical source bindings'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workspace_revision_source_exact_set
AFTER INSERT OR UPDATE OR DELETE ON public.workspace_revision_source
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_source_snapshot_exact_guard();

CREATE CONSTRAINT TRIGGER workspace_revision_snapshot_exact_source_set
AFTER INSERT OR UPDATE ON public.workspace_revision_snapshot
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.workspace_source_snapshot_exact_guard();

CREATE TRIGGER workspace_source_immutable
BEFORE UPDATE OR DELETE ON public.workspace_source
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

CREATE TRIGGER workspace_revision_source_immutable
BEFORE UPDATE OR DELETE ON public.workspace_revision_source
FOR EACH ROW EXECUTE FUNCTION app.source_immutable_or_hard_delete_guard();

ALTER TABLE public.workspace_source ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_source FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_source_tenant_isolation ON public.workspace_source
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_source.organization_id
              AND member.workspace_id = workspace_source.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );

ALTER TABLE public.workspace_revision_source ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_revision_source FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_revision_source_tenant_isolation ON public.workspace_revision_source
    USING (
        organization_id = app.current_organization_id()
        AND EXISTS (
            SELECT 1 FROM public.workspace_member AS member
            WHERE member.organization_id = workspace_revision_source.organization_id
              AND member.workspace_id = workspace_revision_source.workspace_id
              AND member.principal_id = app.current_principal_id()
              AND member.removed_at IS NULL
        )
    );

REVOKE ALL ON TABLE
    public.workspace_source,
    public.workspace_revision_source
FROM PUBLIC;

GRANT SELECT ON TABLE
    public.workspace_source,
    public.workspace_revision_source
TO knowvault_app;

REVOKE ALL ON FUNCTION app.workspace_source_snapshot_exact_guard() FROM PUBLIC;

COMMIT;
