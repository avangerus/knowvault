-- AGG-1: typed structural values of the CURRENT snapshot of a structured
-- (POSTGRESQL_QUERY) source, plus the tenant reporting calendar used to turn
-- "today"/"yesterday" into a real calendar window.
--
-- Why this relation exists. The product's main job (knowvault-DECISIONS.md 5)
-- is "how many X today", "which vehicles were on a route yesterday" over an
-- operational SQL projection. Those answers must be exact, and an exact answer
-- cannot be reduced from whatever lexical retrieval happened to return: the
-- retrieval budget is finite (maximumSearchHits), so a corpus larger than the
-- budget is permanently PARTIAL and any count taken over that window is a
-- number that silently depends on the search engine. The rendered Evidence
-- cell text is also the wrong input for arithmetic: it is a display string,
-- and its number/date typing lives only in the encrypted artifact.
--
-- So the worker, at publication time -- where the attested typed row already
-- exists -- projects each row's already-published Evidence cells into their
-- typed values. Nothing new crosses the boundary: every row here is derived
-- from a cell that is already an Evidence fragment of the same snapshot, and
-- every read below is still authorized per fragment by
-- app.evidence_fragment_readable. This relation adds no new disclosure; it
-- adds the ability to reduce the WHOLE snapshot deterministically instead of
-- a lexical window of it.
--
-- The tenant reporting calendar is the "today" authority. A date is a calendar
-- fact in someone's time zone, never a string comparison: the reducer asks
-- PostgreSQL for (now() AT TIME ZONE <tenant zone>)::date and compares typed
-- dates, so no Go-side zone database or string prefix match is involved.

BEGIN;

CREATE TABLE public.organization_reporting_calendar (
    organization_id text PRIMARY KEY
        REFERENCES public.organization(id) ON DELETE CASCADE,
    time_zone text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE OR REPLACE FUNCTION app.organization_reporting_calendar_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $guard$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    -- The zone is typed against the server's own zone catalog, not a regex:
    -- an operator cannot store a name that later makes AT TIME ZONE raise
    -- mid-question and turn a wrong configuration into an unavailable answer.
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_timezone_names WHERE name = NEW.time_zone
    ) THEN
        RAISE EXCEPTION 'unknown reporting time zone' USING ERRCODE = '22023';
    END IF;
    NEW.updated_at := transaction_timestamp();
    RETURN NEW;
END;
$guard$;

CREATE TRIGGER organization_reporting_calendar_state_guard
BEFORE INSERT OR UPDATE OR DELETE ON public.organization_reporting_calendar
FOR EACH ROW EXECUTE FUNCTION app.organization_reporting_calendar_guard();

-- UTC is the fail-safe default: an organization that has never declared a
-- reporting zone gets the same calendar the audit chain already uses, never a
-- server-local zone that would differ between deployments of the same tenant.
CREATE OR REPLACE FUNCTION app.organization_reporting_time_zone()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $zone$
    SELECT COALESCE(
        (SELECT time_zone FROM public.organization_reporting_calendar
          WHERE organization_id = app.current_organization_id()),
        'UTC')
$zone$;

CREATE TABLE public.structured_snapshot_cell (
    organization_id text NOT NULL
        REFERENCES public.organization(id) ON DELETE RESTRICT,
    evidence_fragment_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(evidence_fragment_id)),
    source_version_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(source_version_id)),
    source_object_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(source_object_id)),
    column_ordinal integer NOT NULL CHECK (column_ordinal BETWEEN 1 AND 4096),
    column_name text NOT NULL CHECK (
        char_length(column_name) BETWEEN 1 AND 63 AND column_name = btrim(column_name)
        AND column_name !~ '[[:cntrl:]]'
    ),
    logical_type text NOT NULL CHECK (logical_type IN (
        'BOOL', 'INT', 'NUMERIC', 'UUID', 'DATE', 'TIMESTAMP', 'TIMESTAMPTZ', 'TEXT'
    )),
    -- The projection's declared TITLE role is the operator's own statement of
    -- "this column names the thing a row is about". It is what a list answer
    -- enumerates; the reducer never guesses an entity column from the question.
    title_role boolean NOT NULL,
    text_value text,
    numeric_value numeric,
    instant_value timestamptz,
    naive_value timestamp,
    date_value date,
    bool_value boolean,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (organization_id, evidence_fragment_id),
    CONSTRAINT structured_snapshot_cell_fragment_fk
        FOREIGN KEY (organization_id, evidence_fragment_id)
        REFERENCES public.evidence_fragment (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT structured_snapshot_cell_typed_shape_check CHECK (
        (logical_type IN ('TEXT', 'UUID') AND text_value IS NOT NULL
             AND numeric_value IS NULL AND instant_value IS NULL AND naive_value IS NULL
             AND date_value IS NULL AND bool_value IS NULL)
        OR (logical_type IN ('INT', 'NUMERIC') AND numeric_value IS NOT NULL
             AND text_value IS NULL AND instant_value IS NULL AND naive_value IS NULL
             AND date_value IS NULL AND bool_value IS NULL)
        OR (logical_type = 'TIMESTAMPTZ' AND instant_value IS NOT NULL
             AND text_value IS NULL AND numeric_value IS NULL AND naive_value IS NULL
             AND date_value IS NULL AND bool_value IS NULL)
        OR (logical_type = 'TIMESTAMP' AND naive_value IS NOT NULL
             AND text_value IS NULL AND numeric_value IS NULL AND instant_value IS NULL
             AND date_value IS NULL AND bool_value IS NULL)
        OR (logical_type = 'DATE' AND date_value IS NOT NULL
             AND text_value IS NULL AND numeric_value IS NULL AND instant_value IS NULL
             AND naive_value IS NULL AND bool_value IS NULL)
        OR (logical_type = 'BOOL' AND bool_value IS NOT NULL
             AND text_value IS NULL AND numeric_value IS NULL AND instant_value IS NULL
             AND naive_value IS NULL AND date_value IS NULL)
    )
);

CREATE INDEX structured_snapshot_cell_version
    ON public.structured_snapshot_cell (organization_id, source_version_id, column_ordinal);

ALTER TABLE public.organization_reporting_calendar ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_reporting_calendar FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_reporting_calendar_tenant_isolation
    ON public.organization_reporting_calendar
    USING (organization_id = app.current_organization_id());

ALTER TABLE public.structured_snapshot_cell ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.structured_snapshot_cell FORCE ROW LEVEL SECURITY;
CREATE POLICY structured_snapshot_cell_tenant_isolation
    ON public.structured_snapshot_cell
    USING (organization_id = app.current_organization_id())
    WITH CHECK (organization_id = app.current_organization_id());

REVOKE ALL ON TABLE public.structured_snapshot_cell, public.organization_reporting_calendar FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON TABLE public.structured_snapshot_cell TO knowvault_worker;
GRANT SELECT ON TABLE public.structured_snapshot_cell TO knowvault_app;
GRANT SELECT ON TABLE public.organization_reporting_calendar TO knowvault_app, knowvault_worker;
REVOKE ALL ON FUNCTION app.organization_reporting_calendar_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.organization_reporting_time_zone() TO knowvault_app, knowvault_worker;

COMMIT;
