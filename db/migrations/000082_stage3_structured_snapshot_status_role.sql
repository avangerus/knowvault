-- SEED-3 #1: the owner's declared STATUS role on a structured source's column
-- contract (internal/source/postgresqlquery/contract.go RoleStatus) reaches
-- the reducer through this column, exactly the way period_role (000081) and
-- title_role (000073) already carry their own declared roles. The reducer's
-- "overdue"/overdue condition (internal/question/snapshot_aggregate.go)
-- uses it to tell a genuinely overdue row (PERIOD date passed AND status not
-- one of the product's closed-status markers) from one whose due date has
-- passed but that is already closed; a projection with no declared STATUS
-- column still answers the same condition by PERIOD alone, with a disclosed
-- note that status was not considered.

BEGIN;

ALTER TABLE public.structured_snapshot_cell
    ADD COLUMN status_role boolean NOT NULL DEFAULT false;

-- A row already published before this migration (title_role/period_role
-- backfilled at publish time, never retroactively) is not retroactively
-- re-derived either: it simply carries status_role = false, exactly as if
-- the owner had never declared STATUS for that source.

COMMIT;
