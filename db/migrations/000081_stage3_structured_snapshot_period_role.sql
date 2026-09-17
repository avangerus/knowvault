-- FIX-3 #1: the owner's declared PERIOD role on a structured source's column
-- contract (internal/source/postgresqlquery/contract.go RolePeriod) reaches
-- the reducer through this column, exactly the way title_role already carries
-- the declared TITLE role (000073). A projection with two temporal columns
-- and no declared PERIOD still gets no free pass here -- the reducer
-- (internal/question/snapshot_aggregate.go) still declines with a
-- clarification unless exactly one of the row's temporal cells is
-- period_role; a single temporal column behaves exactly as before regardless
-- of this flag.

BEGIN;

ALTER TABLE public.structured_snapshot_cell
    ADD COLUMN period_role boolean NOT NULL DEFAULT false;

-- A row already published before this migration (title_role backfilled at
-- publish time, never retroactively) is not retroactively re-derived either:
-- it simply carries period_role = false, exactly as if the owner had never
-- declared PERIOD for that source, which is the safe (fail-closed on
-- ambiguity) default this reducer already had.

COMMIT;
