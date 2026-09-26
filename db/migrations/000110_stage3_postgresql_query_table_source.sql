-- ADR-0097: PostgreSQL sources widen from DBA-reviewed VIEW/MATERIALIZED_VIEW
-- projections to ordinary and partitioned base tables. The application-layer
-- rule stays the same as migration 000025 introduced (a projection is an
-- immutable, typed contract; no SQL text is ever stored or accepted). This
-- migration only widens the persisted relation_kind vocabulary so a
-- registered base/partitioned-table projection can commit.

BEGIN;

ALTER TABLE public.postgresql_query_projection
    DROP CONSTRAINT postgresql_query_projection_relation_kind_check,
    ADD CONSTRAINT postgresql_query_projection_relation_kind_check
        CHECK (relation_kind IN ('VIEW', 'MATERIALIZED_VIEW', 'TABLE', 'PARTITIONED_TABLE'));

COMMIT;
