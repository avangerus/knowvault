-- 000071: the worker may READ the managed-source confirmation predicate.
--
-- app.source_scope_activation_confirmed (000018) is a STABLE, boolean,
-- SECURITY DEFINER predicate: "is there a live, unrevoked WORKSPACE_MANAGED
-- confirmation for exactly this scope revision and scope-config hash, at the
-- workspace's current revision, on an enabled binding, under the current
-- warning contract". 000018 granted EXECUTE to knowvault_app only, because at
-- that time only the operator-facing :activate/:sync surfaces asked the
-- question; the worker met the same predicate solely from INSIDE
-- app.source_scope_registered_begin_sync, which is SECURITY DEFINER and
-- therefore evaluates it as its own owner.
--
-- V1-A added a second, worker-side asker: the scheduled POSTGRESQL_QUERY
-- refresh (registration.Service.AutoSync -> autoSyncOne) deliberately re-checks
-- every precondition an operator's :sync checks, INCLUDING this one, before it
-- places a scheduled job -- "a scope whose confirmation or trust was revoked
-- since its last sync is silently skipped rather than force-run". Running as
-- knowvault_worker, that call was refused with 42501 permission denied, so
-- every scheduled tick died as SOURCE_PERSISTENCE_FAILED and the "SQL source on
-- a schedule" capability never fired a second sync at all (verified live on the
-- acceptance stand: 44 consecutive failed ticks, no autonomous re-sync ever
-- observed).
--
-- This grant widens nothing. The function returns one boolean, takes no
-- caller-supplied SQL, is tenant-bound by app.current_organization_id() inside
-- its own body, and reads only rows the worker already reaches transitively
-- through app.source_scope_registered_begin_sync. It gives the worker no write
-- capability and no way to make an unconfirmed scope confirmed: a false answer
-- still skips the scope, and begin_sync re-checks the same predicate at claim
-- time as the authoritative gate.

BEGIN;

GRANT EXECUTE ON FUNCTION app.source_scope_activation_confirmed(text, bigint, text) TO knowvault_worker;

COMMIT;
