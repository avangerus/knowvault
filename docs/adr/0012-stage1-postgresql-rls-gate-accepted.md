# ADR-0012: Stage 1 PostgreSQL access gate

Status: accepted.

The first runtime database feature is not a generic repository or workspace
endpoint. It is a fail-closed PostgreSQL boundary:

- `knowvault_app` is a dedicated non-owner, non-superuser, non-BYPASSRLS role;
- every tenant table has `organization_id NOT NULL` except the organization root,
  whose `id` is its tenant boundary;
- every tenant relation uses `ENABLE` plus `FORCE ROW LEVEL SECURITY`;
- an application transaction may begin only through
  `internal/platform/database`, after the authenticated organization, principal
  and request identifiers are validated and installed by transaction-local
  `set_config` calls;
- raw pools are private, and application-role DELETE is not granted;
- a deferred database constraint keeps exactly one active organization owner and
  exactly one active workspace owner at transaction commit;
- an executable PostgreSQL integration test proves no-context denial,
  cross-organization isolation, forced RLS and absence of DELETE privilege.

The migration role is operationally separate from the runtime role. Runtime
processes never run migrations and must reject a connection whose session role
is not exactly `knowvault_app` or has superuser/BYPASSRLS authority.

This gate does not yet introduce OIDC, SCIM, REST workspace CRUD, audit rows or
`sqlc` output. Those follow only after this base has passed in CI.
