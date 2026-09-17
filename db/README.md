# Database scaffold

Stage 0 intentionally contains no tenant or business tables. The first migration is a
no-op syntax sentinel, and the only query is a connectivity probe.

`sqlc.yaml` is the source for future generated query types. Generation is not performed
until the exact `sqlc v1.31.1` artifact from `architecture/versions.json` is available in
the reviewed offline tool bundle. A locally discovered or downloaded `sqlc` binary must
not be used.

Stage 1 starts with `000001_stage1_tenancy.sql`. It creates the organization,
principal, organization-role, workspace, workspace-revision and workspace-member
relations, then enables and forces RLS before application queries exist. The
runtime `knowvault_app` role is not a table owner, cannot bypass RLS and has no
`DELETE` privilege. A transaction without `app.organization_id` sees zero tenant
rows.

`000002_stage1_audit.sql` adds the content-free `audit-event-v1` relation and
per-organization chain head. Both relations force RLS. The application can
insert an event only via the typed `internal/audit` store, which derives JCS
canonical bytes, SHA-256 hash, sequence and previous hash. Runtime UPDATE and
DELETE are denied; a chain race is a bounded transaction retry, never a fork.

`000003_stage1_identity.sql` adds the read-only OIDC identity and server-session
foundation. `000004_stage1_workspace_command_idempotency.sql` adds actor-scoped
workspace command receipts plus exact canonical revision snapshots.
The receipt, workspace mutation, revision snapshot and audit event commit in
one transaction; a deferred database constraint rejects a committed `PENDING`
receipt, while terminal receipts and revision snapshots are append-only.
The same migration also installs deferred runtime command gates. A direct
`knowvault_app` workspace, revision, snapshot or membership mutation can commit
only when the transaction contains one fresh successful receipt whose immutable
intent, exact revision, audit actor/action/resource/outcome and resulting domain
effect agree. Old receipts and reused audit events are rejected.

The Stage 1 integration suite creates an isolated `knowvault_test` database,
applies every Stage 1 migration, and proves no-context denial, cross-organization isolation,
owner invariants, runtime-role delete denial, audit append-only behavior and a
concurrent chain race. It also proves exact idempotent replay, concurrent command
collapse, current-access replay checks and receipt/snapshot immutability. It is required in CI; locally it
is skipped unless `KNOWVAULT_TEST_POSTGRES_URL` targets that dedicated database.

`sqlc` output remains forbidden. It will be introduced only after the reviewed
offline `sqlc v1.31.1` artifact and an explicit repository-query gate are added.

`000010_stage2_workspace_managed_confirmation_authority.sql` (ADR-0052) adds the
`WORKSPACE_MANAGED` confirmation authority foundation as a strictly inert,
SELECT-only persistence checkpoint: `organization_policy_revision` (the
append-only, monotonic-not-contiguous bridge from the numeric
`organization.policy_revision` counter to the opaque `policy_revision_id`),
the sealed `workspace_managed_warning_contract` v1 registry, the actor grant
and its revocation, and the confirmation and its revocation. A single shared
insert guard requires every new authority row's own `policy_revision_number`
to exact-match the organization's *current* counter, independent of what
policy any parent row references, so a stale grant or confirmation can still
be revoked while the revocation's own provenance is never itself stale. An
expired or not-yet-started actor grant can never mint a new confirmation even
with a historical `confirmed_at`, because both the historical timestamp and
the live PostgreSQL transaction second are checked against the grant's
`[valid_from, valid_until)` window. Every authority ID (`grant_id`,
`confirmation_id`, both `revocation_id` columns) is validated as an opaque ID,
not the source connection/scope/binding ULID-shaped generated-ID contract.
Grant and confirmation revocation both serialize with confirmation and source
commands through the same `workspace` row lock; the derived-live validator
(itself run under that lock) exact-matches every element of the live tuple —
workspace configuration hash, binding, scope ID/revision/hash, access mode,
enabled state, current policy and current warning — and considers both
revocation relations, so two concurrent grants can never both commit an
ambiguous live confirmation. "Current warning" is defined as the
`workspace_managed_warning_contract` row with the maximum `revision`, not
merely any historical row a confirmation's stored `warning_version`/hash
happen to match: the confirmation exact guard rejects a new confirmation that
names a stale warning revision, and the derived-live validator makes an
existing confirmation stale the moment a higher warning revision is
registered, exactly mirroring how a workspace or policy advance already makes
a confirmation stale. All test/integration timestamps in this checkpoint's
suite are derived from one live `transaction_timestamp()` snapshot rather than
a calendar-fixed date, so the positive-path tests never expire.

Canonical hash boundary: this checkpoint does not implement a second,
self-made JCS engine inside PostgreSQL. Every authority `*_hash` column is a
closed relational projection plus a SHA-256 format check and an exact
child-to-parent hash foreign key; exact field-to-JCS-hash validation remains a
mandatory gate of the next Go authority-command checkpoint, which must
recompute canonical bytes/hash in Go, hold a fresh idempotent command
receipt, and append a matching audit event in the same transaction before any
authority row is ever inserted by application code. Until that checkpoint
lands, `knowvault_app` has SELECT only on every table this migration
introduces; no API, repository command, receipt, audit event, outbox event,
activation, connector job, ingestion, retrieval or search authority exists
yet, and a confirmation row alone activates nothing.

`scripts/check-architecture.go` enforces this checkpoint with a dedicated
`checkWorkspaceManagedConfirmationAuthorityMigration` guard: it fails closed
on a missing table, a missing or weakened safe-integer policy-counter bound,
a missing current-policy guard trigger on *any one* of the four authority
tables individually (not just an aggregate count across all four, which
cannot tell two triggers stacked on one table apart from none on another), a
regression back to the source generated-ID validator for an authority ID, a
missing configuration hash in the confirmation's exact target key/FK, lost
`FORCE ROW LEVEL SECURITY`, any `knowvault_app` grant beyond `SELECT`, any
`EXECUTE` grant on a new helper function, a missing workspace row lock, a
derived-live validator missing either revocation relation or its current-
warning-revision join, a confirmation exact guard missing its own current-
warning-revision check, a weakened warning v1 hash/acknowledgement, a mutable
`status`/`revoked_at` column appearing on the grant or confirmation tables, or
any receipt/API/outbox/activation/job/ingestion/retrieval authority appearing
in this migration.
