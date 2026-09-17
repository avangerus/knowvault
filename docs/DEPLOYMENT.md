# Production deployment operations (R2)

This document is the single operator-visible deployment reference. The
executable is one static binary, `knowvault-operator` (ADR-0069). Every command
it runs either reports success or emits a typed `operator-failure-v1` record;
there is no silent fallback (OPS-010).

## Topology

| Component | Database identity | Mounts | Configuration |
|---|---|---|---|
| `knowvault-server` | `knowvault_app` | `/run/knowvault/secrets` (server mount), `/run/knowvault/trust` | 4 allowlisted `KNOWVAULT_*` env vars |
| `knowvault-worker` | `knowvault_worker` | `/run/knowvault/secrets` (worker mount), `/run/knowvault/trust`, `/run/knowvault/sources` | 5 allowlisted `KNOWVAULT_*` env vars |
| `knowvault-sandbox-dispatcher` | dedicated dispatcher boundary | four owner-only sockets under `/run/knowvault/sandbox` | 15 allowlisted `KNOWVAULT_*` env vars |
| `knowvault-operator` | admin URL (bootstrap and readiness) | protected input files, server/worker secret mounts and trust mount | flags + `KNOWVAULT_OPERATOR_ADMIN_URL` |
| static OIDC IdP | — | none | issuer + `oidc-ca.pem` |
| PostgreSQL | `postgres` (admin) | — | `sslmode=verify-full` behind `database-ca.pem` |

The `knowvault_purger` role is created by the operator and reserved for the
purge component; no process currently connects as it.

The scratch operator image intentionally ships no system CA store. Mount the
deployment database CA read-only and set `SSL_CERT_FILE` to that PEM for every
subcommand that opens the admin URL. `readiness -trust-mount` separately loads
the product's purpose-separated database/OIDC bundle for the two runtime-role
probes; it is not an implicit trust fallback for the admin connection.

## Boot order

### 1. Roles and migrations: `bootstrap`

```text
knowvault-operator bootstrap \
  -admin-url postgres://postgres:...@db.example:5432/knowvault?sslmode=verify-full \
  -migrations-dir db/migrations \
  -app-password-file /sealed/app.password \
  -worker-password-file /sealed/worker.password \
  -purger-password-file /sealed/purger.password
```

- Creates `knowvault_app`, `knowvault_worker`, `knowvault_purger` as
  `LOGIN ... NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
  NOBYPASSRLS`. A role that already exists with any elevated or login-less
  flag is an incompatible deployment state, not repaired silently.
- Applies every `0*.sql` file of the migration directory in lexical order
  under one accounting stream: `operator.schema_migrations (name, checksum,
  applied_at)` with SHA-256 hex checksums. An applied name whose checksum no
  longer matches the file is `MIGRATION_INCOMPATIBLE` and stops the run. A
  non-versioned `*.sql` file in the directory is a deployment input error,
  never a silent skip.
- The accounting stream is admin-only: it is created by the admin connection
  and no grants on `operator.schema_migrations` are issued to the runtime
  roles, so `knowvault_app`/`knowvault_worker`/`knowvault_purger` can neither
  read nor modify migration accounting.
- Repeat runs are state-idempotent: applied migrations are skipped by
  checksum, roles are profile-verified, and each existing role password is
  reconciled to its protected password file. A password rotation therefore
  cannot report green while PostgreSQL still accepts only the old credential.
- Usage errors (unknown subcommand, unknown flag, missing required flags such
  as `-admin-url` with no environment fallback) exit `2` and emit no failure
  record; dependency failures exit `1` with a typed `operator-failure-v1`
  record; green exits `0`.

### 2. Initial owner tenant: `tenant-provision`

Run only after `bootstrap`; the command needs the migrated schema. It creates
the organization, owner principal and OWNER assignment, initial workspace,
canonical revision/snapshot, OWNER membership and `workspace.created` audit
event in one transaction through the product canonicalization/audit contracts:

```text
knowvault-operator tenant-provision \
  -admin-url postgres://postgres:...@db.example:5432/knowvault?sslmode=verify-full \
  -organization org_001 -organization-name "Example Organization" \
  -region ru \
  -owner-principal usr_owner -owner-display-name "Initial Owner" \
  -workspace ws_001 -workspace-name "Operations" \
  -workspace-description "Initial operations workspace"
```

An exact repeat returns `{"created":false}` after verifying every row. Any
partial state, changed payload or cross-tenant identifier collision is
`MIGRATION_INCOMPATIBLE`; the operator never repairs it by overwrite/delete.
This order is mandatory on an empty database: tenant provisioning before
`bootstrap` is a typed red because the required migration relations are absent.

### 3. Identity provider: `provider-register`

```text
knowvault-operator provider-register \
  -admin-url postgres://postgres:...@db.example:5432/knowvault?sslmode=verify-full \
  -organization org_001 -provider provider_001 \
  -issuer https://idp.example \
  -client-id client_001 \
  -client-secret-reference secret_ref_001 \
  -redirect-uri https://vault.example/auth/callback \
  -created-by usr_owner
```

Records the provider and its revision 1 (`["RS256"]`). The recorded
configuration fingerprint is canonical:

```text
sha256:<hex of sha256(4-byte big-endian length prefix + field, per field)>
```

over the fields `issuer | client_id | client_secret_reference | redirect_uri
| "RS256"` in that order: every field is preceded by its own 4-byte
big-endian length prefix, so no field value can be confused with a separator
or a concatenation boundary (a plain `|` join would collide on
`"a","b|c"` and `"a|b","c"`). A repeat registration with the identical
payload verifies the recorded configuration and creates nothing; a
conflicting payload is `MIGRATION_INCOMPATIBLE`, never an overwrite.
- If the issuer is already registered under a different provider id, the
  unique issuer index rejects the insert and registration is
  `MIGRATION_INCOMPATIBLE` (never retryable): the conflict is permanent
  deployment configuration, not a transient race.
- Lock contract: the provider row is locked (`FOR UPDATE`) before its
  revision row is read; any future writer of `oidc_provider_revision` must
  take that lock first.

### 4. Secret mounts: `secrets generate` / `secrets verify`

The server and the worker connect as different database roles, so each
component needs its own mount with its own `db_url` — but both mounts must
share the exact key material and pre-issued IdP client secret, because they
serve one deployment. The operator never creates or rotates the IdP client
secret. Supply the protected file issued by the identity provider to both
mount generations. Generate the server mount first, then the worker mount
reusing its key set:

```text
knowvault-operator secrets generate \
  -out /mnt/sealed/server \
  -organization org_001 -provider provider_001 \
  -database-url-file /sealed/db_url_app \
  -client-secret-file /sealed/oidc-client.secret \
  -client-reference secret_ref_001 \
  -source-credential cred_pg_001=/sealed/customer-db.dsn

knowvault-operator secrets generate \
  -out /mnt/sealed/worker \
  -organization org_001 -provider provider_001 \
  -database-url-file /sealed/db_url_worker \
  -client-secret-file /sealed/oidc-client.secret \
  -client-reference secret_ref_001 \
  -keys-from /mnt/sealed/server

knowvault-operator secrets verify -mount /mnt/sealed/server -organization org_001 -provider provider_001
```

Rules, all enforced fail-closed:

- `db_url` must satisfy the closed production contract: `postgres://`, one
  lowercase DNS host with port, path `/knowvault`, exactly
  `?sslmode=verify-full`, user and password present. The operator rejects
  anything else before writing.
- `-client-secret-file` is mandatory. It must name a protected regular file
  (Linux: root-owned, one link, mode `0400`, `0600`, or `0440` only when its
  group is the pinned runtime GID `65532`; no symlink; bounded to 4 KiB)
  containing a non-empty opaque client secret;
  unsafe, empty, oversized or malformed bytes are rejected before any mount
  file is written. The bytes are copied exactly, without trimming or encoding.
- The client secret is pre-issued deployment input. `secrets generate` never
  generates an IdP client secret; both mounts must receive the same imported
  value.
- An existing `manifest.json` is never overwritten; mount regeneration is a
  reviewed rotation path.
- Every written file is verified through the product loader
  (`secretmount.LoadMounted`) before the command reports success. On hosts
  where the mount boundary is unavailable by design, generation fails closed
  instead of claiming a verified mount.
- `-keys-from` reuses key material and references/versions through the product
  capability API and checks that the imported client secret matches the source
  mount. It is refused while the source mount has an open KEK rotation window
  (ADR-0070 §3): complete the rotation first.
- `-source-credential reference=protected-file` may be repeated for external
  connector credentials (for example a PostgreSQL `verify-full` DSN). The
  reference must exactly match the registered source connection. The file is
  read under the same protected-file boundary as the IdP secret and its bytes
  are never printed. A worker generated with `-keys-from` copies the complete
  source-credential set from the verified server mount.
- Generation writes the published shape directly, matching the image contract
  (`deploy/images/README.md`): files `root:65532` mode `0440`, the mount
  directory `root:65532` mode `0750`. While a file is being written it is
  temporarily write-private (`0400`) and becomes group-readable only after
  the content is synced and closed, so the runtime group can never observe
  partial key material.
- The mount boundary is proven before the first write. The proof covers the
  mount directory itself, not its ancestors: keep every ancestor of the mount
  out of world-writable directories.
- The point-in-time hardening step — remounting the mounts read-only —
  happens after generation and `secrets verify`, before the components
  start. The files are already root-owned by generation, so no ownership
  change is needed; `secrets verify` remains the verification step against
  the hardened mount.
- An interrupted generation can leave written files without a completed
  manifest; a repeat fails with `MOUNT_INVALID` (existing files are never
  overwritten). Remedy: clear the mount directory completely and
  regenerate — a partial mount is never repaired in place.

### 5. Trust bundles

The administrator places exactly two purpose-separated CA bundles in
`/run/knowvault/trust`:

- `database-ca.pem` — CA chain covering the PostgreSQL host;
- `oidc-ca.pem` — CA chain covering the static IdP issuer.

Both files must contain only well-formed CA certificates (no duplicates, no
headers, no non-CA entries). There is no system-pool or environment fallback;
an unreadable or invalid bundle stops startup.

### 5.1 Enterprise retrieval mount

The OpenSearch retrieval capability is mounted separately at
`/run/knowvault/search` with root ownership `root:65532`, directory mode
`0750`, and direct files mode `0440` (the private client key is still
readable only by the pinned runtime group). The fixed file set is:

```text
manifest.json
root-ca.pem
client-cert.pem   # required together with client-key.pem for mTLS
client-key.pem
```

`manifest.json` must have this exact shape; values are deployment-owned and
never request data:

```json
{
  "schema": "knowvault-search-manifest-v1",
  "organization_id": "org_001",
  "endpoint": "https://search.internal.example:9200",
  "index_alias": "org-001-v1",
  "generation": 1,
  "generation_fence": 1,
  "root_ca_file": "root-ca.pem",
  "client_certificate_file": "client-cert.pem",
  "client_key_file": "client-key.pem"
}
```

The server and worker load this mount before exposing the enterprise search
path. The same immutable alias/generation/fence is used by the HTTP/UI/MCP
question authority and the worker-only ordered outbox applier. The mount is a
required enterprise startup capability: missing or malformed material stops
both processes, with no database-only downgrade. OpenSearch still remains a
candidate engine: every hit is re-authorized by PostgreSQL before plaintext
or a citation is disclosed.

### 5.2 Embedding capability mount (V1-C)

The optional CPU embedding channel is mounted at `/run/knowvault/embedding`
with the same ownership/mode convention as the search mount above:
`manifest.json`, `profile.json`, `root-ca.pem`, `client-cert.pem`,
`client-key.pem`. When present and valid, `internal/platform/composition`
wires the real `embedding.Client` as the Model Gateway's `EmbedFunc` and
claim-verifier backing (`modelgateway.DefaultVerifierThreshold`); when
absent, hybrid retrieval stays lexical-only and the interim GENERATIVE
verifier falls back to the deterministic local character-trigram vector
(`modelgateway.LocalHashEmbedFunc`, ADR-0088 GEN-2 addendum) — never a silent
partial claiming to be the real channel. `deploy/compose/bootstrap.sh`
provisions this mount for the one-compose install (see its README's
"Embedding capability — interim scope" for what this activation does and
does not qualify).

### 6. Component startup

`knowvault-server` accepts exactly these four environment variables; any other
`KNOWVAULT_*` variable fails closed:

```text
KNOWVAULT_ORGANIZATION_ID=org_001
KNOWVAULT_PROVIDER_ID=provider_001
KNOWVAULT_PUBLIC_ORIGIN=https://vault.example
KNOWVAULT_HTTP_ADDR=0.0.0.0:8443
```

`knowvault-worker` accepts exactly these five (lease 10..3600, poll 1..300):

```text
KNOWVAULT_ORGANIZATION_ID=org_001
KNOWVAULT_PROVIDER_ID=provider_001
KNOWVAULT_WORKER_ID=worker_001
KNOWVAULT_WORKER_LEASE_SECONDS=60
KNOWVAULT_WORKER_POLL_SECONDS=2
```

`knowvault-sandbox-dispatcher` is a pull-only DispatcherV2 process. It never
starts a parser or accesses the container runtime; the external supervisor
owns one-shot parser processes and the dispatcher only observes and fences
their kernel state. It accepts exactly these fifteen non-secret variables (the
role roots and socket ownership must match the deployment manifest):

```text
KNOWVAULT_DISPATCHER_ROOT_DIR=/run/knowvault/sandbox
KNOWVAULT_DISPATCHER_SUBMIT_SOCKET=unix:///run/knowvault/sandbox/submit/dispatcher.sock
KNOWVAULT_DISPATCHER_HANDOFF_SOCKET=unix:///run/knowvault/sandbox/supervisor/handoff.sock
KNOWVAULT_DISPATCHER_OFFICE_REGISTER_SOCKET=unix:///run/knowvault/sandbox/office/register.sock
KNOWVAULT_DISPATCHER_PDF_REGISTER_SOCKET=unix:///run/knowvault/sandbox/pdf/register.sock
KNOWVAULT_DISPATCHER_SUPERVISOR_UID=0
KNOWVAULT_DISPATCHER_SUPERVISOR_GID=0
KNOWVAULT_DISPATCHER_SUBMITTER_UID=65530
KNOWVAULT_DISPATCHER_SUBMITTER_GID=65530
KNOWVAULT_DISPATCHER_OFFICE_WORKER_UID=65532
KNOWVAULT_DISPATCHER_OFFICE_WORKER_GID=65532
KNOWVAULT_DISPATCHER_PDF_WORKER_UID=65533
KNOWVAULT_DISPATCHER_PDF_WORKER_GID=65533
KNOWVAULT_DISPATCHER_MAX_PAYLOAD_BYTES=67108864
KNOWVAULT_DISPATCHER_FRAME_TIMEOUT_MS=5000
```

The four role roots are pre-created, symlink-free, non-writable by group/world
and owned exactly as declared by `deploy/manifests/sandbox-dispatcher.yaml`.
Startup fails closed if a path, UID/GID, registry tuple, artifact identity or
kernel limit differs; there is no legacy single-socket fallback.

The static broker image is built with `deploy/images/Dockerfile.dispatcher` and
the same digest-pinned Go toolchain as the server and worker. It runs as `0:0`
because the supervisor handoff and kernel observation are privileged boundary
operations. The image does not create the socket tree at runtime and does not
grant container-runtime, database or secret access; the orchestrator supplies
the manifest-owned mounts. Until the external supervisor and parser-worker
acceptance package is signed, this image is a contract artifact only and the
manifest must remain `lifecycle: CONTRACT_ONLY`.

The worker's source mount contract is documented in
`docs/WORKER_OPERATIONS.md`. The server verifies at startup that its database
connection runs as exactly `knowvault_app` (no superuser, no BYPASSRLS); the
worker verifies `knowvault_worker` the same way.

The UI and API expose the same authenticated Question Run authority. Browser
requests use the session cookie plus the origin/CSRF proof. A non-browser
integration may send that same short-lived, server-issued OIDC session token
once as `Authorization: Bearer <token>` (never together with a cookie); this is
not a long-lived service-principal API key. A long-lived service-principal
credential does now exist for agents (V1-C, ADR-0079 §3): a workspace OWNER
issues a bounded-TTL, workspace-scoped "access code" from the workspace's
Access tab (`POST/GET/… /api/v1/workspaces/{id}/access-codes`), and the same
MCP endpoint accepts it as `Authorization: Bearer <access-code>` — a
completely separate authentication path from the human session bearer above,
restricted to `knowvault_question`/`knowvault_evidence_get` and to the
workspaces the code was issued for. See `docs/MCP_ACCESS_CODE.md`. MCP is the
read-only JSON-RPC adapter at `/api/v1/mcp` and accepts `initialize`,
`tools/list`, `knowvault_question`, and the workspace-scoped conversation
list/get/archive tools. Conversation archive still requires the same
Idempotency-Key contract;
no arbitrary SQL or write action is exposed. Workspace creation, source
registration/binding/activation, exact per-workspace source disable/re-enable,
and member changes remain versioned live API operations; the UI dialogs are
clients of those endpoints and never store
local/demo data or credentials.

### 6.1 Install/run smoke (bounded application slice)

Before handing an installation to an operator, run the real containerized
smoke from the repository root:

```powershell
$env:KNOWVAULT_TEST_POSTGRES_URL = 'postgres://.../knowvault_test?sslmode=disable'
$env:KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL = 'postgres://.../external_business?sslmode=disable'
.\scripts\run-install-smoke.ps1 -EvidenceDir out\install-smoke-<run-id>
```

The wrapper requires both the Go toolchain and a reachable Docker daemon,
sets bounded test resources (`GOMAXPROCS=2`, `GOMEMLIMIT=1GiB`), and
executes the real `TestE2ER3FullLoop` from `tests/e2e` followed by
`TestPostgreSQLQueryQuestionWorkspaceIsolation`. The first test builds the pinned
server/worker/harness image, starts real PostgreSQL and OpenSearch containers,
seeds the filesystem source, exercises authenticated REST/MCP and workspace
authorization, and removes its throwaway containers on completion. The second
test connects to the supplied real PostgreSQL endpoints, creates allowlisted
business-object views, publishes two isolated datasets and proves generic
aggregate/RBAC/RLS and Evidence separation.
The wrapper stores the complete JSON event stream, preflight probes and an
atomic `install-smoke-result.json` with SHA-256 references. Missing Docker or
a failed real check is `BLOCKED`/`FAILED`; it is never converted to a skip or
mock result. A smoke `PASS` is evidence for this bounded path only and always
has `release_eligible: false`; the full enterprise DoD still requires the
qualified external providers, connectors, Linux/race/security and operations
acceptance beyond the [pilot scope](PILOT-STATUS.md). Use the
[pilot acceptance checklist](PILOT-ACCEPTANCE.md) for the supported evaluation.

### 7. Readiness and liveness

```text
knowvault-operator readiness \
  -admin-url postgres://postgres:...@db.example:5432/knowvault?sslmode=verify-full \
  -server-mount /mnt/sealed/server \
  -worker-mount /mnt/sealed/worker \
  -trust-mount /run/knowvault/trust \
  -organization org_001 -provider provider_001 \
  -migrations-dir db/migrations
```

All three mount flags are mandatory inputs; there is no `-mount` alias and no
default or cross-component mount fallback. The command emits one
`operator-readiness-v1` report with `readiness_source: "DEPENDENCY_CHECK"`.
`readiness` is true only when every declared dependency is `READY`; `liveness`
reports the operator process evaluation itself and does not claim a worker HTTP
health endpoint or worker heartbeat.

| Dependency | Probe |
|---|---|
| `POSTGRESQL` | connect, all three runtime roles present with the runtime profile, provider registered |
| `SERVER_SECRET_MOUNT` | server mount loads through `secretmount.LoadMounted`, its `DatabaseURL` capability opens a TLS connection, and the live session is exactly `knowvault_app` with the runtime profile and RLS enabled |
| `WORKER_SECRET_MOUNT` | worker mount loads through `secretmount.LoadMounted`, its `DatabaseURL` capability opens a TLS connection, and the live session is exactly `knowvault_worker` with the runtime profile and RLS enabled |
| `TRUST_BUNDLE` | both purpose-separated CA files load through the product trust-bundle loader at the explicit `-trust-mount` root; missing, invalid, aliased or permission-unsafe roots are red |
| `MIGRATION_STATE` | accounting matches the migration directory in both directions, checksums equal |

Each dependency record carries exactly `name` and `status`
(`additionalProperties: false` in the readiness schema); human-readable
detail is emitted only on stderr through the failure record, never inside
the report. Diagnostics are content-free and never include a secret, DSN or
filesystem path.

A red report always maps to a typed failure (`operator-failure-v1`):

| Code | Action | Metric |
|---|---|---|
| `DEPENDENCY_UNAVAILABLE` | `RETRY_AFTER_DEPENDENCY_RECOVERY` | `operator_dependency_failures_total` |
| `MOUNT_INVALID` | `FIX_MOUNT_AND_RESTART` | `operator_mount_failures_total` |
| `MIGRATION_INCOMPATIBLE` | `ROLL_BACK_OR_RUN_COMPATIBLE_MIGRATION` | `operator_migration_failures_total` |
| `RESTORE_NEGATIVE_CHECK_FAILED` | `STOP_AND_RESTORE_FROM_VERIFIED_BACKUP` | `operator_restore_negative_check_failures_total` |

`RESTORE_NEGATIVE_CHECK_FAILED` is reserved by the failure contract for the
restore circuit (ADR-0069 §2); the operator commands of this package never
emit it.

`fallback_allowed` is always `false`. The wire shapes are closed by
`architecture/contracts/operator-failure.schema.json` and
`architecture/contracts/operator-readiness.schema.json`.

## Operational invariants

1. The operator never creates a second implementation of domain rules; every
   check reuses the product package (secretmount, identity, database).
2. Every unavailable dependency surfaces as a typed, operator-visible failure
   with a fixed action and metric (OPS-010). No dependency is assumed ready
   (OPS-011).
3. Applied migrations are immutable; the accounting stream is part of the
   database and is backed up with it.
4. Secret manifests are generated once and verified through the product
   loader; generation refuses to overwrite.
5. A deployment whose runtime role, provider registration, migration
   accounting or mount diverges from what the operator wrote is red, not
   degraded.

## References

- ADR-0069 (deployment operations), ADR-0070 (KEK rotation)
- `architecture/contracts/operator-failure.schema.json`
- `architecture/contracts/operator-readiness.schema.json`
- `docs/WORKER_OPERATIONS.md` (worker mounts and source manifest)
