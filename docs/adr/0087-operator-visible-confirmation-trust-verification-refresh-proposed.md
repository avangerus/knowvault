# ADR-0087: Operator-visible confirmation, trust verification and refresh of workspace-managed sources

Status: proposed.

Date: 2026-09-06.

Owners: product architect, security owner, source/ingestion owner, workspace
authority owner.

Owner sign-off: delegated owner sign-off, curator, 2026-09-05/06. The product
owner delegated every need-owner decision to the curator on 2026-09-05; this
ADR is authored and proposed under that delegation, not final owner
acceptance. It still requires the explicit review this document's Acceptance
tests describe before any status change to `accepted`.

Related: ADR-0053, ADR-0058 §2, ADR-0074, ADR-0086, `PRODUCT_CONSTITUTION.md`
§7, `docs/CANONICALIZATION.md` and `scripts/check-architecture.go`.

## Context

Every source a workspace registers is created `WORKSPACE_MANAGED`; the
registration surface serves no other access mode
(`internal/source/registration/service.go:47-48`, `accessModeManaged =
"WORKSPACE_MANAGED"`, ADR-0074 §1.10). `Activate` gates on that mode: it
refuses unless `target.TrustVerified` is true
(`internal/source/registration/service.go:887`) and, for `WORKSPACE_MANAGED`,
unless `app.source_scope_activation_confirmed(scope, revision,
scope_config_hash)` returns true (`internal/source/registration/service.go:890-899`);
either failure returns the same typed `CodeDenied`
(`internal/source/registration/service.go:941`), with no distinguishing detail
and no route to remedy it. The registration UI drives exactly this path —
register, then bind, then activate
(`web/src/main.tsx:1429-1465`) — and on that denial can only render "Permission
verification incomplete" (`web/src/main.tsx:1251`); there is no button, call or
operator action behind that sentence.

The confirmation authority that `Activate` checks already exists as a fully
specified command chain — `IssueConfirmationGrant`, `ConfirmManagedSource`,
`RevokeConfirmationGrant`, `RevokeManagedConfirmation`
(`internal/workspace/repository/authority_commands.go`) — built exactly to the
canonical envelope, policy matrix, audit and replay rules ADR-0053 froze
before any of that code existed. ADR-0053 is explicit that the boundary it
fixes is "contract-only: … no HTTP, API, UI, MCP, outbox, activation, job,
ingestion or retrieval surface", and `scripts/check-architecture.go`'s
`checkWorkspaceManagedAuthorityCommandRuntime` still enforces exactly that: it
scans `internal`, `cmd`, `api`, `web` and `deploy` for the four operation
tokens and the `WORKSPACE_AUTHORITY_` namespace and reds the build if any of
them appears outside `internal/audit` or the `authority_*.go` files of
`internal/workspace/repository` themselves. In the running system today the
only caller of the four command methods is the e2e test harness
(`tests/e2e/harness/authority.go`) and an equivalent direct-database lab
script — both hold a database connection no operator has. An operator who
hits "Permission verification incomplete" has no product path forward at all.

Trust verification is a second, harder gate on the same road. `DRAFT →
VERIFIED` on `source_connection_trust_projection` is, in the migration's own
words, "a control-plane / admin authority action, not a runtime capability. No
runtime role holds UPDATE on source_connection_trust_projection (000006
grants only SELECT)" (`db/migrations/000014_stage2_catalog_extraction_evidence.sql:1056-1063`),
and ADR-0058 §2 records the same rule: trust is verified only by the
control-plane/admin authority, never by the sync worker under its lease. The
one place this transition happens today is `verifyTrustProjection` in the e2e
harness, which opens an admin-credentialed pool and issues the `UPDATE`
directly (`tests/e2e/harness/authority.go:82-104`) — "trust verification is an
external connector act, not a product API," in that function's own comment.
An organization role named exactly for this, `CONNECTOR_ADMIN`, is already
declared in the role check constraint (`db/migrations/000001_stage1_tenancy.sql:70`)
and in the Go role enum (`internal/policy/decision.go:83`), but no policy
check anywhere grants it any capability — the role exists in name only.

Refresh has the same shape of gap. `:sync` exists as a route on the REST
surface (`internal/platform/workspaceapi/workspaceapi.go`), but the
registration UI never calls it; once a binding is disabled there is no
product path to re-enable it. Acceptance measurement on the accepted stand
confirms all three: `activate` after disable returns 404, re-enabling the
binding returns 404, and `:sync` on a disabled binding returns 404 — an
operator who disables a source by mistake, or whose source goes stale, has no
way back except a developer or a direct SQL session.

The owner's requirement is unchanged by any of this: an operator registers,
confirms and refreshes sources without a developer and without SQL, and every
one of those actions is audited exactly as today's authority chain already
audits grant, confirm and revoke.

## Decision

### 1. Operator confirmation becomes a typed surface over the existing authority chain

`IssueConfirmationGrant`, `ConfirmManagedSource`, `RevokeConfirmationGrant`
and `RevokeManagedConfirmation` gain typed REST and MCP entry points. No new
authority, policy matrix, canonical envelope or audit action is introduced:
these entry points call exactly the command methods and the canonical JCS
contract ADR-0053 already froze, and every one of ADR-0053's role rules —
who may issue a grant, who may confirm, the separation between issuer and
confirmer, self-grant and self-revoke conditions, the closed error surface —
carries over unchanged. The UI stops rendering an unexplained denial and
instead renders the pending confirmation as an operator action: who holds the
grant, what the grant is for, and a control that calls `ConfirmManagedSource`.

ADR-0053's "no HTTP/API/UI/MCP surface" clause is amended by exactly this
ADR: that boundary was correct while the command chain was unreviewed, and
this ADR is the review that lifts it for these four operations only, without
touching the policy matrix, the canonical contract or the audit rules ADR-0053
fixed for them. `checkWorkspaceManagedAuthorityCommandRuntime`'s token scan is
brought forward from "these four tokens are forbidden outside
`internal/audit` and `authority_*.go`" to a contract that instead proves a
composed, policy-checked, audited call path exists in `internal/platform/workspaceapi`
(and its MCP equivalent) and nowhere else uncomposed — a positive gate in the
same spirit as the checker's existing positive gates for the 000011 runtime,
not a removed gate.

### 2. Trust verification opens as a future authority path, gated to CONNECTOR_ADMIN

`DRAFT → VERIFIED` remains exactly what migration 000014 already declares it:
a control-plane/admin authority action, never a runtime-role UPDATE grant. What
changes is that the only way to exercise that authority stops being a direct
database session. A new `SECURITY DEFINER` command performs the transition,
callable only by a principal holding the organization role `CONNECTOR_ADMIN`
through a typed REST/MCP call, and only when the call carries a mandatory
attestation — who verified the connector, the exact connector identity being
attested, and the time of verification. The transition stays monotonic
(`DRAFT → VERIFIED` only, never reversed by this path) and fail-closed on
incomplete attestation data, and it appends exactly one audit event, matching
the content-free shape ADR-0053's audit contract already establishes for the
adjacent confirmation actions. The runtime application role still receives no
UPDATE grant on `source_connection_trust_projection`; the new function is the
only door, and it is a `CONNECTOR_ADMIN`-gated door.

Separation of duties is preserved by construction: the same principal may
never act as both the `CONNECTOR_ADMIN` who verifies a connector's trust and
the workspace owner/manager who confirms that scope's `WORKSPACE_MANAGED`
binding under ADR-0053's confirmation policy. Where ADR-0053 already requires
that separation for issuer/confirmer, this ADR extends the same requirement to
verifier/confirmer without restating or weakening ADR-0053's own wording.

### 3. Refresh and re-enable become operator-visible

`:sync` is reachable from the UI and from the same MCP surface as
confirmation, subject to the same policy and audit rules that already gate it
on the REST route. A disabled `WORKSPACE_MANAGED` binding can be returned to
service through a typed, audited command, closing the measured 404 on
re-enable. The UI shows the freshness of a source against its workspace's
`STALE` threshold, so an operator can see a source needs refreshing before an
answer silently goes stale. The schedule that decides how often a projection
refreshes on its own is out of scope here and belongs to the workspace access
profile ADR-0086 defines; today's manual, full-pass `Activate`/`Sync` remains
the default until that profile says otherwise.

### 4. SQL authorship stays forbidden; every command stays a closed contract

Nothing in this decision opens a SQL input, free-form parameter or connector
string to any operator, UI, API or MCP surface — `PRODUCT_CONSTITUTION.md` §7
forbids that on every surface without exception. The confirmation, trust
verification and refresh commands introduced or exposed here are, without
exception, closed JSON contracts of the exact shape ADR-0053 established:
one canonical envelope, one schema, golden JCS vectors, no free-form metadata
field, documented in `docs/CANONICALIZATION.md` alongside the existing
authority contract.

## Alternatives considered

| Alternative | Why rejected |
| --- | --- |
| Leave admin SQL as the only path | The owner's requirement is exactly that an operator not depend on a developer or a database session; this alternative changes nothing measured today. |
| Grant the runtime application role UPDATE on the trust projection | Breaks the fail-closed control-plane/admin boundary migration 000014 deliberately built; any authenticated runtime request could then move DRAFT to VERIFIED with no attestation and no distinct authorizer. |
| Auto-verify trust at registration time | Removes the separation of duties between registering a source and vouching for its connector's trustworthiness; a compromised or misconfigured connector would activate with no independent check at all. |

## Acceptance tests

Executed on an acceptance deployment:

1. A demo cycle — fresh registration through to an active source, then a
   question answered with citations — completes entirely through the
   REST/UI path and, separately, entirely through MCP, with no admin SQL
   step: `activate` returns 200, `sync` reaches `SUCCEEDED`, and the question
   answer carries citations.
2. A disabled `WORKSPACE_MANAGED` binding is re-enabled through the typed
   command and answers questions again, closing the measured re-enable 404.
3. A trust-verification attempt by a principal who is not `CONNECTOR_ADMIN`
   is denied, and the denial carries no detail that would let the caller
   distinguish "wrong role" from "hidden connector" (no existence oracle).
4. The audit log contains grant, confirm, verify and re-enable events, each
   carrying its responsible principal, for the full cycle above.
5. The e2e harness performs the same cycle through the same typed
   surfaces, with no direct `UPDATE` against `source_connection_trust_projection`
   or the authority relations.
6. `scripts/check-architecture.go` passes green against the revised boundary.

## Consequences

### Positive

- An operator can register, confirm, verify-gate and refresh a
  `WORKSPACE_MANAGED` source end to end without a developer or a database
  session, closing the gap the owner named.
- The existing ADR-0053 authority chain, policy matrix and audit contract are
  reused rather than duplicated: confirmation gains a surface without gaining
  a second authority model.
- Trust verification gets its first authorized, audited, non-SQL path while
  keeping the control-plane/admin boundary and the runtime role's missing
  UPDATE grant exactly as migration 000014 built them.

### Negative / trade-offs

- `checkWorkspaceManagedAuthorityCommandRuntime`'s negative token scan
  becomes a positive composition proof instead, a strictly harder guard to
  write and keep mutation-tested than an absence check.
- `CONNECTOR_ADMIN` moves from a declared-but-inert role to a role with real
  capability; every place that today assumes the role never authorizes
  anything must be re-examined, not just the trust-verification path.
- Adds one new migration, one new `SECURITY DEFINER` function, and new
  REST/MCP/UI surface area that policy, retrieval and audit must all agree
  with, on top of the surface ADR-0074 and ADR-0053 already shipped.

### Security and failure semantics

- Every one of these paths fails closed exactly as the authority chain it
  extends does: no resolvable grant, no `CONNECTOR_ADMIN` role, no complete
  attestation, or no confirmed `WORKSPACE_MANAGED` binding all deny rather
  than degrade.
- `DRAFT → VERIFIED` remains monotonic through this path; there is no
  route, surface or recovery path that reverses it or that skips the
  attestation fields.
- The runtime application role gains no new UPDATE grant on
  `source_connection_trust_projection` or on the four authority relations;
  the new `SECURITY DEFINER` function is a closed door, not a widened one.
- A principal cannot be both the `CONNECTOR_ADMIN` verifier and the
  confirming workspace owner/manager for the same scope; that separation is
  enforced at authorization time, not left to operational discipline.
- SQL authorship is not reachable through any surface this ADR adds; every
  new command is a closed contract validated against a reviewed schema,
  exactly as ADR-0053's four operations already are.

## Implementation and evidence

- Code/packages: `internal/workspace/repository/authority_commands.go` (no
  change to the four existing methods), a new `SECURITY DEFINER`
  trust-verification command and its repository method,
  `internal/platform/workspaceapi` (REST composition of confirmation, trust
  verification and refresh), a new MCP tool surface following ADR-0079's
  authority pattern, `internal/policy` (CONNECTOR_ADMIN capability),
  `web/src/main.tsx` (pending-confirmation, verify-trust, refresh and
  re-enable UI).
- Contracts/schemas: a new canonical envelope and schema for the
  trust-verification command, following the exact shape of
  `architecture/contracts/workspace-managed-authority-command.schema.json`;
  `docs/CANONICALIZATION.md` gains the new contract.
- Negative/mutation tests: verification attempted by a non-`CONNECTOR_ADMIN`
  principal; verification with incomplete attestation; a principal acting as
  both verifier and confirmer for the same scope; refresh/re-enable attempted
  outside a workspace's declared access profile.
- Guardrails/versions/licenses/protected hashes: this ADR adds one migration
  (new, append-only, following 000011's numbering discipline) and revises
  `scripts/check-architecture.go`'s `checkWorkspaceManagedAuthorityCommandRuntime`;
  `docs/adr/README.md` and `architecture/protected-hashes.json` are amended by
  this proposal itself.
- Required CI or phase evidence: architecture, schema and full Go checks; a
  live-stand run of the Acceptance tests above.

## Delivery status

`current`: registration, bind and activation exist
(ADR-0074); the confirmation authority chain exists but is callable only from
the e2e harness and an equivalent direct-database lab script (ADR-0053/0054);
trust verification is admin SQL only; a disabled binding cannot be
re-enabled and `:sync` is unreachable from the UI.

`target`: typed REST/MCP surfaces for confirmation, a `CONNECTOR_ADMIN`-gated
trust-verification command, and an operator-visible refresh/re-enable path —
delivered as this ADR's roadmap slice below.

`reserved`: the trust-verification command name and its audit action, so a
later delivery package can implement them without a naming conflict.

`deferred`: everything under Implementation and evidence above; this ADR
authorizes design only and activates no runtime capability.

### Roadmap consequences

- **S2** — this ADR: operator-visible confirmation, `CONNECTOR_ADMIN` trust
  verification, and refresh/re-enable, as part of sources becoming a
  first-class product surface.
- **S3–S5** — as ADR-0086 already lays out: GOVERNED_QUERY (S3),
  classification/masking and access audit (S4), larger data volumes (S5).

## Supersedes / superseded by

None. This ADR amends ADR-0053's surface-boundary clause for exactly the four
confirmation-authority operations and extends ADR-0058/ADR-0074 without
replacing any accepted decision in them.
