# ADR-0047: Source control-plane revision and activation boundaries

Status: accepted.

`SourceConnectionRevision` and `SourceScopeRevision` are immutable configuration
records. Revocation, expiry, validation and activation are not fields that may
rewrite those records: connection trust and scope activation live in separate
monotonic projections. A new connection revision does not move a current
pointer, rebind a scope or authorize execution implicitly.

Parents therefore expose `latest_revision` only for management lineage and a
separate nullable `active_revision` for authority. Migration `000006` never
sets an active revision.

A connection revision is authority only as one exact tuple: connection and
revision, connector build/version/artifact, capability profile ID **and hash**,
contract-suite hash, connector agent ID plus execution target, trust record ID
and trust-profile hash, allowed access modes, credential reference and limits.
The trust record exact-match binds the same connection revision, target and
trust profile. `CONNECTOR_AGENT` requires a non-null exact connector-agent ID;
`CENTRAL_WORKER` requires that ID to be null. A matching version string or a capability/trust record from
another build, agent or execution target is insufficient. Credentials remain
opaque secret-provider references and never enter a scope, model input or
workspace configuration.

A scope revision exact-match references one trusted discovery row by both
`discovered_scope_id` and `identity_digest`, in addition to connection ID and
revision. Raw external identity remains encrypted and is authenticated through
the canonical scope-config hash. A caller-supplied label or an identity found by
another connection revision cannot authorize a scope. Scope configuration,
access mode, limits and SLA are immutable; changing any of them creates a new
`DRAFT` revision.

`WORKSPACE_MANAGED` consent is a grant to an exact workspace binding, not a
property of a reusable source scope. Its confirmation therefore binds
organization, workspace and WorkspaceRevision, workspace binding, source scope
and revision, scope-config hash, actor, policy revision and warning version.
The confirmation relation and command are deferred to the workspace-binding
checkpoint. A `WORKSPACE_MANAGED` draft may be configured earlier, but cannot
become queryable without that exact confirmation. `SOURCE_ENFORCED` never uses
such a confirmation and must independently pass its source-ACL capability gate.

Migration `000006` is intentionally only a safe control-plane draft. It may
create immutable connection/scope configuration and initial fail-closed trust
and activation projections, but every scope activation remains `DRAFT`, active
scope pointers remain empty, and no query, connector event or content-bearing
job may use these rows. A later accepted migration must add full scan,
activation, exact workspace binding/confirmation, signed event and audit gates
before it can permit `READY`. Replacing a credential, build, trust profile,
agent or execution target creates a new connection revision; cutover is always
an explicit audited operation after dependent scopes have been revalidated.

`DEGRADED` is derived effective health when the referenced connection trust is
not `VERIFIED`; it is not a mutable scope-revision or activation state.

No connector, ingestion, evidence or search capability is introduced by this
decision, and no new dependency or license is added.
