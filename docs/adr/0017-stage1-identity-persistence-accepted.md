# ADR-0017: Stage 1 identity persistence and revocation

Status: accepted.

The Stage 1 identity database boundary consists of tenant-scoped OIDC provider
configurations and immutable revisions, digest-only external identity mappings,
one-time login attempts and opaque server sessions. Every new table has
`organization_id`, forced RLS and no runtime `DELETE` privilege.

The database stores no raw OIDC subject, email, token, authorization code,
nonce, PKCE verifier or browser/session secret. The application computes keyed
digests before persistence. Provider credentials remain only an opaque secret
reference. A future encrypted artifact subsystem is therefore not a dependency
of basic identity mapping; the normative model is deliberately digest-only for
this scope.

An OIDC login attempt moves only from `PENDING` to `CLAIMED`, then to
`CONSUMED` or `FAILED`; expiry is terminal. A deferred database constraint and
a unique key make one attempt capable of creating exactly one session. A
session cannot be edited or reactivated: it may only transition to revoked.
Its issue-time principal and provider revisions are captured for a mandatory
live check on every authenticated operation.

Changing a principal status requires a strictly higher `session_revision`.
`DEPROVISIONED` is one-way in 1.0, and a database trigger revokes every active
session of that principal within the same transaction. The next slice adds the
repository transaction that appends the required audit event in the same
commit; no HTTP login/callback route or cookie parser is enabled by this ADR.
