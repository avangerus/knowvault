# ADR-0019: Identity repository and pre-authentication boundary

Status: accepted.

The Stage 1 identity repository is the only code path allowed to use the
fixed, tenant-scoped `svc_oidc` database context before a user session has
been resolved. This is not an administrator context and it is never persisted
as an audit actor. Login events use `ActorSystem`, and a successful event names
the resolved user only through the structured on-behalf-of field.

The repository accepts opaque internal IDs and validated keyed digests only.
It stores a new OIDC attempt, then atomically claims that attempt, finds an
already-existing digest-only external mapping, creates a server session,
consumes the attempt and appends its `identity.login` audit event. A missing
mapping consumes the valid attempt as failed and appends a denied
`identity.login_failed` event; it never creates a principal automatically.

Session resolution also uses the pre-auth context, but returns a normal user
`AccessContext` only after the pure identity validator exact-matches the
current principal, external mapping and OIDC provider. The repository is not
an OIDC protocol adapter: signature, issuer, audience, nonce and PKCE
verification remain absent until the isolated platform OIDC adapter is added.
