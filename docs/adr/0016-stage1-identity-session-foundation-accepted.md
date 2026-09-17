# ADR-0016: Stage 1 identity and session foundation

Status: accepted.

`internal/identity` is a pure boundary between an already verified transport
assertion and the current, server-resolved principal and OIDC-provider state.
It parses no token, opens no database connection and does not create policy
decisions. Both inputs are typed, opaque internal IDs; email address and
external OIDC subject are not internal principal identifiers.

Each future server session will carry an organization ID, principal ID,
provider ID, expiry, `session_revision` and `provider_revision`. On every
authenticated operation its claims must exactly match the current
server-resolved principal and provider snapshots. Unknown, disabled and
`DEPROVISIONED` principals, unknown or disabled providers, expired sessions,
malformed input or any revision mismatch fail closed. This makes a durable
principal/provider revision bump a mandatory revocation primitive rather than
relying only on cookie expiry.

Validation errors contain only stable safe codes. They must never expose
external subjects, internal IDs, timestamps, provider responses, bearer
tokens or database causes in a client response or audit payload. The following
slice persists the server-side session and identity mapping under RLS; it will
then make deprovisioning, revision bump, session revocation and audit append
one bounded transaction.
