# ADR-0030: Single-tenant security context and session cookie

Status: accepted.

Version 1.0 uses one deployment-bound tenant per server process. The immutable
`tenantsecurity.Context` is constructed at startup from trusted configuration
and secret/KMS results. Its organization, OIDC provider and canonical HTTPS
public origin are never selected from `Host`, `Forwarded`, `X-Forwarded-*`,
path, query, body, cookie or OIDC state. A locked ingress terminates TLS and
must prevent direct backend access; forwarded headers remain non-authoritative.

The context requires two distinct canonical non-secret KMS resource references
and digestor instances. References are attested outputs of the future trusted
secret resolver, not free-form operator labels; the constructor additionally
rejects equal references and the same digestor instance.
The identity selection owns OIDC state, nonce, PKCE, browser binding and
external-subject digests. The session selection owns only `session_token` and
`csrf`. The HTTP authentication adapter projects only the session selection.
This separation is mandatory: rotating a shared key would otherwise invalidate
the durable external-subject mapping and prevent new logins. In 1.0 a session
key rotation intentionally invalidates all current sessions and CSRF proofs;
identity-key rotation requires a later migration ADR.

`browserauth.NewSessionMaterial` receives the complete tenant security context,
uses only its session digestor, obtains exactly 256 bits from the operating
system CSPRNG and exposes only the `session_token` digest to persistence. The raw
value remains private and all normal Go formatting is redacted. The cookie is
issued only after a future successful atomic `CompleteLogin` result.

The accepted session cookie is exactly `__Host-knowvault_session` with
`Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Lax`, an absolute
`Expires`, and `Max-Age` no later than the server-side session expiry or 24
hours. `Lax` preserves the top-level OIDC callback; unsafe workspace requests
still require the independently derived exact Origin/CSRF proof.

This ADR does not add login/callback routes or compose workspace routes into
`cmd/server`. The next OIDC HTTP slice must solve durable multi-instance
transport of raw nonce and PKCE verifier. The accepted direction is a bounded,
short-lived AEAD-sealed `__Host-knowvault_oidc` cookie with a third independent
key selection; a browser-binding cookie alone is insufficient because the
database deliberately stores only digests.
