# ADR-0028: Tenant-bound HTTP session and CSRF boundary

Status: accepted.

Workspace HTTP routes remain disabled until every request crosses the
`internal/platform/httpauth` boundary. The boundary accepts no tenant selector
from an HTTP request. Its injected `TenantResolver` receives only a
server-controlled `context.Context` and returns one immutable
`TenantSecurityContext`: organization ID, canonical HTTPS origin and the
tenant-scoped digestor/key selection. A multi-tenant process therefore cannot
pair one tenant's identity with another tenant's origin or HMAC key.

Authentication requires exactly one `Cookie` header containing exactly one
canonical 256-bit base64url `__Host-knowvault_session` value. The raw value is
held only in a local stack variable, immediately converted to the
domain-separated `session_token` digest and passed to
`identityrepository.ResolveSession`. The returned session must exact-match the
trusted tenant, principal and server-generated request ID. Raw cookie material
is absent from returned structs, errors, audit and persistence contracts.

Unsafe methods additionally require exactly one canonical `Origin` and one
`X-KnowVault-CSRF` value. The expected proof is the tenant-keyed,
domain-separated `csrf` digest of the same raw session value and is compared in
constant time. There is no Referer fallback, reflected CORS or default origin.
The future authenticated CSRF bootstrap endpoint may return the derived proof,
never the session token.

The reviewed HMAC primitive now admits the explicit `session_token` and `csrf`
purposes in addition to OIDC purposes. They remain cryptographically
domain-separated. Version 1.0 uses one active tenant key selection: rotating it
intentionally invalidates existing browser sessions and outstanding CSRF
proofs. A bounded retired-key ring requires a later ADR before implementation.

This slice does not issue cookies or expose routes. Before HTTP composition is
enabled, the OIDC adapter must issue the reserved cookie with `Secure`,
`HttpOnly`, `Path=/`, no `Domain` and the approved `SameSite` policy, and the
production tenant resolver must be backed by deployment configuration or a
separately verified ingress context—not request headers.
