# ADR-0033: OIDC browser HTTP boundary

Status: accepted.

Stage 1 exposes exactly two browser routes: `GET /auth/login` and
`GET /auth/callback`. Paths, methods, request bodies and query strings are
parsed strictly. Tenant, provider and canonical public origin come only from
the server-resolved `tenantsecurity.Context`; redirect URI must exactly equal
the trusted public origin plus `/auth/callback`. User input cannot select a
tenant, provider, redirect URI or source credential.

The login sequence performs every fallible cookie operation before the durable
`BeginLogin`. `oidctransport.Prepare` seals, validates and serializes an opaque
one-shot `PreparedCookie`; after the database commit its only operation is a
no-error, no-clock `WriteOnce`. Copies share the same atomic use state. The
handler then immediately returns a 303 redirect. No fallible operation exists
between a successful login-attempt commit and the response.

The callback clears the transient OIDC cookie before parsing input or writing
any response. It exact-matches the sealed state, pending provider revision and
all four durable digests, discovers the same provider through the injected
hardened client, resolves the client secret only for token exchange using the
exact organization, provider, provider revision and stored secret reference,
and calls atomic `CompleteLogin`. The session cookie is issued only after that atomic
operation has consumed the attempt and committed the session plus audit event.
Every failure is generic, content-free and `no-store`.

`HardenedHTTPClient` is mandatory for discovery, JWKS and token exchange. Its
production constructor accepts only an owned clone of a reviewed standard
`http.Transport`, rejects custom TLS dials, `InsecureSkipVerify` and TLS below
1.2, accepts only HTTPS requests, has a fixed timeout and never follows
redirects. Provider credentials and raw protocol material are never formatted,
persisted in the handler or returned in an error.

This ADR accepts the isolated HTTP boundary and its tests. It does not yet
compose OIDC or workspace routes into `cmd/server`; startup configuration,
secret/KMS adapters, database pools, shutdown and route composition remain the
next reviewed slice.
