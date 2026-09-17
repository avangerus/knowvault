# ADR-0034: Exact root HTTP dispatcher

Status: accepted.

The application root uses `internal/platform/apphttp.Dispatcher`, not
`http.DefaultServeMux` and not a router that cleans, redirects or canonicalizes
paths. It receives four already-constructed handlers: OIDC browser auth,
system endpoints, workspace API and static UI.

Only exact `/auth/login` and `/auth/callback` paths with an empty `RawPath` may
reach the OIDC handler. The entire remaining `/auth` namespace is reserved and
returns a fixed no-store 404. Unknown, trailing-slash and encoded auth aliases
must never reach the SPA fallback.

Exact system health and build-information paths reach `systemapi`. The whole
remaining `/api` namespace reaches the workspace API boundary, including
encoded path variants; that boundary owns strict endpoint rejection. Therefore
no API-shaped request can be rendered as an HTML application page. All other
paths reach the UI handler.

Every handler dependency is mandatory and typed-nil values fail construction.
The dispatcher does not authenticate, select a tenant, clean a URL, infer a
route from `Host` or issue redirects.

This ADR accepts the dispatcher and its isolated tests. It is not yet composed
into `cmd/server`; mounted secrets, typed startup configuration and production
preflight remain mandatory before the listener may expose these routes.
