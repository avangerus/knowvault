# ADR-0029: Workspace HTTP control-plane handler

Status: accepted.

Stage 1 exposes the workspace repository through one transport adapter in
`internal/platform/workspaceapi`. The adapter owns exact route matching,
server-generated request IDs, authentication/CSRF ordering, strict HTTP header
and JSON validation, safe error mapping and response DTOs. It does not receive
a database transaction, append audit events or reproduce workspace policy;
those authorities remain in the repository and PostgreSQL gates.

Every route authenticates through `internal/platform/httpauth`. Unsafe routes
verify the tenant-bound same-origin CSRF proof before reading a request body or
calling the workspace service. The client cannot choose the tenant or request
ID. Encoded or ambiguous paths, path aliases, query strings, duplicate security
headers, unknown/duplicate JSON members and bodies larger than 32 KiB fail
closed before the business service is reached.

All mutations require one canonical 256-bit base64url `Idempotency-Key`.
Mutations other than create additionally require one strong
`If-Match: "sha256:..."` precondition. Absence is `428`, malformed syntax is
`400`, and a valid but stale revision is `412`. A returned workspace carries an
ETag for the exact immutable configuration snapshot returned by the repository.
Repository denial and absence remain the same external `404` for resource
operations; raw idempotency keys, session cookies and repository causes never
enter response envelopes.

JSON responses are non-cacheable and contain only reviewed DTO fields. The
authenticated CSRF bootstrap returns only the derived tenant-bound proof. No
CORS, bearer-token fallback, public API, arbitrary filtering or handler-level
audit exists in this slice.

The handler is deliberately not composed into `cmd/server` by this ADR. Routes
remain unreachable until a later accepted slice provides a production tenant
resolver and an OIDC completion adapter that issues the reserved session cookie
with the exact `__Host-` attributes. Presence of handler code is not authority
to enable the business surface.
