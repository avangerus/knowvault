# ADR-0042: Production local readiness gates

Status: accepted.

Production composition may create a listener only after two additional local
readiness gates succeed: fixed image UI validation and current OIDC provider
preflight. Neither gate accepts a caller-selected filesystem path, tenant,
provider, redirect or secret reference.

`webui.NewProduction` uses only `/web/dist`. It rejects nil and typed-nil API
handlers, a missing or symlinked root, and a missing, symlinked, non-regular,
empty or oversized `index.html`. The index is limited to 2 MiB and is checked
again through an `os.OpenRoot`-pinned handle. All runtime file serving uses
`Root.FS`, so nested relative or absolute symlinks cannot escape the image UI
root. The returned `ProductionHandler` owns that root descriptor; its
idempotent `Close` waits for active requests and then makes future requests
fail closed. Failure exposes only `WEB_UI_ASSETS_UNAVAILABLE`. The older
`webui.New` remains temporarily as a non-production scaffold seam and must
disappear from `cmd/server` when the production Runtime is wired.

OIDC preflight generates one fresh 128-bit CSPRNG request ID and performs one
tenant-scoped `LoadProviderConfiguration` for the deployment organization and
provider. The returned organization, provider, positive revision, bounded
client-secret reference and exact callback
`<public-origin>/auth/callback` must match. The projection must pass
`oidc.ValidateProviderConfiguration`, after which the mounted-secret provider
must validate the exact organization/provider/revision/reference tuple without
returning the secret.

Preflight performs no OIDC discovery, JWKS fetch, token exchange or other
network operation. Cancellation and every mismatch fail closed with the fixed
`COMPOSITION_OIDC_PREFLIGHT_FAILED` code. A successful gate is local
configuration consistency, not proof that the external identity provider is
currently reachable.

No third-party dependency is introduced.
