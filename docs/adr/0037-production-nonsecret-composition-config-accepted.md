# ADR-0037: Production non-secret composition configuration

Status: accepted.

The production server composition begins from one opaque, validated `Config`.
It contains exactly the deployment organization ID, OIDC provider ID, public
HTTPS origin and HTTP listen address. The web asset directory is not
composition configuration: the `webui` package owns its exact image path and
does not accept a caller-supplied root. The configuration contains no
database URL, credentials, cryptographic material, timeout tuning, model
profile or other secret/runtime policy. Those values cross their own reviewed
boundaries rather than becoming generic environment configuration.

`LoadProduction` snapshots `os.Environ` exactly once and accepts only
`KNOWVAULT_ORGANIZATION_ID`, `KNOWVAULT_PROVIDER_ID`,
`KNOWVAULT_PUBLIC_ORIGIN` and `KNOWVAULT_HTTP_ADDR`. Every value is mandatory.
Unknown names in
the `KNOWVAULT_*` namespace, non-canonical casing, and duplicate names under
case-insensitive comparison fail closed. There are no defaults, trimming,
normalization or fallback reads. Errors expose only one fixed code and never
the rejected name or value.

Identifiers use the existing bounded opaque-ID alphabet. The public origin is
one exact canonical HTTPS origin without credentials, path, query, fragment or
explicit default port. The listen address is one canonical TCP host/port. All
values reject invalid UTF-8, whitespace and control characters. Both legacy
`KNOWVAULT_WEB_DIR` and `KNOWVAULT_WEB_ASSET_DIRECTORY` are unknown namespace
entries and fail startup; they cannot redirect `os.DirFS` toward `/etc`, the
secret mount, or another host filesystem subtree.

The validated type has private fields, read-only accessors and redacted
`String`/`GoString` formatting so incidental startup logs do not disclose the
tenant or public origin. Only
`cmd/server` may import the composition package, so internal modules cannot
create an alternate process root or treat deployment environment as business
input. Listener wiring, mounted secrets, database construction and shutdown
remain separate follow-up slices. No third-party dependency is introduced.
