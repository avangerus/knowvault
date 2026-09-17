# ADR-0039: Customer-mounted purpose-scoped trust roots

Status: accepted.

Production TLS trust is explicit customer deployment input, not an implicit
property of the host operating system or application image. The customer
mounts exactly two PEM bundles below `/run/knowvault/trust`:
`database-ca.pem` for PostgreSQL and `oidc-ca.pem` for OIDC discovery, token
exchange and JWKS. KnowVault does not ship, generate, download or copy either
bundle. The customer is responsible for the authority and licensing of this
external runtime material.

The mount root must be a non-symlink Linux directory owned by UID 0 and GID
65532 with mode `0750`. Each bundle must be a regular, single-link file owned
by UID 0 and GID 65532 with mode `0440`. The loader pins the directory file
descriptor, opens only the two fixed basenames with `openat(O_NOFOLLOW)`, and
validates the same opened file descriptor with `fstat`. Non-Linux production
loading fails closed. There is no arbitrary-path API, environment fallback,
system certificate pool fallback or runtime reload.

Each file is limited to 1 MiB and 256 unique CA certificates. Parsing accepts
only header-free `CERTIFICATE` PEM blocks separated by whitespace. Malformed,
duplicate, non-CA, non-signing or unhandled-critical-extension certificates
fail the complete load. A SHA-256 fingerprint records the exact accepted file
bytes, including PEM layout, without exposing certificate contents.

Database and OIDC trust domains remain purpose-separated even when a customer
chooses the same enterprise CA for both. The loader returns two intentionally
non-convertible opaque types, `DatabaseRoots` and `OIDCRoots`. Each owns deep
copies of validated certificate DER and reparses a fresh `x509.CertPool` for
its consumer; no caller-owned certificate pointer, constraint callback, DER
slice or pool is retained. `database.OpenProduction` accepts only
`DatabaseRoots`, while `oidc.NewProductionHTTPClient` accepts only `OIDCRoots`.
PostgreSQL must first parse to an empty root pool, one canonical DNS target and
`verify-full`; OIDC uses an owned transport with no environment proxy and no
system-root fallback.

Rotation is a deployment rollout: replace the mounted files and restart the
process. A running process retains its startup snapshot so a mid-request file
change cannot alter trust. Production composition must load both bundles and
finish all other preflight checks before opening a listener.

No CA certificate, Debian/Mozilla certificate package or third-party trust
bundle is added to the repository, build context, application image, fixtures
or release artifacts. Tests create ephemeral self-signed CA certificates at
runtime. Consequently this decision introduces no shipped third-party
component; an SBOM must describe the mounted bundles as customer-supplied
external artifacts rather than application contents.
