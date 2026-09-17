# ADR-0035: Linux mounted-secret boundary

Status: accepted.

The server loads its database URL, identity HMAC key, browser-session HMAC
key, OIDC transport AEAD key and revision-bound OIDC client secrets only from
`internal/platform/secretmount`. Raw secrets have no environment-variable
fallback. Production uses the compile-time `/run/knowvault/secrets` root and a
fixed `manifest.json`; only a package-private test seam accepts another root.

Manifest schema `knowvault-secret-manifest-v1` declares one exact organization
and OIDC provider. `LoadMountedForTenant` requires the trusted startup
organization/provider to exact-match that scope before returning any material.
Every client secret is bound to the same organization/provider plus an exact
provider revision and reference. A database reference never becomes a path.

Linux is the only accepted production server platform for this boundary.
The root is pinned as a root-owned directory descriptor. Files are opened by
basename with `openat`, `O_NOFOLLOW`, `O_CLOEXEC` and then validated with
`fstat` on that same descriptor. Root and files must be owned by UID 0; files
must be regular, have one link, exact mode 0400 or 0440 and bounded size. Mode
0440 requires `root:<dedicated server GID>`; that group cannot be shared with
another workload. A
symlink-projected Kubernetes Secret is intentionally rejected: deployments
must use a direct read-only bind or compatible CSI mount with root ownership.

The manifest is strict JSON with duplicate and unknown members rejected. The
three 32-byte keys use strict unpadded base64url, distinct references and
distinct material fingerprints. Provider data is preloaded atomically, lookup
is memory-only, accessors return copies, and temporary byte buffers are
cleared. Startup can exact-match an organization/provider/revision/reference
with `ValidateClientBinding` without returning the client secret. The provider
is a copy-safe opaque handle over one private shared state and owns its retained
material: idempotent concurrent `Close` through any handle first makes all
accessors fail closed and then zeroizes the database URL, keys and client
secrets. Value and pointer formatting are both redacted. Errors contain no
path, DSN, reference or material.

The database URL is canonical and permits only one lowercase host, explicit
port, non-empty user/password/database and the exact query
`sslmode=verify-full`. Service/pass/key file parameters, multi-host fallback
and every additional query parameter are rejected before pgx sees the value.
The following composition slice must additionally reject libpq `PG*`
environment overrides and inspect the parsed pgx TLS configuration; this ADR
does not yet authorize `cmd/server` wiring.

`KeyMaterial.Bytes` is a narrowly reviewed composition capability.
Architecture checks permit importing `secretmount` only from the production
composition root. No new third-party dependency is introduced.
