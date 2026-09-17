# ADR-0044: Production server image and mount contract

Status: accepted.

The server is distributed as a `scratch` image containing only the static Go
binary and the compiled Web UI. The exact compiled `web/dist` release artifact
is committed and protected by the architecture hash registry. Required CI
rebuilds it from the exact `package.json`, `pnpm-lock.yaml`, `tsconfig.json` and
`web/src` inputs in the pinned Node builder and rejects any diff. The server is
built from the complete committed `internal` tree in the pinned Go builder.

The runtime identity is exactly numeric `65532:65532`. The image contains no
shell, package manager, system CA bundle, source credentials or customer trust
roots. `/web/dist` is image-owned and read-only. The application requires no
writable directory and the container root filesystem must be read-only.

Production supplies two read-only, direct-regular-file mounts:

```text
/run/knowvault/trust   root:65532 0750
  database-ca.pem      root:65532 0440 nlink=1
  oidc-ca.pem          root:65532 0440 nlink=1

/run/knowvault/secrets root:65532 0750
  manifest.json        root:65532 0440 nlink=1
  <manifest files>     root:65532 0440 nlink=1
```

Symlink projections, hard links, in-place mutation and world-readable `0444`
files are rejected. Generic Kubernetes projected Secrets and Docker secrets are
therefore not implicitly compatible; a platform is supported only when its
volume provider produces the exact direct-file contract. Rotation replaces the
immutable volume and restarts the process.

The environment contains exactly four `KNOWVAULT_*` variables: organization ID,
provider ID, canonical public HTTPS origin and HTTP listen address. `PG*`
variables and additional or case-folded `KNOWVAULT_*` variables fail closed.
The server has no system-root or environment fallback.

The orchestrator must use native HTTP probes because the image has no probe
binary. The current health endpoint is process liveness after complete startup,
not continuous dependency readiness. Termination grace must be at least 90
seconds for the 75-second bounded HTTP drain. External TLS termination, network
policy and database/IdP egress are deployment responsibilities.

The development Compose topology remains data-services-only. Its plaintext
PostgreSQL and unauthenticated OpenSearch configuration is not a production
server deployment contract.

No new dependency is introduced: both CI/build images and all Web/Go packages are
already exact-version and license locked.
