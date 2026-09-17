# Server image contract

`Dockerfile.server` is the only production server image definition. Build it at
the repository root. The committed `web/dist` is a sealed release artifact;
required CI rebuilds it from source with the pinned Node toolchain and rejects a
diff before building the image:

```text
docker build -f deploy/images/Dockerfile.server .
```

Runtime requirements:

- server/connector/purger user `65532:65532`; ingestion worker `65530:65530`;
- read-only root filesystem and all Linux capabilities dropped;
- no writable `/tmp` is required;
- only port `8080` inside the private workload network;
- termination grace at least 90 seconds;
- exactly the four documented `KNOWVAULT_*` variables;
- no `PG*` variables and no `envFrom`/service-link injection;
- native orchestrator HTTP liveness probe;
- the two read-only direct-file mounts below.

```text
/run/knowvault/trust    root:65532 0750
/run/knowvault/secrets  root:65532 0750
```

The ingestion worker uses a separate group on the same paths:

```text
/run/knowvault/trust        root:65530 0750
/run/knowvault/secrets      root:65530 0750
/run/knowvault/source-trust root:65530 0750
/run/knowvault/search       root:65530 0750
/run/knowvault/embedding    root:65530 0750
```

Its mounted regular files are root:65530 mode 0440. Composition selects
worker-specific readers; each pins exactly one group for the directory and
every file. Server readers retain root:65532. The operator accepts
`secrets generate|verify -consumer worker`; key reuse independently selects
`-keys-from-consumer server|worker`. Existing mounts must be staged for upgrade
with the previous tree retained for rollback before switching the worker UID.

The server's enterprise retrieval profile is an additional administrator-owned mount:

```text
/run/knowvault/search   root:65532 0750
```

It contains only `manifest.json`, `root-ca.pem` and, when the OpenSearch
cluster requires mTLS, `client-cert.pem`/`client-key.pem`. Every file is a
direct regular file owned by `root:65532`, mode `0440`, one hard link. The
manifest is the strict `knowvault-search-manifest-v1` shape and binds the
tenant, canonical HTTPS endpoint, index alias, generation and generation
fence; arbitrary paths, IP endpoints, proxy settings and system CAs are not
accepted. A present-but-invalid search mount stops the server/worker rather
than downgrading to a different search dependency. If the mount is absent,
the binary remains usable only for the explicitly staged database-only
compatibility path; that mode is not enterprise retrieval qualification.

Each server/connector/purger mounted file is a direct regular file owned by `root:65532`, mode `0440`,
with one hard link. The server trust mount contains exactly
`database-ca.pem` and `oidc-ca.pem`. The worker additionally receives the
separate `/run/knowvault/source-trust` mount containing exactly `git-ca.pem`
and `mail-ca.pem`; those roots are never used for database or OIDC traffic.
Secrets contains `manifest.json` and the files named by that manifest. Symlink
projections and Docker/Kubernetes default secret modes are not accepted by
assumption; the selected volume provider must be acceptance-tested.

The runtime intentionally contains no shell, curl, system CA bundle or customer
material. Database migrations and OIDC provider bootstrap run under a separate
administrative identity and are not performed by the server.

## Dispatcher image contract

`Dockerfile.dispatcher` builds the static `knowvault-sandbox-dispatcher` broker
using the same digest-pinned Go toolchain. The runtime is `scratch`, runs as
`0:0`, and contains no shell, database, secret or container-runtime client. The
dispatcher is the privileged kernel-observer/supervisor boundary, so the
orchestrator must provide `/run/knowvault/sandbox`, the cgroup namespace and
the four owner-only Unix sockets described in
`deploy/manifests/sandbox-dispatcher.yaml`.

The image is an installable contract artifact, but the manifest deliberately
remains `CONTRACT_ONLY` until the external supervisor, parser workers and
rollback evidence are accepted. Building this image must not be interpreted as
activating the deferred DispatcherV2 lifecycle entry.

## Purger image contract

`Dockerfile.purger` builds the dedicated `knowvault-purger` process. It runs as
`65532:65532` from `scratch`, has no listener or connector, and receives only
the `/run/knowvault/trust` and `/run/knowvault/secrets` mounts. Its five
allowlisted environment variables are `KNOWVAULT_ORGANIZATION_ID`,
`KNOWVAULT_PROVIDER_ID`, `KNOWVAULT_PURGER_ID`,
`KNOWVAULT_PURGER_LEASE_SECONDS` and `KNOWVAULT_PURGER_POLL_SECONDS`.
The process uses the `knowvault_purger` database role and the migration-owned
conversation and source-version queues; it never shares the ingestion worker
role or accepts SQL from a model. Source-version enqueue remains purger-only
because one source version may be visible from more than one workspace.
The image is not an operational readiness claim until a deployment supplies
the real mounts, scheduler restart policy and alert sink.
