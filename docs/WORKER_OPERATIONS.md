# Production worker operations (I3-A)

The production worker is a single-tenant, read-only data-plane process. It
claims durable jobs as `knowvault_worker`, ingests `SOURCE_SCOPE_SYNC`, and
does not expose an HTTP listener.

Its image and compose user are `65530:65530`, separate from the OFFICE parser
and server identities. Secret/trust/source-trust/search/embedding directories
are root:65530 mode 0750 with direct root:65530 mode 0440 files. Composition
selects only worker readers; a server-owned or mixed-group mount is rejected.
Generate or verify a worker secret mount with `-consumer worker`; when reusing
keys, select their source independently with `-keys-from-consumer server|worker`.
An existing 65532 deployment needs staged mounts and a compose user update;
retain the original mount tree, compose and image together for rollback.
The release helper refuses an image/compose user mismatch before migrations.

Required environment variables:

```text
KNOWVAULT_ORGANIZATION_ID=org_001
KNOWVAULT_PROVIDER_ID=provider_001
KNOWVAULT_WORKER_ID=worker_001
KNOWVAULT_WORKER_LEASE_SECONDS=60
KNOWVAULT_WORKER_POLL_SECONDS=2
```

The optional `KNOWVAULT_WORKER_NATIVE_PROFILE` is either `disabled` or
`document-parser-sandbox-v3`; omission preserves the disabled profile. Empty,
unknown, duplicate and path-valued profiles are rejected. All other
`KNOWVAULT_*` variables are rejected. The worker also requires these read-only
mounts:

- `/run/knowvault/secrets/manifest.json` and the files named by its strict
  `knowvault-secret-manifest-v1`, including `source_digest_hmac`;
- `/run/knowvault/trust/database-ca.pem` and `oidc-ca.pem`;
- `/run/knowvault/source-trust/git-ca.pem` and `mail-ca.pem` for the
  deployment-owned Git/IMAP adapters. These roots are purpose-separated from
  database/OIDC trust and are required before a remote scope can resolve;
- `/run/knowvault/sources/manifest.json` and one read-only directory for each
  manifest entry.

The secret manifest uses the exact field names below. `artifact_kek` and
`oidc_client_secrets` are part of the wire contract; similarly named aliases
are rejected.

```json
{
  "schema": "knowvault-secret-manifest-v1",
  "organization_id": "org_001",
  "provider_id": "provider_001",
  "database_url_file": "db_url",
  "identity_hmac": {"reference": "identity-ref", "version": 1, "filename": "identity_key"},
  "session_hmac": {"reference": "session-ref", "version": 1, "filename": "session_key"},
  "source_digest_hmac": {"reference": "source-digest-ref", "version": 1, "filename": "source_digest_key"},
  "oidc_transport_aead": {"reference": "transport-ref", "key_id": "transport-key", "filename": "transport_key"},
  "artifact_kek": {"reference": "artifact-kek-ref", "version": 1, "filename": "artifact_wrap"},
  "oidc_client_secrets": [
    {"organization_id": "org_001", "provider_id": "provider_001", "provider_revision": 1,
     "reference": "client-ref", "filename": "client_secret"}
  ],
  "source_credentials": [
    {"reference": "cred_pg_001", "filename": "source_credential_001"}
  ]
}
```

`source_credentials` is optional and contains only opaque connector
credentials. Each reference is unique across the mount and is matched exactly
to the `credential_reference` stored in a source connection revision. The
operator writes these values byte-for-byte from protected files; the product
never accepts a DSN in a workspace request, job payload, log or audit record.
For a worker mount generated with `-keys-from`, the complete source-credential
set is copied from the verified server mount, so the worker does not need a
second plaintext copy of each credential.

`db_url` is a canonical single-host PostgreSQL URL with
`sslmode=verify-full`; the hostname must be a DNS name covered by the
customer-supplied database CA bundle. The database identity must be the
non-privileged `knowvault_worker` role.

The source manifest is deployment configuration, not tenant data:

```json
{
  "schema": "knowvault-source-mount-manifest-v1",
  "roots": [
    {"alias": "docs-root", "identity": "volume-001", "directory": "docs"}
  ]
}
```

The folder trust profile must contain the exact same `(root_alias,
root_identity)` tuple. The worker never accepts an absolute source path from a
job, profile or environment variable.

The native qualification overlay is `deploy/compose/native-ingest.yaml`. It
adds only the read-only `/run/knowvault/sandbox/submit` directory, never the
registration/handoff sockets, host runtime or supervisor state. The source
folder and all service mounts retain their normal worker rights.

`/knowvault-worker native-readiness` checks the selected profile and the actual
submit service without loading a database or documents. Success requires both
OFFICE and text-PDF peers to have completed registration for the locked artifact
and limits, with unused capacity. A busy, missing, stopped, mismatched or RED
peer is not ready. This is a point-in-time capacity probe, not a liveness probe
or a reservation. Enabled worker startup checks it before opening service
mounts; each later job still goes through normal admission and retry rules.

Native Office/PDF activation remains subject to the separate qualification and
deployment requirements in [Native document ingestion](NATIVE-INGEST.md). The optional profile
does not enable OCR or rendering, and it has no in-process parser fallback.
