# ADR-0065: Production worker composition, source mounts and source-digest capability

Status: accepted.

This records the I3-A composition slice without claiming `P2_ACCEPTED`. It adds
no service, dependency, database migration or product capability. The worker
is still the existing durable-job component and the Office/PDF/OCR sandbox stays
`QUALIFIED_NOT_ACTIVE`.

## 1. Worker composition

`cmd/worker` is a thin `os.Exit(run())` entry point. Its private composition
root acquires, in order, the customer trust bundle, the tenant-bound mounted
secret provider, the fixed source-mount registry, the PostgreSQL pool as
`knowvault_worker`, the mounted artifact-wrap provider, the source digester,
the ingestion repository and the durable job queue. No handler receives a
runtime handle, secret provider, database pool or close capability.

The worker loop uses the existing claim/reclaim/heartbeat/complete/fail job
surface. `SOURCE_SCOPE_SYNC` is dispatched to `ingestion.Handler`; unsupported
job types are failed with a content-free retry code. A handler heartbeat is
performed at every object boundary and before final reconciliation/publication,
using the same bounded extension as the initial lease. The loop stops cleanly
on process cancellation and cleanup is one-shot, reverse ordered and shared by
copied runtime handles.

## 2. Fixed source-mount registry

The worker reads `/run/knowvault/sources/manifest.json`; it never accepts an
absolute path from a job, a source profile or an environment variable. The
manifest is strict JSON with schema `knowvault-source-mount-manifest-v1` and
entries `{alias, identity, directory}`. `directory` is one safe child name
under `/run/knowvault/sources`; the loader rejects unknown/duplicate members,
duplicate tuples/directories, traversal, symlinked roots and missing roots.
The registry resolves only the exact `(root_alias, root_identity)` tuple from
the trusted connection profile. The source directories themselves remain
read-only deployment mounts and the folder connector performs its own pinned
root/containment checks on every discovery/read.

## 3. Purpose-separated source digest key

The mounted manifest adds the required `source_digest_hmac` versioned key. It
is exposed only as a purpose-typed `secretmount.SourceDigestKey`, with a
distinct reference and material fingerprint from identity, session, OIDC
transport and artifact-wrap material. The worker copies the key only into the
in-memory ingestion digester and clears that copy during runtime cleanup;
`Provider.Close` clears the provider-owned material. Missing, duplicated,
zero, malformed or cross-purpose material fails startup.

This is a security-surface change and therefore remains PROPOSED until the
owner confirms the mounted-secret manifest rollout and updates the deployment
secret generation/rotation procedure. Until then, the production parser
activation gate remains unchanged.

## 4. Proof required before the active flip

- Linux worker image build from the complete `internal/**` tree and scratch
  runtime with fixed trust, secret and source mountpoints;
- real PostgreSQL claim → heartbeat across a long folder sync → Evidence →
  complete, plus crash/reclaim idempotency and no duplicate rows;
- mounted-secret positive/negative/zeroization tests for the fifth key;
- architecture checker, unit/integration/acceptance/security checks, pinned
  Linux race run, image/SBOM checks and two independent reviews;
- owner confirmation for the source-digest secret rollout and the existing
  parser dependency/license gate.
