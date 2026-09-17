# Architecture baseline trust boundary

Status of external enforcement: `PENDING_REMOTE_CONFIGURATION`.

## What is the Source of Truth

Regulatory documents, accepted ADR, contracts, version/license locks, architecture checker, and CI definition are protected not by their own hashes within the same workspace tree, but by an external Git server and its policies.

Local `protected-hashes.json` detects random drift. It is not a security trust root: the executor capable of changing the document is also capable of changing the local hash/checker.

## Mandatory remote policy before the first release

- default branch protected, force-push and delete are forbidden;
- modification of protected paths requires CODEOWNER approval from the architecture owner;
- modification of policy/checker/CI workflow requires a second security approval;
- required status checks are executed from the protected branch configuration;
- the PR author cannot unilaterally approve their own change;
- administrator bypass is either disabled or separately audited and blocks release;
- merge commit/tag for release is signed and linked to passed CI attestation;
- CI emits SBOM/AIBOM, test report, and provenance for the exact commit;
- release job reads version/image lock only from the protected commit.
- anti-drift checker treats version/license inventory as a closed registry and performs built-in mutation tests for unknown components and missing integrity evidence;
- required CI command is confirmed by parsing the executable `run` block; matching in comment, `echo`, or arbitrary text in the workflow is not considered enforcement.

Protected paths:

```text
/PRODUCT_CONSTITUTION.md
/ARCHITECTURE.md
/POKA_YOKE.md
/.gitattributes
/.dockerignore
/.gitignore
/go.mod
/db/**
/web/package.json
/web/pnpm-lock.yaml
/deploy/images/Dockerfile.*
/deploy/compose/compose.yaml
/deploy/manifests/sandbox-dispatcher.yaml
/architecture/**
/docs/adr/*-accepted.md
/docs/CANONICALIZATION.md
/docs/CONTRACT_VALIDATION.md
/docs/ENCRYPTION.md
/docs/NUMERIC_VALIDATION.md
/docs/PARSER_CONTRACTS.md
/docs/SOURCE_CONTRACTS.md
/docs/HLD.md
/docs/DATA_MODEL.md
/docs/PILOT-ACCEPTANCE.md
/docs/TRUST_BOUNDARY.md
/scripts/check-architecture.*
/tests/contracts/**
/.github/CODEOWNERS
/.github/workflows/architecture.yml
```

Equivalent GitLab/Bitbucket controls are permitted. The specific provider and actual team identifiers are fixed via a separate configuration after creating the remote.

## Current Mode

Before remote connection, local design, scaffold, and tests under the architect's direct review are permitted. Declaring a baseline as protected, building a release, or considering a local green check sufficient for release approval is prohibited.

## Accepted Additional Boundaries

Answer mode — a part of the signed manifest, not a UI switch. In `EXTRACTIVE` runtime does not receive the capability for generation or semantic verification: the server compares the claim with the authorized snapshot and the only byte-exact citation. In `GENERATIVE`, separate profile/run and verification gates from `CONTRACT_VALIDATION.md` apply.

The sandbox dispatcher remains an isolated future boundary. Neither the server nor the worker creates containers, obtains the container-runtime capability, or mounts secrets into the parser sandbox. The pull-only worker receives exactly one registered socket/parser type; handoff with loss of confirmation yields retry or quarantine, and limits are accepted only from kernel observation.

The future operator does not mix the data encryption key with the backup key. Restore is verified with negative ciphertext/tenant-boundary scenarios, and the operation error has a typed code, action, and metric; dependency-unavailable cannot look like readiness `true`. These boundaries are described in contracts and do not mean that the corresponding runtime is already included in the current composition.

# Model Gateway and customer-controlled inference peer

The accepted design boundary permits, in a closed on-premise deployment perimeter, either an exact pinned local model runtime or an exact customer-owned and customer-operated on-prem inference peer. The peer must reside within the exact customer deployment perimeter and be reachable only via the KnowVault Model Gateway; it is not a third-party/external SaaS service. Private/RFC1918 addressability, a common LAN, or a documented ownership assertion in themselves are not qualification evidence.

Dedicated model CA mount and dedicated client-identity mounts for the gateway — separate customer-mounted capabilities, not the system trust pool and not a common CA. Only exact paths `/run/knowvault/trust/model-ca.pem`, `/run/knowvault/identity/model-client-cert.pem`, and `/run/knowvault/identity/model-client-key.pem` are allowed, with checks for ownership, mode, byte fingerprint, and revision. The gateway and peer mutually verify mTLS exact hostname/peer/runtime/model-profile identity (hostname/SAN or pinned peer identity plus exact runtime and model-profile identity); cleartext, IP/name mismatch, certificate bypass, fallback identity, caller bearer credential, and endpoint discovery are prohibited. The client key is mounted only in the gateway process.

Peer accepts only gateway-only mTLS ingress. UI, API, MCP, and connector adapter do not have a direct route, socket, or protocol to peer; the MCP path remains conditional and inert until the separate acceptance of ADR-0079 and related protected amendments.
Inference host applies deny-all to new outbound connections, including DNS; exceptions are only for explicitly enumerated, digest/version-pinned customer-local dependencies, confirmed by technical routes, counters, and packet-capture evidence. HTTP(S), telemetry, training, log-forwarding, and arbitrary proxy canaries must be rejected.

On peer, technical configuration and live tests must demonstrate the absence of request/response logging, prompt/output retention, disk spool, checkpoint, backup/crash-dump retention, training/fine-tuning, provider forwarding, cross-tenant dynamic batching, and shared prefix/KV caches. Policy, operator declaration, or privacy statement without these tests are not evidence. All model calls remain organization/workspace/run/profile-bound and pass gateway post-authorization; the model receives only bounded authorized Evidence, without tools, credentials, or network capability.

# Customer-mounted TLS trust roots

Production PostgreSQL and OIDC trust are separate customer deployment inputs.
The server reads only `/run/knowvault/trust/database-ca.pem` and
`/run/knowvault/trust/oidc-ca.pem` through the strict Linux loader described in
ADR-0039. It never falls back to the system certificate pool, environment
proxy settings, an arbitrary path or a CA copied into a KnowVault image.

Both files must be present and valid before any listener is opened. Their
contents are snapshotted into non-convertible purpose types that retain only
private DER and reparse fresh certificate pools for the database and OIDC
consumers. Rotation therefore requires a process restart. KnowVault records
only the SHA-256 fingerprints of the exact accepted bytes for deployment
diagnostics. The customer owns the authority selection and licensing of the
mounted certificates.

Worker-side Git and IMAP trust is a third, source-only mount at
`/run/knowvault/source-trust/git-ca.pem` and `mail-ca.pem`. The resolver selects
the matching purpose root only after the exact encrypted source trust/config
artifacts and mounted credential reference have been verified; absence or
malformation fails the remote sync closed. These roots are not a system pool
and are never reused for PostgreSQL, OIDC or model traffic.
