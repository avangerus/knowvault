# ADR-0081 — One-shot parser sandbox dispatcher v2

**Status:** proposed

**Date:** 2026-08-28

**Owners:** product owner, platform/security owners

**Related:** ADR-0062, ADR-0063, ADR-0068; `SAN-001`–`SAN-004`, `ING-006`,
`PAR-002`; P2 criteria 1–4

## Context

The accepted v1 dispatcher contract proves pull-only lease semantics but is not a
production composition. Its single multiplexed socket permits a peer to choose a
role by its first frame, its registered JVM can receive more than one document,
and a successful result can reach the submitter before the parser process and its
descendants are proven gone. The v2 capability tuple added for Office/PDF/OCR is
necessary but does not by itself close those process-lifetime and role-separation
gaps.

Production activation must preserve a stronger invariant: one opaque document,
one exact parser capability tuple, one fresh sandbox, one kernel-confirmed runtime
profile and one fenced result. Tenant, workspace, source-version and persistence
identities must not enter the parser boundary. Qualification-only direct
`os/exec`/container facades are not production composition.

This proposal does not activate the dispatcher, document parser or OCR
dependencies. The existing v1 contracts remain immutable evidence for their
accepted scope until an owner accepts this proposal and the implementation gates
below are complete.

## Decision

1. Dispatcher v2 has physically distinct Unix sockets and mounts:
   `submit`, `supervisor-handoff`, `register-office`, `register-pdf`, and later
   separate renderer/OCR registration sockets. A connection cannot select or
   change its role with a frame. The ingestion worker receives only the submit
   socket. A parser sandbox receives only its exact registration socket. The
   external supervisor receives only the supervisor-handoff socket.
   The submit listener also accepts an optional content-free native readiness
   probe (frame kinds 16/17) after the same exact submitter credential check.
   Its closed body binds the production sandbox revision and artifact; the
   response reports only current unused OFFICE/text-PDF capacity after
   registration acknowledgment. It grants no lease, changes no replay state,
   and is serialized with the RED publication barrier. Wrong/old replies or an
   unavailable listener are non-ready. This extension does not change the v1
   job/result contracts or activate any dependency.
2. Before worker registration, the external supervisor sends a fresh, single-use
   handoff over its dedicated socket. The handoff passes the process pidfd as a
   Unix file descriptor with `SCM_RIGHTS` and binds dispatcher-observed peer
   credentials, host-observed PID namespace inode, exact dedicated cgroup path,
   parser type, exact qualified artifact hash, sandbox/observation profile
   revisions and a random correlation identifier. None of this authority may
   come only from worker JSON, a numeric PID supplied by the worker or an
   unverified filesystem path. The dispatcher rejects missing, duplicate, stale
   or mismatched handoffs before acknowledging registration.
3. Worker registration is versioned and must match exactly one unused supervisor
   handoff. Together they bind one peer pidfd, one dedicated PID namespace whose
   parser is PID 1, one dedicated cgroup, one parser type, one qualified artifact
   identity and one protected sandbox profile. A registration is eligible for
   exactly one lease. A second lease is impossible even after success.
   Submitter, supervisor, Office and PDF are distinct exact UID/GID principals;
   every listener enforces `SO_PEERCRED`, an exact owner and mode `0600`.
4. The deployment-owned capability registry is authoritative. The submitter may
   request only an exact allowlisted `ParserRequestV1` tuple; it cannot choose an
   arbitrary sandbox profile, output contract, limit or deadline. Media family and
   input media type must be an exact registered pair.
5. Before transfer, absence/disconnect is a typed retry. After transfer, every
   contradiction, timeout, cancellation or teardown failure is quarantine. The
   dispatcher recomputes the input digest before transfer and the result digest
   before accepting the outcome. It accepts at most one result frame and compares
   the outcome's complete request byte-for-byte with the active request.
6. A worker sends its bounded result/outcome, closes the socket and exits. The
   dispatcher holds the result unpublished until the pidfd observes exit, the
   dedicated cgroup is empty, descendants cannot survive, and final kernel limits
   match the registered profile. Deadline/shutdown uses pidfd/cgroup teardown;
   inability to kill or confirm emptiness is quarantine and a red readiness state.
7. `runtime_profile_hash` and execution confirmation are dispatcher-owned. The
   runtime hash is added to the Go-side observer identity and therefore to the
   immutable Extraction profile together with worker artifact hash and observation
   revision. Worker self-report is never the authority.
8. The dispatcher creates no container and launches no process. An external
   orchestrator supplies a fresh one-shot sandbox and restarts it for the next
   lease. Production ingestion imports only the dispatcher-backed facade; the
   qualification facades remain inaccessible from production composition.
9. The released parser image exposes only the dispatcher-once entrypoint. A
   direct stdin/CLI extraction mode, including one retained only for tests, is a
   production capability bypass and is forbidden in the shipped artifact.
   Parser-semantic tests must use a test-only harness outside the released JAR;
   end-to-end qualification must exercise the real dispatcher socket path.

## Alternatives considered

| Variant | Why not selected |
| --- | --- |
| Reusable Java daemon | Parser/library state and compromised state can cross document boundaries; success does not prove teardown. |
| One multiplexed Unix socket | A peer can choose submitter or parser role by the first frame; mount-level least privilege is impossible. |
| Go wrapper spawning the Java CLI | The wrapper introduces a child-process lifetime and descendant-escape problem; dispatcher observation no longer directly identifies the parser. |
| Publish then asynchronously clean up | Violates fail-closed publication and permits source-bearing descendants after Evidence activation. |

## Consequences

### Positive

- Cross-document parser state is structurally impossible.
- Role separation is enforced by deployment mounts as well as protocol checks.
- A successful Evidence set has proof that no source-bearing parser process remains.
- Kernel limits and worker identity both change the immutable Extraction identity.

### Negative / trade-offs

- Parser startup cost is paid per document and the orchestrator must maintain a
  ready pool/restart policy.
- Linux pidfd, PID namespace and cgroup v2 become explicit platform requirements;
  unsupported kernels fail readiness.
- v2 needs new deployment, image, SBOM, mutation and real-Linux acceptance proof;
  v1 cannot be relabelled as production evidence.

### Security and failure semantics

No worker, profile or kernel proof means no publication. Pre-transfer unavailability
is retryable under the durable job fence. Once bytes cross the handoff, failure is
per-object quarantine. Dispatcher shutdown drains or tears down every active
sandbox and cannot return green while a pidfd/cgroup remains unresolved. Any
trust contradiction that latches RED stops new admissions and synchronously fences
all active result publication before bounded teardown.

## Implementation and evidence

- Code/packages: a separate v2 runtime in `internal/sandboxdispatch`; production
  facade in `internal/source/dispatchparser`; worker/dispatcher composition roots.
- Contracts/schemas: versioned registration plus existing v2 job/lease/outcome/
  limit-confirmation and parser-request schemas; a separate supervisor-handoff
  wire contract whose pidfd is transferred out-of-band with `SCM_RIGHTS`.
- Negative/mutation tests: cross-role/cross-socket, request/media/profile/limit
  drift, digest/result replay, duplicate result, stale confirmation, PID reuse,
  child escape, deadline, disconnect, shutdown and teardown failure.
- Guardrails: `SAN-001`–`SAN-004`, `ING-006`, `PAR-002`; protected deployment
  manifests must prohibit shared role sockets and reusable parser leases.
- Required proof: real Linux cgroup/pidfd + real one-shot Java worker + real
  PostgreSQL for DOCX/PPTX/XLSX/PDF, pinned Linux race, exact image rebuild,
  SBOM/license/CVE/offline verification and two independent reviews.

## Delivery status

Current: v2 data contracts and text-PDF qualification exist; production activation
does not. Target: the implementation/evidence above and an atomic lifecycle flip.
Reserved: renderer/OCR sockets use the same one-shot rule. Deferred: pool sizing
and performance optimization that does not weaken one-document isolation.

## Supersedes / superseded by

If accepted, this ADR supersedes only ADR-0068's v1 mechanical protocol as the
production-composition target. ADR-0068's no-container-runtime, pull-only,
handoff and kernel-observation decisions remain in force.
