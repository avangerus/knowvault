# ADR-0068: Pull-based sandbox dispatcher (R-7 through R-11)

Status: accepted.

This ADR applies the owner's sandbox boundary as a protected protocol and
deployment contract. It closes the architectural ambiguity about who may create
and supervise a sandbox, but it does not compose or activate the dispatcher in
the current P2/R1 result.

## 1. Decision

1. No application component may create a container or invoke a container
   runtime. `knowvault-sandbox-dispatcher` is the fourth allowed binary and is
   the only future component at the orchestration boundary; its own contract
   still forbids arbitrary runtime access.
2. A sandbox is declared in the protected deployment manifest. A parser worker
   starts independently and pulls one leased document; the dispatcher never
   pushes arbitrary process input into a worker and has no database, secret, or
   container-runtime capability.
3. The parser type is a property of exactly one registration socket. The socket
   registration and the lease must carry the same parser type; a foreign socket
   or a second registration socket is rejected.
4. The handoff point is explicit: before transfer a failure is retryable; after
   transfer the lease is quarantined unless the dispatcher records an explicit
   confirmation.
5. A supervisor owns the deadline. Kernel namespaces are torn down with the
   process so descendants cannot survive the lease.
6. CPU, memory, PID, and wall-clock limits are confirmed from kernel-observed
   state at startup. The observed limits are part of the extraction identity;
   worker self-report is not evidence.

## 2. Mechanical contract

The four wire schemas are `sandbox-job-v1`, `sandbox-lease-v1`,
`sandbox-outcome-v1`, and `sandbox-limit-confirmation-v1`. The protected
`deploy/manifests/sandbox-dispatcher.yaml` declares the boundary and remains
`CONTRACT_ONLY` until a later production-composition result.

The schema suite includes positive instances and negative instances for container
creation, parser-type mismatch, unbound outcome identity, and self-reported
limits. Runtime composition and end-to-end worker activation remain outside this
result and therefore cannot be reported as complete.

## 3. Consequences

The old three-binary invariant is replaced by a four-binary allow-list with only
the three currently composed application commands required at the command
surface. Adding the dispatcher command without its manifest, protocol tests,
and independent composition gate is rejected. No protected access fence is
weakened to make `SOURCE_ENFORCED` succeed.

## 4. Acceptance evidence

- the protected deployment manifest;
- the four strict JSON schemas and their positive/negative fixtures;
- version-lock and command-surface closed registries;
- independent review and architecture/schema CI.
