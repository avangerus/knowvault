# ADR-0073: Product surface for revision activation and Evidence delivery (D3-1, I3)

Status: accepted.

Extends ADR-0059 (source lifecycle) and ADR-0058 (catalog/extraction/Evidence).
The mutation and integration corpus proves the durable-job substrate and the
authorized Evidence read path in isolation, but the product loop is still
absent: no production product surface enqueues a job, and the Evidence viewer
has no HTTP surface. This ADR records the contract that the next product result
must satisfy. It composes no surface itself, creates no endpoint and closes no
R3 criterion while the current coordinate remains P2/R1.

## 1. Decision

1. **Production enqueue (D3-1).** The revision-activation path (and every later
   R3 scenario) places its work through `jobs.Queue.Enqueue` from the product
   surface — an authenticated HTTP operation under the existing policy layer —
   never from a test helper and never by direct SQL. The gate is mechanical:
   `Enqueue` has at least one non-test caller on the activation path, and the
   D3-2 idempotency/lease-reclaim proofs (JOB-001…005) keep binding the
   substrate.

2. **Evidence viewer HTTP (I3).** The viewer surface is an HTTP endpoint that
   returns a fragment's decrypted normalized text and canonical anchor through
   the fail-closed gate of `internal/source/evidence` — every denial an
   identical `ErrNotFound` with no existence oracle, per the R1 deny matrix
   (ADR-0058 §7). The surface adds provenance and deeplink per the I3 charter
   and a minimal inspection UI; no seed data and no value that did not come
   from the system (D4-1). The D3-1/D3-3/D4-1 criterion identifiers originate
   in the owner prototype package outside this repository; this ADR carries
   their wording into the tree.

3. **Access fence, not callbacks.** Any authorization on the viewer or
   ingestion surface must live at the SQL/Go access point (the
   `evidence_fragment_readable` gate pattern) and never in a no-op callback or
   a client-side check. A checker-side gate keeps a surface edit from
   reintroducing a placeholder authorization path.

4. **Not in this ADR.** Question Run, generative answer, session termination
   (OWNER-SESSION-TERMINATION) and extractive answer semantics
   (OWNER-EXTRACTIVE-ANSWER) stay blocked by their own registered decisions;
   composing the enqueue/viewer surface does not unblock them.

## 2. Acceptance binding

D3-1 (production-path enqueue, idempotent, reclaim), D3-3 (typed status and
errors visible), I3 (viewer API, provenance, deeplink, synthetic corpus) and
D4-1 (no surface value that is not system-derived) become the acceptance
criteria of the result that lands this surface, executed on real PostgreSQL in
CI. The ACCEPTED-RISK-EVIDENCE-NOOP blocker in `docs/DELIVERY_STATE.md` ends
only when the composed surface exists and its deny matrix passes — not when
this ADR is accepted, and not when a UI exists without the fail-closed path.

## 3. Consequences

The next product result gets a fixed target: a production enqueue call and an
HTTP Evidence viewer with the R1 deny matrix, provenance and deeplink, proven
by the D3/I3/D4 criteria. Until that result, this ADR is normative
preparation; it activates nothing and renames no blocked scope.
