# ADR-0056: Durable ingestion job substrate and worker execution boundary

Status: accepted.

Closes the delivery gate ADR-0046 deferred. ADR-0046 installed the ordered
transactional outbox and stated that no production applier may be composed
"until a dedicated worker role plus head-only lease/CAS, bounded retry,
poison/dead-letter and idempotent external-effect contract is implemented and
accepted." ADR-0046 remains an unedited historical record; this ADR is the
current authority for the durable job substrate. It authorizes the durable
job / lease / retry / dead-letter execution engine and the dedicated worker
identity that owns it. It does not authorize a connector, extraction, parser,
Evidence or OpenSearch delivery: those attach handlers to this substrate in
later slices, and the outbox applier itself stays uncomposed until its external
sink exists, because a silent skip of an outbox event is still forbidden.

Migration `000013` installs the substrate. It introduces no new runtime
component beyond the already-required `knowvault-worker` binary and no new
dependency; PostgreSQL remains the accepted job store (ADR-0005).

## Dedicated worker identity

`knowvault_worker` is a separate login role from the Web/API runtime
`knowvault_app`. It has no ownership, superuser or RLS-bypass capability. The
separation is the boundary that makes lease/execute authority unreachable from a
request handler: the producer role can enqueue durable work and read
diagnostics, but only the worker role can lease, heartbeat, complete, fail or
reclaim. Neither role receives direct `INSERT`/`UPDATE`/`DELETE` on the job
tables — every mutation flows through a `SECURITY DEFINER` function that owns the
transition, and an independent trigger re-checks the invariants even on that
privileged path. The role is provisioned by the operator exactly like
`knowvault_app`; the migration asserts its existence and fails closed otherwise.

## Lease, fencing and crash recovery (JOB-001, JOB-004)

A job carries a monotonic `lease_epoch` fencing token. Every claim increments it
and opens exactly one attempt row. A claim uses `FOR UPDATE SKIP LOCKED`, so two
workers never lease the same job. A heartbeat, completion or failure succeeds
only against a live lease whose owner and epoch match exactly; a worker whose
lease has already lapsed presents a stale epoch or a passed deadline and is
refused. A lost worker leaves a `RUNNING` row whose `lease_deadline` passes;
reclamation closes the crashed attempt as `LEASE_EXPIRED`, charges it against the
retry budget, and either re-queues the job or dead-letters it. A job is therefore
never lost, never leased twice, and never resurrected by a slow worker whose
lease another worker already took.

## Bounded observable retry and dead-letter (JOB-002, JOB-003)

Retries are bounded by a per-job `max_attempts` budget. A failure within budget
re-queues the job after a bounded backoff; a failure that exhausts the budget —
or a crash that exhausts it — moves the job to the terminal `DEAD` state rather
than looping forever. A poison object that only ever fails or crashes therefore
dead-letters deterministically. Every failure records a content-free operator
error code on both the attempt and the job, and a content-free per-status counter
exposes queue health, so every operator-visible failure has a code and a metric.

A job is acknowledged only inside the worker's own result transaction: derived
writes and follow-on enqueues commit atomically with the `SUCCEEDED` transition,
and a rolled-back completion leaves the job `RUNNING` to be reclaimed. A job is
never marked done without proof the worker still holds its lease.

## Immutability and tenancy

Job identity, definition, idempotency key and creation time are immutable; the
fencing epoch and attempt count only ever advance; a terminal job never
transitions again; attempt history is append-only. Both tables use tenant
`FORCE ROW LEVEL SECURITY`, and the definer functions scope every query to the
caller's organization explicitly rather than trusting RLS on the privileged
path. Enqueue is idempotent on `(organization, idempotency_key)`: a repeat
returns the original job and never creates a second unit of work.

The job payload is a bounded closed reference/hash object identical in spirit to
the outbox payload, except an empty object is allowed because a tenant-scoped job
references no single aggregate. Text, ciphertext, paths, titles, principals and
secrets can never be smuggled into a job or attempt row. The semantic owner is a
typed Go package that exposes exactly these state-machine operations and no
generic table capability.
