# ADR-0005: PostgreSQL durable jobs

Status: `ACCEPTED`

## Solution

In 1.0, jobs, leases, retries, dead letter, and transactional outbox are implemented in PostgreSQL. Separate Redis, broker, or Temporal are not used.

## Why

- fewer runtime components for on-edge;
- atomicity of state transition and outbox;
- sufficient load model for the first version;
- simpler backup, restore, and operations.

## Consequences

Transition to a separate workflow/broker is permitted only after a measured bottleneck and a new ADR.

