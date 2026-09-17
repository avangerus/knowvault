# ADR-NNNN — Short solution name

**Status:** proposed | accepted | superseded

**Date:** YYYY-MM-DD

**Owners:** team/solution owner

**Related:** links to issue, phase charter, contract, ADR, and code

## Context

What problem are we solving? What invariants, trust boundaries, license/version/operation constraints, and current delivery coordinates are important? What is intentionally out of scope?

## Decision

Unambiguously describe the selected rule. Specify the owner of each authoritative state, transaction/process boundaries, rejection on invalid input, and what constitutes proof of correctness.

## Alternatives considered

| Option | Why it was not selected |
| --- | --- |
| Alternative A | trade-off |
| Alternative B | trade-off |

## Consequences

### Positive

- ...

### Negative / trade-offs

- ...

### Security and failure semantics

- What happens in the absence of identity, scope, license, evidence, key, dependency, or upon redelivery?
- Can the solution be bypassed via another route, job, worker, or recovery path?

## Implementation and evidence

- Code/packages:
- Contracts/schemas:
- Negative/mutation tests:
- Guardrails/versions/licenses/protected hashes:
- Required CI or phase evidence:

## Delivery status

Indicate that `current`, that `target`, that `reserved`, and that `deferred`. Do not update `DELIVERY_STATE.md` without factual evidence and owner decision.

## Supersedes / superseded by

Filled only when replacing the solution. The old ADR is preserved for history.
