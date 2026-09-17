# ADR-0069: Deterministic deployment and operations boundary (R-25 through R-28)

Status: accepted.

This ADR records the owner's operational contract and prepares the deployment
gates. It does not create an operator command, deploy a new topology, or close
R2 while the current coordinate remains P2/R1.

## 1. Decision

1. One static `knowvault-operator` binary owns bootstrap, role creation,
   versioned migrations, authentication-provider registration, key/secret
   manifests, and mount verification. It reuses product packages and does not
   contain a second implementation of domain rules.
2. Encryption keys are mounted secrets and are never stored in the backup
   artifact. A backup is not restorable merely because its archive is readable.
3. Restore becomes ready only after negative checks prove that missing keys,
   wrong tenant scope, stale migration state, and unavailable dependencies fail
   with typed errors.
4. Every unavailable dependency produces a typed operator-visible failure. Empty
   results, lexical fallback, silent retry exhaustion, and silent degradation are
   forbidden.

## 2. Mechanical contract

The operator contract is recorded in the protected architecture and trust-boundary
documents, with role/migration/backup accounting reserved for the deployment
implementation result. The version lock records the operator and backup-tool
decision as stage-blocking deferred components until their exact artifacts,
licenses, offline availability, and smoke/negative tests are accepted.

Readiness is a dependency-aware state distinct from process liveness. The
future operator must expose a code-to-action mapping for every failure and must
not turn a missing prerequisite into a green gate.

## 3. Consequences

There is one operational authority and one migration accounting stream. Backup
and restore cannot silently reintroduce secrets or an incompatible schema. This
ADR is normative preparation, not a claim that deployment tooling exists in the
current tree.

## 4. Acceptance evidence

- protected architecture, trust-boundary, and implementation-plan bindings;
- deferred version-lock entries with closed checker membership;
- operator/readiness negative-test requirements;
- independent review and architecture CI.
