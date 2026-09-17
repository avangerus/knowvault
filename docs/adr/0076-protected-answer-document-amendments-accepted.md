# ADR-0076: Protected answer-document amendments

Status: accepted.

Owner decision recorded 2026-08-14: the owner delegated closure of the blocker to the OWNER-EXTRACTIVE-ANSWER executor with the right to make decisions on the scope.
This ADR records the contract of the package of protected edits; it does not weaken any gate; ADR-0067 and its EXA-* guardrails remain unchanged.
Acceptance activates nothing: Question Run, search, and the answer surface remain outside the coordinate; the R6 boundary itself is closed in P4 via an adversarial pass, not by this package.

## 1. Decision

1. The published answer manifest is immutable (R6: "Answer is immutable"). No edit overwrites the published document; each statement remains a verbatim fragment with an exact anchor and a resolvable chain to the version (ADR-0067: claim — deterministic projection of signed context; EXTRACTIVE ⇒ BYTE_EXACT_CITATION).
2. An edit is a separate superseding version of the document with its own signature, the previous version (chain by hash), and the reason for the edit. Semantic edit classes are closed: supersede (replacement), retract (withdrawal of a statement), redact (removal of content while preserving the audit trail). Any class outside the closed list is rejected.
3. Every opening of any version re-verifies access (R6: "manifest is signed and re-verifies access upon every opening"): a version whose organization no longer has access to the cited fragments (retention/purge/ACL revocation) does not open as proof.
4. Verification is deterministic: numbers/dates/units pass validation without a model (ADR-0067 §1); an edit does not change the method of verification for previously published statements.
5. Protected document: edits are gated — applied only via the ownership path (audit event for each edit, actor, and request id), without silent updates or "polishing" of already published text.

## 2. Mechanical contract

- Response version: signed manifest (schema from ADR-0067, v2.0) + immutable
  version record with `previous_version_hash`, `amendment_class`, `amended_at`;
- chain integrity: each new version hashes the previous one (SHA-256 hash chain
  per owner requirements), chain breakage is rejected;
- read-path: signature verification + re-access check for fragments on every
  open; retracted/redacted assertions are not published as proof;
- audit: `answer.document.amended` (class, version, actor, request id, without
  content).

## 3. Consequences

- Acceptance of the package by the owner + independent review removes the blocker
  OWNER-EXTRACTIVE-ANSWER (prerequisite R6).
- No existing gate is weakened; ADR-0067 and its EXA-* guardrails
  remain unchanged.
- The R6 milestone itself is closed in P4 with an adversarial pass, not with this package.

## 4. Acceptance evidence

- schema-fixtures: positive (supersede/retract/redact) and negative (overwrite published → RED; chain break → RED; opening version without rechecking access → RED; edit without owner-path → RED; semantics-preserving permutations → GREEN);
- contract tests and package checker-gates;
- independent package revision.
