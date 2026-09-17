# ADR-0075: Session termination (logout)

Status: accepted.

Owner decision recorded 2026-08-14: the owner delegated the blocker closure to the OWNER-SESSION-TERMINATION executor with the right to make decisions on the scope.
This ADR fixes the semantics of logout; it does not weaken any gate and does not change the accepted ADR-0028/0030/0031. The implementation remains a separate sanctioned package.

## 1. Decision

1. Logout — explicit owner session invocation: `POST /auth/logout`,
   CSRF-protected like other session mutations (ADR-0028). The route is
   already reserved in the dispatcher as an auth route, returning 404 outside
   of authentication; the method is closed (GET and others do not perform logout).
2. Invalidation — existing scheme mechanism: `identity_session` (000003)
   carries `revoked_at`/`revocation_code`; logout transitions the session
   line to revoked in a single transaction. The token (`session_token_digest`) is
   not reused; re-login is a new session. Global invalidation
   session-key rotation (ADR-0030) does not replace logout.
3. Cookie `__Host-knowvault_session` (and `__Host-knowvault_csrf` if necessary) is cleared in
   the same response (`Max-Age=0`). After logout, any request with the same
   token is processed as unauthenticated; no guard opens for a "half-closed"
   session.
4. RP-initiated logout: for production IdP (Keycloak, ADR-0072) — invocation
   of `end_session_endpoint` with `id_token_hint` after local invalidation; for
   test IdP — not required, but the contract does not leave a half-closed
   state. Provider failure does not roll back local invalidation
   (fail closed: session remains closed).
5. Audit: event `session.terminated` (actor — principal, outcome
   SUCCESS/FAILED, error code, request id, without content). Logout with
   invalid/foreign session — FAILED with closed code, not revealing the
   validity of a foreign session (not oracle, AUD-005).
6. Idempotency: repeated logout of an already invalidated session — FAILED with
   the same closed code; state does not change, events are not duplicated.

## 2. Mechanical contract

- Route `POST /auth/logout`, CSRF token is mandatory (ADR-0028);
- invalidation: `UPDATE identity_session SET revoked_at = now(),
  revocation_code = <SESSION_TERMINATED> WHERE ...` in a single transaction with
  the audit event;
- read-path: authorization does not accept revoked sessions (extension of lookup
  for active sessions);
- audit vocabulary: `session.terminated`, error code `SESSION_TERMINATION_FAILED`;
- cookie contract: exact names from ADR-0030.

## 3. Consequences

- Upon acceptance, the logout portion of R4 is closed and the OWNER-SESSION-TERMINATION blocker is removed.
- No existing gate is weakened; ADR-0030 (session key rotation), ADR-0028 (CSRF), ADR-0031 (sealed transport) remain unchanged.
- Upon acceptance, ADR-0072 integration of `end_session_endpoint` Keycloak is part of the production environment, not this package.

## 4. Acceptance evidence

- migration/trigger + handler + negative-tests:
  - logout, launched via GET link (without CSRF) → RED;
  - logout without session invalidation → RED;
  - revoked token passes guard (read-path) → RED;
  - logout reveals validity of another's session → RED;
  - semantics-preserving permutations → GREEN;
- audit-events `session.terminated` (SUCCESS/FAILED) on real PostgreSQL;
- independent package review.
