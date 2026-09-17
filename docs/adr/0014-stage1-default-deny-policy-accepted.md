# ADR-0014: Stage 1 default-deny workspace policy

Status: accepted.

`internal/policy` is the pure, shared decision function for the first Stage 1
operations. It takes a server-resolved identity/session snapshot, current
workspace state and current membership; it does not parse tokens, query a
database or trust client-supplied scope filters.

The function is default deny. It rejects malformed context, tenant mismatch,
inactive/deprovisioned principal, unavailable workspace, absent membership,
insufficient role and unknown operation. Policy output is a typed allow/deny
result with safe reason codes. A later persistence adapter assigns the durable
`PolicyDecision` ID and policy revision; it does not reinterpret the rule.

Organization administration is management authority, not implicit data access:
an Organization Admin without current workspace membership cannot view its
metadata or content. A Security Auditor or workspace Auditor may receive only
the separate `audit.read_metadata` operation. Neither role receives workspace
content through that exception.

`ACTIVE` workspaces permit new questions and management changes by their
allowed roles. `READ_ONLY` and `ARCHIVED` may expose already-authorized
historical metadata/content but do not accept a new question. `DELETING` and
`DELETED` deny all operations.
