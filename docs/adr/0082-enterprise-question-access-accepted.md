# ADR-0082 — Authenticated HTTP/MCP question access

Status: Accepted  
Date: 2026-08-29  
Owner confirmation: the product owner explicitly requested a deployable system
whose users can ask workspace-scoped questions through the UI, a versioned API
and MCP. This ADR records that boundary amendment; it does not authorize any
other MCP tools or public write surface.

## Decision

KnowVault exposes the same `QuestionService` through three adapters:

* the browser UI and `/api/v1/workspaces/{workspace_id}/questions` route;
* the authenticated versioned HTTP API, using the existing tenant/session,
  CSRF, workspace RBAC and evidence disclosure gates. Browser callers use the
  session cookie; non-browser callers may send the same server-issued opaque
  session token once as `Authorization: Bearer …` (never together with a
  cookie). This is a transport adapter, not a second token authority;
* an authenticated read-only JSON-RPC MCP endpoint at `/api/v1/mcp`, using the
  same browser or bearer session boundary.

The MCP adapter implements only `initialize`, `tools/list` and one tool,
`knowvault_question`. The tool accepts a workspace id, human question and the
`EXTRACTIVE` answer mode. It cannot execute SQL, select a source, mutate a
workspace, call a model tool or access another workspace. `Idempotency-Key` is
required for `tools/call`; citations and deep links are returned from the same
persisted Question Run as the UI/API.

## Alternatives and impact

1. Keep MCP forbidden and require browser-only access. Rejected: it cannot
   support the requested integration with another system.
2. Add a separate agent/tool runtime or public unauthenticated API. Rejected:
   it would create a second policy authority, enlarge the threat surface and
   violate the evidence/RBAC invariants.
3. Use a thin adapter over one Question Run authority. Accepted: no new
   persistence or dependency, one authorization path and deterministic replay.

No new third-party dependency or license is introduced. JSON-RPC is implemented
with the pinned Go standard library JSON implementation.

## Acceptance evidence

* route parsing and method/CSRF tests cover initialize, tool discovery, invalid
  calls and a question call delegated to the injected authority;
* existing Question Run integration tests remain the source of truth for tenant
  isolation, workspace membership, idempotency and evidence citations;
* architecture guardrails remove only the MCP prohibition and retain all
  prohibitions on chat, agents, writes, arbitrary SQL and cross-workspace search.
