# Connecting an agent to KnowVault (MCP access code)

An agent authenticates to the knowledge-tool MCP endpoint
(`/api/v1/mcp`) with its own access code — never a human's browser session.
A workspace OWNER creates the code from that workspace's **Access** tab:
name it, choose an expiry, and
copy the code shown — it is never shown again. Revoking it (same tab)
removes the agent's access immediately.
The current dialog issues a code for the open workspace. The API below can
issue one code for several workspaces when the caller is OWNER of each.

## Claude Code

```
claude mcp add --transport http knowvault https://<your-knowvault-host>/api/v1/mcp \
  --header "Authorization: Bearer <access-code>"
```

The equivalent Claude Code `.mcp.json` uses `type`, not `transport`:

```json
{
  "mcpServers": {
    "knowvault": {
      "type": "http",
      "url": "https://<your-knowvault-host>/api/v1/mcp",
      "headers": { "Authorization": "Bearer <access-code>" }
    }
  }
}
```

Use this only in a private client configuration; do not commit a real code.
The HTTP/header syntax is documented by
[Claude Code](https://code.claude.com/docs/en/mcp#option-1-add-a-remote-http-server).
This is not a `claude_desktop_config.json` example. Claude Desktop's local
servers and its cloud-hosted remote connectors use different connection paths;
the latter do not reach this LAN-only pilot directly. See
[the remote connector documentation](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).
No additional bridge or public endpoint is required by the KnowVault pilot.

## What the agent can do

The current `tools/list` catalog contains ten knowledge tools, scoped to
the workspaces the code was issued for:

- `knowvault_question` — a grounded question run;
- `knowvault_evidence_get` — evidence readback;
- `knowvault_search` — ranked search;
- `knowvault_read` — reading an address;
- `knowvault_list_objects` — object inventory;
- `knowvault_related` — related fragments;
- `knowvault_grep` — literal text search;
- `knowvault_sources` — source status and freshness;
- `knowvault_refresh` — request a source refresh under existing permissions;
- `knowvault_governed_query_ask` — an additional read-only SQL capability,
  requiring separate workspace opt-in; it is disabled for the entity-snapshot
  pilot and is not needed to search/read its SQL data.

The credential grants ordinary MEMBER knowledge access. It does not grant
source registration, membership, confirmation or other administration.
Administrative tools and unknown tool names return the same content-free
error; an inaccessible workspace and an unknown workspace return the same
content-free scope error. A refresh remains subject to the normal source
permission checks; listing the tool does not bypass them.

Read audit events identify the SERVICE using `actor_type: SERVICE` and
`actor_principal_id`. The access-code list maps that principal to its chosen
name. Source metadata reads have a separate `source.metadata.read.admitted`
event followed by `completed` or `failed`; they are not journal-read events.
Both the source-status list and confirmation context are covered. Failure to
write the admission or completion withholds the metadata from the caller.

## Owner API lifecycle

All paths below are relative to `/api/v1`. Use the owner's human API bearer,
or the browser session with the required Origin and CSRF headers. A SERVICE
code authenticates only at `/api/v1/mcp`.

- `POST /workspaces/{workspace_id}/access-codes` requires `Idempotency-Key`
  and JSON `{"name":"agent","workspace_ids":["ws_..."],"ttl_seconds":86400}`.
  The route workspace is included automatically. The caller must be OWNER
  of every selected workspace; the maximum is 20. TTL is 3,600–15,552,000
  seconds (1 hour–180 days). The nonempty name is at most 256 UTF-8 bytes.
  No `If-Match` is required. HTTP 201 returns `credential_id`, `principal_id`,
  `name`, the one-time `code`, `workspace_ids` and `expires_at`.
- `GET /workspaces/{workspace_id}/access-codes` requires OWNER and returns
  `access_codes` with identifiers, names, scope, creation/expiry times and
  optional `revoked_at`; it never returns the secret.
- `POST /workspaces/{workspace_id}/access-codes/{credential_id}:revoke`
  requires `Idempotency-Key`, no `If-Match`, and OWNER of every workspace
  in the credential's scope. HTTP 200 returns `{"revoked":true}`. An already
  revoked or unknown credential returns 404. The next MCP call with the
  revoked code fails authentication with HTTP 401.

An exact issuance retry cannot show the raw code again: it returns HTTP 409
`SERVICE_PRINCIPAL_ALREADY_ISSUED`; reusing the key with a different request
returns an idempotency conflict. Keep the first issuance response securely.

## Caveats

- The code is bound to the exact workspaces chosen at creation; asking about
  any other workspace is refused (fail-closed, content-free — the same
  response a wrong workspace ID gets from a human session).
- An expired or revoked code stops authenticating immediately; issue a new
  one rather than trying to recover the old raw value (it is never stored).
- This is a separate authentication path from the human browser/API session
  bearer described in `docs/DEPLOYMENT.md` — the two are never interchangeable.
