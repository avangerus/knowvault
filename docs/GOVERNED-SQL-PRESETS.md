# Governed SQL presets

Governed SQL presets let an external MCP agent run a small, reviewed set of live
database checks such as “check contract status” or “show the current KPI”. They
reuse the governed-query connection and its dedicated PostgreSQL role. A preset
does not accept SQL or parameters from the user, model, MCP request or operator
mount.

## Review and pin a query

1. Configure the governed-query connection with a dedicated role that has
   `CONNECT`, schema `USAGE` and `SELECT` only on approved views. Keep
   `sslmode=verify-full` and a trusted DNS name.
2. Register the exposed schema and enable live queries for the workspace.
3. Run the governed query once, inspect the exact SQL and result, and retain its
   `attempt_id`, `sql_hash` and `exposed_schema_revision`.
4. Add a preset that references those three server-owned values. The preset
   mount contains no SQL. Restart the server so startup validation can fail
   closed on a malformed or ambiguous catalogue.

`config.json` may name an optional `presets_file` beside the existing DSN and
trust-bundle files. The standard Compose deployment mounts
`deploy/compose/mounts/server/governedquery` read-only at
`/run/knowvault/governedquery`. Leave that directory empty to keep the
capability absent. When enabling it, install every file as `root:65532` with
directory mode `0750` and file mode `0440`:

```json
{
  "schema_version": "governed-query-mount-v1",
  "connection_id": "customer-gm-live",
  "database_identity": "gm",
  "workspace_id": "customer-pilot",
  "dsn_file": "dsn",
  "trust_bundle_file": "trust.pem",
  "presets_file": "presets.json",
  "mode": "PRESET_ONLY",
  "statement_timeout_seconds": 5,
  "max_rows": 1000,
  "max_result_bytes": 1048576,
  "max_cost_estimate": 1000
}
```

A mount with `presets_file` must declare its mode. Use `PRESET_ONLY` for a
closed catalogue: MCP advertises only preset list/run and rejects the ad-hoc
model-authored SQL tool as unknown, and the REST ad-hoc `:ask` action fails
closed with the same content-free not-found shape as an unknown connection.
`ADHOC` keeps both surfaces for an explicitly approved compatibility deployment.
A missing or unknown mode fails startup.

Example `presets.json`:

```json
{
  "schema_version": "governed-query-presets-v1",
  "presets": [
    {
      "id": "contract-status",
      "version": "v1",
      "name": "Current contract status",
      "description": "Returns the approved current contract status view.",
      "phrases": ["check contract status", "show contract health"],
      "workspace_id": "customer-pilot",
      "source_attempt_id": "gqat_...",
      "sql_hash": "sha256:...",
      "exposed_schema_revision": 3
    }
  ]
}
```

IDs and normalized phrases must be unique inside their workspace. A catalogue
entry is visible only in its named workspace, even when several workspaces use
the same governed connection. Phrase matching is case-insensitive
and collapses whitespace; a near phrase is not an exact phrase. Changing the
reviewed query or exposed schema requires a new preset version and binding.

## MCP workflow

Call `knowvault_queries_list` with `workspace_id` and `connection_id`, choose the
matching preset, then call `knowvault_query_run` with those two fields and
`preset_id`. An `sql` field, parameters and unknown members are rejected.

The result is marked `LIVE_OBSERVATION` and includes the execution interval,
columns, PostgreSQL text values, nulls, row count, cost estimate, attempt id,
preset hash, SQL hash and result digest. The admission event must be durable
before the database is read, and a successful attempt audit must be durable
before any row is disclosed.

Live rows are not retained evidence and do not receive a `kv1:` address. Use a
prepared PostgreSQL snapshot when an answer needs a stable source page and a
readable historical version.
