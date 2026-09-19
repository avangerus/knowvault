# PostgreSQL entity snapshots

KnowVault's SQL pilot makes business records searchable and readable through the
same MCP tools as documents. A prepared PostgreSQL view exposes one entity per
row: an invoice, ticket, contract, or a report your database already produces.
KnowVault retains versions and provenance so an answer can link to its evidence.

## The five-field contract

| Field | Purpose |
| --- | --- |
| `entity_id` | Stable identity of the entity within this source. |
| `entity_version` | Source-provided version identifying the entity's contents. |
| `last_updated_at` | Modification time reported by the source; separate from KnowVault's observation time. |
| `payload` | The entity's data, normally JSON/JSONB. The adapter also supports text payloads. |
| `payload_format` | The payload representation, for example `JSON`. |

Source discovery checks the prepared view and its column types. Fix reported
contract issues before activation. See [Source contracts](SOURCE_CONTRACTS.md)
for the normative schema and connector behavior.

For example, an invoice's payload might contain:

```json
{
  "invoice_id": "INV-0001",
  "customer": "Example Company",
  "amount": 1250.50,
  "currency": "USD",
  "due_date": "2026-10-01",
  "paid_at": null
}
```

Include business identifiers such as `invoice_id` in the payload even when they
also serve as `entity_id`. The service identity field alone is not indexed as
searchable evidence text. Search is ranked and can return related records;
there is no separate exact entity-ID lookup tool in the pilot.

## What is retained

KnowVault associates the entity with its workspace, connection, source schema,
version, observation time, and evidence addresses. Typed values and metadata
remain available alongside a readable representation. Numbers, dates, booleans,
and nulls should not be reconstructed from a shortened search snippet.

The existing adapter creates readable fragments and JSON-field addresses; a
separate SQL-to-Markdown conversion service is unnecessary. Use paginated reads
to obtain the complete retained entity and returned field addresses to cite
individual values.

`Idempotency-Key` applies to repeating API commands. It does not replace the
entity's stable identity or content version. Re-ingesting unchanged content
should not create extra versions. A changed row produces a new retained
observation; an old address continues to identify its original bytes while
retention and current access permit reading them.

## Prepare the connection

1. Create a VIEW or MATERIALIZED VIEW with the required fields.
2. Give a dedicated role `CONNECT` to the source database, `USAGE` on the relevant
   schema, and `SELECT` only on the intended views. Write access is unnecessary.
3. Have the operator provision the credential reference and trusted connection
   using a DNS hostname and `sslmode=verify-full`.
4. Discover the prepared view in KnowVault, resolve reported type or contract
   issues, and complete the required source confirmation and activation.
5. Read a known entity through MCP and compare every relevant value with the
   source. Check that another workspace cannot read its address.

Keep financial or otherwise restricted data in appropriately controlled
workspaces. Connecting a source does not automatically reproduce all original
row-level permissions for its downstream readers.

## Freshness and deletion

Source modification time and KnowVault observation time answer different
questions. A retained snapshot describes data observed during synchronization;
it is not a live query of the database at answer time.

Incomplete extraction, a failed scan, and authoritative deletion must not be
treated as the same event. Full-snapshot deletion behavior depends on the
configured source policy. Inspect source status and skipped items before
interpreting absence as deletion. Continuous change-data capture is not a pilot
promise.

## Query boundaries

“What is the amount on invoice INV-0001?” can be answered from a retained entity.
“What is the total of every unpaid invoice?” requires a complete authorized
dataset or an existing report view with a stated time. Summing the top search
results is not a valid substitute.

The pilot does not promise arbitrary model-written joins or universal SQL
analytics. The optional [governed SQL preset](GOVERNED-SQL-PRESETS.md) capability
can repeat an already executed and reviewed live query by a versioned reference;
it accepts no SQL or parameters from MCP. It requires explicit workspace
configuration and is not needed for entity snapshots. Live-query results and
their timestamps must not be presented as retained snapshot addresses.

Continue with [Getting started](GETTING_STARTED.md) or the
[MCP tool reference](MCP-TOOLS.md).
