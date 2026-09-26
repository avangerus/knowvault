// Card S3.2 web probe: the Sources database card shows ADR-0097's per-connection
// SQL state. A connection revision that carries the separate read-only query
// credential renders «SQL available» (English label "SQL available" in the code
// table); one that does not renders "SQL not configured", which is the same
// fact the knowvault_source_sql tool reports as SOURCE_SQL_NOT_CONFIGURED.
//
// Plain TypeScript module under the repository's pinned esbuild + node
// toolchain (no test framework), rendering the REAL production
// SourceConnectionCard and the real pure summary function.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SourceConnectionCard,
  sourceConnectionSummary,
  type SourceConnectionGroup,
  type SourceStatus,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function table(overrides: Partial<SourceStatus> & { source_scope_id: string }): SourceStatus {
  const { source_scope_id, ...rest } = overrides;
  return {
    workspace_source_id: `wsrc_${source_scope_id}`,
    source_scope_id,
    source_scope_revision: 1,
    access_mode: "WORKSPACE_MANAGED",
    enabled: true,
    scope_config_hash: `hash_${source_scope_id}`,
    connection_id: "conn_ops",
    connection_name: "Operations database",
    source_type: "POSTGRESQL_QUERY",
    postgresql_schema_name: "reporting",
    postgresql_relation_name: "contract",
    activation_status: "READY",
    trust_verified: true,
    sync_status: "SUCCEEDED",
    sync_error_code: null,
    sync_started_at: null,
    sync_completed_at: null,
    objects_seen: 1,
    objects_ingested: 1,
    versions_created: 1,
    evidence_published: 1,
    quarantined: 0,
    content_freshness_sla_seconds: 1800,
    last_successful_sync_at: "2026-09-12T10:02:00Z",
    freshness_state: "FRESH",
    sync_interval_seconds: 1800,
    confirmed: true,
    confirmation_state: "ACTIVE",
    can_verify_connection_trust: false,
    ...rest,
  };
}

function group(tables: SourceStatus[]): SourceConnectionGroup {
  return { connection_id: "conn_ops", connection_name: "Operations database", source_type: "POSTGRESQL_QUERY", tables };
}

function cardMarkup(tables: SourceStatus[]): string {
  return renderToStaticMarkup(createElement(SourceConnectionCard, { group: group(tables) }));
}

function main(): void {
  const withSQL = table({ source_scope_id: "scope_a", sql_available: true });
  const withoutSQL = table({ source_scope_id: "scope_b", sql_available: false });
  const legacy = table({ source_scope_id: "scope_c" });

  check(sourceConnectionSummary(group([withSQL])).sql_available === true,
    "a connection whose revision has a query credential reports SQL available");
  check(sourceConnectionSummary(group([withoutSQL])).sql_available === false,
    "a connection without a query credential reports SQL not configured");
  check(sourceConnectionSummary(group([legacy])).sql_available === false,
    "a legacy payload without the field fails closed to SQL not configured");

  const availableMarkup = cardMarkup([withSQL]);
  check(availableMarkup.includes("SQL available"), "the database card shows SQL available");
  check(!availableMarkup.includes("SQL not configured"), "the available card never shows the not-configured label");

  const unavailableMarkup = cardMarkup([withoutSQL]);
  check(unavailableMarkup.includes("SQL not configured"), "the database card shows SQL not configured");
  check(!unavailableMarkup.includes("SQL available"), "the unconfigured card never shows the available label");

  // One connection serves all of its tables through the same connection
  // revision, so any table's true flag marks the whole card available.
  check(sourceConnectionSummary(group([withoutSQL, withSQL])).sql_available === true,
    "the connection SQL state is shared by its tables");

  if (failures !== 0) throw new Error(`${failures} source sql availability assertion(s) failed`);
  console.log("source sql availability probe: PASS");
}

main();
