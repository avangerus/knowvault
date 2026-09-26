// Card S5.1 web probe: the Sources page shows every enabled PostgreSQL
// connection as ONE card next to the document sources instead of one row per
// table, carrying the connection state, the registered/indexed table counts,
// the rolled-up freshness served for scopes, and an expansion that lists the
// tables with their per-table state.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency), matching
// postgres_table_discovery_test.ts and postgres_draft_resume_test.ts: it
// renders the REAL production SourcesView and calls the real pure grouping
// functions from main.tsx through react-dom/server.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SourcesView,
  sourceCardEntries,
  sourceConnectionFreshnessState,
  sourceConnectionLastSuccessfulSyncAt,
  sourceConnectionState,
  sourceConnectionSummary,
  sourceTableIndexed,
  type SourceConnectionGroup,
  type SourceStatus,
  type WorkspaceDataState,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

// One scope row exactly as the workspace sources read route serves it: the
// defaults describe a healthy, indexed table, and every test overrides only
// the fields its scenario is about.
function postgresTable(overrides: Partial<SourceStatus> & { source_scope_id: string; relation: string }): SourceStatus {
  const { relation, source_scope_id, ...rest } = overrides;
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
    postgresql_relation_name: relation,
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

function folderSource(): SourceStatus {
  return {
    ...postgresTable({ source_scope_id: "scope_docs", relation: "ignored" }),
    source_scope_id: "scope_docs",
    connection_id: "conn_docs",
    connection_name: "Handbook",
    source_type: "FOLDER",
    postgresql_schema_name: null,
    postgresql_relation_name: null,
    last_successful_sync_at: "2026-09-12T08:00:00Z",
  };
}

function groupOf(tables: SourceStatus[]): SourceConnectionGroup {
  return { connection_id: "conn_ops", connection_name: "Operations database", source_type: "POSTGRESQL_QUERY", tables };
}

function main(): void {
  // --- 1. grouping: one entry per connection, documents stay single --------
  const waste = postgresTable({ source_scope_id: "scope_waste", relation: "waste_site" });
  const contract = postgresTable({
    source_scope_id: "scope_contract", relation: "contract", last_successful_sync_at: "2026-09-12T11:30:00Z",
  });
  const staff = postgresTable({
    source_scope_id: "scope_staff", relation: "staff",
    sync_status: "FAILED", sync_error_code: "INGEST_READ", last_successful_sync_at: null,
    freshness_state: "UNKNOWN", objects_ingested: null, evidence_published: null,
  });
  const document = folderSource();

  // The document source is interleaved on purpose: grouping must merge the
  // connection's tables wherever they appear, not only when adjacent.
  const entries = sourceCardEntries([waste, document, contract, staff]);
  check(entries.length === 2, "three tables of one connection plus a document source render as two cards");
  check(entries[0]?.kind === "connection", "the first card is the database connection");
  check(entries[1]?.kind === "source", "the document source keeps its own card");
  if (entries[0]?.kind === "connection") {
    check(entries[0].group.tables.length === 3, "the connection card carries all three of its tables");
    check(entries[0].group.tables.map((table) => table.postgresql_relation_name).join(",") === "waste_site,contract,staff",
      "the connection card keeps every table in the served order");
  }
  if (entries[1]?.kind === "source") {
    check(entries[1].source.connection_id === "conn_docs", "the document source is never merged into a database card");
  }

  // Two connections of the same type are two cards: a workspace's connections
  // are never folded together and no foreign connection can appear here.
  const otherConnection = { ...contract, source_scope_id: "scope_other", connection_id: "conn_other", connection_name: "Billing replica" };
  const twoConnections = sourceCardEntries([waste, otherConnection]);
  check(twoConnections.length === 2 && twoConnections.every((entry) => entry.kind === "connection"),
    "two distinct PostgreSQL connections stay two separate cards");

  // --- 2. the summary: counts and rolled-up freshness ----------------------
  const group = groupOf([waste, contract, staff]);
  const summary = sourceConnectionSummary(group);
  check(summary.connection_name === "Operations database", "the card carries the connection name");
  check(summary.table_count === 3, "the card counts three registered tables");
  check(summary.indexed_count === 2, "the card counts the two tables that completed a successful run");
  check(sourceTableIndexed(waste) && sourceTableIndexed(contract), "a table with a successful run counts as indexed");
  check(!sourceTableIndexed(staff), "a table that never completed a successful run does not count as indexed");
  check(summary.last_successful_sync_at === "2026-09-12T11:30:00Z", "the card reports the most recent successful sync");
  check(sourceConnectionLastSuccessfulSyncAt(group) === "2026-09-12T11:30:00Z",
    "the rolled-up last successful sync is the latest table run");
  check(sourceConnectionLastSuccessfulSyncAt(groupOf([staff])) === null,
    "a connection whose tables never succeeded reports no successful sync time");
  check(summary.freshness_state === "UNKNOWN",
    "freshness is unknown while one table has never completed a successful run");
  check(sourceConnectionFreshnessState(groupOf([waste, contract])) === "FRESH", "all-fresh tables roll up to fresh");
  check(sourceConnectionFreshnessState(groupOf([waste, { ...contract, freshness_state: "STALE" }])) === "STALE",
    "one stale table makes the connection stale");
  check(sourceConnectionFreshnessState(groupOf([waste, staff])) === "UNKNOWN",
    "a never-synced table leaves the connection's freshness unknown, never fresh");
  check(summary.state === "failed" && summary.state_label === "Failed",
    "an active connection with a failed table reports the failed state");

  // --- 3. the connection state from its tables -----------------------------
  check(sourceConnectionState(groupOf([waste, contract])) === "active", "healthy tables make an active connection");
  check(sourceConnectionState(groupOf([waste, { ...contract, confirmation_state: "NEEDS_CONFIRMATION" }])) === "awaiting_confirmation",
    "an unconfirmed table puts the connection in awaiting confirmation");
  check(sourceConnectionState(groupOf([waste, staff])) === "failed", "a failed table makes the connection failed");
  check(sourceConnectionState(groupOf([waste, { ...contract, sync_status: "RUNNING", last_successful_sync_at: null }])) === "updating",
    "a running table is an updating connection");
  check(sourceConnectionState(groupOf([{ ...waste, enabled: false }])) === "disabled",
    "a connection whose tables are all disabled reports disabled");
  const staleSummary = sourceConnectionSummary(groupOf([waste, { ...contract, freshness_state: "STALE" }]));
  check(staleSummary.state === "active" && staleSummary.state_label === "Data is stale" && staleSummary.variant === "attention",
    "an active but stale connection is flagged as needing attention");

  // --- 4. the rendered page shows two cards and expands the tables --------
  const rendered = renderToStaticMarkup(createElement(SourcesView, {
    state: workspaceState([waste, contract, staff, document]),
    role: "OWNER",
    onChanged: () => {},
    pushToast: () => {},
  }));
  const cardCount = (rendered.match(/class="source-row source-row-/g) ?? []).length;
  check(cardCount === 2, "the Sources page renders exactly two top-level cards for one connection and one document source");
  check(rendered.includes("Operations database"), "the database card shows the connection name");
  check(rendered.includes("Failed"), "the database card shows the connection state");
  check(rendered.includes("3 tables") && rendered.includes("2 indexed"),
    "the database card shows the registered and indexed table counts");
  check(rendered.includes("Last successful update:"), "the database card shows the last successful sync time");
  check(rendered.includes("Freshness: unknown"), "the database card shows the rolled-up freshness");
  check(rendered.includes("Tables (3)"), "the database card offers an expansion for its tables");
  check(rendered.includes("reporting.waste_site") && rendered.includes("reporting.contract") && rendered.includes("reporting.staff"),
    "expanding the card lists every table by its schema-qualified name");
  check(rendered.includes("reporting.staff") && rendered.includes("Update failed"),
    "an expanded table shows its own state");
  check(rendered.includes("Handbook") && rendered.includes("Document folder"),
    "the document source card renders unchanged beside the database card");

  if (failures !== 0) throw new Error(`${failures} source connection card assertion(s) failed`);
  console.log("source connection card probe: PASS");
}

// workspaceState builds the exact loaded workspace payload SourcesView reads:
// an authorized snapshot plus the sources envelope the page already loads.
function workspaceState(sources: SourceStatus[]): WorkspaceDataState {
  return {
    phase: "loaded",
    snapshot: {
      kind: "ok",
      value: {
        id: "ws_alpha", name: "Alpha", description: "", status: "ACTIVE", revision: 3,
        owner_principal_id: "principal_1", retention_policy_id: "retention_1", members: [],
        processing_mode: { mode: "INTERNAL" },
      },
    },
    sources: {
      kind: "ok",
      value: {
        sources,
        confirmation_context: {
          expected_policy_revision: "policy_1",
          warning_contract: { warning_version: "1", warning_contract_hash: "hash" },
          viewer_principal_id: "principal_1",
          can_issue_confirmation_grant: false,
          can_verify_connection_trust: false,
          self_grant: null,
        },
      },
    },
  } as unknown as WorkspaceDataState;
}

main();
