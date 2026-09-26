// Card D-1 web probe: the Sources surface renders an unfinished PostgreSQL
// connection as a draft with its server-derived state and the two actions the
// card requires, and the wizard's discovery catalog renders an unsupported
// base-table column with its exclusion reason instead of hiding it.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency), matching
// postgres_table_discovery_test.ts: it renders the real production exports
// from main.tsx through react-dom/server.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  PostgreSQLDiscoveredViewCard,
  PostgreSQLExcludedColumn,
  PostgreSQLOnboardingDialog,
  SourceConnectionDraftList,
  postgresExcludedReasonLabel,
  sourceConnectionDraftStateLabel,
  type SourceConnectionDraft,
  type SourceDiscoveryView,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function draft(overrides: Partial<SourceConnectionDraft> & { connection_id: string; connection_name: string; state: string }): SourceConnectionDraft {
  return {
    connection_revision: 1,
    source_type: "POSTGRESQL_QUERY",
    trust_status: "DRAFT",
    created_at: "2026-09-25T00:00:00Z",
    ...overrides,
  };
}

function main(): void {
  // --- 1. the Sources page renders draft state + continue/delete ----------
  const awaiting = draft({
    connection_id: "conn_awaiting", connection_name: "Operations database",
    state: "AWAITING_TRUST_VERIFICATION",
  });
  const ready = draft({
    connection_id: "conn_ready", connection_name: "Billing replica",
    state: "READY_FOR_DISCOVERY", trust_status: "VERIFIED",
  });
  const listMarkup = renderToStaticMarkup(createElement(SourceConnectionDraftList, {
    busyID: null,
    canManage: true,
    drafts: [awaiting, ready],
    onContinue: () => {},
    onDiscard: () => {},
  }));
  check(listMarkup.includes("Unfinished connections"), "the drafts section has its own heading");
  check(listMarkup.includes("Operations database") && listMarkup.includes("Billing replica"), "both draft names render");
  check(listMarkup.includes("Needs trust verification"), "an awaiting draft renders its own state");
  check(listMarkup.includes("Ready to find tables"), "a verified draft renders its own state");
  check(listMarkup.includes("Continue"), "a draft row offers Continue");
  check(listMarkup.includes("Delete"), "a draft row offers Delete");

  const readOnlyMarkup = renderToStaticMarkup(createElement(SourceConnectionDraftList, {
    busyID: null,
    canManage: false,
    drafts: [awaiting],
    onContinue: () => {},
    onDiscard: () => {},
  }));
  check(readOnlyMarkup.includes("Needs trust verification") && !readOnlyMarkup.includes("Continue") && !readOnlyMarkup.includes("Delete"),
    "a member who cannot manage sources sees the draft state without action buttons");
  check(renderToStaticMarkup(createElement(SourceConnectionDraftList, {
    busyID: null, drafts: [], onContinue: () => {}, onDiscard: () => {},
  })) === "", "an empty draft list renders nothing");

  check(sourceConnectionDraftStateLabel(awaiting) === "Needs trust verification", "the draft state label is server-state driven");

  // --- 2. the wizard resumes from the draft state -------------------------
  const dialogSnapshot = { id: "ws_alpha", revision: 3 } as never;
  const awaitingDialog = renderToStaticMarkup(createElement(PostgreSQLOnboardingDialog, {
    etag: "\"sha256:" + "a".repeat(64) + "\"",
    initialDraft: awaiting,
    onBack: () => {}, onClose: () => {}, onCompleted: () => {},
    snapshot: dialogSnapshot,
  }));
  check(awaitingDialog.includes("Trust verification") && awaitingDialog.includes("conn_awaiting"),
    "reopening an awaiting draft resumes the wizard at trust verification with the existing connection id");

  const readyDialog = renderToStaticMarkup(createElement(PostgreSQLOnboardingDialog, {
    etag: "\"sha256:" + "a".repeat(64) + "\"",
    initialDraft: ready,
    onBack: () => {}, onClose: () => {}, onCompleted: () => {},
    snapshot: dialogSnapshot,
  }));
  check(readyDialog.includes("Repeat discovery") && readyDialog.includes("conn_ready"),
    "reopening a trust-verified draft resumes the wizard at discovery, not at an empty connection form");

  // --- 3. an unsupported base-table column shows its reason --------------
  const table: SourceDiscoveryView = {
    view_id: "sdv_" + "c".repeat(64),
    schema_name: "public",
    relation_name: "waste_site",
    relation_kind: "TABLE",
    approx_row_count: 12,
    status: "PREPARED",
    columns: [
      { ordinal: 1, name: "site_id", type_name: "uuid", logical_type: "UUID", nullable: false, roles: ["IDENTITY"], primary_key: true },
      { ordinal: 2, name: "site_name", type_name: "text", logical_type: "TEXT", nullable: false, roles: ["EVIDENCE"], primary_key: false },
    ],
    excluded_columns: [
      { ordinal: 2, name: "geom", type_name: "geometry", reason: "UNSUPPORTED_TYPE" },
    ],
  };
  const catalogMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    onToggleColumn: () => {},
    onToggleSelected: () => {},
    selected: false,
    view: table,
  }));
  check(catalogMarkup.includes("Waste") || catalogMarkup.includes("waste_site"), "the prepared table still renders");
  check(catalogMarkup.includes("geom"), "the excluded column is still visible as metadata");
  check(catalogMarkup.includes("column type cannot be read by the query connector"),
    "the excluded column renders its own reason in the wizard");
  check(catalogMarkup.includes("Not included"), "the excluded column is labelled as not included");
  check(catalogMarkup.includes('type="checkbox"'), "the table still offers its row-selection checkbox");

  const excludedMarkup = renderToStaticMarkup(createElement(PostgreSQLExcludedColumn, {
    column: { ordinal: 2, name: "geom", type_name: "geometry", reason: "UNSUPPORTED_TYPE" },
  }));
  check(!excludedMarkup.includes('type="checkbox"'), "an auto-excluded column offers no exclusion checkbox");
  check(postgresExcludedReasonLabel("SOMETHING_NEW") === "column type is not supported",
    "an unknown exclusion reason falls back to the closed generic copy instead of rendering server text");

  if (failures !== 0) throw new Error(`${failures} postgres draft/resume assertion(s) failed`);
  console.log("postgres draft resume probe: PASS");
}

main();
