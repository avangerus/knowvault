// Card W-5 web probe: the chat screen carries exactly ONE control for the
// workspace's sources. Before this card the Ask surface rendered the same
// summary twice — once in the page header next to the title, once above the
// question field — so the owner saw two «Sources: N · need attention: M»
// controls on one screen.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency), matching
// source_connection_card_test.ts and search_surface_test.ts: it statically
// renders the REAL production AskSurface and the REAL opened source list from
// main.tsx through react-dom/server.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AskSurface, RelySourceList, type SourceStatus, type WorkspaceDataState } from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

// source builds one workspace source row exactly as the sources read route
// serves it; the defaults describe a healthy, indexed source, and each fixture
// overrides only the field its scenario is about.
function source(overrides: Partial<SourceStatus> & { source_scope_id: string }): SourceStatus {
  const { source_scope_id, ...rest } = overrides;
  return {
    workspace_source_id: `wsrc_${source_scope_id}`,
    source_scope_id,
    source_scope_revision: 1,
    access_mode: "WORKSPACE_MANAGED",
    enabled: true,
    scope_config_hash: `hash_${source_scope_id}`,
    connection_id: `conn_${source_scope_id}`,
    connection_name: "Operations",
    source_type: "FOLDER",
    postgresql_schema_name: null,
    postgresql_relation_name: null,
    activation_status: "READY",
    trust_verified: true,
    sync_status: "SUCCEEDED",
    sync_error_code: null,
    sync_started_at: null,
    sync_completed_at: null,
    objects_seen: null,
    objects_ingested: null,
    versions_created: null,
    evidence_published: null,
    quarantined: 0,
    job_status: "SUCCEEDED",
    job_attempt_count: 1,
    job_last_error_code: null,
    content_freshness_sla_seconds: 300,
    last_successful_sync_at: "2026-09-21T10:00:00Z",
    freshness_state: "FRESH",
    sync_interval_seconds: 300,
    confirmed: true,
    confirmation_state: "ACTIVE",
    can_verify_connection_trust: false,
    ...rest,
  };
}

// Four enabled sources, three of them needing attention: one failed run, one
// waiting for activation and one stale scope.
const sources = [
  source({ source_scope_id: "scope_1", connection_name: "Regulations" }),
  source({ source_scope_id: "scope_2", connection_name: "Contracts", sync_status: "FAILED" }),
  source({ source_scope_id: "scope_3", connection_name: "Finance", confirmation_state: "READY_TO_ACTIVATE" }),
  source({ source_scope_id: "scope_4", connection_name: "Archive", freshness_state: "STALE" }),
];
const snapshot = { id: "workspace-1", name: "Operations", status: "ACTIVE", revision: 1, model_profiles: [] };
const state = {
  phase: "loaded",
  snapshot: { kind: "ok", value: snapshot },
  sources: { kind: "ok", value: { sources, confirmation_context: {} } },
} as unknown as WorkspaceDataState;

const chatMarkup = renderToStaticMarkup(createElement(AskSurface, {
  active: true,
  onOpenEvidence: () => {},
  onOpenSources: () => {},
  requestedWorkspaceID: "workspace-1",
  state,
}));

// Result 1: one control, showing the count and how many need attention.
const controlCount = (chatMarkup.match(/class="rely-summary"/g) ?? []).length;
check(controlCount === 1, `the chat screen renders exactly one sources control (got ${controlCount})`);
check(chatMarkup.includes("Sources: <b>4</b>"), "the one control shows the enabled source count");
check(chatMarkup.includes("need attention: 3"), "the one control shows how many sources need attention");
check(chatMarkup.includes('aria-expanded="false"'), "the one control is the expandable sources control");

// Result 2: opened, that same control lists the sources and offers management.
const openedMarkup = renderToStaticMarkup(createElement(RelySourceList, {
  onManageSources: () => {},
  sources,
}));
check(openedMarkup.includes("Workspace sources — 4"), "the opened control names the workspace source count");
for (const label of ["Regulations", "Contracts", "Finance", "Archive"]) {
  check(openedMarkup.includes(label), `the opened control lists the source ${label}`);
}
check(openedMarkup.includes("Contracts") && openedMarkup.includes("Update failed"),
  "the opened control carries the per-source freshness the Sources screen shows");
check(openedMarkup.includes("Manage sources"), "the opened control offers the way to manage the sources");

if (failures !== 0) throw new Error(`${failures} chat-sources-control assertion(s) failed`);
console.log("chat sources control probe: PASS");
