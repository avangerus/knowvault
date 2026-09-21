import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AskSurface,
  SearchView,
  askExecutionVisibility,
  defaultAskExecutionMode,
  effectiveAskExecutionMode,
  reduceGovernedRetention,
  type GovernedRetentionState,
  type WorkspaceDataState,
} from "./main";
import { governedCatalogAvailability, type GovernedPresetCatalog } from "./governed-presets";

// This probe is bundled as a CommonJS node script. Keep the small source-shape
// assertions dependency-free: the governed catalogue starts in a loading state
// during server rendering, so its post-load controls are not present in that
// static render.
declare const require: (moduleName: string) => { readFileSync(path: string, encoding: "utf8"): string };
const fs = require("fs");
const governedSource = fs.readFileSync("src/governed-presets.tsx", "utf8");
const mainSource = fs.readFileSync("src/main.tsx", "utf8");
let failures = 0;
const check = (ok: boolean, message: string) => { if (!ok) { failures++; console.error(`FAIL ${message}`); } };

const snapshot = { id: "workspace-1", name: "Operations", status: "ACTIVE", revision: 1, model_profiles: [] };
const workspaceState = (sources: unknown[]): WorkspaceDataState => ({
  phase: "loaded",
  snapshot: { kind: "ok", value: snapshot },
  sources: { kind: "ok", value: { sources, confirmation_context: {} } },
} as unknown as WorkspaceDataState);
const documentsState = workspaceState([]);
const renderAsk = (state: WorkspaceDataState, active = true) => renderToStaticMarkup(createElement(AskSurface, {
  active,
  onOpenEvidence: () => {},
  onOpenSources: () => {},
  onSessionExpired: () => {},
  revalidationKey: 0,
  requestedWorkspaceID: "workspace-1",
  state,
}));
const renderSearch = (active: boolean) => renderToStaticMarkup(createElement(SearchView, {
  active,
  onOpenEvidence: () => {},
  requestedWorkspaceID: "workspace-1",
  state: documentsState,
}));

const searchMarkup = renderAsk(documentsState);
check((searchMarkup.match(/<h1>Ask<\/h1>/g) ?? []).length === 1, "the Ask surface has one page heading");
check(searchMarkup.includes("Live database") && searchMarkup.includes("Workspace search"), "execution modes use honest labels");
check(!/class="ask-source-button[^>]*>Answer<\//.test(searchMarkup) && !/class="ask-source-button[^>]*>Search<\//.test(searchMarkup), "the mode control does not use conversational Answer/Search labels");
check(searchMarkup.includes('aria-label="Mode"'), "execution mode is labelled for assistive technology");
check(searchMarkup.includes('aria-pressed="true"') && searchMarkup.includes('>Workspace search<'), "default mode is Workspace search before governed capability is authorized");
check(searchMarkup.includes('placeholder="Search documents"'), "Workspace search keeps a usable document input");
check(renderSearch(false).includes("hidden"), "document search remains mounted while inactive");
const readyCatalog = { connection_id: "connection-1", database_identity: "gm", presets: [{ id: "p", version: "v1", name: "P", description: "", phrases: [], preset_hash: "h", source_attempt_id: "a", sql_hash: "s", exposed_schema_revision: 1 }] } as GovernedPresetCatalog;
check(JSON.stringify(governedCatalogAvailability(null)) === JSON.stringify({ status: "loading", catalogAvailable: false, liveAskAvailable: false }), "catalog revalidation reports loading without final denial");
check(JSON.stringify(governedCatalogAvailability({ ...readyCatalog, presets: [] }, true)) === JSON.stringify({ status: "unavailable", catalogAvailable: false, liveAskAvailable: false }), "empty catalog is a final unavailable state");
check(JSON.stringify(governedCatalogAvailability(readyCatalog, false)) === JSON.stringify({ status: "available", catalogAvailable: true, liveAskAvailable: false }), "preset-only catalog keeps Live database and Diagnostics but hides ad hoc ask");
check(JSON.stringify(governedCatalogAvailability(readyCatalog, true)) === JSON.stringify({ status: "available", catalogAvailable: true, liveAskAvailable: true }), "advertised ask capability enables the ad hoc composer");
check(defaultAskExecutionMode(false) === "workspace-search" && defaultAskExecutionMode(true) === "workspace-search", "execution mode always defaults to Workspace search");
check(effectiveAskExecutionMode("workspace-search", true) === "workspace-search", "explicit Workspace search selection survives later live authorization");
check(effectiveAskExecutionMode(null, true) === "workspace-search", "live authorization never auto-flips the default mode");
check(effectiveAskExecutionMode("live-database", false, "loading") === "live-database", "same-revision loading preserves an explicitly selected Live database mode");
check(effectiveAskExecutionMode("live-database", false, "unavailable") === "workspace-search", "live mode falls back to Workspace search only after final catalog unavailability");
const live = askExecutionVisibility("live-database");
const workspaceSearch = askExecutionVisibility("workspace-search");
check(live.liveDatabase && !live.workspaceSearch && !workspaceSearch.liveDatabase && workspaceSearch.workspaceSearch, "exactly one execution surface is active at a time");

check(!mainSource.includes("document-search-disclosure"), "the old document-search details wrapper is removed");
check(mainSource.includes("<GovernedPresetPanelHost") && mainSource.includes("<SearchView"), "both source surfaces remain mounted under the Ask owner");
const ownerStart = mainSource.indexOf("export function AskSurface");
const hostInOwner = mainSource.indexOf("<GovernedPresetPanelHost", ownerStart);
const searchInOwner = mainSource.indexOf("<SearchView", ownerStart);
check(ownerStart >= 0 && hostInOwner > ownerStart && searchInOwner > hostInOwner, "governed host is a sibling before SearchView, outside its early returns");
check(!mainSource.includes('aria-label="Ask mode"') && !mainSource.includes('aria-label="Source scope"') && !mainSource.includes('>Answer<'), "Ask owner contains no conversational mode labels");
check(mainSource.includes('active={active && visibility.liveDatabase}') && mainSource.includes('active={active && visibility.workspaceSearch}'), "owner gates exactly one visible composer without submitting on selection");
check(mainSource.includes('onClick={() => setRequestedMode("live-database")}') && mainSource.includes('onClick={() => setRequestedMode("workspace-search")}'), "mode buttons only change execution mode");
check(!mainSource.includes('onClick={() => setMode("answer")}') && !mainSource.includes('onClick={() => setMode("search")}'), "legacy Answer/Search switching is removed");
check(mainSource.includes('<div className="governed-preset-owner" hidden={!visible}>'), "governed host is not wrapped in a nested search-pilot scroller");
check(mainSource.includes("onCatalogAvailability") && mainSource.includes("catalogAvailability.catalogAvailable") && mainSource.includes("catalogAvailability.liveAskAvailable"), "catalog and live-ask capabilities are kept separate");
check(mainSource.includes('availability.status === "unavailable"') && mainSource.includes('authorization.phase === "pending" ? "loading" : "unavailable"'), "loading preserves explicit mode while only final unavailability triggers fallback");

check((governedSource.match(/<h1[^>]*>Ask company data<\/h1>/g) ?? []).length === 0, "governed panel does not add a second page heading");
check(governedSource.includes('<label className="sr-only" htmlFor="governed-ask-input">Ask company data</label>'), "governed ask keeps an accessible field label");
check(governedSource.includes('placeholder="Ask a question"'), "governed ask uses a useful placeholder");
check(governedSource.includes("onCatalogAuthorization(governedCatalogAvailability(null))") && governedSource.includes('governedCatalogAvailability(null, false, "unavailable")') && governedSource.includes('setCatalogState({ phase: "empty" })'), "loading, empty and unavailable catalog outcomes are distinguished");
check(governedSource.includes("governedMCPAskCapability(fetch)") && governedSource.includes("governedCatalogAvailability(outcome.value, askCapability.kind === \"ok\" && askCapability.value)"), "only the tools/list ask capability plus a ready catalog can authorize live ask");
check(governedSource.includes("liveAskAvailable: boolean") && governedSource.includes("catalog && liveAskAvailable"), "PRESET_ONLY keeps the catalog and Diagnostics while hiding only the ad hoc form");
check(governedSource.includes('GOVERNED_QUERY_ASK_TOOL = "knowvault_governed_query_ask"') && governedSource.includes('method, params'), "capability probe uses the existing content-free MCP transport");
const diagnosticsMatch = governedSource.match(/\{catalog && <details className="governed-reviewed-checks">[\s\S]*?<\/details>\}/);
const diagnosticsBlock = diagnosticsMatch?.[0] ?? "";
check(diagnosticsBlock.includes("<summary>Diagnostics</summary>"), "reviewed checks are under Diagnostics");
check(!/<details[^>]*\bopen\b/.test(diagnosticsBlock), "Diagnostics is closed by default");
check(diagnosticsBlock.includes("Reviewed checks") && diagnosticsBlock.includes("governed-preset-select") && diagnosticsBlock.includes("run(catalog)"), "reviewed check controls remain inside Diagnostics");
const runStart = governedSource.indexOf("async function run");
const askStart = governedSource.indexOf("function ask");
check(runStart >= 0 && governedSource.indexOf("setAskState({ phase: \"idle\" })", runStart) < askStart, "starting a reviewed check clears a prior ask result");
check(askStart >= 0 && governedSource.indexOf("setRunState({ phase: \"idle\" })", askStart) >= askStart, "starting an ask clears a prior reviewed-check result");

const initial: GovernedRetentionState = { workspaceID: null, revision: null, phase: "pending", resetKey: 0 };
const pending = reduceGovernedRetention(initial, { workspaceID: "workspace-1", phase: "pending", revision: null });
const authorized = reduceGovernedRetention(pending, { workspaceID: "workspace-1", phase: "authorized", revision: 7 });
const away = reduceGovernedRetention(authorized, { workspaceID: "workspace-1", phase: "pending", revision: null });
const back = reduceGovernedRetention(away, { workspaceID: "workspace-1", phase: "authorized", revision: 7 });
const revised = reduceGovernedRetention(back, { workspaceID: "workspace-1", phase: "authorized", revision: 8 });
const denied = reduceGovernedRetention(revised, { workspaceID: "workspace-1", phase: "denied", revision: null });
check(away.phase === "pending" && away.revision === 7 && away.resetKey === authorized.resetKey, "same-revision revalidation hides while retaining the live result identity");
check(back.phase === "authorized" && back.revision === 7 && back.resetKey === authorized.resetKey, "same-revision return reveals without reset or resubmit");
check(revised.resetKey === back.resetKey + 1 && revised.revision === 8, "revision change resets retained state");
check(denied.phase === "denied" && denied.revision === null && denied.resetKey === revised.resetKey + 1, "denial clears retained state");

if (failures !== 0) throw new Error(`${failures} search-surface assertion(s) failed`);
console.log("search surface probe: PASS");
