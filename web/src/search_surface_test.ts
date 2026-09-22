import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AskSurface,
  SearchView,
  authorizedSourcesForAsk,
  buildSearchHash,
  hasLiveDataReceipt,
  initialConversationWorkspaceOwner,
  parseSearchHash,
  questionClaimGroundingLabel,
  questionRunPayload,
  relySourceSummary,
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
const stylesSource = fs.readFileSync("src/styles.css", "utf8");
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
const fixtureSource = {
  workspace_source_id: "workspace-source-1",
  source_scope_id: "source-1",
  source_scope_revision: 1,
  access_mode: "WORKSPACE_MANAGED",
  enabled: true,
  scope_config_hash: "sha256:scope",
  connection_id: "conn-1",
  connection_name: "GM",
  source_type: "POSTGRESQL_QUERY",
  postgresql_schema_name: "public",
  postgresql_relation_name: "v_container_group_contract",
  activation_status: "READY",
  trust_verified: true,
  sync_status: "SUCCEEDED",
  sync_error_code: null,
  sync_started_at: null,
  sync_completed_at: "2026-09-21T10:00:00Z",
  objects_seen: 12,
  objects_ingested: 12,
  versions_created: 12,
  evidence_published: 12,
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
};
const sourceState = workspaceState([fixtureSource]);
const pendingState = { phase: "loading" } as WorkspaceDataState;
const deniedState = {
  phase: "loaded",
  snapshot: { kind: "failure", status: 403 },
  sources: { kind: "ok", value: { sources: [fixtureSource], confirmation_context: {} } },
} as unknown as WorkspaceDataState;
const sourceSummary = relySourceSummary([fixtureSource] as never);
check(authorizedSourcesForAsk(sourceState, "workspace-1").length === 1, "authorized Ask state exposes the current source metadata");
check(authorizedSourcesForAsk(pendingState, "workspace-1").length === 0 && authorizedSourcesForAsk(deniedState, "workspace-1").length === 0, "pending and denied Ask state exposes no protected sources");
check(sourceSummary.length === 1 && sourceSummary[0].label === "GM · public.v_container_group_contract" && sourceSummary[0].headline === "Data is up to date", "RelyBar uses the real source label and freshness headline");
check(!renderAsk(pendingState).includes("rely-summary") && !renderAsk(deniedState).includes("rely-summary"), "pending and denied Ask surfaces render no source summary");
check((searchMarkup.match(/<h1>Ask<\/h1>/g) ?? []).length === 1, "the Ask surface has one page heading");
check(!searchMarkup.includes("Live database") && !searchMarkup.includes("Workspace search") && !searchMarkup.includes("Search source"), "the Ask surface has no user-facing execution-mode selector");
check(!searchMarkup.includes("GovernedPresetPanelHost") && !searchMarkup.includes("Reviewed checks"), "governed checks are not placed beside the question");
check(searchMarkup.includes('placeholder="Ask as you would ask a colleague"') && searchMarkup.includes('id="ask-question"'), "Ask mounts the conversational composer");
check((searchMarkup.match(/<form/g) ?? []).length === 1, "Ask surface exposes exactly one question composer");
check((searchMarkup.match(/<textarea[^>]*id="ask-question"/g) ?? []).length === 1, "Ask surface exposes one visible question textarea");
check(searchMarkup.includes("Sources: ") && searchMarkup.includes("<b>0</b>"), "authorized empty sources use the compact Sources: 0 pill");
check(mainSource.includes("authorizedSourcesForAsk") && mainSource.includes("askSources && <RelyBar onManageSources={onOpenSources}"), "Ask RelyBar is gated by workspace authorization and offers source management");
check(!mainSource.includes('<button className="text-button" onClick={onOpenSources} type="button">Sources</button>'), "the duplicate header Sources button is removed");
check(mainSource.includes("sourceLabel(source)") && mainSource.includes("sourceHeadline(source)"), "the source popover renders real labels and freshness headlines");
check(stylesSource.includes(".ask-page-actions .rely-list") && stylesSource.includes("left: 0; right: auto")
  && stylesSource.includes("width: min(360px, calc(100vw - 88px)); max-width: calc(100vw - 88px)"), "header source popover stays inside the 56px rail plus 32px mobile gutters");
check(renderSearch(false).includes("hidden"), "document search remains mounted while inactive");
const searchStart = mainSource.indexOf("export function SearchView");
const searchEnd = mainSource.indexOf("function AskView", searchStart);
const searchSource = searchStart >= 0 && searchEnd > searchStart ? mainSource.slice(searchStart, searchEnd) : "";
const answerStart = mainSource.indexOf("function QuestionRunAnswer");
const answerSource = answerStart >= 0 && searchStart > answerStart ? mainSource.slice(answerStart, searchStart) : "";
check((searchSource.match(/apiPost<QuestionRun>/g) ?? []).length === 1, "one question submit performs exactly one QuestionRun POST");
check(!searchSource.includes("tools/search") && !searchSource.includes("apiGet<"), "question submit does not issue a preliminary document-search GET");
check(searchSource.includes("<QuestionRunAnswer") && answerSource.includes("<AnswerBody") && answerSource.includes("run.citations") && answerSource.includes("onOpenEvidence"), "QuestionRun renders the existing answer, citations and evidence actions");
check(answerSource.includes("isLiveScalar") && answerSource.includes("Verified live calculation") && answerSource.includes("live-calculation-evidence")
  && answerSource.includes("Contributing rows") && answerSource.includes("Observed window") && answerSource.includes("Receipt digest"), "shipped QuestionRun live scalars render the compact verified-calculation disclosure");
const liveCardStart = answerSource.indexOf('className="answer-body live-calculation-answer"');
const documentContextStart = answerSource.indexOf('className="answer-body document-grounded-context"');
const liveCardSource = liveCardStart >= 0 && documentContextStart > liveCardStart ? answerSource.slice(liveCardStart, documentContextStart) : "";
check(answerSource.includes("isCombinedLiveResult") && answerSource.includes("document-grounded context / paraphrase")
  && documentContextStart > liveCardStart && liveCardSource.includes("isCombinedLiveResult && resultValue"), "combined live answers keep the verified calculation and document-grounded context as separate blocks");
check(answerSource.includes("(!hasLiveReceipt || hasDocumentGroundedContext)") && answerSource.includes("questionClaimGroundingLabel"), "receipt-backed answers suppress document grounding while combined answers disclose their separate document context");
check(!answerSource.includes("<AnswerResultBlock") && !answerSource.includes("<UnifiedAnswerRows"), "shipped QuestionRun does not mount the verbose structured-result panels");
check(mainSource.includes('className="tool-trace"') && mainSource.includes("TOOL_CALLS_TITLE") && mainSource.includes("run.tool_loop.calls"), "QuestionRun uses the actual collapsed tool-call disclosure");
check(searchSource.includes('className="search-model-select"') && searchSource.includes('aria-label="Model"'), "the configured model selector remains available");
check(!searchSource.includes("<pre>") && !searchSource.includes("answer_hash") && !searchSource.includes("result_digest"), "the main answer surface does not render raw technical rows or hashes");
const denialStart = searchSource.indexOf("if (summary.kind !== \"ok\" && [401, 403, 404].includes(summary.status))");
const denialBlock = denialStart >= 0 ? searchSource.slice(denialStart, denialStart + 520) : "";
check(denialBlock.includes("setAnswer(summary)") && denialBlock.includes("setResultWorkspace(workspaceID)") && denialBlock.includes("setAnswerPending(false)"), "denied QuestionRun clears the old answer but keeps the current failure visible");
const byteExactLabel = questionClaimGroundingLabel({ answer_mode: "DOCUMENT", verification_method: "BYTE_EXACT_CITATION", grounding_status: "CONFIRMED_BY_FRAGMENT", tool_loop: undefined });
check(byteExactLabel.includes("supported by a fragment") && !byteExactLabel.toLowerCase().includes("unbound"), "byte-exact verified answers use grounding state instead of an unbound tool-loop label");
check(JSON.stringify(questionRunPayload("show contracts", { id: "model-1", label: "Local", location: "INTERNAL" })) === JSON.stringify({ question: "show contracts", model_profile_id: "model-1" }), "selected model is sent with the governed question");
check(JSON.stringify(questionRunPayload("show contracts", null)) === JSON.stringify({ question: "show contracts" }), "one QuestionRun remains usable when no model catalog is exposed");
const readyCatalog = { connection_id: "connection-1", database_identity: "gm", presets: [{ id: "p", version: "v1", name: "P", description: "", phrases: [], preset_hash: "h", source_attempt_id: "a", sql_hash: "s", exposed_schema_revision: 1 }] } as GovernedPresetCatalog;
check(JSON.stringify(governedCatalogAvailability(null)) === JSON.stringify({ status: "loading", catalogAvailable: false, liveAskAvailable: false }), "catalog revalidation reports loading without final denial");
check(JSON.stringify(governedCatalogAvailability({ ...readyCatalog, presets: [] }, true)) === JSON.stringify({ status: "unavailable", catalogAvailable: false, liveAskAvailable: false }), "empty catalog is a final unavailable state");
check(JSON.stringify(governedCatalogAvailability(readyCatalog, false)) === JSON.stringify({ status: "available", catalogAvailable: true, liveAskAvailable: false }), "preset-only catalog keeps Live database and Diagnostics but hides ad hoc ask");
check(JSON.stringify(governedCatalogAvailability(readyCatalog, true)) === JSON.stringify({ status: "available", catalogAvailable: true, liveAskAvailable: true }), "advertised ask capability enables the ad hoc composer");
check(!mainSource.includes("document-search-disclosure"), "the old document-search details wrapper is removed");
const ownerStart = mainSource.indexOf("export function AskSurface");
const ownerEnd = mainSource.indexOf("// The Ask surface sends one governed question run", ownerStart);
const askOwnerSource = ownerStart >= 0 && ownerEnd > ownerStart ? mainSource.slice(ownerStart, ownerEnd) : "";
check(askOwnerSource.includes("<AskView") && !askOwnerSource.includes("<SearchView") && !askOwnerSource.includes("<GovernedPresetPanelHost"), "Ask owns one conversational surface and keeps governed checks out of the main flow");
check(askOwnerSource.includes("onConversationChange") && mainSource.includes("...(selectedConversationID ? { conversation_id: selectedConversationID } : {})") && mainSource.includes("questionRunPayload(trimmed, selectedModel)"), "conversation follow-ups retain their server id and selected model in the one QuestionRun request");
check(mainSource.includes('className="tool-trace"') && mainSource.includes("receipt_digest") && mainSource.includes("run.citations"), "conversation turns retain tool disclosure, receipt, and citation rendering");
check(buildSearchHash("workspace-1", "conv_01") === "#search/workspace-1?conversation=conv_01", "conversation selection is encoded as an opaque search hash parameter");
check(JSON.stringify(parseSearchHash("#search/workspace-1?conversation=conv_01")) === JSON.stringify({ workspace: "workspace-1", conversation: "conv_01" }), "reload parsing restores the selected conversation");
check(parseSearchHash("#search/workspace-1?conversation=one&other=two") === null, "search routing rejects unknown conversation parameters");
check(initialConversationWorkspaceOwner("conv_01", "workspace-1") === "workspace-1", "first authorized workspace hydration owns a deep-linked conversation before the reset effect runs");
check(initialConversationWorkspaceOwner(null, "workspace-1") === null, "a normal first visit remains ownerless and takes the ordinary initial-load reset path");
check(mainSource.includes("initialConversationWorkspaceOwner(initialConversationID, requestedWorkspaceID)") && mainSource.includes("sameRequestedWorkspace"), "the first-hydration owner feeds the existing same-workspace reload guard rather than bypassing a real workspace-change reset");
const receiptRun = { status: "COMPLETED", answer_result: { receipt_digest: "sha256:receipt" } } as never;
const documentRun = { status: "COMPLETED", answer_result: undefined } as never;
check(hasLiveDataReceipt(receiptRun) && !hasLiveDataReceipt(documentRun), "a completed receipt-backed live answer suppresses only the document-citation warning");
check(mainSource.includes("run.citations.length === 0 && !hasLiveReceipt"), "TurnAnswer keeps the no-citation warning for unsupported document claims");
check(!askOwnerSource.includes('aria-label="Search source"') && !askOwnerSource.includes("Workspace search") && !askOwnerSource.includes("Live database"), "Ask owner contains no execution-mode labels");
check(mainSource.includes('<div className="governed-preset-owner" hidden={!visible}>'), "the governed host remains available for a future Diagnostics surface");

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
