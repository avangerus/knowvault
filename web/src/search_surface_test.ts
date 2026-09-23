import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AskSurface,
  EvidencePanel,
  SearchView,
  authorizedSourcesForAsk,
  buildSearchHash,
  comparisonEvidenceForReceipt,
  hasLiveDataReceipt,
  initialConversationWorkspaceOwner,
  LiveTableEvidenceList,
  LiveResultEvidencePanel,
  liveTablePayloadForReceipt,
  parseSearchHash,
  pendingActionFromEvents,
  questionClaimGroundingLabel,
  questionRunPayload,
  relySourceSummary,
  reduceGovernedRetention,
  sidebarConversations,
  TurnCard,
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
const askViewStart = mainSource.indexOf("function AskView", searchEnd);
const askViewEnd = mainSource.indexOf("function sourceHeadline", askViewStart);
const askSource = askViewStart >= 0 && askViewEnd > askViewStart ? mainSource.slice(askViewStart, askViewEnd) : "";
const answerStart = mainSource.indexOf("function QuestionRunAnswer");
const answerSource = answerStart >= 0 && searchStart > answerStart ? mainSource.slice(answerStart, searchStart) : "";
check((searchSource.match(/apiPost<QuestionRun>/g) ?? []).length === 1, "document search retains its one QuestionRun POST");
check((askSource.match(/apiPostQuestionStream\(/g) ?? []).length === 1, "Ask submits exactly one opt-in QuestionRun POST");
check(!searchSource.includes("tools/search") && !searchSource.includes("apiGet<"), "question submit does not issue a preliminary document-search GET");
check(mainSource.includes('Accept: "application/x-ndjson"') && mainSource.includes('response.json()) as QuestionRun')
  && !askSource.includes("apiPost<QuestionRun>("), "streaming falls back to the same JSON response without replay");
check(askSource.includes("observationForGeneration(workspaceGeneration, () => workspaceGenerationRef.current")
  && askSource.includes("if (workspaceGenerationRef.current !== workspaceGeneration) return;"),
"a workspace switch blocks both delayed progress frames and the final answer");
const orderedProgress = pendingActionFromEvents([
  { type: "action", sequence: 3, phase: "action_finished", label: "document_read", outcome: "succeeded", duration_ms: 3 },
  { type: "action", sequence: 1, phase: "action_started", label: "document_search" },
  { type: "action", sequence: 2, phase: "action_started", label: "document_read" },
]);
check(orderedProgress.current === "working" && JSON.stringify(orderedProgress.completed) === JSON.stringify([{ kind: "reading", outcome: "succeeded", durationMS: 3 }]),
"progress follows server sequence and shows observed outcomes");
const failedProgress = pendingActionFromEvents([
  { type: "action", sequence: 4, phase: "action_finished", label: "document_search", outcome: "failed", duration_ms: 3 },
  { type: "action", sequence: 5, phase: "action_started", label: "model" },
]);
check(failedProgress.current === "model" && JSON.stringify(failedProgress.completed) === JSON.stringify([{ kind: "searching", outcome: "failed", durationMS: 3 }]),
"a failed tool attempt stays in history while the next model step is neutral");
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
const liveReceipts = [1, 2, 3].map((ordinal) => ({
  execution_id: `attempt-${ordinal}`,
  result_digest: `sha256:${String.fromCharCode(96 + ordinal).repeat(64)}`,
  receipt_digest: `sha256:${String(ordinal).repeat(64)}`,
  row_count: 1,
  completeness: "COMPLETE",
  observation_window: {
    basis: "SERVER_GOVERNED_QUERY_EXECUTION",
    started_at: "2026-09-21T08:12:29Z",
    completed_at: "2026-09-21T08:12:30Z",
  },
}));
const liveAnswerResult = {
  kind: "LIVE_TABLE",
  receipts: liveReceipts,
} as never;
const liveRunFixture = {
  question_run_id: "qrun-1",
  tool_loop: {
    model: "fixture-model",
    stop_reason: "END_TURN",
    all_claims_bound: true,
    calls: [
      ...liveReceipts.map((receipt, index) => ({
        id: `call-${index + 1}`,
        name: "knowvault_ask_live_data",
        system: false,
        outcome: "SUCCEEDED",
        duration_ms: 25,
        result: {
          text: "",
          structured: {
            attempt_id: receipt.execution_id,
            result_digest: receipt.result_digest,
            receipt_digest: receipt.receipt_digest,
            complete: true,
            read_window: { complete: true },
            row_count: 1,
            columns: ["id"],
            rows: [[`PRIVATE_LIVE_ROW_${index + 1}`]],
          },
        },
      })),
      {
        id: "document-call",
        name: "knowvault_search",
        system: false,
        outcome: "SUCCEEDED",
        duration_ms: 12,
        result: { text: "PRIVATE_DOCUMENT_TOOL_JSON" },
      },
    ],
  },
};
const liveEvidenceMarkup = renderToStaticMarkup(createElement(LiveTableEvidenceList, {
  result: liveAnswerResult,
  run: liveRunFixture as never,
}));
const livePanelMarkup = renderToStaticMarkup(createElement(LiveResultEvidencePanel, {
  run: { ...liveRunFixture, answer_result: liveAnswerResult } as never,
}));
check(livePanelMarkup.includes("live database reads") && livePanelMarkup.includes("Live result 1")
  && livePanelMarkup.includes(`sha256:${"1".repeat(64)}`)
  && !livePanelMarkup.includes("no supporting citations") && !livePanelMarkup.includes("Evidence unavailable"),
  "live-only evidence panel presents the receipt without a document-citation warning");
check([1, 2, 3].every((ordinal) => liveEvidenceMarkup.includes(`Live result ${ordinal}`)), "every current live receipt has a separately labelled evidence disclosure");
check([1, 2, 3].every((ordinal) => liveEvidenceMarkup.includes(`sha256:${String(ordinal).repeat(64)}`))
  && liveEvidenceMarkup.includes("Database read:"), "live evidence disclosures carry read times and each receipt digest");
check(liveEvidenceMarkup.includes(" · read ") && liveEvidenceMarkup.indexOf("Database read:") < liveEvidenceMarkup.indexOf("<summary>Technical details</summary>")
  && liveEvidenceMarkup.indexOf("Receipt digest") > liveEvidenceMarkup.indexOf("<summary>Technical details</summary>")
  && liveEvidenceMarkup.includes("Execution ID") && liveEvidenceMarkup.includes("Result digest"),
  "live receipt shows read time first and keeps identifiers and hashes in closed technical details");
check(liveEvidenceMarkup.includes("Show returned table") && !liveEvidenceMarkup.includes("PRIVATE_LIVE_ROW_"), "the receipt UI keeps table rows out of default markup and offers an explicit disclosure control");
const matchingLivePayload = liveTablePayloadForReceipt(liveRunFixture, liveReceipts[1]);
check(matchingLivePayload?.rows[0]?.[0] === "PRIVATE_LIVE_ROW_2", "a returned table is available only from the successful call matching the exact live receipt");
check(liveTablePayloadForReceipt(liveRunFixture, { ...liveReceipts[1], receipt_digest: `sha256:${"9".repeat(64)}` }) === null
  && liveTablePayloadForReceipt(liveRunFixture, { ...liveReceipts[1], result_digest: `sha256:${"9".repeat(64)}` }) === null
  && liveTablePayloadForReceipt(liveRunFixture, { ...liveReceipts[1], execution_id: "another-run" }) === null
  && liveTablePayloadForReceipt(liveRunFixture, { ...liveReceipts[1], completeness: "PARTIAL" }) === null,
  "a receipt, result, run ID or completeness mismatch withholds the table payload");
const comparisonReceipt = { ...liveReceipts[0], row_count: 2 };
const comparisonResult = {
  metric_id: "work.assignments", profile_hash: `sha256:${"a".repeat(64)}`,
  evidence_schema_version: 1, exposed_schema_revision: 7,
  unit: "unknown", coverage: "OBSERVED_SNAPSHOT",
  first: { date: "2026-09-10", snapshot_at: "2026-09-10T09:00:00Z", value: "32520", contributing_rows: 9, distinct_subjects: 9 },
  second: { date: "2026-09-17", snapshot_at: "2026-09-17T09:00:00Z", value: "36454", contributing_rows: 10, distinct_subjects: 10 },
  delta: "-3934", percent_change: "-10.79",
  attempt_id: comparisonReceipt.execution_id, raw_result_digest: comparisonReceipt.result_digest,
  evidence_digest: `sha256:${"e".repeat(64)}`, receipt_digest: comparisonReceipt.receipt_digest,
};
const comparisonRun = { ...liveRunFixture, tool_loop: { ...liveRunFixture.tool_loop, calls: [{
  id: "comparison-call", name: "knowvault_compare_metric", outcome: "SUCCEEDED", duration_ms: 30,
  result: { text: JSON.stringify(comparisonResult), structured: comparisonResult },
}] } };
check(comparisonEvidenceForReceipt(comparisonRun as never, comparisonReceipt)?.delta === "-3934"
  && comparisonEvidenceForReceipt(comparisonRun as never, { ...comparisonReceipt, result_digest: `sha256:${"9".repeat(64)}` }) === null
  && comparisonEvidenceForReceipt(comparisonRun as never, { ...comparisonReceipt, receipt_digest: `sha256:${"9".repeat(64)}` }) === null
  && comparisonEvidenceForReceipt(comparisonRun as never, { ...comparisonReceipt, execution_id: "other" }) === null,
  "comparison evidence requires the exact attempt, raw result and receipt digests");
const alteredComparisonRun = (structured: unknown) => ({ ...comparisonRun, tool_loop: { ...comparisonRun.tool_loop,
  calls: [{ ...comparisonRun.tool_loop.calls[0], result: { text: "", structured } }],
} });
check(comparisonEvidenceForReceipt(alteredComparisonRun({ ...comparisonResult, first: { ...comparisonResult.first, distinct_subjects: 8 } }) as never, comparisonReceipt) === null
  && comparisonEvidenceForReceipt(alteredComparisonRun({ ...comparisonResult, coverage: "COMPLETE" }) as never, comparisonReceipt) === null
  && comparisonEvidenceForReceipt(alteredComparisonRun({ ...comparisonResult, sql: "SELECT * FROM private" }) as never, comparisonReceipt) === null,
  "comparison evidence rejects inconsistent counts, coverage claims and unexpected fields");
const comparisonMarkup = renderToStaticMarkup(createElement(LiveTableEvidenceList, {
  result: { kind: "LIVE_TABLE", receipts: [comparisonReceipt] } as never, run: comparisonRun as never,
}));
check(comparisonMarkup.includes("32520") && comparisonMarkup.includes("36454")
  && comparisonMarkup.includes("2026-09-10T09:00:00Z") && comparisonMarkup.includes("2026-09-17T09:00:00Z")
  && comparisonMarkup.includes("Observed subjects") && comparisonMarkup.includes("-3934")
  && comparisonMarkup.includes("-10.79%") && comparisonMarkup.includes("full population coverage is unknown")
  && comparisonMarkup.includes(`sha256:${"e".repeat(64)}`) && !comparisonMarkup.includes("table payload is unavailable")
  && !comparisonMarkup.includes("SELECT *"), "comparison receipt renders compact observed evidence without SQL");
check(comparisonMarkup.indexOf("2026-09-10: 32520") < comparisonMarkup.indexOf("<summary>Technical details</summary>")
  && comparisonMarkup.indexOf("Semantic evidence digest") > comparisonMarkup.indexOf("<summary>Technical details</summary>")
  && comparisonMarkup.includes(comparisonResult.profile_hash) && comparisonMarkup.includes("Exposed schema revision"),
  "comparison values and dates precede its closed provenance details");
check(mainSource.includes("<ToolCallsDisclosure run={run} showResults={false} />")
  && !mainSource.includes("<ToolCallsDisclosure run={run} showResults={true}"), "live table disclosure leaves generic tool outputs hidden");
const activeConversationRun = {
  ...liveRunFixture,
  workspace_id: "workspace-1",
  question: "Summarize the live reads",
  answer_mode: "TOOL_LOOP",
  status: "COMPLETED",
  corpus_status: "COMPLETE",
  verification_method: "ADDRESS_BOUND",
  grounding_status: "CONFIRMED_BY_FRAGMENT",
  freshness: {},
  answer: "SUPPORTED_LIVE_ANSWER_TEXT",
  citations: [],
  uncertainties: [],
  conflicts: [],
  answer_result: liveAnswerResult,
} as never;
const liveTurn = {
  turn_id: "turn-1",
  question_run_id: "qrun-1",
  turn_index: 1,
  created_at: "2026-09-21T08:12:30Z",
  question_run: activeConversationRun,
} as never;
const liveSidePanelMarkup = renderToStaticMarkup(createElement(EvidencePanel, {
  workspaceID: "workspace-1",
  target: { turnId: "turn-1", citationId: null },
  turnsByID: new Map([["turn-1", liveTurn]]),
  sourceNameByConnection: new Map(),
  allSources: [],
  fullscreen: false,
  onOpenEvidence: () => {},
  onToggleFullscreen: () => {},
  onSelectCitation: () => {},
}));
check(liveSidePanelMarkup.includes("Live database evidence") && liveSidePanelMarkup.includes("Live result 1")
  && liveSidePanelMarkup.includes(`sha256:${"1".repeat(64)}`)
  && !liveSidePanelMarkup.includes("Evidence unavailable") && !liveSidePanelMarkup.includes("no supporting citations"),
  "selecting a live-only turn shows its receipts in the right evidence panel");
const activeConversationMarkup = renderToStaticMarkup(createElement(TurnCard, {
  turn: liveTurn,
  panelTurnId: null,
  selectedCitationId: null,
  onSelectTurn: () => {},
  onSelectCitation: () => {},
}));
check(activeConversationMarkup.includes("SUPPORTED_LIVE_ANSWER_TEXT")
  && [1, 2, 3].every((ordinal) => activeConversationMarkup.includes(`Live result ${ordinal}`)), "the active conversation TurnCard renders the answer and every receipt disclosure");
check(activeConversationMarkup.indexOf("SUPPORTED_LIVE_ANSWER_TEXT") < activeConversationMarkup.indexOf("Live result 1")
  && !activeConversationMarkup.includes("Run ID") && !activeConversationMarkup.includes("R1 audit receipt"), "the active conversation shows live receipts after prose without the old technical result panel");
check(activeConversationMarkup.includes("tool-trace") && !activeConversationMarkup.includes("PRIVATE_LIVE_ROW_")
  && !activeConversationMarkup.includes("PRIVATE_DOCUMENT_TOOL_JSON") && !activeConversationMarkup.includes("<pre"),
  "the active conversation keeps table rows and generic document/tool JSON hidden by default");
const askViewSource = mainSource.slice(mainSource.indexOf("function AskView("));
check(askViewSource.includes("{feedTurns.map((turn) => (") && askViewSource.includes("<TurnCard")
  && mainSource.includes("export function TurnCard"), "the exercised TurnCard is mounted by the active AskView conversation feed");
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

const sidebarRows = [
  { conversation_id: "empty-old", turns: [] },
  { conversation_id: "asked", turns: [{ question_run: { question: "How fresh is GM?" } }] },
  { conversation_id: "empty-current", turns: [] },
  { conversation_id: "archived", archived_at: "2026-09-23T00:00:00Z", turns: [{ question_run: { question: "Archived" } }] },
] as unknown as Parameters<typeof sidebarConversations>[0];
check(sidebarConversations(sidebarRows, null, "").map((item) => item.conversation_id).join() === "asked",
  "sidebar hides old empty conversations and archived history without deleting them");
check(sidebarConversations(sidebarRows, "empty-current", "").map((item) => item.conversation_id).join() === "asked,empty-current",
  "sidebar keeps the currently open empty conversation reachable");
check(sidebarConversations(sidebarRows, null, "fresh").map((item) => item.conversation_id).join() === "asked",
  "sidebar search still finds conversations after their first Ask");

if (failures !== 0) throw new Error(`${failures} search-surface assertion(s) failed`);
console.log("search surface probe: PASS");
