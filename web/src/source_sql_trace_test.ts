// Card ui-sql probe: the chat surface shows the exact SQL knowvault_source_sql
// ran, and its short result, for both a successful and a refused call.
//
// 2026-09-26 critique / walkthrough (F2, F5, critique finding 5):
// GET /api/v1/workspaces/{id}/conversations/{id} already returns
// run.tool_loop.calls[].arguments.sql and the call's own result for every
// knowvault_source_sql call, but ToolCallsDisclosure (the tool trace) read
// only name/duration/outcome/result text, and liveTablePayloadForReceipt (the
// live-read citation block) matched only knowvault_ask_live_data, so a
// SQL-sourced citation always rendered "the table payload is unavailable".
// Nothing here fetches or persists anything new -- every assertion is a
// projection of a fixture shaped exactly like the real API response.
//
// Plain TypeScript module run by the repository's pinned esbuild + node
// toolchain (no test framework, no jsdom), matching tool_call_summary_test.ts
// and search_surface_test.ts.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  LiveTableEvidenceList,
  ToolCallsDisclosure,
  liveTablePayloadForReceipt,
  sourceSQLRefusalCode,
  sourceSQLResultPreview,
  sourceSQLStatementForReceipt,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

// react-dom/server escapes text-node content (&, <, >, ", ') exactly like any
// other HTML renderer would; assertions against the rendered markup compare
// against this same escaping rather than the raw literal.
function htmlText(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

const SQL_TEXT = "SELECT count(*) AS total_contracts, count(*) FILTER (WHERE expiration_date >= CURRENT_DATE) AS active_contracts FROM public.contract";

const successReceipt = {
  execution_id: "gqat_success1",
  result_digest: `sha256:${"a".repeat(64)}`,
  receipt_digest: `sha256:${"b".repeat(64)}`,
  row_count: 1,
  completeness: "COMPLETE",
  observation_window: {
    basis: "SERVER_GOVERNED_QUERY_EXECUTION",
    started_at: "2026-09-26T13:42:00Z",
    completed_at: "2026-09-26T13:42:01Z",
  },
};

const successCall = {
  id: "call-sql-1",
  name: "knowvault_source_sql",
  arguments: { source_id: "conn_gm", sql: SQL_TEXT, purpose: "count active contracts" },
  system: false,
  outcome: "SUCCEEDED",
  duration_ms: 180,
  result: {
    text: "",
    structured: {
      attempt_id: successReceipt.execution_id,
      result_digest: successReceipt.result_digest,
      receipt_digest: successReceipt.receipt_digest,
      complete: true,
      read_window: { complete: true },
      row_count: 1,
      columns: ["total_contracts", "active_contracts"],
      rows: [["6556", "5857"]],
    },
  },
};

const refusedCall = {
  id: "call-sql-2",
  name: "knowvault_source_sql",
  arguments: { source_id: "conn_gm", sql: "SELECT status_id, sign_status_id, count(*) AS cnt FROM public.contract GROUP BY status_id, sign_status_id ORDER BY cnt DESC" },
  system: false,
  outcome: "REFUSED",
  duration_ms: 40,
  result: { text: '{"error":"ROW_LIMIT"}', structured: { error: "ROW_LIMIT" }, is_error: true },
};

const noSQLCall = {
  id: "call-search-1",
  name: "knowvault_search",
  arguments: { query: "GM data dictionary" },
  system: false,
  outcome: "SUCCEEDED",
  duration_ms: 12,
  result: { text: "", structured: { results: [{}] } },
};

const runFixture = {
  question_run_id: "qrun-sql-1",
  tool_loop: {
    model: "fixture-model",
    stop_reason: "END_TURN",
    all_claims_bound: true,
    calls: [successCall, refusedCall, noSQLCall],
  },
};

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

check(sourceSQLRefusalCode(refusedCall as never) === "ROW_LIMIT", "a refused source-SQL call exposes its closed refusal code");
check(sourceSQLRefusalCode(successCall as never) === null, "a successful source-SQL call has no refusal code");
check(sourceSQLRefusalCode(noSQLCall as never) === null, "a non-SQL tool call has no refusal code");

const preview = sourceSQLResultPreview(successCall as never);
check(preview?.columns.join(",") === "total_contracts,active_contracts" && preview?.rows[0]?.[0] === "6556" && preview?.rowCount === 1,
  "a successful source-SQL call's own returned table is available as a bounded preview");
check(sourceSQLResultPreview(refusedCall as never) === null, "a refused source-SQL call has no result preview");

check(sourceSQLStatementForReceipt(runFixture as never, successReceipt) === SQL_TEXT,
  "the exact SQL behind a matching LIVE_TABLE receipt is readable from the call the answer actually made");
check(sourceSQLStatementForReceipt(runFixture as never, { ...successReceipt, receipt_digest: `sha256:${"9".repeat(64)}` }) === null,
  "a receipt-digest mismatch withholds the SQL statement, exactly like the table payload");

// ---------------------------------------------------------------------------
// Tool trace (ToolCallsDisclosure): the actual "How the answer was found"
// disclosure both production call sites render (showResults=false).
// ---------------------------------------------------------------------------

const traceMarkup = renderToStaticMarkup(createElement(ToolCallsDisclosure, { run: runFixture as never, showResults: false }));

check(traceMarkup.includes(htmlText(SQL_TEXT)), "the tool trace shows the exact SQL of a successful knowvault_source_sql call");
check(traceMarkup.includes("6556") && traceMarkup.includes("5857"), "the tool trace shows the short result (returned rows) of a successful SQL call");
check(traceMarkup.includes("Refused: ROW_LIMIT"), "the tool trace shows the refusal code of a failed knowvault_source_sql call");
check(traceMarkup.includes("GROUP BY status_id, sign_status_id"), "the tool trace shows the SQL of a refused call too, not only successful ones");
check((traceMarkup.match(/class="tool-trace-sql"/g) ?? []).length === 2, "only the two SQL calls carry the SQL disclosure, not the document-search call");

// ---------------------------------------------------------------------------
// Live-read citation block (LiveTableEvidenceList / LiveTableEvidenceItem):
// the SQL renders next to the citation it supports, and the previously
// broken table payload now renders instead of "unavailable".
// ---------------------------------------------------------------------------

const liveTableAnswerResult = { kind: "LIVE_TABLE", receipts: [successReceipt] } as never;
const evidenceMarkup = renderToStaticMarkup(createElement(LiveTableEvidenceList, { result: liveTableAnswerResult, run: runFixture as never }));

check(evidenceMarkup.includes("SQL executed") && evidenceMarkup.includes(htmlText(SQL_TEXT)),
  "the live-read citation for a SQL-sourced receipt shows the exact SQL that ran");
check(!evidenceMarkup.includes("table payload is unavailable"),
  "a knowvault_source_sql receipt's own columns and rows are now recognized instead of reporting the table unavailable");
check(liveTablePayloadForReceipt(runFixture as never, successReceipt)?.rows[0]?.[0] === "6556",
  "liveTablePayloadForReceipt now matches a successful knowvault_source_sql call, not only knowvault_ask_live_data");

// A receipt backed by knowvault_ask_live_data (no agent-written SQL) renders
// exactly as before: no "SQL executed" disclosure invented for it.
const liveDataReceipt = {
  execution_id: "attempt-live-1",
  result_digest: `sha256:${"c".repeat(64)}`,
  receipt_digest: `sha256:${"d".repeat(64)}`,
  row_count: 1,
  completeness: "COMPLETE",
};
const liveDataRun = {
  question_run_id: "qrun-live-1",
  tool_loop: {
    model: "fixture-model", stop_reason: "END_TURN", all_claims_bound: true,
    calls: [{
      id: "call-live-1", name: "knowvault_ask_live_data", system: false, outcome: "SUCCEEDED", duration_ms: 20,
      result: {
        text: "",
        structured: {
          attempt_id: liveDataReceipt.execution_id, result_digest: liveDataReceipt.result_digest,
          receipt_digest: liveDataReceipt.receipt_digest, complete: true, read_window: { complete: true },
          row_count: 1, columns: ["id"], rows: [["3888"]],
        },
      },
    }],
  },
};
const liveDataMarkup = renderToStaticMarkup(createElement(LiveTableEvidenceList, {
  result: { kind: "LIVE_TABLE", receipts: [liveDataReceipt] } as never, run: liveDataRun as never,
}));
check(!liveDataMarkup.includes("SQL executed"), "a knowvault_ask_live_data receipt renders as before, with no invented SQL disclosure");
check(!liveDataMarkup.includes("table payload is unavailable"), "a knowvault_ask_live_data receipt still resolves its own table payload as before");

if (failures !== 0) throw new Error(`${failures} source-SQL trace/citation assertion(s) failed`);
console.log("source SQL trace and citation probe: PASS");
