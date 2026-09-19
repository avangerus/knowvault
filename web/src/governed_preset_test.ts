// D3B — in-tree UI probe for the governed live-preset panel.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency). It renders
// the real production exports from governed-presets.tsx through
// react-dom/server, so the browser surface can no longer be narrative-only:
//
//   1. the list and run tools/call arguments carry exactly the workspace,
//      connection and preset identity the server approves -- there is no SQL,
//      no parameter and no free-text member to smuggle anything else;
//   2. a cell is projected verbatim: SQL NULL and the empty string stay
//      distinct and a precise decimal never passes through a JavaScript
//      number;
//   3. the rendered table keeps the server's column order and its exact
//      values, and the live observation, its source and its full receipt are
//      all present -- while no input, no SQL statement text and no internal
//      kv1: address ever reach the DOM;
//   4. an empty rowset is stated rather than left blank;
//   5. the generic unavailable/run-failure copy is content-free, so a server
//      error message is never an operator surface.
//
// It is additive: it only reads production source and never changes payloads,
// styles or the already-compliant surfaces.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  GOVERNED_EMPTY_CELL,
  GOVERNED_LIVE_DATA_STATE,
  GOVERNED_NO_ROWS,
  GOVERNED_NULL_CELL,
  GOVERNED_PRESETS_UNAVAILABLE,
  GOVERNED_QUERY_RUN_TOOL,
  GOVERNED_RECEIPT_NOTE,
  GOVERNED_RESULT_RUN_UNAVAILABLE,
  GOVERNED_RESULT_UNKNOWN_PRESET,
  GovernedPresetResultView,
  governedCellText,
  governedMCPCall,
  governedPresetListArguments,
  governedPresetRunArguments,
  governedRequestAccepted,
  type GovernedPresetRunResult,
} from "./governed-presets";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

// A precise decimal beyond Number.MAX_SAFE_INTEGER whose fractional digits
// are lost the moment the text is parsed as a number.
const PRECISE_DECIMAL = "9007199254740993.123456789";
const STARTED_AT = "2026-09-15T10:30:00.123456789Z";
const COMPLETED_AT = "2026-09-15T10:30:00.987654321Z";

async function main(): Promise<void> {
  // --- 1. exact tools/call arguments -------------------------------------
  const listArguments = governedPresetListArguments("workspace-7");
  check(
    Object.keys(listArguments).length === 1 && listArguments.workspace_id === "workspace-7",
    "the catalogue call names exactly the workspace",
  );

  const runArguments = governedPresetRunArguments(
    "workspace-7",
    { connection_id: "connection-2" },
    "preset-9",
  );
  const runKeys = Object.keys(runArguments).sort();
  check(
    runKeys.length === 3
      && runKeys[0] === "connection_id"
      && runKeys[1] === "preset_id"
      && runKeys[2] === "workspace_id",
    "the run call names exactly workspace_id, connection_id and preset_id",
  );
  check(
    runArguments.workspace_id === "workspace-7"
      && runArguments.connection_id === "connection-2"
      && runArguments.preset_id === "preset-9",
    "the run call carries the exact selected identities",
  );
  check(
    !("sql" in runArguments) && !("parameters" in runArguments),
    "the run call carries no sql and no parameters member",
  );

  // --- 2. verbatim cell projection ---------------------------------------
  check(governedCellText(null) === GOVERNED_NULL_CELL && GOVERNED_NULL_CELL === "NULL", "a SQL NULL is shown as NULL");
  check(governedCellText("") === GOVERNED_EMPTY_CELL && GOVERNED_EMPTY_CELL === '""', "an empty string stays distinct from NULL");
  check(governedCellText(PRECISE_DECIMAL) === PRECISE_DECIMAL, "a precise decimal is preserved exactly");

  // --- 3. rendered live observation --------------------------------------
  const result: GovernedPresetRunResult = {
    attempt_id: "attempt-3",
    preset: {
      id: "preset-9",
      version: "7",
      name: "Recent rows",
      description: "The latest rows for this connection",
      phrases: ["recent", "latest"],
      preset_hash: "hmac-sha256:k4:" + "a".repeat(64),
      source_attempt_id: "attempt-1",
      sql_hash: "hmac-sha256:k5:" + "b".repeat(64),
      exposed_schema_revision: 12,
    },
    sql_hash: "hmac-sha256:k5:" + "b".repeat(64),
    columns: ["second", "first"],
    rows: [[PRECISE_DECIMAL, null]],
    row_count: 1,
    cost_estimate: 4.5,
    connection_id: "connection-2",
    database_identity: "db-identity-1",
    exposed_schema_revision: 12,
    result_format: "json_rows",
    result_digest: "hmac-sha256:k6:" + "c".repeat(64),
    execution_started_at: STARTED_AT,
    execution_completed_at: COMPLETED_AT,
    data_state: GOVERNED_LIVE_DATA_STATE,
  };
  const markup = renderToStaticMarkup(createElement(GovernedPresetResultView, { result }));

  const headerSecond = markup.indexOf(">second<");
  const headerFirst = markup.indexOf(">first<");
  check(headerSecond !== -1 && headerFirst !== -1 && headerSecond < headerFirst, "the header keeps the server column order");
  check(markup.includes('scope="col"'), "the header cells are column headers");
  check(markup.includes(PRECISE_DECIMAL), "the precise decimal reaches the DOM verbatim");
  check(markup.includes(GOVERNED_NULL_CELL), "the NULL cell reaches the DOM");

  check(markup.includes(GOVERNED_LIVE_DATA_STATE), "the live observation state is disclosed");
  check(markup.includes(result.database_identity), "the database identity is disclosed");
  check(markup.includes(result.connection_id), "the connection id is disclosed");
  check(markup.includes(STARTED_AT) && markup.includes(COMPLETED_AT), "both read-window timestamps are shown verbatim");
  check(markup.includes(`Rows: ${result.row_count}`), "the reported row count is shown");

  check(markup.includes(result.attempt_id), "the attempt id is in the receipt");
  check(markup.includes(result.preset.id), "the preset id is in the receipt");
  check(markup.includes(result.preset.version), "the preset version is in the receipt");
  check(markup.includes(result.preset.preset_hash), "the preset hash is in the receipt");
  check(markup.includes(result.sql_hash), "the sql_hash is in the receipt");
  check(markup.includes(result.result_digest), "the result digest is in the receipt");
  check(markup.includes("exposed_schema_revision") && markup.includes(String(result.exposed_schema_revision)),
    "the schema revision is in the receipt");
  check(markup.includes(result.result_format), "the result format is in the receipt");
  check(markup.includes("Receipt"), "the receipt is present");
  check(markup.includes(GOVERNED_RECEIPT_NOTE), "the live-data receipt note is present");

  check(!markup.includes("<input"), "the panel renders no input control");
  check(!markup.includes("SELECT ") && !markup.includes("FROM "), "no SQL statement text reaches the DOM");
  check(!markup.includes("kv1:"), "no internal kv1: address reaches the DOM");

  // --- 4. empty rowset ----------------------------------------------------
  const emptyMarkup = renderToStaticMarkup(createElement(GovernedPresetResultView, {
    result: { ...result, columns: ["second", "first"], rows: [], row_count: 0 },
  }));
  check(emptyMarkup.includes(GOVERNED_NO_ROWS), "an empty rowset is stated, not left blank");

  // --- 5. content-free generic copy --------------------------------------
  const genericCopy = [
    GOVERNED_PRESETS_UNAVAILABLE,
    GOVERNED_RESULT_RUN_UNAVAILABLE,
    GOVERNED_RESULT_UNKNOWN_PRESET,
  ];
  for (const copy of genericCopy) {
    check(copy.trim().length > 0, "generic copy is not blank");
  }
  check(!GOVERNED_PRESETS_UNAVAILABLE.includes("SELECT ") && !GOVERNED_PRESETS_UNAVAILABLE.includes("kv1:"),
    "the unavailable copy leaks no server content");
  check(!GOVERNED_RESULT_RUN_UNAVAILABLE.includes("SELECT ") && !GOVERNED_RESULT_RUN_UNAVAILABLE.includes("kv1:")
    && !GOVERNED_RESULT_RUN_UNAVAILABLE.includes("connection-2"),
    "the run-failure copy leaks no server content");

  // --- 6. stale continuation is discarded --------------------------------
  // A run that was started for one selection must not record its result once
  // the user has moved on. The helper is the single gate for that decision.
  {
    let current = 0;
    const alive = true;
    current += 1;
    const stamp = current;
    let recorded = false;
    const continuation = new Promise<void>((resolve) => {
      if (governedRequestAccepted(stamp, current, alive)) recorded = true;
      resolve();
    });
    // The user changes to preset B / a different workspace: the epoch moves on.
    current += 1;
    await continuation;
    check(recorded === false, "a continuation that was superseded before it ran records nothing");

    current += 1;
    const freshStamp = current;
    check(governedRequestAccepted(freshStamp, current, alive), "a fresh stamp is accepted");
    check(!governedRequestAccepted(freshStamp, current, false), "an unmounted panel rejects even a fresh stamp");
  }

  // --- 7. CSRF 401 is sessionExpired, with no MCP POST --------------------
  {
    const calls: string[] = [];
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response("", { status: 401 });
    };
    const outcome = await governedMCPCall<GovernedPresetRunResult>(
      fakeFetch, GOVERNED_QUERY_RUN_TOOL, governedPresetRunArguments("workspace-7", { connection_id: "connection-2" }, "preset-9"));
    check(outcome.kind === "sessionExpired", "an HTTP 401 on the CSRF GET is reported as sessionExpired");
    check(calls.length === 1 && calls[0] === "/api/v1/session/csrf", "the 401 short-circuits before any MCP POST");
  }

  if (failures !== 0) throw new Error(`${failures} governed-preset assertion(s) failed`);
  console.log("governed preset UI probe: PASS");
}

void main();
