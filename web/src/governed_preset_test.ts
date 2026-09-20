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
  GovernedAskResultView,
  GovernedPresetResultView,
  governedAsk,
  governedAskReceiptRows,
  governedCellText,
  governedMCPCall,
  governedPresetListArguments,
  governedPresetRunArguments,
  governedRequestAccepted,
  type GovernedAskResult,
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

const ASK_CSRF_TOKEN = "csrf-token-ask-1";

function askResultFixture(connectionID = "connection-2"): GovernedAskResult {
  return {
    attempt_id: "attempt-ask-4",
    sql: "SELECT amount FROM ledger",
    sql_hash: "hmac-sha256:k7:" + "d".repeat(64),
    columns: ["amount", "note", "memo"],
    rows: [[PRECISE_DECIMAL, null, ""]],
    row_count: 1,
    cost_estimate: 4.5,
    answer: "The latest ledger amount is the precise value shown.",
    connection_id: connectionID,
    database_identity: "db-identity-1",
    exposed_schema_revision: 12,
    result_format: "json_rows",
    result_digest: "hmac-sha256:k8:" + "e".repeat(64),
    execution_started_at: STARTED_AT,
    execution_completed_at: COMPLETED_AT,
  };
}

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
    // The run's result arrives later, so its completion is deferred until we
    // explicitly release it below.
    let resolveDeferred!: () => void;
    const deferred = new Promise<void>((resolve) => {
      resolveDeferred = resolve;
    });
    const continuation = deferred.then(() => {
      if (governedRequestAccepted(stamp, current, alive)) recorded = true;
    });
    // The user changes to preset B / a different workspace: the epoch moves on
    // and supersedes the stamp A is still holding.
    current += 1;
    resolveDeferred();
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

  // --- 8. governedAsk success: exact request and unchanged result ---------
  // The transport must fetch a CSRF token, POST the connection-scoped :ask
  // path with exactly the ask headers, send exactly { question } and return
  // the server's result untouched -- precise decimal, NULL and empty string
  // all preserved verbatim.
  {
    const encodedWorkspaceID = "workspace/7 ?";
    const encodedConnectionID = "connection/2 ?";
    const expectedResult = askResultFixture(encodedConnectionID);
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    let step = 0;
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      step += 1;
      if (step === 1) {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ connection_id: encodedConnectionID, result: expectedResult }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const outcome = await governedAsk(
      fakeFetch,
      encodedWorkspaceID,
      { connection_id: encodedConnectionID },
      "What is the latest ledger amount?",
    );

    check(calls.length === 2, "governedAsk makes exactly two calls");

    const csrfCall = calls[0];
    check(csrfCall.url === "/api/v1/session/csrf", "governedAsk first GETs the CSRF endpoint");
    check(
      (csrfCall.init?.method ?? "GET") === "GET",
      "the CSRF call is a GET with no method override",
    );

    const askCall = calls[1];
    check(
      askCall.url
        === "/api/v1/workspaces/workspace%2F7%20%3F/governed-query-connections/connection%2F2%20%3F:ask",
      "governedAsk encodes both identities in the workspace- and connection-scoped :ask path",
    );
    check(askCall.init?.method === "POST", "the ask call is a POST");

    const headers = new Headers(askCall.init?.headers);
    check(headers.get("Accept") === "application/json", "the ask Accept header is exact");
    check(headers.get("Content-Type") === "application/json", "the ask Content-Type header is exact");
    check(headers.get("X-KnowVault-CSRF") === ASK_CSRF_TOKEN, "the ask CSRF header is exact");
    const idempotencyKey = headers.get("Idempotency-Key") ?? "";
    check(idempotencyKey.length === 43, "the generated ask Idempotency-Key is exactly 43 characters");
    check(/^[A-Za-z0-9_-]{43}$/.test(idempotencyKey), "the generated ask Idempotency-Key is unpadded base64url");
    check(!headers.has("If-Match"), "the ask call sends no If-Match header");

    const body = JSON.parse(String(askCall.init?.body)) as Record<string, unknown>;
    check(Object.keys(body).length === 1 && body.question === "What is the latest ledger amount?",
      "the ask body is exactly { question } with the exact text");

    check(outcome.kind === "ok", "a well-formed ask response is an ok outcome");
    if (outcome.kind === "ok") {
      const value = outcome.value;
      check(JSON.stringify(value) === JSON.stringify(expectedResult), "the complete ask result JSON is returned unchanged");
      check(value.rows[0][0] === PRECISE_DECIMAL, "the ask precise decimal is preserved exactly");
      check(value.rows[0][1] === null, "the ask NULL cell is preserved as null");
      check(value.rows[0][2] === "", "the ask empty-string cell is preserved as an empty string");
      check(value.answer === expectedResult.answer, "the ask answer text is unchanged");
      check(value.attempt_id === expectedResult.attempt_id, "the ask attempt identity is unchanged");
      check(value.connection_id === expectedResult.connection_id
        && value.database_identity === expectedResult.database_identity,
        "the ask identity fields are unchanged");
      check(value.execution_started_at === STARTED_AT && value.execution_completed_at === COMPLETED_AT,
        "the ask read-window timestamps are unchanged");
      check(value.sql_hash === expectedResult.sql_hash
        && value.result_digest === expectedResult.result_digest
        && value.result_format === expectedResult.result_format
        && value.exposed_schema_revision === expectedResult.exposed_schema_revision,
        "the ask receipt fields are unchanged");
    }
  }

  // --- 9. every invocation owns a fresh idempotency key ------------------
  {
    const keys: string[] = [];
    let call = 0;
    const fakeFetch: typeof fetch = async (_input: RequestInfo | URL, init?: RequestInit) => {
      call += 1;
      if (call % 2 === 1) {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      const key = new Headers(init?.headers).get("Idempotency-Key") ?? "";
      keys.push(key);
      return new Response(JSON.stringify({ connection_id: "connection-2", result: askResultFixture() }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const first = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "First question");
    const second = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "Second question");
    check(first.kind === "ok" && second.kind === "ok", "two independent governedAsk invocations both complete");
    check(keys.length === 2, "two governedAsk invocations each POST exactly once");
    check(keys.every((key) => /^[A-Za-z0-9_-]{43}$/.test(key)), "each invocation generates a valid 43-character key");
    check(keys[0] !== keys[1], "separate governedAsk invocations never reuse an idempotency key");
  }

  // --- 10. governedAsk CSRF 401 is sessionExpired, with no POST -----------
  {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      return new Response("", { status: 401 });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "sessionExpired", "an HTTP 401 on the ask CSRF GET is reported as sessionExpired");
    check(calls.length === 1, "the ask 401 makes exactly one call");
    check(calls[0].url === "/api/v1/session/csrf", "the ask 401 short-circuits on the CSRF GET");
    check(calls.every((call) => (call.init?.method ?? "GET") !== "POST"), "the ask 401 makes no POST");
  }

  // --- 11. governedAsk POST 401 is sessionExpired -------------------------
  {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      if (calls.length === 1) {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 401 });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "sessionExpired", "an HTTP 401 on the ask POST is reported as sessionExpired");
    check(calls.length === 2 && calls[1].init?.method === "POST", "the POST 401 follows exactly one CSRF request");
  }

  // --- 12. a non-2xx response never exposes server detail ----------------
  {
    const secretDetail = "secret database topology and operator token";
    let call = 0;
    const fakeFetch: typeof fetch = async () => {
      call += 1;
      if (call === 1) {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ detail: secretDetail }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(JSON.stringify(outcome) === '{"kind":"error"}', "a non-2xx ask response becomes only the generic error outcome");
    check(!JSON.stringify(outcome).includes(secretDetail), "a non-2xx ask response exposes none of the server detail");
  }

  // --- 13. governedAsk rejects a mismatched envelope connection ----------
  // The answer is only ever the connection the user is looking at: a result
  // for a different connection is a content-free error, not a result.
  {
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL) => {
      if (String(input) === "/api/v1/session/csrf") {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ connection_id: "connection-9", result: askResultFixture() }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "error", "a response envelope for a different connection_id is an error");
  }

  // --- 14. governedAsk rejects a mismatched result connection ------------
  {
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL) => {
      if (String(input) === "/api/v1/session/csrf") {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({
        connection_id: "connection-2",
        result: askResultFixture("connection-9"),
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "error", "a result that names a different connection_id is an error");
  }

  // --- 15. governedAsk rejects a malformed partial result ----------------
  {
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL) => {
      if (String(input) === "/api/v1/session/csrf") {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({
        connection_id: "connection-2",
        result: { connection_id: "connection-2", attempt_id: "partial-attempt" },
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "error", "a partial ask result that omits receipt and row fields is an error");
  }

  // --- 16. governedAsk rejects result fields outside the allow-list ------
  {
    const secretExtra = "TOP_SECRET";
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL) => {
      if (String(input) === "/api/v1/session/csrf") {
        return new Response(JSON.stringify({ csrf_token: ASK_CSRF_TOKEN }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({
        connection_id: "connection-2",
        result: { ...askResultFixture(), secret_extra: secretExtra },
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "error", "an otherwise valid ask result with an unapproved field is an error");
    check(!JSON.stringify(outcome).includes(secretExtra), "an unapproved result field never reaches the serialized outcome");
  }

  // --- 17. malformed CSRF tokens fail before the ask POST ----------------
  for (const csrfToken of [17, ""] as const) {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fakeFetch: typeof fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      return new Response(JSON.stringify({ csrf_token: csrfToken }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const outcome = await governedAsk(
      fakeFetch, "workspace-7", { connection_id: "connection-2" }, "What is the latest ledger amount?");
    check(outcome.kind === "error", `a ${typeof csrfToken === "number" ? "numeric" : "blank"} CSRF token is an error`);
    check(calls.length === 1, "a malformed CSRF token makes exactly one request");
    check(calls.every((call) => (call.init?.method ?? "GET") !== "POST"), "a malformed CSRF token makes no POST");
  }

  // --- 18. governed ask result projection (pure render) ------------------
  // The real component is rendered from a fixture whose question, answer,
  // cell and SQL all contain HTML-looking text. Every server string must
  // reach the DOM as escaped text: no <img> or <script> element may appear.
  {
    const ASK_QUESTION = 'Latest <img src=x onerror=alert(1)> amount?';
    const ASK_ANSWER = 'Answer <script>alert(2)</script> stays text <img src=x onerror=alert(3)>.';
    const ASK_SQL = "SELECT '<img src=x onerror=alert(4)>', '<script>alert(5)</script>' FROM ledger";
    const ASK_CELL = '<script>alert(6)</script>';
    const ASK_IDENTITY = 'db-identity-<img src=x onerror=alert(7)>';
    const ASK_CONNECTION = "connection-<script>alert(8)</script>";

    const askResult: GovernedAskResult = {
      attempt_id: "attempt-ask-4",
      sql: ASK_SQL,
      sql_hash: "hmac-sha256:k7:" + "d".repeat(64),
      columns: ["second", "first"],
      rows: [[PRECISE_DECIMAL, null], [ASK_CELL, ""]],
      row_count: 2,
      cost_estimate: 4.5,
      answer: ASK_ANSWER,
      connection_id: ASK_CONNECTION,
      database_identity: ASK_IDENTITY,
      exposed_schema_revision: 12,
      result_format: "json_rows",
      result_digest: "hmac-sha256:k8:" + "e".repeat(64),
      execution_started_at: STARTED_AT,
      execution_completed_at: COMPLETED_AT,
    };

    const askMarkup = renderToStaticMarkup(
      createElement(GovernedAskResultView, { result: askResult, submittedQuestion: ASK_QUESTION }));

    // Escaping: HTML-looking server text is inert, and no element is created.
    check(!askMarkup.includes("<img"), "no literal <img element is created from server text");
    check(!askMarkup.includes("<script"), "no literal <script element is created from server text");
    check(!askMarkup.includes("<pre><script"), "the SQL <pre> carries no injected script element");

    // Headings and the primary content.
    check(askMarkup.includes("Database answer"), "the answer heading is present");
    check(askMarkup.includes("Latest &lt;img src=x onerror=alert(1)&gt; amount?"),
      "the submitted question is present, escaped as text");
    check(askMarkup.includes("Answer &lt;script&gt;alert(2)&lt;/script&gt; stays text"),
      "the answer is present as escaped text");

    // Source identity and read window, verbatim.
    check(askMarkup.includes("db-identity-&lt;img src=x onerror=alert(7)&gt;"),
      "the escaped database identity is disclosed");
    check(askMarkup.includes("connection-&lt;script&gt;alert(8)&lt;/script&gt;"),
      "the escaped connection id is disclosed");
    check(askMarkup.includes(STARTED_AT) && askMarkup.includes(COMPLETED_AT),
      "both read-window timestamps are shown verbatim");

    // Table: server column and row order, precise decimal, NULL and empty.
    const askHeaderSecond = askMarkup.indexOf(">second<");
    const askHeaderFirst = askMarkup.indexOf(">first<");
    check(askHeaderSecond !== -1 && askHeaderFirst !== -1 && askHeaderSecond < askHeaderFirst,
      "the ask header keeps the server column order");
    const askDecimal = askMarkup.indexOf(PRECISE_DECIMAL);
    const askNull = askMarkup.indexOf(GOVERNED_NULL_CELL);
    const askCell = askMarkup.indexOf("&lt;script&gt;alert(6)&lt;/script&gt;");
    // An empty string cell renders as the two-quote marker, with each quote
    // escaped by React.
    const askEmpty = askMarkup.indexOf("&quot;&quot;");
    check(askDecimal !== -1 && askDecimal < askNull && askNull < askCell && askCell < askEmpty,
      "the ask rows keep the server row order with a precise decimal, NULL and an empty string");
    check(!askMarkup.includes('>"' + PRECISE_DECIMAL + '"<'), "the precise decimal is not re-quoted");

    // Reported row count.
    check(askMarkup.includes(`Rows: ${askResult.row_count}`), "the reported row count is shown");

    // The full receipt, in order, inside the collapsed Technical details.
    check(askMarkup.includes("<details"), "the technical details are collapsed");
    check(askMarkup.includes("<summary>Technical details</summary>"), "the summary is Technical details");
    let previous = -1;
    for (const entry of governedAskReceiptRows(askResult)) {
      const labelAt = askMarkup.indexOf(`<dt>${entry.label}</dt>`);
      const valueAt = askMarkup.indexOf(`<dd>${entry.value}</dd>`);
      check(labelAt !== -1 && valueAt !== -1 && labelAt > previous,
        `the receipt carries ${entry.label} in order`);
      previous = labelAt;
    }
    check(askMarkup.includes(askResult.sql_hash) && askMarkup.includes(askResult.result_digest)
      && askMarkup.includes(askResult.attempt_id) && askMarkup.includes(askResult.result_format)
      && askMarkup.includes(String(askResult.exposed_schema_revision)),
      "the receipt values are present verbatim");

    // The exact SQL, inert, inside <pre>, with no dangerouslySetInnerHTML.
    check(askMarkup.includes("<pre class=\"governed-ask-sql\">"), "the exact SQL sits in a <pre>");
    check(askMarkup.includes("SELECT &#x27;&lt;img src=x onerror=alert(4)&gt;&#x27;"),
      "the exact SQL is present as escaped text");

    // Empty rowset is stated.
    const askEmptyMarkup = renderToStaticMarkup(createElement(GovernedAskResultView, {
      result: { ...askResult, rows: [], row_count: 0 },
      submittedQuestion: ASK_QUESTION,
    }));
    check(askEmptyMarkup.includes(GOVERNED_NO_ROWS), "an empty ask rowset is stated, not left blank");
  }

  if (failures !== 0) throw new Error(`${failures} governed-preset assertion(s) failed`);
  console.log("governed preset UI probe: PASS");
}

void main();
