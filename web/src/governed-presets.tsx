// D3B — Live database checks: a thin browser client over the existing
// POST /api/v1/mcp transport.
//
// The Search screen may show the administrator-approved live SQL presets for
// the current workspace, let the authorized user select exactly one and run it
// explicitly, and then show the live table with its execution receipt. There is
// deliberately no SQL field, no parameter input, no credential and no model
// call: the server-owned catalogue is the only source of a runnable identity,
// and this file never invents one.
//
// Everything here is a projection. The wire types below mirror the server's
// governedask.PresetCatalog / PresetRunResult and governedquery.PresetSummary
// allow-lists exactly (internal/governedask/preset.go). A value read from the
// server is rendered verbatim — never rounded, sorted, reordered, shortened or
// coerced — and a failure is a content-free generic UI state, because server
// error messages are not an operator surface.

import { useCallback, useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------------------
// Wire types: exactly the server's disclosed fields.
// ---------------------------------------------------------------------------

/** governedquery.PresetSummary — the SQL-free discovery projection. */
export type GovernedPresetSummary = {
  id: string;
  version: string;
  name: string;
  description: string;
  phrases: string[];
  preset_hash: string;
  source_attempt_id: string;
  sql_hash: string;
  exposed_schema_revision: number;
};

/** governedask.PresetCatalog — the catalogue disclosed for one workspace. */
export type GovernedPresetCatalog = {
  connection_id: string;
  database_identity: string;
  presets: GovernedPresetSummary[];
};

// Rows keep the server's exact JSON shape: one nullable string per cell, so a
// SQL NULL stays distinguishable from an empty string and a precise decimal
// never passes through a JavaScript number.
export type GovernedCell = string | null;
export type GovernedRow = GovernedCell[];
export type GovernedRows = GovernedRow[];

/** governedask.PresetRunResult — one live observation plus its receipt. */
export type GovernedPresetRunResult = {
  attempt_id: string;
  preset: GovernedPresetSummary;
  sql_hash: string;
  columns: string[];
  rows: GovernedRows;
  row_count: number;
  cost_estimate: number;
  connection_id: string;
  database_identity: string;
  exposed_schema_revision: number;
  result_format: string;
  result_digest: string;
  execution_started_at: string;
  execution_completed_at: string;
  data_state: string;
};

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/** The canonical governed preset tool names. The server advertises exactly
 * these two (and withdraws both when no preset is mounted). */
export const GOVERNED_QUERIES_LIST_TOOL = "knowvault_queries_list";
export const GOVERNED_QUERY_RUN_TOOL = "knowvault_query_run";

/** The only data-state value a live preset run can carry. */
export const GOVERNED_LIVE_DATA_STATE = "LIVE_OBSERVATION";

/** Generic, content-free copy. Server messages are never shown. */
export const GOVERNED_PRESETS_UNAVAILABLE = "Live database checks unavailable.";
export const GOVERNED_PRESETS_EMPTY = "No live database checks configured.";
export const GOVERNED_PRESETS_LOADING = "Loading live database checks…";
export const GOVERNED_RESULT_UNKNOWN_PRESET = "Select a live database check before running it.";
export const GOVERNED_RESULT_RUN_UNAVAILABLE = "Live database check could not be run.";
export const GOVERNED_RESULT_HISTORICAL = "Not a live observation.";
export const GOVERNED_NO_ROWS = "No rows returned.";
export const GOVERNED_NULL_CELL = "NULL";
export const GOVERNED_EMPTY_CELL = '""';
export const GOVERNED_RECEIPT_NOTE = "Live data; no saved evidence page.";

export type GovernedFetch = typeof fetch;

/** Outcome of one JSON-RPC tools/call. `sessionExpired` is the transport's
 * answer to HTTP 401; `absent` means the server does not advertise the tool
 * (no preset is mounted), which is a normal configuration, not a failure. */
export type GovernedCallOutcome<T> =
  | { kind: "ok"; value: T }
  | { kind: "sessionExpired" }
  | { kind: "absent" }
  | { kind: "error" };

/** The minimal CSRF/tools-call transport: GET /api/v1/session/csrf, then POST
 * /api/v1/mcp with Accept, Content-Type and X-KnowVault-CSRF and deliberately
 * no Idempotency-Key (the endpoint rejects it). */
export async function governedMCPCall<T>(
  fetchImpl: GovernedFetch,
  tool: string,
  args: Record<string, unknown>,
): Promise<GovernedCallOutcome<T>> {
  let csrf: Response;
  try {
    csrf = await fetchImpl("/api/v1/session/csrf", { cache: "no-store", headers: { Accept: "application/json" } });
  } catch {
    return { kind: "error" };
  }
  if (csrf.status === 401) return { kind: "sessionExpired" };
  if (!csrf.ok) return { kind: "error" };
  let token = "";
  try {
    token = ((await csrf.json()) as { csrf_token?: string }).csrf_token ?? "";
  } catch {
    return { kind: "error" };
  }
  if (!token) return { kind: "error" };

  let response: Response;
  try {
    response = await fetchImpl("/api/v1/mcp", {
      method: "POST",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-KnowVault-CSRF": token,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: tool, method: "tools/call", params: { name: tool, arguments: args } }),
    });
  } catch {
    return { kind: "error" };
  }
  if (response.status === 401) return { kind: "sessionExpired" };
  // A JSON-RPC failure is reported with HTTP 200, so the body is inspected
  // regardless of the HTTP status.
  let envelope: { result?: unknown; error?: { code?: number } };
  try {
    envelope = (await response.json()) as typeof envelope;
  } catch {
    return { kind: "error" };
  }
  if (envelope.error !== undefined) {
    // The server hides an unmounted tool behind the same "method not found" it
    // uses for an unknown name, so this is the absent-catalogue signal.
    return envelope.error.code === -32601 ? { kind: "absent" } : { kind: "error" };
  }
  if (!response.ok) return { kind: "error" };
  const result = envelope.result as { isError?: unknown; structuredContent?: unknown } | undefined;
  if (!result || typeof result !== "object") return { kind: "error" };
  if (result.isError === true) return { kind: "error" };
  // The catalogue and its rows are read from the structured payload only. The
  // mirrored content[].text channel is deliberately never accepted: a success
  // requires structuredContent, so no text channel can substitute for it.
  const structured = result.structuredContent;
  if (!structured || typeof structured !== "object") return { kind: "error" };
  return { kind: "ok", value: structured as T };
}

/** The exact tools/call arguments for the catalogue: workspace only. No
 * connection is named here, so no catalogue value can influence the request. */
export function governedPresetListArguments(workspaceID: string): Record<string, unknown> {
  return { workspace_id: workspaceID };
}

/** The exact tools/call arguments for one run: the workspace, the connection
 * id taken from the catalogue the user is currently looking at, and the chosen
 * preset id. There is no SQL, no parameter and no free-text member. */
export function governedPresetRunArguments(
  workspaceID: string,
  catalog: { readonly connection_id: string },
  presetID: string,
): Record<string, unknown> {
  return { workspace_id: workspaceID, connection_id: catalog.connection_id, preset_id: presetID };
}

// ---------------------------------------------------------------------------
// Pure projection helpers.
// ---------------------------------------------------------------------------

/** One cell exactly as it arrived. An explicit NULL and an empty string stay
 * visibly distinct; nothing is trimmed, padded or reformatted. */
export function governedCellText(cell: GovernedCell): string {
  if (cell === null) return GOVERNED_NULL_CELL;
  return cell === "" ? GOVERNED_EMPTY_CELL : cell;
}

/** The row count the server reported, never a recount of the rendered rows. */
export function governedRowCountText(result: { readonly row_count: number }): string {
  return `Rows: ${String(result.row_count)}`;
}

/** A server timestamp is shown verbatim. An absent or unparsable value is
 * shown as itself rather than silently replaced with a plausible time. */
export function governedTimestampText(value: string): string {
  return typeof value === "string" ? value : String(value);
}

/** True only for the live observation state the run tool reports. Anything
 * else is a non-live result and is labelled as such instead of being shown as
 * a fresh observation. */
export function governedIsLiveObservation(result: { readonly data_state: string }): boolean {
  return result.data_state === GOVERNED_LIVE_DATA_STATE;
}

/** Receipt fields, in display order. Every value is verbatim; no field is
 * synthesized and none is omitted. */
export function governedReceiptRows(result: GovernedPresetRunResult): { label: string; value: string }[] {
  return [
    { label: "attempt_id", value: result.attempt_id },
    { label: "preset id", value: result.preset.id },
    { label: "preset version", value: result.preset.version },
    { label: "preset hash", value: result.preset.preset_hash },
    { label: "sql_hash", value: result.sql_hash },
    { label: "result_digest", value: result.result_digest },
    { label: "exposed_schema_revision", value: String(result.exposed_schema_revision) },
    { label: "result_format", value: result.result_format },
    { label: "Read window start", value: governedTimestampText(result.execution_started_at) },
    { label: "Read window end", value: governedTimestampText(result.execution_completed_at) },
  ];
}

/** True only when the continuation that produced a result still belongs to
 * the current epoch and the panel is still mounted. A stale continuation (an
 * earlier workspace load or a superseded preset selection) returns false and
 * its result is discarded. */
export function governedRequestAccepted(stamp: number, current: number, alive: boolean): boolean {
  return alive && stamp === current;
}

// ---------------------------------------------------------------------------
// Panel.
// ---------------------------------------------------------------------------

type CatalogState =
  | { phase: "loading" }
  | { phase: "unavailable" }
  | { phase: "empty" }
  | { phase: "ready"; catalog: GovernedPresetCatalog };

type RunState =
  | { phase: "idle" }
  | { phase: "pending" }
  | { phase: "failed" }
  | { phase: "done"; result: GovernedPresetRunResult };

export type GovernedPresetPanelProps = {
  /** The workspace whose catalogue is shown. The panel is keyed by it: a
   * workspace change remounts and discards everything below. */
  workspaceID: string;
  /** Called on HTTP 401 so the shell can expire the session. The panel never
   * shows its own signed-out copy. */
  onSessionExpired: () => void;
};

/** The live-database-checks section of the Search screen. It loads the
 * catalogue on mount only; running a preset is always an explicit click. */
export function GovernedPresetPanel({ workspaceID, onSessionExpired }: GovernedPresetPanelProps) {
  const [catalogState, setCatalogState] = useState<CatalogState>({ phase: "loading" });
  const [presetID, setPresetID] = useState("");
  const [runState, setRunState] = useState<RunState>({ phase: "idle" });
  // Every async continuation is stamped with the epoch that started it and
  // checks "alive" after awaiting, so a response for a previous workspace (or
  // for an unmounted panel) can never restore a catalogue or rows.
  const epoch = useRef(0);
  const alive = useRef(true);

  const loadCatalog = useCallback(async () => {
    const current = ++epoch.current;
    setCatalogState({ phase: "loading" });
    setRunState({ phase: "idle" });
    const outcome = await governedMCPCall<GovernedPresetCatalog>(
      fetch, GOVERNED_QUERIES_LIST_TOOL, governedPresetListArguments(workspaceID));
    if (!governedRequestAccepted(current, epoch.current, alive.current)) return;
    if (outcome.kind === "sessionExpired") { onSessionExpired(); return; }
    if (outcome.kind !== "ok") { setCatalogState({ phase: "unavailable" }); return; }
    const presets = outcome.value.presets ?? [];
    setPresetID("");
    setCatalogState(presets.length === 0
      ? { phase: "empty" }
      : { phase: "ready", catalog: outcome.value });
  }, [workspaceID, onSessionExpired]);

  useEffect(() => {
    // The panel only ever loads the catalogue here. No preset is run without
    // an explicit user click, and a remount (workspace or session change)
    // starts from a clean catalogue.
    alive.current = true;
    void loadCatalog();
    return () => { alive.current = false; epoch.current++; };
  }, [loadCatalog]);

  async function run(catalog: GovernedPresetCatalog) {
    if (runState.phase === "pending") return;
    const chosen = catalog.presets.find((preset) => preset.id === presetID);
    if (!chosen) { setRunState({ phase: "failed" }); return; }
    const current = ++epoch.current;
    // A new run clears the previous result before it starts, so a failure (or
    // an unauthorized response) can never leave stale rows on screen.
    setRunState({ phase: "pending" });
    const outcome = await governedMCPCall<GovernedPresetRunResult>(
      fetch, GOVERNED_QUERY_RUN_TOOL, governedPresetRunArguments(workspaceID, catalog, chosen.id));
    if (!governedRequestAccepted(current, epoch.current, alive.current)) return;
    if (outcome.kind === "sessionExpired") { onSessionExpired(); return; }
    setRunState(outcome.kind === "ok" ? { phase: "done", result: outcome.value } : { phase: "failed" });
  }

  const catalog = catalogState.phase === "ready" ? catalogState.catalog : null;
  const chosenPreset = catalog?.presets.find((preset) => preset.id === presetID) ?? null;
  const pending = runState.phase === "pending";

  return (
    <section aria-labelledby="governed-presets-heading" className="governed-presets">
      <h2 className="governed-presets-heading" id="governed-presets-heading">Live database checks</h2>
      {catalogState.phase === "loading" && <p className="governed-presets-note" role="status">{GOVERNED_PRESETS_LOADING}</p>}
      {catalogState.phase === "empty" && <p className="governed-presets-note">{GOVERNED_PRESETS_EMPTY}</p>}
      {catalogState.phase === "unavailable" && (
        <p className="governed-presets-note">
          {GOVERNED_PRESETS_UNAVAILABLE}{" "}
          <button className="text-button" onClick={() => { void loadCatalog(); }} type="button">Retry</button>
        </p>
      )}
      {catalog && (
        <div className="governed-presets-picker">
          <label className="sr-only" htmlFor="governed-preset-select">Live database check</label>
          <select className="governed-preset-select" id="governed-preset-select" value={presetID} disabled={pending}
            onChange={(event) => {
              // Selecting a different check supersedes any run in flight: the
              // epoch is bumped first, so that run's continuation is rejected
              // even if it resolves before the new preset settles.
              epoch.current++;
              // The previously rendered rows belong to the previously chosen
              // check. They are discarded before the selection changes, so a
              // result is never shown under a newly selected check.
              setRunState({ phase: "idle" });
              setPresetID(event.target.value);
            }}>
            <option value="">Select a live database check</option>
            {catalog.presets.map((preset) => (
              <option key={preset.id} value={preset.id}>
                {preset.description ? `${preset.name} — ${preset.description}` : preset.name}
              </option>
            ))}
          </select>
          <button className="secondary-button" disabled={pending || !chosenPreset}
            onClick={() => { if (catalog) void run(catalog); }} type="button">
            {pending ? "Running…" : "Run"}
          </button>
        </div>
      )}
      {runState.phase === "failed" && (
        <p className="governed-presets-note" role="status">
          {chosenPreset ? GOVERNED_RESULT_RUN_UNAVAILABLE : GOVERNED_RESULT_UNKNOWN_PRESET}
        </p>
      )}
      {runState.phase === "done" && <GovernedPresetResultView result={runState.result} />}
    </section>
  );
}

/** The live table plus its receipt. Split out so the probe can render the
 * exact production markup from a fixture without touching the network. */
export function GovernedPresetResultView({ result }: { result: GovernedPresetRunResult }) {
  const live = governedIsLiveObservation(result);
  return (
    <section aria-labelledby="governed-result-heading" className="governed-result">
      <h3 id="governed-result-heading">Live result</h3>
      <p className="governed-result-meta">
        <span className={live ? "governed-badge" : "governed-badge governed-badge-muted"}>
          {live ? GOVERNED_LIVE_DATA_STATE : GOVERNED_RESULT_HISTORICAL}
        </span>
        <span className="governed-result-source">
          database_identity {result.database_identity} · connection_id {result.connection_id}
        </span>
      </p>
      <p className="governed-result-window">
        Read window {governedTimestampText(result.execution_started_at)} – {governedTimestampText(result.execution_completed_at)}
      </p>
      <div className="governed-result-table-wrap">
        <table className="governed-result-table">
          <thead>
            <tr>{result.columns.map((column) => <th key={column} scope="col">{column}</th>)}</tr>
          </thead>
          <tbody>
            {result.rows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {row.map((cell, cellIndex) => (
                  <td key={cellIndex}>{cell === null
                    ? <span className="governed-null">{GOVERNED_NULL_CELL}</span>
                    : governedCellText(cell)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="governed-result-count">{governedRowCountText(result)}</p>
      {result.rows.length === 0 && <p className="governed-presets-note">{GOVERNED_NO_ROWS}</p>}
      <details className="governed-receipt">
        <summary>Receipt</summary>
        <dl>
          {governedReceiptRows(result).map((entry) => (
            <div className="governed-receipt-row" key={entry.label}>
              <dt>{entry.label}</dt>
              <dd>{entry.value}</dd>
            </div>
          ))}
        </dl>
        <p className="governed-presets-note">{GOVERNED_RECEIPT_NOTE}</p>
      </details>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Governed ask transport (no UI yet).
// ---------------------------------------------------------------------------

/** governedask.AskResult — one ad hoc governed answer plus its receipt, the
 * exact server allow-list. Rows reuse the preset row shape: one nullable
 * string per cell, so NULL stays distinct from "". */
export type GovernedAskResult = {
  attempt_id: string;
  sql: string;
  sql_hash: string;
  columns: string[];
  rows: GovernedRows;
  row_count: number;
  cost_estimate: number;
  answer: string;
  connection_id: string;
  database_identity: string;
  exposed_schema_revision: number;
  result_format: string;
  result_digest: string;
  execution_started_at: string;
  execution_completed_at: string;
};

/** One idempotency key: 32 crypto-random bytes, base64url, no padding.
 * Identical to main.tsx's newIdempotencyKey so both transports agree. */
export function newGovernedIdempotencyKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  bytes.forEach((value) => { binary += String.fromCharCode(value); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The ask csrf_token is accepted only as a nonempty string: a missing, empty
 * or non-string token is a failure, never a header value. */
function governedCsrfToken(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** The exact key allow-list of governedask.AskResult (service.go: attempt_id
 * through execution_completed_at — the same 15 exposed fields the mirror type
 * declares), in server order. A result is accepted only when Object.keys names
 * exactly these and nothing else. */
const GOVERNED_ASK_RESULT_KEYS = [
  "attempt_id",
  "sql",
  "sql_hash",
  "columns",
  "rows",
  "row_count",
  "cost_estimate",
  "answer",
  "connection_id",
  "database_identity",
  "exposed_schema_revision",
  "result_format",
  "result_digest",
  "execution_started_at",
  "execution_completed_at",
] as const;

/** Structural check for one AskResult. It is deliberately strict: an array, a
 * partial or a malformed object is rejected rather than coerced into a row.
 * Every string field must be a string, every numeric field a finite number,
 * columns a string[] and rows an array of arrays whose cells are string|null.
 * The result's own connection_id must equal the catalog's, so no answer can
 * describe a connection the user is not looking at. Only a value that passes
 * this guard is ever returned as `ok`. */
function isGovernedAskResult(
  value: unknown,
  catalogConnectionID: string,
): value is GovernedAskResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;

  // The result carries exactly the server's allow-listed keys: a different
  // key count, or any name outside this set (e.g. a smuggled `secret_extra`),
  // is rejected before any field is read, so an undeclared member can never be
  // returned as part of an `ok` value.
  const keys = Object.keys(r);
  if (keys.length !== GOVERNED_ASK_RESULT_KEYS.length) return false;
  for (const key of keys) {
    if (!GOVERNED_ASK_RESULT_KEYS.includes(key as (typeof GOVERNED_ASK_RESULT_KEYS)[number])) return false;
  }

  const stringFields = [
    "attempt_id",
    "sql",
    "sql_hash",
    "answer",
    "connection_id",
    "database_identity",
    "result_format",
    "result_digest",
    "execution_started_at",
    "execution_completed_at",
  ] as const;
  for (const field of stringFields) {
    if (typeof r[field] !== "string") return false;
  }
  if (r.connection_id !== catalogConnectionID) return false;

  if (typeof r.row_count !== "number" || !Number.isFinite(r.row_count)) return false;
  if (typeof r.cost_estimate !== "number" || !Number.isFinite(r.cost_estimate)) return false;
  if (typeof r.exposed_schema_revision !== "number" || !Number.isFinite(r.exposed_schema_revision)) return false;

  if (!Array.isArray(r.columns)) return false;
  for (const column of r.columns) {
    if (typeof column !== "string") return false;
  }

  if (!Array.isArray(r.rows)) return false;
  for (const row of r.rows) {
    if (!Array.isArray(row)) return false;
    for (const cell of row) {
      if (cell !== null && typeof cell !== "string") return false;
    }
  }

  return true;
}

/** The governed ask call: GET /api/v1/session/csrf, then POST the :ask
 * endpoint with Accept, Content-Type, X-KnowVault-CSRF and Idempotency-Key
 * and deliberately no If-Match. The body is exactly { question } — no SQL,
 * no connection id, no free-text beyond the one question. The idempotency key
 * is owned here: exactly one is minted per invocation, after CSRF succeeds and
 * before the POST, so a CSRF 401 creates neither a key nor a POST. A 401 is the
 * transport's sessionExpired answer; every other network failure, non-2xx
 * status, unparsable body, invalid CSRF token, missing/malformed result,
 * mismatched envelope connection or mismatched result connection becomes a
 * content-free `error`, and server error text is never returned. */
export async function governedAsk(
  fetchImpl: GovernedFetch,
  workspaceID: string,
  catalog: { readonly connection_id: string },
  question: string,
): Promise<GovernedCallOutcome<GovernedAskResult>> {
  let csrf: Response;
  try {
    csrf = await fetchImpl("/api/v1/session/csrf", { cache: "no-store", headers: { Accept: "application/json" } });
  } catch {
    return { kind: "error" };
  }
  if (csrf.status === 401) return { kind: "sessionExpired" };
  if (!csrf.ok) return { kind: "error" };
  let token: string | null = null;
  try {
    token = governedCsrfToken(((await csrf.json()) as { csrf_token?: unknown }).csrf_token);
  } catch {
    return { kind: "error" };
  }
  if (token === null) return { kind: "error" };

  // CSRF succeeded, so the POST will carry a fresh single-use key. The key is
  // minted here — after CSRF, before the POST — so a 401 above never creates
  // one and this invocation never reuses another's.
  const idempotencyKey = newGovernedIdempotencyKey();

  let response: Response;
  try {
    response = await fetchImpl(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/governed-query-connections/${encodeURIComponent(catalog.connection_id)}:ask`,
      {
        method: "POST",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-KnowVault-CSRF": token,
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({ question }),
      },
    );
  } catch {
    return { kind: "error" };
  }
  if (response.status === 401) return { kind: "sessionExpired" };
  if (!response.ok) return { kind: "error" };
  let envelope: { connection_id?: unknown; result?: unknown };
  try {
    envelope = (await response.json()) as typeof envelope;
  } catch {
    return { kind: "error" };
  }
  // The envelope must still name the connection the user is looking at: a
  // mismatched (or absent) connection id is a failure, not a result.
  if (envelope.connection_id !== catalog.connection_id) return { kind: "error" };
  // The result itself must be structurally sound and must repeat the same
  // connection. Only then is it returned as `ok`.
  if (!isGovernedAskResult(envelope.result, catalog.connection_id)) return { kind: "error" };
  return { kind: "ok", value: envelope.result };
}
