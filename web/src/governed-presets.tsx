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

/** Copy for the ad hoc ask form. Content-free: a failed ask never shows the
 * server's message, only this generic sentence, and every non-401 failure
 * (transport error, non-2xx, unparsable or mismatched payload) collapses to
 * it. The pending line is a state, not progress the server reported. */
export const GOVERNED_ASK_UNAVAILABLE = "Database answer unavailable.";
export const GOVERNED_ASK_PENDING = "Asking the live database…";

/** Reserve one governed-ask submission: the single gate that makes at most one
 * `governedAsk` call per user submit. The component holds a boolean ref; the
 * first call in a synchronous burst flips it true and returns true, and any
 * same-tick second call returns false. Correctness depends on this being
 * synchronous and immediate: the flip happens in this call, before the caller
 * has a chance to await, so a double submit or a form submitted twice cannot
 * mint two POSTs. A missing ref is treated as already reserved (fail closed).
 *
 * The function is deliberately question-agnostic: the caller must submit the
 * ORIGINAL question text, never a trimmed copy. The guard inspects the
 * question only to refuse a blank one — whitespace is not a question. */
export function reserveGovernedAskSubmission(
  ref: { current: boolean } | null | undefined,
  submission: { question: string },
): boolean {
  if (!ref) return false;
  if (submission.question.trim().length === 0) return false;
  if (ref.current) return false;
  ref.current = true;
  return true;
}

/** Reserve one governed-run submission: the sibling of the ask guard, and the
 * gate that serializes a preset run against an in-flight ask (and vice versa).
 * A run is admitted only when NEITHER guard is held; it then holds the run
 * guard and refuses every later reservation until its own continuation
 * releases it. Correctness depends on this being synchronous: both refs are
 * inspected and the run ref is set before the caller can await, so an ask that
 * starts in the same tick as a run cannot slip through.
 *
 * A missing ref fails closed (a caller without a guard mints nothing), as does
 * a held ask guard. The order of the checks is deliberate: the fail-closed
 * input check, then the ask guard (already-busy), then the run guard — so a
 * refused call never consumes the reservation. */
export function reserveGovernedRunSubmission(
  runRef: { current: boolean } | null | undefined,
  askRef: { current: boolean } | null | undefined,
): boolean {
  if (!runRef || !askRef) return false;
  if (askRef.current) return false;
  if (runRef.current) return false;
  runRef.current = true;
  return true;
}

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

/** The governed-ask form's state: a result is only ever shown together with
 * the exact question text that produced it, so the two can never drift apart. */
type AskState =
  | { phase: "idle" }
  | { phase: "pending" }
  | { phase: "failed" }
  | { phase: "done"; result: GovernedAskResult; submittedQuestion: string };

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
  const [question, setQuestion] = useState("");
  const [askState, setAskState] = useState<AskState>({ phase: "idle" });
  // Every async continuation is stamped with the epoch that started it and
  // checks "alive" after awaiting, so a response for a previous workspace (or
  // for an unmounted panel) can never restore a catalogue or rows.
  const epoch = useRef(0);
  const alive = useRef(true);
  // The ask owns its own epoch: a catalogue reload, a preset run or a remount
  // must be able to supersede an in-flight ask without disturbing the run
  // epoch (and vice versa). An ask continuation is accepted only when BOTH the
  // panel is alive and its stamp still equals this ref, so a stale, unmounted
  // or workspace-switched answer is discarded rather than rendered.
  const askEpoch = useRef(0);
  // The one-submission guard (see reserveGovernedAskSubmission). It is a ref
  // so it flips synchronously, and it is released only by the continuation of
  // the request that reserved it — never by a superseded one.
  const askPendingRef = useRef(false);
  // The run guard (see reserveGovernedRunSubmission). A run holds it from the
  // synchronous reservation until its own continuation releases it, and an ask
  // reservation is refused while it is held — so no ask can start while a run
  // is in flight and no run can start while an ask is in flight.
  const runPendingRef = useRef(false);

  const loadCatalog = useCallback(async () => {
    const current = ++epoch.current;
    setCatalogState({ phase: "loading" });
    setRunState({ phase: "idle" });
    // A catalogue reload replaces the connection the form would ask, so any
    // answer still in flight belongs to a catalogue that no longer exists: its
    // epoch is bumped (its continuation is now rejected), the form is dropped
    // back to idle and the guards are released for the new catalogue. A reset
    // only ever runs from a live panel with no accepted continuation pending,
    // so clearing the refs here cannot race an in-flight release; reloading the
    // catalogue never itself sends an ask.
    askEpoch.current++;
    askPendingRef.current = false;
    runPendingRef.current = false;
    setAskState({ phase: "idle" });
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
    return () => {
      alive.current = false;
      epoch.current++;
      // Unmount invalidates every ask epoch too: no answer may resolve into a
      // component that is no longer mounted.
      askEpoch.current++;
    };
  }, [loadCatalog]);

  async function run(catalog: GovernedPresetCatalog) {
    // The synchronous reservation is the FIRST thing a run does: no work — not
    // even the "selection is missing" failure — happens before the run guard
    // is held. It is admitted only when no ask and no run is in flight (see
    // reserveGovernedRunSubmission), which is what makes a run and an ask
    // mutually exclusive.
    if (!reserveGovernedRunSubmission(runPendingRef, askPendingRef)) return;
    // The epoch this run owns is minted exactly once, immediately after the
    // synchronous reservation and before any await: it is the stamp both the
    // accepted path and the catch path compare against, so a stale rejection
    // can never release a newer run's guard or set its state.
    const current = ++epoch.current;
    try {
      const chosen = catalog.presets.find((preset) => preset.id === presetID);
      // A reservation that names no runnable preset consumes nothing: the
      // guard is released again before this early return.
      if (!chosen) { runPendingRef.current = false; setRunState({ phase: "failed" }); return; }
      // A new run clears the previous result before it starts, so a failure
      // (or an unauthorized response) can never leave stale rows on screen.
      setRunState({ phase: "pending" });
      const outcome = await governedMCPCall<GovernedPresetRunResult>(
        fetch, GOVERNED_QUERY_RUN_TOOL, governedPresetRunArguments(workspaceID, catalog, chosen.id));
      // A superseded or unmounted run (a catalogue reset, a remount, a preset
      // change) releases the guard to its new owner and touches no state.
      if (!governedRequestAccepted(current, epoch.current, alive.current)) return;
      // The current run — and only it — releases the guard, on every accepted
      // outcome including sessionExpired.
      runPendingRef.current = false;
      if (outcome.kind === "sessionExpired") { onSessionExpired(); return; }
      setRunState(outcome.kind === "ok" ? { phase: "done", result: outcome.value } : { phase: "failed" });
    } catch (failure) {
      // The reservation must never leak into the UI as a rejected promise. A
      // throw from the transport is not a run outcome, so the guard is
      // released only for the continuation that still owns it.
      if (governedRequestAccepted(current, epoch.current, alive.current)) {
        runPendingRef.current = false;
        setRunState({ phase: "failed" });
      }
    }
  }

  /** The governed-ask submit. This is the ONLY path that calls governedAsk.
   * It is reached exclusively from the form's explicit onSubmit — no effect,
   * no timer, no storage or history listener ever asks on the user's behalf.
   * The question is the ORIGINAL text from the input (never trimmed): the
   * helper trims only to decide emptiness, so what the server receives is
   * exactly what the user typed (minus nothing), and the result view repeats
   * that same string. */
  function ask(catalog: GovernedPresetCatalog) {
    // A run in flight owns the slot: an ask is refused here, before it reserves
    // anything, so the run guard is never disturbed and no ask starts while a
    // run is pending. The reverse is enforced inside reserveGovernedRunSubmission.
    if (runPendingRef.current) return;
    // The single-submission guard: a second synchronous submit (a double
    // click, an Enter plus a click) returns false here and produces no POST.
    if (!reserveGovernedAskSubmission(askPendingRef, { question })) return;
    const submittedQuestion = question;
    const current = ++askEpoch.current;
    // A new ask clears the previous answer before it leaves, so a failure can
    // never leave stale rows or a stale question on screen.
    setAskState({ phase: "pending" });
    // governedAsk resolves for every transport outcome, but it is a promise
    // and the panel must survive a rejection as well: a rejection for the
    // CURRENT alive ask releases the guard and shows the same generic failed
    // state as any other failure, while a stale or unmounted rejection changes
    // nothing (the guard already belongs to whoever superseded it).
    governedAsk(fetch, workspaceID, catalog, submittedQuestion).then((outcome) => {
      // The answer only lands when the panel is still mounted and this is
      // still the newest ask; otherwise it is discarded and the guard is left
      // to its rightful owner.
      if (!governedRequestAccepted(current, askEpoch.current, alive.current)) return;
      // This continuation is the current ask, so it — and only it — releases
      // the guard, whether it succeeded or failed.
      askPendingRef.current = false;
      if (outcome.kind === "sessionExpired") { onSessionExpired(); return; }
      setAskState(outcome.kind === "ok"
        ? { phase: "done", result: outcome.value, submittedQuestion }
        : { phase: "failed" });
    }, () => {
      // A rejected ask is a failure, not a crash: the current alive ask
      // releases its guard and shows the generic content-free state.
      if (!governedRequestAccepted(current, askEpoch.current, alive.current)) return;
      askPendingRef.current = false;
      setAskState({ phase: "failed" });
    });
  }

  const catalog = catalogState.phase === "ready" ? catalogState.catalog : null;
  const chosenPreset = catalog?.presets.find((preset) => preset.id === presetID) ?? null;
  const pending = runState.phase === "pending";
  // The ask form exists only once the server's catalogue is ready, because
  // only then is there a connection_id to ask against. It is never built from
  // client state.
  const askPending = askState.phase === "pending";
  // The ask, the run and the picker are mutually exclusive surfaces: while an
  // ask is in flight the whole picker (select and Run) is disabled, and while
  // a run is in flight the Ask control is. The Ask button is additionally
  // disabled for a blank question, which is not a question.
  const askDisabled = askPending || pending || question.trim().length === 0;
  const runDisabled = askPending;

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
        <form className="governed-ask-form" onSubmit={(event) => { event.preventDefault(); ask(catalog); }}>
          <h3 className="governed-ask-form-heading">Ask live database</h3>
          <div className="governed-ask-form-row">
            <label className="sr-only" htmlFor="governed-ask-input">Ask a question about live company data</label>
            <input
              className="governed-ask-input"
              id="governed-ask-input"
              type="text"
              placeholder="Ask a question about live company data"
              autoComplete="off"
              value={question}
              disabled={askPending}
              onChange={(event) => { setQuestion(event.target.value); }}
            />
            <button className="secondary-button" disabled={askDisabled} type="submit">
              {askPending ? "Asking…" : "Ask"}
            </button>
          </div>
          {askPending && <p className="governed-presets-note" role="status">{GOVERNED_ASK_PENDING}</p>}
          {askState.phase === "failed" && (
            <p className="governed-presets-note" role="status">{GOVERNED_ASK_UNAVAILABLE}</p>
          )}
          {askState.phase === "done" && (
            <GovernedAskResultView result={askState.result} submittedQuestion={askState.submittedQuestion} />
          )}
        </form>
      )}
      {catalog && (
        <p className="governed-presets-subheading">Reviewed checks</p>
      )}
      {catalog && (
        <div className="governed-presets-picker">
          <label className="sr-only" htmlFor="governed-preset-select">Live database check</label>
          <select className="governed-preset-select" id="governed-preset-select" value={presetID} disabled={pending || runDisabled}
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
          <button className="secondary-button" disabled={pending || runDisabled || !chosenPreset}
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
// Governed ask  -- pure result projection (no network, no state, no form yet).
// ---------------------------------------------------------------------------

/** Receipt fields of one governed ask, in display order. Exactly the server's
 * exposed receipt values, verbatim: the attempt id, the statement hash, the
 * result digest, the schema revision the answer was produced against, the
 * result format and the read window's start and end. No field is synthesized
 * and none is omitted; the SQL text itself is shown separately. */
export function governedAskReceiptRows(
  result: GovernedAskResult,
): { label: string; value: string }[] {
  return [
    { label: "attempt_id", value: result.attempt_id },
    { label: "sql_hash", value: result.sql_hash },
    { label: "result_digest", value: result.result_digest },
    { label: "exposed_schema_revision", value: String(result.exposed_schema_revision) },
    { label: "result_format", value: result.result_format },
    { label: "Read window start", value: governedTimestampText(result.execution_started_at) },
    { label: "Read window end", value: governedTimestampText(result.execution_completed_at) },
  ];
}

/** One governed answer: the question that was asked, the answer itself as the
 * primary content, the source it was read from, the exact read window, the
 * rows exactly as the server returned them, and the receipt — with the exact
 * SQL kept inert inside a collapsed <details>. Split out so the probe can
 * render the real production markup from a fixture without touching the
 * network. Every server string is rendered as React text, so HTML-looking
 * content is escaped, never parsed. */
export function GovernedAskResultView(
  { result, submittedQuestion }: { result: GovernedAskResult; submittedQuestion: string },
) {
  return (
    <section aria-labelledby="governed-ask-heading" className="governed-ask">
      <h3 id="governed-ask-heading">Database answer</h3>
      <p className="governed-ask-question">Question: {submittedQuestion}</p>
      <p className="governed-ask-answer">{result.answer}</p>
      <p className="governed-ask-source">
        database_identity <span className="governed-ask-source-database">{result.database_identity}</span>
        {" · "}
        connection_id <span className="governed-ask-source-connection">{result.connection_id}</span>
      </p>
      <p className="governed-ask-window">
        Read window {governedTimestampText(result.execution_started_at)} – {governedTimestampText(result.execution_completed_at)}
      </p>
      <div className="governed-ask-table-wrap">
        <table className="governed-ask-table">
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
      <p className="governed-ask-count">{governedRowCountText(result)}</p>
      {result.rows.length === 0 && <p className="governed-presets-note">{GOVERNED_NO_ROWS}</p>}
      <details className="governed-ask-technical">
        <summary>Technical details</summary>
        <dl>
          {governedAskReceiptRows(result).map((entry) => (
            <div className="governed-ask-receipt-row" key={entry.label}>
              <dt>{entry.label}</dt>
              <dd>{entry.value}</dd>
            </div>
          ))}
        </dl>
        <pre className="governed-ask-sql">{result.sql}</pre>
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
  // one and this invocation never reuses another's. The key mint and the
  // encoded :ask path are built inside this try so that a crypto or encoding
  // failure becomes a content-free `error` rather than a rejected promise: the
  // only outcome this function ever produces is a GovernedCallOutcome.
  let response: Response;
  try {
    const idempotencyKey = newGovernedIdempotencyKey();
    const askPath = `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/governed-query-connections/${encodeURIComponent(catalog.connection_id)}:ask`;
    response = await fetchImpl(
      askPath,
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
