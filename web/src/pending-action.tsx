export type PendingActionKind = "working" | "model" | "searching" | "reading" | "checking_data" | "comparing" | "answering";

export type PendingActionStep = {
  kind: PendingActionKind;
  /** A short, safe description of what was asked, e.g. the search query text. Absent when the server sent none. */
  request?: string;
  outcome: "succeeded" | "failed";
  /** A short, safe outcome summary, e.g. a hit count or "Read 512 characters". Absent when the server sent none. */
  detail?: string;
  durationMS?: number;
};

export type PendingActionState = {
  current: PendingActionKind;
  /** The request text of the step currently in flight, when the server has sent one. */
  currentRequest?: string;
  completed: readonly PendingActionStep[];
};

const actionLabels: Record<PendingActionKind, string> = {
  working: "Working on your question",
  model: "Model is working",
  searching: "Searching sources",
  reading: "Reading evidence",
  checking_data: "Checking live data",
  comparing: "Comparing values",
  answering: "Preparing answer",
};

/** Presentation only: callers supply observed actions; this component never invents steps or content. */
export function PendingAction({ state, elapsedSeconds }: { state: PendingActionState; elapsedSeconds: number }) {
  const elapsed = Math.max(0, Math.floor(elapsedSeconds));
  return (
    <div className="pending-action">
      <div className="pending-action-line">
        <span className="pending-action-label" role="status">
          <span aria-hidden="true" className="search-answer-spinner" />
          <span className="pending-action-text" title={`${actionLabels[state.current]}${state.currentRequest ? `: ${state.currentRequest}` : ""}`}>
            {actionLabels[state.current]}{state.currentRequest ? `: ${state.currentRequest}` : ""}
          </span>
        </span>
        <span aria-label={`Elapsed ${elapsed} seconds`} className="pending-action-elapsed" role="timer">{elapsed}s</span>
      </div>
      {state.completed.length > 0 && (
        <ol className="pending-action-history" aria-label="Completed actions">
          {state.completed.map((action, index) => {
            const line = `${actionLabels[action.kind]}${action.request ? `: ${action.request}` : ""} · ${action.outcome === "failed" ? "failed" : "done"}${action.detail ? ` — ${action.detail}` : ""}${action.durationMS !== undefined ? ` · ${(action.durationMS / 1000).toFixed(1)}s` : ""}`;
            return (
              <li key={`${action.kind}-${index}`} title={line}>
                {line}
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
