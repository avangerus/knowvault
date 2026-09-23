export type PendingActionKind = "working" | "model" | "searching" | "reading" | "checking_data" | "comparing" | "answering";

export type PendingActionState = {
  current: PendingActionKind;
  completed: readonly { kind: PendingActionKind; outcome: "succeeded" | "failed"; durationMS?: number }[];
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

/** Presentation only: callers supply observed actions; this component never invents steps. */
export function PendingAction({ state, elapsedSeconds }: { state: PendingActionState; elapsedSeconds: number }) {
  const elapsed = Math.max(0, Math.floor(elapsedSeconds));
  return (
    <div className="pending-action">
      <div className="pending-action-line">
        <span className="pending-action-label" role="status"><span aria-hidden="true" className="search-answer-spinner" />{actionLabels[state.current]}</span>
        <span aria-label={`Elapsed ${elapsed} seconds`} className="pending-action-elapsed" role="timer">{elapsed}s</span>
      </div>
      {state.completed.length > 0 && (
        <ol className="pending-action-history" aria-label="Completed actions">
          {state.completed.map((action, index) => (
            <li key={`${action.kind}-${index}`}>
              {actionLabels[action.kind]} · {action.outcome === "failed" ? "failed" : "done"}
              {action.durationMS !== undefined ? ` · ${(action.durationMS / 1000).toFixed(1)}s` : ""}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
