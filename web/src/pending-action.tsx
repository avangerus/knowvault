export type PendingActionKind = "working" | "searching" | "reading" | "checking_data" | "comparing" | "answering";

export type PendingActionState = {
  current: PendingActionKind;
  completed: readonly PendingActionKind[];
};

const actionLabels: Record<PendingActionKind, string> = {
  working: "Working on your question",
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
        <details className="pending-action-history">
          <summary>{state.completed.length} completed {state.completed.length === 1 ? "action" : "actions"}</summary>
          <ol>{state.completed.map((action, index) => <li key={`${action}-${index}`}>{actionLabels[action]}</li>)}</ol>
        </details>
      )}
    </div>
  );
}
