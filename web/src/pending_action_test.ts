import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { PendingAction, type PendingActionState } from "./pending-action";

function check(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

const waiting: PendingActionState = { current: "working", completed: [] };
const initial = renderToStaticMarkup(createElement(PendingAction, { state: waiting, elapsedSeconds: 0 }));
check(initial.includes("Working on your question"), "initial action is explicit and generic");
check(initial.includes("role=\"status\""), "current action is an accessible status");
check(initial.includes("role=\"timer\""), "elapsed time is accessible without repeated status announcements");
check(initial.includes("0s"), "elapsed seconds are visible");
check(!initial.includes("<details"), "unobserved tool actions are not invented");

const observed: PendingActionState = { current: "model", completed: [
  { kind: "searching", outcome: "succeeded", durationMS: 1230 }, { kind: "reading", outcome: "failed" },
] };
const history = renderToStaticMarkup(createElement(PendingAction, { state: observed, elapsedSeconds: 74.8 }));
check(history.includes("Model is working") && !history.includes("Preparing answer"), "ordinary model activity is not labelled as finalization");
check(history.includes("74s"), "elapsed seconds round down");
check(history.includes('<ol class="pending-action-history"') && !history.includes("<details"), "observed actions are visible without opening a disclosure");
check(history.includes("Searching sources · done · 1.2s") && history.includes("Reading evidence · failed"), "outcome and elapsed time remain visible");

console.log("pending action presentation: ok");
