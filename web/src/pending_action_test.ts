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

const observed: PendingActionState = { current: "comparing", completed: ["searching", "reading"] };
const history = renderToStaticMarkup(createElement(PendingAction, { state: observed, elapsedSeconds: 74.8 }));
check(history.includes("Comparing values"), "current allowlisted action is shown");
check(history.includes("74s"), "elapsed seconds round down");
check(history.includes("<details") && history.includes("2 completed actions"), "completed actions are expandable");
check(history.includes("Searching sources") && history.includes("Reading evidence"), "only supplied completed actions are shown");

console.log("pending action presentation: ok");
