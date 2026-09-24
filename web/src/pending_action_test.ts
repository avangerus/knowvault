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

// R1: the request (what was asked) and detail (what came back) are shown per
// step, incrementally — the current in-flight step shows its request as soon
// as the server sends it, and each completed step shows its own outcome text.
const live: PendingActionState = {
  current: "searching",
  currentRequest: "termination clause",
  completed: [
    { kind: "searching", request: "renewal notice period", outcome: "succeeded", detail: "3 hits: Renewal is automatic unless notice is given.", durationMS: 420 },
    { kind: "reading", request: "frag_812", outcome: "failed", detail: "Access denied" },
  ],
};
const liveMarkup = renderToStaticMarkup(createElement(PendingAction, { state: live, elapsedSeconds: 2 }));
check(liveMarkup.includes("Searching sources: termination clause"), "the in-flight step shows its own request as soon as it is known");
check(liveMarkup.includes("Searching sources: renewal notice period · done — 3 hits: Renewal is automatic unless notice is given. · 0.4s"),
  "a completed step shows its own request and outcome detail together");
check(liveMarkup.includes("Reading evidence: frag_812 · failed — Access denied"), "a failed step shows a short, safe failure detail");

// R2: any server-supplied text is rendered as literal text, never HTML.
const hostile: PendingActionState = {
  current: "working",
  currentRequest: "<img src=x onerror=alert(1)>",
  completed: [{ kind: "searching", request: "<script>steal()</script>", outcome: "succeeded", detail: "<b>bold</b>" }],
};
const hostileMarkup = renderToStaticMarkup(createElement(PendingAction, { state: hostile, elapsedSeconds: 0 }));
check(!hostileMarkup.includes("<img") && !hostileMarkup.includes("<script") && !hostileMarkup.includes("<b>"),
  "action text is never rendered as HTML");
check(hostileMarkup.includes("&lt;img") || hostileMarkup.includes("&lt;script"), "hostile action text is escaped, not dropped");

console.log("pending action presentation: ok");
