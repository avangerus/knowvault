// R1.S10.s1.T4 probe: the answer-feedback mark's pure request path/label
// helpers, plus the component's own no-flash-before-load contract.
//
// The repository's plain esbuild + node test pipeline runs server-side
// renderToStaticMarkup, which never executes effects (no jsdom, no act()), so
// AnswerFeedback's data-loading GET never resolves during this render. That
// is exactly the property under test: before the caller's own current mark
// is known, the surface must render nothing rather than flash the unmarked
// "Верно"/"Неверно" controls and then replace them once the mark loads.
//
// Plain TypeScript module run by the repository's pinned esbuild + node
// toolchain (no test framework, no jsdom), matching tool_call_summary_test.ts
// and source_sql_trace_test.ts.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AnswerFeedback, feedbackStatusLabel, questionFeedbackPath, type QuestionFeedbackState } from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

check(
  questionFeedbackPath("ws 1", "qrun/1") === "/api/v1/workspaces/ws%201/questions/qrun%2F1:feedback",
  "the feedback path percent-encodes both the workspace and question run id",
);

check(feedbackStatusLabel({ marked: false }) === "", "an unmarked state has no status label");
check(
  feedbackStatusLabel({ marked: true, verdict: "CORRECT" }) === "Отмечено: верно.",
  "a CORRECT mark without a comment reads exactly \"Отмечено: верно.\"",
);
check(
  feedbackStatusLabel({ marked: true, verdict: "INCORRECT", has_comment: true }) === "Отмечено: неверно (с комментарием).",
  "an INCORRECT mark with a comment names both the verdict and the comment",
);
check(
  feedbackStatusLabel({ marked: true, verdict: "INCORRECT", has_comment: false }) === "Отмечено: неверно.",
  "an INCORRECT mark without a comment omits the comment parenthetical",
);

// AnswerFeedback fetches its own state; server-side rendering never resolves
// that promise, so the very first render must be empty, not the unmarked
// button pair (which would otherwise flash before the real mark is known).
const originalFetch = (globalThis as { fetch?: unknown }).fetch;
(globalThis as { fetch?: unknown }).fetch = () => new Promise<never>(() => {});
try {
  const markup = renderToStaticMarkup(
    createElement(AnswerFeedback, { questionRunID: "qrun-1", workspaceID: "ws-1" }),
  );
  check(markup === "", "AnswerFeedback renders nothing before its own current mark has loaded");
} finally {
  (globalThis as { fetch?: unknown }).fetch = originalFetch;
}

const markedState: QuestionFeedbackState = { marked: true, verdict: "INCORRECT", has_comment: true, updated_at: "2026-09-26T10:00:00Z" };
check(markedState.verdict === "INCORRECT", "fixture sanity: the marked fixture is INCORRECT with a comment");

if (failures !== 0) throw new Error(`${failures} answer-feedback assertion(s) failed`);
console.log("answer feedback probe: PASS");
