// 000121 — a question whose answering process died is finished by the server
// as INTERRUPTED. This probe renders the real conversation turn component with
// such a run and asserts the user-visible terminal state: explicit
// "interrupted", an explicit "ask again" hint, and no partial answer presented
// as if it were complete. Like every other web probe it runs on the pinned
// esbuild + node toolchain with no test framework.
//
//   1. the interrupted turn is rendered through the production TurnCard;
//   2. it names the interruption and invites a retry;
//   3. it must not reuse the "not enough evidence" copy or render an answer.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { TurnCard } from "./main";

function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

type TurnCardProps = Parameters<typeof TurnCard>[0];

const interruptedRun = {
  question_run_id: "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  workspace_id: "ws_operations",
  workspace_revision: 7,
  question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?",
  answer_mode: "EXTRACTIVE",
  verification_method: "BYTE_EXACT_CITATION",
  grounding_status: "UNCONFIRMED",
  status: "INTERRUPTED",
  corpus_status: "COMPLETE",
  freshness: { state: "UNKNOWN" },
  started_at: "2026-09-25T00:00:00.000Z",
  completed_at: "2026-09-25T00:00:05.000Z",
  failure_code: "QUESTION_INTERRUPTED",
  manifest_status: "NOT_PUBLISHED",
  citations: [],
  uncertainties: [],
  conflicts: [],
};

const turn = {
  turn_id: "turn_01ARZ3NDEKTSV4RRFFQ69G5FAW",
  question_run_id: interruptedRun.question_run_id,
  turn_index: 2,
  created_at: "2026-09-25T00:00:05.000Z",
  question_run: interruptedRun,
} as unknown as TurnCardProps["turn"];

const markup = renderToStaticMarkup(createElement(TurnCard, {
  turn,
  panelTurnId: null,
  selectedCitationId: null,
  onSelectTurn: () => {},
  onSelectCitation: () => {},
}));

check(markup.toLowerCase().includes("interrupted"), "an interrupted turn must say the answer was interrupted");
check(markup.toLowerCase().includes("ask again"), "an interrupted turn must offer an ask-again hint");
check(!markup.toLowerCase().includes("not enough evidence"), "an interruption is not a missing-evidence result");
check(!markup.includes("answer-body") && !markup.includes("answer-quote"), "no partial answer is rendered as a complete one");
check(markup.includes(interruptedRun.failure_code), "the terminal failure code is shown beside the hint");

console.log("question interruption web probe passed");
