// Card W-3 — the answer in the chat without the «paraphrase» self-label and
// without an English incomplete-data banner.
//
// The probe drives the real answer view (TurnCard -> TurnAnswer) with the
// repository's pinned esbuild + node toolchain and react-dom/server, so the
// acceptance is a property of the shipped component rather than a narrative:
//
//   1. an answer whose data is complete shows no «paraphrase» text and no
//      incomplete-data warning -- including the owner's case, where the
//      workspace corpus flag is PARTIAL because of a source this answer never
//      read;
//   2. an answer to a Russian question whose own numbers rest on incomplete
//      data shows exactly one short warning line, in Russian;
//   3. the same answer to an English question gets the English sentence, never
//      the Russian one.
//
// It reads production source only; it changes no answer text, no REST/MCP
// payload and no other answer-view control.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { TurnCard } from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

const citation = {
  citation_id: "cit-1",
  number: 1,
  evidence_fragment_id: "frg-1",
  excerpt: "Вывоз твёрдых коммунальных отходов выполняется не позднее 24 часов.",
  grounding_status: "CONFIRMED_BY_FRAGMENT",
};

// answeredDocument is a complete, fully grounded document answer: no
// answer_result, so nothing about it rests on an incomplete snapshot. Its
// verification method is neither a byte-exact quote nor address-bound, so the
// answer body is the ordinary prose block that used to carry the «paraphrase»
// badge.
const answeredDocument = {
  question_run_id: "qrun-1",
  workspace_id: "workspace-1",
  workspace_revision: 1,
  question: "что ты знаешь?",
  answer_mode: "DOCUMENT",
  verification_method: "EXTRACTIVE",
  grounding_status: "CONFIRMED_BY_FRAGMENT",
  status: "COMPLETED",
  corpus_status: "COMPLETE",
  freshness: { state: "FRESH" },
  started_at: "2026-09-25T20:00:00Z",
  manifest_status: "PUBLISHED",
  answer: "Вывоз твёрдых коммунальных отходов выполняется не позднее 24 часов.",
  citations: [citation],
  uncertainties: [],
  conflicts: [],
};

// partialAggregate is a structured answer whose own completeness is PARTIAL:
// its numbers do not cover the whole source.
const partialAggregate = {
  ...answeredDocument,
  question_run_id: "qrun-2",
  planning_operation: "AGGREGATE",
  corpus_status: "PARTIAL",
  answer_result: {
    kind: "AGGREGATE",
    operation: "AGGREGATE",
    rule: "server rule",
    snapshot: { row_count: 3 },
    completeness: "PARTIAL",
    value: "3",
  },
  uncertainties: [
    {
      code: "CORPUS_PARTIAL",
      evidence_ids: ["frg-1"],
      message: "Корпус источников неполный: ответ не охватывает все данные рабочей области.",
    },
  ],
};

function renderTurn(run: unknown): string {
  return renderToStaticMarkup(createElement(TurnCard, {
    turn: {
      turn_id: "turn-1",
      question_run_id: "qrun-1",
      turn_index: 1,
      created_at: "2026-09-25T20:00:00Z",
      question_run: run,
    } as never,
    panelTurnId: null,
    selectedCitationId: null,
    onSelectTurn: () => {},
    onSelectCitation: () => {},
  }));
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

const RUSSIAN_WARNING = "Ответ основан на неполных данных. Проверьте доказательства и состояние источников, прежде чем опираться на него.";
const ENGLISH_WARNING = "This answer uses an incomplete dataset. Check the evidence and source status before relying on it.";

// --- 1. Complete data: no «paraphrase» text, no incomplete-data warning ----

const completeMarkup = renderTurn(answeredDocument);
check(!completeMarkup.includes("paraphrase"), "a complete answer still rendered the word «paraphrase»");
check(!completeMarkup.includes('badge-tell">paraphrase'), "a complete answer still rendered the «paraphrase» badge");
check(completeMarkup.includes("Вывоз твёрдых коммунальных отходов выполняется не позднее 24 часов."), "the complete answer text was not rendered");
check(!completeMarkup.includes(ENGLISH_WARNING), "a complete answer carried the English incomplete-data warning");
check(!completeMarkup.includes(RUSSIAN_WARNING), "a complete answer carried the Russian incomplete-data warning");

// The owner's case: the workspace corpus flag is PARTIAL and the server sends
// its CORPUS_PARTIAL uncertainty, but this answer read a complete source. The
// warning must not appear and the raw uncertainty line must not leak into the
// answer view as a second caveat.
const completeAnswerPartialCorpus = {
  ...answeredDocument,
  corpus_status: "PARTIAL",
  uncertainties: [
    {
      code: "CORPUS_PARTIAL",
      evidence_ids: ["frg-1"],
      message: "Корпус источников неполный: ответ не охватывает все данные рабочей области.",
    },
  ],
};
const partialCorpusMarkup = renderTurn(completeAnswerPartialCorpus);
check(!partialCorpusMarkup.includes("incomplete dataset"), "a whole-corpus flag painted an incomplete-data warning under a complete answer");
check(!partialCorpusMarkup.includes("Корпус источников неполный"), "the raw CORPUS_PARTIAL uncertainty leaked as a second caveat");
check(count(partialCorpusMarkup, 'class="msg-warning"') === 0, "a complete answer rendered a warning line");

// --- 2. Russian question, incomplete answer data: one Russian line ---------

const partialMarkup = renderTurn(partialAggregate);
check(partialMarkup.includes(RUSSIAN_WARNING), "a partially covered Russian answer did not get the Russian warning");
check(!partialMarkup.includes(ENGLISH_WARNING), "a Russian answer got the incomplete-data warning in English");
check(count(partialMarkup, 'class="msg-warning"') === 1, `a partially covered answer rendered ${count(partialMarkup, 'class="msg-warning"')} warning lines instead of one`);
check(count(partialMarkup, RUSSIAN_WARNING) === 1, "the Russian warning was rendered more than once");
check(RUSSIAN_WARNING.length <= 200, "the Russian warning is not one short line");

// --- 3. The same incomplete answer in English keeps English ----------------

const englishPartial = { ...partialAggregate, question: "how many vehicles are there?" };
const englishMarkup = renderTurn(englishPartial);
check(englishMarkup.includes(ENGLISH_WARNING), "an incomplete English answer did not get the English warning");
check(!englishMarkup.includes(RUSSIAN_WARNING), "an English answer got the Russian warning");

if (failures !== 0) throw new Error(`${failures} answer incomplete-warning probe assertion(s) failed`);
console.log("answer incomplete-warning probe: PASS");
