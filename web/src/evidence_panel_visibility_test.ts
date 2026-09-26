// Card W-8 web probe: the chat screen's evidence panel opens on demand.
//
// Before this card the panel was always in the chat screen's grid, so it took
// a column even when the person was only reading answers; the empty panel
// ("Ask a question to view the source text behind the answer here") was the
// first thing on the right of every answer. This probe statically renders the
// REAL production AnswerEvidence region of main.tsx with a real answer turn
// through react-dom/server (no test framework, no new dependency, matching
// conversation_sidebar_test.ts and chat_sources_control_test.ts) and checks
// the card results:
//
//   1. with nothing opened there is no evidence panel, and the control that
//      opens it is present on the chat screen;
//   2. with the panel open the same control closes it; closing it again leaves
//      no panel and the closed-state layout carries no evidence column;
//   3. the panel opened on an answer's turn carries that answer's turn, so the
//      source an evidence link opens is the answer's source.
//
// The card's width claim itself (the chat is wider with the panel closed) is
// measured in the real browser by the local screen walkthrough.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AnswerEvidence, AskSurface, type ConversationTurn, type WorkspaceDataState } from "./main";

declare const require: (moduleName: string) => { readFileSync(path: string, encoding: string): string };
const fs = require("fs");
const mainSource = fs.readFileSync("src/main.tsx", "utf8");

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

const PANEL = 'aria-label="Answer evidence"';
const OPEN_CONTROL = "<span>Show evidence</span>";
const CLOSE_CONTROL = "<span>Hide evidence</span>";

const snapshot = { id: "workspace-1", name: "Operations", status: "ACTIVE", revision: 1, model_profiles: [] };
const state = {
  phase: "loaded",
  snapshot: { kind: "ok", value: snapshot },
  sources: { kind: "ok", value: { sources: [], confirmation_context: {} } },
} as unknown as WorkspaceDataState;

// answerTurn is one answer that has evidence: one citation of a real fragment,
// exactly the shape the chat feed renders after a governed question.
const answerTurn = {
  turn_id: "turn-1",
  question_run_id: "qrun-1",
  turn_index: 0,
  created_at: "2026-09-25T19:12:20Z",
  question_run: {
    question_run_id: "qrun-1",
    conversation_id: "conversation-1",
    question: "Which container is emptied within 24 hours?",
    answer: "Solid municipal waste is removed within 24 hours [1].",
    citations: [{
      citation_id: "citation-1",
      number: 1,
      evidence_fragment_id: "fragment-1",
      excerpt: "Вывоз твёрдых коммунальных отходов выполняется не позднее 24 часов.",
      grounding_status: "CONFIRMED_BY_FRAGMENT",
      address: null,
    }],
    uncertainties: [],
    conflicts: [],
  },
} as unknown as ConversationTurn;

const turnsByID = new Map([[answerTurn.turn_id, answerTurn]]);

function renderEvidenceProps(open: boolean): string {
  return renderToStaticMarkup(createElement(AnswerEvidence, {
    allSources: [],
    fullscreen: false,
    onOpenEvidence: () => {},
    onSelectCitation: () => {},
    onToggle: () => {},
    onToggleFullscreen: () => {},
    open,
    sourceNameByConnection: new Map(),
    target: { turnId: answerTurn.turn_id, citationId: "citation-1" },
    turnsByID,
    workspaceID: "workspace-1",
  }));
}

// Result 1: nothing opened — no panel, and the control that opens it is there.
const closed = renderEvidenceProps(false);
check(!closed.includes(PANEL), "the closed evidence region renders no panel");
check(!closed.includes('class="evi"'), "the closed evidence region renders no panel body");
check(closed.includes('class="evidence-dock"'), "the closed evidence region is the dock");
check(!closed.includes("evidence-dock-open"), "the closed evidence region is not the open dock");
check(closed.includes('class="evidence-toggle"'), "the closed evidence region carries the one evidence control");
check(closed.includes(OPEN_CONTROL), "the closed evidence control offers to show the evidence");
check(!closed.includes(CLOSE_CONTROL), "the closed evidence control does not offer to hide it");
check(closed.includes('aria-expanded="false"'), "the closed evidence control reports the panel as closed");

// Result 2: open — the panel is there and the same control closes it.
const opened = renderEvidenceProps(true);
check(opened.includes(`<aside ${PANEL}`), "the open evidence region renders the answer evidence panel");
check(opened.includes('class="evi"'), "the open evidence region renders the panel body");
check(opened.includes("evidence-dock-open"), "the open evidence region is the open dock");
check(opened.includes('class="evidence-toggle"'), "the open panel carries the one evidence control");
check(opened.includes(CLOSE_CONTROL), "the open panel's control offers to hide the evidence");
check(!opened.includes(OPEN_CONTROL), "the open panel does not still offer to show it");
check(opened.includes('aria-expanded="true"'), "the open panel's control reports the panel as open");
// Result 3: the panel opened on an answer carries that answer's turn, so the
// source an evidence link opens is the answer's own source.
check(opened.includes("Which container is emptied within 24 hours?"),
  "the open panel names the answer whose source it shows");
check(opened.includes('class="evi-turn"'), "the open panel carries the answer's turn context");

// Closing again: the render has no panel (the state the screen returns to).
const closedAgain = renderEvidenceProps(false);
check(!closedAgain.includes(PANEL), "after closing, the evidence region renders no panel again");
check(closedAgain.includes(OPEN_CONTROL), "after closing, the open control is the one on screen again");

// Result 1 on the chat screen itself: the real AskSurface with nothing opened
// has no evidence panel and carries the control that opens it, and its layout
// has no evidence column.
const chatMarkup = renderToStaticMarkup(createElement(AskSurface, {
  active: true,
  onOpenEvidence: () => {},
  onOpenSources: () => {},
  requestedWorkspaceID: "workspace-1",
  state,
}));
check(!chatMarkup.includes(PANEL), "the chat screen with nothing opened shows no evidence panel");
check(chatMarkup.includes('class="evidence-toggle"'), "the chat screen carries the control that opens the evidence");
check(chatMarkup.includes(OPEN_CONTROL), "that control is the one that opens the panel");
check(chatMarkup.includes('class="ask-layout"'), "the chat screen uses the base layout with no evidence column");
check(!chatMarkup.includes("ask-layout-evidence"), "the closed chat screen does not reserve an evidence column");

// The source of the two facts above: opening an answer's evidence link asks
// for the panel, not only the screen control.
const selectCitation = mainSource.slice(mainSource.indexOf("function selectCitation("));
const selectCitationBody = selectCitation.slice(0, selectCitation.indexOf("\n  }", 0) + 4);
check(selectCitationBody.includes("setEvidenceOpen(true)"),
  "opening an answer's evidence link opens the evidence panel");
const toggleBody = mainSource.slice(mainSource.indexOf("function toggleEvidence()"));
check(toggleBody.slice(0, 200).includes("closeEvidence()"),
  "the screen's one evidence control closes an open panel");

if (failures !== 0) throw new Error(`${failures} evidence-panel visibility assertion(s) failed`);
console.log("evidence panel visibility probe: PASS");
