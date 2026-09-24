// S2-T probe: proposal text is plain text in the browser (the web half of
// result 3).
//
// The Go half — tests/integration/postgres/s2_workspace_context_hostile_test.go,
// TestS2TProposalTextFromChatHistoryIsPlainText — proves the server stores a
// proposal's markup candidate byte-for-byte and returns it unchanged through
// the proposer and the REST review queue. This probe proves the browser half:
// the strict decoder preserves the markup verbatim, and the proposal card
// renders every proposal field (candidate term, target term, suggested text
// and example excerpt) as React text, never as markup.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  decodeModelContextProposals,
  emptyModelContextDocument,
  type ModelContext,
  type ModelContextProposal,
} from "./model-context";
import { ModelContextEditorSurface } from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

const candidateMarkup = `<script>alert(1)</script>`;
const targetMarkup = `<img src=x onerror=alert(1)>`;
const suggestedMarkup = `<script>alert('definition')</script>`;
const excerptMarkup = `<b>bold</b> prompt`;

const rawProposal = {
  proposal_id: "ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  kind: "SYNONYM",
  candidate_term: candidateMarkup,
  target_term: targetMarkup,
  suggested_text: suggestedMarkup,
  status: "PROPOSED",
  occurrences: 2,
  created_at: "2026-09-10T00:00:00Z",
  examples: [{ conversation_id: "conv_1", question_excerpt: excerptMarkup }],
  hidden_examples: 0,
};

// --- 1. The strict decoder preserves markup verbatim; it neither strips tags
// nor decodes entities.
const decoded = decodeModelContextProposals({ proposals: [rawProposal] });
if (decoded === null || decoded.length !== 1) throw new Error("proposal envelope did not decode");
check(decoded[0].candidate_term === candidateMarkup, "candidate term survives decoding verbatim");
check(decoded[0].target_term === targetMarkup, "target term survives decoding verbatim");
check(decoded[0].suggested_text === suggestedMarkup, "suggested text survives decoding verbatim");
check(decoded[0].examples[0].question_excerpt === excerptMarkup, "example excerpt survives decoding verbatim");
check(
  decoded[0].candidate_term.includes("<script>") && !decoded[0].candidate_term.includes("&lt;"),
  "the decoder does not entity-encode or strip markup",
);

// --- 2. The web view renders the proposal as text, not markup.
const context: ModelContext = { version: 3, content_hash: "sha256:livehash", editable: true, document: emptyModelContextDocument() };
const proposal = rawProposal as ModelContextProposal;
const markup = renderToStaticMarkup(createElement(ModelContextEditorSurface, {
  context,
  document: context.document,
  proposals: [proposal],
  versions: [],
  workspaceID: "ws_1",
  initialTab: "proposals",
  onChange: () => {},
}));

check(!markup.includes("<script>"), "candidate/suggested markup never renders a script element");
check(!markup.includes("<img"), "target markup never renders an inline element");
check(!markup.includes("<b>bold</b>"), "example excerpt markup never renders a bold element");
check(markup.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "the candidate term is escaped as text");
check(markup.includes("&lt;script&gt;alert(") && markup.includes(")&lt;/script&gt;"), "the suggested text is escaped as text");
check(markup.includes("&lt;img src=x onerror=alert(1)&gt;"), "the target term is escaped as text");
check(markup.includes("&lt;b&gt;bold&lt;/b&gt; prompt"), "the example excerpt is escaped as text");

if (failures !== 0) throw new Error(`${failures} proposal plain-text probe assertion(s) failed`);
console.log("proposal plain-text probe: PASS");
