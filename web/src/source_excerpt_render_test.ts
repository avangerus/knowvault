import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AnswerBody } from "./main";

const escaped = "A &amp; B &lt;tag&gt; raw\\_field \\`code\\` \\[1\\] \\*bold\\* &amp;lt;";
const markup = renderToStaticMarkup(createElement(AnswerBody, {
  text: `Source excerpt [2]: “${escaped}”`,
  citations: [{
    number: 2, citation_id: "cite-2", evidence_fragment_id: "frag-2", excerpt: "A & B",
    anchor: "paragraph", deep_link: "#evidence", source_version_id: "version-2",
    extraction_id: "extract-2", source_object_id: "object-2", evidence_text_hash: "hash-2", excerpt_hash: "excerpt-2",
  }],
  turnId: "turn-1", panelTurnId: null, selectedCitationId: null, onSelectCitation: () => {},
}));

function check(condition: boolean, description: string): void {
  if (!condition) throw new Error(description);
}

check(markup.includes("A &amp; B &lt;tag&gt; raw_field `code` [1] *bold* &amp;lt;"), "source text displays its literal characters and decodes one escape layer");
check(!markup.includes("raw\\_field") && !markup.includes("&amp;amp;") && !markup.includes("&amp;lt;tag"), "source escape syntax is not visible");
check(!markup.includes("<tag>") && !markup.includes("<strong>") && !markup.includes("<em>") && !markup.includes("ans-code") && !markup.includes("<a "), "source text cannot create HTML or Markdown elements");
check((markup.match(/class="fn"/g) ?? []).length === 1, "only the source citation marker becomes an evidence control");

const russian = renderToStaticMarkup(createElement(AnswerBody, {
  text: `\u0424\u0440\u0430\u0433\u043c\u0435\u043d\u0442 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430 [2]: “${escaped}”`,
  citations: [], turnId: "turn-2", panelTurnId: null, selectedCitationId: null, onSelectCitation: () => {},
}));
check(russian.includes("A &amp; B &lt;tag&gt; raw_field `code` [1] *bold*"), "Russian source label uses the same literal quote path");

console.log("source excerpt literal render: PASS");
