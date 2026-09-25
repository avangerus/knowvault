// Card W-2 probe: the three plain-text fields. Result 1 of the card says the
// description, the instructions for the assistant (today's rules) and the
// glossary are each one free-text field with a save action, and the screen
// shows no tables, chips, per-term forms, data-link blocks, ids or hashes for
// them. This probe renders the real production surface and asserts exactly
// that; the Go integration test asserts the server projects the structured
// records into the field and still keeps them stored.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { type ModelContext, type ModelContextDocument } from "./model-context";
import { ModelContextEditorSurface } from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

// The document a workspace that predates this card returns: structured rules
// and terms, and the readable text the server projects from them.
const document: ModelContextDocument = {
  description: "Синтетический словарь рабочей области.",
  instructions: "Действующим считается договор, у которого поле status равно active.",
  glossary_text: "МНО (место накопления отходов) — Место накопления отходов — контейнерная площадка. [container_group.code]",
  rules: [{ id: "rule_01ARZ3NDEKTSV4RRFFQ69G5FAV", text: "Действующим считается договор, у которого поле status равно active." }],
  glossary: [{
    id: "term_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    term: "МНО",
    synonyms: ["место накопления отходов"],
    definition: "Место накопления отходов — контейнерная площадка.",
    data_locations: [{ source_connection_id: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", relation: "public.container_group", column: "code", hint: "код МНО" }],
  }],
  sources: [{ source_connection_id: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", description: "МНО", tables: [] }],
};

const context: ModelContext = { version: 3, content_hash: "sha256:livehash", editable: true, document };

function render(tab: "description" | "instructions" | "glossary"): string {
  return renderToStaticMarkup(createElement(ModelContextEditorSurface, {
    context,
    document,
    proposals: [],
    versions: [],
    workspaceID: "ws_1",
    initialTab: tab,
    onChange: () => {},
    onSave: () => {},
  }));
}

const description = render("description");
const instructions = render("instructions");
const glossary = render("glossary");

// --- 1. Each section is exactly one text field with a save action.
check((description.match(/<textarea/g) ?? []).length === 1, "description is one textarea");
check(description.includes(document.description), "description shows its own text");
check((instructions.match(/<textarea/g) ?? []).length === 1, "instructions is one textarea");
check(instructions.includes(document.instructions), "instructions shows the readable rule text");
check((glossary.match(/<textarea/g) ?? []).length === 1, "glossary is one textarea");
check(glossary.includes("МНО"), "glossary shows the term as text");
check(glossary.includes("место накопления отходов"), "glossary shows the synonym as text");
check(glossary.includes("контейнерная площадка"), "glossary shows the definition as text");
check(glossary.includes("container_group.code"), "glossary shows the data link as readable text");
for (const markup of [description, instructions, glossary]) {
  check(markup.includes(">Save<"), "each plain-text section offers a save action");
}

// --- 2. No table, no chips, no per-term form, no data-link block.
for (const [label, markup] of [["description", description], ["instructions", instructions], ["glossary", glossary]] as const) {
  check(!markup.includes("<table"), `${label} renders no table`);
  check(!markup.includes('class="chip"'), `${label} renders no chip`);
  check(!markup.includes("model-context-locations"), `${label} renders no data-link block`);
  check(!markup.includes("model-context-term-editor"), `${label} renders no per-term form`);
  check(!markup.includes("Add term") && !markup.includes("Add rule") && !markup.includes("Save term"), `${label} renders no per-term action`);
}

// --- 3. No id and no content hash anywhere on the screen.
for (const [label, markup] of [["description", description], ["instructions", instructions], ["glossary", glossary]] as const) {
  check(!markup.includes("term_") && !markup.includes("rule_"), `${label} shows no record id`);
  check(!markup.includes("conn_"), `${label} shows no source connection id`);
  check(!markup.includes("sha256:"), `${label} shows no content hash`);
}

// --- 4. A read-only caller gets the same one field per section, no save.
const readOnly: ModelContext = { ...context, editable: false };
for (const tab of ["description", "instructions", "glossary"] as const) {
  const markup = renderToStaticMarkup(createElement(ModelContextEditorSurface, {
    context: readOnly,
    document,
    proposals: [],
    versions: [],
    workspaceID: "ws_1",
    initialTab: tab,
    onChange: () => {},
    onSave: () => {},
  }));
  check((markup.match(/<textarea/g) ?? []).length === 1, `read-only ${tab} is one textarea`);
  check(!markup.includes(">Save<"), `read-only ${tab} offers no save action`);
}

if (failures !== 0) throw new Error(`${failures} plain-text field probe assertion(s) failed`);
console.log("model context plain-text probe: PASS");
