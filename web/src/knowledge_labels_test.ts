import { KNOWLEDGE_TOOL_LABELS } from "./knowledge-labels";

function check(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

// The live step list renders each tool call's label from this map. ADR-0097's
// source schema tool is «Схема источника» in the product's Russian UI; the
// label table in code carries its English label ("Source schema"), which the UI
// renders through its existing step-label path.
check(
  KNOWLEDGE_TOOL_LABELS["knowvault_source_schema"] === "Source schema",
  "knowvault_source_schema must have its own source schema step label",
);
check(
  KNOWLEDGE_TOOL_LABELS["knowvault_sources"] === "Source status",
  "the existing source status label must not drift",
);
for (const [name, label] of Object.entries(KNOWLEDGE_TOOL_LABELS)) {
  check(name.startsWith("knowvault_"), `unexpected tool label key: ${name}`);
  check(label.trim().length > 0, `empty step label for ${name}`);
}
console.log("knowledge labels: ok");
