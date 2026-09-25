// Card W-7: the source of an answer reads like a document, not a debug dump.
//
// These are static renders of the opened source (`EvidenceSourceView`, the
// article the standalone evidence route shows after a real fetch) with the
// details control closed and open. They are the front-end half of the card:
// the first screen is the document, and every address/id/hash lives behind
// the one "Details" control.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { EvidenceSourceView, type EvidenceData } from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

const provenance = {
  extraction_id: "extraction-token",
  source_version_id: "source-version-token",
  ordinal: 3,
  external_version_key: "external-version-token",
  content_hash: "content-hash-token",
  observed_at: "observed-at-token",
  source_object_id: "object-token",
  connection_id: "connection-token",
};

const documentText = "Регламент обращения с отходами.\n\n"
  + "Вывоз твёрдых коммунальных отходов выполняется не позднее 24 часов.\n";

const evidence: EvidenceData = {
  fragment_id: "fragment-token",
  text: documentText,
  anchor: "anchor-token",
  source_path: "projects\\alpha\\waste-removal-regulation.txt",
  canonical_address: "canonical-address-token",
  address: { note: "structured-address-token" },
  is_current_version: true,
  provenance,
};

// Every value the owner named as "too much information": addresses, ids,
// hashes, anchors, JSON and version/extraction data.
const TECHNICAL_TOKENS = [
  "fragment-token",
  "anchor-token",
  "canonical-address-token",
  "structured-address-token",
  "source-version-token",
  "external-version-token",
  "content-hash-token",
  "extraction-token",
  "observed-at-token",
];

function render(
  value: EvidenceData,
  options: { highlight?: { start: number; end: number; text: string } | null; detailsOpen?: boolean } = {},
): string {
  return renderToStaticMarkup(createElement(EvidenceSourceView, {
    evidence: value,
    highlight: options.highlight ?? null,
    detailsOpen: options.detailsOpen ?? false,
    workspaceName: "Рабочая область",
    returnHref: "#search/workspace",
    onReturn: () => {},
  }));
}

// Result 1: name, path, quoted fragment and document text are the first
// screen; no technical field is.
const opened = render(evidence, { highlight: { start: 0, end: 9, text: "Регламент" } });
check(opened.includes("waste-removal-regulation.txt"), "the document name is on the first screen");
check(opened.includes("projects\\alpha\\waste-removal-regulation.txt"), "the document path is on the first screen");
const quoted = opened.match(/<blockquote[^>]*>([\s\S]*?)<\/blockquote>/);
check(quoted !== null && quoted[1].includes("Регламент"), "the quoted fragment is shown as a quote");
check(opened.includes("Вывоз твёрдых коммунальных отходов выполняется не позднее 24 часов."), "the document text is on the first screen");
check(opened.includes("<summary>Details</summary>"), "one Details control is offered");
for (const token of TECHNICAL_TOKENS) {
  check(!opened.includes(token), `the first screen hides the technical field ${token}`);
}

// Result 2: a Markdown document is formatted, not dumped.
const markdownText = [
  "# Регламент обращения с отходами",
  "",
  "Основной текст документа.",
  "",
  "| Срок | Значение |",
  "| --- | --- |",
  "| Вывоз | 24 часа |",
  "",
  "```",
  "kvctl --check",
  "```",
  "",
].join("\n");
const formatted = render({ ...evidence, text: markdownText });
check(/<h[1-6][ >]/.test(formatted), "a Markdown heading renders as a heading element");
check(formatted.includes("<table"), "a Markdown table renders as a table element");
check(formatted.includes("<th") && formatted.includes("<td"), "table cells render as table cells");
check(formatted.includes("<pre") && formatted.includes("<code"), "a fenced block renders as code");
check(!formatted.includes("# Регламент обращения") && !formatted.includes("| Срок") && !formatted.includes("| --- |"),
  "no Markdown heading or table line is shown as text");
check(!formatted.split("\n").some((line) => /^(#|\|)/.test(line.trim())), "no rendered line starts with # or |");

// Result 3: one Details control opens every technical field.
const openedDetails = render(evidence, { detailsOpen: true });
check(openedDetails.includes("<details"), "the Details control is a disclosure element");
for (const token of TECHNICAL_TOKENS) {
  check(openedDetails.includes(token), `opened Details shows the technical field ${token}`);
}

if (failures !== 0) throw new Error(`${failures} evidence-source-document assertion(s) failed`);
console.log("evidence source document render: PASS");
