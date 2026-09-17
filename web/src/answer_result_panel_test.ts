// R2 Outcome 3 — in-tree UI probe for the unified AnswerResult panel.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency). It drives
// the real pure projection that AnswerResultBlock / UnifiedAnswerRows render,
// so the UI surface can no longer be narrative-only:
//
//   1. the panel field set is the server's AnswerResult contract, parsed from
//      internal/question/structured_result.go rather than a hand-copied list;
//   2. a legacy answer without answer_result renders the literal “no data”
//      for every missing field -- never a blank, a zero, a fabricated
//      COMPLETE or an invented value, through the legacy showUnifiedFallback
//      component path as well as the answer_result path;
//   3. a PARTIAL completeness is preserved as non-full in the rendered panel.
//
// It is additive: it only reads production source, and it never changes the
// REST/MCP payloads, styles or the already-compliant topic-list error states.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  ANSWER_NO_DATA,
  ANSWER_RESULT_UNIFIED_FIELDS,
  AnswerResultBlock,
  UnifiedAnswerRows,
  answerResultFieldTexts,
  type AnswerResult,
  type AnswerResultUnifiedField,
} from "./main";

// The acceptance field set for R2 Outcome 3. It is deliberately written out
// here (not derived from the source under test) so a silently dropped panel
// field fails instead of shrinking the expectation.
const requiredUnifiedFields: AnswerResultUnifiedField[] = [
  "run_id",
  "intent",
  "value",
  "unit",
  "metric_version",
  "snapshot_id",
  "execution_id",
  "rowset_ref",
  "result_digest",
  "completeness",
  "freshness",
  "evidence_refs",
  "audit_receipt",
];

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function sorted(values: readonly string[]): string[] {
  return [...values].sort();
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  const a = sorted(left);
  const b = sorted(right);
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

// answerResultStructBody returns the exact body of the server's AnswerResult
// struct, located by name with a brace counter so a nested literal cannot leak
// fields from a neighbouring type.
function answerResultStructBody(goSource: string): string {
  const marker = "type AnswerResult struct {";
  const start = goSource.indexOf(marker);
  if (start < 0) throw new Error("type AnswerResult struct { not found in structured_result.go");
  const open = goSource.indexOf("{", start);
  let depth = 0;
  for (let index = open; index < goSource.length; index += 1) {
    if (goSource[index] === "{") depth += 1;
    else if (goSource[index] === "}") {
      depth -= 1;
      if (depth === 0) return goSource.slice(open + 1, index);
    }
  }
  throw new Error("AnswerResult struct is unterminated");
}

function jsonTagNames(structBody: string): string[] {
  const names: string[] = [];
  const pattern = /json:"([^",]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(structBody)) !== null) names.push(match[1]);
  return names;
}

// r2ServerTagNames are the server's R2-unified members: everything after the
// `// R2 Outcome 3 unified fields` marker inside the struct body. The panel
// projection must add exactly the R1 value/unit/completeness it also renders.
function r2ServerTagNames(structBody: string): string[] {
  const marker = structBody.indexOf("// R2 Outcome 3 unified fields");
  if (marker < 0) throw new Error("R2 Outcome 3 unified field marker is missing from AnswerResult");
  return jsonTagNames(structBody.slice(marker));
}

const serverStructCandidates = [
  "internal/question/structured_result.go",
  "../internal/question/structured_result.go",
  "../../internal/question/structured_result.go",
];

async function readServerAnswerResultStruct(): Promise<string> {
  // The module id is typed as a plain string and loaded dynamically so neither
  // esbuild nor tsc tries to resolve a Node built-in at build time: esbuild
  // leaves the runtime import, and no @types/node is needed.
  const fsModuleID: string = "node:fs";
  const fs = (await import(fsModuleID)) as {
    readFileSync(path: string, encoding: "utf8"): string;
  };
  const errors: string[] = [];
  for (const candidate of serverStructCandidates) {
    try {
      return fs.readFileSync(candidate, "utf8");
    } catch (error) {
      errors.push(`${candidate}: ${(error as Error).message}`);
    }
  }
  throw new Error(`internal/question/structured_result.go was not found from the probe cwd:\n${errors.join("\n")}`);
}

function everyAbsentFieldIsNoData(result: AnswerResult | undefined, label: string): void {
  const texts = answerResultFieldTexts(result);
  for (const field of requiredUnifiedFields) {
    const text = texts[field];
    check(text === ANSWER_NO_DATA, `${label}: absent ${field} rendered ${JSON.stringify(text)} instead of «${ANSWER_NO_DATA}»`);
    check(text.trim().length > 0, `${label}: ${field} rendered blank`);
  }
}

async function main(): Promise<void> {
  // --- 1. Panel field set === server AnswerResult contract -----------------
  const goSource = await readServerAnswerResultStruct();
  const structBody = answerResultStructBody(goSource);
  const serverTags = jsonTagNames(structBody);
  const projectionKeys = Object.keys(answerResultFieldTexts(undefined)) as AnswerResultUnifiedField[];

  check(sameSet(projectionKeys, requiredUnifiedFields), `panel projection fields ${JSON.stringify(sorted(projectionKeys))} do not equal the acceptance set ${JSON.stringify(sorted(requiredUnifiedFields))}`);
  check(sameSet([...ANSWER_RESULT_UNIFIED_FIELDS], projectionKeys), "exported unified field tuple and projection keys diverged");

  for (const field of requiredUnifiedFields) {
    check(serverTags.includes(field), `server AnswerResult struct has no json tag ${field} for panel field ${field}`);
  }

  const r2Tags = r2ServerTagNames(structBody);
  const expectedFromServer = [...r2Tags, "value", "unit", "completeness"];
  check(sameSet(expectedFromServer, projectionKeys), `panel projection ${JSON.stringify(sorted(projectionKeys))} is not the server R2 members ${JSON.stringify(sorted(r2Tags))} plus value/unit/completeness`);

  // --- 2. Legacy answers render “no data”, never invented values -----------
  everyAbsentFieldIsNoData(undefined, "legacy fallback (showUnifiedFallback)");
  everyAbsentFieldIsNoData({} as AnswerResult, "empty result object");

  const legacyMarkup = renderToStaticMarkup(createElement(UnifiedAnswerRows, {}));
  const noDataOccurrences = legacyMarkup.split(ANSWER_NO_DATA).length - 1;
  check(noDataOccurrences >= requiredUnifiedFields.length - 2, `legacy panel markup carried only ${noDataOccurrences} «${ANSWER_NO_DATA}» markers`);
  check(!legacyMarkup.includes("complete"), "legacy panel markup fabricated complete coverage");

  // The answer_result-present component renders the same projection: absent
  // unified fields stay “no data” while real values pass through untouched.
  const minimalResult = {
    kind: "AGGREGATE",
    operation: "AGGREGATE",
    rule: "server rule",
    snapshot: { row_count: 0 },
    completeness: "COMPLETE",
    value: "42",
    unit: "\u0448\u0442",
  } as AnswerResult;
  const minimalTexts = answerResultFieldTexts(minimalResult);
  check(minimalTexts.value === "42" && minimalTexts.unit === "\u0448\u0442", "present value/unit were not passed through the projection");
  check(minimalTexts.run_id === ANSWER_NO_DATA, "absent run_id was not 'no data' on a present result object");
  const minimalMarkup = renderToStaticMarkup(createElement(AnswerResultBlock, { result: minimalResult }));
  check(minimalMarkup.includes("42") && minimalMarkup.includes("\u0448\u0442"), "AnswerResultBlock did not render the present value/unit");
  check(minimalMarkup.includes(ANSWER_NO_DATA), "AnswerResultBlock did not render 'no data' for absent unified fields");

  // --- 3. PARTIAL stays non-full ------------------------------------------
  const partialResult = { kind: "AGGREGATE", operation: "AGGREGATE", rule: "r", snapshot: { row_count: 0 }, completeness: "PARTIAL" } as AnswerResult;
  const partialTexts = answerResultFieldTexts(partialResult);
  check(partialTexts.completeness !== ANSWER_NO_DATA, "PARTIAL completeness collapsed into 'no data'");
  check(partialTexts.completeness !== "complete", "PARTIAL completeness was rendered as full");
  const partialMarkup = renderToStaticMarkup(createElement(UnifiedAnswerRows, { result: partialResult }));
  check(partialMarkup.includes("incomplete"), "PARTIAL completeness was not rendered as non-full in the panel markup");

  if (failures !== 0) throw new Error(`${failures} answer-result panel probe assertion(s) failed`);
  console.log("answer-result panel probe: PASS");
}

// A thrown assertion surfaces as an unhandled rejection, which terminates node
// with a non-zero exit code; the probe has no other output on failure.
void main();
