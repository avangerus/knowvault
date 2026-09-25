// S2 card D probe: the workspace model context (Settings) surface.
//
// Like the other web probes this is a plain TypeScript module run by the
// repository's pinned esbuild + node toolchain (no test framework, no jsdom).
// It exercises the real production source:
//
//   1. the strict GET decoder (and its rejection of malformed shapes);
//   2. the exact PUT body / If-Match / Idempotency-Key a save sends, including
//      the version-0 "sha256:empty" sentinel;
//   3. read-only mode (editable=false) hides the Proposals tab and disables
//      inputs;
//   4. an accept sends If-Match on the current hash;
//   5. the «Использованы термины» line rendered from a sample
//      tool_loop.workspace_context, above the tool-calls disclosure;
//   6. a glossary term or matched term containing markup is escaped, never
//      executed.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  decodeModelContext,
  decodeModelContextProposals,
  emptyModelContextDocument,
  workspaceContextUsageLineFromToolLoop,
  type ModelContext,
  type ModelContextDocument,
} from "./model-context";
import {
  ModelContextEditorSurface,
  WorkspaceContextUsage,
  sendModelContextProposalAccept,
  sendModelContextSave,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function checkEqual(actual: unknown, expected: unknown, message: string): void {
  const left = JSON.stringify(actual);
  const right = JSON.stringify(expected);
  check(left === right, `${message} (got ${left}, want ${right})`);
}

// ---------------------------------------------------------------------------
// fetch stub: capture every request the production transports make.
// ---------------------------------------------------------------------------

type CapturedRequest = { method: string; path: string; headers: Record<string, string>; body: unknown };
type StubReply = { match: (path: string, method: string) => boolean; status: number; body: unknown };

function installFetchStub(replies: StubReply[]): { calls: CapturedRequest[]; restore: () => void } {
  const calls: CapturedRequest[] = [];
  const original = globalThis.fetch;
  const stub = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const rawBody = init?.body;
    calls.push({ method, path, headers, body: typeof rawBody === "string" ? JSON.parse(rawBody) as unknown : rawBody });
    if (path === "/api/v1/session/csrf") {
      return new Response(JSON.stringify({ csrf_token: "csrf_probe" }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    const reply = replies.find((candidate) => candidate.match(path, method));
    if (!reply) return new Response(JSON.stringify({ error: { code: "PROBE_UNMATCHED", request_id: "req_probe" } }), { status: 500, headers: { "Content-Type": "application/json" } });
    return new Response(JSON.stringify(reply.body), { status: reply.status, headers: { "Content-Type": "application/json" } });
  };
  globalThis.fetch = stub as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = original; } };
}

const rawContextDocument = {
  description: "The monthly reporting workspace.",
  rules: [{ id: "rule_1", text: "Always cite the source." }],
  glossary: [{
    id: "term_1",
    term: "МНО",
    synonyms: ["МНОшка"],
    definition: "Monthly net orders.",
    data_locations: [{ source_connection_id: "conn_1", relation: "public.orders", column: "", hint: "primary" }],
  }],
  sources: [{
    source_connection_id: "conn_1",
    description: "Orders connection",
    tables: [{ relation: "public.orders", note: "one row per order", columns: [{ name: "created_at", note: "UTC" }] }],
  }],
};

const rawContext = {
  version: 3,
  content_hash: "sha256:livehash",
  editable: true,
  document: rawContextDocument,
  updated_at: "2026-09-10T00:00:00Z",
  updated_by: "principal_owner",
};

function requireDecoded(value: unknown, label: string): ModelContext {
  const decoded = decodeModelContext(value);
  if (decoded === null) throw new Error(`${label}: decodeModelContext returned null`);
  return decoded;
}

async function main(): Promise<void> {
  // --- 1. Strict GET decoding ---------------------------------------------
  const decoded = requireDecoded(rawContext, "contract GET");
  check(decoded.version === 3 && decoded.content_hash === "sha256:livehash" && decoded.editable, "version/hash/editable survive decoding");
  check(decoded.document.description === rawContextDocument.description, "description survives decoding");
  check(decoded.document.rules[0].id === "rule_1" && decoded.document.rules[0].text === "Always cite the source.", "rule survives decoding");
  check(decoded.document.glossary[0].term === "МНО" && decoded.document.glossary[0].synonyms[0] === "МНОшка", "term and synonyms survive decoding");
  check(decoded.document.glossary[0].data_locations[0].column === "", "an explicitly empty location column is preserved, not dropped");
  check(decoded.document.glossary[0].data_locations[0].relation === "public.orders", "location relation survives decoding");
  check(decoded.document.sources[0].tables[0].columns[0].note === "UTC", "per-column note survives decoding");
  check(requireDecoded({ ...rawContext, editable: false }, "read-only GET").editable === false, "editable=false decodes as read-only");

  check(decodeModelContext({ ...rawContext, version: -1 }) === null, "a negative version is rejected");
  check(decodeModelContext({ ...rawContext, document: "text" }) === null, "a non-object document is rejected");
  check(decodeModelContext({ ...rawContext, document: { description: 7, rules: [], glossary: [], sources: [] } }) === null, "a non-string description is rejected");
  check(decodeModelContext({ ...rawContext, document: { description: "", rules: [{ id: "r", text: 7 }], glossary: [], sources: [] } }) === null, "a non-string rule text is rejected");
  check(decodeModelContext(null) === null, "null is rejected");

  const proposals = decodeModelContextProposals({
    proposals: [{
      proposal_id: "prop_1",
      kind: "NEW_TERM",
      candidate_term: "МНО",
      target_term_id: "",
      target_term: "",
      suggested_text: "Monthly net orders.",
      status: "PROPOSED",
      occurrences: 4,
      created_at: "2026-09-10T00:00:00Z",
      examples: [{ conversation_id: "conv_1", question_excerpt: "what are МНО?" }],
      hidden_examples: 2,
    }],
    next_cursor: "cursor_1",
  });
  check(proposals !== null && proposals.length === 1 && proposals[0].occurrences === 4 && proposals[0].hidden_examples === 2, "proposal envelope decodes with occurrences and hidden_examples");
  check(decodeModelContextProposals({ proposals: [{ proposal_id: "p" }] }) === null, "a malformed proposal is rejected");

  // --- 2. PUT body / If-Match / Idempotency-Key ---------------------------
  const contextV3 = decoded;
  const draft: ModelContextDocument = {
    description: "Updated description",
    rules: [{ id: "", text: "A brand new rule" }],
    glossary: [{
      id: "term_1",
      term: "МНО",
      synonyms: ["mno", ""],
      definition: "Monthly net orders.",
      data_locations: [{ source_connection_id: "conn_1", relation: "public.orders", column: "", hint: "" }],
    }],
    sources: [{ source_connection_id: "conn_1", description: "", tables: [{ relation: "public.orders", note: "", columns: [{ name: "created_at", note: "" }] }] }],
  };

  const saveStub = installFetchStub([{ match: (path) => path.endsWith("/model-context"), status: 200, body: rawContext }]);
  let saveResult;
  try {
    saveResult = await sendModelContextSave("ws_1", contextV3, draft);
  } finally {
    saveStub.restore();
  }
  check(saveResult.kind === "ok", "a 200 save resolves ok");
  const put = saveStub.calls.find((call) => call.method === "PUT");
  check(put !== undefined, "the save sent a PUT");
  if (put !== undefined) {
    check(put.path === "/api/v1/workspaces/ws_1/model-context", `the save path is the workspace model-context route (got ${put.path})`);
    check(put.headers["If-Match"] === "\"sha256:livehash\"", `If-Match is the current content hash as a quoted entity-tag (got ${put.headers["If-Match"]})`);
    check(/^[A-Za-z0-9_-]{43}$/.test(put.headers["Idempotency-Key"] ?? ""), `a fresh base64url Idempotency-Key is sent (got ${put.headers["Idempotency-Key"]})`);
    check(put.headers["X-KnowVault-CSRF"] === "csrf_probe", "the mutation carries the session CSRF token");
    checkEqual(put.body, {
      document: {
        description: "Updated description",
        rules: [{ id: "", text: "A brand new rule" }],
        glossary: [{ id: "term_1", term: "МНО", synonyms: ["mno"], definition: "Monthly net orders.", data_locations: [{ source_connection_id: "conn_1", relation: "public.orders" }] }],
        sources: [{ source_connection_id: "conn_1", tables: [{ relation: "public.orders", columns: [{ name: "created_at" }] }] }],
      },
    }, "the PUT body is {document} with new ids empty and cleared optional members dropped");
  }

  const emptyContext: ModelContext = { version: 0, content_hash: "sha256:ignored", editable: true, document: emptyModelContextDocument() };
  const emptyStub = installFetchStub([{ match: (path) => path.endsWith("/model-context"), status: 200, body: { version: 1, content_hash: "sha256:first", editable: true, document: rawContextDocument } }]);
  try {
    await sendModelContextSave("ws_empty", emptyContext, emptyModelContextDocument());
  } finally {
    emptyStub.restore();
  }
  const emptyPut = emptyStub.calls.find((call) => call.method === "PUT");
  check(emptyPut?.headers["If-Match"] === "\"sha256:empty\"", `a version-0 save sends the quoted If-Match: "sha256:empty" (got ${emptyPut?.headers["If-Match"]})`);

  // --- 3. Read-only mode ---------------------------------------------------
  const readOnlyContext: ModelContext = { ...contextV3, editable: false };
  const readOnlyDescription = renderToStaticMarkup(createElement(ModelContextEditorSurface, {
    context: readOnlyContext,
    document: readOnlyContext.document,
    proposals: [{ proposal_id: "prop_1" } as never],
    versions: [],
    workspaceID: "ws_1",
    onChange: () => {},
  }));
  check(!readOnlyDescription.includes("Proposals"), "read-only mode hides the Proposals tab");
  check(/<textarea[^>]*disabled/.test(readOnlyDescription), "read-only mode disables the description textarea");
  check(!readOnlyDescription.includes(">Save<"), "read-only mode hides the Save button");

  const readOnlyRules = renderToStaticMarkup(createElement(ModelContextEditorSurface, {
    context: readOnlyContext,
    document: readOnlyContext.document,
    proposals: [],
    versions: [],
    workspaceID: "ws_1",
    initialTab: "rules",
    onChange: () => {},
  }));
  check(/<input[^>]*disabled/.test(readOnlyRules), "read-only mode disables rule inputs");

  const editableSurface = renderToStaticMarkup(createElement(ModelContextEditorSurface, {
    context: contextV3,
    document: contextV3.document,
    proposals: [{
      proposal_id: "prop_1",
      kind: "NEW_TERM",
      candidate_term: "МНО",
      target_term: "Monthly net orders",
      suggested_text: "Monthly net orders.",
      status: "PROPOSED",
      occurrences: 4,
      examples: [{ conversation_id: "conv_1", question_excerpt: "what are МНО?" }],
      hidden_examples: 2,
    }],
    versions: [{ version: 3, content_hash: "sha256:livehash", change_kind: "EDIT", created_at: "2026-09-10T00:00:00Z", created_by: "principal_owner" }],
    workspaceID: "ws_1",
    initialTab: "proposals",
    onChange: () => {},
  }));
  check(editableSurface.includes("Proposals"), "an editable surface shows the Proposals tab");
  check(editableSurface.includes("Accept") && editableSurface.includes("Edit") && editableSurface.includes("Reject"), "proposal actions are offered");
  check(editableSurface.includes("conv_1") || editableSurface.includes("what are МНО?"), "proposal examples render a conversation link");

  // --- 4. Accept sends If-Match -------------------------------------------
  const acceptStub = installFetchStub([{ match: (path, method) => method === "POST" && path.endsWith(":accept"), status: 200, body: rawContext }]);
  try {
    await sendModelContextProposalAccept("ws_1", contextV3, "prop_1", { term: "МНО", synonyms: ["mno"], definition: "Monthly net orders." });
  } finally {
    acceptStub.restore();
  }
  const accept = acceptStub.calls.find((call) => call.method === "POST");
  check(accept !== undefined, "the accept sent a POST");
  if (accept !== undefined) {
    check(accept.path === "/api/v1/workspaces/ws_1/model-context/proposals/prop_1:accept", `the accept path addresses the proposal (got ${accept.path})`);
    check(accept.headers["If-Match"] === "\"sha256:livehash\"", `the accept sends a quoted If-Match on the current hash (got ${accept.headers["If-Match"]})`);
    check(/^[A-Za-z0-9_-]{43}$/.test(accept.headers["Idempotency-Key"] ?? ""), "the accept sends a fresh Idempotency-Key");
    checkEqual(accept.body, { term: "МНО", synonyms: ["mno"], definition: "Monthly net orders." }, "the accept body carries only the inline edits");
  }

  // --- 5. «Использованы термины» line -------------------------------------
  const sampleToolLoop = {
    model: "test-model",
    stop_reason: "COMPLETED",
    all_claims_bound: true,
    calls: [],
    workspace_context: {
      version: 3,
      content_hash: "sha256:livehash",
      truncated: false,
      terms: [
        { term_id: "term_1", term: "МНО", matched_text: "мно", locations: [{ source_connection_id: "conn_1", relation: "public.t", column: "" }] },
        { term_id: "term_2", term: "ВП", matched_text: "вп", locations: [{ source_connection_id: "conn_1", relation: "public.u", column: "c" }] },
      ],
    },
  };
  const expectedLine = "Использованы термины: МНО → public.t, ВП → public.u.c (контекст v3)";
  check(workspaceContextUsageLineFromToolLoop(sampleToolLoop) === expectedLine, `the usage projection renders the contract line (got ${workspaceContextUsageLineFromToolLoop(sampleToolLoop)})`);
  const usageMarkup = renderToStaticMarkup(createElement(WorkspaceContextUsage, { toolLoop: sampleToolLoop }));
  check(usageMarkup.includes(expectedLine), "WorkspaceContextUsage renders the terms line");
  check(renderToStaticMarkup(createElement(WorkspaceContextUsage, { toolLoop: { ...sampleToolLoop, workspace_context: { ...sampleToolLoop.workspace_context, terms: [] } } })) === "", "no terms means no line");
  check(renderToStaticMarkup(createElement(WorkspaceContextUsage, { toolLoop: undefined })) === "", "no tool loop means no line");
  check(workspaceContextUsageLineFromToolLoop({ workspace_context: { version: 1, terms: [{ term: 7 }] } }) === null, "a malformed workspace_context is rejected, not rendered");

  // --- 6. No HTML injection ------------------------------------------------
  const injectionTerm = {
    id: "term_x",
    term: "<script>alert(1)</script>",
    synonyms: ["<img src=x onerror=alert(1)>"],
    definition: "<b>bold</b>",
    data_locations: [],
  };
  const injectionDocument: ModelContextDocument = { ...contextV3.document, glossary: [injectionTerm] };
  const injectionMarkup = renderToStaticMarkup(createElement(ModelContextEditorSurface, {
    context: { ...contextV3, editable: false },
    document: injectionDocument,
    proposals: [],
    versions: [],
    workspaceID: "ws_1",
    initialTab: "glossary",
    onChange: () => {},
  }));
  check(!injectionMarkup.includes("<script>"), "a glossary term never renders a script element");
  check(!injectionMarkup.includes("<img"), "a synonym never renders an inline element");
  check(injectionMarkup.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "the script-like term is escaped as text");
  check(injectionMarkup.includes("&lt;b&gt;bold&lt;/b&gt;"), "the definition is escaped as text");

  const injectionUsage = renderToStaticMarkup(createElement(WorkspaceContextUsage, {
    toolLoop: { workspace_context: { version: 1, terms: [{ term: "<script>alert(1)</script>", locations: [] }] } },
  }));
  check(!injectionUsage.includes("<script>"), "a matched term never renders a script element");
  check(injectionUsage.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "a matched term is escaped as text");

  if (failures !== 0) throw new Error(`${failures} model-context probe assertion(s) failed`);
  console.log("model context probe: PASS");
}

void main();
