// S2 card D: the workspace model context. The REST contract is S2-CONTRACT.md
// (card A0's internal/workspacecontext types). Everything the browser sends or
// trusts is decoded here, strictly and fail-closed: a response that does not
// match the documented shape is rejected rather than rendered as if it did.
//
// This module is deliberately transport-free. It owns the wire shapes, the
// decoders, the request descriptors and the one presentation projection
// (workspaceContextUsageLine). main.tsx performs the actual fetch calls with
// the descriptors so the tests can assert the exact headers and body of every
// mutation without a server or a DOM.

// ---------------------------------------------------------------------------
// Wire shapes. Optional members are optional only where the contract documents
// them as such; an absent collection decodes to an empty one, while a present
// value of the wrong type is a decode failure.
// ---------------------------------------------------------------------------

export const MODEL_CONTEXT_DESCRIPTION_MAX = 4000;
export const MODEL_CONTEXT_INSTRUCTIONS_MAX = 16000;
export const MODEL_CONTEXT_GLOSSARY_TEXT_MAX = 64000;
export const MODEL_CONTEXT_RULES_MAX = 30;
export const MODEL_CONTEXT_RULE_TEXT_MAX = 500;
export const MODEL_CONTEXT_EMPTY_HASH = "sha256:empty";

export type ModelContextDataLocation = {
  source_connection_id: string;
  relation: string;
  column?: string;
  hint?: string;
};

export type ModelContextTerm = {
  id: string;
  term: string;
  synonyms: string[];
  definition: string;
  data_locations: ModelContextDataLocation[];
};

export type ModelContextRule = {
  id: string;
  text: string;
};

export type ModelContextColumn = {
  name: string;
  note?: string;
};

export type ModelContextTable = {
  relation: string;
  note?: string;
  columns: ModelContextColumn[];
};

export type ModelContextSource = {
  source_connection_id: string;
  description?: string;
  tables: ModelContextTable[];
};

export type ModelContextDocument = {
  description: string;
  // Card W-2: the three plain-text fields the Settings screen edits. A
  // workspace whose rules and glossary predate the card returns their readable
  // text here (the server renders the structured records), so the field is the
  // one place an administrator reads and writes them.
  instructions: string;
  glossary_text: string;
  rules: ModelContextRule[];
  glossary: ModelContextTerm[];
  sources: ModelContextSource[];
};

export type ModelContext = {
  version: number;
  content_hash: string;
  editable: boolean;
  document: ModelContextDocument;
  updated_at?: string;
  updated_by?: string;
};

export type ModelContextProposalExample = {
  conversation_id: string;
  question_excerpt: string;
};

export type ModelContextProposal = {
  proposal_id: string;
  kind: string;
  candidate_term: string;
  target_term_id?: string;
  target_term?: string;
  suggested_text: string;
  status: string;
  occurrences: number;
  created_at?: string;
  examples: ModelContextProposalExample[];
  hidden_examples: number;
};

export type ModelContextVersion = {
  version: number;
  content_hash: string;
  change_kind: string;
  created_at?: string;
  created_by?: string;
  proposal_id?: string;
};

export type ModelContextProposalEdits = {
  term?: string;
  synonyms?: string[];
  definition?: string;
};

// The tool-loop observer projection. It is nested under a question run's
// tool_loop as `workspace_context`; the UI renders one summary line from it.
export type WorkspaceContextUsageLocation = {
  relation: string;
  column: string;
};

export type WorkspaceContextUsageTerm = {
  term: string;
  locations: WorkspaceContextUsageLocation[];
};

export type WorkspaceContextUsage = {
  version: number;
  terms: WorkspaceContextUsageTerm[];
};

// ---------------------------------------------------------------------------
// Strict decoding. A malformed member throws DecodeError internally and the
// public decoder converts that into null, so callers cannot accidentally use
// a partially decoded object.
// ---------------------------------------------------------------------------

class DecodeError extends Error {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new DecodeError(`${label} must be an object`);
  return value;
}

function stringValue(record: Record<string, unknown>, key: string, label: string): string {
  const value = record[key];
  if (typeof value !== "string") throw new DecodeError(`${label}.${key} must be a string`);
  return value;
}

function optionalStringValue(record: Record<string, unknown>, key: string, label: string): string | undefined {
  const value = record[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new DecodeError(`${label}.${key} must be a string`);
  return value;
}

function numberValue(record: Record<string, unknown>, key: string, label: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isFinite(value)) throw new DecodeError(`${label}.${key} must be a number`);
  return value;
}

function arrayValue(record: Record<string, unknown>, key: string, label: string): unknown[] {
  const value = record[key];
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new DecodeError(`${label}.${key} must be an array`);
  return value;
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function decodeDataLocation(value: unknown): ModelContextDataLocation {
  const record = objectValue(value, "data_location");
  const column = optionalStringValue(record, "column", "data_location");
  const hint = optionalStringValue(record, "hint", "data_location");
  return {
    source_connection_id: stringValue(record, "source_connection_id", "data_location"),
    relation: stringValue(record, "relation", "data_location"),
    ...(column !== undefined ? { column } : {}),
    ...(hint !== undefined ? { hint } : {}),
  };
}

function decodeTerm(value: unknown): ModelContextTerm {
  const record = objectValue(value, "glossary_term");
  return {
    id: stringValue(record, "id", "glossary_term"),
    term: stringValue(record, "term", "glossary_term"),
    synonyms: arrayValue(record, "synonyms", "glossary_term").map((synonym) => {
      if (typeof synonym !== "string") throw new DecodeError("glossary_term.synonyms must contain strings");
      return synonym;
    }),
    definition: stringValue(record, "definition", "glossary_term"),
    data_locations: arrayValue(record, "data_locations", "glossary_term").map(decodeDataLocation),
  };
}

function decodeRule(value: unknown): ModelContextRule {
  const record = objectValue(value, "rule");
  return { id: stringValue(record, "id", "rule"), text: stringValue(record, "text", "rule") };
}

function decodeColumn(value: unknown): ModelContextColumn {
  const record = objectValue(value, "column");
  const note = optionalStringValue(record, "note", "column");
  return { name: stringValue(record, "name", "column"), ...(note !== undefined ? { note } : {}) };
}

function decodeTable(value: unknown): ModelContextTable {
  const record = objectValue(value, "table");
  const note = optionalStringValue(record, "note", "table");
  return {
    relation: stringValue(record, "relation", "table"),
    ...(note !== undefined ? { note } : {}),
    columns: arrayValue(record, "columns", "table").map(decodeColumn),
  };
}

function decodeSource(value: unknown): ModelContextSource {
  const record = objectValue(value, "source");
  const description = optionalStringValue(record, "description", "source");
  return {
    source_connection_id: stringValue(record, "source_connection_id", "source"),
    ...(description !== undefined ? { description } : {}),
    tables: arrayValue(record, "tables", "source").map(decodeTable),
  };
}

export function decodeModelContextDocument(value: unknown): ModelContextDocument | null {
  try {
    const record = objectValue(value, "document");
    return {
      description: stringValue(record, "description", "document"),
      instructions: stringValue(record, "instructions", "document"),
      glossary_text: stringValue(record, "glossary_text", "document"),
      rules: arrayValue(record, "rules", "document").map(decodeRule),
      glossary: arrayValue(record, "glossary", "document").map(decodeTerm),
      sources: arrayValue(record, "sources", "document").map(decodeSource),
    };
  } catch {
    return null;
  }
}

export function decodeModelContext(value: unknown): ModelContext | null {
  try {
    const record = objectValue(value, "model_context");
    const version = numberValue(record, "version", "model_context");
    if (!Number.isSafeInteger(version) || version < 0) throw new DecodeError("model_context.version must be a non-negative integer");
    const document = decodeModelContextDocument(record.document);
    if (document === null) throw new DecodeError("model_context.document is malformed");
    const updatedAt = optionalStringValue(record, "updated_at", "model_context");
    const updatedBy = optionalStringValue(record, "updated_by", "model_context");
    return {
      version,
      content_hash: stringValue(record, "content_hash", "model_context"),
      editable: record.editable === true,
      document,
      ...(updatedAt !== undefined ? { updated_at: updatedAt } : {}),
      ...(updatedBy !== undefined ? { updated_by: updatedBy } : {}),
    };
  } catch {
    return null;
  }
}

function decodeProposalExample(value: unknown): ModelContextProposalExample {
  const record = objectValue(value, "proposal_example");
  return {
    conversation_id: stringValue(record, "conversation_id", "proposal_example"),
    question_excerpt: stringValue(record, "question_excerpt", "proposal_example"),
  };
}

function decodeProposal(value: unknown): ModelContextProposal {
  const record = objectValue(value, "proposal");
  const targetTermID = optionalStringValue(record, "target_term_id", "proposal");
  const targetTerm = optionalStringValue(record, "target_term", "proposal");
  const createdAt = optionalStringValue(record, "created_at", "proposal");
  return {
    proposal_id: stringValue(record, "proposal_id", "proposal"),
    kind: stringValue(record, "kind", "proposal"),
    candidate_term: stringValue(record, "candidate_term", "proposal"),
    ...(targetTermID !== undefined ? { target_term_id: targetTermID } : {}),
    ...(targetTerm !== undefined ? { target_term: targetTerm } : {}),
    suggested_text: stringValue(record, "suggested_text", "proposal"),
    status: stringValue(record, "status", "proposal"),
    occurrences: numberValue(record, "occurrences", "proposal"),
    ...(createdAt !== undefined ? { created_at: createdAt } : {}),
    examples: arrayValue(record, "examples", "proposal").map(decodeProposalExample),
    hidden_examples: numberValue(record, "hidden_examples", "proposal"),
  };
}

// decodeModelContextProposals reads {proposals: [...]}. A malformed envelope
// decodes to null; a valid envelope never drops an item silently.
export function decodeModelContextProposals(value: unknown): ModelContextProposal[] | null {
  try {
    const record = objectValue(value, "proposals");
    return arrayValue(record, "proposals", "proposals").map(decodeProposal);
  } catch {
    return null;
  }
}

function decodeVersion(value: unknown): ModelContextVersion {
  const record = objectValue(value, "version");
  const version = numberValue(record, "version", "version");
  if (!Number.isSafeInteger(version) || version < 0) throw new DecodeError("version.version must be a non-negative integer");
  const createdAt = optionalStringValue(record, "created_at", "version");
  const createdBy = optionalStringValue(record, "created_by", "version");
  const proposalID = optionalStringValue(record, "proposal_id", "version");
  return {
    version,
    content_hash: stringValue(record, "content_hash", "version"),
    change_kind: stringValue(record, "change_kind", "version"),
    ...(createdAt !== undefined ? { created_at: createdAt } : {}),
    ...(createdBy !== undefined ? { created_by: createdBy } : {}),
    ...(proposalID !== undefined ? { proposal_id: proposalID } : {}),
  };
}

// decodeModelContextVersions reads {versions: [...], next_cursor?}.
export function decodeModelContextVersions(value: unknown): ModelContextVersion[] | null {
  try {
    const record = objectValue(value, "versions");
    return arrayValue(record, "versions", "versions").map(decodeVersion);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Request descriptors. main.tsx uses these verbatim; the tests assert them.
// ---------------------------------------------------------------------------

export type ModelContextMutationRequest = {
  method: "PUT" | "POST";
  path: string;
  body: unknown;
  ifMatch: string;
  idempotencyKey: string;
};

export function modelContextPath(workspaceID: string): string {
  return `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/model-context`;
}

// A workspace that has never had a context answers version 0; its If-Match is
// the documented "sha256:empty" sentinel, never a fabricated hash.
export function modelContextIfMatch(context: Pick<ModelContext, "version" | "content_hash">): string {
  return context.version === 0 ? MODEL_CONTEXT_EMPTY_HASH : context.content_hash;
}

export function modelContextSaveRequest(
  workspaceID: string,
  context: Pick<ModelContext, "version" | "content_hash">,
  document: ModelContextDocument,
  idempotencyKey: string,
): ModelContextMutationRequest {
  return {
    method: "PUT",
    path: modelContextPath(workspaceID),
    body: { document: modelContextDocumentForSave(document) },
    ifMatch: modelContextIfMatch(context),
    idempotencyKey,
  };
}

// modelContextDocumentForSave drops empty optional members (a cleared note,
// column or hint) instead of sending an empty string, and keeps a new item's
// deliberate empty id so the server assigns the real one. Rules and synonyms
// are sent exactly as the owner left them.
export function modelContextDocumentForSave(document: ModelContextDocument): ModelContextDocument {
  return {
    description: document.description,
    instructions: document.instructions,
    glossary_text: document.glossary_text,
    rules: document.rules.map((rule) => ({ id: rule.id, text: rule.text })),
    glossary: document.glossary.map((term) => ({
      id: term.id,
      term: term.term,
      synonyms: term.synonyms.filter((synonym) => synonym.length > 0),
      definition: term.definition,
      data_locations: term.data_locations.map((location) => ({
        source_connection_id: location.source_connection_id,
        relation: location.relation,
        ...(location.column ? { column: location.column } : {}),
        ...(location.hint ? { hint: location.hint } : {}),
      })),
    })),
    sources: document.sources.map((source) => ({
      source_connection_id: source.source_connection_id,
      ...(source.description ? { description: source.description } : {}),
      tables: source.tables.map((table) => ({
        relation: table.relation,
        ...(table.note ? { note: table.note } : {}),
        columns: table.columns.map((column) => ({
          name: column.name,
          ...(column.note ? { note: column.note } : {}),
        })),
      })),
    })),
  };
}

export function modelContextProposalPath(workspaceID: string, proposalID: string): string {
  return `${modelContextPath(workspaceID)}/proposals/${encodeURIComponent(proposalID)}`;
}

export function modelContextAcceptRequest(
  workspaceID: string,
  context: Pick<ModelContext, "version" | "content_hash">,
  proposalID: string,
  edits: ModelContextProposalEdits | undefined,
  idempotencyKey: string,
): ModelContextMutationRequest {
  const body = edits === undefined ? undefined : {
    ...(edits.term !== undefined ? { term: edits.term } : {}),
    ...(edits.synonyms !== undefined ? { synonyms: edits.synonyms } : {}),
    ...(edits.definition !== undefined ? { definition: edits.definition } : {}),
  };
  return {
    method: "POST",
    path: `${modelContextProposalPath(workspaceID, proposalID)}:accept`,
    body,
    ifMatch: modelContextIfMatch(context),
    idempotencyKey,
  };
}

export function modelContextRestoreRequest(
  workspaceID: string,
  context: Pick<ModelContext, "version" | "content_hash">,
  version: number,
  idempotencyKey: string,
): ModelContextMutationRequest {
  return {
    method: "POST",
    path: `${modelContextPath(workspaceID)}/versions/${encodeURIComponent(String(version))}:restore`,
    body: undefined,
    ifMatch: modelContextIfMatch(context),
    idempotencyKey,
  };
}

// ---------------------------------------------------------------------------
// Tool-loop usage projection. The line is rendered as a React text child, so a
// term is never interpreted as markup.
// ---------------------------------------------------------------------------

export function decodeWorkspaceContextUsage(value: unknown): WorkspaceContextUsage | null {
  try {
    const record = objectValue(value, "workspace_context");
    const version = numberValue(record, "version", "workspace_context");
    if (!Number.isSafeInteger(version) || version < 0) throw new DecodeError("workspace_context.version must be a non-negative integer");
    const terms = arrayValue(record, "terms", "workspace_context").map((value): WorkspaceContextUsageTerm => {
      const termRecord = objectValue(value, "workspace_context.term");
      const locations = arrayValue(termRecord, "locations", "workspace_context.term").map((value): WorkspaceContextUsageLocation => {
        const locationRecord = objectValue(value, "workspace_context.location");
        // column is documented as always present (possibly empty).
        const column = optionalStringValue(locationRecord, "column", "workspace_context.location") ?? "";
        return { relation: stringValue(locationRecord, "relation", "workspace_context.location"), column };
      });
      return { term: stringValue(termRecord, "term", "workspace_context.term"), locations };
    });
    return { version, terms };
  } catch {
    return null;
  }
}

// workspaceContextUsageLine renders the single summary line above the tool-calls
// disclosure: each term points at its first location's relation.column, and the
// shared context version is appended once. Terms with no location show a bare
// term rather than a fabricated address.
export function workspaceContextUsageLine(usage: WorkspaceContextUsage | null): string | null {
  if (usage === null || usage.terms.length === 0) return null;
  const parts = usage.terms.map((entry) => {
    const location = entry.locations[0];
    if (location === undefined) return entry.term;
    return `${entry.term} → ${location.column ? `${location.relation}.${location.column}` : location.relation}`;
  });
  return `Использованы термины: ${parts.join(", ")} (контекст v${usage.version})`;
}

export function workspaceContextUsageLineFromToolLoop(toolLoop: unknown): string | null {
  if (!isPlainObject(toolLoop)) return null;
  return workspaceContextUsageLine(decodeWorkspaceContextUsage(toolLoop.workspace_context));
}

// ---------------------------------------------------------------------------
// Draft helpers. A new item is sent with an empty id so the server assigns it.
// ---------------------------------------------------------------------------

export function emptyModelContextDocument(): ModelContextDocument {
  return { description: "", instructions: "", glossary_text: "", rules: [], glossary: [], sources: [] };
}

export function cloneModelContextDocument(document: ModelContextDocument): ModelContextDocument {
  return {
    description: document.description,
    instructions: document.instructions,
    glossary_text: document.glossary_text,
    rules: document.rules.map((rule) => ({ ...rule })),
    glossary: document.glossary.map((term) => ({
      ...term,
      synonyms: [...term.synonyms],
      data_locations: term.data_locations.map((location) => ({ ...location })),
    })),
    sources: document.sources.map((source) => ({
      ...source,
      tables: source.tables.map((table) => ({
        ...table,
        columns: table.columns.map((column) => ({ ...column })),
      })),
    })),
  };
}

export function newModelContextRule(): ModelContextRule {
  return { id: "", text: "" };
}

export function newModelContextTerm(): ModelContextTerm {
  return { id: "", term: "", synonyms: [], definition: "", data_locations: [newModelContextLocation()] };
}

export function newModelContextLocation(): ModelContextDataLocation {
  return { source_connection_id: "", relation: "" };
}

// fieldErrorsFromFields maps the server's error.fields names to one display
// message each. It never invents fields the server did not name.
export function fieldErrorsFromServerFields(fields: readonly string[]): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const field of fields) {
    if (field.length === 0 || hasOwn(errors, field)) continue;
    errors[field] = "The server rejected this value.";
  }
  return errors;
}
