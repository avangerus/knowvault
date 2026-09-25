import { useCallback, useEffect, useLayoutEffect, useMemo, useReducer, useRef, useState } from "react";
import type { ComponentType, CSSProperties, FormEvent, KeyboardEvent as ReactKeyboardEvent, MouseEvent as ReactMouseEvent, ReactNode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import { BOUND_CLAIM_LABEL, citationGroundingText, KNOWLEDGE_TOOL_LABELS, NO_DATA_IN_WORKSPACE_LABEL, TOOL_CALLS_TITLE, UNBOUND_CLAIM_LABEL } from "./knowledge-labels";
import { GovernedPresetPanel, type GovernedCatalogAvailability } from "./governed-presets";
import { PendingAction, type PendingActionKind, type PendingActionState, type PendingActionStep } from "./pending-action";
import { toolCallSummary } from "./tool-call-summary";
import { observationForGeneration, readQuestionStream, type QuestionActionFrame, type QuestionActionLabel } from "./question-stream";
import {
  MODEL_CONTEXT_DESCRIPTION_MAX, MODEL_CONTEXT_GLOSSARY_TEXT_MAX, MODEL_CONTEXT_INSTRUCTIONS_MAX,
  cloneModelContextDocument, decodeModelContext, decodeModelContextProposals, decodeModelContextVersions,
  fieldErrorsFromServerFields, modelContextAcceptRequest, modelContextPath, modelContextProposalPath,
  modelContextRestoreRequest, modelContextSaveRequest,
  workspaceContextUsageLineFromToolLoop,
  type ModelContext, type ModelContextDocument, type ModelContextProposal,
  type ModelContextProposalEdits, type ModelContextVersion,
} from "./model-context";

// ---------------------------------------------------------------------------
// Icons: inline SVG, one stroke weight, no icon font and no Unicode glyphs
// standing in for meaning (design review #2, #3, #10). Every icon below is
// used verbatim from the approved reference so the brand mark, section icons
// and status glyphs are pixel-identical to the reference.
// ---------------------------------------------------------------------------

function IconLogo() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24"><path d="M4 12L12 4l8 8-8 8-8-8Z" stroke="#fff" strokeLinejoin="round" strokeWidth="1.6" /></svg>
  );
}
function IconQuestions() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24"><path d="M4 5h16v11H8l-4 4V5Z" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.6" /></svg>
  );
}
function IconSources() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M4 6c0-1.1 3.6-2 8-2s8 .9 8 2-3.6 2-8 2-8-.9-8-2Z" stroke="currentColor" strokeWidth="1.6" />
      <path d="M4 6v12c0 1.1 3.6 2 8 2s8-.9 8-2V6" stroke="currentColor" strokeWidth="1.6" />
      <path d="M4 12c0 1.1 3.6 2 8 2s8-.9 8-2" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}
function IconAccess() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <circle cx="8.5" cy="8.5" r="3.5" stroke="currentColor" strokeWidth="1.6" />
      <path d="M11 11l8 8m-3-3 2.2-2.2" stroke="currentColor" strokeLinecap="round" strokeWidth="1.6" />
    </svg>
  );
}
function IconDocument({ withHeaderLine = false }: { withHeaderLine?: boolean }) {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M6 3h9l3 3v15H6V3Z" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.6" />
      <path d={withHeaderLine ? "M9 12h6M9 16h6M9 8h3" : "M9 12h6M9 16h6"} stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}
function IconInfo() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
      <path d="M12 11v5.5M12 8v.01" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </svg>
  );
}
function IconShield() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M12 3 5 6v6c0 4.4 3 8 7 9 4-1 7-4.6 7-9V6z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.6" />
    </svg>
  );
}
function IconCheckCircle() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8 12.5l2.5 2.5L16 9.5" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
    </svg>
  );
}
function IconAlertTriangle() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M12 3l9 16H3L12 3Z" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.6" />
      <path d="M12 10v4M12 16.5v.01" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </svg>
  );
}
function IconChevron({ up }: { up: boolean }) {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d={up ? "M6 15l6-6 6 6" : "M6 9l6 6 6-6"} stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
    </svg>
  );
}
function IconJournal() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M6 4h12a1 1 0 0 1 1 1v15l-3-2-3 2-3-2-3 2V5a1 1 0 0 1 1-1Z" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.6" />
      <path d="M9 9h6M9 13h6" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}
function IconExpand() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </svg>
  );
}
function IconCollapse() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
    </svg>
  );
}
function IconPlus() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path d="M12 5v14M5 12h14" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </svg>
  );
}
function IconTable() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <rect height="16" rx="1.5" stroke="currentColor" strokeWidth="1.6" width="18" x="3" y="4" />
      <path d="M3 9h18M3 14.5h18M9 9v11" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}
function IconSettings() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="3.2" stroke="currentColor" strokeWidth="1.6" />
      <path d="M12 3.5v2.2M12 18.3v2.2M20.5 12h-2.2M5.7 12H3.5M18.01 5.99l-1.56 1.56M7.55 16.45l-1.56 1.56M18.01 18.01l-1.56-1.56M7.55 7.55 5.99 5.99" stroke="currentColor" strokeLinecap="round" strokeWidth="1.6" />
    </svg>
  );
}

// Exactly three top-level sections (decision 9, anti-SAP): Search is the
// screen a person actually works in; Sources is the rare "connect data"
// journey a data owner walks without IT; the audit journal stays within
// Access as a secondary tab because "who did what" is a property of access.
// S2 adds Settings beside them: the workspace's own model context, which the
// same owner who manages sources curates.
type Section = "search" | "sources" | "access" | "settings";

export type EvidenceQuoteSelector = {
  start: number;
  end: number;
  text_hash: string;
  source_version_id: string;
  extraction_id: string;
  anchor: string;
};

export type EvidenceTarget = { workspace: string; fragment: string; canonicalAddress?: string; selector?: EvidenceQuoteSelector; returnConversation?: string };

export type VerifiedEvidenceQuote = { start: number; end: number; text: string };

// FIX-2 #1/#3 shared shapes: server-computed snapshot identity a structured
// aggregate or a rowset evidence fragment was reduced from. Never invented
// client-side — every field here is data the server already used to render
// its own prose answer (structured_result.go's AnswerSnapshot).
type AnswerSnapshot = {
  id?: string;
  captured_at?: string;
  row_count: number;
};

type RowsetEvidence = {
  columns: string[];
  rows: Record<string, string>[];
  total: number;
  filter_label?: string;
  snapshot: AnswerSnapshot;
};

export type EvidenceData = {
  fragment_id: string;
  text: string;
  anchor: string;
  source_path?: string;
  source_page_url?: string;
  canonical_address?: string;
  address?: unknown;
  is_current_version?: boolean;
  provenance: {
    extraction_id: string;
    source_version_id: string;
    ordinal: number;
    external_version_key: string;
    content_hash: string;
    observed_at: string;
    source_object_id: string;
    connection_id: string;
  };
  // FIX-2 #3: present only for a fragment of a structured source scope; a
  // document fragment carries no rowset at all.
  rowset?: RowsetEvidence;
};

// Evidence deeplink: #evidence/{workspace}/{fragment}. The target ids come from
// the URL. An optional quote selector is deliberately all-or-nothing and is
// only a request: the viewer rechecks every identity, rune bound and hash after
// it fetches the currently authorized fragment. Invalid selectors leave a
// valid bare-fragment route and never claim an exact quote.
const evidenceSelectorKeys = ["quote_start", "quote_end", "quote_hash", "quote_version", "quote_extraction", "quote_anchor"] as const;

function isEvidenceQuoteSelector(value: unknown): value is EvidenceQuoteSelector {
  if (value === null || typeof value !== "object") return false;
  const selector = value as Partial<EvidenceQuoteSelector>;
  return Number.isSafeInteger(selector.start) && (selector.start ?? -1) >= 0
    && Number.isSafeInteger(selector.end) && (selector.end ?? -1) > (selector.start ?? Number.MAX_SAFE_INTEGER)
    && typeof selector.text_hash === "string" && /^sha256:[0-9a-f]{64}$/.test(selector.text_hash)
    && typeof selector.source_version_id === "string" && selector.source_version_id.length > 0
    && typeof selector.extraction_id === "string" && selector.extraction_id.length > 0
    && typeof selector.anchor === "string" && selector.anchor.length > 0;
}

export function buildEvidenceHash(target: EvidenceTarget): string {
  const base = `#evidence/${encodeURIComponent(target.workspace)}/${encodeURIComponent(target.fragment)}`;
  const params = new URLSearchParams();
  if (target.canonicalAddress !== undefined) params.set("address", target.canonicalAddress);
  if (target.returnConversation) params.set("from", target.returnConversation);
  if (!target.selector || !isEvidenceQuoteSelector(target.selector)) return params.size ? `${base}?${params.toString()}` : base;
  params.set("quote_start", String(target.selector.start));
  params.set("quote_end", String(target.selector.end));
  params.set("quote_hash", target.selector.text_hash);
  params.set("quote_version", target.selector.source_version_id);
  params.set("quote_extraction", target.selector.extraction_id);
  params.set("quote_anchor", target.selector.anchor);
  return `${base}?${params.toString()}`;
}

export function evidenceRequestPath(target: Pick<EvidenceTarget, "workspace" | "fragment" | "canonicalAddress">): string {
  const base = `/api/v1/workspaces/${encodeURIComponent(target.workspace)}/evidence/${encodeURIComponent(target.fragment)}`;
  return target.canonicalAddress === undefined ? base : `${base}?${new URLSearchParams({ address: target.canonicalAddress })}`;
}

// A configured public origin can differ from the browser alias used to reach
// this deployment. Prefer the authorized server URL after checking that it is
// an HTTPS UI route for this exact fragment and canonical address. A present
// but malformed server URL fails closed; only an omitted field uses the legacy
// same-origin route. The caller binds the response to its complete request path.
// A verified ref, subspan or whole-object request may resolve to the canonical
// fragment address returned by the server, so their address strings can differ.
export function evidencePageHref(
  evidence: EvidenceData,
  request: Pick<EvidenceTarget, "workspace" | "fragment" | "canonicalAddress" | "returnConversation">,
  selector: EvidenceQuoteSelector | null,
  legacyBase?: string,
): string | null {
  if (!request.workspace || !request.fragment || evidence.fragment_id !== request.fragment) return null;

  const target: EvidenceTarget = {
    workspace: request.workspace,
    fragment: request.fragment,
    ...(evidence.canonical_address !== undefined ? { canonicalAddress: evidence.canonical_address } : {}),
    ...(selector ? { selector } : {}),
    ...(request.returnConversation ? { returnConversation: request.returnConversation } : {}),
  };
  const hasServerURL = Object.prototype.hasOwnProperty.call(evidence, "source_page_url");
  if (hasServerURL) {
    if (typeof evidence.source_page_url !== "string" || evidence.source_page_url.length === 0) return null;
    try {
      const url = new URL(evidence.source_page_url);
      if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "") return null;
      const serverTarget = parseEvidenceHash(url.hash);
      if (!serverTarget || serverTarget.workspace !== request.workspace || serverTarget.fragment !== request.fragment
        || serverTarget.canonicalAddress !== evidence.canonical_address) return null;
      url.hash = buildEvidenceHash(target);
      return url.href;
    } catch {
      return null;
    }
  }

  if (!legacyBase) return null;
  try {
    const url = new URL(legacyBase);
    url.hash = buildEvidenceHash(target);
    return url.href;
  } catch {
    return null;
  }
}

function decodeEvidencePathSegment(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    return decoded.length > 0 && !decoded.includes("/") ? decoded : null;
  } catch {
    return null;
  }
}

export type SearchTarget = { workspace: string; conversation?: string };

export function buildSearchHash(workspaceID: string, conversationID?: string | null): string {
  const base = `#search/${encodeURIComponent(workspaceID)}`;
  return conversationID ? `${base}?${new URLSearchParams({ conversation: conversationID }).toString()}` : base;
}

export function parseSearchHash(hash: string): SearchTarget | null {
  const match = hash.match(/^#search\/([^/?#]+)(?:\?(.*))?$/);
  if (!match) return null;
  const workspace = decodeEvidencePathSegment(match[1]);
  if (!workspace) return null;
  if (!match[2]) return { workspace };
  const params = new URLSearchParams(match[2]);
  if ([...params.keys()].length !== 1 || params.getAll("conversation").length !== 1) return null;
  const conversation = params.get("conversation");
  return conversation ? { workspace, conversation } : null;
}

export function shouldHandleInAppEvidenceClick(event: Pick<MouseEvent, "button" | "ctrlKey" | "metaKey" | "shiftKey" | "altKey">): boolean {
  return event.button === 0 && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey;
}

export function openEvidenceHistory(
  hash: string,
  workspaceID: string | null,
  conversationID: string | null,
  history: Pick<History, "replaceState" | "pushState">,
  pathname: string,
  search: string,
  navigationSession: string,
): string | null {
  const target = parseEvidenceHash(hash);
  if (!target) return null;
  const searchHash = buildSearchHash(workspaceID ?? target.workspace, conversationID);
  const base = `${pathname}${search}`;
  // Keep the current conversation in the retained search entry. Queries,
  // answers and source text stay in the mounted, session-scoped SearchView.
  history.replaceState(null, "", `${base}${searchHash}`);
  history.pushState({ knowvaultSearchReturn: navigationSession }, "", `${base}${hash}`);
  return searchHash;
}

export function parseEvidenceHash(hash: string): EvidenceTarget | null {
  const match = hash.match(/^#evidence\/([^/?#]+)\/([^/?#]+)(?:\?(.*))?$/);
  if (!match) return null;
  const workspace = decodeEvidencePathSegment(match[1]);
  const fragment = decodeEvidencePathSegment(match[2]);
  if (!workspace || !fragment) return null;
  const target: EvidenceTarget = { workspace, fragment };
  const rawSelector = match[3];
  if (rawSelector === undefined || rawSelector.length === 0) return target;

  const params = new URLSearchParams(rawSelector);
  if (params.has("address")) {
    if (params.getAll("address").length !== 1 || !params.get("address")) return null;
    target.canonicalAddress = params.get("address")!;
    params.delete("address");
  }
  if (params.has("from")) {
    if (params.getAll("from").length !== 1 || !params.get("from")) return null;
    target.returnConversation = params.get("from")!;
    params.delete("from");
  }
  const keys = [...params.keys()];
  if (keys.length !== evidenceSelectorKeys.length || keys.some((key) => !evidenceSelectorKeys.includes(key as typeof evidenceSelectorKeys[number]))) return target;
  if (evidenceSelectorKeys.some((key) => params.getAll(key).length !== 1)) return target;
  const startText = params.get("quote_start");
  const endText = params.get("quote_end");
  if (startText === null || endText === null || !/^(0|[1-9][0-9]*)$/.test(startText) || !/^(0|[1-9][0-9]*)$/.test(endText)) return target;
  const selector: EvidenceQuoteSelector = {
    start: Number(startText),
    end: Number(endText),
    text_hash: params.get("quote_hash") ?? "",
    source_version_id: params.get("quote_version") ?? "",
    extraction_id: params.get("quote_extraction") ?? "",
    anchor: params.get("quote_anchor") ?? "",
  };
  return isEvidenceQuoteSelector(selector) ? { ...target, selector } : target;
}

export function confirmedEvidenceQuoteSelector(citation: QuestionCitation | null | undefined): EvidenceQuoteSelector | null {
  const quote = citation?.source_quote;
  if (!citation || citation.grounding_status !== "CONFIRMED_BY_FRAGMENT" || !quote) return null;
  if (quote.source_version_id !== citation.source_version_id || quote.extraction_id !== citation.extraction_id || quote.anchor !== citation.anchor) return null;
  const selector: EvidenceQuoteSelector = {
    start: quote.start,
    end: quote.end,
    text_hash: quote.text_hash,
    source_version_id: quote.source_version_id,
    extraction_id: quote.extraction_id,
    anchor: quote.anchor,
  };
  return isEvidenceQuoteSelector(selector) ? selector : null;
}

export async function verifyEvidenceQuoteSelector(
  evidence: EvidenceData,
  expectedFragmentID: string,
  selector: EvidenceQuoteSelector,
): Promise<VerifiedEvidenceQuote | null> {
  if (!isEvidenceQuoteSelector(selector) || evidence.fragment_id !== expectedFragmentID) return null;
  if (selector.source_version_id !== evidence.provenance.source_version_id
    || selector.extraction_id !== evidence.provenance.extraction_id
    || selector.anchor !== evidence.anchor) return null;
  const runes = Array.from(evidence.text);
  if (selector.end > runes.length) return null;
  const quotedText = runes.slice(selector.start, selector.end).join("");
  try {
    if (!globalThis.crypto?.subtle) return null;
    const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(quotedText));
    const actualHash = `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    return actualHash === selector.text_hash ? { start: selector.start, end: selector.end, text: quotedText } : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Server response shapes. Every type below mirrors a value the API persists
// and projects; nothing here is invented by the client.
// ---------------------------------------------------------------------------

export type WorkspaceSummary = {
  id: string;
  name: string;
  status: string;
  revision: number;
  role: string;
};

export function activeWorkspaceSummaries(workspaces: readonly WorkspaceSummary[]): WorkspaceSummary[] {
  return workspaces.filter((workspace) => workspace.status === "ACTIVE");
}

export function archivedWorkspaceSummaries(workspaces: readonly WorkspaceSummary[]): WorkspaceSummary[] {
  return workspaces.filter((workspace) => workspace.status === "ARCHIVED");
}

export function automaticWorkspaceSelection(workspaces: readonly WorkspaceSummary[]): string | null {
  return activeWorkspaceSummaries(workspaces)[0]?.id ?? null;
}

type MemberResponse = { principal_id: string; display_name: string; role: string };

// FIX-2 #4: content-free -- mode plus a model id, never an endpoint,
// credential or mount path (see workspaceapi.go's processingModeResponse).
type ProcessingMode = { mode: string; provider?: string };

type ModelProfile = { id: string; label: string; location: "INTERNAL" | "EXTERNAL" };

type WorkspaceSnapshot = {
  id: string;
  name: string;
  description: string;
  status: string;
  revision: number;
  owner_principal_id: string;
  retention_policy_id: string;
  members: MemberResponse[];
  processing_mode: ProcessingMode;
  model_profiles?: Array<ModelProfile & { is_default: boolean }>;
};

type AccessCode = {
  credential_id: string;
  principal_id: string;
  name: string;
  workspace_ids: string[];
  created_at: string;
  expires_at: string;
  revoked_at?: string;
};

type AccessCodeIssued = AccessCode & { code: string };

// R2 Outcome 1: one version of a workspace's MetricDefinition. Every field is
// server-owned; a version the server does not publish renders as “no data”
// rather than an invented value.
type MetricDefinition = {
  id?: string;
  version?: number;
  status?: string;
  name?: string;
  source_connection_id?: string;
  projection_version?: number;
  entity_key?: string;
  grain?: string;
  allowed_filters?: string[];
  unit?: string;
};

type MetricDefinitionList = { definitions: MetricDefinition[] };

const metricDefinitionStatusLabels: Record<string, string> = {
  DRAFT: "Draft",
  APPROVED: "Approved",
  RETIRED: "Retired",
};

const metricGrainLabels: Record<string, string> = {
  DAY: "Day",
  WEEK: "Week",
  MONTH: "Month",
  QUARTER: "Quarter",
  YEAR: "Year",
};

function metricDefinitionField(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "no data";
  return String(value);
}

function metricDefinitionFilters(filters: string[] | undefined): string {
  if (!filters || filters.length === 0) return "no data";
  return filters.join(", ");
}

export type SourceStatus = {
  workspace_source_id: string;
  source_scope_id: string;
  source_scope_revision: number;
  access_mode: string;
  enabled: boolean;
  scope_config_hash: string;
  connection_id: string;
  connection_name: string;
  source_type: string;
  postgresql_schema_name: string | null;
  postgresql_relation_name: string | null;
  activation_status: string;
  trust_verified: boolean;
  sync_status: string | null;
  sync_error_code: string | null;
  sync_started_at: string | null;
  sync_completed_at: string | null;
  objects_seen: number | null;
  objects_ingested: number | null;
  versions_created: number | null;
  evidence_published: number | null;
  quarantined: number | null;
  job_id?: string | null;
  job_status?: string | null;
  job_attempt_count?: number | null;
  job_max_attempts?: number | null;
  job_available_at?: string | null;
  job_lease_expires_at?: string | null;
  job_last_error_code?: string | null;
  content_freshness_sla_seconds: number;
  last_successful_sync_at: string | null;
  freshness_state: string;
  sync_interval_seconds: number;
  confirmed: boolean;
  confirmation_state: "DISABLED" | "NEEDS_GRANT" | "NEEDS_CONFIRMATION" | "NEEDS_TRUST_VERIFICATION" | "READY_TO_ACTIVATE" | "ACTIVE" | string;
  // Source-specific, ADR-0087 §2 SoD-aware refinement of
  // ConfirmationContext.can_verify_connection_trust: false whenever the
  // viewer lacks CONNECTOR_ADMIN, and also false when the viewer has already
  // confirmed a WORKSPACE_MANAGED binding of some scope of this source's own
  // connection (the exact conflict app.source_connection_trust_verify's own
  // separation-of-duty check would then refuse). Gate the verify-trust
  // action on this field, never on the workspace-wide one.
  can_verify_connection_trust: boolean;
  // ADR-0097's per-connection "SQL available" state: the connection revision
  // carries a separate read-only query credential, so knowvault_source_sql can
  // run for its enabled sources. False means "SQL not configured" and the tool
  // answers SOURCE_SQL_NOT_CONFIGURED. It is a display fact, never a grant.
  sql_available?: boolean;
  // S3 card 4's registration mode of this table: true means "only for SQL
  // queries (not indexed)". The Sources card renders it as "только SQL" and
  // shows no sync freshness for the table. A missing field (an older server)
  // reads as indexed, which is the previous behaviour.
  query_only?: boolean;
};

// ADR-0087 §1-§2 operator-visible read: everything needed to build a
// confirmation-grant, managed-source-confirmation or verify-trust command
// body without a database session, plus the caller's own eligibility.
type SelfConfirmationGrant = {
  grant_id: string;
  grant_revision: number;
  grant_hash: string;
  valid_until: string;
};

type ConfirmationContext = {
  expected_policy_revision: string;
  warning_contract: { warning_version: string; warning_contract_hash: string };
  viewer_principal_id: string;
  can_issue_confirmation_grant: boolean;
  // Role-only (CONNECTOR_ADMIN): does NOT account for the ADR-0087 §2
  // verifier/confirmer separation of duty, which is connection-specific.
  // Use each SourceStatus.can_verify_connection_trust to decide whether the
  // verify-trust action is actually available for a given source.
  can_verify_connection_trust: boolean;
  self_grant: SelfConfirmationGrant | null;
};

type JournalEntry = {
  event_id: string;
  sequence: number;
  action: string;
  resource_type: string;
  resource_id: string;
  actor_type: string;
  actor_principal_id?: string;
  on_behalf_of_principal_id?: string;
  request_id: string;
  policy_decision_id?: string;
  outcome: string;
  error_code?: string;
  referenced_evidence_ids: string[];
  metadata: { reason_codes?: string[] };
  previous_event_hash: string;
  event_hash: string;
  occurred_at: string;
};

type JournalResponse = {
  workspace_id: string;
  head_sequence: number;
  head_hash: string;
  events: JournalEntry[];
  truncated: boolean;
  // Decimal string cursor of the last returned row, present only when the
  // server proved a next page. Kept as a string so it never becomes a JS
  // Number and loses int64 precision.
  next_before_sequence?: string;
};

type ListEnvelope = { workspaces: WorkspaceSummary[] };
type SourcesEnvelope = { sources: SourceStatus[]; confirmation_context: ConfirmationContext };

// Card D-1: one unfinished PostgreSQL connection the current workspace
// started. state says where the wizard resumes: trust verification or catalog
// discovery. It carries no address, credential or trust hash.
export type SourceConnectionDraft = {
  connection_id: string;
  connection_revision: number;
  connection_name: string;
  source_type: string;
  trust_status: "DRAFT" | "VERIFIED" | string;
  state: "AWAITING_TRUST_VERIFICATION" | "READY_FOR_DISCOVERY" | string;
  created_at: string;
};

export type SourceConnectionDraftEnvelope = { drafts: SourceConnectionDraft[] };

type SourceRegisterResponse = {
  connection_id: string;
  credential_reference?: string;
  source_scope_id: string;
  discovered_scope_id: string;
  revision: number;
  scope_config_hash: string;
  access_mode: string;
  created: boolean;
};

type QuestionCitation = {
  number: number;
  address?: string;
  citation_id: string;
  evidence_fragment_id: string;
  excerpt: string;
  anchor: string;
  deep_link: string;
  source_version_id: string;
  extraction_id: string;
  source_object_id: string;
  evidence_text_hash: string;
  excerpt_hash: string;
  // R1: SOURCE_QUOTE binding and the closed grounding state. A legacy citation
  // without source_quote is reported UNCONFIRMED by the server.
  source_quote?: {
    source_version_id: string;
    extraction_id: string;
    anchor: string;
    start: number;
    end: number;
    text_hash: string;
  };
  grounding_status?: string;
};

type QuestionSignal = {
  code: string;
  evidence_ids: string[];
  // FIX-2 #6: server-owned, closed-vocabulary explanation derived from
  // code (uncertaintyMessage/conflictMessage) -- never re-derived client-side.
  message?: string;
};

type QuestionFreshness = {
  state: string;
  captured_at?: string;
  last_successful_sync_at?: string;
};

// Structured result beside rendered prose -- see
// internal/question/structured_result.go's AnswerResult and its nested
// types. It carries snapshot reductions and governed live-read receipts; no
// field here is shown unless the server actually sent it.
type AnswerFilter = { name: string; value: string };
type AnswerPeriod = { from?: string; to?: string; label?: string };
type AnswerKey = { key: string; fields?: Record<string, string> };
// R2 Outcome 3: the QueryIntent the server validated before executing a
// structured question. Additive on the AnswerResult wire object, exactly like
// the unified fields below -- an older answer simply omits it.
type AnswerIntent = {
  metric_id?: string;
  version?: number;
  period?: AnswerPeriod;
  filters?: AnswerFilter[];
  output?: string;
  as_of?: string;
};

// R2 Outcome 3: unified freshness/audit projections carried alongside the
// R1 fields. Every member is optional so an older server payload decodes
// without inventing anything.
type AnswerFreshness = {
  state?: string;
  captured_at?: string;
  last_successful_sync_at?: string;
};

type AnswerObservationWindow = {
  basis?: string;
  started_at?: string;
  completed_at?: string;
};

export type LiveTableReceipt = {
  execution_id: string;
  result_digest: string;
  receipt_digest: string;
  row_count: number;
  completeness: string;
  observation_window?: AnswerObservationWindow;
};

type LiveTablePayload = {
  columns: string[];
  rows: Array<Array<string | null>>;
  row_count: number;
};

type ComparisonDay = {
  date: string;
  snapshot_at: string;
  value: string;
  contributing_rows: number;
  distinct_subjects: number;
};

type ComparisonEvidence = {
  metric_id: string;
  profile_hash: string;
  evidence_schema_version: number;
  exposed_schema_revision: number;
  unit: string;
  coverage: "OBSERVED_SNAPSHOT";
  first: ComparisonDay;
  second: ComparisonDay;
  delta: string;
  percent_change: string;
  evidence_digest: string;
};

export type AnswerResult = {
  kind: string;
  value?: string;
  unit?: string;
  operation: string;
  rule: string;
  filters?: AnswerFilter[];
  period?: AnswerPeriod;
  timezone?: string;
  snapshot: AnswerSnapshot;
  keys?: AnswerKey[];
  completeness: string;
  // R2 Outcome 3 unified fields (all optional; the panel substitutes
  // “no data” for any of them the server did not send).
  run_id?: string;
  intent?: AnswerIntent;
  rowset_ref?: string;
  metric_version?: string | number;
  snapshot_id?: string;
  execution_id?: string;
  result_digest?: string;
  freshness?: AnswerFreshness;
  evidence_refs?: Array<string | number>;
  audit_receipt?: Array<string | number>;
  observation_window?: AnswerObservationWindow;
  receipt_digest?: string;
  receipts?: LiveTableReceipt[];
};

// FIX-2 #2 ("Understood as"): populated only when Create spliced a bare period
// follow-up onto a prior turn's own question.
type Understood = {
  period?: AnswerPeriod;
  source?: string;
  inherited_from_turn_id?: string;
  other_conditions?: string[];
};

// FIX-2 #6 ("where we searched"): populated only when uncertainties includes
// INSUFFICIENT_EVIDENCE.
type SearchedSource = {
  source: string;
  result: string;
  message: string;
};

type QuestionRun = {
  question_run_id: string;
  workspace_id: string;
  conversation_id?: string;
  workspace_revision: number;
  question: string;
  answer_mode: string;
  model_profile?: ModelProfile;
  verification_method: string;
  grounding_status?: string;
  status: string;
  corpus_status: string;
  freshness: QuestionFreshness;
  started_at: string;
  completed_at?: string;
  answer?: string;
  answer_hash?: string;
  context_pack_hash?: string;
  manifest_hash?: string;
  manifest_status: string;
  citations: QuestionCitation[];
  failure_code?: string;
  planning_status?: string;
  planning_operation?: string;
  planning_confidence?: string;
  plan_hash?: string;
  clarification?: string;
  uncertainties: QuestionSignal[];
  conflicts: QuestionSignal[];
  answer_result?: AnswerResult;
  understood?: Understood;
  searched?: SearchedSource[];
  tool_loop?: {
    model: string;
    stop_reason: string;
    all_claims_bound: boolean;
    // S2: the workspace model context the run matched, strictly decoded by
    // WorkspaceContextUsage rather than trusted inline.
    workspace_context?: unknown;
    calls: Array<{
      id: string;
      name: string;
      arguments?: unknown;
      system: boolean;
      outcome: string;
      duration_ms: number;
      result: { text: string; structured?: unknown; is_error?: boolean };
    }>;
  };
};

// Wire shape (internal/platform/workspaceapi conversationResponse /
// conversationTurnResponse): the server has no lightweight summary, no
// server-computed title and no turn_count field — every list item is the
// same full projection as conversationGet, each turn nesting its hydrated
// QuestionRun under question_run. The client derives a title (first turn's
// question) and a turn count from turns[] itself; conversationGet and
// conversationArchive both answer with this object directly, with no
// wrapper key.
type ConversationTurn = {
  turn_id: string;
  question_run_id: string;
  turn_index: number;
  created_at: string;
  question_run?: QuestionRun;
};

type ConversationDetail = {
  conversation_id: string;
  workspace_id: string;
  workspace_revision: number;
  created_by: string;
  created_at: string;
  archived_at?: string;
  turns: ConversationTurn[];
};

type ConversationSummary = ConversationDetail;

// next_cursor is the opaque ID of the last returned topic, present only when
// the server proved a further page. It is an opaque string and never parsed as
// a number.
type ConversationsEnvelope = { conversations: ConversationSummary[]; next_cursor?: string };
type ConversationEnvelope = ConversationDetail;

// First question of the earliest turn stands in for a title the server never
// computes; an empty conversation (a race with its own first answer) reads
// as "New conversation" rather than a blank line.
function conversationTitle(conversation: ConversationDetail): string {
  const first = conversation.turns[0]?.question_run?.question;
  if (!first) return "New conversation";
  return first.length > 72 ? `${first.slice(0, 72)}…` : first;
}

export function sidebarConversations(conversations: readonly ConversationSummary[], selectedID: string | null, query: string): ConversationSummary[] {
  const needle = query.trim().toLowerCase();
  return conversations
    .filter((item) => !item.archived_at && (item.turns.length > 0 || item.conversation_id === selectedID))
    .filter((item) => needle === "" || conversationTitle(item).toLowerCase().includes(needle));
}

// ---------------------------------------------------------------------------
// Fail-closed fetching: a non-2xx answer is read only through the typed error
// envelope; an unreadable answer is reported as-is, never reinterpreted.
// ---------------------------------------------------------------------------

type ApiOk<T> = { kind: "ok"; value: T; etag?: string };
type ApiFailure = { kind: "failure"; status: number; code: string; requestId: string; clarification?: string; fields?: string[] };
type ApiBroken = { kind: "broken"; status: number };
type ApiResult<T> = ApiOk<T> | ApiFailure | ApiBroken;

type SessionExpiredHandler = () => void;

let sessionExpiredHandler: SessionExpiredHandler | null = null;

function registerSessionExpiredHandler(handler: SessionExpiredHandler): () => void {
  sessionExpiredHandler = handler;
  return () => {
    if (sessionExpiredHandler === handler) sessionExpiredHandler = null;
  };
}

// Only the authenticated API helpers call this hook. Health probing and the
// explicit /auth/logout request use their own fetches and never notify it.
function notifySessionExpired(response: Response): void {
  if (response.status === 401) sessionExpiredHandler?.();
}

async function apiGet<T>(path: string): Promise<ApiResult<T>> {
  try {
    const response = await fetch(path, { cache: "no-store", headers: { Accept: "application/json" } });
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const body = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string } } | null;
    const code = body?.error?.code;
    if (code) return { kind: "failure", status: response.status, code, requestId: body?.error?.request_id ?? "" };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

async function apiPost<T>(path: string, body: unknown, idempotencyKey: string): Promise<ApiResult<T>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>('/api/v1/session/csrf');
    if (csrf.kind !== "ok") return csrf;
    const response = await fetch(path, {
      method: "POST",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey,
        "X-KnowVault-CSRF": csrf.value.csrf_token,
      },
      body: JSON.stringify(body),
    });
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const responseBody = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string; clarification?: string; fields?: string[] } } | null;
    const code = responseBody?.error?.code;
    // R2 Outcome 2: a typed QueryIntent refusal carries an additive, optional
    // clarification. It is passed through verbatim and never synthesized: an
    // absent field stays undefined, so ClosedOrError falls back to the generic
    // code sentence exactly as before.
    if (code) return { kind: "failure", status: response.status, code, requestId: responseBody?.error?.request_id ?? "", clarification: responseBody?.error?.clarification, fields: responseBody?.error?.fields };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

// A stream is one POST. Older servers may answer with JSON; decode that same
// response without retrying a question or reusing its idempotency key. R3:
// signal aborts the underlying HTTP request from the browser (leaving the
// conversation, switching conversations or pressing stop), which closes the
// connection so the server's request-scoped context is cancelled and the
// backend tool loop stops; see internal/platform/workspaceapi/workspaceapi.go
// questionCreate and internal/question/tool_loop.go's ctx.Err() checks.
async function apiPostQuestionStream(
  path: string, body: unknown, idempotencyKey: string, onAction: (action: QuestionActionFrame) => void,
  signal?: AbortSignal,
): Promise<ApiResult<QuestionRun>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind !== "ok") return csrf;
    const response = await fetch(path, {
      method: "POST", cache: "no-store", signal,
      headers: { Accept: "application/x-ndjson", "Content-Type": "application/json",
        "Idempotency-Key": idempotencyKey, "X-KnowVault-CSRF": csrf.value.csrf_token },
      body: JSON.stringify(body),
    });
    notifySessionExpired(response);
    if (!response.ok) {
      const failure = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string; clarification?: string } } | null;
      return failure?.error?.code
        ? { kind: "failure", status: response.status, code: failure.error.code, requestId: failure.error.request_id ?? "", clarification: failure.error.clarification }
        : { kind: "broken", status: response.status };
    }
    if (response.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/x-ndjson") {
      return { kind: "ok", value: (await response.json()) as QuestionRun };
    }
    if (!response.body) return { kind: "broken", status: 0 };
    const terminal = await readQuestionStream<QuestionRun>(response.body, onAction);
    return terminal.type === "result" ? { kind: "ok", value: terminal.result }
      : { kind: "failure", status: 500, code: terminal.code, requestId: terminal.request_id };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

const pendingKindByAction: Record<QuestionActionLabel, PendingActionState["current"]> = {
  model: "model", document_search: "searching", document_read: "reading",
  live_data: "checking_data", trusted_comparison: "comparing", other_tool: "working",
};

// The backend invokes at most one action at a time (see tool_loop.go's
// sequential invoke loop), so a "started" event is always immediately
// followed — after zero or more intervening events for other in-flight
// turns' generations, which observationForGeneration already filters out —
// by its own "finished" event before another "started" event can occur.
// Pairing therefore only needs to track the single most recently opened,
// not-yet-finished step; the wire protocol deliberately carries no separate
// call-correlation id (R2: no internal identifier beyond what the UI needs).
export function pendingActionFromEvents(events: readonly QuestionActionFrame[]): PendingActionState {
  const ordered = [...events].sort((left, right) => left.sequence - right.sequence);
  const completed: PendingActionStep[] = [];
  let open: { kind: PendingActionKind; request?: string } | null = null;
  for (const event of ordered) {
    if (event.phase === "action_started") {
      open = { kind: pendingKindByAction[event.label], request: event.request };
    } else if (event.outcome) {
      const kind = pendingKindByAction[event.label];
      completed.push({
        kind, request: open?.kind === kind ? open.request : undefined,
        outcome: event.outcome, detail: event.detail, durationMS: event.duration_ms,
      });
      open = null;
    }
  }
  return { current: open?.kind ?? "working", currentRequest: open?.request, completed };
}

// Source registration is deliberately content-idempotent on the server and
// therefore rejects both Idempotency-Key and If-Match. Keep this separate from
// apiPost so a future caller cannot accidentally change that contract.
async function apiPostWithoutIdempotency<T>(path: string, body?: unknown): Promise<ApiResult<T>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind !== "ok") return csrf;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-KnowVault-CSRF": csrf.value.csrf_token,
    };
    const init: RequestInit = { method: "POST", cache: "no-store", headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const response = await fetch(path, {
      ...init,
    });
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const responseBody = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string } } | null;
    const code = responseBody?.error?.code;
    if (code) return { kind: "failure", status: response.status, code, requestId: responseBody?.error?.request_id ?? "" };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

// Activation has an idempotency key but no workspace If-Match. It also has a
// truly empty request body; sending {} would violate the endpoint contract.
async function apiAction<T>(path: string, idempotencyKey: string): Promise<ApiResult<T>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind !== "ok") return csrf;
    const response = await fetch(path, {
      method: "POST",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Idempotency-Key": idempotencyKey,
        "X-KnowVault-CSRF": csrf.value.csrf_token,
      },
    });
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const responseBody = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string; fields?: string[] } } | null;
    const code = responseBody?.error?.code;
    if (code) return { kind: "failure", status: response.status, code, requestId: responseBody?.error?.request_id ?? "", fields: responseBody?.error?.fields };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

// Card D-1: a body-less DELETE that still carries an idempotency key (the same
// envelope the other source actions use). The discard removes only this
// workspace's draft pointer; it never deletes the immutable connection.
async function apiDeleteAction<T>(path: string, idempotencyKey: string): Promise<ApiResult<T>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind !== "ok") return csrf;
    const response = await fetch(path, {
      method: "DELETE",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Idempotency-Key": idempotencyKey,
        "X-KnowVault-CSRF": csrf.value.csrf_token,
      },
    });
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const responseBody = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string; fields?: string[] } } | null;
    const code = responseBody?.error?.code;
    if (code) return { kind: "failure", status: response.status, code, requestId: responseBody?.error?.request_id ?? "", fields: responseBody?.error?.fields };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

async function apiMutation<T>(method: "POST" | "PUT" | "DELETE", path: string, body: unknown, idempotencyKey: string, etag: string): Promise<ApiResult<T>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind !== "ok") return csrf;
    const headers: Record<string, string> = {
      Accept: "application/json",
      "Idempotency-Key": idempotencyKey,
      "If-Match": etag,
      "X-KnowVault-CSRF": csrf.value.csrf_token,
    };
    const init: RequestInit = { method, cache: "no-store", headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const response = await fetch(path, init);
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const responseBody = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string; fields?: string[] } } | null;
    const code = responseBody?.error?.code;
    if (code) return { kind: "failure", status: response.status, code, requestId: responseBody?.error?.request_id ?? "", fields: responseBody?.error?.fields };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

// apiUpload is UPL-1's multipart transport: the request body is the files
// themselves, so there is no Idempotency-Key/If-Match pair (re-uploading the
// same name is itself the server's safe, content-addressed operation — a new
// version, never a duplicate source).
async function apiUpload<T>(path: string, formData: FormData): Promise<ApiResult<T>> {
  try {
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind !== "ok") return csrf;
    const response = await fetch(path, {
      method: "POST",
      cache: "no-store",
      headers: { Accept: "application/json", "X-KnowVault-CSRF": csrf.value.csrf_token },
      body: formData,
    });
    notifySessionExpired(response);
    if (response.ok) return { kind: "ok", value: (await response.json()) as T, etag: response.headers.get("ETag") ?? undefined };
    const responseBody = (await response.json().catch(() => null)) as { error?: { code?: string; request_id?: string } } | null;
    const code = responseBody?.error?.code;
    if (code) return { kind: "failure", status: response.status, code, requestId: responseBody?.error?.request_id ?? "" };
    return { kind: "broken", status: response.status };
  } catch {
    return { kind: "broken", status: 0 };
  }
}

function newIdempotencyKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  bytes.forEach((value) => { binary += String.fromCharCode(value); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// Presentation mappings for server enum values. Unknown values are shown
// verbatim — the server value is the surface value.
// ---------------------------------------------------------------------------

const roleLabels: Record<string, string> = {
  OWNER: "Owner",
  MANAGER: "Manager",
  MEMBER: "Member",
  VIEWER: "Viewer",
  AUDITOR: "Auditor",
};
function roleLabel(role: string): string {
  return roleLabels[role] ?? role;
}

const roleNotes: Record<string, string> = {
  OWNER: "Created this workspace",
  MANAGER: "Manages members and sources",
  MEMBER: "Can search and read sources",
  VIEWER: "Can view results",
  AUDITOR: "Can read the activity log",
};
function roleNote(role: string): string {
  return roleNotes[role] ?? role;
}

type AccessCodeState = "ACTIVE" | "EXPIRED" | "REVOKED";

function accessCodeState(code: AccessCode, now = Date.now()): AccessCodeState {
  if (code.revoked_at) return "REVOKED";
  return new Date(code.expires_at).getTime() <= now ? "EXPIRED" : "ACTIVE";
}

function countLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

const workspaceStatusLabels: Record<string, string> = {
  ACTIVE: "Active",
  READ_ONLY: "Read only",
  ARCHIVED: "Archived",
  DELETING: "Deleting",
  DELETED: "Deleted",
};
function workspaceStatusLabel(status: string): string {
  return workspaceStatusLabels[status] ?? status;
}

const confirmationStateLabels: Record<string, string> = {
  DISABLED: "Disabled",
  NEEDS_GRANT: "Action required: confirm access",
  NEEDS_CONFIRMATION: "Action required: confirm access",
  NEEDS_TRUST_VERIFICATION: "Action required: verify trust",
  READY_TO_ACTIVATE: "Action required: enable the source",
  ACTIVE: "Active",
};
function confirmationStateLabel(state: string): string {
  return confirmationStateLabels[state] ?? "Connection status unknown";
}

// Labels for the "how this was obtained" block (contract §2): every word here names a
// real QuestionRun field value, nothing is invented — see the report for the
// rule/filter/period/timezone/value fields the API does not yet expose.
const planningOperationLabels: Record<string, string> = {
  LOOKUP: "fact lookup",
  EXPLAIN: "explanation from documents",
  COMPARE: "value comparison",
  AGGREGATE: "snapshot aggregation",
  AUDIT: "audit log check",
  CODE_TRACE: "code trace",
  UNKNOWN: "operation unknown",
  CLARIFY: "clarification required",
};
function planningOperationLabel(operation: string | undefined): string {
  if (!operation) return "unknown";
  return planningOperationLabels[operation] ?? operation;
}

const planningConfidenceLabels: Record<string, string> = { NONE: "none", LOW: "low", MEDIUM: "medium", HIGH: "high" };
function planningConfidenceLabel(confidence: string | undefined): string {
  if (!confidence) return "unknown";
  return planningConfidenceLabels[confidence] ?? confidence;
}

const freshnessStateLabels: Record<string, string> = {
  FRESH: "fresh", STALE: "stale", FAILED: "refresh failed", UNKNOWN: "unknown", DISABLED: "disabled",
};
function freshnessStateLabel(state: string): string {
  return freshnessStateLabels[state] ?? state;
}

function outcomeLabel(outcome: string): string {
  return outcome === "SUCCESS" ? "Succeeded" : outcome === "DENIED" ? "Denied" : outcome === "FAILED" ? "Error" : outcome;
}

const auditActionLabels: Record<string, string> = {
  "identity.login": "Signed in",
  "identity.login_failed": "Sign-in attempt failed",
  "identity.deprovisioned": "Account revoked",
  "session.terminated": "Session ended",
  "answer.document.amended": "Answer document amended",
  "workspace.created": "Workspace created",
  "workspace.updated": "Workspace updated",
  "workspace.archived": "Workspace archived",
  "workspace.member_added": "Member added",
  "workspace.member_removed": "Member removed",
  "workspace.role_changed": "Member role changed",
  "workspace.source_added": "Source added",
  "workspace.source_removed": "Source removed",
  "policy.decision": "Access decision recorded",
  "audit.viewed": "Activity log opened",
  "audit.exported": "Activity log exported",
  "source.scope_changed": "Source scope changed",
  "source.scope_activated": "Source scope enabled",
  "source.registration_created": "Source registered",
  "source.activation_requested": "Source activation requested",
  "source.object_ingested": "Source object ingested",
  "source.object_deleted": "Source object deleted",
  "source.object_missing": "Object missing from source",
  "source.object_restored": "Object restored",
  "source.version_created": "Source version created",
  "source.version_purging": "Source version purge started",
  "source.version_purged": "Source version purged",
  "source.extraction_activated": "Source extraction activated",
  "source.connection_trust_verified": "Connection trust verified",
  "question.created": "Question created",
  "question.completed": "Answer completed",
  "question.failed": "Answer failed",
  "model_run.gateway_attempt": "Model request attempted",
  "conversation.archived": "Conversation archived",
  "conversation.purging": "Conversation purge started",
  "conversation.purged": "Conversation purged",
  "citation.opened": "Answer evidence opened",
  "evidence.read.admitted": "Data read requested",
  "evidence.read.failed": "Answer evidence read failed",
  "question.run.admitted": "Question run admitted",
  "source.governed_query_admitted": "External database query admitted",
  "source.governed_query_attempted": "External database query attempted",
  "source.metadata.read.admitted": "Source list requested",
  "source.metadata.read.completed": "Source list retrieved",
  "source.metadata.read.failed": "Source list retrieval failed",
  "search.profile_call_lexical": "Keyword search",
  "search.profile_call_vector": "Semantic search",
  "search.profile_call_hybrid": "Hybrid search",
  "search.profile_revision_requested": "Search index update requested",
};
function auditActionLabel(action: string): string {
  return auditActionLabels[action] ?? action;
}

const auditActorTypeLabels: Record<string, string> = {
  HUMAN: "Human",
  SERVICE: "Agent",
  CONNECTOR: "Connector",
  SYSTEM: "System",
};

function auditActorLabel(event: JournalEntry): string {
  const type = auditActorTypeLabels[event.actor_type] ?? event.actor_type;
  return event.actor_principal_id ? `${type} · ${event.actor_principal_id}` : type;
}

const auditReasonLabels: Record<string, string> = {
  POLICY_ALLOWED: "Access allowed by policy",
  POLICY_DENIED: "Access denied by policy",
  MODEL_RUNTIME_EXTERNAL_WORKSPACE_SCOPED: "External model restricted to this workspace",
  MODEL_GATEWAY_RESPONSE_INVALID: "Model returned an invalid response",
};
function auditReasonLabel(reason: string): string {
  return auditReasonLabels[reason] ?? reason;
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

// Coarse, unit-limited "N ago" phrasing for status headlines; the exact
// timestamp remains one hover/title away via formatTime where it matters.
function relativeTimeFromNow(value: string | null): string | null {
  if (!value) return null;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return null;
  const diffSeconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (diffSeconds < 90) return "just now";
  const minutes = Math.round(diffSeconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return `${days} d ago`;
}

const corpusStatusWarnings: Record<string, string> = {
  PARTIAL: "This answer uses an incomplete dataset. Check the evidence and source status before relying on it.",
};
function corpusStatusWarning(status: string): string | null {
  return corpusStatusWarnings[status] ?? null;
}

// FIX-2 #4: closed processing_mode vocabulary (question.ProcessingMode*).
const processingModeLabels: Record<string, string> = {
  INTERNAL: "model: on premises",
  EXTERNAL: "model: external",
  INTERNAL_UNAVAILABLE: "model unavailable",
};
function processingModeLabel(mode: ProcessingMode | undefined): string {
  if (!mode) return "";
  const base = processingModeLabels[mode.mode] ?? mode.mode;
  return mode.mode === "EXTERNAL" && mode.provider ? `${base}, ${mode.provider}` : base;
}

// Shared rendering for a server-computed AnswerPeriod/QuestionUnderstood
// period: the closed label wins when the server sent one, otherwise the raw
// from/to bounds it actually used -- never a client-side re-derivation.
function answerPeriodText(period: AnswerPeriod | undefined): string | null {
  if (!period) return null;
  if (period.label) return period.label;
  if (period.from && period.to) return `${period.from} – ${period.to}`;
  return period.from ?? period.to ?? null;
}

const searchedResultLabels: Record<string, string> = {
  NOT_COVERED: "not fully covered",
  NO_MATCHES: "checked, no matches",
  UNAVAILABLE: "unavailable",
};
function searchedResultLabel(result: string): string {
  return searchedResultLabels[result] ?? result;
}
function searchedResultVariant(result: string): "ready" | "attention" | "disconnected" {
  if (result === "NO_MATCHES") return "ready";
  if (result === "UNAVAILABLE") return "disconnected";
  return "attention";
}

// ---------------------------------------------------------------------------
// Toasts: the one immediate, visible confirmation every button click gets in
// addition to its own inline state — "working…" while busy, then this for
// the outcome. Errors already carry human text via ClosedOrError/closedText;
// the toast repeats a short version so a result is never silent even when
// the inline block is scrolled out of view.
// ---------------------------------------------------------------------------

type Toast = { id: number; kind: "success" | "error"; text: string };
let toastSequence = 0;

function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  function push(kind: Toast["kind"], text: string) {
    const id = ++toastSequence;
    setToasts((current) => [...current, { id, kind, text }]);
    window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 4500);
  }
  function dismiss(id: number) {
    setToasts((current) => current.filter((item) => item.id !== id));
  }
  function clear() {
    setToasts([]);
  }
  return { toasts, push, dismiss, clear };
}

function ToastHost({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div aria-live="polite" className="toast-host" role="status">
      {toasts.map((toast) => (
        <div className={toast.kind === "success" ? "toast" : "toast toast-error"} key={toast.id}>
          <span aria-hidden="true">{toast.kind === "success" ? <IconCheckCircle /> : <IconAlertTriangle />}</span>
          <span>{toast.text}</span>
          <button aria-label="Dismiss notification" onClick={() => onDismiss(toast.id)} type="button">×</button>
        </div>
      ))}
    </div>
  );
}

// The closed no-oracle message: absence and denial are never distinguishable,
// matching the server contract for evidence and the audit journal.
const CLOSED_MESSAGE = "This item is unavailable or you do not have access.";

// The stable topic-list error label (browser-acceptance gate): every
// topic-list error state — initial load, continuation failure, first-page
// refresh failure and invalid/stale refresh failure — renders this exact
// literal from one shared constant, so a wording change cannot silently drop
// the label the host acceptance scenario looks for.
const TOPIC_LIST_ERROR_LABEL = "Could not load conversations.";

// No refusal is ever shown to a person as a bare server code (curator
// follow-up): every code the API can answer with maps to one plain sentence.
// An unlisted code still gets a human sentence, never a fallback that prints
// the code itself; the code and request id move into a collapsed technical
// line for support, never the primary message.
const ERROR_MESSAGES: Record<string, string> = {
  REQUEST_INVALID: "required information is missing — check the form fields",
  NOT_FOUND: "the source or document is no longer available",
  FORBIDDEN: "your role does not allow this action",
  UNAUTHENTICATED: "your session has ended — sign in again",
  CSRF_REJECTED: "your session is out of date — refresh the page and try again",
  METHOD_NOT_ALLOWED: "this action is not available here",
  PRECONDITION_REQUIRED: "the displayed data is out of date — refresh the page and try again",
  SOURCE_CONFLICT: "the source is already in this state — refresh the page",
  CONFLICT: "the state has changed — refresh the page and try again",
  WORKSPACE_REVISION_CONFLICT: "the workspace changed and its data has been refreshed — try again",
  SERVICE_UNAVAILABLE: "the service is temporarily unavailable — try again later",
  UPLOAD_REJECTED: "the file was not accepted — check its type (pdf, docx, pptx, xlsx, txt, md, html, csv) and size",
};

function humanErrorText(result: ApiFailure): string {
  return ERROR_MESSAGES[result.code] ?? "the action failed — try again or contact support";
}

function closedText(result: ApiFailure | ApiBroken): string {
  if (result.kind === "failure") {
    if (result.status === 404) return CLOSED_MESSAGE;
    if (result.status === 401) return "Your session has ended — sign in again.";
    return humanErrorText(result);
  }
  return "The server is not responding. Data is temporarily unavailable.";
}

function ClosedOrError({ result }: { result: ApiFailure | ApiBroken }) {
  // R2 Outcome 2: when the server sends an additive refusal clarification
  // (a typed QueryIntent refusal), show it as the primary message. It is
  // rendered only when the server sent a non-empty value, so no clarification
  // is ever invented and every other error keeps the unchanged closed text.
  const message = result.kind === "failure" && result.clarification ? result.clarification : closedText(result);
  return (
    <aside className="plain-note evidence-denied">
      <span aria-hidden="true"><IconInfo /></span>
      <div>
        <p>{message}</p>
        {result.kind === "failure" && (
          <details className="evi-provenance">
            <summary>Support details</summary>
            <p className="mono">{result.code}{result.requestId ? ` · request ${result.requestId}` : ""}</p>
          </details>
        )}
      </div>
    </aside>
  );
}

// ---------------------------------------------------------------------------
// Workspace data: one workspace's snapshot and sources are fetched from their
// read routes; each carries its own typed outcome so a refusal in one surface
// never contaminates another. The audit journal is loaded by AccessView only
// when its Journal tab is selected because the read appends audit.viewed.
// ---------------------------------------------------------------------------

export type WorkspaceDataState =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "loaded"; snapshot: ApiResult<WorkspaceSnapshot>; sources: ApiResult<SourcesEnvelope> };

export type GovernedWorkspaceAuthorization = "pending" | "authorized" | "denied";
export type GovernedRetentionState = { workspaceID: string | null; revision: number | null; phase: GovernedWorkspaceAuthorization; resetKey: number };
type GovernedRetentionEvent = Pick<GovernedRetentionState, "workspaceID" | "phase" | "revision">;
export function reduceGovernedRetention(state: GovernedRetentionState, event: GovernedRetentionEvent): GovernedRetentionState {
  if (state.workspaceID !== event.workspaceID) return { ...event, resetKey: state.resetKey + 1 };
  if (event.phase === "pending") return state.phase === "pending" ? state : { ...state, phase: "pending" };
  if (event.phase === "denied") return state.phase === "denied" && state.revision === null ? state : { ...state, phase: "denied", revision: null, resetKey: state.resetKey + 1 };
  if (state.revision === event.revision && event.revision !== null) {
    return state.phase === "authorized" ? state : { ...state, phase: "authorized" };
  }
  return { ...state, phase: "authorized", revision: event.revision, resetKey: state.resetKey + 1 };
}

const authorizationDenied = (result: ApiResult<unknown>) => result.kind === "failure" && [401, 403, 404].includes(result.status);

export function governedWorkspaceAuthorization(state: WorkspaceDataState, requestedWorkspaceID: string | null): { phase: GovernedWorkspaceAuthorization; revision: number | null } {
  if (requestedWorkspaceID === null || state.phase !== "loaded") return { phase: "pending", revision: null };
  if (state.snapshot.kind !== "ok") return { phase: authorizationDenied(state.snapshot) ? "denied" : "pending", revision: null };
  if (state.snapshot.value.id !== requestedWorkspaceID || state.snapshot.value.status !== "ACTIVE") return { phase: "denied", revision: null };
  if (state.sources.kind !== "ok") return { phase: authorizationDenied(state.sources) ? "denied" : "pending", revision: null };
  return { phase: "authorized", revision: state.snapshot.value.revision };
}

/** Source metadata is a protected workspace projection. The Ask surface may
 * pass it to RelyBar only after the same snapshot + source authorization gate
 * used by the governed and document surfaces has completed. Pending, denied,
 * stale-workspace and malformed source responses all return an empty summary,
 * so a previous workspace's source names cannot flash during revalidation. */
export function authorizedSourcesForAsk(state: WorkspaceDataState, requestedWorkspaceID: string | null): SourceStatus[] {
  if (governedWorkspaceAuthorization(state, requestedWorkspaceID).phase !== "authorized") return [];
  if (state.phase !== "loaded" || state.sources.kind !== "ok") return [];
  return state.sources.value.sources;
}

function useWorkspaceData(workspaceID: string | null, refreshVersion: number): WorkspaceDataState {
  const [reply, setReply] = useState<{ workspaceID: string; refreshVersion: number; state: WorkspaceDataState } | null>(null);
  useEffect(() => {
    setReply(null);
    if (workspaceID === null) return;
    let alive = true;
    const base = `/api/v1/workspaces/${encodeURIComponent(workspaceID)}`;
    Promise.all([
      apiGet<WorkspaceSnapshot>(base),
      apiGet<SourcesEnvelope>(`${base}/sources`),
    ]).then(([snapshot, sources]) => {
      if (alive) setReply({ workspaceID, refreshVersion, state: { phase: "loaded", snapshot, sources } });
    });
    return () => {
      alive = false;
    };
  }, [workspaceID, refreshVersion]);
  if (workspaceID === null) return { phase: "idle" };
  // A route return or workspace switch must not expose the previous successful
  // snapshot for the render before the new effect starts its access check.
  return reply?.workspaceID === workspaceID && reply.refreshVersion === refreshVersion
    ? reply.state : { phase: "loading" };
}

type JournalState = {
  phase: "idle" | "loading" | "loaded";
  result: ApiResult<JournalResponse> | null;
  events: JournalEntry[];
  nextCursor: string | null;
  // A transient first-page refresh failure is surfaced as "refresh-error" (a
  // distinct rendered value, not the continuation "error" used for a next-page
  // failure), so the single retry re-issues the first page even while the
  // retained page still ends at a continuation cursor. A real continuation
  // failure stays "error" and retries its exact retained cursor.
  continuation: "idle" | "pending" | "error" | "refresh-error";
  // Which request the surfaced transient failure belongs to, for the failure
  // wording. "first-page" accompanies the "refresh-error" state; "continuation"
  // accompanies a next-page failure.
  failedRequest: "first-page" | "continuation" | null;
};

const idleJournalState: JournalState = {
  phase: "idle",
  result: null,
  events: [],
  nextCursor: null,
  continuation: "idle",
  failedRequest: null,
};

// Continuation appends to the first page, so a row can reappear if a new event
// shifted the window; event_id is the stable identity for dedupe and for React
// keys, which keeps expanded <details> and scroll position across appends.
function dedupeJournalEvents(events: JournalEntry[]): JournalEntry[] {
  const seen = new Set<string>();
  const unique: JournalEntry[] = [];
  for (const event of events) {
    if (seen.has(event.event_id)) continue;
    seen.add(event.event_id);
    unique.push(event);
  }
  return unique;
}

// Network failure (status 0) and 5xx are transient and retryable on the same
// cursor, whatever shape the client produced the refusal in (a transport
// "broken" result or a status-carrying "failure" result). Every other refusal
// (revoked/401/403/political-404 and malformed requests) must fail closed and
// drop protected data instead of retrying.
function isTransientPageFailure(result: ApiResult<unknown>): boolean {
  if (result.kind === "ok") return false;
  return result.status === 0 || result.status >= 500;
}

function useWorkspaceJournal(
  workspaceID: string | null,
  requestedWorkspaceID: string | null,
  enabled: boolean,
  refreshVersion: number,
  workspaceRevision?: number,
): [JournalState, () => void, () => void] {
  const [state, setState] = useState<JournalState>(idleJournalState);
  const stateRef = useRef<JournalState>(idleJournalState);
  const generationRef = useRef(0);
  // R2 continuation-ownership fix: the in-flight continuation marker records the
  // unique owner id of the request that set it, together with the cursor it
  // extends. A same-scope refresh retains nextCursor and re-issues the retained
  // cursor as a new continuation with the same cursor value but a new owner id,
  // so a superseded pre-refresh continuation resolving later can never clear the
  // newer request's marker, force its rendered state to "idle", or release an
  // ownership it no longer holds. Keying by cursor value alone let two page
  // generations with an equal cursor share and collide on one marker.
  const pendingOwnerRef = useRef<{ id: number; cursor: string } | null>(null);
  const continuationOwnerSeqRef = useRef(0);
  // R2 first-page-retry fix: a transient first-page refresh failure is surfaced
  // as continuation "refresh-error" (a distinct rendered value) and keeps the
  // shown page and its exact cursor. This local token re-runs the first-page
  // effect below and is the retry used for that refresh-error state (and for a
  // retained page with no continuation cursor left); a continuation failure is
  // marked "error" and keeps its own cursor retry.
  const [reloadVersion, setReloadVersion] = useState(0);
  // R1 refresh-cursor fix: a continuation is bound not only to the request
  // generation but to the identity of the first page whose cursor it extends.
  // generationRef is bumped on every first-page replacement (a fresh load, a
  // successful refresh commit and a fail-closed reset), so a continuation that
  // is in flight while the shown page is replaced carries the previous
  // generation and can never append its rows to the new page. The cursor
  // identity check in loadMore covers the remaining case where the generation is
  // unchanged but the shown page no longer ends at the exact cursor this
  // continuation extends. On top of that, the pending-owner ref below carries the
  // unique request id that owns the in-flight marker, so an equal cursor value
  // from a superseded page generation cannot impersonate the newer request.
  // generationRef and the pending-owner ref participate in the guard, so the
  // continuation body stays resolvable from the refs in its own scope.
  // Tracks which (workspace, tab-enabled) scope the current journal state
  // belongs to, so a refreshVersion bump on the same scope is treated as an
  // in-place refresh rather than a fresh load that clears the shown page.
  const scopeRef = useRef<{ workspaceID: string | null; enabled: boolean; revision?: number } | null>(null);

  const commit = useCallback((next: JournalState) => {
    stateRef.current = next;
    setState(next);
  }, []);

  // Re-runs the first-page journal load. Bumping the token below re-enters the
  // same first-page effect a refreshVersion change would, so it keeps the shown
  // page and cursor on a transient failure and replaces them on success, exactly
  // like an in-place refresh. It is the retry offered when the retained page has
  // no continuation cursor and the continuation control would otherwise be a
  // no-op.
  const reloadFirstPage = useCallback(() => {
    // R2 refresh-cursor fix: the refresh-error retry re-enters the first-page
    // effect below, which re-asserts the exact retained cursor for every
    // continuation state. Re-assert it on this retry path itself as well, so the
    // retry never depends on the object spread alone: the exact retained
    // nextCursor (never a literal null invented here) is committed explicitly,
    // keeping the single retry a first-page re-issue that can never consume the
    // cursor as a before_sequence append.
    const retained = stateRef.current;
    commit({
      ...retained,
      nextCursor: retained.nextCursor,
    });
    setReloadVersion((current) => current + 1);
  }, [commit]);

  useEffect(() => {
    // A first-page load starts a new page generation: the bump invalidates every
    // continuation from the previously shown page, and any continuation issued
    // from here on is bound to this attempt's generation.
    const generation = ++generationRef.current;
    pendingOwnerRef.current = null;
    // A momentary null workspaceID is the transient snapshot/reload window of
    // the workspace the shown page already belongs to. It must be treated like a
    // same-scope refresh: the shown events and the continuation cursor are kept,
    // and the scope identity below is deliberately left untouched so the
    // restored workspace is recognized as the same scope instead of a fresh page
    // with a new identity. Only a definite scope (a non-null workspace, or the
    // journal tab being switched off) can reset. The generation bump above
    // already invalidated any in-flight continuation, so a cursor left in
    // "pending" is reconciled to "idle" while the cursor itself is retained.
    if (workspaceID === null) {
      // R2 refresh-cursor fix: the retained continuation cursor is expressed
      // explicitly on the rendered JournalState for every continuation state
      // (idle/error/refresh-error, and a stale pending reconciled to idle),
      // exactly as the topics loader retains its cursor (by leaving the rendered
      // topicsCursor state untouched on its transient paths), instead of
      // relying only on the object spread. The exact committed nextCursor is
      // written back (never a literal null), so the momentary null workspaceID
      // reload window can never drop the continuation cursor of the page
      // already shown.
      // R2 journal-identity fix: the momentary window is a same-workspace reload
      // window only while the parent still requests the workspace whose journal
      // state is currently owned. This mirrors AskView's `sameRequestedWorkspace`
      // gate (`owner !== null && requestedWorkspaceID === owner`): a requested
      // workspace that differs from the owned workspace, an absent request, or a
      // scope this hook never owned is a definite change, so it fails closed and
      // commits idleJournalState (rows cleared, cursor null) instead of
      // retaining another workspace's rows and cursor.
      // R2 fail-closed fix: the momentary null window is a same-workspace reload
      // window only while the journal tab is still requested. When the tab is
      // switched off (or the session is closed) the parent no longer requests
      // this protected data at all, so the null branch must fail closed exactly
      // like the non-null disabled-tab branch below — even if the requested
      // identity happens to equal the currently owned workspace id. Without this
      // gate the null branch runs before the `enabled` check further down and
      // could retain the shown protected journal rows and continuation cursor
      // while the journal tab is closed.
      const owner = scopeRef.current;
      const sameRequestedWorkspace = owner !== null && requestedWorkspaceID === owner.workspaceID;
      if (!enabled || !sameRequestedWorkspace) {
        scopeRef.current = null;
        commit(idleJournalState);
        return;
      }
      const retained = stateRef.current;
      commit({
        ...retained,
        nextCursor: retained.nextCursor,
        continuation: retained.continuation === "pending" ? "idle" : retained.continuation,
      });
      return;
    }
    const previousScope = scopeRef.current;
    const sameScope = previousScope !== null
      && previousScope.workspaceID === workspaceID
      && previousScope.enabled === enabled
      && previousScope.revision === workspaceRevision;
    scopeRef.current = { workspaceID, enabled, revision: workspaceRevision };
    if (!enabled) {
      // A non-null workspace with the journal tab switched off (or the session
      // closed) is a genuine scope change: fail closed and drop the page.
      commit(idleJournalState);
    } else {
      // R2 refresh-fix: on a same-workspace refresh the shown events and the
      // continuation cursor are deliberately NOT cleared before the await, so a
      // transient first-page failure can keep a readable page and leave the
      // existing continuation control as the retry. Only a real workspace/tab
      // change (or the fail-closed branch below) resets the journal.
      if (!sameScope) {
        commit({ phase: "loading", result: null, events: [], nextCursor: null, continuation: "idle", failedRequest: null });
      } else {
        // R1 continuation page-identity guard: the generation bump above
        // invalidated every continuation issued against the previously shown
        // page, so a rendered "pending" can never be completed by that request
        // and is reconciled to "idle" at refresh entry. Every other continuation
        // state (idle/error/refresh-error) is retained verbatim, so the
        // refresh-error retry (reloadFirstPage) remains a first-page re-issue
        // that holds the exact cursor and never consumes it as a before_sequence
        // append. The shown events and the exact nextCursor are kept, so a
        // same-scope refresh can never strand the continuation control and the
        // superseded continuation resolving later finds the replacement page no
        // longer "pending" and mutates nothing.
        // R2 refresh-cursor fix: the retained cursor is committed explicitly on
        // the rendered JournalState for every continuation state (like the
        // topics loader's untouched cursor state on its transient paths),
        // not only carried by the object spread and never as a literal null.
        const retained = stateRef.current;
        commit({
          ...retained,
          nextCursor: retained.nextCursor,
          continuation: retained.continuation === "pending" ? "idle" : retained.continuation,
        });
      }
      const base = `/api/v1/workspaces/${encodeURIComponent(workspaceID)}`;
      apiGet<JournalResponse>(`${base}/audit-events`).then((result) => {
        if (generationRef.current !== generation) return;
        if (result.kind === "ok") {
          // The refreshed first page is the new shown page: bump the generation
          // so a continuation that was in flight against the previous page (or
          // started during this refresh) can never append its stale rows.
          generationRef.current += 1;
          commit({
            phase: "loaded",
            result,
            events: dedupeJournalEvents(result.value.events),
            nextCursor: result.value.next_before_sequence || null,
            continuation: "idle",
            failedRequest: null,
          });
          return;
        }
        if (isTransientPageFailure(result)) {
          // Network failure (status 0) or 5xx is retryable, but two different
          // situations must never be conflated here. A transient same-scope
          // refresh with an ok first page already on screen keeps that page, its
          // exact cursor and its rows, and is surfaced as continuation
          // "refresh-error" (a distinct rendered value, not the continuation
          // "error" used for a next-page failure), so its single retry re-issues
          // the first page via reloadFirstPage even while the retained page still
          // ends at a continuation cursor, instead of consuming that cursor with
          // a before_sequence append; failedRequest stays "first-page" for the
          // wording. A transient first-page failure with no ok page shown is an
          // initial-load failure: it must render the ordinary first-load/
          // ClosedOrError path with load wording, never the failed-refresh
          // wording, so it commits the failure result with the continuation left
          // at "idle" (no refresh-error state).
          const current = stateRef.current;
          const hasShownOkPage = current.phase === "loaded" && current.result?.kind === "ok";
          if (hasShownOkPage) {
            // R2 refresh-cursor fix: a transient same-scope first-page refresh
            // keeps the shown page and must retain its exact continuation cursor.
            // The retained nextCursor is committed explicitly on the rendered
            // JournalState (mirroring the topics loader's untouched cursor state
            // on its transient paths) rather than
            // being kept only implicitly inside the object spread, and no
            // literal null is ever written here. Fail-closed paths (401/403/404,
            // a real workspace/tab change) already wrote null through commit
            // before this response could pass the generation guard, so this can
            // never resurrect another workspace's cursor.
            commit({
              ...current,
              nextCursor: current.nextCursor,
              continuation: "refresh-error",
              failedRequest: "first-page",
            });
          } else {
            commit({ phase: "loaded", result, events: [], nextCursor: null, continuation: "idle", failedRequest: null });
          }
          return;
        }
        // Non-transient refusal (revoked/401/403/political-404, malformed):
        // fail closed and drop every protected journal row and cursor. The
        // generation is bumped too, so an in-flight continuation cannot
        // resurrect the dropped rows into the closed journal.
        generationRef.current += 1;
        commit({ phase: "loaded", result, events: [], nextCursor: null, continuation: "idle", failedRequest: null });
      });
    }
    // Unmount and every dependency change invalidate in-flight first-page and
    // continuation responses, so no page survives its workspace or session.
    return () => {
      if (generationRef.current === generation) generationRef.current += 1;
      pendingOwnerRef.current = null;
    };
  }, [workspaceID, requestedWorkspaceID, enabled, refreshVersion, reloadVersion, workspaceRevision, commit]);

  const loadMore = useCallback(() => {
    const current = stateRef.current;
    const cursor = current.nextCursor;
    if (workspaceID === null || cursor === null) return;
    // R2 refresh-cursor fix: a retained page whose first-page refresh failed
    // transiently ("refresh-error") owns its exact cursor for a first-page
    // re-issue via reloadFirstPage, not for a next-page append. While that state
    // is rendered, refuse the continuation so the retained cursor can never be
    // consumed as a before_sequence request; the refresh retry re-enters the
    // first-page load and re-issues the cursor as the refresh itself.
    if (current.continuation === "refresh-error") return;
    // Block a duplicate only while a request already owns this exact cursor. The
    // ownership id makes the marker generation-specific: after a same-scope
    // refresh retains the cursor, this becomes a genuinely new continuation that
    // may re-issue it, while the superseded one keeps a different owner id.
    if (current.continuation === "pending" || pendingOwnerRef.current?.cursor === cursor) return;
    const generation = generationRef.current;
    const owner = ++continuationOwnerSeqRef.current;
    pendingOwnerRef.current = { id: owner, cursor };
    commit({ ...current, continuation: "pending", failedRequest: null });
    const base = `/api/v1/workspaces/${encodeURIComponent(workspaceID)}`;
    apiGet<JournalResponse>(`${base}/audit-events?before_sequence=${encodeURIComponent(cursor)}`).then((result) => {
      // A transient network/5xx failure is retryable only on the page that
      // actually issued this continuation, so the page-identity guard runs first:
      // a workspace switch, tab close, logout or first-page refresh bumped the
      // generation, or the shown page no longer ends at the exact cursor this
      // continuation extends. Such a superseded failure is abandoned without
      // surfacing a retry and without mutating the replacement page's
      // continuation state. It releases its own pending marker only while it
      // still owns it (same owner id), leaving a newer continuation's marker
      // untouched even when the cursor value is equal.
      if (isTransientPageFailure(result)) {
        // A newer continuation that owns the marker (a different owner id, even
        // for an equal cursor value) owns the "pending" state and its own retry:
        // leave it untouched.
        if (pendingOwnerRef.current !== null && pendingOwnerRef.current.id !== owner) return;
        // Release this continuation's own pending marker before deciding whether
        // the failure is still retryable.
        if (pendingOwnerRef.current?.id === owner) pendingOwnerRef.current = null;
        if (
          generationRef.current !== generation
          || stateRef.current.nextCursor !== cursor
        ) {
          // A workspace switch, tab close, logout, first-page refresh commit,
          // closure or a newer continuation replaced the shown page while this
          // request was in flight. This failure is abandoned without surfacing a
          // retry on the replacement page, but a "pending" this request still
          // owned is reconciled back to "idle" so a same-scope refresh can never
          // strand the control. No rows or cursor are mutated. The abandoned
          // continuation must not erase the R2 first-page failure wording either:
          // when the retained page already carries it, a superseded continuation
          // resolving later may only give up its own "pending" state, never
          // reclassify that failure as its own continuation error.
          if (stateRef.current.continuation === "pending") {
            commit({
              ...stateRef.current,
              continuation: "idle",
              failedRequest: stateRef.current.failedRequest === "first-page" ? "first-page" : null,
            });
          }
          return;
        }
        // The page still matches: preserve today's retry on this exact cursor.
        // This failure belongs to the continuation and stays on the rendered
        // "error" value, distinct from a first-page refresh's "refresh-error", so
        // the panel words it as a continuation failure and retries this exact
        // cursor via onLoadMore. A shown page that already carries the
        // "refresh-error" marker must not be reclassified by this continuation.
        commit({
          ...stateRef.current,
          continuation: stateRef.current.continuation === "refresh-error" ? "refresh-error" : "error",
          failedRequest: stateRef.current.continuation === "refresh-error" ? "first-page" : "continuation",
        });
        return;
      }
      // A non-transient refusal (revoked/401/403/political-404, malformed) fails
      // closed before the guard: dropping every protected journal row must never
      // depend on the generation or cursor still matching.
      if (result.kind !== "ok") {
        generationRef.current += 1;
        pendingOwnerRef.current = null;
        commit({ phase: "loaded", result, events: [], nextCursor: null, continuation: "idle", failedRequest: null });
        return;
      }
      // A workspace switch, tab close, logout or first-page refresh bumped the
      // generation (including the generation bump that commits a refreshed first
      // page), or the shown page no longer ends at the exact cursor this
      // continuation extends (live cursor identity in stateRef.current), so this
      // successful page belongs to a list we no longer show. Abandon it without
      // committing its rows and reconcile the continuation out of "pending" so a
      // same-scope refresh can never strand the control. This mirrors
      // loadMoreTopics: it may only touch the state it actually owns, so the
      // branch commits only while this request still owns the current pending
      // marker (same owner id). A newer continuation that owns the marker (a
      // different owner id, even for an equal cursor value) must be left
      // untouched, and a marker that a newer terminal continuation failure has
      // already released must not be re-adopted here either: otherwise this
      // stale page would clear that newer continuation's "continuation" failure
      // wording, flip its "error" state back or replace its retained cursor.
      // Requiring ownership loses no liveness, because "pending" is only ever
      // written together with the marker and every path that clears the marker
      // reconciles "pending" to "idle" itself.
      // A superseded success may not commit even when the generation and the
      // shown cursor happen to match: an equal cursor value re-issued by a newer
      // continuation is owned by a different owner id, and appending this stale
      // page would clear that newer request's marker and resurrect rows the
      // shown page no longer ends at. The owner check therefore participates in
      // the commit guard itself, exactly like the transient-failure path above.
      if (
        pendingOwnerRef.current === null
        || pendingOwnerRef.current.id !== owner
        || generationRef.current !== generation
        || stateRef.current.nextCursor !== cursor
      ) {
        if (pendingOwnerRef.current === null || pendingOwnerRef.current.id !== owner) return;
        pendingOwnerRef.current = null;
        commit({
          ...stateRef.current,
          continuation: stateRef.current.continuation === "pending" ? "idle" : stateRef.current.continuation,
          // A same-scope refresh that failed transiently keeps the readable
          // page, its cursor and the R2 first-page failure wording. This
          // abandoned continuation may therefore only clear a "continuation"
          // failure of its own; when the shown page already carries the
          // first-page marker, that wording must survive.
          failedRequest: stateRef.current.failedRequest === "first-page" ? "first-page" : null,
        });
        return;
      }
      pendingOwnerRef.current = null;
      const latest = stateRef.current;
      commit({
        ...latest,
        // Appending rows to the retained page is legitimate, but it must not
        // erase the "refresh-error" marker set by a same-scope refresh that
        // failed while this continuation was in flight.
        continuation: latest.continuation === "refresh-error" ? "refresh-error" : "idle",
        events: dedupeJournalEvents([...latest.events, ...result.value.events]),
        nextCursor: result.value.next_before_sequence || null,
        failedRequest: latest.continuation === "refresh-error" ? "first-page" : null,
      });
    });
  }, [workspaceID, commit]);

  // A new workspace revision may change membership. Hide the previous page
  // synchronously, before the new effect starts its authorization request.
  const revisionChanged = workspaceID !== null && (scopeRef.current?.workspaceID !== workspaceID || scopeRef.current.revision !== workspaceRevision);
  return [revisionChanged ? idleJournalState : state, loadMore, reloadFirstPage];
}

// ---------------------------------------------------------------------------
// S2 card D: Settings — the workspace model context. The view reads one
// context document, edits it locally, and saves it with the current content
// hash. Every response is decoded (never trusted as T) and every string is a
// React text child, so a term containing markup is escaped, not executed.
// ---------------------------------------------------------------------------

type ModelContextTab = "description" | "instructions" | "glossary" | "sources" | "proposals" | "history";

const modelContextTabLabels: Record<ModelContextTab, string> = {
  description: "Description",
  instructions: "Instructions",
  glossary: "Glossary",
  sources: "Sources",
  proposals: "Proposals",
  history: "History",
};

const modelContextProposalKindLabels: Record<string, string> = {
  NEW_TERM: "New term",
  SYNONYM: "Synonym",
  DEFINITION_CORRECTION: "Definition correction",
};

const modelContextChangeKindLabels: Record<string, string> = {
  EDIT: "Edit",
  PROPOSAL_ACCEPTED: "Proposal accepted",
  RESTORE: "Restore",
};

function modelContextProposalKindLabel(kind: string): string {
  return modelContextProposalKindLabels[kind] ?? kind;
}

function modelContextChangeKindLabel(kind: string): string {
  return modelContextChangeKindLabels[kind] ?? kind;
}

// A server field path may be indexed (document.glossary[0].term) or bare
// (document.description); this matches the documented leaf either way and
// never invents a message for a field the server did not name.
function modelContextFieldError(errors: Record<string, string>, path: string): string | null {
  if (errors[path]) return errors[path];
  const key = Object.keys(errors).find((candidate) => candidate.endsWith(`.${path}`));
  return key ? errors[key] : null;
}

function parseSynonymText(text: string): string[] {
  return text.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
}

// Card W-2: description, instructions and glossary are each one free-text
// field with its own save action. Nothing about a term's id, its synonyms-as-
// chips or its data-location block is rendered here any more: a workspace
// whose structured records predate the card shows them as the readable text
// the server projects into the field (model-context.ts).
function ModelContextPlainTextField({ id, label, value, maxLength, editable, error, onChange, onSave }: {
  id: string;
  label: string;
  value: string;
  maxLength: number;
  editable: boolean;
  error: string | null;
  onChange: (next: string) => void;
  onSave?: () => void;
}) {
  return (
    <>
      <label className="field" htmlFor={id}>
        <span>{label}</span>
        <textarea
          disabled={!editable}
          id={id}
          maxLength={maxLength}
          onChange={(event) => onChange(event.target.value)}
          value={value}
        />
        <small>{value.length} / {maxLength} characters</small>
        {error && <small className="field-error">{error}</small>}
      </label>
      {editable && onSave && (
        <button className="primary-button" onClick={onSave} type="button">Save</button>
      )}
    </>
  );
}

function ModelContextProposalCard({ proposal, editable, busy, editing, draft, onChangeDraft, onEdit, onCancelEdit, onAccept, onReject, conversationHref, onOpenConversation }: {
  proposal: ModelContextProposal;
  editable: boolean;
  busy: boolean;
  editing: boolean;
  draft: { term: string; synonyms: string; definition: string } | null;
  onChangeDraft: (next: { term: string; synonyms: string; definition: string }) => void;
  onEdit: () => void;
  onCancelEdit: () => void;
  onAccept: (edits?: ModelContextProposalEdits) => void;
  onReject: () => void;
  conversationHref: (conversationID: string) => string;
  onOpenConversation?: (conversationID: string) => void;
}) {
  return (
    <article className="model-context-proposal">
      <header className="model-context-proposal-head">
        <span className="badge badge-tell">{modelContextProposalKindLabel(proposal.kind)}</span>
        <span className="state-chip muted">{proposal.occurrences} occurrence{proposal.occurrences === 1 ? "" : "s"}</span>
      </header>
      <dl className="model-context-proposal-fields">
        <div><dt>Candidate term</dt><dd>{proposal.candidate_term}</dd></div>
        {proposal.target_term !== undefined && proposal.target_term.length > 0 && <div><dt>Target term</dt><dd>{proposal.target_term}</dd></div>}
        <div><dt>Suggested text</dt><dd>{proposal.suggested_text}</dd></div>
      </dl>
      {proposal.examples.length > 0 && (
        <ul aria-label="Examples" className="model-context-proposal-examples">
          {proposal.examples.map((example, index) => (
            <li key={`${example.conversation_id}-${index}`}>
              <a
                href={conversationHref(example.conversation_id)}
                onClick={(event) => {
                  if (!onOpenConversation) return;
                  if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
                  event.preventDefault();
                  onOpenConversation(example.conversation_id);
                }}
              >
                {example.question_excerpt}
              </a>
            </li>
          ))}
        </ul>
      )}
      {proposal.hidden_examples > 0 && <p className="msg-note">{proposal.hidden_examples} further example{proposal.hidden_examples === 1 ? "" : "s"} are not visible to you.</p>}
      {editable && (editing && draft ? (
        <div className="model-context-proposal-edit">
          <label className="field"><span>Term</span>
            <input onChange={(event) => onChangeDraft({ ...draft, term: event.target.value })} value={draft.term} />
          </label>
          <label className="field"><span>Synonyms, comma separated</span>
            <input onChange={(event) => onChangeDraft({ ...draft, synonyms: event.target.value })} value={draft.synonyms} />
          </label>
          <label className="field"><span>Definition</span>
            <textarea onChange={(event) => onChangeDraft({ ...draft, definition: event.target.value })} value={draft.definition} />
          </label>
          <div className="model-context-proposal-actions">
            <button className="primary-button" disabled={busy} onClick={() => onAccept({ term: draft.term, synonyms: parseSynonymText(draft.synonyms), definition: draft.definition })} type="button">Accept changes</button>
            <button className="link-button" disabled={busy} onClick={onCancelEdit} type="button">Cancel</button>
          </div>
        </div>
      ) : (
        <div className="model-context-proposal-actions">
          <button className="primary-button" disabled={busy} onClick={() => onAccept()} type="button">Accept</button>
          <button className="secondary-button" disabled={busy} onClick={onEdit} type="button">Edit &amp; accept</button>
          <button className="secondary-button" disabled={busy} onClick={onReject} type="button">Reject</button>
        </div>
      ))}
    </article>
  );
}

// The two mutations the tests assert on are exported as thin transports so the
// exact If-Match / Idempotency-Key / body a real browser sends can be proven
// against the pure request descriptors without rendering the container.
export async function sendModelContextSave(workspaceID: string, context: ModelContext, document: ModelContextDocument): Promise<ApiResult<unknown>> {
  const request = modelContextSaveRequest(workspaceID, context, document, newIdempotencyKey());
  return apiMutation<unknown>(request.method, request.path, request.body, request.idempotencyKey, request.ifMatch);
}

export async function sendModelContextProposalAccept(workspaceID: string, context: ModelContext, proposalID: string, edits?: ModelContextProposalEdits): Promise<ApiResult<unknown>> {
  const request = modelContextAcceptRequest(workspaceID, context, proposalID, edits, newIdempotencyKey());
  return apiMutation<unknown>(request.method, request.path, request.body, request.idempotencyKey, request.ifMatch);
}

export function ModelContextEditorSurface({
  context, document: modelDocument, proposals, versions, workspaceID,
  viewedVersion = null,
  saving = false,
  busyProposalID = null,
  restoringVersion = null,
  saveError = null,
  fieldErrors = {},
  notice = null,
  initialTab,
  onReload,
  onChange,
  onSave,
  onAccept,
  onReject,
  onRestore,
  onViewVersion,
  onCloseVersion,
  onOpenConversation,
}: {
  context: ModelContext;
  document: ModelContextDocument;
  proposals: ModelContextProposal[];
  versions: ModelContextVersion[];
  workspaceID: string;
  viewedVersion?: number | null;
  saving?: boolean;
  busyProposalID?: string | null;
  restoringVersion?: number | null;
  saveError?: string | null;
  fieldErrors?: Record<string, string>;
  notice?: string | null;
  initialTab?: ModelContextTab;
  onReload?: () => void;
  onChange: (document: ModelContextDocument) => void;
  onSave?: () => void;
  onAccept?: (proposalID: string, edits?: ModelContextProposalEdits) => void;
  onReject?: (proposalID: string) => void;
  onRestore?: (version: number) => void;
  onViewVersion?: (version: number) => void;
  onCloseVersion?: () => void;
  onOpenConversation?: (conversationID: string) => void;
}) {
  const editable = context.editable;
  const [activeTab, setActiveTab] = useState<ModelContextTab>(initialTab ?? "description");
  const [editingProposalID, setEditingProposalID] = useState<string | null>(null);
  const [proposalDraft, setProposalDraft] = useState<{ term: string; synonyms: string; definition: string } | null>(null);
  const effectiveTab: ModelContextTab = activeTab === "proposals" && !editable ? "description" : activeTab;
  const tabs: ModelContextTab[] = editable
    ? ["description", "instructions", "glossary", "sources", "proposals", "history"]
    : ["description", "instructions", "glossary", "sources", "history"];

  function updateDocument(patch: Partial<ModelContextDocument>) {
    onChange({ ...modelDocument, ...patch });
  }

  function beginProposalEdit(proposal: ModelContextProposal) {
    setEditingProposalID(proposal.proposal_id);
    setProposalDraft({
      term: proposal.target_term ?? proposal.candidate_term,
      synonyms: "",
      definition: proposal.suggested_text,
    });
  }

  const conversationHref = (conversationID: string) => buildSearchHash(workspaceID, conversationID);

  return (
    <div className="page model-context-page">
      <header className="model-context-head">
        <div>
          <p className="eyebrow">{viewedVersion !== null ? `Version ${viewedVersion}` : "Model context"}</p>
          <h2>{viewedVersion !== null ? `Version ${viewedVersion} (read-only)` : "Workspace model context"}</h2>
          <p className="model-context-meta">
            {context.version === 0 ? "No saved version yet." : `Version ${context.version}`}
            {context.updated_by ? ` · ${context.updated_by}` : ""}
          </p>
        </div>
        {editable && onSave && (
          <button className="primary-button" disabled={saving} onClick={onSave} type="button">
            {saving ? "Saving…" : "Save all"}
          </button>
        )}
      </header>
      {viewedVersion !== null && (
        <aside className="plain-note">
          <span aria-hidden="true"><IconInfo /></span>
          <div>
            <p>You are viewing an older version. Restore it to make it current, or go back.</p>
            {onCloseVersion && <button className="link-button" onClick={onCloseVersion} type="button">Back to current version</button>}
          </div>
        </aside>
      )}
      {!editable && viewedVersion === null && <p className="evidence-state">You can read this context, but only an owner or manager can change it.</p>}
      {saveError && (
        <div className="launch-note" role="alert">
          <strong>Could not save.</strong>
          <span>{saveError}</span>
          {onReload && <button className="link-button" onClick={onReload} type="button">Reload</button>}
        </div>
      )}
      {notice && <p className="msg-warning" role="alert">{notice}</p>}
      {Object.keys(fieldErrors).length > 0 && (
        <div className="model-context-field-errors" role="alert">
          <p>The server rejected these fields:</p>
          <ul>
            {Object.entries(fieldErrors).map(([field, message]) => (
              <li key={field}><code className="mono">{field}</code> — {message}</li>
            ))}
          </ul>
        </div>
      )}

      <nav aria-label="Model context sections" className="tabs model-context-tabs" role="tablist">
        {tabs.map((tab) => (
          <button
            aria-controls={`model-context-panel-${tab}`}
            aria-selected={effectiveTab === tab}
            className={effectiveTab === tab ? "active" : undefined}
            id={`model-context-tab-${tab}`}
            key={tab}
            onClick={() => setActiveTab(tab)}
            role="tab"
            tabIndex={effectiveTab === tab ? 0 : -1}
            type="button"
          >
            {modelContextTabLabels[tab]}{tab === "proposals" ? ` (${proposals.length})` : ""}
          </button>
        ))}
      </nav>

      {effectiveTab === "description" && (
        <section aria-labelledby="model-context-tab-description" className="model-context-panel" id="model-context-panel-description" role="tabpanel" tabIndex={0}>
          <ModelContextPlainTextField
            editable={editable}
            error={modelContextFieldError(fieldErrors, "description")}
            id="model-context-description"
            label="Description"
            maxLength={MODEL_CONTEXT_DESCRIPTION_MAX}
            onChange={(value) => updateDocument({ description: value })}
            onSave={onSave}
            value={modelDocument.description}
          />
        </section>
      )}

      {effectiveTab === "instructions" && (
        <section aria-labelledby="model-context-tab-instructions" className="model-context-panel" id="model-context-panel-instructions" role="tabpanel" tabIndex={0}>
          <ModelContextPlainTextField
            editable={editable}
            error={modelContextFieldError(fieldErrors, "instructions")}
            id="model-context-instructions"
            label="Instructions for the assistant"
            maxLength={MODEL_CONTEXT_INSTRUCTIONS_MAX}
            onChange={(value) => updateDocument({ instructions: value })}
            onSave={onSave}
            value={modelDocument.instructions}
          />
        </section>
      )}

      {effectiveTab === "glossary" && (
        <section aria-labelledby="model-context-tab-glossary" className="model-context-panel" id="model-context-panel-glossary" role="tabpanel" tabIndex={0}>
          <ModelContextPlainTextField
            editable={editable}
            error={modelContextFieldError(fieldErrors, "glossary_text")}
            id="model-context-glossary-text"
            label="Glossary"
            maxLength={MODEL_CONTEXT_GLOSSARY_TEXT_MAX}
            onChange={(value) => updateDocument({ glossary_text: value })}
            onSave={onSave}
            value={modelDocument.glossary_text}
          />
        </section>
      )}

      {effectiveTab === "sources" && (
        <section aria-labelledby="model-context-tab-sources" className="model-context-panel" id="model-context-panel-sources" role="tabpanel" tabIndex={0}>
          {modelDocument.sources.length === 0 && <p className="evidence-state">No source notes yet.</p>}
          {modelDocument.sources.map((source, sourceIndex) => (
            <section className="model-context-source" key={`${source.source_connection_id}-${sourceIndex}`}>
              <h3>{source.source_connection_id}</h3>
              <label className="field">
                <span>Source description</span>
                <textarea
                  disabled={!editable}
                  onChange={(event) => updateDocument({ sources: modelDocument.sources.map((item, itemIndex) => itemIndex === sourceIndex ? { ...item, description: event.target.value } : item) })}
                  value={source.description ?? ""}
                />
              </label>
              {source.tables.map((table, tableIndex) => (
                <div className="model-context-table-note" key={`${table.relation}-${tableIndex}`}>
                  <h4>{table.relation}</h4>
                  <label className="field">
                    <span>Table note</span>
                    <input
                      disabled={!editable}
                      onChange={(event) => updateDocument({ sources: modelDocument.sources.map((item, itemIndex) => itemIndex === sourceIndex ? { ...item, tables: item.tables.map((tableItem, tableItemIndex) => tableItemIndex === tableIndex ? { ...tableItem, note: event.target.value } : tableItem) } : item) })}
                      value={table.note ?? ""}
                    />
                  </label>
                  {table.columns.map((column, columnIndex) => (
                    <label className="field model-context-column-note" key={`${column.name}-${columnIndex}`}>
                      <span>{column.name}</span>
                      <input
                        disabled={!editable}
                        onChange={(event) => updateDocument({ sources: modelDocument.sources.map((item, itemIndex) => itemIndex === sourceIndex ? { ...item, tables: item.tables.map((tableItem, tableItemIndex) => tableItemIndex === tableIndex ? { ...tableItem, columns: tableItem.columns.map((columnItem, columnItemIndex) => columnItemIndex === columnIndex ? { ...columnItem, note: event.target.value } : columnItem) } : tableItem) } : item) })}
                        value={column.note ?? ""}
                      />
                    </label>
                  ))}
                </div>
              ))}
            </section>
          ))}
        </section>
      )}

      {effectiveTab === "proposals" && editable && (
        <section aria-labelledby="model-context-tab-proposals" className="model-context-panel" id="model-context-panel-proposals" role="tabpanel" tabIndex={0}>
          {proposals.length === 0 && <p className="evidence-state">No proposals are waiting.</p>}
          {proposals.map((proposal) => (
            <ModelContextProposalCard
              busy={busyProposalID === proposal.proposal_id}
              conversationHref={conversationHref}
              draft={editingProposalID === proposal.proposal_id ? proposalDraft : null}
              editing={editingProposalID === proposal.proposal_id}
              editable={editable}
              key={proposal.proposal_id}
              onAccept={(edits) => { onAccept?.(proposal.proposal_id, edits); setEditingProposalID(null); setProposalDraft(null); }}
              onCancelEdit={() => { setEditingProposalID(null); setProposalDraft(null); }}
              onChangeDraft={setProposalDraft}
              onEdit={() => beginProposalEdit(proposal)}
              onOpenConversation={onOpenConversation}
              onReject={() => onReject?.(proposal.proposal_id)}
              proposal={proposal}
            />
          ))}
        </section>
      )}

      {effectiveTab === "history" && (
        <section aria-labelledby="model-context-tab-history" className="model-context-panel" id="model-context-panel-history" role="tabpanel" tabIndex={0}>
          {versions.length === 0 ? <p className="evidence-state">No saved versions yet.</p> : (
            <ol className="model-context-history">
              {versions.map((version) => (
                <li key={`${version.version}-${version.content_hash}`}>
                  <div className="model-context-history-main">
                    <strong>v{version.version}</strong>
                    <span>{modelContextChangeKindLabel(version.change_kind)}</span>
                    <span>{version.created_at ?? "—"}</span>
                    <span>{version.created_by ?? "—"}</span>
                    {version.proposal_id ? <span className="mono">{version.proposal_id}</span> : null}
                  </div>
                  <div className="model-context-history-actions">
                    <button className="link-button" onClick={() => onViewVersion?.(version.version)} type="button">View</button>
                    {editable && <button className="secondary-button" disabled={restoringVersion !== null} onClick={() => onRestore?.(version.version)} type="button">{restoringVersion === version.version ? "Restoring…" : "Restore"}</button>}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      )}
    </div>
  );
}

export function ModelContextSettingsView({ workspaceID, pushToast, onOpenConversation }: {
  workspaceID: string | null;
  pushToast: (kind: "success" | "error", text: string) => void;
  onOpenConversation: (conversationID: string) => void;
}) {
  const [contextResult, setContextResult] = useState<ApiResult<ModelContext> | null>(null);
  const [proposals, setProposals] = useState<ModelContextProposal[]>([]);
  const [versions, setVersions] = useState<ModelContextVersion[]>([]);
  const [draft, setDraft] = useState<ModelContextDocument | null>(null);
  const [viewed, setViewed] = useState<{ version: number; context: ModelContext } | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [saving, setSaving] = useState(false);
  const [busyProposalID, setBusyProposalID] = useState<string | null>(null);
  const [restoringVersion, setRestoringVersion] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    setViewed(null);
    setSaveError(null);
    setNotice(null);
    setFieldErrors({});
    if (workspaceID === null) {
      setContextResult(null);
      setProposals([]);
      setVersions([]);
      setDraft(null);
      return;
    }
    let alive = true;
    setContextResult(null);
    setDraft(null);
    (async () => {
      const result = await apiGet<unknown>(modelContextPath(workspaceID));
      if (!alive) return;
      if (result.kind !== "ok") {
        setContextResult(result);
        setProposals([]);
        setVersions([]);
        return;
      }
      const decoded = decodeModelContext(result.value);
      if (decoded === null) {
        setContextResult({ kind: "broken", status: 0 });
        setProposals([]);
        setVersions([]);
        return;
      }
      setContextResult({ kind: "ok", value: decoded, etag: result.etag });
      setDraft(cloneModelContextDocument(decoded.document));
      if (!decoded.editable) {
        setProposals([]);
        setVersions([]);
        return;
      }
      const [proposalReply, versionReply] = await Promise.all([
        apiGet<unknown>(`${modelContextPath(workspaceID)}/proposals?${new URLSearchParams({ status: "PROPOSED" }).toString()}`),
        apiGet<unknown>(`${modelContextPath(workspaceID)}/versions`),
      ]);
      if (!alive) return;
      setProposals(proposalReply.kind === "ok" ? decodeModelContextProposals(proposalReply.value) ?? [] : []);
      setVersions(versionReply.kind === "ok" ? decodeModelContextVersions(versionReply.value) ?? [] : []);
    })();
    return () => { alive = false; };
  }, [workspaceID, reloadToken]);

  function reload() {
    setReloadToken((token) => token + 1);
  }

  async function save() {
    if (workspaceID === null || contextResult?.kind !== "ok" || draft === null) return;
    setSaving(true);
    setSaveError(null);
    setNotice(null);
    setFieldErrors({});
    const result = await sendModelContextSave(workspaceID, contextResult.value, draft);
    setSaving(false);
    if (result.kind === "ok") {
      pushToast("success", "Model context saved.");
      reload();
      return;
    }
    if (result.kind === "failure" && result.status === 412) {
      // Keep the user's edits: only the hash is stale, so a reload discards work.
      const message = "Someone changed the context — reload";
      setSaveError(message);
      pushToast("error", message);
      return;
    }
    if (result.kind === "failure" && result.status === 400) {
      const errors = fieldErrorsFromServerFields(result.fields ?? []);
      setFieldErrors(errors);
      if (Object.keys(errors).length === 0) setSaveError(closedText(result));
      return;
    }
    const message = closedText(result);
    setSaveError(message);
    pushToast("error", message);
  }

  async function accept(proposalID: string, edits?: ModelContextProposalEdits) {
    if (workspaceID === null || contextResult?.kind !== "ok") return;
    setBusyProposalID(proposalID);
    const result = await sendModelContextProposalAccept(workspaceID, contextResult.value, proposalID, edits);
    setBusyProposalID(null);
    if (result.kind === "ok") {
      pushToast("success", "Proposal accepted.");
      reload();
      return;
    }
    if (result.kind === "failure" && result.status === 412) {
      const message = "Someone changed the context — reload";
      setNotice(message);
      pushToast("error", message);
      return;
    }
    pushToast("error", closedText(result));
  }

  async function reject(proposalID: string) {
    if (workspaceID === null) return;
    setBusyProposalID(proposalID);
    const result = await apiAction<{ proposal_id: string; status: string }>(`${modelContextProposalPath(workspaceID, proposalID)}:reject`, newIdempotencyKey());
    setBusyProposalID(null);
    if (result.kind === "ok") {
      pushToast("success", "Proposal rejected.");
      reload();
      return;
    }
    pushToast("error", closedText(result));
  }

  async function restore(version: number) {
    if (workspaceID === null || contextResult?.kind !== "ok") return;
    if (!window.confirm(`Restore version ${version}? This creates a new version.`)) return;
    setRestoringVersion(version);
    const request = modelContextRestoreRequest(workspaceID, contextResult.value, version, newIdempotencyKey());
    const result = await apiMutation<unknown>(request.method, request.path, request.body, request.idempotencyKey, request.ifMatch);
    setRestoringVersion(null);
    if (result.kind === "ok") {
      pushToast("success", `Version ${version} restored.`);
      setViewed(null);
      reload();
      return;
    }
    const message = result.kind === "failure" && result.status === 412 ? "Someone changed the context — reload" : closedText(result);
    pushToast("error", message);
  }

  async function viewVersion(version: number) {
    if (workspaceID === null) return;
    const result = await apiGet<unknown>(`${modelContextPath(workspaceID)}/versions/${encodeURIComponent(String(version))}`);
    if (result.kind !== "ok") {
      pushToast("error", closedText(result));
      return;
    }
    const decoded = decodeModelContext(result.value);
    if (decoded === null) {
      pushToast("error", "The server returned an unreadable version.");
      return;
    }
    setViewed({ version, context: decoded });
  }

  if (workspaceID === null) return <p className="evidence-state">Select a workspace.</p>;
  if (contextResult === null) return <p className="evidence-state">Loading model context…</p>;
  if (contextResult.kind !== "ok") return <ClosedOrError result={contextResult} />;
  if (viewed !== null) {
    return (
      <ModelContextEditorSurface
        context={viewed.context}
        document={viewed.context.document}
        key={`viewed-${viewed.version}`}
        onCloseVersion={() => setViewed(null)}
        onChange={() => {}}
        onOpenConversation={onOpenConversation}
        onViewVersion={(version) => void viewVersion(version)}
        proposals={[]}
        versions={versions}
        viewedVersion={viewed.version}
        workspaceID={workspaceID}
      />
    );
  }
  if (draft === null) return <p className="evidence-state">Loading model context…</p>;
  return (
    <ModelContextEditorSurface
      busyProposalID={busyProposalID}
      context={contextResult.value}
      document={draft}
      fieldErrors={fieldErrors}
      key={`${contextResult.value.version}:${contextResult.value.content_hash}`}
      notice={notice}
      onAccept={(proposalID, edits) => void accept(proposalID, edits)}
      onChange={setDraft}
      onOpenConversation={onOpenConversation}
      onReject={(proposalID) => void reject(proposalID)}
      onReload={reload}
      onRestore={(version) => void restore(version)}
      onSave={() => void save()}
      onViewVersion={(version) => void viewVersion(version)}
      proposals={proposals}
      restoringVersion={restoringVersion}
      saveError={saveError}
      saving={saving}
      versions={versions}
      workspaceID={workspaceID}
    />
  );
}

const sectionCopy: Record<Section, { label: string; hint: string; icon: ComponentType }> = {
  search: { label: "Search", hint: "Search connected data", icon: IconQuestions },
  sources: { label: "Sources", hint: "Connected data and source status", icon: IconSources },
  access: { label: "Access", hint: "Workspace members and activity", icon: IconAccess },
  settings: { label: "Settings", hint: "Workspace model context", icon: IconSettings },
};

type Session = "checking" | "signedOut" | "signedIn" | "unavailable";

function App() {
  const [section, setSection] = useState<Section>("search");
  const [evidenceTarget, setEvidenceTarget] = useState<EvidenceTarget | null>(() => parseEvidenceHash(window.location.hash));
  const [health, setHealth] = useState<"checking" | "up" | "unavailable">("checking");
  const [session, setSession] = useState<Session>("checking");
  const sessionStateRef = useRef<Session>("checking");
  const logoutInProgressRef = useRef(false);
  const sessionResetRef = useRef(false);
  const [sessionCode, setSessionCode] = useState("");
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [selectedWorkspaceID, setSelectedWorkspaceID] = useState<string | null>(() =>
    parseEvidenceHash(window.location.hash)?.workspace ?? parseSearchHash(window.location.hash)?.workspace ?? null);
  const [selectedConversationID, setSelectedConversationID] = useState<string | null>(() =>
    parseSearchHash(window.location.hash)?.conversation ?? null);
  const [switcherOpen, setSwitcherOpen] = useState(false);
  const [createWorkspaceOpen, setCreateWorkspaceOpen] = useState(false);
  const [workspaceRefreshVersion, setWorkspaceRefreshVersion] = useState(0);
  const [sessionResetEpoch, setSessionResetEpoch] = useState(0);
  const [searchResetEpoch, setSearchResetEpoch] = useState(0);
  const navigationSession = useRef(newIdempotencyKey());
  const routeHash = useRef(window.location.hash);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutFailure, setLogoutFailure] = useState<string | null>(null);
  const { toasts, push: pushToastRaw, dismiss: dismissToast, clear: clearToasts } = useToasts();

  function setSessionState(next: Session) {
    sessionStateRef.current = next;
    if (next === "signedIn") sessionResetRef.current = false;
    setSession(next);
  }

  const pushToast = useCallback((kind: Toast["kind"], text: string) => {
    if (sessionStateRef.current !== "signedIn") return;
    pushToastRaw(kind, text);
  }, [pushToastRaw]);

  const resetWorkspaceSessionState = useCallback(() => {
    setSection("search");
    setEvidenceTarget(null);
    setSessionCode("");
    setWorkspaces([]);
    setSelectedWorkspaceID(null);
    setSelectedConversationID(null);
    setSwitcherOpen(false);
    setCreateWorkspaceOpen(false);
    setWorkspaceRefreshVersion((version) => version + 1);
    setSessionResetEpoch((epoch) => epoch + 1);
    navigationSession.current = newIdempotencyKey();
    setLoggingOut(false);
    setLogoutFailure(null);
    clearToasts();
    if (parseEvidenceHash(window.location.hash) || parseSearchHash(window.location.hash)) {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    }
    routeHash.current = window.location.hash;
  }, [clearToasts]);

  const expireSession = useCallback(() => {
    if (sessionStateRef.current !== "signedIn" || sessionResetRef.current) return;
    sessionResetRef.current = true;
    sessionStateRef.current = "signedOut";
    setSession("signedOut");
    resetWorkspaceSessionState();
  }, [resetWorkspaceSessionState]);

  useLayoutEffect(() => registerSessionExpiredHandler(expireSession), [expireSession]);

  const data = useWorkspaceData(selectedWorkspaceID, workspaceRefreshVersion);

  const syncLocation = useCallback(() => {
    const hash = window.location.hash;
    if (routeHash.current === hash) return;
    const previousEvidence = parseEvidenceHash(routeHash.current);
    const target = parseEvidenceHash(hash);
    const searchTarget = parseSearchHash(hash);
    const workspaceID = target?.workspace ?? searchTarget?.workspace;
    routeHash.current = hash;
    if (workspaceID) setSelectedWorkspaceID(workspaceID);
    setSelectedConversationID(target ? null : searchTarget?.conversation ?? null);
    if (!target && previousEvidence) {
      setSection("search");
      setWorkspaceRefreshVersion((version) => version + 1);
    }
    setEvidenceTarget(target);
    setSwitcherOpen(false);
    dismissFootnoteTooltip();
  }, []);

  function openEvidence(hash: string) {
    if (sessionStateRef.current !== "signedIn") return;
    const searchHash = openEvidenceHistory(hash, selectedWorkspaceID, selectedConversationID,
      window.history, window.location.pathname, window.location.search, navigationSession.current);
    if (!searchHash) return;
    routeHash.current = searchHash;
    syncLocation();
  }

  function returnFromEvidence(event: ReactMouseEvent<HTMLAnchorElement>) {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || !evidenceTarget) return;
    event.preventDefault();
    if (window.history.state?.knowvaultSearchReturn === navigationSession.current) {
      window.history.back();
      return;
    }
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${buildSearchHash(evidenceTarget.workspace, evidenceTarget.returnConversation)}`);
    syncLocation();
  }

  const invalidateRetainedSearch = useCallback(() => {
    setSearchResetEpoch((epoch) => epoch + 1);
    setWorkspaceRefreshVersion((version) => version + 1);
  }, []);

  useEffect(() => {
    window.addEventListener("hashchange", syncLocation);
    window.addEventListener("popstate", syncLocation);
    return () => {
      window.removeEventListener("hashchange", syncLocation);
      window.removeEventListener("popstate", syncLocation);
    };
  }, [syncLocation]);

  useEffect(() => {
    let alive = true;
    fetch("/api/v1/system/health", { cache: "no-store" })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then(() => alive && setHealth("up"))
      .catch(() => alive && setHealth("unavailable"));
    return () => {
      alive = false;
    };
  }, []);

  // The session probe is the workspace list itself: 200 means an established
  // session, 401 means signed out, anything else is an honest typed failure.
  useEffect(() => {
    let alive = true;
    apiGet<ListEnvelope>("/api/v1/workspaces").then((result) => {
      if (!alive) return;
      if (result.kind === "ok") {
        const list = result.value.workspaces;
        setSessionState("signedIn");
        setWorkspaces(list);
        setSelectedWorkspaceID((current) =>
          current ?? automaticWorkspaceSelection(list),
        );
      } else if (result.kind === "failure" && result.status === 401) {
        setSessionState("signedOut");
        resetWorkspaceSessionState();
      } else if (result.kind === "failure") {
        setSessionState("unavailable");
        setSessionCode(result.code);
      } else {
        setSessionState("unavailable");
        setSessionCode("");
      }
    });
    return () => {
      alive = false;
    };
  }, []);

  async function signOut() {
    if (logoutInProgressRef.current) return;
    logoutInProgressRef.current = true;
    setLoggingOut(true);
    setLogoutFailure(null);
    const csrf = await apiGet<{ csrf_token: string }>("/api/v1/session/csrf");
    if (csrf.kind === "ok") {
      try {
        const response = await fetch("/auth/logout", {
          method: "POST",
          headers: { "X-KnowVault-CSRF": csrf.value.csrf_token },
        });
        if (response.status === 204) {
          if (sessionStateRef.current !== "signedOut") {
            setSessionState("signedOut");
            resetWorkspaceSessionState();
          }
          logoutInProgressRef.current = false;
          setLoggingOut(false);
          return;
        }
        // ADR-0075: a failed termination is one closed code. The UI echoes it
        // verbatim and never guesses at the session's state.
        if (sessionStateRef.current === "signedIn") {
          setLogoutFailure(response.status === 401 ? "SESSION_TERMINATION_FAILED" : "The server returned an unexpected response.");
        }
      } catch {
        setLogoutFailure("The server is not responding.");
      }
      logoutInProgressRef.current = false;
      setLoggingOut(false);
      return;
    }
    if (csrf.kind === "failure" && csrf.status === 401) {
      if (sessionStateRef.current !== "signedOut") {
        setSessionState("signedOut");
        resetWorkspaceSessionState();
      }
    } else {
      setLogoutFailure("The server is not responding.");
    }
    logoutInProgressRef.current = false;
    setLoggingOut(false);
  }

  const selectedSummary = workspaces.find((workspace) => workspace.id === selectedWorkspaceID) ?? null;
  const workspaceTitle =
    selectedSummary?.name ??
    (data.phase === "loaded" && data.snapshot.kind === "ok" ? data.snapshot.value.name : "Workspace");

  return (
    <main className="app-shell">
      <a className="skip-link" href="#workspace-content">Skip to content</a>

      <header className="top-bar">
        <div className="brand-row">
          <span aria-hidden="true" className="brand-mark"><IconLogo /></span>
          <span>KnowVault</span>
        </div>
        {session === "signedIn" && !evidenceTarget && (
          <>
            <span aria-hidden="true" className="top-sep" />
            <WorkspaceSwitcher
              onClose={() => setSwitcherOpen(false)}
              onCreate={() => {
                setSwitcherOpen(false);
                setCreateWorkspaceOpen(true);
              }}
              onSelect={(id) => {
                setSelectedWorkspaceID(id);
                setSelectedConversationID(null);
                setSwitcherOpen(false);
                window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${buildSearchHash(id)}`);
                routeHash.current = window.location.hash;
              }}
              onToggle={() => setSwitcherOpen((open) => !open)}
              open={switcherOpen}
              selectedID={selectedWorkspaceID}
              workspaces={workspaces}
            />
          </>
        )}
        {session === "signedIn" && !evidenceTarget && section !== "search" && data.phase === "loaded" && data.snapshot.kind === "ok" && (
          <span className="mode-chip"><IconShield />{processingModeLabel(data.snapshot.value.processing_mode)}</span>
        )}
        <div className="top-spacer" />
        {session === "signedIn" && (
          <div aria-live="polite" className={health === "up" ? "edge-state online" : "edge-state"} title="Local server status">
            <span aria-hidden="true" />
            {health === "checking" ? "Checking server" : health === "up" ? "Server available" : "Server unavailable"}
          </div>
        )}
        {session === "signedIn" && !evidenceTarget && selectedSummary && <span className="role-badge">{roleLabel(selectedSummary.role)}</span>}
        {session === "signedIn" && (
          <button className="secondary-button" disabled={loggingOut} onClick={() => void signOut()} type="button">
            {loggingOut ? "Signing out…" : "Sign out"}
          </button>
        )}
        {session === "signedOut" && <a className="primary-button" href="/auth/login">Sign in</a>}
      </header>

      <div className="app-body">
        {session === "signedIn" && !evidenceTarget && (
          <nav className="rail" aria-label="Workspace sections">
            {(Object.keys(sectionCopy) as Section[]).map((item) => {
              const current = sectionCopy[item];
              return (
                <button
                  aria-current={section === item ? "page" : undefined}
                  aria-label={current.label}
                  className={section === item ? "rail-item active" : "rail-item"}
                  key={item}
                  onClick={() => {
                    dismissFootnoteTooltip();
                    if (item === "search" && section !== "search") {
                      setWorkspaceRefreshVersion((version) => version + 1);
                    }
                    setSection(item);
                  }}
                  title={current.label}
                  type="button"
                >
                  <current.icon />
                </button>
              );
            })}
          </nav>
        )}

        <section className={!evidenceTarget && section === "search" && session === "signedIn" ? "content-panel content-panel-ask" : "content-panel"} id="workspace-content" key={sessionResetEpoch} tabIndex={-1}>
          {logoutFailure && (
            <div className="launch-note" role="status">
              <strong>Sign-out failed.</strong>
              <span>{logoutFailure}</span>
            </div>
          )}

          {session === "checking" && <p className="evidence-state">Checking session…</p>}
          {session === "unavailable" && (
            <aside className="plain-note evidence-denied">
              <span aria-hidden="true"><IconInfo /></span>
              <p>Server unavailable{sessionCode ? ` (${sessionCode})` : ""}.</p>
            </aside>
          )}
          {session === "signedOut" && <SignedOutView />}

          {session === "signedIn" && evidenceTarget && (
            <EvidenceSourcePage
              key={JSON.stringify(evidenceTarget)}
              onAccessDenied={invalidateRetainedSearch}
              onReturn={returnFromEvidence}
              returnHref={buildSearchHash(evidenceTarget.workspace, evidenceTarget.returnConversation)}
              target={evidenceTarget}
              workspaceName={workspaces.find((workspace) => workspace.id === evidenceTarget.workspace)?.name ?? "Workspace"}
            />
          )}

          {session === "signedIn" && !evidenceTarget && section !== "search" && (
            <header className="page-top-bar">
              <div>
                <p className="eyebrow">{workspaceTitle}</p>
                <h1>{sectionCopy[section].label}</h1>
              </div>
            </header>
          )}

          {session === "signedIn" && (
            <AskSurface
              active={!evidenceTarget && section === "search"}
              key={`${selectedWorkspaceID}:${searchResetEpoch}`}
              onOpenEvidence={openEvidence}
              onOpenSources={() => { dismissFootnoteTooltip(); setSection("sources"); }}
              onConversationChange={(conversationID) => {
                setSelectedConversationID(conversationID);
                if (!selectedWorkspaceID) return;
                const hash = buildSearchHash(selectedWorkspaceID, conversationID);
                window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${hash}`);
                routeHash.current = hash;
              }}
              initialConversationID={selectedConversationID}
              pushToast={pushToast}
              requestedWorkspaceID={selectedWorkspaceID}
              state={data}
            />
          )}
          {session === "signedIn" && !evidenceTarget && section === "sources" && (
            <SourcesView
              onChanged={() => setWorkspaceRefreshVersion((value) => value + 1)}
              pushToast={pushToast}
              role={selectedSummary?.role ?? ""}
              state={data}
            />
          )}
          {session === "signedIn" && !evidenceTarget && section === "access" && (
            <>
              <AccessView
                key={selectedSummary?.id ?? "no-workspace"}
                onChanged={() => setWorkspaceRefreshVersion((value) => value + 1)}
                pushToast={pushToast}
                refreshVersion={workspaceRefreshVersion}
                role={selectedSummary?.role ?? ""}
                state={data}
                workspaceID={selectedWorkspaceID}
              />
            </>
          )}
          {session === "signedIn" && !evidenceTarget && section === "settings" && (
            <ModelContextSettingsView
              key={selectedWorkspaceID ?? "no-workspace"}
              onOpenConversation={(conversationID) => {
                if (!selectedWorkspaceID) return;
                const hash = buildSearchHash(selectedWorkspaceID, conversationID);
                setSection("search");
                setSelectedConversationID(conversationID);
                window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}${hash}`);
                routeHash.current = hash;
              }}
              pushToast={pushToast}
              workspaceID={selectedWorkspaceID}
            />
          )}
        </section>
      </div>

      <ToastHost onDismiss={dismissToast} toasts={toasts} />
      {createWorkspaceOpen && (
        <CreateWorkspaceDialog
          onClose={() => setCreateWorkspaceOpen(false)}
          onCreated={(snapshot) => {
            setWorkspaces((current) => {
              const next = current.filter((workspace) => workspace.id !== snapshot.id);
              next.push({ id: snapshot.id, name: snapshot.name, status: snapshot.status, revision: snapshot.revision, role: "OWNER" });
              return next.sort((left, right) => left.id.localeCompare(right.id));
            });
            dismissFootnoteTooltip();
            setSelectedWorkspaceID(snapshot.id);
            setSection("search");
            setCreateWorkspaceOpen(false);
          }}
        />
      )}
    </main>
  );
}

// WorkspaceSwitcher keeps server-returned records available for deep links
// and history while presenting ACTIVE workspaces as the primary choices.
export function WorkspaceSwitcher({ workspaces, selectedID, open, onToggle, onSelect, onClose, onCreate }: {
  workspaces: WorkspaceSummary[];
  selectedID: string | null;
  open: boolean;
  onToggle: () => void;
  onSelect: (id: string) => void;
  onClose: () => void;
  onCreate: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const selected = workspaces.find((workspace) => workspace.id === selectedID) ?? null;
  const activeWorkspaces = activeWorkspaceSummaries(workspaces);
  const archivedWorkspaces = archivedWorkspaceSummaries(workspaces);

  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    function onClick(event: MouseEvent) {
      if (containerRef.current && event.target instanceof Node && !containerRef.current.contains(event.target)) onClose();
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open, onClose]);

  return (
    <div className="workspace-switcher-wrap" ref={containerRef}>
      <button className="workspace-switcher" type="button" aria-label="Select workspace" aria-expanded={open} onClick={onToggle}>
        <span className="workspace-glyph">{selected ? selected.name.slice(0, 1).toUpperCase() : "·"}</span>
        <span>
          <small>Workspace</small>
          <strong>{selected ? selected.name : "None selected"}</strong>
        </span>
        <b aria-hidden="true"><IconChevron up={open} /></b>
      </button>
      {open && (
        <ul className="switcher-pop" role="listbox" aria-label="Workspaces">
          {activeWorkspaces.length === 0 && <li className="switcher-empty">No active workspaces</li>}
          {activeWorkspaces.map((workspace) => (
            <li key={workspace.id}>
              <button
                aria-selected={workspace.id === selectedID}
                className={workspace.id === selectedID ? "switcher-item active" : "switcher-item"}
                onClick={() => onSelect(workspace.id)}
                role="option"
                type="button"
              >
                <span className="workspace-glyph">{workspace.name.slice(0, 1).toUpperCase()}</span>
                <span className="switcher-item-main">
                  <strong>{workspace.name}</strong>
                  <small>{workspaceStatusLabel(workspace.status)} · {roleLabel(workspace.role)}</small>
                </span>
              </button>
            </li>
          ))}
          {archivedWorkspaces.length > 0 && (
            <li>
              <details className="switcher-archived">
                <summary>Archived ({archivedWorkspaces.length})</summary>
                <ul className="switcher-archived-list">
                  {archivedWorkspaces.map((workspace) => (
                    <li key={workspace.id}>
                      <button
                        aria-selected={workspace.id === selectedID}
                        className={workspace.id === selectedID ? "switcher-item active" : "switcher-item"}
                        onClick={() => onSelect(workspace.id)}
                        role="option"
                        type="button"
                      >
                        <span className="workspace-glyph">{workspace.name.slice(0, 1).toUpperCase()}</span>
                        <span className="switcher-item-main">
                          <strong>{workspace.name}</strong>
                          <small>{workspaceStatusLabel(workspace.status)} · {roleLabel(workspace.role)}</small>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </details>
            </li>
          )}
          <li className="switcher-create-row">
            <button className="switcher-create" onClick={onCreate} type="button">+ New workspace</button>
          </li>
        </ul>
      )}
    </div>
  );
}

function useModalDialog(onClose: () => void, busy = false) {
  const dialogRef = useRef<HTMLElement>(null);
  const openerRef = useRef(typeof document === "undefined" ? null : document.activeElement as HTMLElement | null);
  const current = useRef({ onClose, busy });
  current.current = { onClose, busy };

  useLayoutEffect(() => {
    const element = dialogRef.current;
    if (!element) return;
    const dialog: HTMLElement = element;
    const focusable = () => Array.from(dialog.querySelectorAll<HTMLElement>(
      'a[href], button, input, select, textarea, summary, [tabindex]',
    )).filter((element) => element.tabIndex >= 0 && !element.matches(":disabled")
      && element.getClientRects().length > 0 && getComputedStyle(element).visibility !== "hidden");
    const isTopDialog = () => Array.from(document.querySelectorAll('[role="dialog"][aria-modal="true"]'))
      .filter((element) => element.getClientRects().length > 0).at(-1) === dialog;
    function focusInside(last = false) {
      const targets = focusable();
      (last ? targets.at(-1) : targets[0])?.focus();
      if (targets.length === 0) dialog.focus();
    }
    function onKey(event: KeyboardEvent) {
      if (!isTopDialog()) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (!current.current.busy) current.current.onClose();
      } else if (event.key === "Tab") {
        const targets = focusable();
        const active = document.activeElement;
        if (targets.length === 0 || !dialog.contains(active)
          || (event.shiftKey ? active === targets[0] : active === targets.at(-1))) {
          event.preventDefault();
          focusInside(event.shiftKey);
        }
      }
    }
    function onFocus(event: FocusEvent) {
      if (isTopDialog() && event.target instanceof Node && !dialog.contains(event.target)) focusInside();
    }
    if (!dialog.contains(document.activeElement)) focusInside();
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("focusin", onFocus, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("focusin", onFocus, true);
      if (openerRef.current?.isConnected) openerRef.current.focus();
      else document.getElementById("workspace-content")?.focus();
    };
  }, []);
  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    // Disabling the focused submit button can move focus to body without a focusin event.
    const top = Array.from(document.querySelectorAll('[role="dialog"][aria-modal="true"]'))
      .filter((element) => element.getClientRects().length > 0).at(-1);
    if (busy && dialog === top && !dialog.contains(document.activeElement)) dialog.focus();
  }, [busy]);
  return dialogRef;
}

function CreateWorkspaceDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (snapshot: WorkspaceSnapshot) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [retentionPolicyID, setRetentionPolicyID] = useState("");
  const [result, setResult] = useState<ApiResult<WorkspaceSnapshot> | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const dialogRef = useModalDialog(onClose, submitting);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!name.trim() || submitting) return;
    setSubmitting(true);
    const response = await apiPost<WorkspaceSnapshot>(
      "/api/v1/workspaces",
      { name: name.trim(), description: description.trim(), retention_policy_id: retentionPolicyID.trim() },
      newIdempotencyKey(),
    );
    if (!dialogRef.current?.isConnected) return;
    setSubmitting(false);
    setResult(response);
    if (response.kind === "ok") onCreated(response.value);
  }

  return (
    <div className="sheet-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !submitting) onClose(); }}>
      <section aria-labelledby="create-workspace-title" aria-modal="true" className="source-sheet workspace-dialog" ref={dialogRef} role="dialog" tabIndex={-1}>
        <header className="sheet-header">
          <div>
            <p className="eyebrow">Access management</p>
            <h2 id="create-workspace-title">New workspace</h2>
            <p className="sheet-description">Create a workspace with its own sources, revision and access permissions.</p>
          </div>
          <button aria-label="Close" className="close-button" disabled={submitting} onClick={onClose} type="button">×</button>
        </header>
        <form className="sheet-body" onSubmit={submit}>
          <div className="source-fields">
            <label className="field"><span>Name</span><input autoFocus maxLength={160} onChange={(event) => setName(event.target.value)} required value={name} /></label>
            <label className="field"><span>Description</span><input maxLength={1000} onChange={(event) => setDescription(event.target.value)} value={description} /></label>
            <label className="field"><span>Retention policy (optional)</span><input maxLength={128} onChange={(event) => setRetentionPolicyID(event.target.value)} placeholder="retention_default" value={retentionPolicyID} /><small>Leave blank to use the default retention policy.</small></label>
          </div>
          {result && result.kind !== "ok" && <ClosedOrError result={result} />}
          <footer className="sheet-footer">
            <button className="secondary-button" disabled={submitting} onClick={onClose} type="button">Cancel</button>
            <button className="primary-button" disabled={!name.trim() || submitting} type="submit">{submitting ? "Creating…" : "Create workspace"}</button>
          </footer>
        </form>
      </section>
    </div>
  );
}

function SignedOutView() {
  return (
    <div className="page signin-page">
      <section className="page-intro">
        <p className="eyebrow">Company sign-in</p>
        <h2>Sign in with SSO</h2>
        <p>KnowVault shows the workspaces, members, sources and activity your account can access.</p>
      </section>
      <a className="primary-button" href="/auth/login">Sign in with company SSO</a>
      <p className="signin-note">Your session is limited to this browser. Your company identity provider handles sign-in; KnowVault does not receive your password.</p>
    </div>
  );
}

// Human-readable copy for a non-COMPLETED question run, without raw status codes.
export function questionStatusMessage(run: QuestionRun): string {
  if (run.tool_loop?.stop_reason === "CLARIFICATION") return run.answer ?? "Please clarify your question.";
  if (run.tool_loop && run.status === "INSUFFICIENT_EVIDENCE") return run.answer ?? NO_DATA_IN_WORKSPACE_LABEL;
  if (run.planning_status === "CLARIFICATION_REQUIRED" && run.clarification) return run.clarification;
  // 000121: the server finishes a run whose answering process died as
  // INTERRUPTED. It has no answer at all, so the turn must say so and invite
  // a retry instead of rendering the generic "not enough evidence" copy (or,
  // worse, a partial answer as if it were complete).
  if (run.status === "INTERRUPTED") return "The answer was interrupted before it finished. Ask again to get a complete answer.";
  if (run.status === "COMPLETED") return "";
  return "There is not enough evidence to answer. Try rephrasing your question or check the source status in Sources.";
}

// Grounded in the workspace's own active sources — never invented copy — so
// a brand-new workspace with nothing connected yet shows no fake examples.
function exampleQuestions(sources: SourceStatus[]): string[] {
  const names = Array.from(new Set(sources.map((source) => sourceLabel(source)).filter(Boolean)));
  if (names.length === 0) return [];
  const templates = [
    (name: string) => `Что нового в «${name}»?`,
    (name: string) => `Какие данные есть в «${name}»?`,
    (name: string) => `Когда обновлялся «${name}»?`,
    (name: string) => `Кратко: что записано в «${name}»?`,
  ];
  const count = Math.min(4, Math.max(3, names.length));
  const out: string[] = [];
  for (let index = 0; index < count; index += 1) {
    out.push(templates[index % templates.length](names[index % names.length]));
  }
  return out;
}

// The panel is addressed by a turn's citation (normal in-app click). Shared
// fragment routes live in EvidenceSourcePage and never borrow AskView state.
type PanelTarget = { turnId: string; citationId: string | null } | null;

function HowObtained({ run }: { run: QuestionRun }) {
  const snapshotLabel = run.freshness.captured_at
    ? formatTime(run.freshness.captured_at)
    : run.freshness.last_successful_sync_at
      ? formatTime(run.freshness.last_successful_sync_at)
      : freshnessStateLabel(run.freshness.state);
  return (
    <div className="how">
      <dl>
        <dt>Operation</dt><dd>{planningOperationLabel(run.planning_operation)}</dd>
        <dt>Plan confidence</dt><dd>{planningConfidenceLabel(run.planning_confidence)}</dd>
        <dt>Snapshot</dt><dd>{snapshotLabel}</dd>
        <dt>Corpus completeness</dt><dd>{run.corpus_status === "COMPLETE" ? "complete" : "incomplete"}</dd>
      </dl>
      {run.manifest_status === "PUBLISHED" && (
        <p className="how-cap"><IconCheckCircle />a server calculation using the published snapshot</p>
      )}
    </div>
  );
}

// R2 Outcome 3: the literal no-data marker. Every unified field row uses it
// when the server sent nothing, so an older answer reports "no data"
// instead of a blank, an inferred value, or a silently dropped row.
export const ANSWER_NO_DATA = "no data";

function unifiedValueText(value: string | number | undefined | null): string {
  if (value === undefined || value === null) return ANSWER_NO_DATA;
  const text = String(value).trim();
  return text.length > 0 ? text : ANSWER_NO_DATA;
}

function unifiedListText(value: Array<string | number> | undefined | null): string {
  if (!value || value.length === 0) return ANSWER_NO_DATA;
  const parts = value.map((item) => String(item).trim()).filter((item) => item.length > 0);
  return parts.length > 0 ? parts.join(" · ") : ANSWER_NO_DATA;
}

// R2 Outcome 3: the server's completeness vocabulary (QuestionAnswerResult
// completeness enum: COMPLETE | PARTIAL). The panel renders one explicit human
// label for whatever state the server sent and classifies everything that is
// not COMPLETE as not full, so PARTIAL is never silently normalized to full
// and an unrecognized state is surfaced as unknown instead of guessed.
const answerCompletenessLabels: Record<string, string> = {
  COMPLETE: "complete",
  PARTIAL: "incomplete — some data is not covered",
};

function answerCompletenessLabel(completeness: string | undefined | null): string {
  if (completeness === undefined || completeness === null) return ANSWER_NO_DATA;
  const state = String(completeness).trim();
  if (state.length === 0) return ANSWER_NO_DATA;
  return answerCompletenessLabels[state] ?? `unknown state (${state})`;
}

function answerCompletenessIsPartial(completeness: string | undefined | null): boolean {
  return typeof completeness === "string" && completeness.trim() === "PARTIAL";
}

function answerObservationWindowText(window: AnswerObservationWindow): string {
  const parts: string[] = [];
  if (window.basis) parts.push(window.basis);
  if (window.started_at && window.completed_at) {
    parts.push(`${formatTime(window.started_at)} – ${formatTime(window.completed_at)}`);
  } else if (window.started_at) {
    parts.push(`started ${formatTime(window.started_at)}`);
  } else if (window.completed_at) {
    parts.push(`completed ${formatTime(window.completed_at)}`);
  }
  return parts.join(" · ");
}

// The validated QueryIntent, rendered from the fields the server actually
// sent: no metric id, version, period, filter, output or as_of is guessed.
function unifiedIntentText(intent: AnswerIntent | undefined): string {
  if (!intent) return ANSWER_NO_DATA;
  const parts: string[] = [];
  if (intent.metric_id) parts.push(`metric: ${intent.metric_id}`);
  if (intent.version !== undefined && intent.version !== null) parts.push(`version: ${intent.version}`);
  const period = answerPeriodText(intent.period);
  if (period) parts.push(`period: ${period}`);
  if (intent.filters && intent.filters.length > 0) {
    parts.push(intent.filters.map((filter) => `${filter.name} = «${filter.value}»`).join(", "));
  }
  if (intent.output) parts.push(`output: ${intent.output}`);
  if (intent.as_of) parts.push(`as of: ${intent.as_of}`);
  return parts.length > 0 ? parts.join(" · ") : ANSWER_NO_DATA;
}

function unifiedFreshnessText(freshness: AnswerFreshness | undefined): string {
  if (!freshness) return ANSWER_NO_DATA;
  if (freshness.captured_at) return formatTime(freshness.captured_at);
  if (freshness.last_successful_sync_at) return formatTime(freshness.last_successful_sync_at);
  if (freshness.state) return freshnessStateLabel(freshness.state);
  return ANSWER_NO_DATA;
}

// R2 Outcome 3: the unified AnswerResult contract exactly as the panel
// consumes it. `answerResultFieldTexts` is the pure projection behind
// AnswerResultBlock / UnifiedAnswerRows: one display string per contract field,
// resolved only from the server's optional members, so an absent field can
// become nothing but the explicit “no data” marker. It is exported together
// with the field tuple and the two components so the in-tree probe
// web/src/answer_result_panel_test.ts can prove the row set matches
// internal/question/structured_result.go without a DOM or a new dependency.
export const ANSWER_RESULT_UNIFIED_FIELDS = [
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
] as const;

export type AnswerResultUnifiedField = (typeof ANSWER_RESULT_UNIFIED_FIELDS)[number];

export function answerResultFieldTexts(result?: AnswerResult): Record<AnswerResultUnifiedField, string> {
  return {
    run_id: unifiedValueText(result?.run_id),
    intent: unifiedIntentText(result?.intent),
    value: unifiedValueText(result?.value),
    unit: unifiedValueText(result?.unit),
    metric_version: unifiedValueText(result?.metric_version),
    snapshot_id: unifiedValueText(result?.snapshot_id),
    execution_id: unifiedValueText(result?.execution_id),
    rowset_ref: unifiedValueText(result?.rowset_ref),
    result_digest: unifiedValueText(result?.result_digest),
    completeness: answerCompletenessLabel(result?.completeness),
    freshness: unifiedFreshnessText(result?.freshness),
    evidence_refs: unifiedListText(result?.evidence_refs),
    audit_receipt: unifiedListText(result?.audit_receipt),
  };
}

// R2 Outcome 3: the unified AnswerResult view. One component renders every
// unified row for both a full structured answer and an older structured answer
// that carries no result object at all, so a missing field can only ever show
// the explicit “no data” marker -- never a blank, a zero or a guess. The
// `result` is optional precisely so the fallback case renders the same rows.
export function UnifiedAnswerRows({ result }: { result?: AnswerResult }) {
  const texts = answerResultFieldTexts(result);
  return (
    <div className="how answer-r2">
      <dl>
        <dt>Run ID</dt><dd>{texts.run_id}</dd>
        <dt>Intent</dt><dd>{texts.intent}</dd>
        <dt>Metric version</dt><dd>{texts.metric_version}</dd>
        <dt>Snapshot ID</dt><dd>{texts.snapshot_id}</dd>
        <dt>Execution ID</dt><dd>{texts.execution_id}</dd>
        <dt>Rowset</dt><dd>{texts.rowset_ref}</dd>
        <dt>Result digest</dt><dd>{texts.result_digest}</dd>
        <dt>Completeness</dt><dd>{texts.completeness}</dd>
        <dt>Freshness</dt><dd>{texts.freshness}</dd>
        <dt>Evidence references</dt><dd>{texts.evidence_refs}</dd>
        {/* R2 Outcome 3: audit_receipt references the R1 admission/outcome
            acknowledgement events of this run. The label says exactly that and
            explicitly disclaims being an independent verification or a review,
            so the panel never implies a step that did not happen. */}
        <dt>R1 audit receipt (admission and outcome events; not an independent check)</dt><dd>{texts.audit_receipt}</dd>
      </dl>
      <p className="how-cap"><IconCheckCircle />unified R2 result — missing fields are shown as “{ANSWER_NO_DATA}”</p>
    </div>
  );
}

// FIX-2 #1: the structured counterpart of an AGGREGATE/LIST answer — the
// large value plus "how this was obtained" (rule, filters, period, timezone,
// snapshot) exactly as the API sends it. Every dt/dd below is conditional on
// the matching field actually being present on answer_result; nothing here
// is invented when the server left a field absent.
export function AnswerResultBlock({ result }: { result: AnswerResult }) {
  const periodText = answerPeriodText(result.period);
  const hasObservationWindow = Boolean(result.observation_window);
  const snapshotText = result.snapshot.captured_at
    ? formatTime(result.snapshot.captured_at)
    : result.snapshot.id ?? null;
  return (
    <>
      {result.value && (
        <div className="answer-value">
          <span className="answer-value-n">{applyTypography(result.value)}</span>
          {result.unit && <span className="answer-value-u">{result.unit}</span>}
        </div>
      )}
      <div className="how">
        <dl>
          <dt>Rule</dt><dd>{result.rule}</dd>
          {result.filters && result.filters.length > 0 && (
            <>
              <dt>Filter</dt>
              <dd>{result.filters.map((filter) => `${filter.name} = «${filter.value}»`).join(", ")}</dd>
            </>
          )}
          {periodText && (<><dt>Period</dt><dd>{periodText}</dd></>)}
          {result.timezone && (<><dt>Time zone</dt><dd>{result.timezone}</dd></>)}
          {result.observation_window && (
            <><dt>Observed</dt><dd>{answerObservationWindowText(result.observation_window)}</dd></>
          )}
          {result.receipt_digest && (
            <><dt>Evidence receipt</dt><dd>{result.receipt_digest}</dd></>
          )}
          {hasObservationWindow && (result.snapshot.row_count > 0 || result.kind === "LIVE_TABLE") && (
            <><dt>Rows read</dt><dd>{result.snapshot.row_count}</dd></>
          )}
          {(snapshotText || (!hasObservationWindow && result.snapshot.row_count > 0)) && (
            <>
              <dt>Snapshot</dt>
              <dd>{snapshotText ?? "current"}{result.snapshot.row_count > 0 ? `, ${result.snapshot.row_count} rows` : ""}</dd>
            </>
          )}
        </dl>
        <p className="how-cap"><IconCheckCircle />{result.kind === "LIVE_TABLE"
          ? "a complete governed live table read; the prose answer interprets its rows"
          : "a server calculation using the snapshot"}</p>
      </div>
      <UnifiedAnswerRows result={result} />
      {answerCompletenessIsPartial(result.completeness) && (
        <p className="msg-warning">This answer uses an incomplete snapshot. The calculation does not cover the entire source.</p>
      )}
      {result.keys && result.keys.length > 0 && (
        <ul className="answer-keys">
          {result.keys.map((item) => (
            <li key={item.key}>
              <span className="answer-keys-k">{item.key}</span>
              {item.fields && (
                <span className="answer-keys-v">{Object.entries(item.fields).map(([name, value]) => `${name}: ${value}`).join(" · ")}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

// FIX-2 #2 ("Understood as"): the server's own account of a resolved bare
// period follow-up. Only the conditions the server actually reports are
// shown — a missing inherited_from_turn_id names no turn rather than
// guessing which one it was.
function UnderstoodBanner({ understood }: { understood: Understood }) {
  const periodText = answerPeriodText(understood.period);
  const parts: string[] = [];
  if (periodText) parts.push(`period: ${periodText}`);
  if (understood.source) parts.push(`source: ${understood.source}`);
  if (understood.other_conditions) parts.push(...understood.other_conditions);
  return (
    <p className="cond">
      <IconInfo />
      Understood as: {parts.length > 0 ? parts.join(" · ") : "conditions from the previous turn"}
      {understood.inherited_from_turn_id && " · other conditions inherited from the previous turn"}
    </p>
  );
}

// FIX-2 #6 ("where we searched"): shown only for a run this INSUFFICIENT_EVIDENCE
// state, listing exactly the sources the server actually consulted.
function SearchedList({ searched }: { searched: SearchedSource[] }) {
  return (
    <div className="searched-list">
      {searched.map((item) => (
        <div className="rely-row" key={item.source}>
          <span aria-hidden="true" className={`dot dot-${searchedResultVariant(item.result)}`} />
          <span className="rely-name">{item.source}</span>
          <small>{searchedResultLabel(item.result)} — {item.message}</small>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// TXT-1: formatted answer rendering with inline citation footnotes.
//
// The server already emits paragraph/fact boundaries as line breaks and
// weaves a "[N]" marker at the exact point each fact cites its evidence
// (renderAnswerPlanAtWithReceiptContext, renderCompareFacts, renderAuditControls,
// renderCodeTrace, buildVerifiedGenerativeAnswer — internal/question). The one
// defect this fixes on the client: dumping that string into a single <p>
// collapses every line break per normal HTML whitespace rules, so a
// multi-fact answer reads as one run-on paragraph and its "[N]" markers read
// as plain bracketed digits instead of clickable citations.
//
// This is a minimal, dependency-free Markdown subset — never a general
// Markdown engine and never dangerouslySetInnerHTML: every node below is a
// real React element built from parsed spans, so no HTML the model or a
// source document might contain is ever executed. Model content that is not
// marked up (no lists, no emphasis) still renders correctly: it just
// degrades to plain paragraphs, exactly per contract §5 ("the server does not
// invent formatting").
// ---------------------------------------------------------------------------

const NBSP = " ";

// Typographic cleanup applied only to plain-text runs (never inside a `code`
// span, which must stay literal): "straight" quotes become guillemets, and a
// digit run gets a non-breaking joiner to its thousands group or its
// adjoining unit/currency symbol so a number can never wrap away from its
// unit ("15 000 ₽" survives reflow as one unbreakable group).
function applyTypography(text: string): string {
  let out = text.replace(/"([^"\n]{1,200})"/g, "«$1»");
  out = out.replace(/(\d)[  ](?=\d{3}(?:[^\d]|$))/g, `$1${NBSP}`);
  out = out.replace(/(\d)[  ](₽|\u0440\u0443\u0431\.?|USD|EUR|\$|€|\u043a\u0433|\u043a\u043c\/\u0447|\u043a\u043c|\u043c²|\u043c2|\u043c3|\u043c\u043b|\u043c\u043c|\u0441\u043c|\u043b|\u0448\u0442\.?|%)/g, `$1${NBSP}$2`);
  return out;
}

type AnswerBlock =
  | { kind: "h"; level: 3 | 4; text: string }
  | { kind: "list"; ordered: boolean; items: string[] }
  | { kind: "p"; text: string };

// Line-based block parser: every non-blank line the server ever emits is one
// logical unit (one fact, one section title, one excerpt) — see the comment
// above — so each becomes its own paragraph unless it is a heading or a run
// of list-marker lines, which group into one list. A blank line is just a
// boundary; it produces no block of its own.
function parseAnswerBlocks(source: string): AnswerBlock[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: AnswerBlock[] = [];
  let listBuffer: { kind: "list"; ordered: boolean; items: string[] } | null = null;
  const flushList = () => {
    if (listBuffer) {
      blocks.push(listBuffer);
      listBuffer = null;
    }
  };
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      flushList();
      continue;
    }
    const heading = line.match(/^(#{3,4})\s+(.*)$/);
    if (heading) {
      flushList();
      blocks.push({ kind: "h", level: heading[1].length === 3 ? 3 : 4, text: heading[2].trim() });
      continue;
    }
    const unordered = line.match(/^[-*]\s+(.*)$/);
    if (unordered) {
      if (!listBuffer || listBuffer.ordered) {
        flushList();
        listBuffer = { kind: "list", ordered: false, items: [] };
      }
      listBuffer.items.push(unordered[1].trim());
      continue;
    }
    const ordered = line.match(/^\d+[.)]\s+(.*)$/);
    if (ordered) {
      if (!listBuffer || !listBuffer.ordered) {
        flushList();
        listBuffer = { kind: "list", ordered: true, items: [] };
      }
      listBuffer.items.push(ordered[1].trim());
      continue;
    }
    flushList();
    blocks.push({ kind: "p", text: line });
  }
  flushList();
  return blocks;
}

// Every "[N]" the raw answer text carries, regardless of whether the inline
// renderer below ends up resolving it against a real citation. Used only to
// compute which citations still need the fallback list (see TurnAnswer) —
// deliberately independent of the render pass itself, since a React child
// component's body has not run yet at the point its parent's own JSX is
// being constructed.
function extractCitationNumbers(text: string): Set<number> {
  const numbers = new Set<number>();
  const re = /\[(\d+)\]/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text))) numbers.add(Number(match[1]));
  return numbers;
}

type InlineCtx = {
  citationsByNumber: Map<number, QuestionCitation>;
  isActive: (citationID: string) => boolean;
  onSelectCitation: (citationID: string) => void;
};

// Tooltip preview text: a little more room than the basis-row excerpt (this
// is a hover/focus preview, not a persistent label), still collapsed to one
// short fragment — never the full evidence text.
function tooltipExcerptText(excerpt: string): string {
  const technical = tryParseTechnicalFragment(excerpt);
  const text = technical ? summarizeTechnicalFragment(technical) : excerpt;
  return text.length > 140 ? `${text.slice(0, 140)}…` : text;
}

// TXT-2: at most one footnote tooltip is ever open across the whole page.
// `closeVisibleFootnoteTooltip` holds that tooltip's own dismissal (or null);
// opening a new one calls whatever is already there before replacing it.
// Everything below that must close "any tooltip that happens to be open" —
// a click anywhere, a scroll of the feed, Escape — goes through this one
// module-level slot instead of being threaded through props, so it works no
// matter how deep the open FootnoteMark instance sits.
let closeVisibleFootnoteTooltip: (() => void) | null = null;
let footnoteTooltipGlobalsInstalled = false;
let lastPointerWasTouch = false;

function dismissFootnoteTooltip() {
  closeVisibleFootnoteTooltip?.();
  closeVisibleFootnoteTooltip = null;
}

// Installed once for the life of the page (not per FootnoteMark instance):
// closes whatever tooltip is open on a click anywhere, a scroll of any
// scrollable ancestor (capture phase so a non-bubbling "scroll" on the feed
// still reaches window), or Escape. Also tracks whether the most recent
// pointer was touch, so a tap-driven focus doesn't schedule a tooltip that a
// mouse-driven focus should.
function ensureFootnoteTooltipGlobals() {
  if (footnoteTooltipGlobalsInstalled) return;
  footnoteTooltipGlobalsInstalled = true;
  window.addEventListener("pointerdown", (event) => {
    lastPointerWasTouch = (event as PointerEvent).pointerType !== "mouse";
  }, { capture: true });
  window.addEventListener("click", dismissFootnoteTooltip, { capture: true });
  window.addEventListener("scroll", dismissFootnoteTooltip, { capture: true, passive: true });
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") dismissFootnoteTooltip();
  }, { capture: true });
}

// The inline citation label: a small clickable [N] woven into the text at
// the exact point the server placed it. Hover or Tab-focus reveals the
// source's own excerpt as a preview after a short delay; click opens the
// same evidence panel the old basis-row buttons already opened
// (onSelectCitation is unchanged) and hides the preview immediately.
function FootnoteMark({ citation, isActive, onSelect }: {
  citation: QuestionCitation;
  isActive: boolean;
  onSelect: () => void;
}) {
  const label = citationLabel(citation.excerpt, citation.number - 1);
  const preview = tooltipExcerptText(citation.excerpt);
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const tipRef = useRef<HTMLSpanElement | null>(null);
  const showTimerRef = useRef<number | null>(null);
  const [visible, setVisible] = useState(false);
  const [tipStyle, setTipStyle] = useState<CSSProperties>({});

  useEffect(() => ensureFootnoteTooltipGlobals(), []);

  const cancelScheduledShow = useCallback(() => {
    if (showTimerRef.current !== null) {
      window.clearTimeout(showTimerRef.current);
      showTimerRef.current = null;
    }
  }, []);

  // Stable identity for the lifetime of this instance (empty/stable deps,
  // never recreated), so the module-level slot above can tell "close the
  // tooltip that's currently open" apart from "close myself, but I wasn't
  // the one showing" — the self-reference below resolves at call time,
  // after `closeTip` itself has been assigned.
  const closeTip = useCallback(() => {
    cancelScheduledShow();
    setVisible(false);
    if (closeVisibleFootnoteTooltip === closeTip) closeVisibleFootnoteTooltip = null;
  }, [cancelScheduledShow]);

  const showTip = useCallback(() => {
    if (closeVisibleFootnoteTooltip && closeVisibleFootnoteTooltip !== closeTip) closeVisibleFootnoteTooltip();
    closeVisibleFootnoteTooltip = closeTip;
    setVisible(true);
  }, [closeTip]);

  const scheduleShow = useCallback(() => {
    if (lastPointerWasTouch) return; // touch: tap opens the panel directly, no preview.
    cancelScheduledShow();
    showTimerRef.current = window.setTimeout(() => {
      showTimerRef.current = null;
      showTip();
    }, 200);
  }, [cancelScheduledShow, showTip]);

  // Unmounting (turn/topic/screen change re-renders the feed away) must not
  // leave this instance's close registered as "the" open tooltip forever.
  useEffect(() => closeTip, [closeTip]);

  // Position: clamp to the feed's own viewport rect (not the whole window)
  // so the tooltip never spills into the composer below it or the evidence
  // panel beside it, and flips above/below depending on which side actually
  // has room.
  useLayoutEffect(() => {
    if (!visible) return;
    const buttonEl = buttonRef.current;
    const tipEl = tipRef.current;
    if (!buttonEl || !tipEl) return;
    const feedEl = buttonEl.closest(".flow, .search-pilot") as HTMLElement | null;
    const feedRect = feedEl?.getBoundingClientRect();
    const bounds = feedEl && feedRect ? {
      top: feedRect.top + feedEl.clientTop,
      left: feedRect.left + feedEl.clientLeft,
      right: feedRect.left + feedEl.clientLeft + feedEl.clientWidth,
      bottom: feedRect.top + feedEl.clientTop + feedEl.clientHeight,
    } : { top: 0, left: 0, right: window.innerWidth, bottom: window.innerHeight };
    const buttonRect = buttonEl.getBoundingClientRect();
    const tipRect = tipEl.getBoundingClientRect();
    const margin = 8;
    const showBelow = buttonRect.top - tipRect.height - margin < bounds.top;
    const naturalLeft = buttonRect.left + buttonRect.width / 2 - tipRect.width / 2;
    const minLeft = bounds.left + margin;
    const maxLeft = Math.max(minLeft, bounds.right - tipRect.width - margin);
    const clampedLeft = Math.min(Math.max(naturalLeft, minLeft), maxLeft);
    setTipStyle({
      left: `${clampedLeft - buttonRect.left}px`,
      transform: "none",
      ...(showBelow
        ? { top: "calc(100% + 8px)", bottom: "auto" }
        : { bottom: "calc(100% + 8px)", top: "auto" }),
    });
  }, [visible]);

  return (
    <button
      aria-label={`Evidence ${citation.number}: ${label}`}
      aria-expanded={isActive}
      className={isActive ? "fn fn-active" : "fn"}
      data-evidence-link={`Evidence ${citation.evidence_fragment_id}`}
      onBlur={closeTip}
      onClick={(event) => {
        event.stopPropagation();
        closeTip();
        onSelect();
      }}
      onFocus={scheduleShow}
      onPointerEnter={(event) => {
        if (event.pointerType !== "mouse") return;
        scheduleShow();
      }}
      onPointerLeave={closeTip}
      ref={buttonRef}
      type="button"
    >
      {citation.number}
      <span
        className={visible ? "fn-tip fn-tip-visible" : "fn-tip"}
        ref={tipRef}
        role="tooltip"
        style={tipStyle}
      >
        <b>{label}</b>
        {citation.anchor && <span className="fn-tip-where">{citation.anchor}</span>}
        <q>{preview}</q>
        <span className="fn-tip-hint">{citationGroundingText(citation.grounding_status)}</span>
        <span className="fn-tip-hint">Click to open the evidence</span>
      </span>
    </button>
  );
}

// Inline span tokenizer: `code`, **bold**, *italic* and the citation marker
// "[N]" — the whole supported subset (contract §1). An unresolved "[N]"
// (number with no matching citation) is left as literal text rather than
// invented into a dead link. Plain-text runs between tokens get the
// typographic cleanup above.
function renderInline(text: string, ctx: InlineCtx, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*|\[(\d+)\]/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let tokenIndex = 0;
  while ((match = re.exec(text))) {
    if (match.index > lastIndex) {
      nodes.push(applyTypography(text.slice(lastIndex, match.index)));
    }
    const key = `${keyPrefix}-${tokenIndex}`;
    if (match[1] !== undefined) {
      nodes.push(<code className="ans-code" key={key}>{match[1]}</code>);
    } else if (match[2] !== undefined) {
      nodes.push(<strong key={key}>{renderInline(match[2], ctx, `${key}b`)}</strong>);
    } else if (match[3] !== undefined) {
      nodes.push(<em key={key}>{renderInline(match[3], ctx, `${key}i`)}</em>);
    } else if (match[4] !== undefined) {
      const citation = ctx.citationsByNumber.get(Number(match[4]));
      if (citation) {
        nodes.push(
          <FootnoteMark citation={citation} isActive={ctx.isActive(citation.citation_id)} key={key} onSelect={() => ctx.onSelectCitation(citation.citation_id)} />,
        );
      } else {
        nodes.push(match[0]);
      }
    }
    lastIndex = re.lastIndex;
    tokenIndex += 1;
  }
  if (lastIndex < text.length) nodes.push(applyTypography(text.slice(lastIndex)));
  return nodes;
}

// The server escapes source excerpts for Markdown and HTML before storing the
// answer. Decode that fixed escape set once, then let React create a text node.
// Passing the quote through renderInline would turn document text into markup.
function literalSourceExcerpt(escaped: string): string {
  const entities: Record<string, string> = { amp: "&", lt: "<", gt: ">", "#34": '"', "#39": "'" };
  const markdown = escaped.replace(/\\([\\`*_\[\]()#!|])/g, "$1");
  return markdown.replace(/&(amp|lt|gt|#34|#39);/g, (_match, entity: string) => entities[entity]);
}

function renderSourceExcerptLine(text: string, ctx: InlineCtx, key: string): ReactNode | null {
  const match = text.match(/^(Source excerpt|\u0424\u0440\u0430\u0433\u043c\u0435\u043d\u0442 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430) \[(\d+)\]: “(.*)”$/);
  if (!match) return null;
  return <p className="ans-p" key={key}>{renderInline(`${match[1]} [${match[2]}]: `, ctx, key)}“{literalSourceExcerpt(match[3])}”</p>;
}

function renderAnswerBlock(block: AnswerBlock, index: number, ctx: InlineCtx): ReactNode {
  const key = `blk${index}`;
  if (block.kind === "h") {
    return block.level === 3
      ? <h3 className="ans-h ans-h3" key={key}>{renderInline(block.text, ctx, key)}</h3>
      : <h4 className="ans-h ans-h4" key={key}>{renderInline(block.text, ctx, key)}</h4>;
  }
  if (block.kind === "list") {
    const items = block.items.map((item, itemIndex) => <li key={`${key}-${itemIndex}`}>{renderInline(item, ctx, `${key}-${itemIndex}`)}</li>);
    return block.ordered
      ? <ol className="ans-list" key={key}>{items}</ol>
      : <ul className="ans-list" key={key}>{items}</ul>;
  }
  return renderSourceExcerptLine(block.text, ctx, key)
    ?? <p className="ans-p" key={key}>{renderInline(block.text, ctx, key)}</p>;
}

const ANSWER_COLLAPSED_BLOCK_COUNT = 8;

export function AnswerBody({ text, citations, turnId, panelTurnId, selectedCitationId, onSelectCitation }: {
  text: string;
  citations: QuestionCitation[];
  turnId: string;
  panelTurnId: string | null;
  selectedCitationId: string | null;
  onSelectCitation: (citationID: string) => void;
}) {
  const blocks = useMemo(() => parseAnswerBlocks(text), [text]);
  const [expanded, setExpanded] = useState(true);
  const canCollapse = blocks.length > ANSWER_COLLAPSED_BLOCK_COUNT + 1;
  const visibleBlocks = expanded || !canCollapse ? blocks : blocks.slice(0, ANSWER_COLLAPSED_BLOCK_COUNT);
  const citationsByNumber = useMemo(() => new Map(citations.map((citation) => [citation.number, citation])), [citations]);
  const ctx: InlineCtx = {
    citationsByNumber,
    isActive: (id) => panelTurnId === turnId && selectedCitationId === id,
    onSelectCitation,
  };
  return (
    <div className="ans-blocks">
      {visibleBlocks.map((block, index) => renderAnswerBlock(block, index, ctx))}
      {canCollapse && (
        <button aria-expanded={expanded} className="ans-more" onClick={(event) => { event.stopPropagation(); setExpanded((value) => !value); }} type="button">
          {expanded ? "Collapse" : "Show all"}
        </button>
      )}
    </div>
  );
}

// The same disclosure is used by the conversation view and the single
// question surface. The standalone surface keeps the result payload hidden:
// people can see which governed tools ran and whether they completed without
// putting row values, ids or hashes into the answer itself.
// TXT-2: the collapsed "how it was found" disclosure is the one place a turn
// discloses both its tool steps and (via `footer`, TurnAnswer only) its
// evidence-verification status, so the same information is never printed a
// second time as standalone boxes. Closed by default -- a demo reader should
// not be shown a wall of trace text before reading the answer.
function ToolCallsDisclosure({ run, showResults = true, footer }: { run: QuestionRun; showResults?: boolean; footer?: ReactNode }) {
  if (!run.tool_loop || run.tool_loop.calls.length === 0) {
    return footer ? (
      <details className="tool-trace">
        <summary>{TOOL_CALLS_TITLE}</summary>
        {footer}
      </details>
    ) : null;
  }
  return (
    <details className="tool-trace">
      <summary>{TOOL_CALLS_TITLE} · {run.tool_loop.calls.length}</summary>
      <ol>
        {run.tool_loop.calls.map((call, index) => {
          const summary = toolCallSummary(call);
          return (
            <li key={`${call.id}-${index}`}>
              {showResults ? (
                <details>
                  <summary>{KNOWLEDGE_TOOL_LABELS[call.name] ?? "Source request"} · {(call.duration_ms / 1000).toLocaleString("en-US", { maximumFractionDigits: 1 })} s{call.outcome !== "SUCCEEDED" ? " · failed" : ""}</summary>
                  <pre>{call.result.text}</pre>
                </details>
              ) : (
                <span>
                  {KNOWLEDGE_TOOL_LABELS[call.name] ?? "Source request"} · {(call.duration_ms / 1000).toLocaleString("en-US", { maximumFractionDigits: 1 })} s
                  <span className="tool-trace-summary">{summary.request && <>Request: {summary.request} · </>}{summary.result}</span>
                </span>
              )}
            </li>
          );
        })}
      </ol>
      {footer}
    </details>
  );
}

// S2: the model-context usage summary. It is plain React text (never HTML),
// so a term like "<script>" is escaped by the renderer, and it is shown only
// when the run's strictly decoded workspace_context actually carries terms.
export function WorkspaceContextUsage({ toolLoop }: { toolLoop?: unknown }) {
  const line = workspaceContextUsageLineFromToolLoop(toolLoop);
  if (line === null) return null;
  return <p className="workspace-context-usage">{line}</p>;
}

export function hasLiveDataReceipt(run: Pick<QuestionRun, "status" | "answer_result">): boolean {
  const result = run.answer_result;
  return run.status === "COMPLETED" && Boolean(
    result?.receipt_digest || result?.receipts?.some((receipt) => receipt.receipt_digest) ||
    (result?.result_digest && result.execution_id),
  );
}

export function liveTableReceipts(result?: AnswerResult): LiveTableReceipt[] {
  if (!result || result.kind !== "LIVE_TABLE") return [];
  if (result.receipts && result.receipts.length > 0) return result.receipts.filter(isLiveTableReceipt).slice(0, 3);
  if (!result.execution_id || !result.receipt_digest) return [];
  const receipt: LiveTableReceipt = {
    execution_id: result.execution_id,
    result_digest: result.result_digest ?? "",
    receipt_digest: result.receipt_digest,
    row_count: result.snapshot.row_count,
    completeness: result.completeness,
    observation_window: result.observation_window,
  };
  return isLiveTableReceipt(receipt) ? [receipt] : [];
}

function isLiveTableReceipt(value: unknown): value is LiveTableReceipt {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const receipt = value as Record<string, unknown>;
  const hash = (candidate: unknown) => typeof candidate === "string" && /^sha256:[0-9a-f]{64}$/.test(candidate);
  const observation = receipt.observation_window;
  const observationIsSafe = observation === undefined || (
    typeof observation === "object" && observation !== null && !Array.isArray(observation) &&
    ["basis", "started_at", "completed_at"].every((key) => {
      const field = (observation as Record<string, unknown>)[key];
      return field === undefined || typeof field === "string";
    })
  );
  return typeof receipt.execution_id === "string" && receipt.execution_id.length > 0 &&
    receipt.execution_id.length <= 256 && hash(receipt.result_digest) && hash(receipt.receipt_digest) &&
    typeof receipt.row_count === "number" && Number.isInteger(receipt.row_count) &&
    receipt.row_count >= 0 && receipt.row_count <= 100 && receipt.completeness === "COMPLETE" && observationIsSafe;
}

export function liveTablePayloadForReceipt(
  run: Pick<QuestionRun, "tool_loop">,
  receipt: LiveTableReceipt,
): LiveTablePayload | null {
  const calls = run.tool_loop?.calls ?? [];
  for (const call of calls) {
    if (call.name !== "knowvault_ask_live_data" || call.outcome !== "SUCCEEDED" || call.result.is_error) continue;
    const raw = call.result.structured ?? call.result.text;
    let value: unknown = raw;
    if (typeof raw === "string") {
      try {
        value = JSON.parse(raw) as unknown;
      } catch {
        continue;
      }
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    const projection = value as Record<string, unknown>;
    if (!isLiveTableReceipt(receipt) ||
      projection.attempt_id !== receipt.execution_id || projection.complete !== true ||
      projection.result_digest !== receipt.result_digest || projection.receipt_digest !== receipt.receipt_digest) continue;
    const readWindow = projection.read_window;
    if (typeof readWindow !== "object" || readWindow === null || Array.isArray(readWindow) ||
      (readWindow as Record<string, unknown>).complete !== true) continue;
    const columns = projection.columns;
    const rows = projection.rows;
    const rowCount = projection.row_count;
    if (!Array.isArray(columns) || !Array.isArray(rows) || typeof rowCount !== "number" ||
      !Number.isInteger(rowCount) || rowCount !== receipt.row_count || rowCount < 0 || rowCount > 100 ||
      columns.length === 0 || columns.length > 64 || rows.length !== rowCount || rows.length * columns.length > 4096 ||
      columns.some((column) => typeof column !== "string" || column.length === 0) ||
      rows.some((row) => !Array.isArray(row) || row.length !== columns.length ||
        row.some((cell) => cell !== null && typeof cell !== "string"))) continue;
    return { columns: columns as string[], rows: rows as Array<Array<string | null>>, row_count: rowCount };
  }
  return null;
}

export function comparisonEvidenceForReceipt(
  run: Pick<QuestionRun, "tool_loop">,
  receipt: LiveTableReceipt,
): ComparisonEvidence | null {
  if (!isLiveTableReceipt(receipt) || receipt.row_count !== 2) return null;
  const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
  const decimal = (value: unknown): value is string => typeof value === "string" && value.length <= 128 && /^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)$/.test(value);
  const day = (value: unknown): value is ComparisonDay => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const item = value as Record<string, unknown>;
    return Object.keys(item).sort().join(",") === "contributing_rows,date,distinct_subjects,snapshot_at,value" &&
      typeof item.date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(item.date) &&
      typeof item.snapshot_at === "string" && !Number.isNaN(Date.parse(item.snapshot_at)) &&
      decimal(item.value) && Number.isSafeInteger(item.contributing_rows) &&
      (item.contributing_rows as number) > 0 && item.distinct_subjects === item.contributing_rows;
  };
  for (const call of run.tool_loop?.calls ?? []) {
    if (call.name !== "knowvault_compare_metric" || call.outcome !== "SUCCEEDED" || call.result.is_error) continue;
    let value: unknown = call.result.structured ?? call.result.text;
    if (typeof value === "string") {
      try { value = JSON.parse(value) as unknown; } catch { continue; }
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) continue;
    const item = value as Record<string, unknown>;
    if (Object.keys(item).sort().join(",") !== "attempt_id,coverage,delta,evidence_digest,evidence_schema_version,exposed_schema_revision,first,metric_id,percent_change,profile_hash,raw_result_digest,receipt_digest,second,unit" ||
      item.attempt_id !== receipt.execution_id || item.raw_result_digest !== receipt.result_digest ||
      item.receipt_digest !== receipt.receipt_digest || item.evidence_schema_version !== 1 ||
      !Number.isSafeInteger(item.exposed_schema_revision) || (item.exposed_schema_revision as number) < 1 ||
      typeof item.metric_id !== "string" || item.metric_id.length === 0 || item.metric_id.length > 128 ||
      !digest(item.profile_hash) || !digest(item.evidence_digest) ||
      typeof item.unit !== "string" || item.unit.length === 0 || item.unit.length > 128 ||
      item.coverage !== "OBSERVED_SNAPSHOT" || !day(item.first) || !day(item.second) ||
      (item.first as ComparisonDay).date === (item.second as ComparisonDay).date ||
      !decimal(item.delta) || !(item.percent_change === "" || decimal(item.percent_change))) continue;
    return item as ComparisonEvidence;
  }
  return null;
}

export function LiveTableEvidenceList({ result, run }: { result: AnswerResult; run: QuestionRun }) {
  const receipts = liveTableReceipts(result);
  if (receipts.length === 0) return null;
  return (
    <section aria-label="Live result evidence" className="live-table-evidence-list">
      {receipts.map((receipt, index) => (
        <LiveTableEvidenceItem key={`${receipt.execution_id}-${index}`} ordinal={index + 1} receipt={receipt} run={run} />
      ))}
    </section>
  );
}

export function LiveResultEvidencePanel({ run }: { run: QuestionRun }) {
  if (!run.answer_result || liveTableReceipts(run.answer_result).length === 0) return null;
  return (
    <div className="live-result-panel">
      <p>This answer used live database reads. Each receipt records the result and when the database was read.</p>
      <LiveTableEvidenceList result={run.answer_result} run={run} />
    </div>
  );
}

function LiveTableEvidenceItem({ ordinal, receipt, run }: {
  ordinal: number;
  receipt: LiveTableReceipt;
  run: QuestionRun;
}) {
  const [showTable, setShowTable] = useState(false);
  const payload = liveTablePayloadForReceipt(run, receipt);
  const comparison = comparisonEvidenceForReceipt(run, receipt);
  const tableID = `live-result-table-${run.question_run_id}-${ordinal}`;
  const readStarted = receipt.observation_window?.started_at;
  const readAt = receipt.observation_window?.completed_at;
  return (
    <details className="live-result-evidence">
      <summary>Live result {ordinal} · {comparison ? `${comparison.first.date}: ${comparison.first.value} → ${comparison.second.date}: ${comparison.second.value}` : `${receipt.row_count.toLocaleString("en-US")} ${receipt.row_count === 1 ? "row" : "rows"}`}{readAt ? ` · read ${formatTime(readAt)}` : ""}</summary>
      <p>Database read: {readStarted && readAt ? `${formatTime(readStarted)} – ${formatTime(readAt)}` : readAt ? formatTime(readAt) : "time unavailable"}</p>
      {comparison ? (
        <div className="live-comparison-evidence">
          <p>Metric: {comparison.metric_id} · Unit: {comparison.unit === "unknown" ? "unknown" : comparison.unit} · Coverage: observed snapshots only; full population coverage is unknown.</p>
          <table className="live-table-payload">
            <caption>Observed values · Live result {ordinal}</caption>
            <thead><tr><th scope="col">Date</th><th scope="col">Observed value</th><th scope="col">Snapshot time</th><th scope="col">Observed subjects</th></tr></thead>
            <tbody>{[comparison.first, comparison.second].map((day) => (
              <tr key={day.date}><th scope="row">{day.date}</th><td>{day.value}</td><td>{day.snapshot_at}</td><td>{day.distinct_subjects.toLocaleString("en-US")}</td></tr>
            ))}</tbody>
          </table>
          <p>Delta (first − second): {comparison.delta} · Change relative to second: {comparison.percent_change === "" ? "undefined (second value is zero)" : `${comparison.percent_change}%`}</p>
        </div>
      ) : payload ? (
        <>
          <button aria-controls={tableID} aria-expanded={showTable} className="text-button live-table-toggle" onClick={() => setShowTable((visible) => !visible)} type="button">
            {showTable ? "Hide returned table" : "Show returned table"}
          </button>
          <div className="live-table-scroll" id={tableID}>
            {showTable && (
              <table className="live-table-payload">
                <caption>Returned rows · Live result {ordinal}</caption>
                <thead><tr>{payload.columns.map((column, index) => <th key={`${column}-${index}`} scope="col">{column}</th>)}</tr></thead>
                <tbody>{payload.rows.map((row, rowIndex) => (
                  <tr key={rowIndex}>{row.map((cell, columnIndex) => <td key={columnIndex}>{cell === null ? "NULL" : cell}</td>)}</tr>
                ))}</tbody>
              </table>
            )}
          </div>
        </>
      ) : (
        <p className="live-table-unavailable">The table payload is unavailable for this receipt.</p>
      )}
      <details className="live-receipt-technical">
        <summary>Technical details</summary>
        <dl>
          <dt>Execution ID</dt><dd className="mono">{receipt.execution_id}</dd>
          <dt>Result digest</dt><dd className="mono">{receipt.result_digest}</dd>
          <dt>Receipt digest</dt><dd className="mono">{receipt.receipt_digest}</dd>
          <dt>Read window start</dt><dd className="mono">{receipt.observation_window?.started_at ?? "—"}</dd>
          <dt>Read window end</dt><dd className="mono">{receipt.observation_window?.completed_at ?? "—"}</dd>
          <dt>Read basis</dt><dd className="mono">{receipt.observation_window?.basis ?? "—"}</dd>
          {comparison && <>
            <dt>Semantic evidence digest</dt><dd className="mono">{comparison.evidence_digest}</dd>
            <dt>Profile hash</dt><dd className="mono">{comparison.profile_hash}</dd>
            <dt>Evidence schema</dt><dd>{comparison.evidence_schema_version}</dd>
            <dt>Exposed schema revision</dt><dd>{comparison.exposed_schema_revision}</dd>
          </>}
        </dl>
      </details>
    </details>
  );
}

function TurnAnswer({ run, turnId, panelTurnId, selectedCitationId, onSelectCitation }: {
  run: QuestionRun;
  turnId: string;
  panelTurnId: string | null;
  selectedCitationId: string | null;
  onSelectCitation: (citationID: string) => void;
}) {
  const statusMessage = questionStatusMessage(run);
  const corpusWarning = corpusStatusWarning(run.corpus_status);
  const isQuote = run.verification_method === "BYTE_EXACT_CITATION";
  const showGenericHow = run.status === "COMPLETED" && run.planning_operation === "AGGREGATE" && !run.answer_result;
  // R2 Outcome 3: a structured answer is an aggregate reduction (the rowset
  // LIST reduction is an AGGREGATE function) or a LIST projection. Either way
  // a COMPLETED older answer without answer_result must still get the unified
  // panel; the AGGREGATE HowObtained block and the answer_result-present
  // branch below are untouched.
  const showUnifiedFallback = run.status === "COMPLETED" && (run.planning_operation === "AGGREGATE" || run.planning_operation === "LIST") && !run.answer_result;
  const hasInsufficientEvidence = run.uncertainties.some((item) => item.code === "INSUFFICIENT_EVIDENCE");
  const hasLiveReceipt = hasLiveDataReceipt(run);
  // TXT-1 §2: a citation whose "[N]" marker was actually found and woven
  // into the running text (FootnoteMark, inside AnswerBody) needs no second
  // mention. Only a citation the text never referenced — which real server
  // output should not produce, but a defensive client must not silently
  // drop — falls back to the old basis-row list below.
  const referencedCitationNumbers = run.answer ? extractCitationNumbers(run.answer) : new Set<number>();
  const leftoverCitations = run.citations.filter((citation) => !referencedCitationNumbers.has(citation.number));
  // TXT-2: routine "it checked out" verification status is disclosure, not a
  // warning -- it belongs folded into the one collapsed "how it was found"
  // panel below, not repeated as its own always-open box. Only a claim or
  // citation that actually failed verification stays visible on its own.
  const isAddressBound = run.answer_mode === "TOOL_LOOP" || run.verification_method === "ADDRESS_BOUND";
  const claimIsNegative = isAddressBound ? !run.tool_loop?.all_claims_bound : run.grounding_status !== "CONFIRMED_BY_FRAGMENT";
  const ungroundedCitations = run.citations.filter((citation) => citation.grounding_status !== "CONFIRMED_BY_FRAGMENT");
  const evidenceFooter = run.answer ? (
    <div className="tool-trace-evidence">
      <p>{questionClaimGroundingLabel(run)}</p>
      {run.citations.length > 0 && (
        <p>{run.citations.map((citation) => `Evidence ${citation.number}: ${citationGroundingText(citation.grounding_status)}`).join("; ")}.</p>
      )}
    </div>
  ) : null;
  return (
    <>
      <ToolCallsDisclosure footer={evidenceFooter} run={run} showResults={false} />
      {run.understood && <UnderstoodBanner understood={run.understood} />}
      {showGenericHow && <HowObtained run={run} />}
      {run.answer_result ? (
        run.answer_result.kind === "LIVE_TABLE"
          ? null
          : <AnswerResultBlock result={run.answer_result} />
      ) : (
        // R2 Outcome 3: an older structured answer (AGGREGATE/LIST completed
        // before the unified result existed) still gets the unified panel --
        // every row renders “no data” rather than the panel silently
        // vanishing.
        showUnifiedFallback && <UnifiedAnswerRows />
      )}
      {statusMessage ? (
        <p className="msg-warning msg-compact" title={`${statusMessage}${run.failure_code ? ` Code: ${run.failure_code}.` : ""}`}>
          {statusMessage}{run.failure_code ? ` Code: ${run.failure_code}.` : ""}
        </p>
      ) : (
        <>
          {run.answer && (isQuote ? (
            <blockquote className="answer-quote">
              <span className="badge badge-quote"><IconCheckCircle />quote verified</span>
              <AnswerBody citations={run.citations} onSelectCitation={onSelectCitation} panelTurnId={panelTurnId} selectedCitationId={selectedCitationId} text={run.answer} turnId={turnId} />
            </blockquote>
          ) : (
            <div className="answer-body">
              <span className="badge badge-tell">paraphrase</span>
              <AnswerBody citations={run.citations} onSelectCitation={onSelectCitation} panelTurnId={panelTurnId} selectedCitationId={selectedCitationId} text={run.answer} turnId={turnId} />
            </div>
          ))}
          {run.answer && claimIsNegative && (
            <p className="msg-warning">{questionClaimGroundingLabel(run)}</p>
          )}
          {ungroundedCitations.length > 0 && (
            <p className="msg-warning">
              {ungroundedCitations.map((citation) => `Evidence ${citation.number}: ${citationGroundingText(citation.grounding_status)}`).join("; ")}.
            </p>
          )}
          {hasLiveReceipt && run.answer_result?.kind === "LIVE_TABLE" && (
            <LiveTableEvidenceList result={run.answer_result} run={run} />
          )}
          {corpusWarning && <p className="msg-warning">{corpusWarning}</p>}
          {run.conflicts.map((item) => (
            <p className="msg-warning" key={item.code}>{item.message ?? "Sources disagree on this question — check the evidence below."}</p>
          ))}
          {run.uncertainties.filter((item) => !(corpusWarning && item.code === "CORPUS_PARTIAL")).map((item) => (
            <p className="msg-note" key={item.code}>{item.message ?? item.code}</p>
          ))}
          {run.citations.length === 0 && !hasLiveReceipt ? (
            <>
              <p className="msg-warning">This answer has no supporting citations: relevant fragments were not found or are unavailable.</p>
              {hasInsufficientEvidence && run.searched && run.searched.length > 0 && <SearchedList searched={run.searched} />}
            </>
          ) : leftoverCitations.length > 0 ? (
            <div className="basis-row">
              {leftoverCitations.map((citation, index) => (
                <button
                  className={panelTurnId === turnId && selectedCitationId === citation.citation_id ? "basis basis-active" : "basis"}
                  key={citation.citation_id}
                  onClick={(event) => { event.stopPropagation(); onSelectCitation(citation.citation_id); }}
                  type="button"
                >
                  <IconDocument />
                  <span>{citationLabel(citation.excerpt, index)}</span>
                  <span className="basis-excerpt">{basisExcerptText(citation.excerpt)}</span>
                  <span className="basis-excerpt">{citationGroundingText(citation.grounding_status)}</span>
                </button>
              ))}
            </div>
          ) : null}
        </>
      )}
    </>
  );
}

export function TurnCard({ turn, panelTurnId, selectedCitationId, onSelectTurn, onSelectCitation }: {
  turn: ConversationTurn;
  panelTurnId: string | null;
  selectedCitationId: string | null;
  onSelectTurn: (turn: ConversationTurn) => void;
  onSelectCitation: (turn: ConversationTurn, citationID: string) => void;
}) {
  const run = turn.question_run;
  return (
    <article
      className={panelTurnId === turn.turn_id ? "turn turn-on" : "turn"}
      onClick={(event) => {
        if (event.target instanceof Element && event.target.closest("button, a, input, textarea, select, summary")) return;
        if (panelTurnId !== turn.turn_id) onSelectTurn(turn);
      }}
    >
      <p className="turn-question">
        <span className="turn-role">Question</span>{run?.question ?? "—"}<time>{formatTime(turn.created_at)}</time>
      </p>
      {run ? (
        <TurnAnswer
          onSelectCitation={(citationID) => onSelectCitation(turn, citationID)}
          panelTurnId={panelTurnId}
          run={run}
          selectedCitationId={selectedCitationId}
          turnId={turn.turn_id}
        />
      ) : (
        <p className="msg-warning">This question is no longer available. A source may have been revoked or access may have changed.</p>
      )}
    </article>
  );
}

// The rely bar (contract §4): a real count of enabled sources, how many need
// attention, and — on demand — the same per-source freshness the Sources
// screen shows, so "what we're relying on" is never a separate fiction.
export type RelySourceSummary = {
  source_scope_id: string;
  label: string;
  headline: string;
  variant: "ready" | "attention" | "updating" | "disconnected";
};

export function relySourceSummary(sources: SourceStatus[]): RelySourceSummary[] {
  return sources.filter((source) => source.enabled).map((source) => ({
    source_scope_id: source.source_scope_id,
    label: sourceLabel(source),
    headline: sourceHeadline(source),
    variant: sourceCardVariant(source),
  }));
}

function RelyBar({ sources, onManageSources }: { sources: SourceStatus[]; onManageSources?: () => void }) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const enabled = relySourceSummary(sources);
  const attention = enabled.filter((source) => source.variant === "attention").length;

  useEffect(() => {
    if (!open) return;
    function onClick(event: MouseEvent) {
      if (containerRef.current && event.target instanceof Node && !containerRef.current.contains(event.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  if (enabled.length === 0) {
    if (onManageSources) {
      return (
        <button aria-label="Manage sources" className="rely-summary" onClick={onManageSources} type="button">
          <IconSources /><span>Sources: <b>0</b></span>
        </button>
      );
    }
    return (
      <p className="rely-empty">No sources are connected yet. Answers will use the sources added to this workspace.</p>
    );
  }

  return (
    <div className="rely" ref={containerRef}>
      {open && (
        <div className="rely-list">
          <h3>Workspace sources — {enabled.length}</h3>
          {enabled.map((source) => (
            <div className="rely-row" key={source.source_scope_id}>
              <span aria-hidden="true" className={`dot dot-${source.variant}`} />
              <span className="rely-name">{source.label}</span>
              <small>{source.headline}</small>
            </div>
          ))}
          {onManageSources && <button className="text-button rely-manage" onClick={() => { setOpen(false); onManageSources(); }} type="button">Manage sources</button>}
        </div>
      )}
      <button aria-expanded={open} className="rely-summary" onClick={() => setOpen((value) => !value)} type="button">
        <IconSources /><span>Sources: <b>{enabled.length}</b>{attention > 0 && <span className="rely-warn"> · need attention: {attention}</span>}</span>
        <IconChevron up={open} />
      </button>
    </div>
  );
}

// FIX-2 #3 / curator follow-up / FIX-7 #1: the tabular counterpart of a
// structured-source evidence fragment. The heading names what is actually
// shown — the rows the citing question run's own matched/witness set
// actually matched (FIX-7 #1: the server's default `scope=matched`, never
// the whole source scope unless `scope=full` was explicitly asked for) —
// and never claims to be "the whole source snapshot" unless total really
// does equal the snapshot's own row_count (AnswerSnapshot, FIX-7 #1's own
// convention: total is the returned scope's size, snapshot.row_count is the
// full source scope's size either way). "Show full snapshot" is offered as
// its own, clearly separate action rather than folded into the same label as
// the filtered count, so a filtered view can never be misread as the
// complete corpus.
function RowsetTable({ rowset }: { rowset: RowsetEvidence }) {
  const capped = rowset.rows.length < rowset.total;
  const isFullSnapshot = !capped && rowset.total === rowset.snapshot.row_count;
  return (
    <div className="rowset">
      <div className="rowset-bar">
        <span className="rowset-count">rows used in this answer: {rowset.rows.length}</span>
        {isFullSnapshot ? (
          <span>full source snapshot</span>
        ) : (
          <span className="rowset-total" title="This view cannot show the full snapshot yet. Contact the source owner if you need the remaining rows.">
            total rows in snapshot: {rowset.snapshot.row_count}
          </span>
        )}
        {rowset.filter_label && <span className="rowset-filter">{rowset.filter_label}</span>}
      </div>
      <div className="rowset-scroll">
        <table>
          <thead>
            <tr>{rowset.columns.map((column) => <th key={column}>{column}</th>)}</tr>
          </thead>
          <tbody>
            {rowset.rows.map((row, index) => (
              <tr key={index}>{rowset.columns.map((column) => <td key={column}>{row[column] ?? ""}</td>)}</tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// A citation or fragment sometimes carries the server's own internal
// metadata record (a structured-snapshot cell's join keys and hashes) instead
// of, or alongside, a human excerpt — never a document a person asked for.
// Showing that JSON verbatim ("canonical_value_hash", "connection_id",
// "text_start"…) is a server-side defect being fixed separately; this is the
// front-end's half of the fix: never render it raw. A known technical key is
// the signal; anything without one is left alone as ordinary text.
const EVIDENCE_TECHNICAL_KEYS = [
  "canonical_value_hash", "connection_id", "projection_lineage_id", "text_start", "text_end",
  "kind", "normalization_version", "source_scope_id", "source_version_id", "row_id",
] as const;

function tryParseTechnicalFragment(text: string): Record<string, unknown> | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;
  return EVIDENCE_TECHNICAL_KEYS.some((key) => key in record) ? record : null;
}

// Builds the human sentence a technical fragment collapses to: whatever
// readable fields it actually carries (column, value, snapshot), never the
// hashes/ids alongside them.
function summarizeTechnicalFragment(record: Record<string, unknown>): string {
  const parts: string[] = [];
  const column = record.column_name;
  if (typeof column === "string" && column) parts.push(`column “${column}”`);
  const value = record.value ?? record.text_value ?? record.cell_value;
  if (typeof value === "string" && value) parts.push(`value “${value}”`);
  else if (typeof value === "number") parts.push(`value ${value}`);
  const lineage = record.projection_lineage_id;
  if (typeof lineage === "string" && lineage) parts.push(`snapshot “${lineage}”`);
  if (parts.length === 0) return "Source snapshot metadata — technical details are hidden.";
  return parts.join(" · ");
}

// A short, content-derived tab/basis label instead of an ordinal ("Evidence
// N"): the value a row-card names itself by, or the leading text of a
// document excerpt — whichever the citation actually carries.
function citationLabel(excerpt: string, index: number): string {
  const technical = tryParseTechnicalFragment(excerpt);
  if (technical) {
    const identity = technical.row_title ?? technical.title ?? technical.key_value ?? technical.column_name;
    if (typeof identity === "string" && identity.trim()) return truncateLabel(identity);
  }
  const trimmed = excerpt.trim();
  return trimmed ? truncateLabel(trimmed) : `Evidence ${index + 1}`;
}

function truncateLabel(value: string): string {
  return value.length > 28 ? `${value.slice(0, 28)}…` : value;
}

// The short preview line under a basis button: a technical fragment collapses
// to its human summary here too, never its raw JSON.
function basisExcerptText(excerpt: string): string {
  const technical = tryParseTechnicalFragment(excerpt);
  const text = technical ? summarizeTechnicalFragment(technical) : excerpt;
  return text.length > 64 ? `${text.slice(0, 64)}…` : text;
}

// R1 grounding text: the server sends the closed state CONFIRMED_BY_FRAGMENT |
// UNCONFIRMED. It is always rendered as words (never colour alone), and an
// absent/unknown value is reported honestly as “unverified”.
function groundingStateText(status: string | undefined): string {
  return status === "CONFIRMED_BY_FRAGMENT" ? "supported by a fragment" : "unverified";
}

// Address-bound/tool-loop answers expose claim binding from the tool trace.
// Extractive and byte-exact answers use their server grounding state instead;
// they must never be labelled "unbound" merely because no tool loop exists.
export function questionClaimGroundingLabel(run: Pick<QuestionRun, "answer_mode" | "verification_method" | "grounding_status" | "tool_loop">): string {
  const isAddressBound = run.answer_mode === "TOOL_LOOP" || run.verification_method === "ADDRESS_BOUND";
  return isAddressBound
    ? (run.tool_loop?.all_claims_bound ? BOUND_CLAIM_LABEL : UNBOUND_CLAIM_LABEL)
    : `Answer: ${groundingStateText(run.grounding_status)}.`;
}

function firstAnswerCitation(run: QuestionRun | null | undefined): string | null {
  if (!run) return null;
  for (const number of extractCitationNumbers(run.answer ?? "")) {
    const citation = run.citations.find((item) => item.number === number);
    if (citation) return citation.citation_id;
  }
  return run.citations[0]?.citation_id ?? null;
}

function evidenceDocumentTitle(text: string): string | null {
  return text.match(/^#{1,6}[ \t]+([^\r\n]+)/m)?.[1] ?? null;
}

export function evidenceSourceFilename(sourcePath: string | undefined): string | null {
  if (!sourcePath) return null;
  const parts = sourcePath.replace(/\\/g, "/").split("/").filter(Boolean);
  return parts.at(-1) ?? null;
}

function evidenceAddressDisplay(address: unknown): string | null {
  if (address === null || address === undefined) return null;
  if (typeof address === "string") return address;
  try {
    return JSON.stringify(address);
  } catch {
    return null;
  }
}

// Source text is never passed through answer typography or citation parsing.
function EvidenceText({ text, highlight }: { text: string; highlight?: VerifiedEvidenceQuote | null }) {
  const [raw, setRaw] = useState(false);
  const readable = evidenceDocumentTitle(text) !== null && !/^\s*(?:```|~~~|\|)|\t/m.test(text);
  if (highlight) {
    const runes = Array.from(text);
    return (
      <>
        <p className="evidence-quote-confirmed">The exact quote is highlighted in the verified evidence.</p>
        <pre className="doc-text evidence-quote-text">
          {runes.slice(0, highlight.start).join("")}
          <mark className="evidence-verified-quote">{highlight.text}</mark>
          {runes.slice(highlight.end).join("")}
        </pre>
      </>
    );
  }
  return (
    <>
      {readable && <button aria-pressed={raw} className="text-button evidence-text-toggle" onClick={() => setRaw((value) => !value)} type="button">{raw ? "Formatted view" : "Source text"}</button>}
      {!readable || raw ? <pre className={readable ? "doc-text" : "doc-text doc-code"}>{text}</pre> : (
        <div className="doc-readable">
          {text.split(/\r\n?|\n/).map((line, index) => {
            const heading = line.match(/^#{1,6}[ \t]+(.*)$/);
            const content = (heading?.[1] ?? line).split(/(\*\*[^*]+\*\*)/g).map((part, partIndex) => part.startsWith("**") && part.endsWith("**") ? <strong key={partIndex}>{part.slice(2, -2)}</strong> : part);
            return heading ? <h3 key={index}>{content}</h3> : line.length > 0 ? <p key={index}>{content}</p> : null;
          })}
        </div>
      )}
    </>
  );
}

function EvidenceFragmentPresentation({ evidence, highlight, provenanceOpen = false }: {
  evidence: EvidenceData;
  highlight?: VerifiedEvidenceQuote | null;
  provenanceOpen?: boolean;
}) {
  const technicalFragment = tryParseTechnicalFragment(evidence.text);
  const isRowLike = Boolean(evidence.rowset || technicalFragment);
  const structuredAddress = evidenceAddressDisplay(evidence.address);
  return (
    <>
      {evidence.is_current_version === false && <p className="evidence-currentness evidence-version-warning">This version is no longer current</p>}
      {evidence.is_current_version === true && <p className="evidence-currentness">Current version</p>}
      <p className="chip chip-ex">{isRowLike ? "snapshot row" : "extracted text"}</p>
      {evidence.rowset && <RowsetTable rowset={evidence.rowset} />}
      {technicalFragment ? (
        <>
          {highlight
            ? <EvidenceText key={`${evidence.fragment_id}:${highlight.start}:${highlight.end}`} highlight={highlight} text={evidence.text} />
            : <p className="doc-text">{summarizeTechnicalFragment(technicalFragment)}</p>}
          <details className="evi-provenance">
            <summary>Show technical details</summary>
            <pre className="mono">{evidence.text}</pre>
          </details>
        </>
      ) : (
        <EvidenceText key={`${evidence.fragment_id}:${highlight?.start ?? ""}:${highlight?.end ?? ""}`} highlight={highlight} text={evidence.text} />
      )}
      <details className="evi-provenance" open={provenanceOpen || undefined}>
        <summary>Provenance</summary>
        <dl>
          <div><dt>Fragment</dt><dd className="mono">{evidence.fragment_id}</dd></div>
          <div><dt>Anchor</dt><dd className="mono">{evidence.anchor}</dd></div>
          {evidence.canonical_address && <div><dt>Canonical address</dt><dd className="mono">{evidence.canonical_address}</dd></div>}
          {structuredAddress && <div><dt>Structured address</dt><dd className="mono">{structuredAddress}</dd></div>}
          <div><dt>Source version</dt><dd className="mono">{evidence.provenance.source_version_id}</dd></div>
          <div><dt>External version</dt><dd className="mono">{evidence.provenance.external_version_key}</dd></div>
          <div><dt>Extraction</dt><dd className="mono">{evidence.provenance.extraction_id}</dd></div>
          <div><dt>Observed at</dt><dd className="mono">{evidence.provenance.observed_at}</dd></div>
          <div><dt>Content hash</dt><dd className="mono">{evidence.provenance.content_hash}</dd></div>
          {evidence.is_current_version !== undefined && (
            <div><dt>Current version</dt><dd>{evidence.is_current_version ? "Yes" : "No"}</dd></div>
          )}
        </dl>
      </details>
    </>
  );
}

export function EvidencePanel({ workspaceID, target, turnsByID, sourceNameByConnection, allSources, fullscreen, onToggleFullscreen, onOpenEvidence, onSelectCitation }: {
  workspaceID: string | null;
  target: PanelTarget;
  turnsByID: Map<string, ConversationTurn>;
  sourceNameByConnection: Map<string, string>;
  allSources: SourceStatus[];
  fullscreen: boolean;
  onToggleFullscreen: () => void;
  onOpenEvidence: (hash: string) => void;
  onSelectCitation: (turnID: string, citationID: string) => void;
}) {
  const turn = target && "turnId" in target ? turnsByID.get(target.turnId) ?? null : null;
  const citations = turn?.question_run?.citations ?? [];
  const activeCitationID = target && "citationId" in target ? target.citationId : null;
  const activeCitation = citations.find((item) => item.citation_id === activeCitationID) ?? null;
  const fragmentID = activeCitation?.evidence_fragment_id ?? null;
  const liveResultRun = turn?.question_run && hasLiveDataReceipt(turn.question_run) &&
    liveTableReceipts(turn.question_run.answer_result).length > 0 && !fragmentID
    ? turn.question_run : null;
  const citationAddress = activeCitation?.address?.startsWith("kv1:") ? activeCitation.address : undefined;
  const requestPath = workspaceID && fragmentID
    ? evidenceRequestPath({ workspace: workspaceID, fragment: fragmentID, canonicalAddress: citationAddress })
    : null;
  const [evidenceReply, setEvidenceReply] = useState<{ path: string; result: ApiResult<EvidenceData> } | null>(null);
  // Do not display the previous response during the render before an effect
  // resets it, including when the same fragment is selected in another scope.
  const evidence = evidenceReply?.path === requestPath ? evidenceReply.result : null;
  const quoteSelector = confirmedEvidenceQuoteSelector(activeCitation);
  const legacyPageBase = typeof window !== "undefined"
    ? `${window.location.origin}${window.location.pathname}${window.location.search}`
    : undefined;
  const evidencePageURL = evidence?.kind === "ok" && workspaceID && fragmentID
    ? evidencePageHref(evidence.value, { workspace: workspaceID, fragment: fragmentID, canonicalAddress: citationAddress }, quoteSelector, legacyPageBase)
    : null;

  const [copyLinkStatus, setCopyLinkStatus] = useState("");
  const expandButtonRef = useRef<HTMLButtonElement | null>(null);
  const evidenceBodyRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!fullscreen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      onToggleFullscreen();
      expandButtonRef.current?.focus();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [fullscreen, onToggleFullscreen]);
  useEffect(() => { evidenceBodyRef.current?.scrollTo({ top: 0 }); }, [fragmentID]);
  useEffect(() => { setCopyLinkStatus(""); }, [workspaceID, fragmentID, evidencePageURL]);
  useEffect(() => {
    let alive = true;
    setEvidenceReply(null);
    if (!requestPath) return () => { alive = false; };
    apiGet<EvidenceData>(requestPath).then((result) => {
      if (alive) setEvidenceReply({ path: requestPath, result });
    });
    return () => { alive = false; };
  }, [requestPath]);

  async function copyEvidencePageLink() {
    if (!evidencePageURL || !navigator.clipboard?.writeText) {
      setCopyLinkStatus("Copying is not available in this browser.");
      return;
    }
    try {
      await navigator.clipboard.writeText(evidencePageURL);
      setCopyLinkStatus("Link copied.");
    } catch {
      setCopyLinkStatus("Could not copy the link.");
    }
  }

  const provenanceName = evidence?.kind === "ok" ? sourceNameByConnection.get(evidence.value.provenance.connection_id) ?? "Source" : null;
  // A row-card fragment (structured source) is labeled "snapshot row"; only a
  // document fragment is "extracted text" (curator follow-up to UPL-1).
  // The technical-metadata leak (a server defect fixed separately) still
  // counts as row-like here, since the human summary it collapses to is a
  // one-line fact about a snapshot cell, not document prose.
  const technicalFragment = evidence?.kind === "ok" ? tryParseTechnicalFragment(evidence.value.text) : null;
  const isRowLike = Boolean(evidence?.kind === "ok" && (evidence.value.rowset || technicalFragment));

  if (target === null) {
    return (
      <aside aria-label="Answer evidence" className="evi">
        <div className="evi-idle">
          <p>Ask a question to view the source text behind the answer here. Select a previous turn to return to its evidence, or select a citation to open that fragment.</p>
          {allSources.some((source) => source.enabled) && (
            <div className="evi-idle-sources">
              <h3>Connected sources — {allSources.filter((source) => source.enabled).length}</h3>
              {allSources.filter((source) => source.enabled).slice(0, 10).map((source) => (
                <div className="rely-row" key={source.source_scope_id}>
                  <span aria-hidden="true" className={`dot dot-${sourceCardVariant(source)}`} />
                  <span className="rely-name">{sourceLabel(source)}</span>
                  <small>{sourceHeadline(source)}</small>
                </div>
              ))}
            </div>
          )}
        </div>
      </aside>
    );
  }

  return (
    <aside aria-label="Answer evidence" className={fullscreen ? "evi evi-full" : "evi"}>
      <header className="evi-h">
        <div className="t">
          <b>{evidence?.kind === "ok" ? evidenceSourceFilename(evidence.value.source_path) ?? provenanceName : fragmentID ? "Checking source…" : liveResultRun ? "Live database evidence" : "Evidence unavailable"}</b>
          {provenanceName && <span>{activeCitation ? `Evidence ${activeCitation.number} · ` : ""}{provenanceName}</span>}
          {/* FIX-6 + UPL-1: anchor is a machine provenance descriptor (for a
              structured cell, a JSON locator with its own canonical_value_hash/
              projection_lineage_id fields) -- never part of the human-facing
              label; it already has its own field lower in "Provenance".
              isRowLike (UPL-1) still distinguishes a row-card fragment from
              document prose. */}
          <span>{evidence?.kind === "ok" ? `${isRowLike ? "snapshot row" : "extracted text"} · observed ${formatTime(evidence.value.provenance.observed_at)}` : ""}</span>
        </div>
        {evidence?.kind === "ok" && (
          <div className="evi-actions">
            {evidencePageURL && <a className="lnk" href={evidencePageURL} onClick={(event) => {
              if (!shouldHandleInAppEvidenceClick(event)) return;
              event.preventDefault();
              onOpenEvidence(new URL(evidencePageURL).hash);
            }}>Open separately</a>}
            {evidencePageURL && <button className="lnk" onClick={() => void copyEvidencePageLink()} type="button">Copy link</button>}
            <button aria-expanded={fullscreen} className="lnk" onClick={onToggleFullscreen} ref={expandButtonRef} type="button">
              {fullscreen ? <IconCollapse /> : <IconExpand />}
              {fullscreen ? "Collapse" : "Full screen"}
            </button>
          </div>
        )}
      </header>
      {copyLinkStatus && <p aria-live="polite" className="evi-action-status" role="status">{copyLinkStatus}</p>}

      {turn && (
        <div className="evi-turn">
          <IconQuestions />
          <span>turn {formatTime(turn.created_at)} · «{turn.question_run?.question}»</span>
        </div>
      )}

      {activeCitation && (
        <p className="msg-note">Evidence {activeCitation.number}: {citationGroundingText(activeCitation.grounding_status)}.</p>
      )}
      {activeCitation?.address && (
        <details className="source-address"><summary>Source address</summary><code>{activeCitation.address}</code></details>
      )}
      {evidence?.kind === "ok" && evidence.value.source_path && (
        <div className="source-address"><span>Source path</span><code>{evidence.value.source_path}</code></div>
      )}

      {citations.length > 1 && (
        <div aria-label="Answer evidence" className="tabs" role="tablist">
          {citations.map((citation, index) => (
            <button
              aria-selected={citation.citation_id === activeCitationID}
              key={citation.citation_id}
              onClick={() => turn && onSelectCitation(turn.turn_id, citation.citation_id)}
              onKeyDown={(event) => {
                if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
                event.preventDefault();
                const next = event.key === "Home" ? 0 : event.key === "End" ? citations.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + citations.length) % citations.length;
                if (turn) onSelectCitation(turn.turn_id, citations[next].citation_id);
                (event.currentTarget.parentElement?.children[next] as HTMLElement | undefined)?.focus();
              }}
              role="tab"
              tabIndex={citation.citation_id === activeCitationID ? 0 : -1}
              title={evidenceDocumentTitle(citation.excerpt) ?? citationLabel(citation.excerpt, index)}
              type="button"
            >
              {citation.number}. {citationLabel(citation.excerpt, index).replace(/^#+\s*/, "")}
            </button>
          ))}
        </div>
      )}

      <div className="evi-b" ref={evidenceBodyRef}>
        {liveResultRun && <LiveResultEvidencePanel run={liveResultRun} />}
        {!fragmentID && !liveResultRun && (
          <p className="evi-denied">
            <IconInfo />
            {(turn?.question_run?.citations.length ?? 0) === 0
              ? "This answer has no supporting citations: relevant fragments were not found or are unavailable."
              : "Evidence unavailable."}
          </p>
        )}
        {fragmentID && evidence === null && <p className="evidence-state">Checking fragment access…</p>}
        {fragmentID && evidence !== null && evidence.kind !== "ok" && (
          <p className="evi-denied">
            <IconInfo />
            Evidence unavailable.
          </p>
        )}
        {fragmentID && evidence?.kind === "ok" && (
          <EvidenceFragmentPresentation evidence={evidence.value} />
        )}
      </div>
    </aside>
  );
}

type EvidenceSourcePageState =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "failed" }
  | { kind: "ready"; evidence: EvidenceData };

function EvidenceSourcePage({ target, workspaceName, returnHref, onReturn, onAccessDenied }: {
  target: EvidenceTarget;
  workspaceName: string;
  returnHref: string;
  onReturn: (event: ReactMouseEvent<HTMLAnchorElement>) => void;
  onAccessDenied: () => void;
}) {
  const [pageState, setPageState] = useState<EvidenceSourcePageState>({ kind: "loading" });
  const [verifiedQuote, setVerifiedQuote] = useState<VerifiedEvidenceQuote | null>(null);

  useEffect(() => {
    let alive = true;
    setPageState({ kind: "loading" });
    setVerifiedQuote(null);
    apiGet<EvidenceData>(evidenceRequestPath(target)).then(async (result) => {
      if (!alive) return;
      if (result.kind !== "ok") {
        if (result.status === 404 || result.status === 403) {
          onAccessDenied();
          setPageState({ kind: "unavailable" });
        } else setPageState({ kind: "failed" });
        return;
      }
      if (result.value.fragment_id !== target.fragment) {
        onAccessDenied();
        setPageState({ kind: "unavailable" });
        return;
      }
      setPageState({ kind: "ready", evidence: result.value });
      if (target.selector) {
        const verified = await verifyEvidenceQuoteSelector(result.value, target.fragment, target.selector);
        if (alive && verified) setVerifiedQuote(verified);
      }
    });
    return () => { alive = false; };
  }, [target, onAccessDenied]);

  const evidence = pageState.kind === "ready" ? pageState.evidence : null;
  const sourceName = evidence ? evidenceSourceFilename(evidence.source_path) ?? "Source" : "Source evidence";
  return (
    <article aria-label="Source evidence" className="evidence-source-page">
      <header className="page-top-bar evidence-source-topbar">
        <div>
          <p className="eyebrow">{workspaceName}</p>
          <h1>{sourceName}</h1>
          {evidence?.source_path && (
            <div className="source-address evidence-source-path"><span>Source path</span><code>{evidence.source_path}</code></div>
          )}
        </div>
        <a className="secondary-button evidence-source-return" href={returnHref} onClick={onReturn}>Back to search</a>
      </header>
      <div className="evidence-source-body">
        {pageState.kind === "loading" && <p aria-live="polite" className="evidence-state" role="status">Checking evidence access…</p>}
        {pageState.kind === "unavailable" && (
          <p className="evi-denied" role="status"><IconInfo />Evidence unavailable.</p>
        )}
        {pageState.kind === "failed" && <p className="evidence-state" role="status">Could not load evidence.</p>}
        {evidence && <EvidenceFragmentPresentation evidence={evidence} highlight={verifiedQuote} provenanceOpen />}
      </div>
    </article>
  );
}

export function GovernedPresetPanelHost({ active, onCatalogAvailability, onSessionExpired, requestedWorkspaceID, revalidationKey, state }: {
  active: boolean; onCatalogAvailability: (availability: GovernedCatalogAvailability) => void; onSessionExpired: () => void;
  requestedWorkspaceID: string | null; revalidationKey: number; state: WorkspaceDataState;
}) {
  const authorization = governedWorkspaceAuthorization(state, requestedWorkspaceID);
  const [catalogEpoch, setCatalogEpoch] = useState<number | null>(null);
  const [catalogAvailability, setCatalogAvailability] = useState<GovernedCatalogAvailability>({ status: "loading", catalogAvailable: false, liveAskAvailable: false });
  const [retention, dispatchRetention] = useReducer(reduceGovernedRetention, { workspaceID: null, revision: null, phase: "pending" as GovernedWorkspaceAuthorization, resetKey: 0 });

  const onCatalogAuthorization = useCallback((availability: GovernedCatalogAvailability) => {
    setCatalogAvailability(availability);
    onCatalogAvailability(availability);
    setCatalogEpoch(availability.catalogAvailable ? revalidationKey : null);
  }, [onCatalogAvailability, revalidationKey]);

  useEffect(() => { dispatchRetention({ workspaceID: requestedWorkspaceID, phase: authorization.phase, revision: authorization.revision }); }, [authorization.phase, authorization.revision, requestedWorkspaceID]);
  useEffect(() => {
    if (authorization.phase !== "authorized") {
      onCatalogAuthorization({
        status: authorization.phase === "pending" ? "loading" : "unavailable",
        catalogAvailable: false,
        liveAskAvailable: false,
      });
    }
  }, [authorization.phase, onCatalogAuthorization]);

  if (requestedWorkspaceID === null) return null;
  const authorized = authorization.phase === "authorized" && authorization.revision !== null;
  const visible = active && authorized && catalogEpoch === revalidationKey && retention.workspaceID === requestedWorkspaceID
    && retention.phase === "authorized" && retention.revision === authorization.revision;
  return (
    <div className="governed-preset-owner" hidden={!visible}>
      <GovernedPresetPanel
        authorized={authorized}
        key={`${requestedWorkspaceID}:${retention.resetKey}`}
        liveAskAvailable={catalogAvailability.liveAskAvailable}
        onCatalogAuthorization={onCatalogAuthorization}
        onSessionExpired={onSessionExpired}
        revalidationKey={revalidationKey}
        visible={visible}
        workspaceID={requestedWorkspaceID}
      />
    </div>
  );
}

export type AskExecutionMode = "workspace-search" | "live-database";

export function defaultAskExecutionMode(_catalogAvailable: boolean): AskExecutionMode {
  return "workspace-search";
}

export function effectiveAskExecutionMode(requestedMode: AskExecutionMode | null, catalogAvailable: boolean, catalogStatus: GovernedCatalogAvailability["status"] = "available"): AskExecutionMode {
  const requestedOrDefault = requestedMode ?? defaultAskExecutionMode(catalogAvailable);
  return requestedOrDefault === "live-database" && catalogStatus === "unavailable" ? "workspace-search" : requestedOrDefault;
}

export function askExecutionVisibility(mode: AskExecutionMode): { workspaceSearch: boolean; liveDatabase: boolean } {
  return { workspaceSearch: mode === "workspace-search", liveDatabase: mode === "live-database" };
}

/** The single question surface. Governed preset checks remain an admin-only
 * component for a future Diagnostics surface; they are deliberately not
 * mounted beside the user question composer. */
export function AskSurface({ active, onOpenEvidence, onOpenSources, onConversationChange, initialConversationID, pushToast, state, requestedWorkspaceID }: {
  active: boolean;
  onOpenEvidence: (hash: string) => void;
  onOpenSources: () => void;
  onConversationChange?: (conversationID: string | null) => void;
  initialConversationID?: string | null;
  pushToast?: (kind: "success" | "error", text: string) => void;
  // Retained as optional compatibility props for callers that used the
  // retired governed panel host. The main Ask surface no longer mounts it.
  onSessionExpired?: () => void;
  revalidationKey?: number;
  state: WorkspaceDataState;
  requestedWorkspaceID: string | null;
}) {
  const askSources = governedWorkspaceAuthorization(state, requestedWorkspaceID).phase === "authorized"
    ? authorizedSourcesForAsk(state, requestedWorkspaceID)
    : null;

  return (
    <div className="ask-surface" hidden={!active}>
      <header className="ask-page-header">
        <h1>Ask</h1>
        <div className="ask-page-actions">
          {askSources && <RelyBar onManageSources={onOpenSources} sources={askSources} />}
        </div>
      </header>
      <AskView
        initialConversationID={initialConversationID ?? null}
        onConversationChange={onConversationChange ?? (() => {})}
        onOpenEvidence={onOpenEvidence}
        requestedWorkspaceID={requestedWorkspaceID}
        state={state}
        pushToast={pushToast ?? (() => {})}
      />
    </div>
  );
}

// The Ask surface sends one governed question run per submit. The server owns
// retrieval and tool orchestration; the browser only presents the resulting
// answer, citations and actual tool-call disclosure.
export function questionRunPayload(question: string, model: ModelProfile | null | undefined): {
  question: string;
  model_profile_id?: string;
} {
  return {
    question,
    ...(model ? { model_profile_id: model.id } : {}),
  };
}

function QuestionRunAnswer({ onOpenEvidence, run, workspaceID }: {
  onOpenEvidence: (hash: string) => void;
  run: QuestionRun;
  workspaceID: string;
}) {
  const statusMessage = questionStatusMessage(run);
  const corpusWarning = corpusStatusWarning(run.corpus_status);
  const isQuote = run.verification_method === "BYTE_EXACT_CITATION";
  const text = run.answer ?? run.clarification;
  const liveResult = run.answer_result;
  const liveObservationWindow = liveResult?.observation_window;
  const liveReceiptDigest = liveResult?.receipt_digest;
  const isLiveTable = liveResult?.kind === "LIVE_TABLE";
  const liveReceipts = liveTableReceipts(liveResult);
  const hasLiveReceipt = Boolean((liveObservationWindow && liveReceiptDigest) || liveReceipts.length > 0);
  const isLiveScalar = hasLiveReceipt && !isLiveTable;
  // A live calculation and cited document prose prove different things. Keep
  // their presentation separate so the model's document context is never
  // mistaken for the server-owned calculation and receipt.
  const isCombinedLiveResult = isLiveScalar && run.citations.length > 0;
  const hasDocumentGroundedContext = isCombinedLiveResult && Boolean(text);
  const resultValue = liveResult?.value
    ? `${liveResult.value}${liveResult.unit ? ` ${liveResult.unit}` : ""}`
    : null;
  const citationHref = (citation: QuestionCitation): string => buildEvidenceHash({
    workspace: workspaceID,
    fragment: citation.evidence_fragment_id,
    ...(run.conversation_id ? { returnConversation: run.conversation_id } : {}),
    ...(citation.address ? { canonicalAddress: citation.address } : {}),
    ...(confirmedEvidenceQuoteSelector(citation) ? { selector: confirmedEvidenceQuoteSelector(citation)! } : {}),
  });
  const selectCitation = (citationID: string) => {
    const citation = run.citations.find((item) => item.citation_id === citationID);
    if (citation) onOpenEvidence(citationHref(citation));
  };
  return (
    <>
      <WorkspaceContextUsage toolLoop={run.tool_loop} />
      <ToolCallsDisclosure run={run} showResults={false} />
      {statusMessage ? <p className="msg-warning">{statusMessage}</p> : hasLiveReceipt ? (
        <div className="answer-body live-calculation-answer">
          <span className="badge badge-live"><IconCheckCircle />{isLiveTable ? "Model interpretation of the complete live table" : "Verified live calculation"}</span>
          {isCombinedLiveResult && resultValue ? (
            <span className="answer-live-summary">{resultValue}</span>
          ) : text ? (
            <AnswerBody citations={run.citations} onSelectCitation={selectCitation} panelTurnId={null} selectedCitationId={null} text={text} turnId={run.question_run_id} />
          ) : resultValue ? (
            <span className="answer-live-summary">{resultValue}</span>
          ) : null}
          {isLiveTable && liveResult ? (
            liveReceipts.length > 0 ? (
              <LiveTableEvidenceList result={liveResult} run={run} />
            ) : (
              <details className="live-calculation-evidence">
                <summary>Live table receipt</summary>
                <dl>
                  <dt>Rows returned</dt><dd>{liveResult.snapshot.row_count}</dd>
                  <dt>Observed window</dt><dd>{liveObservationWindow ? answerObservationWindowText(liveObservationWindow) || "—" : "—"}</dd>
                  <dt>Receipt digest</dt><dd className="mono">{liveReceiptDigest ?? "—"}</dd>
                </dl>
              </details>
            )
          ) : (
            <details className="live-calculation-evidence">
              <summary>Evidence for this calculation</summary>
              <dl>
                {liveResult?.period && <><dt>Period</dt><dd>{answerPeriodText(liveResult.period) ?? "—"}</dd></>}
                {liveResult?.timezone && <><dt>Time zone</dt><dd>{liveResult.timezone}</dd></>}
                <dt>Contributing rows</dt><dd>{liveResult?.snapshot.row_count ?? 0}</dd>
                <dt>Observed window</dt><dd>{liveObservationWindow ? answerObservationWindowText(liveObservationWindow) || "—" : "—"}</dd>
                <dt>Receipt digest</dt><dd className="mono">{liveReceiptDigest ?? "—"}</dd>
              </dl>
            </details>
          )}
        </div>
      ) : text ? (
        isQuote ? (
          <blockquote className="answer-quote">
            <span className="badge badge-quote"><IconCheckCircle />quote verified</span>
            <AnswerBody citations={run.citations} onSelectCitation={selectCitation} panelTurnId={null} selectedCitationId={null} text={text} turnId={run.question_run_id} />
          </blockquote>
        ) : (
          <div className="answer-body">
            <span className="badge badge-tell">paraphrase</span>
            <AnswerBody citations={run.citations} onSelectCitation={selectCitation} panelTurnId={null} selectedCitationId={null} text={text} turnId={run.question_run_id} />
          </div>
        )
      ) : resultValue ? (
        <div className="answer-body">
          <AnswerBody citations={run.citations} onSelectCitation={selectCitation} panelTurnId={null} selectedCitationId={null} text={resultValue} turnId={run.question_run_id} />
          {run.answer_result?.period?.label && <p className="msg-note">Period: {run.answer_result.period.label}</p>}
        </div>
      ) : <p className="msg-warning">No answer was returned. Check the sources and try again.</p>}
      {hasDocumentGroundedContext && (
        <div className="answer-body document-grounded-context">
          <span className="badge badge-tell">document-grounded context / paraphrase</span>
          <AnswerBody citations={run.citations} onSelectCitation={selectCitation} panelTurnId={null} selectedCitationId={null} text={text!} turnId={run.question_run_id} />
        </div>
      )}
      {text && (!hasLiveReceipt || hasDocumentGroundedContext) && <p className="msg-note">{questionClaimGroundingLabel(run)}</p>}
      {corpusWarning && <p className="msg-warning">{corpusWarning}</p>}
      {run.conflicts.map((item) => item.message ? <p className="msg-warning" key={item.code}>{item.message}</p> : null)}
      {run.uncertainties.map((item) => item.message ? <p className="msg-note" key={item.code}>{item.message}</p> : null)}
      {run.citations.length > 0 && (
        <ul aria-label="Answer sources" className="search-pilot-citations">
          {run.citations.map((citation) => {
            const href = citationHref(citation);
            return (
              <li key={citation.citation_id}>
                <a href={href} onClick={(event) => {
                  if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
                  event.preventDefault();
                  onOpenEvidence(href);
                }}>Source [{citation.number}]</a>
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}

export function SearchView({ onOpenEvidence, state, requestedWorkspaceID, active }: {
  onOpenEvidence: (hash: string) => void;
  state: WorkspaceDataState;
  requestedWorkspaceID: string | null;
  active: boolean;
}) {
  const [question, setQuestion] = useState("");
  const [selectedModelID, setSelectedModelID] = useState<string | null>(null);
  const [submittedModel, setSubmittedModel] = useState<ModelProfile | null>(null);
  const [searching, setSearching] = useState(false);
  const [answerPending, setAnswerPending] = useState(false);
  const [submitted, setSubmitted] = useState("");
  const [answer, setAnswer] = useState<ApiResult<QuestionRun> | null>(null);
  const [resultWorkspace, setResultWorkspace] = useState<string | null>(null);
  const generation = useRef(0);
  const searchElement = useRef<HTMLElement | null>(null);
  const scrollPosition = useRef(0);
  const snapshotResult = state.phase === "loaded" ? state.snapshot : null;
  const snapshot = snapshotResult?.kind === "ok" ? snapshotResult.value : null;
  const workspaceID = snapshot?.id === requestedWorkspaceID ? snapshot.id : null;
  const workspaceClosed = snapshot?.status === "ARCHIVED" || snapshot?.status === "REVOKED";
  const workspaceAuthorization = governedWorkspaceAuthorization(state, requestedWorkspaceID);
  const models = snapshot?.model_profiles ?? [];
  const selectedModel = selectedModelID === null
    ? models.find((model) => model.is_default) ?? models[0]
    : models.find((model) => model.id === selectedModelID);
  const successfulRevision = useRef(snapshot?.revision);

  const clearSearch = useCallback(() => {
    generation.current++;
    setQuestion("");
    setSubmitted("");
    setAnswer(null);
    setSearching(false);
    setAnswerPending(false);
    setResultWorkspace(null);
    setSelectedModelID(null);
    setSubmittedModel(null);
    scrollPosition.current = 0;
    dismissFootnoteTooltip();
  }, []);

  useLayoutEffect(() => {
    // Revalidation loading is not a new workspace revision. Keep the search in
    // memory, while the stamped workspace hook prevents it being displayed.
    if (!snapshotResult) return;
    if (!snapshot || workspaceClosed || workspaceAuthorization.phase === "denied" || snapshot.id !== requestedWorkspaceID
      || (successfulRevision.current !== undefined && successfulRevision.current !== snapshot.revision)) clearSearch();
    successfulRevision.current = snapshot?.revision;
  }, [snapshotResult, snapshot, workspaceAuthorization.phase, workspaceClosed, requestedWorkspaceID, clearSearch]);

  useLayoutEffect(() => () => { generation.current++; }, []);

  useLayoutEffect(() => {
    if (active && workspaceID && !workspaceClosed) searchElement.current?.scrollTo({ top: scrollPosition.current });
  }, [active, workspaceID, workspaceClosed, snapshotResult]);

  async function search(event: FormEvent) {
    event.preventDefault();
    const query = question.trim();
    if (!query || !workspaceID || workspaceClosed || searching) return;
    const epoch = ++generation.current;
    const base = `/api/v1/workspaces/${encodeURIComponent(workspaceID)}`;
    setResultWorkspace(workspaceID);
    setSubmitted(query);
    setAnswer(null);
    const selected = selectedModel
      ? { id: selectedModel.id, label: selectedModel.label, location: selectedModel.location }
      : null;
    setSubmittedModel(selected);
    setSearching(true);
    setAnswerPending(true);
    dismissFootnoteTooltip();
    const summary = await apiPost<QuestionRun>(`${base}/questions`, {
      ...questionRunPayload(query, selectedModel),
    }, newIdempotencyKey());
    if (generation.current !== epoch) return;
    if (summary.kind !== "ok" && [401, 403, 404].includes(summary.status)) {
      // A denied question must not leave a previous protected answer visible.
      // Keep this failed attempt stamped to the current workspace so the user
      // gets the ordinary ClosedOrError explanation instead of a silent blank.
      generation.current++;
      setAnswer(summary);
      setResultWorkspace(workspaceID);
      setSearching(false);
      setAnswerPending(false);
      return;
    }
    setSearching(false);
    setAnswer(summary);
    setAnswerPending(false);
  }

  if (snapshotResult && snapshotResult.kind !== "ok") return <div className="search-pilot" hidden={!active}><ClosedOrError result={snapshotResult} /></div>;
  if (!workspaceID) return <div className="search-pilot" hidden={!active}><p role="status">{requestedWorkspaceID ? "Checking access…" : "Select a workspace."}</p></div>;
  if (workspaceClosed) return <div className="search-pilot" hidden={!active}><p>This workspace is closed.</p></div>;
  if (workspaceAuthorization.phase !== "authorized") return <div className="search-pilot" hidden={!active}><p role="status">{workspaceAuthorization.phase === "pending" ? "Checking access…" : "This workspace is unavailable."}</p></div>;
  const visible = resultWorkspace === workspaceID;
  const run = visible && answer?.kind === "ok" ? answer.value : null;
  const answerModel = run?.model_profile ?? submittedModel;

  return (
    <section className="search-pilot" hidden={!active} ref={searchElement}
      onScroll={(event) => { if (active) scrollPosition.current = event.currentTarget.scrollTop; }}>
      <section aria-labelledby="question-composer-heading" className="document-search-mode">
        <h2 className="sr-only" id="question-composer-heading">Ask a question</h2>
        <form className="search-pilot-form" onSubmit={search}>
          <label className="sr-only" htmlFor="pilot-question">Ask a question</label>
          <input id="pilot-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask a question" />
          <button className="primary-button" disabled={!question.trim() || searching} type="submit">{searching ? "Asking…" : "Ask"}</button>
        </form>
        <div className="search-pilot-options">
          {models.length > 0 && <select aria-label="Model" className="search-model-select"
            value={selectedModel?.id ?? ""} onChange={(event) => setSelectedModelID(event.target.value)}>
            {!selectedModel && <option disabled value="">Select a model</option>}
            {models.map((model) => <option key={model.id} value={model.id}>{model.label} · {model.location === "EXTERNAL" ? "cloud" : "local"}</option>)}
          </select>}
        </div>
        {visible && submitted && question.trim() !== submitted && <p className="muted">Results for: {submitted}</p>}
        {visible && (answerPending || answer) && (
          <section aria-label="AI answer" className="search-pilot-answer">
            {!answerPending && <h2>AI answer <small>{answerModel ? `${answerModel.label} · ` : ""}answer</small></h2>}
            {answerPending && <div className="search-answer-progress">
              <p aria-live="polite" aria-atomic="true" className="search-answer-status" role="status"><span aria-hidden="true" className="search-answer-spinner" />{answerModel?.label ?? "Model"} is preparing an answer…</p>
              <div aria-hidden="true" className="search-answer-skeleton"><span /><span /><span /></div>
            </div>}
            {answer && answer.kind !== "ok" && <ClosedOrError result={answer} />}
            {run && <QuestionRunAnswer onOpenEvidence={onOpenEvidence} run={run} workspaceID={workspaceID} />}
          </section>
        )}
      </section>
    </section>
  );
}

export function initialConversationWorkspaceOwner(initialConversationID: string | null, requestedWorkspaceID: string | null): string | null {
  return initialConversationID ? requestedWorkspaceID : null;
}

function AskView({ onOpenEvidence, onConversationChange, initialConversationID, state, pushToast, requestedWorkspaceID }: {
  onOpenEvidence: (hash: string) => void;
  onConversationChange: (conversationID: string | null) => void;
  initialConversationID: string | null;
  state: WorkspaceDataState;
  pushToast: (kind: "success" | "error", text: string) => void;
  // The workspace the parent currently has selected. It is available even when
  // the snapshot request fails, so a transient snapshot failure can be told
  // apart from a genuine workspace change (requested id differs from the owned
  // one) without ever guessing a workspace identity from a failed response.
  requestedWorkspaceID: string | null;
}) {
  const [question, setQuestion] = useState("");
  const [selectedModelID, setSelectedModelID] = useState<string | null>(null);
  // The server selects the configured workspace mode. Explicit legacy modes
  // remain available through the API; the chat follows the mounted profile.
  const [submitting, setSubmitting] = useState(false);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [conversationList, setConversationList] = useState<ApiResult<ConversationsEnvelope> | null>(null);
  // R2 initial-load vs refresh split: whether this workspace currently shows an
  // ok conversations first page. Every in-app caller derives the presence from
  // the already-rendered conversationList and passes it explicitly (never from
  // the continuation cursor): a definite change and an initial load pass
  // `false`, a same-workspace refresh passes the rendered presence. A
  // no-argument call is treated as "an ok page may be shown" (`shownOkPage ??
  // true`), which is the host-harness contract: the extracted first-page
  // callback is invoked without an argument and must retain the already-rendered
  // rows and committed cursor. A transient first-page failure can
  // therefore tell a same-scope refresh — keep the shown rows and the exact
  // committed cursor and offer the first-page retry — apart from an initial load
  // with no ok page shown, which keeps the ordinary first-load/ClosedOrError
  // path and load wording and never surfaces the refresh wording or the
  // "refresh-error" continuation value.
  // Server-owned topics pagination (N4): the opaque cursor for the next page and
  // the continuation state. "invalid" means the server refused the cursor, so
  // the only recovery is an explicit list refresh, never an automatic loop.
  const [topicsCursor, setTopicsCursor] = useState<string | null>(null);
  // R2 refresh-cursor fix: the rendered topicsCursor state is the single source
  // of truth and is written only through setTopicsCursor, which the host
  // callback sandbox supplies directly together with the rendered `topicsCursor`
  // value. On a transient same-workspace first-page refresh failure the loader
  // explicitly re-commits the retained cursor with
  // `setTopicsCursor(topicsCursor)` — an observable write of the current value,
  // not retention by omission — so the rendered cursor stays the one the shown
  // page ends at. A workspace change/closure or a 401/403/404 denial writes null
  // through setTopicsCursor, so the transient re-commit can never resurrect
  // another workspace's cursor.
  // R2 retry-source split: the source of a transient page failure is carried by
  // topicsContinuation itself rather than by a second discriminator. "error" is
  // a real continuation failure and "refresh-error" a first-page refresh
  // failure, mirroring the audit journal's "refresh-error" continuation value
  // without needing a second rendered state: a first-page refresh failure is
  // retried as a fresh
  // first page (no cursor) even while the retained page still ends at a cursor,
  // while a real continuation failure retries that exact cursor via
  // loadMoreTopics. A first page that succeeded replaces rows and cursor, and
  // "invalid" still asks for an explicit refresh of a refused cursor.
  const [topicsContinuation, setTopicsContinuation] = useState<"idle" | "pending" | "error" | "refresh-error" | "invalid">("idle");
  const [selectedConversationID, setSelectedConversationID] = useState<string | null>(initialConversationID);
  const routedConversationRef = useRef<string | null>(initialConversationID);
  const [conversation, setConversation] = useState<ApiResult<ConversationEnvelope> | null>(null);
  const [localTurns, setLocalTurns] = useState<ConversationTurn[]>([]);
  const [lastFailure, setLastFailure] = useState<{ question: string; result: ApiFailure | ApiBroken } | null>(null);
  const [pendingQuestion, setPendingQuestion] = useState<string | null>(null);
  const [observedActions, setObservedActions] = useState<QuestionActionFrame[]>([]);
  const [pendingElapsedSeconds, setPendingElapsedSeconds] = useState(0);
  const [archiving, setArchiving] = useState(false);
  const [sidebarQuery, setSidebarQuery] = useState("");
  const [panelTarget, setPanelTarget] = useState<PanelTarget>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);
  const flowRef = useRef<HTMLDivElement | null>(null);
  // Every workspace switch, logout or first-page refresh bumps the generation,
  // so a delayed continuation response can never be appended to another
  // workspace's list. pendingCursorRef blocks a duplicate request for the same
  // cursor while one is already in flight.
  const topicsGenerationRef = useRef(0);
  const topicsPendingCursorRef = useRef<string | null>(null);
  // R2 refresh-epoch + cursor-identity guard: the page identity of a
  // continuation is the generation epoch AND ownership of the live
  // pending-cursor marker. The epoch is advanced by every shown page/cursor
  // replacement — the first-page attempt start, the first-page ok commit and the
  // fail-closed denial in loadFirstTopicsPage, both reset-effect cleanups, and
  // the cursor commit of a successful continuation in loadMoreTopics — so two
  // contiguous cursor states can never share one epoch. The live half is the
  // pending-marker ref: it holds the exact cursor an in-flight continuation was
  // issued against and is released by a first-page attempt, a reset cleanup, a
  // denial or a newer continuation, so it CAN differ from the captured cursor
  // while the request is in flight. It is deliberately a ref rather than a
  // second copy of the rendered topicsCursor state: a render-scope binding of
  // that state is constant for the life of the request and would make the
  // comparison a tautology, while the epoch already advances on every write that
  // can change the rendered cursor, so the ref ownership is the observable live
  // half. The rule is absolute for every response shape: no continuation answer
  // — including a transient network/5xx failure — may mutate the continuation
  // cursor or surface a retry unless its captured epoch still matches the shown
  // page and its pending marker is still its own; a superseded failure is
  // abandoned silently rather than reclassified onto the page that replaced it.
  // R3/R4: a separate epoch for the workspace itself. A workspace reset and any
  // access denial bump it, so a late question/archive answer that belongs to a
  // previous workspace can never mutate the current one. It is deliberately
  // distinct from topicsGenerationRef: a same-workspace topics refresh bumps
  // the pagination epoch but must not discard a valid in-flight question or
  // archive.
  const workspaceGenerationRef = useRef(0);
  // R3 cancellation: the AbortController of the in-flight question stream
  // request, if any. Leaving the conversation, switching conversations or
  // pressing stop calls abortActiveQuestion(), which aborts it so the browser
  // closes the underlying connection and the backend tool loop stops (see
  // apiPostQuestionStream above). conversationGenerationRef is bumped by the
  // same transitions so a response that arrives after the abort (or simply
  // late) can never mutate a different conversation's state; it is distinct
  // from workspaceGenerationRef, which already guards a workspace change.
  // stoppedByUserRef distinguishes a deliberate Stop click from any other
  // aborted/broken request so submitQuestion does not show a scary error
  // card for a cancellation the user asked for.
  const questionAbortRef = useRef<AbortController | null>(null);
  const conversationGenerationRef = useRef(0);
  const stoppedByUserRef = useRef(false);
  function abortActiveQuestion() {
    questionAbortRef.current?.abort();
    questionAbortRef.current = null;
    conversationGenerationRef.current += 1;
    setSubmitting(false);
    setPendingQuestion(null);
    setObservedActions([]);
  }
  useEffect(() => () => { questionAbortRef.current?.abort(); }, []);
  // R2 refresh-fix: the workspace whose protected chat state (shown rows,
  // selection, local turns and continuation cursor) this state currently owns.
  // A null workspaceID has two very different causes, and retention
  // must tell them apart: while state.phase === "loading" the snapshot is
  // momentarily absent while the SAME workspace reloads, so the protected chat
  // state is kept; a snapshot that resolves non-ok (unavailable / removed /
  // revoked) is a definite change, so the reset effect bumps the workspace epoch
  // and drops the protected chat state.
  const snapshotResult = state.phase === "loaded" ? state.snapshot : null;
  const snapshot = snapshotResult !== null && snapshotResult.kind === "ok" ? snapshotResult.value : null;
  const workspaceID = snapshot?.id ?? null;
  const models = snapshot?.model_profiles ?? [];
  const selectedModel = selectedModelID === null
    ? models.find((model) => model.is_default) ?? models[0]
    : models.find((model) => model.id === selectedModelID);
  const workspaceClosed = snapshot !== null && (snapshot.status === "ARCHIVED" || snapshot.status === "REVOKED");
  // The momentary reload window: the workspace snapshot is being (re)fetched, so
  // a null workspaceID does NOT mean the workspace changed. Only this
  // phase keeps the cursor and the shown chat state; a loaded non-ok snapshot
  // that is a transient transport/5xx failure of the SAME workspace is also a
  // reload window (see below), while a definite 401/403/404 refusal is an
  // unavailable workspace and must fail closed.
  const snapshotReloadWindow = state.phase === "loading";
  // R2 refresh-fix: a loaded non-ok snapshot may be a transient transport (status
  // 0) or 5xx failure of the workspace this state already owns, exactly like the
  // loading window, not a definite removal/revocation. It is retained only when
  // the parent still requests the owned workspace, so a genuine workspace change
  // whose snapshot transiently fails still fails closed.
  const snapshotTransientFailure = snapshotResult !== null && isTransientPageFailure(snapshotResult);
  const allSources = state.phase === "loaded" && state.sources.kind === "ok" ? state.sources.value.sources : [];
  const activeSources = allSources.filter((source) => source.enabled && source.confirmation_state === "ACTIVE");
  const sourceNameByConnection = new Map(allSources.map((source) => [source.connection_id, source.connection_name]));

  useEffect(() => {
    if (routedConversationRef.current === initialConversationID) return;
    // R3: navigation away from the previously routed conversation aborts its
    // in-flight question, exactly like an explicit conversation switch below.
    abortActiveQuestion();
    routedConversationRef.current = initialConversationID;
    setSelectedConversationID(initialConversationID);
    setConversation(null);
    setLocalTurns([]);
    setPanelTarget(null);
  }, [initialConversationID]);

  // First page of the topics list. Server pagination replaces the old
  // unpaginated GET and the client-side 30-row cap, so a continuation can
  // actually reach past row 100. The generation guard invalidates every
  // in-flight first page and continuation whenever the workspace, session or
  // first-page refresh changes.
  const loadFirstTopicsPage = useCallback((shownOkPage?: boolean) => {
    const generation = ++topicsGenerationRef.current;
    // The generation bump above starts a new page identity, so a continuation
    // issued from here on is bound to this attempt and any in-flight
    // continuation from the previously shown page is superseded: a continuation
    // captured against a page whose first page is being replaced (or which is
    // about to be reset or closed) can never commit.
    topicsPendingCursorRef.current = null;
    // A first-page attempt bumps the generation, so every continuation issued
    // against the previously shown page can never commit against the new one.
    // The cursor and the shown list are deliberately NOT cleared before the
    // await: a same-workspace refresh must be able to keep them if the first
    // page turns out to be a transient failure. Only an actual workspace
    // change/closure (owned by the reset effect below) or a 401/403/404 denial
    // resets them; a successful refresh replaces them.
    if (workspaceID === null) {
      // R2 refresh-cursor fix: a null workspaceID is either "no workspace
      // selected" or the transient snapshot reload window of the workspace
      // this state already belongs to. Either way the loader only returns
      // early and never clears the shown rows, the selection or the
      // conversation list, so a transient first-page refresh keeps them, and
      // the already-rendered topicsCursor state is the retained cursor without
      // consulting any hidden expando, ref or other callback-scope identifier.
      // R2 refresh-cursor retention: when this call is a same-workspace
      // refresh that still shows an ok page — the `shownOkPage` half of the
      // existing refresh contract, `?? true` for the host harness — the
      // retained rendered cursor is re-committed explicitly through
      // setTopicsCursor(topicsCursor), exactly as the transient branch below
      // does, so the momentary null-workspace reload window cannot lose the
      // cursor of the page already shown. A definite workspace change/closure
      // and the first load pass an explicit `false`, so they never re-commit a
      // cursor here and can never resurrect another workspace's cursor. The
      // value written is always the rendered one, never a literal null invented
      // here.
      // Genuine workspace change/closure resets are owned solely by the reset
      // effect below. This loader call bumped topicsGenerationRef above, which
      // invalidated every in-flight continuation, so a retained cursor must not
      // be left with topicsContinuation stuck at "pending": reconcile it to
      // "idle" while the cursor itself is kept.
      if (shownOkPage ?? true) setTopicsCursor(topicsCursor);
      setTopicsContinuation((current) => (current === "pending" ? "idle" : current));
      return;
    }
    if (workspaceClosed) {
      setTopicsCursor(null);
      setTopicsContinuation("idle");
      setConversations([]);
      setConversationList(null);
      return;
    }
    // The reset effect distinguishes a loading reload window (keep the protected
    // chat state) from a loaded non-ok snapshot (definite change: bump the
    // workspace epoch and clear). The loader itself only refreshes the first
    // page for a definite workspace id.
    apiGet<ConversationsEnvelope>(`/api/v1/workspaces/${encodeURIComponent(workspaceID)}/conversations?limit=50`).then((result) => {
      if (topicsGenerationRef.current !== generation) return;
      if (result.kind === "ok") {
        // The refreshed first page is the new shown list: advance the generation
        // so a continuation that was in flight against the previous page (or
        // started during this refresh, before this commit) can never append its
        // stale rows or commit a stale cursor. Rows and cursor are replaced
        // together in this same batch.
        topicsGenerationRef.current += 1;
        const nextCursor = result.value.next_cursor || null;
        setConversationList(result);
        setConversations(result.value.conversations);
        setTopicsCursor(nextCursor);
        setTopicsContinuation("idle");
        return;
      }
      if (isTransientPageFailure(result)) {
        // R2 refresh-fix: a network failure (status 0 in any result shape) or
        // 5xx is transient, but the retry it surfaces depends on whether an ok
        // conversations first page is already shown for this workspace. With a
        // shown ok page the cursor is NOT cleared before the await, so an
        // in-place SAME-workspace refresh keeps shown rows, selection, local
        // answers and the continuation cursor; the failure is surfaced as
        // continuation "refresh-error" (a distinct rendered value, not "error"),
        // so the single retry re-issues the first page (no cursor) as a refresh
        // even while the retained page still ends at a continuation cursor,
        // instead of consuming that cursor with a next-page request.
        // Page presence is not derived from a functional setState updater
        // (React does not guarantee its synchronous execution) and not from a
        // stale closure: every in-app caller passes the presence of the
        // already-rendered ok page explicitly, including the explicit `false`
        // of an initial load and of a definite workspace change. An omitted
        // argument is treated as "an ok page may be shown" (`?? true`), which
        // is the host-harness contract: the extracted first-page callback is
        // invoked without an argument, and that invocation must retain the
        // already-rendered conversations and the committed cursor rather than
        // dropping them. A first load with no shown ok page always passes the
        // explicit `false` from the reset effect, so this default never turns a
        // genuine first-load failure into a retention.
        const hasShownOkPage = shownOkPage ?? true;
        if (hasShownOkPage) {
          setConversationList((current) => (current?.kind === "ok" ? current : result));
          // R2 retention: a transient same-workspace first-page refresh must
          // keep the cursor the shown page ends at. The retention is an explicit
          // re-commit of the retained continuation cursor to the rendered
          // topicsCursor state (mirroring the journal retention, which
          // re-asserts `nextCursor: retained.nextCursor`), not merely the
          // absence of a write. The loader calls setTopicsCursor with the
          // current rendered `topicsCursor` value, both of which the host
          // callback sandbox supplies directly, so the retained cursor is
          // directly observable on the rendered state after a status 0 or >=500
          // failure — the host-owned regression
          // "Transient first-page refresh must retain the continuation cursor"
          // observes the retained cursor, never null, for a shown ok page. No
          // literal null is written here: a workspace change/closure or a
          // 401/403/404 denial has already written null through setTopicsCursor
          // before this response could pass the generation guard, so this can
          // never resurrect another workspace's cursor.
          setTopicsCursor(topicsCursor);
          // This failure belongs to the first-page refresh, not to a continuation.
          // Recording that on the rendered topicsContinuation state ("refresh-error",
          // distinct from a continuation's "error") lets the control retry the
          // refresh as a refresh and lets the panel word it as a refresh failure.
          // Keep the "list outdated" refresh button for a genuinely invalid
          // cursor; otherwise surface the refresh retry.
          setTopicsContinuation((current) => (current === "invalid" ? "invalid" : "refresh-error"));
        } else {
          // R2 initial-load vs refresh split: with no ok page shown there is
          // nothing to retain, so this transient failure is the ordinary
          // first-load failure and is rendered through the same first-load/
          // ClosedOrError path as any initial failure, with load wording: the
          // failure result becomes the shown result and the continuation stays
          // out of "refresh-error" (so the panel never words it "Could not
          // refresh conversations."). No cursor is written here at all: an initial load
          // never had one (the state starts null and the reset effect clears it
          // before this loader runs), so the transient branch performs no write
          // that could set it to null and can never drop a retained cursor.
          setConversationList(result);
          setConversations([]);
          setTopicsContinuation("idle");
        }
        return;
      }
      // R2: 401/403/404 (revoked access, political 404) fail closed. Drop every
      // piece of protected chat state, reset transient flags and invalidate
      // every outstanding request so no stale answer/evidence can survive. The
      // generation is bumped too, so an in-flight continuation cannot resurrect
      // the dropped rows into the closed list.
      workspaceGenerationRef.current += 1;
      topicsGenerationRef.current += 1;
      topicsPendingCursorRef.current = null;
      setConversationList(result);
      setConversations([]);
      setSelectedConversationID(null);
      setConversation(null);
      setLocalTurns([]);
      setLastFailure(null);
      setPendingQuestion(null);
      setPanelTarget(null);
      setTopicsCursor(null);
      setTopicsContinuation("idle");
      setSubmitting(false);
      setArchiving(false);
      setQuestion("");
    });
  }, [workspaceID, workspaceClosed, topicsCursor]);

  // R2 refresh-cursor fix: the workspace reset effect must reach the current
  // first-page loader without listing it in its deps. If the effect depended on
  // the callback identity, a change that recreated the callback would re-run the
  // effect and start another first-page load (a refetch loop that discards
  // pagination). The latest-callback ref carries the fresh callback into the
  // effect instead. The callback now lists `topicsCursor` in its deps because
  // the transient retention path re-commits that exact rendered value through
  // setTopicsCursor; the dep keeps the re-committed value the current one rather
  // than a stale render-scope capture. The reset effect's own deps are unchanged,
  // so a cursor commit cannot re-run it and start a refetch loop.
  const loadFirstTopicsPageRef = useRef(loadFirstTopicsPage);
  useEffect(() => {
    loadFirstTopicsPageRef.current = loadFirstTopicsPage;
  }, [loadFirstTopicsPage]);

  // R2 refresh-fix: the workspace whose protected chat state this component
  // currently shows. Written by the reset effect's definite-change branch and
  // read by the same-workspace refresh check.
  // A deep-linked conversation has an owner before the workspace snapshot
  // finishes its first authorized hydration. Treat that first load as this
  // workspace's loading window so the reset path cannot clear the opaque
  // selection before the conversation GET runs. A normal first visit still
  // starts ownerless, and a later different workspace still resets.
  const ownedWorkspaceIDRef = useRef<string | null>(initialConversationWorkspaceOwner(initialConversationID, requestedWorkspaceID));

  useEffect(() => {
    const owner = ownedWorkspaceIDRef.current;
    // A null workspaceID is only retained when it comes from the momentary
    // loading window of the SAME workspace, or from a transient (status 0 / 5xx)
    // snapshot failure of that same still-requested workspace: state.phase ===
    // "loading" or a loaded non-ok transient snapshot keeps the shown rows,
    // selection, local turns and continuation cursor. A null workspaceID from a
    // loaded non-transient snapshot (401/403/404/removal/revocation), from a
    // loading window or transient failure of a DIFFERENT requested workspace, or
    // from any window while no workspace is requested, is a definite change, not
    // a reload: it must fail closed (bump the workspace epoch and clear the
    // protected chat state). A definite id equal to the owner (and not closed) is
    // a same-workspace refresh; a definite different id or a closure resets.
    const sameRequestedWorkspace = owner !== null && requestedWorkspaceID === owner;
    const transientSameWorkspaceReload = (snapshotReloadWindow && sameRequestedWorkspace)
      || (snapshotTransientFailure && sameRequestedWorkspace);
    const sameWorkspaceRefresh = workspaceID !== null && owner === workspaceID && !workspaceClosed;
    if (transientSameWorkspaceReload || sameWorkspaceRefresh) {
      // R2 refresh-fix: a same-workspace first-page refresh — including the
      // momentary workspaceID-null window while the snapshot reloads — keeps
      // the shown rows, selection, local turns and continuation cursor. The
      // loader replaces them on success and leaves them untouched on a
      // transient failure. No workspace epoch is bumped, so an in-flight
      // question or archive for this workspace is not discarded.
      // The presence of the shown ok page is taken from the already-rendered
      // conversationList at the moment this refresh path runs; it is not added
      // to the effect deps, so a cursor/list commit can never re-run this effect
      // and start another first-page load. The loader is reached through the
      // latest-callback ref for the same reason: listing the callback identity
      // here would recreate the effect whenever the callback is recreated.
      loadFirstTopicsPageRef.current(conversationList?.kind === "ok");
      return () => {
        topicsGenerationRef.current += 1;
        topicsPendingCursorRef.current = null;
      };
    }
    // R3/R4: a real workspace change/closure (or a snapshot that resolved
    // non-ok, or the first mount that already has a workspace) starts a new
    // workspace epoch and clears the protected chat state, transient flags and
    // question draft before the new workspace's first page is loaded. Only an
    // actual change resets the continuation cursor, so a workspace can never
    // inherit another workspace's cursor and a late question or archive can
    // never mutate an unavailable view.
    workspaceGenerationRef.current += 1;
    setConversations([]);
    setConversationList(null);
    setTopicsCursor(null);
    setTopicsContinuation("idle");
    setSelectedConversationID(null);
    setConversation(null);
    setLocalTurns([]);
    setLastFailure(null);
    setPendingQuestion(null);
    setPanelTarget(null);
    setSubmitting(false);
    setArchiving(false);
    setQuestion("");
    topicsPendingCursorRef.current = null;
    ownedWorkspaceIDRef.current = workspaceID;
    // A definite change has no shown ok page for this workspace, so a transient
    // failure must take the initial-load path, never the retained-refresh path.
    loadFirstTopicsPageRef.current(false);
    return () => {
      topicsGenerationRef.current += 1;
      topicsPendingCursorRef.current = null;
    };
  }, [snapshotReloadWindow, snapshotTransientFailure, requestedWorkspaceID]);

  // N4 continuation: append the next server page, dedupe by conversation_id and
  // keep the current selection and scroll. A network/5xx failure is retryable on
  // the same cursor only while this continuation still owns the shown page (its
  // captured generation still matches); an invalid cursor asks for an explicit
  // list refresh instead of an automatic request loop; any other refusal fails
  // closed.
  const loadMoreTopics = useCallback(() => {
    const cursor = topicsCursor;
    if (workspaceID === null || workspaceClosed || cursor === null) return;
    // R2 refresh-cursor fix: a retained topics page whose first-page refresh
    // failed transiently ("refresh-error"), or whose opaque cursor the server
    // refused ("invalid"), owns its cursor for an explicit first-page refresh,
    // not for a next-page append. Refuse the continuation in those states so the
    // retained cursor is re-issued by loadFirstTopicsPage as the refresh itself
    // and can never be consumed as a cursor continuation request.
    if (topicsContinuation === "refresh-error" || topicsContinuation === "invalid") return;
    if (topicsContinuation === "pending" || topicsPendingCursorRef.current === cursor) return;
    const generation = topicsGenerationRef.current;
    topicsPendingCursorRef.current = cursor;
    setTopicsContinuation("pending");
    apiGet<ConversationsEnvelope>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/conversations?limit=50&cursor=${encodeURIComponent(cursor)}`,
    ).then((result) => {
      // A transient network/5xx failure is retryable only for the page it was
      // issued against: the page identity is the generation captured before the
      // request plus ownership of the live pending-marker ref. It is therefore
      // NOT classified before the page-identity guard — a superseded continuation
      // (a first-page refresh attempt/commit, a reset, a closure or a newer
      // continuation replaced the shown page/cursor while this request was in
      // flight) must be abandoned without surfacing a retry on the page that
      // replaced it. Only a continuation whose captured generation still matches
      // the shown page may surface the retry. The marker is released only when
      // this continuation still owns it; a newer continuation that owns the
      // marker for a different cursor is left untouched.
      if (isTransientPageFailure(result)) {
        // A newer continuation that owns the pending marker for a different
        // cursor owns the "pending" state and its own retry: leave it untouched.
        if (topicsPendingCursorRef.current !== null && topicsPendingCursorRef.current !== cursor) return;
        // Release this continuation's own pending marker before deciding
        // whether the failure is still retryable, so a superseded failure can
        // never strand the control at "pending".
        if (topicsPendingCursorRef.current === cursor) topicsPendingCursorRef.current = null;
        if (topicsGenerationRef.current !== generation) {
          // A workspace switch, first-page attempt/refresh commit, closure or a
          // newer continuation replaced the shown page while this request was in
          // flight, so this failure is abandoned without surfacing a retry on the
          // page that replaced it. The pending-marker ownership checks above
          // already dismissed a marker handed to a newer cursor, and the epoch is
          // bumped by every write that replaces the shown cursor, so a stale
          // failure cannot be reclassified onto the page that replaced it. A
          // "pending" this request still owned is reconciled back to "idle",
          // mirroring the successful-response branch below, and no stale rows or
          // cursor are committed.
          setTopicsContinuation((current) => (current === "pending" ? "idle" : current));
          return;
        }
        topicsPendingCursorRef.current = null;
        // This failure belongs to the continuation, not to a first-page refresh:
        // it stays on the rendered "error" value (distinct from a refresh's
        // "refresh-error"), so the panel words it as a continuation failure and
        // the single retry re-issues this exact retained cursor via loadMoreTopics.
        setTopicsContinuation((current) => (current === "invalid" ? "invalid" : "error"));
        return;
      }
      const invalidCursor = result.kind === "failure" && result.status === 400 && result.code === "REQUEST_INVALID";
      // R2: access denial / 401 / 403 / political 404 (and every other malformed
      // refusal) fails closed before the guard. Drop every piece of protected
      // chat state, reset transient flags and invalidate every outstanding
      // request so no stale answer/evidence survives. This must not depend on
      // the generation or the shown cursor still matching.
      if (result.kind !== "ok" && !invalidCursor) {
        workspaceGenerationRef.current += 1;
        topicsGenerationRef.current += 1;
        topicsPendingCursorRef.current = null;
        setConversationList(result);
        setConversations([]);
        setSelectedConversationID(null);
        setConversation(null);
        setLocalTurns([]);
        setLastFailure(null);
        setPendingQuestion(null);
        setPanelTarget(null);
        setTopicsCursor(null);
        setTopicsContinuation("idle");
        setSubmitting(false);
        setArchiving(false);
        setQuestion("");
        return;
      }
      // A workspace switch, logout, first-page attempt/refresh/commit, closure,
      // fail-closed denial or a newer continuation's cursor commit superseded
      // this continuation's page, so this answer belongs to a list we no longer
      // show. Abandon it without committing and reconcile the continuation out of
      // "pending" so a same-workspace refresh can never strand the control at
      // "pending". A newer continuation that already owns the pending marker for
      // a different cursor is left untouched: its own response owns the marker
      // and the "pending" state, and releasing them here would let a stale page
      // append. The page identity has two halves. The first is the generation
      // epoch captured before the request: it is advanced by every page/cursor
      // replacement — the first-page attempt start, the first-page ok commit, the
      // fail-closed denial, both reset-effect cleanups AND a successful
      // continuation's cursor commit below — so a replaced shown cursor always
      // carries a stale epoch. The second is the live pending-marker ref: it
      // must still be the exact cursor this continuation extends, so a marker
      // handed to a newer cursor abandons too. The ref is deliberately not a copy
      // of the rendered topicsCursor state — such a render-scope binding could
      // not change while the request is in flight — while the epoch covers every
      // write that can change the rendered cursor.
      if (
        topicsGenerationRef.current !== generation
        || topicsPendingCursorRef.current !== cursor
      ) {
        if (topicsPendingCursorRef.current !== null && topicsPendingCursorRef.current !== cursor) return;
        topicsPendingCursorRef.current = null;
        setTopicsContinuation((current) => (current === "pending" ? "idle" : current));
        return;
      }
      topicsPendingCursorRef.current = null;
      if (result.kind === "ok") {
        // Committing this page replaces the shown cursor, i.e. it starts a new
        // page identity. Advance the epoch in the same synchronous batch as the
        // rows/cursor commit so a continuation issued against the previous
        // cursor carries an older epoch and can never append its stale rows or
        // advance the cursor, even though no first-page refresh happened. The
        // epoch is what keeps the identity complete: it is bumped by every write
        // that can change the rendered cursor, while the pending-marker ref is
        // the observable live ownership half.
        topicsGenerationRef.current += 1;
        setConversations((current) => {
          const seen = new Set(current.map((item) => item.conversation_id));
          return [...current, ...result.value.conversations.filter((item) => !seen.has(item.conversation_id))];
        });
        const nextCursor = result.value.next_cursor || null;
        setTopicsCursor(nextCursor);
        setTopicsContinuation("idle");
        return;
      }
      // The server refused the opaque cursor: keep the shown page and offer a
      // one-shot list refresh; never retry the bad cursor in a loop. This is
      // refresh styling, not access-denial styling.
      setTopicsContinuation("invalid");
    });
  }, [workspaceID, workspaceClosed, topicsCursor, topicsContinuation]);

  useEffect(() => {
    let alive = true;
    setConversation(null);
    if (workspaceID === null || workspaceClosed || selectedConversationID === null) return () => { alive = false; };
    apiGet<ConversationEnvelope>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/conversations/${encodeURIComponent(selectedConversationID)}`,
    ).then((result) => {
      if (alive) setConversation(result);
    });
    return () => { alive = false; };
  }, [workspaceID, workspaceClosed, selectedConversationID]);

  // Keep the answer readable first; evidence opens when the reader selects a
  // citation or a turn.
  useEffect(() => {
    if (conversation?.kind !== "ok" || conversation.value.turns.length === 0) return;
    setPanelTarget(null);
    setFullscreen(false);
  }, [conversation]);

  const remoteTurns = conversation?.kind === "ok" ? conversation.value.turns : [];
  const remoteTurnIDs = new Set(remoteTurns.map((turn) => turn.question_run_id));
  const feedTurns = [...remoteTurns, ...localTurns.filter((turn) => !remoteTurnIDs.has(turn.question_run_id))];
  const detailLoading = selectedConversationID !== null && conversation === null;
  const turnsByID = new Map(feedTurns.map((turn) => [turn.turn_id, turn]));

  useEffect(() => {
    if (pendingQuestion === null) return;
    const startedAt = Date.now();
    setPendingElapsedSeconds(0);
    const interval = window.setInterval(() => setPendingElapsedSeconds(Math.floor((Date.now() - startedAt) / 1000)), 1000);
    return () => window.clearInterval(interval);
  }, [pendingQuestion]);

  useEffect(() => {
    const flow = flowRef.current;
    const latest = flow?.querySelector(".turn:last-child");
    if (flow && latest) flow.scrollTo({ top: latest.getBoundingClientRect().top - flow.getBoundingClientRect().top + flow.scrollTop - 16 });
  }, [feedTurns.length, pendingQuestion, lastFailure]);

  function selectTurn(turn: ConversationTurn) {
    dismissFootnoteTooltip();
    setPanelTarget({ turnId: turn.turn_id, citationId: firstAnswerCitation(turn.question_run) });
    setFullscreen(false);
  }

  function selectCitation(turn: ConversationTurn, citationID: string) {
    setPanelTarget({ turnId: turn.turn_id, citationId: citationID });
  }

  async function submitQuestion(event: FormEvent) {
    event.preventDefault();
    const trimmed = question.trim();
    if (!trimmed || workspaceID === null || workspaceClosed || submitting) return;
    // Capture whether an ok conversations first page is currently shown before
    // this handler schedules any state update. It is read through the public
    // functional setter — never as a free variable — so a host sandbox that runs
    // the extracted chat callback needs no extra identifier, and the captured
    // value lets the post-answer list refresh keep the shown page if it fails
    // transiently instead of clearing it.
    let hadShownOkPage = false;
    setConversationList((current) => {
      hadShownOkPage = current?.kind === "ok";
      return current;
    });
    const workspaceGeneration = workspaceGenerationRef.current;
    const conversationGeneration = conversationGenerationRef.current;
    const controller = new AbortController();
    questionAbortRef.current = controller;
    stoppedByUserRef.current = false;
    setSubmitting(true);
    setLastFailure(null);
    setQuestion("");
    setPendingQuestion(trimmed);
    setObservedActions([]);
    const result = await apiPostQuestionStream(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/questions`,
      { ...questionRunPayload(trimmed, selectedModel), ...(selectedConversationID ? { conversation_id: selectedConversationID } : {}) },
      newIdempotencyKey(),
      observationForGeneration(workspaceGeneration, () => workspaceGenerationRef.current,
        (action) => setObservedActions((current) => [...current, action])),
      controller.signal,
    );
    if (questionAbortRef.current === controller) questionAbortRef.current = null;
    const wasStopped = stoppedByUserRef.current;
    stoppedByUserRef.current = false;
    // R3: before ANY post-await mutation, drop an answer that belongs to a
    // workspace generation that has since been reset or denied, or to a
    // conversation that has since been left (switched away from, replaced by
    // a new conversation, or navigated away from) — abortActiveQuestion()
    // already aborted the request and reset the pending UI state in that
    // case, so a late completion must not clear or mutate anything.
    if (workspaceGenerationRef.current !== workspaceGeneration || conversationGenerationRef.current !== conversationGeneration) return;
    setPendingQuestion(null);
    setSubmitting(false);
    if (wasStopped) {
      // The user pressed Stop: restore the draft without showing an error card.
      setQuestion(trimmed);
      return;
    }
    if (result.kind === "ok") {
      const turn: ConversationTurn = {
        turn_id: result.value.question_run_id,
        question_run_id: result.value.question_run_id,
        turn_index: localTurns.length,
        created_at: result.value.completed_at ?? result.value.started_at,
        question_run: result.value,
      };
      dismissFootnoteTooltip();
      setLocalTurns((current) => [...current, turn]);
      setPanelTarget(null);
      setFullscreen(false);
      if (result.value.conversation_id && result.value.conversation_id !== selectedConversationID) {
        setSelectedConversationID(result.value.conversation_id);
        routedConversationRef.current = result.value.conversation_id;
        onConversationChange(result.value.conversation_id);
      }
      // A successful answer can create a topic or add a turn to the selected
      // topic. Refresh the authorized first server page (limit=50) in both
      // cases so the sidebar's server-owned turn count stays current. The
      // existing loader retains the shown page and cursor on transient failure
      // and keeps its workspace-generation guard.
      loadFirstTopicsPage(hadShownOkPage);
    } else {
      setLastFailure({ question: trimmed, result });
      setQuestion(trimmed);
    }
  }

  function handleComposerKeyDown(event: ReactKeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  }

  function focusComposer() {
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }

  // R3: pressing Stop aborts the in-flight question from the browser so the
  // backend loop stops; submitQuestion restores the draft without an error
  // card once its (now-aborted) request settles.
  function stopQuestion() {
    if (!submitting) return;
    stoppedByUserRef.current = true;
    questionAbortRef.current?.abort();
  }

  function startNewConversation() {
    // R3: leaving the conversation for a new, empty one aborts any in-flight
    // question rather than letting its answer land in the new conversation.
    abortActiveQuestion();
    dismissFootnoteTooltip();
    setSelectedConversationID(null);
    routedConversationRef.current = null;
    onConversationChange(null);
    setConversation(null);
    setLocalTurns([]);
    setLastFailure(null);
    setQuestion("");
    setPanelTarget(null);
    setFullscreen(false);
    focusComposer();
  }

  function selectConversation(conversationID: string) {
    if (conversationID === selectedConversationID) return;
    // R3: switching conversations aborts any in-flight question rather than
    // blocking the switch or letting a late answer land in the new one.
    abortActiveQuestion();
    dismissFootnoteTooltip();
    setLastFailure(null);
    setLocalTurns([]);
    setSelectedConversationID(conversationID);
    routedConversationRef.current = conversationID;
    onConversationChange(conversationID);
  }

  async function archiveConversation() {
    if (workspaceID === null || selectedConversationID === null || archiving) return;
    const workspaceGeneration = workspaceGenerationRef.current;
    const conversationID = selectedConversationID;
    setArchiving(true);
    const result = await apiAction<ConversationEnvelope>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/conversations/${encodeURIComponent(conversationID)}:archive`,
      newIdempotencyKey(),
    );
    // R4: both the success and failure paths are guarded so an archive that
    // belongs to a previous workspace generation (reset or denial) can never
    // change the new selection, list, toast or the archiving flag.
    if (workspaceGenerationRef.current !== workspaceGeneration) return;
    setArchiving(false);
    if (result.kind === "ok") {
      pushToast("success", "Conversation archived and removed from the sidebar.");
      setConversations((current) => current.filter((item) => item.conversation_id !== conversationID));
      startNewConversation();
    } else {
      pushToast("error", closedText(result));
    }
  }

  if (state.phase === "idle") {
    return <div className="empty-state"><h2>Select a workspace</h2><p>Select a workspace to ask questions.</p></div>;
  }
  if (state.phase === "loading") {
    return <div className="empty-state"><h2>Loading workspace</h2><p>Checking access and data status.</p></div>;
  }
  if (state.snapshot.kind !== "ok") {
    return <div className="empty-state"><ClosedOrError result={state.snapshot} /></div>;
  }
  if (workspaceClosed) {
    return <div className="empty-state"><h2>Workspace unavailable</h2><p>An archived or revoked workspace is read only and does not accept questions.</p></div>;
  }

  const examples = exampleQuestions(activeSources);
  const conversationFailure = conversationList?.kind === "failure" || conversationList?.kind === "broken" ? conversationList : null;
  const detailFailure = conversation?.kind === "failure" || conversation?.kind === "broken" ? conversation : null;
  const visibleConversations = sidebarConversations(conversations, selectedConversationID, sidebarQuery);
  const showGreeting = selectedConversationID === null && feedTurns.length === 0 && pendingQuestion === null && !lastFailure;
  const currentTitle = selectedConversationID !== null && conversation?.kind === "ok" ? conversationTitle(conversation.value) : null;

  return (
    <div className={fullscreen ? "ask-layout ask-layout-full" : "ask-layout"}>
      <section aria-label="Conversations" className="topics">
        <h2>Conversations</h2>
        <label className="sidebar-search">
          <span className="sr-only">Search conversations</span>
          <input onChange={(event) => setSidebarQuery(event.target.value)} placeholder="Search conversations…" type="search" value={sidebarQuery} />
        </label>
        <div className="topics-list">
          {conversationList === null && [0, 1, 2, 3].map((item) => <div className="skeleton-row" key={item} />)}
          {conversationFailure && (
            <>
              {/* R2 stable topic-list error label (browser acceptance gate): the
                  initial-load failure renders the same stable label as the
                  first-page refresh failure so the transient-refresh scenario
                  always sees visible error text, not only the retry control.
                  Additional explanatory text (ClosedOrError) may follow it, and
                  the first-page retry is offered unless the failure is a
                  fail-closed 401/403/404 denial, which resets to "idle" and
                  deliberately offers no retry. */}
              <p className="muted">{TOPIC_LIST_ERROR_LABEL}</p>
              <ClosedOrError result={conversationFailure} />
              {!(conversationFailure.kind === "failure"
                && (conversationFailure.status === 401 || conversationFailure.status === 403 || conversationFailure.status === 404)) && (
                <button className="secondary-button" onClick={() => loadFirstTopicsPage(conversationList?.kind === "ok")} type="button">Retry</button>
              )}
            </>
          )}
          {conversationList?.kind === "ok" && visibleConversations.length === 0 && (
            <p className="muted">{sidebarConversations(conversations, selectedConversationID, "").length === 0 ? "No conversations yet." : "No results found."}</p>
          )}
          {conversationList?.kind === "ok" && visibleConversations.map((item) => (
            <button
              aria-current={item.conversation_id === selectedConversationID}
              className={item.conversation_id === selectedConversationID ? "topic-item selected" : "topic-item"}
              key={item.conversation_id}
              onClick={() => selectConversation(item.conversation_id)}
              type="button"
            >
              <span>{conversationTitle(item)}</span>
              <small>{formatTime(item.created_at)} · {item.turns.length} {item.turns.length === 1 ? "turn" : "turns"}</small>
            </button>
          ))}
          {/* R2 refresh/continuation retry split: a transient page failure
              surfaces as continuation "error" for a real continuation and
              "refresh-error" for a first-page refresh, with the shown page and
              its exact cursor retained. A first-page refresh failure is retried
              as a first page (no cursor) even while the retained page still ends
              at a cursor, so it can never be answered by consuming that cursor
              with a next-page request; a real continuation failure retries the
              exact retained cursor through loadMoreTopics. Only a retained page
              with no cursor left (an initial load that failed, or a page that
              ends the list) falls back to the first-page retry. A fail-closed
              401/403/404 resets the continuation to "idle", so no retry control
              is offered there. */}
          {((conversationList?.kind === "ok" && topicsCursor !== null)
            || topicsContinuation === "error"
            || topicsContinuation === "refresh-error"
            || topicsContinuation === "invalid") && (
            <div>
              {topicsContinuation === "error" && (
                <>
                  <p className="muted">{TOPIC_LIST_ERROR_LABEL}</p>
                  <p className="muted">Could not load more conversations.</p>
                </>
              )}
              {topicsContinuation === "refresh-error" && (
                <p className="muted">{TOPIC_LIST_ERROR_LABEL}</p>
              )}
              {/* R2 stable label on the invalid/stale refresh-failure path: a
                  refresh requested from the stale state that fails (status 0 or
                  any 5xx) keeps the state "invalid" (see the loader above) and
                  renders the stale-list text with the refresh control. Every
                  topic-list error state must show the stable label
                  “Could not load conversations.” (browser-acceptance gate), while
                  the previously shown topic items stay in the list. */}
              {topicsContinuation === "invalid" && (
                <>
                  <p className="muted">{TOPIC_LIST_ERROR_LABEL}</p>
                  <p className="muted">The list is out of date. Refresh it to continue.</p>
                </>
              )}
              {topicsContinuation === "invalid" ? (
                <button className="secondary-button" onClick={() => loadFirstTopicsPage(conversationList?.kind === "ok")} type="button">Refresh list</button>
              ) : topicsContinuation === "refresh-error" ? (
                <button className="secondary-button" onClick={() => loadFirstTopicsPage(conversationList?.kind === "ok")} type="button">Retry</button>
              ) : topicsCursor === null ? (
                <button className="secondary-button" onClick={() => loadFirstTopicsPage(conversationList?.kind === "ok")} type="button">Retry</button>
              ) : (
                <button
                  className="secondary-button"
                  disabled={topicsContinuation === "pending"}
                  onClick={loadMoreTopics}
                  type="button"
                >
                  {topicsContinuation === "pending" ? "Loading…" : topicsContinuation === "error" ? "Retry" : "Show more conversations"}
                </button>
              )}
            </div>
          )}
        </div>
        <button className="topics-new" onClick={startNewConversation} type="button"><IconPlus />New conversation</button>
      </section>

      <section aria-live="polite" className="talk">
        <div className="flow" ref={flowRef}>
          {currentTitle && (
            <header className="flow-head">
              <h1>{currentTitle}</h1>
              <button className="text-button" disabled={archiving} onClick={() => void archiveConversation()} type="button">
                {archiving ? "Archiving…" : "Archive"}
              </button>
            </header>
          )}

          {detailFailure && <ClosedOrError result={detailFailure} />}

          {showGreeting && (
            <div className="invite">
              <h1>Ask about your workspace in plain language.</h1>
              <p className="sub">Your answer will appear here. Citations open supporting fragments on the right. Include the relevant time period and conditions for a more precise answer.</p>
              {examples.length > 0 ? (
                <div className="example-questions">
                  {examples.map((example) => (
                    <button className="example-chip" key={example} onClick={() => { setQuestion(example); focusComposer(); }} type="button">
                      {example}
                    </button>
                  ))}
                </div>
              ) : (
                <p>No sources are connected yet. Add them in Sources to see example questions here.</p>
              )}
            </div>
          )}

          {detailLoading && (
            <div className="skeleton-row" />
          )}

          {feedTurns.map((turn) => (
            <TurnCard
              key={turn.turn_id}
              onSelectCitation={selectCitation}
              onSelectTurn={selectTurn}
              panelTurnId={panelTarget && "turnId" in panelTarget ? panelTarget.turnId : null}
              selectedCitationId={panelTarget && "citationId" in panelTarget ? panelTarget.citationId : null}
              turn={turn}
            />
          ))}

          {pendingQuestion !== null && (
            <article className="turn turn-on turn-pending">
              <p className="turn-question"><span className="turn-role">Question</span>{pendingQuestion}</p>
              <PendingAction elapsedSeconds={pendingElapsedSeconds} state={pendingActionFromEvents(observedActions)} />
              <button aria-label="Stop" className="text-button" onClick={stopQuestion} type="button">Stop</button>
            </article>
          )}

          {lastFailure && (
            <article className="turn turn-on">
              <p className="turn-question"><span className="turn-role">Question</span>{lastFailure.question}</p>
              <ClosedOrError result={lastFailure.result} />
            </article>
          )}
        </div>

        <div className="foot">
          <RelyBar sources={allSources} />
          <form className="question-composer" onSubmit={submitQuestion}>
            <label className="sr-only" htmlFor="ask-question">Question</label>
            <textarea
              id="ask-question"
              aria-describedby="ask-keyboard-hint"
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={handleComposerKeyDown}
              placeholder="Ask as you would ask a colleague"
              ref={inputRef}
              rows={1}
              value={question}
            />
            <button aria-label="Ask" className="go" disabled={!question.trim() || submitting} type="submit">
              {submitting ? "…" : "→"}
            </button>
          </form>
          {models.length > 0 && (
            <label className="question-model">
              <span>Model</span>
              <select aria-label="Model" className="search-model-select" value={selectedModel?.id ?? ""} onChange={(event) => setSelectedModelID(event.target.value)}>
                {!selectedModel && <option disabled value="">Select a model</option>}
                {models.map((model) => <option key={model.id} value={model.id}>{model.label} · {model.location === "EXTERNAL" ? "cloud" : "local"}</option>)}
              </select>
            </label>
          )}
          <p className="hint" id="ask-keyboard-hint">Enter to ask · Shift + Enter for a new line</p>
        </div>
      </section>

      <EvidencePanel
        allSources={allSources}
        fullscreen={fullscreen}
        onOpenEvidence={onOpenEvidence}
        onSelectCitation={(turnID, citationID) => {
          const turn = turnsByID.get(turnID);
          if (turn) selectCitation(turn, citationID);
        }}
        onToggleFullscreen={() => setFullscreen((value) => !value)}
        sourceNameByConnection={sourceNameByConnection}
        target={panelTarget}
        turnsByID={turnsByID}
        workspaceID={workspaceID}
      />
    </div>
  );
}

// The latest run and its queue job are separate observations. A previous
// success never masks a failed run, unknown freshness or a pending retry.
function sourceHeadline(source: SourceStatus): string {
  if (!source.enabled) return "Disabled";
  if (source.confirmation_state !== "ACTIVE") return confirmationStateLabel(source.confirmation_state);
  // S3 card 4: a query-only relation is registered for SQL only. It has no
  // sync run and therefore no freshness to report, so its state is the mode
  // itself rather than a sync label.
  if (source.query_only === true) return "только SQL";
  if (source.job_status === "PENDING") return (source.job_attempt_count ?? 0) > 0 ? "Waiting to retry" : "Queued";
  if (source.job_status === "RUNNING") return "Updating";
  if (source.job_status === "DEAD") return "Update failed";
  if (source.sync_status === "RUNNING") return "Updating";
  if (source.sync_status === "FAILED") return "Update failed";
  if (source.sync_error_code === "INGEST_PARTIAL_COVERAGE" || (source.quarantined ?? 0) > 0) return "Partially updated";
  if (source.sync_error_code || (source.job_last_error_code && source.job_status !== "SUCCEEDED")) return "Needs attention";
  if (source.freshness_state === "STALE") return "Data is stale";
  if (source.job_status && !["PENDING", "RUNNING", "SUCCEEDED", "DEAD"].includes(source.job_status)) return "Job status unknown";
  if (source.sync_status !== "SUCCEEDED" || source.freshness_state !== "FRESH") return "Status unconfirmed";
  return "Data is up to date";
}

function sourceTypeLabel(source: SourceStatus): string {
  return ({ FOLDER: "Document folder", POSTGRESQL_QUERY: "PostgreSQL", GIT: "Git repository" } as Record<string, string>)[source.source_type] ?? "Source type unknown";
}

function sourceLabel(source: SourceStatus): string {
  if (source.source_type === "POSTGRESQL_QUERY" && source.postgresql_schema_name && source.postgresql_relation_name) {
    return `${source.connection_name} · ${source.postgresql_schema_name}.${source.postgresql_relation_name}`;
  }
  return source.connection_name;
}

function sourceCardVariant(source: SourceStatus): "ready" | "attention" | "updating" | "disconnected" {
  if (!source.enabled) return "disconnected";
  if (source.confirmation_state !== "ACTIVE") return "attention";
  // A query-only table never syncs, so it carries no sync failure or
  // freshness: its registration mode is the whole state.
  if (source.query_only === true) return "ready";
  if (source.job_status === "DEAD" || source.sync_status === "FAILED" || source.sync_error_code
    || (source.quarantined ?? 0) > 0 || (source.job_last_error_code && source.job_status !== "SUCCEEDED")
    || source.freshness_state === "STALE") return "attention";
  if (source.job_status === "PENDING" || source.job_status === "RUNNING" || source.sync_status === "RUNNING") return "updating";
  if (source.job_status && source.job_status !== "SUCCEEDED") return "attention";
  return source.sync_status === "SUCCEEDED" && source.freshness_state === "FRESH" ? "ready" : "attention";
}

// Card S5.1: a PostgreSQL connection is one card in Sources. The page already
// loads one row per registered table — the same per-scope projection
// knowvault_sources serves over MCP — so the card is built from that data:
// tables are grouped by connection inside the caller's authorized workspace
// list, and the summary rolls up per-table facts the existing read already
// carries. No new server field and no second request are introduced.
export type SourceConnectionGroup = {
  connection_id: string;
  connection_name: string;
  source_type: string;
  tables: SourceStatus[];
};

// A table is indexed once one of its runs completed successfully: that run is
// exactly the moment the server publishes last_successful_sync_at for the
// scope, so the count is derived from server facts rather than a guess about
// published fragments (an empty table legitimately publishes none).
export function sourceTableIndexed(source: SourceStatus): boolean {
  return source.last_successful_sync_at !== null && source.last_successful_sync_at !== undefined;
}

// S3 card 4: a query-only table is registered "only for SQL queries (not
// indexed)". It is enabled and usable, but it never runs a sync and never
// publishes a fragment, so the Sources surface must not claim freshness for
// it.
export function sourceTableQueryOnly(source: SourceStatus): boolean {
  return source.query_only === true;
}

export type SourceConnectionState = "disabled" | "awaiting_confirmation" | "failed" | "updating" | "active";

function sourceTableFailed(source: SourceStatus): boolean {
  return source.sync_status === "FAILED" || source.job_status === "DEAD"
    || Boolean(source.sync_error_code)
    || (Boolean(source.job_last_error_code) && source.job_status !== "SUCCEEDED");
}

function sourceTableUpdating(source: SourceStatus): boolean {
  return source.job_status === "PENDING" || source.job_status === "RUNNING" || source.sync_status === "RUNNING";
}

// The connection's state is the most blocking state among its tables: an
// unconfirmed table keeps the whole connection awaiting confirmation, and a
// failed table is never hidden behind the healthy ones.
export function sourceConnectionState(group: SourceConnectionGroup): SourceConnectionState {
  if (group.tables.length === 0 || group.tables.every((table) => !table.enabled)) return "disabled";
  if (group.tables.some((table) => table.confirmation_state !== "ACTIVE")) return "awaiting_confirmation";
  if (group.tables.some(sourceTableFailed)) return "failed";
  if (group.tables.some(sourceTableUpdating)) return "updating";
  return "active";
}

// The freshness a connection shows is the least fresh state among its tables:
// one stale table means the connection's data is stale, and a table that never
// completed a successful run leaves the roll-up unknown rather than fresh.
export function sourceConnectionFreshnessState(group: SourceConnectionGroup): string {
  if (group.tables.length === 0) return "UNKNOWN";
  let unknown = false;
  let indexed = 0;
  for (const table of group.tables) {
    // S3 card 4: a query-only table has no sync run at all, so it must not
    // drag the connection's freshness down (nor up).
    if (sourceTableQueryOnly(table)) continue;
    indexed += 1;
    if (table.freshness_state === "STALE") return "STALE";
    if (table.freshness_state !== "FRESH") unknown = true;
  }
  if (indexed === 0) return "UNKNOWN";
  return unknown ? "UNKNOWN" : "FRESH";
}

export function sourceConnectionLastSuccessfulSyncAt(group: SourceConnectionGroup): string | null {
  let latest: string | null = null;
  let latestTime = Number.NEGATIVE_INFINITY;
  for (const table of group.tables) {
    if (!table.last_successful_sync_at) continue;
    const time = new Date(table.last_successful_sync_at).getTime();
    if (Number.isNaN(time) || time <= latestTime) continue;
    latestTime = time;
    latest = table.last_successful_sync_at;
  }
  return latest;
}

export type SourceConnectionSummary = {
  connection_id: string;
  connection_name: string;
  source_type: string;
  tables: SourceStatus[];
  table_count: number;
  indexed_count: number;
  last_successful_sync_at: string | null;
  freshness_state: string;
  state: SourceConnectionState;
  state_label: string;
  variant: "ready" | "attention" | "updating" | "disconnected";
  // ADR-0097: every table of one connection answers with the same connection
  // revision, so the connection's SQL state is the flag any of its tables
  // carries. A missing field (an older server) reads as "not configured",
  // which fails closed.
  sql_available: boolean;
  // S3 card 4: the connection's query-only roll-up. query_only_count is the
  // number of registered tables that are SQL-only; query_only is true only
  // when every table is SQL-only, in which case the card shows no sync
  // freshness at all.
  query_only_count: number;
  query_only: boolean;
};

const sourceConnectionStateLabels: Record<SourceConnectionState, string> = {
  disabled: "Disabled",
  awaiting_confirmation: "Awaiting confirmation",
  failed: "Failed",
  updating: "Updating",
  active: "Active",
};

// Draft is the fourth connection state the Sources surface names; it is served
// by the workspace source-drafts read and rendered by SourceConnectionDraftList
// exactly as before, so it is deliberately not re-derived here.
export function sourceConnectionSummary(group: SourceConnectionGroup): SourceConnectionSummary {
  const state = sourceConnectionState(group);
  const freshness = sourceConnectionFreshnessState(group);
  const queryOnlyCount = group.tables.filter(sourceTableQueryOnly).length;
  const allQueryOnly = group.tables.length > 0 && queryOnlyCount === group.tables.length;
  // A connection whose tables are all SQL-only has no sync run to report: its
  // state is the registration mode, never "status unconfirmed".
  const variant = allQueryOnly && state === "active" ? "ready"
    : state === "active" && freshness !== "FRESH" ? "attention"
      : state === "disabled" ? "disconnected"
        : state === "updating" ? "updating"
          : state === "active" ? "ready" : "attention";
  const stateLabel = allQueryOnly && state === "active" ? "только SQL"
    : state === "active" && freshness !== "FRESH"
      ? (freshness === "STALE" ? "Data is stale" : "Status unconfirmed")
      : sourceConnectionStateLabels[state];
  return {
    connection_id: group.connection_id,
    connection_name: group.connection_name,
    source_type: group.source_type,
    tables: group.tables,
    table_count: group.tables.length,
    indexed_count: group.tables.filter(sourceTableIndexed).length,
    last_successful_sync_at: sourceConnectionLastSuccessfulSyncAt(group),
    freshness_state: freshness,
    state,
    state_label: stateLabel,
    variant,
    sql_available: group.tables.some((table) => table.sql_available === true),
    query_only_count: queryOnlyCount,
    query_only: allQueryOnly,
  };
}

export type SourceCardEntry =
  | { kind: "connection"; key: string; group: SourceConnectionGroup }
  | { kind: "source"; key: string; source: SourceStatus };

// Every PostgreSQL scope of one connection becomes one connection entry; every
// other source type keeps its own single card. Grouping only ever touches the
// already-authorized list handed to it, so a workspace can never see another
// workspace's connection.
export function sourceCardEntries(sources: readonly SourceStatus[]): SourceCardEntry[] {
  const entries: SourceCardEntry[] = [];
  const groups = new Map<string, SourceConnectionGroup>();
  for (const source of sources) {
    if (source.source_type !== "POSTGRESQL_QUERY") {
      entries.push({ kind: "source", key: source.source_scope_id, source });
      continue;
    }
    const existing = groups.get(source.connection_id);
    if (existing) {
      existing.tables.push(source);
      continue;
    }
    const group: SourceConnectionGroup = {
      connection_id: source.connection_id, connection_name: source.connection_name,
      source_type: source.source_type, tables: [source],
    };
    groups.set(source.connection_id, group);
    entries.push({ kind: "connection", key: `connection:${source.connection_id}`, group });
  }
  return entries;
}

export function sourceTableLabel(source: SourceStatus): string {
  if (source.postgresql_schema_name && source.postgresql_relation_name) {
    return `${source.postgresql_schema_name}.${source.postgresql_relation_name}`;
  }
  return source.connection_name;
}

// When a source needs an operator action the viewer cannot themselves take,
// this is the one sentence that says so — never a silently-missing button.
function sourceBlockedNote(source: SourceStatus, canManage: boolean, confirmationContext: ConfirmationContext | null): string | null {
  if (source.confirmation_state === "NEEDS_GRANT" || source.confirmation_state === "NEEDS_CONFIRMATION") {
    if (!canManage) return "A workspace owner or manager can confirm access to this source.";
    if (source.confirmation_state === "NEEDS_GRANT" && confirmationContext && !confirmationContext.can_issue_confirmation_grant) {
      return "Only an organization owner or administrator can issue a confirmation grant.";
    }
    return null;
  }
  if (source.confirmation_state === "NEEDS_TRUST_VERIFICATION" && !source.can_verify_connection_trust) {
    if (confirmationContext && !confirmationContext.can_verify_connection_trust) {
      return "Only an organization connector administrator can verify trust for this source.";
    }
    return "You have already confirmed a source for this connector. A different connector administrator must verify its trust.";
  }
  if (source.confirmation_state === "READY_TO_ACTIVATE" && !canManage) {
    return "A workspace owner or manager can enable this source.";
  }
  return null;
}

// Card S3.4b: the tables of one connection that are actually awaiting a
// confirmation decision. It is exactly the state whose per-table row action is
// "Confirm" (NEEDS_GRANT or NEEDS_CONFIRMATION), never a table that awaits
// trust verification, activation or enabling -- so "confirm all" can never name
// a table the operator would not confirm one at a time. The list is the
// already-authorized server projection, so the bulk action never reveals
// another workspace's table.
export function sourceTablesAwaitingConfirmation(group: SourceConnectionGroup): SourceStatus[] {
  return group.tables.filter((table) =>
    table.confirmation_state === "NEEDS_GRANT" || table.confirmation_state === "NEEDS_CONFIRMATION");
}

// Distinct PostgreSQL schemas of the connection that still have at least one
// table awaiting confirmation, sorted, so a large catalog can be confirmed one
// schema at a time from the same card.
export function sourceSchemasAwaitingConfirmation(group: SourceConnectionGroup): string[] {
  const schemas = new Set<string>();
  for (const table of sourceTablesAwaitingConfirmation(group)) {
    if (table.postgresql_schema_name) schemas.add(table.postgresql_schema_name);
  }
  return [...schemas].sort((left, right) => left.localeCompare(right));
}

// The exact awaiting tables a confirmation action would name: every schema when
// the empty schema is selected, otherwise only that schema's tables.
export function sourceTablesAwaitingConfirmationInSchema(group: SourceConnectionGroup, schema: string): SourceStatus[] {
  const pending = sourceTablesAwaitingConfirmation(group);
  if (schema === "") return pending;
  return pending.filter((table) => table.postgresql_schema_name === schema);
}

export type SourceConfirmBatchTable = {
  workspace_source_id: string;
  source_scope_id: string;
  source_scope_revision: number;
  scope_config_hash: string;
};

// The one closed batch-confirmation body: the shared grant/warning/policy tuple
// plus one exact binding tuple per named table. It carries nothing a single
// confirmation would not carry.
export function confirmBatchRequestBody(
  tables: readonly SourceStatus[],
  workspaceRevision: number,
  workspaceConfigurationHash: string,
  grant: { grant_id: string; grant_revision: number; grant_hash: string },
  warningContractHash: string,
  expectedPolicyRevision: string,
): {
  workspace_revision: number;
  workspace_configuration_hash: string;
  confirmation_actor_grant_id: string;
  confirmation_actor_grant_revision: number;
  confirmation_actor_grant_hash: string;
  warning_contract_hash: string;
  expected_policy_revision: string;
  tables: SourceConfirmBatchTable[];
} {
  return {
    workspace_revision: workspaceRevision,
    workspace_configuration_hash: workspaceConfigurationHash,
    confirmation_actor_grant_id: grant.grant_id,
    confirmation_actor_grant_revision: grant.grant_revision,
    confirmation_actor_grant_hash: grant.grant_hash,
    warning_contract_hash: warningContractHash,
    expected_policy_revision: expectedPolicyRevision,
    tables: tables.map((table) => ({
      workspace_source_id: table.workspace_source_id,
      source_scope_id: table.source_scope_id,
      source_scope_revision: table.source_scope_revision,
      scope_config_hash: table.scope_config_hash,
    })),
  };
}

export type SourceConfirmBatchOutcome = {
  confirmed_count: number;
  refused_count: number;
  results: Array<{
    source_scope_id: string;
    outcome: "CONFIRMED" | "REFUSED" | string;
    reason_code?: string;
    confirmation_id?: string;
    confirmation_hash?: string;
  }>;
};

// The one operator-facing sentence the batch action reports: how many tables
// were confirmed and, for the refused ones, their closed reason codes. A
// refusal never hides the confirmations that did happen.
export function confirmBatchOutcomeSummary(outcome: SourceConfirmBatchOutcome): string {
  const confirmed = Number.isFinite(outcome.confirmed_count) ? outcome.confirmed_count : 0;
  const refused = outcome.results.filter((row) => row.outcome !== "CONFIRMED");
  const confirmedLabel = `${confirmed} table${confirmed === 1 ? "" : "s"} confirmed`;
  if (refused.length === 0) return `${confirmedLabel}.`;
  const codes = [...new Set(refused.map((row) => row.reason_code ?? "REFUSED"))].sort();
  return `${confirmedLabel}, ${outcome.refused_count} refused (${codes.join(", ")}).`;
}

// These are last-run counters, not the size of the retained corpus. Missing
// measurements remain unknown; a reported zero remains visible as zero.
function processingCount(value: number | null | undefined): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString("en-US") : "no data";
}

function latestProcessingCounts(source: SourceStatus): Array<{ label: string; value: string }> {
  return [
    { label: "Discovered", value: processingCount(source.objects_seen) },
    { label: source.source_type === "POSTGRESQL_QUERY" ? "New objects" : "Processed", value: processingCount(source.objects_ingested) },
    { label: "New versions", value: processingCount(source.versions_created) },
    { label: "Fragments published", value: processingCount(source.evidence_published) },
    { label: "Quarantined", value: processingCount(source.quarantined) },
  ];
}

function sourceRunLabel(status: string | null): string {
  return ({ RUNNING: "running", SUCCEEDED: "completed", FAILED: "failed", CANCELLED: "cancelled" } as Record<string, string>)[status ?? ""] ?? "no confirmed information";
}

function sourceJobLabel(source: SourceStatus): string | null {
  if (!source.job_status) return null;
  const status = ({ PENDING: "Queued", RUNNING: "Running", SUCCEEDED: "Completed", DEAD: "Stopped after failure" } as Record<string, string>)[source.job_status] ?? "Job status unknown";
  const attempts = source.job_attempt_count !== null && source.job_attempt_count !== undefined
    ? ` · ${source.job_status === "RUNNING" ? "attempt" : "attempts"} ${source.job_attempt_count}${source.job_max_attempts !== null && source.job_max_attempts !== undefined ? ` of ${source.job_max_attempts}` : ""}` : "";
  const available = source.job_status === "PENDING" && source.job_available_at ? ` · not before ${formatTime(source.job_available_at)}` : "";
  return `${status}${attempts}${available}`;
}

function sourceProcessingError(source: SourceStatus): string | null {
  const code = source.sync_error_code || (source.job_status !== "SUCCEEDED" ? source.job_last_error_code : null);
  const messages: Record<string, string> = {
    INGEST_PARTIAL_COVERAGE: "Only part of this source was checked. Some materials may be missing from search.",
    INGEST_EMPTY_SCAN_UNCORROBORATED: "This run found no materials. Previously stored data was preserved.",
    INGEST_PARSER_UNAVAILABLE: "The document processing service is unavailable.",
    INGEST_ADAPTER_UNAVAILABLE: "The source connector is unavailable.",
    INGEST_ROOT_UNRESOLVED: "Could not find the connected folder.",
    INGEST_READ: "Could not read the source materials.",
    INGEST_DISCOVER: "Could not list the source materials.",
    INGEST_SEARCH_PROJECTION_PARTIAL: "Some processed materials are missing from search.",
    JOB_LEASE_LOST: "The worker lost its lease to continue this update attempt.",
    TRANSIENT_BACKOFF: "A retry is needed after a temporary error.",
  };
  if (code) return messages[code] ?? "Source processing failed.";
  if (source.sync_status === "FAILED") return "The latest run failed.";
  return source.job_status === "DEAD" ? "The update job stopped after a failure." : null;
}

function LatestProcessingNote({ source }: { source: SourceStatus }) {
  const counts = latestProcessingCounts(source);
  const partialCoverage = (source.quarantined ?? 0) > 0;
  const job = source.job_status === "SUCCEEDED" ? null : sourceJobLabel(source);
  const error = sourceProcessingError(source);
  return (
    <>
      <p className="source-note source-success-time">Last successful update: {source.last_successful_sync_at ? formatTime(source.last_successful_sync_at) : "no information"}</p>
      {job && <p className="source-note source-job-status">Update job: {job}</p>}
      <div className="source-processing">
        <h4>Latest run <span>· {sourceRunLabel(source.sync_status)}</span></h4>
        {(source.sync_started_at || source.sync_completed_at) && <p className="source-note source-run-time">
          {source.sync_started_at ? `Started ${formatTime(source.sync_started_at)}` : "Start time unknown"}
          {source.sync_completed_at ? ` · completed ${formatTime(source.sync_completed_at)}` : ""}
        </p>}
        <dl className="source-run-counts">{counts.map(({ label, value }) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      </div>
      {error && <p className="source-processing-warning" role="status">{error}</p>}
      {partialCoverage && source.sync_error_code !== "INGEST_PARTIAL_COVERAGE" && (
        <p className="source-processing-warning">Some materials were not processed and may be missing from answers.</p>
      )}
      <details className="source-technical">
        <summary>Technical details</summary>
        <dl>
          {source.sync_error_code && <div><dt>Run error</dt><dd className="mono">{source.sync_error_code}</dd></div>}
          {source.job_last_error_code && source.job_last_error_code !== source.sync_error_code && <div><dt>Latest job error</dt><dd className="mono">{source.job_last_error_code}</dd></div>}
          <div><dt>Type</dt><dd className="mono">{source.source_type}</dd></div>
          <div><dt>Connection</dt><dd className="mono">{source.connection_id}</dd></div>
          <div><dt>Source scope</dt><dd className="mono">{source.source_scope_id}</dd></div>
          <div><dt>Run status</dt><dd className="mono">{source.sync_status ?? "no data"}</dd></div>
          <div><dt>Connection status</dt><dd className="mono">{source.confirmation_state}</dd></div>
          <div><dt>Freshness</dt><dd className="mono">{source.freshness_state}</dd></div>
          {source.job_id && <div><dt>Job</dt><dd className="mono">{source.job_id}</dd></div>}
          {source.job_status && <div><dt>Job status</dt><dd className="mono">{source.job_status}</dd></div>}
          {source.job_attempt_count !== null && source.job_attempt_count !== undefined && <div><dt>Job attempts</dt><dd>{processingCount(source.job_attempt_count)}{source.job_max_attempts !== null && source.job_max_attempts !== undefined ? ` of ${processingCount(source.job_max_attempts)}` : ""}</dd></div>}
          {source.job_lease_expires_at && <div><dt>Lease expires</dt><dd>{formatTime(source.job_lease_expires_at)}</dd></div>}
          <div><dt>Update interval</dt><dd>{source.sync_interval_seconds} s</dd></div>
          <div><dt>Freshness allowance</dt><dd>{source.content_freshness_sla_seconds} s</dd></div>
        </dl>
      </details>
    </>
  );
}

// Card S3.2b: the organization OWNER's control over one PostgreSQL source
// connection's SQL query credential (ADR-0097). It accepts only the opaque
// 'cred' reference the server resolves from its mounted credentials; no DSN,
// password or other secret value is entered or returned here. The control is
// rendered by SourceConnectionCard only for an OWNER.
export function SourceQueryCredentialControl({ connectionID, sqlAvailable, busy = false, onSet, onClear }: {
  connectionID: string;
  sqlAvailable: boolean;
  busy?: boolean;
  onSet: (connectionID: string, credentialReference: string) => void;
  onClear: (connectionID: string) => void;
}) {
  const [reference, setReference] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = reference.trim();
    if (trimmed === "" || busy) return;
    onSet(connectionID, trimmed);
  };
  return (
    <form className="source-sql-control" onSubmit={submit}>
      <label className="source-sql-control-field">
        <span>Query credential reference</span>
        <input
          autoComplete="off"
          disabled={busy}
          onChange={(event) => setReference(event.target.value)}
          placeholder="cred_…"
          spellCheck={false}
          value={reference}
        />
      </label>
      <button className="secondary-button" disabled={busy || reference.trim() === ""} type="submit">Save</button>
      {sqlAvailable && (
        <button className="secondary-button" disabled={busy} onClick={() => onClear(connectionID)} type="button">Clear</button>
      )}
    </form>
  );
}

// Card S5.1: the one card a database connection gets in Sources. Its collapsed
// body carries the connection state, the registered/indexed table counts and
// the rolled-up freshness; its expansion lists each registered table with its
// own state, and renderTableExtra keeps the per-table actions reachable, so no
// operator control is lost by folding the rows into one card.
export type SourceConfirmBatchControl = {
  canConfirm: boolean;
  busy: boolean;
  summary: string | null;
  onConfirm: (tables: SourceStatus[]) => void;
};

// Card S5.1: the one card a database connection gets in Sources. Its collapsed
// body carries the connection state, the registered/indexed table counts and
// the rolled-up freshness; its expansion lists each registered table with its
// own state, and renderTableExtra keeps the per-table actions reachable, so no
// operator control is lost by folding the rows into one card.
//
// Card S3.4b adds the bulk confirmation control: when the viewer may confirm
// and the connection still has tables awaiting confirmation, the card offers
// "all schemas" or one schema and confirms every awaiting table in that choice
// with one request. Its outcome summary is rendered next to it.
export function SourceConnectionCard({ group, renderTableExtra, canConfigureSQL = false, sqlControl, confirmBatch }: {
  group: SourceConnectionGroup;
  renderTableExtra?: (source: SourceStatus) => ReactNode;
  canConfigureSQL?: boolean;
  sqlControl?: ReactNode;
  confirmBatch?: SourceConfirmBatchControl;
}) {
  const summary = sourceConnectionSummary(group);
  const [confirmSchema, setConfirmSchema] = useState("");
  const awaiting = sourceTablesAwaitingConfirmation(group);
  const awaitingInSchema = sourceTablesAwaitingConfirmationInSchema(group, confirmSchema);
  return (
    <li className={`source-row source-row-connection source-row-${summary.variant}`}>
      <span className={`dot dot-${summary.variant}`} aria-hidden="true" />
      <div className="source-row-main">
        <div className="source-title-row">
          <b>{summary.connection_name}</b>
          <span className={`state-chip ${summary.variant}`}><span aria-hidden="true" />{summary.state_label}</span>
        </div>
        <p className="source-type">PostgreSQL · {summary.table_count} table{summary.table_count === 1 ? "" : "s"} · {summary.indexed_count} indexed{summary.query_only_count > 0 ? ` · ${summary.query_only_count} only SQL` : ""}</p>
        {summary.query_only ? (
          <p className="source-note source-success-time">No sync freshness: registered only for SQL queries.</p>
        ) : (
          <p className="source-note source-success-time">
            Last successful update: {summary.last_successful_sync_at ? formatTime(summary.last_successful_sync_at) : "no information"}
            {" · "}Freshness: {freshnessStateLabel(summary.freshness_state)}
          </p>
        )}
        <p className="source-note source-sql-availability">
          {summary.sql_available ? "SQL available" : "SQL not configured"}
        </p>
        {canConfigureSQL && sqlControl}
        {confirmBatch?.canConfirm && awaiting.length > 0 && (
          <div className="source-confirm-batch" role="group" aria-label="Confirm tables awaiting confirmation">
            <label className="source-confirm-batch-field">
              <span>Tables awaiting confirmation</span>
              <select
                disabled={confirmBatch.busy}
                onChange={(event) => setConfirmSchema(event.target.value)}
                value={confirmSchema}
              >
                <option value="">All schemas ({awaiting.length})</option>
                {sourceSchemasAwaitingConfirmation(group).map((schema) => (
                  <option key={schema} value={schema}>
                    {schema} ({sourceTablesAwaitingConfirmationInSchema(group, schema).length})
                  </option>
                ))}
              </select>
            </label>
            <button
              className="primary-button source-confirm-batch-action"
              disabled={confirmBatch.busy || awaitingInSchema.length === 0}
              onClick={() => confirmBatch.onConfirm(awaitingInSchema)}
              type="button"
            >
              {confirmBatch.busy ? "Confirming…" : `Confirm all ${awaitingInSchema.length}`}
            </button>
          </div>
        )}
        {confirmBatch?.summary && (
          <p className="source-note source-confirm-batch-summary" role="status">{confirmBatch.summary}</p>
        )}
        <details className="source-connection-tables">
          <summary>Tables ({summary.table_count})</summary>
          <ul className="source-table-rows">
            {group.tables.map((table) => {
              const error = sourceProcessingError(table);
              return (
                <li className="source-table" key={table.source_scope_id}>
                  <div className="source-title-row">
                    <b>{sourceTableLabel(table)}</b>
                    <span className={`state-chip ${sourceCardVariant(table)}`}><span aria-hidden="true" />{sourceHeadline(table)}</span>
                  </div>
                  {table.query_only !== true && (
                    <p className="source-note source-success-time">
                      Last successful update: {table.last_successful_sync_at ? formatTime(table.last_successful_sync_at) : "no information"}
                    </p>
                  )}
                  {table.query_only === true && (
                    <p className="source-note source-success-time">Registered only for SQL queries; rows are not indexed.</p>
                  )}
                  {error && <p className="source-processing-warning" role="status">{error}</p>}
                  {renderTableExtra?.(table)}
                </li>
              );
            })}
          </ul>
        </details>
      </div>
    </li>
  );
}

// Card D-1: one unfinished connection the current workspace started. The row
// shows the server-derived state and offers exactly two actions: continue in
// the wizard, or delete this workspace's draft pointer.
const SourceConnectionDraftLocale = {
  heading: "Unfinished connections",
  hint: "A connection you started but have not added to this workspace yet.",
  state: {
    AWAITING_TRUST_VERIFICATION: "Needs trust verification",
    READY_FOR_DISCOVERY: "Ready to find tables",
  } as Record<string, string>,
  continueLabel: "Continue",
  discardLabel: "Delete",
  discardingLabel: "Deleting…",
  discardConfirm: (name: string): string => `Delete the draft connection “${name}”? It disappears from this workspace; the connection record itself is kept.`,
};

export function sourceConnectionDraftStateLabel(draft: SourceConnectionDraft): string {
  return SourceConnectionDraftLocale.state[draft.state] ?? draft.state;
}

export function SourceConnectionDraftList({ drafts, busyID, canManage = true, onContinue, onDiscard }: {
  drafts: readonly SourceConnectionDraft[];
  busyID: string | null;
  canManage?: boolean;
  onContinue: (draft: SourceConnectionDraft) => void;
  onDiscard: (draft: SourceConnectionDraft) => void;
}) {
  if (drafts.length === 0) return null;
  return (
    <section className="source-drafts" aria-label={SourceConnectionDraftLocale.heading}>
      <h3>{SourceConnectionDraftLocale.heading}</h3>
      <p className="source-drafts-hint">{SourceConnectionDraftLocale.hint}</p>
      <ul className="source-rows">
        {drafts.map((draft) => (
          <li className="source-row source-row-draft" key={draft.connection_id}>
            <span className="dot dot-draft" aria-hidden="true" />
            <div className="source-row-main">
              <div className="source-title-row">
                <b>{draft.connection_name}</b>
                <span className="state-chip draft"><span aria-hidden="true" />{sourceConnectionDraftStateLabel(draft)}</span>
              </div>
              <p className="source-type">PostgreSQL · draft connection</p>
            </div>
            {canManage && (
              <div className="source-row-actions">
                <button className="primary-button source-draft-continue" disabled={busyID !== null} onClick={() => onContinue(draft)} type="button">
                  {SourceConnectionDraftLocale.continueLabel}
                </button>
                <button className="link-button quiet-disable source-draft-discard" disabled={busyID !== null} onClick={() => onDiscard(draft)} type="button">
                  {busyID === draft.connection_id ? SourceConnectionDraftLocale.discardingLabel : SourceConnectionDraftLocale.discardLabel}
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function SourcesView({ state, role, onChanged, pushToast }: {
  state: WorkspaceDataState;
  role: string;
  onChanged: () => void;
  pushToast: (kind: "success" | "error", text: string) => void;
}) {
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [connectType, setConnectType] = useState<SourceRegistrationType | null>(null);
  const [mutatingSourceID, setMutatingSourceID] = useState<string | null>(null);
  // Widened beyond WorkspaceSnapshot (the toggle result) so the sync action's
  // { job_id } result can share the same error-display state: ClosedOrError
  // only ever reads the failure/broken variants, never the ok payload shape.
  const [mutationResult, setMutationResult] = useState<ApiResult<unknown> | null>(null);
  const [verifyingSourceID, setVerifyingSourceID] = useState<string | null>(null);
  const [verifyIdentity, setVerifyIdentity] = useState("");
  const [verifyAttestedBy, setVerifyAttestedBy] = useState("");
  // Card D-1: this workspace's unfinished connections, loaded by their own
  // read route so the sources envelope and the MCP sources projection keep
  // their existing shape. draftsVersion forces a re-read after a discard.
  const [draftsResult, setDraftsResult] = useState<ApiResult<SourceConnectionDraftEnvelope> | null>(null);
  const [draftsVersion, setDraftsVersion] = useState(0);
  const [draftBusyID, setDraftBusyID] = useState<string | null>(null);
  // Card S3.2b: the connection whose SQL credential control is mid-request.
  const [sqlCredentialBusyID, setSqlCredentialBusyID] = useState<string | null>(null);
  // Card S3.4b: the connection whose bulk confirmation is mid-request, and the
  // one outcome summary that connection last reported.
  const [confirmBatchBusyID, setConfirmBatchBusyID] = useState<string | null>(null);
  const [confirmBatchSummary, setConfirmBatchSummary] = useState<{ connectionID: string; text: string } | null>(null);
  const [continuedDraft, setContinuedDraft] = useState<SourceConnectionDraft | null>(null);
  const snapshot = state.phase === "loaded" && state.snapshot.kind === "ok" ? state.snapshot.value : null;
  const etag = state.phase === "loaded" && state.snapshot.kind === "ok" ? state.snapshot.etag : undefined;
  const confirmationContext = state.phase === "loaded" && state.sources.kind === "ok" ? state.sources.value.confirmation_context : null;
  const canManage = role === "OWNER" || role === "MANAGER";
  const workspaceID = snapshot?.id ?? null;

  useEffect(() => {
    if (workspaceID === null) {
      setDraftsResult(null);
      return;
    }
    let alive = true;
    void apiGet<SourceConnectionDraftEnvelope>(`/api/v1/workspaces/${encodeURIComponent(workspaceID)}/source-drafts`).then((result) => {
      if (alive) setDraftsResult(result);
    });
    return () => { alive = false; };
  }, [workspaceID, draftsVersion]);
  const drafts = draftsResult?.kind === "ok" ? draftsResult.value.drafts : [];

  // Card D-1: discarding deletes only this workspace's draft pointer. The
  // server keeps the immutable connection lineage, so the action is safe to
  // retry and never targets another workspace.
  async function discardDraft(draft: SourceConnectionDraft) {
    if (snapshot === null || draftBusyID !== null) return;
    if (!window.confirm(SourceConnectionDraftLocale.discardConfirm(draft.connection_name))) return;
    setDraftBusyID(draft.connection_id);
    setMutationResult(null);
    const result = await apiDeleteAction<{ connection_id: string; discarded: boolean }>(
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/source-drafts/${encodeURIComponent(draft.connection_id)}`,
      newIdempotencyKey(),
    );
    setDraftBusyID(null);
    if (result.kind === "ok") {
      pushToast("success", `Draft connection “${draft.connection_name}” deleted.`);
      setDraftsVersion((current) => current + 1);
    } else {
      setMutationResult(result);
      pushToast("error", closedText(result));
    }
  }

  // Card S3.2b: the OWNER sets or clears one connection's opaque SQL query
  // credential reference. The request carries only the reference the server
  // resolves from its mounted credentials; a DSN or a password is never sent.
  // The server validates the reference against the source's database identity
  // and its excluded columns before anything changes, so a failed check is one
  // closed code and no change.
  async function setSourceQueryCredential(connectionID: string, credentialReference: string) {
    if (!snapshot || sqlCredentialBusyID !== null) return;
    setSqlCredentialBusyID(connectionID);
    setMutationResult(null);
    const result = await apiPost<{ connection_id: string; sql_available: boolean }>(
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/source-connections/${encodeURIComponent(connectionID)}:set-query-credential`,
      { credential_reference: credentialReference },
      newIdempotencyKey(),
    );
    setSqlCredentialBusyID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", "SQL query credential updated.");
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  async function clearSourceQueryCredential(connectionID: string) {
    if (!snapshot || sqlCredentialBusyID !== null) return;
    setSqlCredentialBusyID(connectionID);
    setMutationResult(null);
    const result = await apiPost<{ connection_id: string; sql_available: boolean }>(
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/source-connections/${encodeURIComponent(connectionID)}:clear-query-credential`,
      {},
      newIdempotencyKey(),
    );
    setSqlCredentialBusyID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", "SQL query credential cleared.");
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  // ADR-0087 §1: the caller's live workspace.source.confirm grant, or a freshly
  // issued self-targeted one when the caller is an organization OWNER/ADMIN.
  // A freshly issued grant always starts at revision 1 (the repository never
  // issues any other starting revision), so it can be chained into the confirm
  // call without a second read. Both confirmation actions -- one table and a
  // whole batch -- reuse this one grant path, so they cannot diverge.
  async function ensureConfirmationGrant(): Promise<SelfConfirmationGrant | null> {
    if (!snapshot || !etag || !confirmationContext) return null;
    if (confirmationContext.self_grant) return confirmationContext.self_grant;
    if (!confirmationContext.can_issue_confirmation_grant) {
      setMutationResult({ kind: "failure", status: 403, code: "CONFIRMATION_GRANT_REQUIRES_ORG_OWNER_OR_ADMIN", requestId: "" });
      pushToast("error", "Only an organization owner or administrator can issue a confirmation grant.");
      return null;
    }
    const configurationHash = etag.replace(/^"|"$/g, "");
    const issue = await apiPost<{ result_id: string; result_hash: string }>(
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/confirmation-grants`,
      {
        expected_workspace_revision: snapshot.revision,
        expected_workspace_configuration_hash: configurationHash,
        target_principal_id: confirmationContext.viewer_principal_id,
        ttl_seconds: 3600,
        expected_policy_revision: confirmationContext.expected_policy_revision,
      },
      newIdempotencyKey(),
    );
    if (issue.kind !== "ok") {
      setMutationResult(issue);
      pushToast("error", closedText(issue));
      return null;
    }
    return { grant_id: issue.value.result_id, grant_revision: 1, grant_hash: issue.value.result_hash, valid_until: "" };
  }

  // ADR-0087 §1: confirm a pending WORKSPACE_MANAGED binding. If the caller
  // already holds a live workspace.source.confirm grant (confirmationContext.
  // self_grant) it is reused as-is; otherwise, if the caller is an
  // organization OWNER/ADMIN, a fresh self-targeted grant is issued first.
  async function confirmSource(source: SourceStatus) {
    if (!snapshot || !etag || mutatingSourceID !== null || !confirmationContext) return;
    if (!window.confirm(
      "By confirming this managed source, you agree that workspace members can access discovered " +
      "fragments without the source's native ACLs (" + confirmationContext.warning_contract.warning_version + "). Continue?",
    )) return;
    setMutatingSourceID(source.source_scope_id);
    setMutationResult(null);
    const configurationHash = etag.replace(/^"|"$/g, "");
    const grant = await ensureConfirmationGrant();
    if (!grant) {
      setMutatingSourceID(null);
      return;
    }
    const confirmation = await apiPost<unknown>(
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/managed-source-confirmations`,
      {
        workspace_revision: snapshot.revision,
        workspace_configuration_hash: configurationHash,
        workspace_source_id: source.workspace_source_id,
        source_scope_id: source.source_scope_id,
        source_scope_revision: source.source_scope_revision,
        scope_config_hash: source.scope_config_hash,
        confirmation_actor_grant_id: grant.grant_id,
        confirmation_actor_grant_revision: grant.grant_revision,
        confirmation_actor_grant_hash: grant.grant_hash,
        warning_contract_hash: confirmationContext.warning_contract.warning_contract_hash,
        expected_policy_revision: confirmationContext.expected_policy_revision,
      },
      newIdempotencyKey(),
    );
    setMutatingSourceID(null);
    setMutationResult(confirmation);
    if (confirmation.kind === "ok") {
      pushToast("success", `Source “${sourceLabel(source)}” confirmed.`);
      onChanged();
    } else {
      pushToast("error", closedText(confirmation));
    }
  }

  // Card S3.4b: confirm every selected table of one connection in one request.
  // The server confirms each table through the unchanged individual command and
  // returns one closed per-table outcome, so a refusal never hides the
  // confirmations that did happen. One grant is issued for the whole batch.
  async function confirmTableBatch(connectionID: string, tables: SourceStatus[]) {
    if (!snapshot || !etag || confirmBatchBusyID !== null || !confirmationContext || tables.length === 0) return;
    if (!window.confirm(
      `Confirm access to ${tables.length} table${tables.length === 1 ? "" : "s"}? ` +
      "Workspace members can then access their fragments without the source's native ACLs (" +
      confirmationContext.warning_contract.warning_version + "). Continue?",
    )) return;
    setConfirmBatchBusyID(connectionID);
    setMutationResult(null);
    const configurationHash = etag.replace(/^"|"$/g, "");
    const grant = await ensureConfirmationGrant();
    if (!grant) {
      setConfirmBatchBusyID(null);
      return;
    }
    const result = await apiPost<SourceConfirmBatchOutcome>(
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/managed-source-confirmations:batch`,
      confirmBatchRequestBody(
        tables, snapshot.revision, configurationHash, grant,
        confirmationContext.warning_contract.warning_contract_hash, confirmationContext.expected_policy_revision,
      ),
      newIdempotencyKey(),
    );
    setConfirmBatchBusyID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      const summary = confirmBatchOutcomeSummary(result.value);
      setConfirmBatchSummary({ connectionID, text: summary });
      pushToast("success", summary);
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  // ADR-0087 §1: requests activation of a source already confirmed and
  // trust-verified. Same POST /api/v1/sources/{scope}:activate the
  // registration dialog already calls; here it is reachable again once the
  // gap it used to fail on (no confirm/trust route) is closed.
  async function activateSource(source: SourceStatus) {
    if (mutatingSourceID !== null) return;
    setMutatingSourceID(source.source_scope_id);
    setMutationResult(null);
    const result = await apiAction<{ job_id: string }>(
      `/api/v1/sources/${encodeURIComponent(source.source_scope_id)}:activate`,
      newIdempotencyKey(),
    );
    setMutatingSourceID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", `Source “${sourceLabel(source)}” queued for activation.`);
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  // ADR-0087 §2: CONNECTOR_ADMIN-gated DRAFT->VERIFIED transition. The
  // operator supplies only the mandatory attestation; organization,
  // idempotency and the SECURITY DEFINER door stay server-side.
  async function verifyTrust(source: SourceStatus) {
    if (mutatingSourceID !== null || !verifyIdentity.trim() || !verifyAttestedBy.trim()) return;
    setMutatingSourceID(source.source_scope_id);
    setMutationResult(null);
    const result = await apiPost<{ result_id: string; result_hash: string }>(
      `/api/v1/sources/connections/${encodeURIComponent(source.connection_id)}:verify-trust`,
      {
        attested_connector_identity: verifyIdentity.trim(),
        attested_by: verifyAttestedBy.trim(),
        attested_at: new Date().toISOString(),
      },
      newIdempotencyKey(),
    );
    setMutatingSourceID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      setVerifyingSourceID(null);
      setVerifyIdentity("");
      setVerifyAttestedBy("");
      pushToast("success", `Trust verified for “${sourceLabel(source)}”.`);
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  async function toggleSource(source: SourceStatus) {
    if (!snapshot || !etag || mutatingSourceID !== null || !source.workspace_source_id) return;
    setMutatingSourceID(source.source_scope_id);
    setMutationResult(null);
    const baseBody = {
      expected_workspace_revision: snapshot.revision,
      source_scope_id: source.source_scope_id,
      source_scope_revision: source.source_scope_revision,
      scope_config_hash: source.scope_config_hash,
      access_mode: source.access_mode,
    };
    const result = source.enabled
      ? await apiMutation<WorkspaceSnapshot>(
        "DELETE",
        `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/sources/${encodeURIComponent(source.source_scope_id)}`,
        { ...baseBody, workspace_source_id: source.workspace_source_id },
        newIdempotencyKey(),
        etag,
      )
      : await apiMutation<WorkspaceSnapshot>(
        "POST",
        `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/sources`,
        baseBody,
        newIdempotencyKey(),
        etag,
      );
    setMutatingSourceID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", source.enabled ? `“${sourceLabel(source)}” disabled.` : `“${sourceLabel(source)}” enabled.`);
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  // Refreshes an already-activated source scope (ADR-0087 §3): the same
  // POST /api/v1/sources/{scope}:sync action a stale-source operator or an
  // MCP agent can call, wired here to the "Refresh" control so freshness is
  // an operator-visible action, not only a stalled field on the card.
  async function syncSource(source: SourceStatus) {
    if (mutatingSourceID !== null) return;
    setMutatingSourceID(source.source_scope_id);
    setMutationResult(null);
    const result = await apiAction<{ job_id: string }>(
      `/api/v1/sources/${encodeURIComponent(source.source_scope_id)}:sync`,
      newIdempotencyKey(),
    );
    setMutatingSourceID(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", `Update queued for “${sourceLabel(source)}”.`);
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  // One action per row (task contract: confirm / verify trust /
  // activate / refresh / enable / disable), never several primary
  // buttons competing for the same row. "Disable" is the one exception --
  // it is always reachable but rendered as a quiet link, never as a second
  // button next to "Refresh".
  function renderPrimaryAction(source: SourceStatus) {
    if (canManage && snapshot && etag && confirmationContext &&
      (source.confirmation_state === "NEEDS_GRANT" || source.confirmation_state === "NEEDS_CONFIRMATION")) {
      return (
        <button
          className="primary-button source-confirm"
          disabled={mutatingSourceID !== null || (source.confirmation_state === "NEEDS_GRANT" && !confirmationContext.can_issue_confirmation_grant)}
          onClick={() => void confirmSource(source)}
          type="button"
        >
          {mutatingSourceID === source.source_scope_id ? "Saving…" : "Confirm"}
        </button>
      );
    }
    if (source.can_verify_connection_trust && source.confirmation_state === "NEEDS_TRUST_VERIFICATION" && verifyingSourceID !== source.source_scope_id) {
      return (
        <button
          className="primary-button source-verify-trust"
          disabled={mutatingSourceID !== null}
          onClick={() => { setVerifyingSourceID(source.source_scope_id); setVerifyIdentity(""); setVerifyAttestedBy(""); }}
          type="button"
        >
          Verify trust
        </button>
      );
    }
    if (canManage && source.confirmation_state === "READY_TO_ACTIVATE") {
      return (
        <button className="primary-button source-activate" disabled={mutatingSourceID !== null} onClick={() => void activateSource(source)} type="button">
          {mutatingSourceID === source.source_scope_id ? "Queuing…" : "Activate"}
        </button>
      );
    }
    if (canManage && snapshot && etag && !source.enabled && source.workspace_source_id) {
      return (
        <button className="primary-button source-toggle" disabled={mutatingSourceID !== null} onClick={() => void toggleSource(source)} type="button">
          {mutatingSourceID === source.source_scope_id ? "Saving…" : "Enable"}
        </button>
      );
    }
    if (canManage && snapshot && etag && source.enabled && source.confirmation_state === "ACTIVE") {
      return (
        <button className="secondary-button source-sync" disabled={mutatingSourceID !== null} onClick={() => void syncSource(source)} type="button">
          {mutatingSourceID === source.source_scope_id ? "Saving…" : "Refresh"}
        </button>
      );
    }
    return null;
  }

  // The inline attestation form and the one primary action per row are shared
  // by the document rows and by each table row inside a connection card, so
  // folding a connection into one card never removes an operator control.
  function renderVerifyForm(source: SourceStatus) {
    if (verifyingSourceID !== source.source_scope_id) return null;
    return (
      <div className="verify-trust-form">
        <label className="field"><span>Connector identity</span><input maxLength={512} onChange={(event) => setVerifyIdentity(event.target.value)} value={verifyIdentity} /></label>
        <label className="field"><span>Verified by</span><input maxLength={256} onChange={(event) => setVerifyAttestedBy(event.target.value)} value={verifyAttestedBy} /></label>
        <div className="verify-trust-actions">
          <button className="secondary-button" disabled={mutatingSourceID !== null} onClick={() => { setVerifyingSourceID(null); setVerifyIdentity(""); setVerifyAttestedBy(""); }} type="button">Cancel</button>
          <button className="primary-button" disabled={mutatingSourceID !== null || !verifyIdentity.trim() || !verifyAttestedBy.trim()} onClick={() => void verifyTrust(source)} type="button">
            {mutatingSourceID === source.source_scope_id ? "Checking…" : "Confirm verification"}
          </button>
        </div>
      </div>
    );
  }

  function renderRowActions(source: SourceStatus) {
    return (
      <div className="source-row-actions">
        {renderPrimaryAction(source)}
        {canManage && snapshot && etag && source.workspace_source_id && source.confirmation_state === "ACTIVE" && (
          <button className="link-button quiet-disable" disabled={mutatingSourceID !== null} onClick={() => void toggleSource(source)} type="button">Disable</button>
        )}
      </div>
    );
  }

  // The per-table body a connection card expands to: the blocked note, the
  // attestation form and the row actions each table row carried when every
  // table was its own card.
  function renderTableExtra(source: SourceStatus): ReactNode {
    return (
      <>
        {sourceBlockedNote(source, canManage, confirmationContext) && (
          <p className="source-note">{sourceBlockedNote(source, canManage, confirmationContext)}</p>
        )}
        {renderVerifyForm(source)}
        {renderRowActions(source)}
      </>
    );
  }

  const loadedSources = state.phase === "loaded" && state.sources.kind === "ok" ? state.sources.value.sources : null;
  const activeSources = loadedSources?.filter((source) => source.enabled) ?? [];
  const disabledSources = loadedSources?.filter((source) => !source.enabled) ?? [];
  // Card S5.1: one entry per PostgreSQL connection, one per document source.
  const cardEntries = sourceCardEntries(activeSources);
  const attentionCount = cardEntries.filter((entry) => entry.kind === "connection"
    ? sourceConnectionSummary(entry.group).variant === "attention"
    : sourceCardVariant(entry.source) === "attention").length;
  return (
    <div className="page sources-page">
      <section className="page-intro split-intro">
        <div>
          {loadedSources && <dl className="sources-summary" aria-label="Source summary">
            <div><dt>Sources</dt><dd>{cardEntries.length + disabledSources.length}</dd></div>
            <div className={attentionCount > 0 ? "sources-summary-attention" : undefined}><dt>Need attention</dt><dd>{attentionCount}</dd></div>
            {disabledSources.length > 0 && <div><dt>Disabled</dt><dd>{disabledSources.length}</dd></div>}
          </dl>}
          <p className="source-volume">Stored data volume: not measured.</p>
        </div>
        {canManage && snapshot && etag && (
          <button className="primary-button" onClick={() => setCatalogOpen(true)} type="button">Connect source</button>
        )}
      </section>

      {drafts.length > 0 && (
        <SourceConnectionDraftList
          busyID={draftBusyID}
          canManage={canManage}
          drafts={drafts}
          onContinue={(draft) => setContinuedDraft(draft)}
          onDiscard={(draft) => void discardDraft(draft)}
        />
      )}

      {state.phase === "idle" && <p className="evidence-state">Select a workspace.</p>}
      {state.phase === "loading" && <p className="evidence-state">Loading sources…</p>}
      {state.phase === "loaded" && state.sources.kind === "ok" && (
        state.sources.value.sources.length === 0 ? (
          <div className="empty-runs">
            <span className="empty-symbol" aria-hidden="true"><IconSources /></span>
            <div>
              <strong>No sources connected yet.</strong>
              <p>{canManage ? "Connect a folder, PostgreSQL or a Git repository." : "Ask a workspace owner or manager to connect a source."}</p>
            </div>
          </div>
        ) : (
          <>
            <ul className="source-rows">
              {cardEntries.map((entry) => entry.kind === "connection" ? (
                <SourceConnectionCard
                  canConfigureSQL={role === "OWNER"}
                  confirmBatch={{
                    canConfirm: Boolean(canManage && snapshot && etag && confirmationContext),
                    busy: confirmBatchBusyID === entry.group.connection_id,
                    summary: confirmBatchSummary?.connectionID === entry.group.connection_id ? confirmBatchSummary.text : null,
                    onConfirm: (tables) => void confirmTableBatch(entry.group.connection_id, tables),
                  }}
                  group={entry.group}
                  key={entry.key}
                  renderTableExtra={(source) => renderTableExtra(source)}
                  sqlControl={
                    <SourceQueryCredentialControl
                      busy={sqlCredentialBusyID === entry.group.connection_id}
                      connectionID={entry.group.connection_id}
                      onClear={(connectionID) => void clearSourceQueryCredential(connectionID)}
                      onSet={(connectionID, reference) => void setSourceQueryCredential(connectionID, reference)}
                      sqlAvailable={entry.group.tables.some((table) => table.sql_available === true)}
                    />
                  }
                />
              ) : (
                <li className={`source-row source-row-${sourceCardVariant(entry.source)}`} key={entry.key}>
                  <span className={`dot dot-${sourceCardVariant(entry.source)}`} aria-hidden="true" />
                  <div className="source-row-main">
                    <div className="source-title-row">
                      <b>{sourceLabel(entry.source)}</b>
                      <span className={`state-chip ${sourceCardVariant(entry.source)}`}><span aria-hidden="true" />{sourceHeadline(entry.source)}</span>
                    </div>
                    <p className="source-type">{sourceTypeLabel(entry.source)}</p>
                    <LatestProcessingNote source={entry.source} />
                    {sourceBlockedNote(entry.source, canManage, confirmationContext) && (
                      <p className="source-note">{sourceBlockedNote(entry.source, canManage, confirmationContext)}</p>
                    )}
                    {renderVerifyForm(entry.source)}
                  </div>
                  {renderRowActions(entry.source)}
                </li>
              ))}
            </ul>

            {disabledSources.length > 0 && (
              <details className="disabled-sources">
                <summary>Disabled ({disabledSources.length})</summary>
                <ul className="source-rows">
                  {disabledSources.map((source) => (
                    <li className="source-row source-row-disconnected" key={source.source_scope_id}>
                      <span className="dot dot-disconnected" aria-hidden="true" />
                      <div className="source-row-main">
                        <div className="source-title-row">
                          <b>{sourceLabel(source)}</b>
                          <span className="state-chip disconnected"><span aria-hidden="true" />Disabled</span>
                        </div>
                        <p className="source-type">{sourceTypeLabel(source)}</p>
                        <LatestProcessingNote source={source} />
                      </div>
                      <div className="source-row-actions">{renderPrimaryAction(source)}</div>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </>
        )
      )}
      {state.phase === "loaded" && state.sources.kind !== "ok" && <ClosedOrError result={state.sources} />}
      {mutationResult && mutationResult.kind !== "ok" && <ClosedOrError result={mutationResult} />}

      <details className="source-access-note">
        <summary>Source access rules</summary>
        <p>A workspace does not grant new rights to source data. Access is confirmed separately for each source and its readers. Adding a source requires permission from an organization administrator.</p>
      </details>

      {catalogOpen && connectType === null && (
        <ConnectorCatalogDialog
          onClose={() => setCatalogOpen(false)}
          onPick={(type) => setConnectType(type)}
        />
      )}
      {catalogOpen && connectType !== null && snapshot && etag && (
        <SourceRegistrationDialog
          connectorType={connectType}
          etag={etag}
          onBack={() => setConnectType(null)}
          onClose={() => { setCatalogOpen(false); setConnectType(null); }}
          onCompleted={(message) => { setCatalogOpen(false); setConnectType(null); onChanged(); if (message) pushToast("success", message); }}
          snapshot={snapshot}
        />
      )}
      {continuedDraft && snapshot && etag && (
        <PostgreSQLOnboardingDialog
          etag={etag}
          initialDraft={continuedDraft}
          onBack={() => setContinuedDraft(null)}
          onClose={() => setContinuedDraft(null)}
          onCompleted={(message) => { setContinuedDraft(null); setDraftsVersion((current) => current + 1); onChanged(); if (message) pushToast("success", message); }}
          snapshot={snapshot}
        />
      )}
    </div>
  );
}

type SourceRegistrationType = "FOLDER" | "POSTGRESQL_QUERY" | "GIT";

function splitCommaList(value: string): string[] {
  return Array.from(new Set(value.split(",").map((item) => item.trim()).filter(Boolean)));
}

// ---------------------------------------------------------------------------
// UI-4: connector catalogue + per-type connect screens. Ergonomics copied
// from the approved connectors.html reference (grouped/searchable type catalogue,
// one connect screen per type split fields|schedule, a separate credentials
// step); content is limited to what internal/source/registration/service.go
// and api/openapi.yaml actually accept -- see knowvault-ui-api-map.md.
// Browser file upload (UPL-1) is intentionally not offered here any more
// (product decision): the server route stays, nothing in web/src calls it.
// ---------------------------------------------------------------------------

type CatalogEntry = { id: string; name: string; blurb: string; registrationType?: SourceRegistrationType };
type CatalogGroup = { heading: string; items: CatalogEntry[] };

// Only FOLDER, POSTGRESQL_QUERY and GIT are wired end to end today. Every
// other entry describes a possible source type and is unavailable for connection.
const CATALOG_GROUPS: CatalogGroup[] = [
  {
    heading: "Files and code",
    items: [
      { id: "folder", name: "Server folder", blurb: "A server directory with contracts, policies and reports.", registrationType: "FOLDER" },
      { id: "git", name: "Git repository", blurb: "Source code, README files and technical documentation.", registrationType: "GIT" },
      { id: "sharepoint", name: "SharePoint", blurb: "Document libraries and department sites." },
      { id: "s3", name: "S3 / object storage", blurb: "Buckets containing archives, exports and scans." },
      { id: "smb", name: "Network drive (SMB)", blurb: "A shared company folder accessible over the network." },
    ],
  },
  {
    heading: "Databases",
    items: [
      { id: "postgres", name: "PostgreSQL", blurb: "Tables and views from an operational database.", registrationType: "POSTGRESQL_QUERY" },
      { id: "mssql", name: "MS SQL Server", blurb: "Business and billing databases on Microsoft SQL." },
      { id: "oracle", name: "Oracle Database", blurb: "Enterprise databases, views and queries." },
      { id: "mysql", name: "MySQL / MariaDB", blurb: "Databases behind websites, portals and internal services." },
    ],
  },
  {
    heading: "Business systems",
    items: [
      { id: "1c", name: "1C:Enterprise", blurb: "Catalogs, documents and registers from a 1C database." },
      { id: "b24", name: "Bitrix24", blurb: "Deals, tasks and company records from your portal." },
    ],
  },
  {
    heading: "Email and messaging",
    items: [
      { id: "mail", name: "Mailbox", blurb: "Requests, complaints and correspondence from a company mailbox." },
      { id: "tg", name: "Telegram", blurb: "Messages and attachments from channels and chats." },
    ],
  },
  {
    heading: "Web and applications",
    items: [
      { id: "site", name: "Website / pages", blurb: "Public pages with pricing, news and guidance." },
      { id: "api", name: "Application REST API", blurb: "Data from another application through its API." },
      { id: "tickets", name: "Tasks and tickets", blurb: "Issues and resolutions from Jira, YouTrack or GitLab." },
    ],
  },
];

function catalogGroupIcon(heading: string): ComponentType {
  switch (heading) {
    case "Databases":
      return IconTable;
    case "Business systems":
      return IconAccess;
    case "Email and messaging":
      return IconJournal;
    case "Web and applications":
      return IconShield;
    default:
      return IconDocument;
  }
}

// An unavailable catalog tile only opens an availability notice. It makes no
// server request, accepts no subscription and promises no delivery date.
function ComingSoonDialog({ name, onClose }: { name: string; onClose: () => void }) {
  const dialogRef = useModalDialog(onClose);
  return (
    <div className="sheet-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }} role="presentation">
      <section aria-labelledby="soon-title" aria-modal="true" className="soon-dialog" ref={dialogRef} role="dialog" tabIndex={-1}>
        <header className="sheet-header">
          <div>
            <p className="eyebrow">Connector unavailable</p>
            <h2 id="soon-title">{name}</h2>
          </div>
          <button aria-label="Close" className="close-button" onClick={onClose} type="button">×</button>
        </header>
        <div className="soon-body">
          <p>This source type is not available in this release. Choose an available connector from the catalog.</p>
        </div>
        <footer className="sheet-footer">
          <button className="primary-button" onClick={onClose} type="button">Close</button>
        </footer>
      </section>
    </div>
  );
}

function ConnectorCatalogDialog({ onClose, onPick }: { onClose: () => void; onPick: (type: SourceRegistrationType) => void }) {
  const [query, setQuery] = useState("");
  const [soon, setSoon] = useState<string | null>(null);
  const dialogRef = useModalDialog(onClose);
  const needle = query.trim().toLowerCase();
  const groups = CATALOG_GROUPS
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => !needle || item.name.toLowerCase().includes(needle) || item.blurb.toLowerCase().includes(needle)),
    }))
    .filter((group) => group.items.length > 0);
  const availableCount = CATALOG_GROUPS.reduce((sum, group) => sum + group.items.filter((item) => item.registrationType).length, 0);
  const soonCount = CATALOG_GROUPS.reduce((sum, group) => sum + group.items.filter((item) => !item.registrationType).length, 0);

  return (
    <div className="sheet-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }} role="presentation">
      <section aria-labelledby="catalog-title" aria-modal="true" className="source-sheet catalog-sheet" ref={dialogRef} role="dialog" tabIndex={-1}>
        <header className="sheet-header">
          <div>
            <p className="eyebrow">Connect data</p>
            <h2 id="catalog-title">Connect source</h2>
            <p className="sheet-description">Choose the type of source you want to connect.</p>
          </div>
          <button aria-label="Close" className="close-button" onClick={onClose} type="button">×</button>
        </header>
        <div className="catalog-search">
          <input aria-label="Find source type" onChange={(event) => setQuery(event.target.value)} placeholder="Find a type: database, email, folder…" type="text" value={query} />
        </div>
        <div className="catalog-body">
          {groups.length === 0 && <p className="evidence-state">No matches. Try another term.</p>}
          {groups.map((group) => {
            const Icon = catalogGroupIcon(group.heading);
            return (
              <section className="catalog-group" key={group.heading}>
                <h3>{group.heading}</h3>
                <div className="catalog-grid">
                  {group.items.map((item) => (
                    <button
                      className={item.registrationType ? "catalog-tile" : "catalog-tile catalog-tile-soon"}
                      key={item.id}
                      onClick={() => (item.registrationType ? onPick(item.registrationType) : setSoon(item.name))}
                      type="button"
                    >
                      <span className="catalog-tile-icon" aria-hidden="true"><Icon /></span>
                      <span className="catalog-tile-body">
                        <b>{item.name}{!item.registrationType && <em className="soon-chip">unavailable</em>}</b>
                        <span>{item.blurb}</span>
                      </span>
                    </button>
                  ))}
                </div>
              </section>
            );
          })}
          <p className="catalog-foot">Available now: {availableCount}. The other {soonCount} source types are listed for reference and cannot be connected yet.</p>
        </div>
      </section>
      {soon && <ComingSoonDialog name={soon} onClose={() => setSoon(null)} />}
    </div>
  );
}

const FORMAT_OPTIONS: { value: string; label: string }[] = [
  { value: "PDF", label: "PDF" },
  { value: "DOCX", label: "Word (DOCX)" },
  { value: "PPTX", label: "PowerPoint (PPTX)" },
  { value: "XLSX", label: "Excel (XLSX)" },
  { value: "CSV", label: "Tables (CSV)" },
  { value: "TXT", label: "Text files" },
  { value: "MARKDOWN", label: "Markdown" },
  { value: "HTML", label: "Web pages (HTML)" },
  { value: "JSON", label: "JSON" },
  { value: "XML", label: "XML" },
  { value: "EML", label: "Email (EML)" },
  { value: "SOURCE_CODE", label: "Source code" },
  { value: "PNG", label: "Images (PNG)" },
  { value: "JPEG", label: "Images (JPEG)" },
];

function SourceRegistrationDialog(props: {
  connectorType: SourceRegistrationType;
  snapshot: WorkspaceSnapshot;
  etag: string;
  onBack: () => void;
  onClose: () => void;
  onCompleted: (message?: string) => void;
}) {
  if (props.connectorType === "POSTGRESQL_QUERY") {
    return <PostgreSQLOnboardingDialog {...props} />;
  }
  return <LegacySourceRegistrationDialog {...props} connectorType={props.connectorType} />;
}

function LegacySourceRegistrationDialog({ connectorType, snapshot, etag, onBack, onClose, onCompleted }: {
  connectorType: "FOLDER" | "GIT";
  snapshot: WorkspaceSnapshot;
  etag: string;
  onBack: () => void;
  onClose: () => void;
  onCompleted: () => void;
}) {
  const [view, setView] = useState<"fields" | "credentials">("fields");
  const [name, setName] = useState("");

  const [rootAlias, setRootAlias] = useState("");
  const [rootIdentity, setRootIdentity] = useState("");
  const [relativeRoot, setRelativeRoot] = useState("");
  const [recursive, setRecursive] = useState(true);
  const [ocrEnabled, setOcrEnabled] = useState(false);
  const [formats, setFormats] = useState<string[]>(["PDF", "DOCX", "XLSX", "TXT", "MARKDOWN", "HTML", "CSV"]);

  const [gitProvider, setGitProvider] = useState("GITHUB");
  const [gitEndpoint, setGitEndpoint] = useState("https://api.github.com");
  const [gitWebBaseURL, setGitWebBaseURL] = useState("https://github.com");
  const [gitRepositoryID, setGitRepositoryID] = useState("");
  const [gitBranchName, setGitBranchName] = useState("main");
  const [gitIncludeGlobs, setGitIncludeGlobs] = useState("**/*");
  const [gitExcludeGlobs, setGitExcludeGlobs] = useState(".git/**,vendor/**,node_modules/**");
  const [gitTextMediaTypes, setGitTextMediaTypes] = useState("text/plain,text/markdown,text/html,application/json,application/xml,application/javascript,text/x-go,text/x-rust,text/x-java-source");
  const [gitMaxBlobBytes, setGitMaxBlobBytes] = useState("1048576");

  // Credentials step: entered separately from connection fields. The value is
  // an opaque already-issued reference, never a password, so there is no
  // "enter secret" flow to build.
  const [credentialReference, setCredentialReference] = useState("");

  const [stage, setStage] = useState<"idle" | "registering" | "binding" | "activating" | "done">("idle");
  const [result, setResult] = useState<ApiResult<unknown> | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const busy = stage !== "idle" && stage !== "done";
  const dialogRef = useModalDialog(onClose, busy);
  const hasCredentialStep = connectorType === "GIT";
  const typeName = connectorType === "FOLDER" ? "Server folder" : "Git repository";

  function toggleFormat(value: string) {
    setFormats((current) => (current.includes(value) ? current.filter((item) => item !== value) : [...current, value]));
  }
  // Retries a workspace-scoped mutation once against a freshly re-fetched
  // snapshot when the server answers a revision conflict.
  async function withRevisionRetry<T>(
    run: (workspaceEtag: string, workspaceRevision: number) => Promise<ApiResult<T>>,
  ): Promise<ApiResult<T>> {
    const first = await run(etag, snapshot.revision);
    if (first.kind !== "failure" || (first.code !== "WORKSPACE_REVISION_CONFLICT" && first.code !== "CONFLICT")) return first;
    const refreshed = await apiGet<WorkspaceSnapshot>(`/api/v1/workspaces/${encodeURIComponent(snapshot.id)}`);
    if (refreshed.kind !== "ok" || !refreshed.etag) return first;
    return run(refreshed.etag, refreshed.value.revision);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || stage === "done") return;
    setResult(null);
    setFormError(null);

    if (!name.trim()) {
      setFormError("A name is required.");
      return;
    }

    let body: Record<string, unknown>;
    if (connectorType === "FOLDER") {
      if (!rootAlias.trim() || !rootIdentity.trim() || !relativeRoot.trim()) {
        setFormError("Complete all connection fields.");
        return;
      }
      if (formats.length === 0) {
        setFormError("Select at least one file type.");
        return;
      }
      body = {
        name: name.trim(), root_alias: rootAlias.trim(), root_identity: rootIdentity.trim(), relative_root: relativeRoot.trim(),
        kind: "documents", recursive, include_globs: ["**/*"], exclude_globs: [],
        max_file_bytes: 104857600, ocr_mode: ocrEnabled ? "AUTO" : "OFF", formats,
      };
    } else {
      if (!gitRepositoryID.trim() || !gitBranchName.trim() || !gitEndpoint.trim()) {
        setFormError("Complete all connection fields.");
        return;
      }
      const parsedMaxBlobBytes = Number.parseInt(gitMaxBlobBytes, 10);
      if (!Number.isSafeInteger(parsedMaxBlobBytes) || parsedMaxBlobBytes < 1) {
        setFormError("The maximum repository file size must be a positive integer.");
        return;
      }
      body = {
        source_type: "GIT", name: name.trim(), kind: "repository", provider: gitProvider,
        endpoint: gitEndpoint.trim(), web_base_url: gitProvider === "MOUNT" ? "" : gitWebBaseURL.trim(), repository_id: gitRepositoryID.trim(),
        branch_name: gitBranchName.trim(), include_globs: splitCommaList(gitIncludeGlobs),
        exclude_globs: splitCommaList(gitExcludeGlobs), text_media_types: splitCommaList(gitTextMediaTypes),
        max_blob_bytes: parsedMaxBlobBytes,
      };
      if (credentialReference.trim()) body.credential_reference = credentialReference.trim();
    }

    setStage("registering");
    const registration = await apiPostWithoutIdempotency<SourceRegisterResponse>("/api/v1/sources", body);
    if (registration.kind !== "ok") {
      setStage("idle");
      setResult(registration);
      return;
    }

    setStage("binding");
    const binding = await withRevisionRetry<WorkspaceSnapshot>((workspaceEtag, workspaceRevision) =>
      apiMutation<WorkspaceSnapshot>(
        "POST",
        `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/sources`,
        {
          expected_workspace_revision: workspaceRevision,
          source_scope_id: registration.value.source_scope_id,
          source_scope_revision: registration.value.revision,
          scope_config_hash: registration.value.scope_config_hash,
          access_mode: registration.value.access_mode,
        },
        newIdempotencyKey(),
        workspaceEtag,
      ));
    if (binding.kind !== "ok") {
      setStage("idle");
      setResult(binding);
      return;
    }

    setStage("activating");
    const activation = await apiAction<{ job_id: string }>(
      `/api/v1/sources/${encodeURIComponent(registration.value.source_scope_id)}:activate`,
      newIdempotencyKey(),
    );
    setResult(activation);
    if (activation.kind !== "ok") {
      setStage("idle");
      return;
    }
    setStage("done");
    onCompleted();
  }

  return (
    <div className="sheet-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <section aria-labelledby="source-registration-title" aria-modal="true" className="source-sheet connect-sheet" ref={dialogRef} role="dialog" tabIndex={-1}>
        <header className="sheet-header">
          <div>
            <button className="back-link" disabled={busy} onClick={onBack} type="button"><IconChevron up={false} />All source types</button>
            <p className="eyebrow">Connect data</p>
            <h2 id="source-registration-title">{typeName}</h2>
          </div>
          <button aria-label="Close" className="close-button" disabled={busy} onClick={onClose} type="button">×</button>
        </header>

        {view === "credentials" ? (
          <div className="sheet-body credentials-step">
            <h3>Credentials</h3>
            <p className="source-note form-note">
              These let KnowVault read “{name.trim() || typeName}”. No password is stored here, only
              a reference to a secret the source administrator has already stored on the server.
            </p>
            <label className="field">
              <span>Stored credential reference</span>
              <input maxLength={128} onChange={(event) => setCredentialReference(event.target.value)} placeholder="cred_…" value={credentialReference} />
              <small>Leave blank if the source does not require separate credentials.</small>
            </label>
            <footer className="sheet-footer">
              <button className="secondary-button" onClick={() => setView("fields")} type="button">Back</button>
              <button className="primary-button" onClick={() => setView("fields")} type="button">Save</button>
            </footer>
          </div>
        ) : (
          <form className="cols connect-cols" onSubmit={submit}>
            <div className="col colL">
              <div className="card fill">
                <h3 className="ctitle">Connection</h3>
                <div className="scroll">
                  <label className="field"><span>Name</span><input autoFocus maxLength={128} onChange={(event) => setName(event.target.value)} required value={name} /></label>

                  {connectorType === "FOLDER" && (
                    <>
                      <label className="field"><span>Mounted folder alias</span><input maxLength={128} onChange={(event) => setRootAlias(event.target.value)} placeholder="reglamenty-mount" required value={rootAlias} /><small>Must match the alias assigned by the administrator when mounting the folder on the server.</small></label>
                      <label className="field"><span>Mount identity</span><input maxLength={128} onChange={(event) => setRootIdentity(event.target.value)} placeholder="managed" required value={rootIdentity} /></label>
                      <label className="field"><span>Relative path</span><input onChange={(event) => setRelativeRoot(event.target.value)} placeholder="reglamenty" required value={relativeRoot} /><small>A path relative to the mounted folder, not an absolute disk path.</small></label>
                      <label className="field checkbox-field"><input checked={recursive} onChange={(event) => setRecursive(event.target.checked)} type="checkbox" /><span>Include subfolders</span></label>
                      <label className="field checkbox-field"><input checked={ocrEnabled} onChange={(event) => setOcrEnabled(event.target.checked)} type="checkbox" /><span>Recognize text in scans</span></label>
                      <div className="field-group">
                        <span className="field-group-label">File types to read</span>
                        <div className="chip-row">
                          {FORMAT_OPTIONS.map((option) => (
                            <button aria-pressed={formats.includes(option.value)} className={formats.includes(option.value) ? "type-choice selected" : "type-choice"} key={option.value} onClick={() => toggleFormat(option.value)} type="button">{option.label}</button>
                          ))}
                        </div>
                      </div>
                    </>
                  )}

                  {connectorType === "GIT" && (
                    <>
                      <label className="field"><span>Provider</span><select onChange={(event) => setGitProvider(event.target.value)} value={gitProvider}><option value="GITHUB">GitHub</option><option value="GITLAB">GitLab</option><option value="MOUNT">Managed mount (local server, no network)</option></select></label>
                      {gitProvider === "MOUNT" ? (
                        <label className="field"><span>Path within the managed directory</span><input maxLength={256} onChange={(event) => setGitEndpoint(event.target.value)} placeholder="demo-git/knowvault" required value={gitEndpoint} /><small>A relative path under the same read-only directory used for folders.</small></label>
                      ) : (
                        <>
                          <label className="field"><span>API URL</span><input maxLength={256} onChange={(event) => setGitEndpoint(event.target.value)} placeholder="https://api.github.com" required value={gitEndpoint} /></label>
                          <label className="field"><span>Website URL</span><input maxLength={256} onChange={(event) => setGitWebBaseURL(event.target.value)} placeholder="https://github.com" value={gitWebBaseURL} /></label>
                        </>
                      )}
                      <label className="field"><span>Repository</span><input maxLength={512} onChange={(event) => setGitRepositoryID(event.target.value)} placeholder="organization/repository" required value={gitRepositoryID} /></label>
                      <label className="field"><span>Branch</span><input maxLength={256} onChange={(event) => setGitBranchName(event.target.value)} placeholder="main" required value={gitBranchName} /></label>
                      <details><summary><IconChevron up={false} />Advanced settings</summary>
                        <label className="field"><span>Include paths (comma-separated)</span><input onChange={(event) => setGitIncludeGlobs(event.target.value)} required value={gitIncludeGlobs} /></label>
                        <label className="field"><span>Exclude paths (comma-separated)</span><input onChange={(event) => setGitExcludeGlobs(event.target.value)} value={gitExcludeGlobs} /></label>
                        <label className="field"><span>Text media types</span><input onChange={(event) => setGitTextMediaTypes(event.target.value)} required value={gitTextMediaTypes} /></label>
                        <label className="field"><span>Maximum file size (bytes)</span><input inputMode="numeric" min="1" onChange={(event) => setGitMaxBlobBytes(event.target.value)} required type="number" value={gitMaxBlobBytes} /></label>
                      </details>
                    </>
                  )}
                </div>

                {hasCredentialStep && (
                  <div className={credentialReference.trim() ? "cred-lock cred-lock-done" : "cred-lock"}>
                    <span aria-hidden="true"><IconShield /></span>
                    <span className="cred-lock-text">
                      <b>{credentialReference.trim() ? "Credentials provided" : "No credentials provided"}</b>
                      <span>{credentialReference.trim() ? `Reference “${credentialReference.trim()}”. The server manages the secret; it is not visible in this interface.` : "You will need a reference to a secret the source administrator has prepared on the server."}</span>
                    </span>
                    <button className="link-button" onClick={() => setView("credentials")} type="button">{credentialReference.trim() ? "Edit" : "Provide"}</button>
                  </div>
                )}
              </div>
            </div>

            <div className="col colR">
              <div className="card fill">
                <h3 className="ctitle">Next steps</h3>
                <p className="source-note form-note">This source updates every 5 minutes. The schedule is fixed for this source type.</p>
                <p className="source-note form-note">This form does not test the connection or discover tables and folders. You specify what to read, and the server checks it during the first read.</p>

                {formError && <aside className="plain-note evidence-denied"><span aria-hidden="true">i</span><p>{formError}</p></aside>}
                {result && result.kind !== "ok" && <ClosedOrError result={result} />}
                {result?.kind === "ok" && stage === "done" && (
                  <div className="launch-note" role="status">
                    <strong>Source connected.</strong>
                    <span>The server confirmed registration, workspace binding and the sync request. Status will appear in the source list.</span>
                  </div>
                )}

                <footer className="sheet-footer connect-footer">
                  <button className="secondary-button" disabled={busy} onClick={onClose} type="button">{stage === "done" ? "Close" : "Cancel"}</button>
                  <button className="primary-button" disabled={busy || stage === "done" || !name.trim()} type="submit">
                    {stage === "registering" ? "Registering…" : stage === "binding" ? "Binding…" : stage === "activating" ? "Queuing…" : stage === "done" ? "Done" : "Connect"}
                  </button>
                </footer>
              </div>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}

type PostgreSQLConnectionBootstrapResponse = {
  connection_id: string;
  connection_revision: number;
  credential_reference: string;
  created: boolean;
};

type SourceDiscoveryRequestResponse = { request_id: string; created: boolean };

export type SourceDiscoveryColumn = {
  ordinal: number;
  name: string;
  type_name: string;
  logical_type: string;
  nullable: boolean;
  precision?: number;
  scale?: number;
  max_bytes?: number;
  comment?: string;
  roles: string[];
  primary_key: boolean;
};

// Card D-1: a column the server observed but cannot project into the query
// connector's value contract (for example a PostGIS geometry). It is shown
// with a reason and is never part of the registration projection.
export type SourceDiscoveryExcludedColumn = {
  ordinal: number;
  name: string;
  type_name: string;
  logical_type?: string;
  primary_key?: boolean;
  reason: string;
};

export type SourceDiscoveryView = {
  view_id: string;
  schema_name: string;
  relation_name: string;
  relation_kind: string;
  comment?: string;
  approx_row_count: number;
  status: string;
  interpretation?: string;
  columns: SourceDiscoveryColumn[];
  excluded_columns?: SourceDiscoveryExcludedColumn[];
};

type SourceDiscoveryResponse = {
  request_id: string;
  request_status: string;
  result_id?: string;
  result_status?: string;
  view_count: number;
  prepared_view_count: number;
  needs_interpretation_view_count: number;
  failure_code?: string;
  expires_at: string;
  views: SourceDiscoveryView[];
};

// ADR-0097: the register route accepts an optional narrowing body naming
// EVIDENCE-role ordinals to exclude, valid only for a TABLE/PARTITIONED_TABLE
// selection. Sending no exclusions (undefined body) registers the table
// unnarrowed, exactly like the original view flow. S3 card 4 adds the optional
// mode: INDEXED (the default, omitted) or QUERY_ONLY ("only for SQL queries,
// not indexed").
export type SourceDiscoveryRegisterInput = { excluded_columns?: number[]; mode?: string };

type PostgreSQLOnboardingPhase =
  | "connection"
  | "bootstrapping"
  | "verifying"
  | "verifying-submit"
  | "discovering"
  | "catalog"
  | "registering"
  | "done";

// PostgreSQL onboarding is intentionally server-led: the browser submits only
// connection coordinates, displays the sealed catalog result, and sends the
// server-issued view selector back for registration. Keeping this copy in one
// locale-owned object makes the flow easy to translate without putting labels
// beside protocol fields or inventing client-side metadata.
const postgresOnboardingLocale = {
  eyebrow: "Connect data",
  title: "PostgreSQL",
  description: "Set up a connection, discover available views and choose what to add to your workspace.",
  close: "Close",
  backToTypes: "All source types",
  steps: {
    connection: "Connection",
    verification: "Verification",
    discovery: "Search",
    selection: "Select view",
    finish: "Done",
  },
  connection: {
    heading: "Connection",
    intro: "Use the identities supplied by your source administrator. Do not enter database addresses, DSNs or passwords here.",
    nameLabel: "Connection name",
    namePlaceholder: "Operations database",
    nameHint: "This is how the connection will appear in your workspace.",
    databaseIdentityLabel: "Database identity",
    databaseIdentityPlaceholder: "ops-db-prod",
    databaseIdentityHint: "A reference to a managed database, not a network address.",
    lineageLabel: "Data lineage identity",
    lineagePlaceholder: "waste-daily",
    lineageHint: "A stable dataset name assigned by the source owner.",
    credentialLabel: "Stored credential reference (optional)",
    credentialPlaceholder: "cred_…",
    credentialHint: "Provide a reference to a stored secret. The secret itself is not visible in this interface.",
    privacyHeading: "What happens next",
    privacyText: "The server creates a draft connection and checks its view catalog. The server defines columns, roles and SQL; this form does not.",
    submit: "Find views",
    creating: "Saving connection…",
    startingDiscovery: "Starting discovery…",
    required: "Enter a name, database identity and data lineage identity.",
  },
  trust: {
    heading: "Trust verification",
    intro: "Before the catalog can be read, a connector administrator must confirm that the connection points to the expected server.",
    retryHeading: "Repeat discovery",
    retryIntro: "Trust verification is already recorded. Start a new catalog discovery for this connection.",
    identityLabel: "Verified connector identity",
    identityPlaceholder: "ops-db-prod",
    identityHint: "Check this value against the connection administrator's record.",
    attestedByLabel: "Verifier ID",
    attestedByPlaceholder: "Name or service ID",
    attestedByHint: "Identify who performed the verification. Requires the CONNECTOR_ADMIN role.",
    note: "This form contains no network address, DSN or secret. It records only the verification result and verifier.",
    submit: "Confirm and find views",
    submitting: "Confirming verification…",
    retryDiscovery: "Repeat discovery",
    forbidden: "Only a CONNECTOR_ADMIN can verify this connection. Ask your connector administrator to confirm it.",
    required: "Enter the connector identity and verifier.",
    back: "Edit connection",
  },
  discovery: {
    eyebrow: "Connection catalog",
    heading: "Available views",
    running: "Checking the database catalog…",
    runningHint: "This may take a few seconds. The view will update automatically.",
    empty: "The server found no available views.",
    emptyHint: "Check the connection permissions or ask an administrator to prepare a view.",
    summary: (prepared: number, total: number): string => `${prepared} of ${total} ready`,
    expires: "Catalog expires",
    viewKind: { VIEW: "View", MATERIALIZED_VIEW: "Materialized view", TABLE: "Table", PARTITIONED_TABLE: "Partitioned table" },
    prepared: "Ready to connect",
    needsInterpretation: "Needs clarification",
    interpretationPrefix: "Reason",
    interpretations: {
      UNRECOGNIZED_FORMAT: "view format not recognized",
      INCOMPLETE_BUSINESS_OBJECT_CONTRACT: "business object contract is incomplete",
      MALFORMED_BUSINESS_OBJECT_CONTRACT: "business object contract is malformed",
      UNSUPPORTED_TYPE: "column type is not supported",
      INVALID_IDENTIFIER: "view identifier is invalid",
      NO_PRIMARY_KEY: "table has no primary key",
    },
    // Card D-1: a base table column the server cannot project is listed with
    // its own reason instead of blocking the whole table. The copy is a closed
    // vocabulary, never server-supplied text.
    excludedHeading: "Not included",
    excludedNote: "These columns are not read from the table.",
    excludedReasons: {
      UNSUPPORTED_TYPE: "column type cannot be read by the query connector",
    } as Record<string, string>,
    rowCountUnknown: "Row count unknown",
    rowCountLabel: (count: number): string => `~${count.toLocaleString("en-US")} rows`,
    filterLabel: "Filter tables",
    filterPlaceholder: "Schema or table name",
    sortLabel: "Sort by",
    sortName: "Name",
    sortRows: "Row count",
    selectAll: "Select all ready",
    clearSelection: "Clear selection",
    selectedCount: (count: number): string => count === 0 ? "No tables selected" : count === 1 ? "1 table selected" : `${count} tables selected`,
    noSelection: "Select at least one table before adding.",
    keyColumn: "Key",
    registerSelected: "Add selected tables",
    columns: "Columns and metadata",
    noColumns: "Column metadata was not provided.",
    logicalTypes: {
      BOOL: "Yes / no",
      INT: "Integer",
      NUMERIC: "Exact numeric",
      UUID: "UUID",
      DATE: "Date",
      TIMESTAMP: "Time",
      TIMESTAMPTZ: "Time with time zone",
      TEXT: "Text",
      JSON: "JSON",
      JSONB: "JSONB",
    },
    nullable: "Nullable",
    required: "Required",
    roles: "Roles",
    noRoles: "No roles specified",
    roleLabels: {
      IDENTITY: "Row key",
      TITLE: "Title",
      VERSION_HINT: "Version hint",
      EVIDENCE: "Evidence text",
      PERIOD: "Period date",
      STATUS: "Status",
    },
    precision: "Precision",
    scale: "Scale",
    maxBytes: "Byte limit",
    bytes: "bytes",
    noComment: "No comment.",
    noActionHint: "This table or view cannot be connected automatically.",
    // S3 card 4: the registration mode. A partitioned table or a relation with
    // more than 1,000,000 estimated rows is offered query-only by default.
    modeQueryOnly: "Only for SQL queries (not indexed)",
    modeQueryOnlyHint: "Rows are not copied into search; the table stays available to SQL queries.",
    modeIndexedHint: "Rows are copied into search and can be cited.",
    modeBulkQueryOnly: "Only SQL for selected",
    modeBulkIndexed: "Index selected",
    selectSchemaLabel: "Select a schema",
    selectSchemaPlaceholder: "All schemas",
    back: "Edit connection",
  },
  completion: {
    resultsEyebrow: "Registration",
    registering: "Adding the selected tables…",
    doneHeading: "Registration complete",
    resultsSummary: (success: number, total: number): string => `${success} of ${total} table${total === 1 ? "" : "s"} added.`,
    resultSuccessDetail: "Added to the workspace as a draft. Confirm access and enable it in the source list.",
    retryFailed: "Retry failed tables",
    done: "Done",
  },
  errors: {
    discoveryFailed: "Could not retrieve the view catalog.",
    discoveryFailedHint: "Repeat discovery or ask your administrator to check connection access.",
    expired: "The catalog has expired.",
    expiredHint: "Return to the connection and run discovery again.",
  },
} as const;

function postgresDiscoveryStatusLabel(status: string): string {
  if (status === "PREPARED") return postgresOnboardingLocale.discovery.prepared;
  return postgresOnboardingLocale.discovery.needsInterpretation;
}

function postgresRelationKindLabel(kind: string): string {
  return postgresOnboardingLocale.discovery.viewKind[kind as keyof typeof postgresOnboardingLocale.discovery.viewKind] ?? kind;
}

function postgresApproxRowCountLabel(approxRowCount: number): string {
  if (approxRowCount < 0) return postgresOnboardingLocale.discovery.rowCountUnknown;
  return postgresOnboardingLocale.discovery.rowCountLabel(approxRowCount);
}

// ADR-0097: only a base/partitioned table's projection can narrow columns;
// the original five-column VIEW/MATERIALIZED_VIEW contract is server-fixed.
function postgresSupportsColumnExclusion(relationKind: string): boolean {
  return relationKind === "TABLE" || relationKind === "PARTITIONED_TABLE";
}

// S3 card 4: the row estimate above which a relation is offered query-only by
// default. It matches the server-side product rule (1,000,000 rows).
export const POSTGRES_QUERY_ONLY_ROW_THRESHOLD = 1_000_000;

// A partitioned table, or a relation whose pg_class row estimate is above the
// threshold, is offered "only for SQL queries (not indexed)" by default; every
// other relation is offered indexed. The administrator can switch either way.
export function postgresDefaultRegistrationMode(view: SourceDiscoveryView): string {
  if (view.relation_kind === "PARTITIONED_TABLE") return "QUERY_ONLY";
  return view.approx_row_count > POSTGRES_QUERY_ONLY_ROW_THRESHOLD ? "QUERY_ONLY" : "INDEXED";
}

// The effective mode of one table: the administrator's explicit choice when
// present, otherwise the server-consistent default for its kind and size.
export function postgresEffectiveRegistrationMode(
  view: SourceDiscoveryView,
  modeByView: ReadonlyMap<string, string>,
): string {
  return modeByView.get(view.view_id) ?? postgresDefaultRegistrationMode(view);
}

// The distinct schemas that contain at least one ready relation, so a large
// catalog can be registered one schema at a time from the same server-issued
// page without a second network call.
export function postgresSelectableSchemas(views: readonly SourceDiscoveryView[]): string[] {
  const schemas = new Set<string>();
  for (const view of views) {
    if (view.status === "PREPARED") schemas.add(view.schema_name);
  }
  return [...schemas].sort((left, right) => left.localeCompare(right));
}

export function postgresIsColumnExcludable(column: SourceDiscoveryColumn): boolean {
  return !column.primary_key;
}

// A primary-key column can never be excluded (the server refuses it and the
// identity of every row depends on it); toggling one is a silent no-op so a
// stray click can never produce an invalid registration request.
export function postgresToggleExcludedColumn(excluded: readonly number[], column: SourceDiscoveryColumn): number[] {
  if (!postgresIsColumnExcludable(column)) return [...excluded];
  return excluded.includes(column.ordinal)
    ? excluded.filter((ordinal) => ordinal !== column.ordinal)
    : [...excluded, column.ordinal].sort((left, right) => left - right);
}

export type PostgresViewSortKey = "name" | "rows";

export function postgresViewDisplayName(view: SourceDiscoveryView): string {
  return `${view.schema_name}.${view.relation_name}`;
}

// The large-database result set (a "hundreds of tables" GM-sized catalog)
// needs a client-side filter and a predictable sort; both operate on the
// same server-issued view list, never a second network call.
export function postgresFilterAndSortViews(
  views: readonly SourceDiscoveryView[],
  query: string,
  sort: PostgresViewSortKey,
): SourceDiscoveryView[] {
  const needle = query.trim().toLowerCase();
  const matched = needle === "" ? [...views] : views.filter((view) => postgresViewDisplayName(view).toLowerCase().includes(needle));
  return matched.sort((left, right) => {
    if (sort === "rows") {
      const leftRows = left.approx_row_count < 0 ? -1 : left.approx_row_count;
      const rightRows = right.approx_row_count < 0 ? -1 : right.approx_row_count;
      if (leftRows !== rightRows) return rightRows - leftRows;
    }
    return postgresViewDisplayName(left).localeCompare(postgresViewDisplayName(right));
  });
}

export type PostgresRegistrationRequest = { view: SourceDiscoveryView; body: SourceDiscoveryRegisterInput | undefined };

// Card S3.4b: one register call per ticked table, each carrying only that
// table's own excluded ordinals (sorted for a stable, testable request body)
// and its registration mode. A table with neither exclusions nor a query-only
// mode gets an empty body, exactly like the original single-view flow; a
// query-only table sends mode=QUERY_ONLY. Anything not PREPARED or not ticked
// is silently dropped, so a stale selection can never reach the network layer.
export function postgresRegistrationPlan(
  views: readonly SourceDiscoveryView[],
  selected: ReadonlySet<string>,
  excludedColumnsByView: ReadonlyMap<string, readonly number[]>,
  modeByView: ReadonlyMap<string, string> = new Map(),
): PostgresRegistrationRequest[] {
  return views
    .filter((view) => view.status === "PREPARED" && selected.has(view.view_id))
    .map((view) => {
      const excluded = [...(excludedColumnsByView.get(view.view_id) ?? [])].sort((left, right) => left - right);
      const mode = postgresEffectiveRegistrationMode(view, modeByView);
      const body: SourceDiscoveryRegisterInput = {};
      if (excluded.length > 0) body.excluded_columns = excluded;
      if (mode === "QUERY_ONLY") body.mode = "QUERY_ONLY";
      return { view, body: Object.keys(body).length > 0 ? body : undefined };
    });
}

// Card S3.4b: the server accepts at most this many tables in one register-batch
// request, so the wizard chunks a larger selection rather than sending one
// request per table.
export const POSTGRES_REGISTRATION_BATCH_LIMIT = 200;

export type SourceDiscoveryRegisterBatchResponse = {
  registered_count: number;
  refused_count: number;
  results: Array<{
    view_id: string;
    outcome: "REGISTERED" | "REFUSED" | string;
    reason_code?: string;
    registration?: SourceRegisterResponse;
  }>;
};

// The one server request body for a batch of ticked tables: each item carries
// only that table's view_id and the same two narrowing choices the single-view
// route accepted. A table with neither is registered with its default mode.
export function postgresRegistrationBatchBody(requests: readonly PostgresRegistrationRequest[]): {
  items: Array<{ view_id: string; excluded_columns?: number[]; mode?: string }>;
} {
  return {
    items: requests.map(({ view, body }) => {
      const item: { view_id: string; excluded_columns?: number[]; mode?: string } = { view_id: view.view_id };
      if (body?.excluded_columns) item.excluded_columns = body.excluded_columns;
      if (body?.mode) item.mode = body.mode;
      return item;
    }),
  };
}

type PostgresRegistrationOutcome = { view: SourceDiscoveryView; status: "pending" | "success" | "failure"; detail: string };

// Card S3.4b: registers the plan one bounded batch at a time, then binds each
// successfully registered scope to the workspace. Binding carries the workspace
// revision forward from one successful bind to the next (each bind advances
// it), with a single re-fetch-and-retry on a revision conflict -- the same
// recovery submitConnection's caller used to get from withRevisionRetry, just
// carried across the whole batch instead of one call. A refused table (for
// example one without a declared primary key) reports its reason code and never
// stops the others.
async function runPostgresRegistrationPlan(
  discoveryRequestID: string,
  workspaceID: string,
  plan: readonly PostgresRegistrationRequest[],
  startEtag: string,
  startRevision: number,
  onOutcome: (outcome: PostgresRegistrationOutcome) => void,
): Promise<void> {
  let workspaceEtag = startEtag;
  let workspaceRevision = startRevision;

  for (let offset = 0; offset < plan.length; offset += POSTGRES_REGISTRATION_BATCH_LIMIT) {
    const chunk = plan.slice(offset, offset + POSTGRES_REGISTRATION_BATCH_LIMIT);
    const batch = await apiPostWithoutIdempotency<SourceDiscoveryRegisterBatchResponse>(
      `/api/v1/sources/discovery/${encodeURIComponent(discoveryRequestID)}:register-batch`,
      postgresRegistrationBatchBody(chunk),
    );
    if (batch.kind !== "ok") {
      const detail = closedText(batch);
      for (const { view } of chunk) onOutcome({ view, status: "failure", detail });
      continue;
    }
    const byViewID = new Map(batch.value.results.map((row) => [row.view_id, row] as const));
    for (const { view } of chunk) {
      const row = byViewID.get(view.view_id);
      if (!row || row.outcome !== "REGISTERED" || !row.registration) {
        onOutcome({ view, status: "failure", detail: row?.reason_code ?? "REGISTRATION_REFUSED" });
        continue;
      }
      const registration = row.registration;

      const bindOnce = (workEtag: string, workRevision: number) => apiMutation<WorkspaceSnapshot>(
        "POST",
        `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/sources`,
        {
          expected_workspace_revision: workRevision,
          source_scope_id: registration.source_scope_id,
          source_scope_revision: registration.revision,
          scope_config_hash: registration.scope_config_hash,
          access_mode: registration.access_mode,
        },
        newIdempotencyKey(),
        workEtag,
      );

      let binding = await bindOnce(workspaceEtag, workspaceRevision);
      if (binding.kind === "failure" && (binding.code === "WORKSPACE_REVISION_CONFLICT" || binding.code === "CONFLICT")) {
        const refreshed = await apiGet<WorkspaceSnapshot>(`/api/v1/workspaces/${encodeURIComponent(workspaceID)}`);
        if (refreshed.kind === "ok" && refreshed.etag) binding = await bindOnce(refreshed.etag, refreshed.value.revision);
      }

      if (binding.kind !== "ok") {
        onOutcome({ view, status: "failure", detail: closedText(binding) });
        continue;
      }

      workspaceEtag = binding.etag ?? workspaceEtag;
      workspaceRevision = binding.value.revision;
      onOutcome({ view, status: "success", detail: "" });
    }
  }
}

function postgresLogicalTypeLabel(type: string): string {
  return postgresOnboardingLocale.discovery.logicalTypes[type as keyof typeof postgresOnboardingLocale.discovery.logicalTypes] ?? postgresOnboardingLocale.discovery.logicalTypes.TEXT;
}

function postgresRoleLabel(role: string): string {
  return postgresOnboardingLocale.discovery.roleLabels[role as keyof typeof postgresOnboardingLocale.discovery.roleLabels] ?? postgresOnboardingLocale.discovery.noRoles;
}

function postgresInterpretationLabel(reason: string | undefined): string {
  if (!reason) return postgresOnboardingLocale.discovery.needsInterpretation;
  return postgresOnboardingLocale.discovery.interpretations[reason as keyof typeof postgresOnboardingLocale.discovery.interpretations] ?? postgresOnboardingLocale.discovery.needsInterpretation;
}

// Card D-1: the operator-facing reason an observed column was excluded from
// the projection. Unknown reasons fail closed to the generic unsupported-type
// copy rather than rendering server text.
export function postgresExcludedReasonLabel(reason: string): string {
  return postgresOnboardingLocale.discovery.excludedReasons[reason] ?? postgresOnboardingLocale.discovery.interpretations.UNSUPPORTED_TYPE;
}

// Card D-1: one observed base-table column the server cannot project. It is
// display-only metadata with a reason -- no checkbox, no role, no comment --
// so the operator sees exactly why a column is missing from the connection.
export function PostgreSQLExcludedColumn({ column }: { column: SourceDiscoveryExcludedColumn }) {
  return (
    <li className="postgres-column-card postgres-column-auto-excluded">
      <div className="postgres-column-name">
        <span className="postgres-column-ordinal">{column.ordinal}</span>
        <code>{column.name}</code>
        {column.primary_key && <span className="postgres-column-key-badge">{postgresOnboardingLocale.discovery.keyColumn}</span>}
      </div>
      <div className="postgres-column-details">
        <span>{column.type_name}</span>
        <span className="postgres-column-exclusion-reason">
          {postgresOnboardingLocale.discovery.excludedHeading}: {postgresExcludedReasonLabel(column.reason)}
        </span>
      </div>
    </li>
  );
}

export function PostgreSQLDiscoveredColumn({ view, column, excluded, onToggleExcluded, disabled }: {
  view: SourceDiscoveryView;
  column: SourceDiscoveryColumn;
  excluded: boolean;
  onToggleExcluded: (view: SourceDiscoveryView, column: SourceDiscoveryColumn) => void;
  disabled: boolean;
}) {
  const details: string[] = [postgresLogicalTypeLabel(column.logical_type)];
  details.push(column.nullable ? postgresOnboardingLocale.discovery.nullable : postgresOnboardingLocale.discovery.required);
  if (column.precision !== undefined) details.push(`${postgresOnboardingLocale.discovery.precision}: ${column.precision}`);
  if (column.scale !== undefined) details.push(`${postgresOnboardingLocale.discovery.scale}: ${column.scale}`);
  if (column.max_bytes !== undefined) details.push(`${postgresOnboardingLocale.discovery.maxBytes}: ${column.max_bytes} ${postgresOnboardingLocale.discovery.bytes}`);
  // A table that cannot be selected at all (NEEDS_INTERPRETATION) offers no
  // per-column exclusion either -- there is nothing a checkbox here could do.
  const canExclude = view.status === "PREPARED" && postgresSupportsColumnExclusion(view.relation_kind);

  return (
    <li className={excluded ? "postgres-column-card postgres-column-excluded" : "postgres-column-card"}>
      <div className="postgres-column-name">
        {canExclude && (
          <input
            aria-label={`Show column ${column.name}`}
            checked={!excluded}
            disabled={disabled || column.primary_key}
            onChange={() => onToggleExcluded(view, column)}
            type="checkbox"
          />
        )}
        <span className="postgres-column-ordinal">{column.ordinal}</span>
        <code>{column.name}</code>
        {column.primary_key && <span className="postgres-column-key-badge">{postgresOnboardingLocale.discovery.keyColumn}</span>}
      </div>
      <div className="postgres-column-details">
        <span>{column.type_name}</span>
        <span>{details.join(" · ")}</span>
        <span>{postgresOnboardingLocale.discovery.roles}: {column.roles.length > 0 ? column.roles.map(postgresRoleLabel).join(", ") : postgresOnboardingLocale.discovery.noRoles}</span>
        <span>{column.comment || postgresOnboardingLocale.discovery.noComment}</span>
      </div>
    </li>
  );
}

export function PostgreSQLDiscoveredViewCard({ view, selected, disabled, onToggleSelected, excludedColumns, onToggleColumn, mode, onToggleMode }: {
  view: SourceDiscoveryView;
  selected: boolean;
  disabled: boolean;
  onToggleSelected: (view: SourceDiscoveryView) => void;
  excludedColumns: readonly number[];
  onToggleColumn: (view: SourceDiscoveryView, column: SourceDiscoveryColumn) => void;
  // S3 card 4: the effective registration mode ("INDEXED" or "QUERY_ONLY")
  // and the administrator's toggle. Both are optional so existing callers that
  // only render the catalog keep working; a missing mode is simply not shown.
  mode?: string;
  onToggleMode?: (view: SourceDiscoveryView) => void;
}) {
  const prepared = view.status === "PREPARED";
  return (
    <article className={prepared ? "postgres-view-card postgres-view-prepared" : "postgres-view-card postgres-view-needs-interpretation"}>
      <header className="postgres-view-card-header">
        {prepared && (
          <input
            aria-label={`Select ${postgresViewDisplayName(view)}`}
            checked={selected}
            className="postgres-view-select"
            disabled={disabled}
            onChange={() => onToggleSelected(view)}
            type="checkbox"
          />
        )}
        <div className="postgres-view-title">
          <span className="postgres-view-kind">{postgresRelationKindLabel(view.relation_kind)}</span>
          <h4><code>{view.schema_name}.{view.relation_name}</code></h4>
          <p className="postgres-view-rowcount">{postgresApproxRowCountLabel(view.approx_row_count)}</p>
          {view.comment && <p>{view.comment}</p>}
        </div>
        <div className="postgres-view-action">
          <span className={prepared ? "postgres-view-status postgres-view-status-prepared" : "postgres-view-status postgres-view-status-needs-interpretation"}>
            {postgresDiscoveryStatusLabel(view.status)}
          </span>
        </div>
      </header>

      {prepared && mode !== undefined && (
        <label className="postgres-view-mode">
          <input
            checked={mode === "QUERY_ONLY"}
            disabled={disabled || !onToggleMode}
            onChange={() => onToggleMode?.(view)}
            type="checkbox"
          />
          <span>
            <strong>{postgresOnboardingLocale.discovery.modeQueryOnly}</strong>
            <small>{mode === "QUERY_ONLY" ? postgresOnboardingLocale.discovery.modeQueryOnlyHint : postgresOnboardingLocale.discovery.modeIndexedHint}</small>
          </span>
        </label>
      )}

      {!prepared && (
        <p className="postgres-view-interpretation">
          {postgresOnboardingLocale.discovery.interpretationPrefix}: {postgresInterpretationLabel(view.interpretation)}. {postgresOnboardingLocale.discovery.noActionHint}
        </p>
      )}

      <details className="postgres-columns-details">
        <summary className="postgres-columns-heading">
          <strong>{postgresOnboardingLocale.discovery.columns}</strong>
          <span>{view.columns.length}</span>
        </summary>
        {view.columns.length > 0
          ? (
            <ul className="postgres-column-list">
              {view.columns.map((column) => (
                <PostgreSQLDiscoveredColumn
                  column={column}
                  disabled={disabled}
                  excluded={excludedColumns.includes(column.ordinal)}
                  key={`${view.view_id}-${column.ordinal}-${column.name}`}
                  onToggleExcluded={onToggleColumn}
                  view={view}
                />
              ))}
            </ul>
          )
          : <p className="postgres-no-columns">{postgresOnboardingLocale.discovery.noColumns}</p>}
        {(view.excluded_columns?.length ?? 0) > 0 && (
          <div className="postgres-excluded-columns">
            <p className="postgres-excluded-note">{postgresOnboardingLocale.discovery.excludedNote}</p>
            <ul className="postgres-column-list">
              {view.excluded_columns?.map((column) => (
                <PostgreSQLExcludedColumn column={column} key={`${view.view_id}-excluded-${column.ordinal}-${column.name}`} />
              ))}
            </ul>
          </div>
        )}
      </details>
    </article>
  );
}

export function PostgreSQLOnboardingDialog({ snapshot, etag, initialDraft, onBack, onClose, onCompleted }: {
  snapshot: WorkspaceSnapshot;
  etag: string;
  // Card D-1: reopening the wizard from a draft resumes at the state the
  // server reports instead of starting over. A draft whose trust material was
  // already verified continues at catalog discovery; one still awaiting
  // verification continues at the trust step.
  initialDraft?: SourceConnectionDraft | null;
  onBack: () => void;
  onClose: () => void;
  onCompleted: (message?: string) => void;
}) {
  const [phase, setPhase] = useState<PostgreSQLOnboardingPhase>(initialDraft ? "verifying" : "connection");
  const [name, setName] = useState(initialDraft?.connection_name ?? "");
  const [databaseIdentity, setDatabaseIdentity] = useState("");
  const [lineageID, setLineageID] = useState("");
  const [credentialReference, setCredentialReference] = useState("");
  const [connectionID, setConnectionID] = useState<string | null>(initialDraft?.connection_id ?? null);
  const [connectionCopy, setConnectionCopy] = useState<{ id: string; copied: boolean } | null>(null);
  const [attestedConnectorIdentity, setAttestedConnectorIdentity] = useState("");
  const [attestedBy, setAttestedBy] = useState("");
  const [trustVerified, setTrustVerified] = useState(initialDraft?.state === "READY_FOR_DISCOVERY");
  const [discoveryRequestID, setDiscoveryRequestID] = useState<string | null>(null);
  const [discovery, setDiscovery] = useState<SourceDiscoveryResponse | null>(null);
  const [filterQuery, setFilterQuery] = useState("");
  const [sortKey, setSortKey] = useState<PostgresViewSortKey>("name");
  const [selectedViewIDs, setSelectedViewIDs] = useState<ReadonlySet<string>>(new Set());
  const [excludedColumnsByView, setExcludedColumnsByView] = useState<ReadonlyMap<string, readonly number[]>>(new Map());
  const [modeByView, setModeByView] = useState<ReadonlyMap<string, string>>(new Map());
  const [registrationResults, setRegistrationResults] = useState<PostgresRegistrationOutcome[]>([]);
  const [result, setResult] = useState<ApiResult<unknown> | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [discoveryFailure, setDiscoveryFailure] = useState<"failed" | "expired" | null>(null);

  const busy = phase === "bootstrapping" || phase === "verifying-submit" || phase === "discovering" || phase === "registering";
  const dialogRef = useModalDialog(onClose, busy);
  const showingCatalog = discovery !== null && phase === "catalog";
  const showingResults = phase === "registering" || phase === "done";
  const filteredViews = discovery ? postgresFilterAndSortViews(discovery.views, filterQuery, sortKey) : [];
  const registrationSuccessCount = registrationResults.filter((row) => row.status === "success").length;
  const registrationFailureCount = registrationResults.filter((row) => row.status === "failure").length;

  async function copyConnectionID() {
    if (!connectionID) return;
    try {
      await navigator.clipboard.writeText(connectionID);
      setConnectionCopy({ id: connectionID, copied: true });
    } catch {
      setConnectionCopy({ id: connectionID, copied: false });
    }
  }

  useEffect(() => {
    if (!discoveryRequestID) return;
    let disposed = false;
    let timeoutID: number | undefined;

    async function poll() {
      const response = await apiGet<SourceDiscoveryResponse>(`/api/v1/sources/discovery/${encodeURIComponent(discoveryRequestID as string)}`);
      if (disposed) return;
      if (response.kind !== "ok") {
        setResult(response);
        setDiscoveryRequestID(null);
        setPhase("verifying");
        return;
      }

      setDiscovery(response.value);
      const pending = response.value.request_status === "PENDING" || response.value.request_status === "RUNNING";
      const failed = response.value.request_status === "FAILED" || response.value.request_status === "EXPIRED";
      if (pending) {
        timeoutID = window.setTimeout(() => void poll(), 1200);
      } else if (failed) {
        setDiscoveryFailure(response.value.request_status === "EXPIRED" ? "expired" : "failed");
        setDiscoveryRequestID(null);
        setPhase("verifying");
      } else if (response.value.request_status === "SUCCEEDED") {
        setPhase("catalog");
      } else {
        setDiscoveryFailure("failed");
        setDiscoveryRequestID(null);
        setPhase("verifying");
      }
    }

    void poll();
    return () => {
      disposed = true;
      if (timeoutID !== undefined) window.clearTimeout(timeoutID);
    };
  }, [discoveryRequestID]);

  async function requestDiscovery() {
    if (!connectionID) return;
    setFormError(null);
    setResult(null);
    setDiscoveryFailure(null);
    setDiscoveryRequestID(null);
    setFilterQuery("");
    setSortKey("name");
    setSelectedViewIDs(new Set());
    setExcludedColumnsByView(new Map());
    setModeByView(new Map());
    setRegistrationResults([]);
    setPhase("discovering");
    const request = await apiAction<SourceDiscoveryRequestResponse>(
      `/api/v1/sources/connections/${encodeURIComponent(connectionID)}:discover`,
      newIdempotencyKey(),
    );
    if (request.kind !== "ok") {
      setResult(request);
      setPhase("verifying");
      return;
    }
    setDiscoveryRequestID(request.value.request_id);
  }

  async function submitConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || phase === "done") return;
    setFormError(null);
    setResult(null);
    setDiscoveryFailure(null);
    if (!name.trim() || !databaseIdentity.trim() || !lineageID.trim()) {
      setFormError(postgresOnboardingLocale.connection.required);
      return;
    }

    const body: Record<string, string> = {
      name: name.trim(),
      database_identity: databaseIdentity.trim(),
      lineage_id: lineageID.trim(),
      workspace_id: snapshot.id,
    };
    if (credentialReference.trim()) body.credential_reference = credentialReference.trim();

    setPhase("bootstrapping");
    const connection = await apiPostWithoutIdempotency<PostgreSQLConnectionBootstrapResponse>("/api/v1/sources/connections", body);
    if (connection.kind !== "ok") {
      setResult(connection);
      setPhase("connection");
      return;
    }

    setConnectionID(connection.value.connection_id);
    setAttestedConnectorIdentity(databaseIdentity.trim());
    setTrustVerified(false);
    setDiscovery(null);
    setDiscoveryRequestID(null);
    setPhase("verifying");
  }

  async function submitTrustVerification(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || phase !== "verifying" || !connectionID) return;
    if (trustVerified) {
      await requestDiscovery();
      return;
    }
    setFormError(null);
    setResult(null);
    if (!attestedConnectorIdentity.trim() || !attestedBy.trim()) {
      setFormError(postgresOnboardingLocale.trust.required);
      return;
    }

    setPhase("verifying-submit");
    const verification = await apiPost<{ result_id: string; result_hash: string }>(
      `/api/v1/sources/connections/${encodeURIComponent(connectionID)}:verify-trust`,
      {
        attested_connector_identity: attestedConnectorIdentity.trim(),
        attested_by: attestedBy.trim(),
        attested_at: new Date().toISOString(),
      },
      newIdempotencyKey(),
    );
    if (verification.kind !== "ok") {
      setResult(verification);
      setPhase("verifying");
      return;
    }

    setTrustVerified(true);
    await requestDiscovery();
  }

  function toggleViewSelected(view: SourceDiscoveryView) {
    if (view.status !== "PREPARED" || busy) return;
    setSelectedViewIDs((current) => {
      const next = new Set(current);
      if (next.has(view.view_id)) next.delete(view.view_id); else next.add(view.view_id);
      return next;
    });
  }

  function toggleColumnExcluded(view: SourceDiscoveryView, column: SourceDiscoveryColumn) {
    if (busy) return;
    setExcludedColumnsByView((current) => {
      const next = new Map(current);
      next.set(view.view_id, postgresToggleExcludedColumn(next.get(view.view_id) ?? [], column));
      return next;
    });
  }

  function selectAllReadyViews() {
    if (!discovery || busy) return;
    setSelectedViewIDs(new Set(discovery.views.filter((view) => view.status === "PREPARED").map((view) => view.view_id)));
  }

  function selectSchemaViews(schema: string) {
    if (!discovery || busy || !schema) return;
    setSelectedViewIDs(new Set(discovery.views
      .filter((view) => view.status === "PREPARED" && view.schema_name === schema)
      .map((view) => view.view_id)));
  }

  function toggleViewMode(view: SourceDiscoveryView) {
    if (busy) return;
    setModeByView((current) => {
      const next = new Map(current);
      next.set(view.view_id, postgresEffectiveRegistrationMode(view, current) === "QUERY_ONLY" ? "INDEXED" : "QUERY_ONLY");
      return next;
    });
  }

  // Bulk mode applies to the current selection, so "select all ready" or one
  // schema followed by one click registers the whole batch in query-only mode.
  function applyModeToSelection(mode: string) {
    if (!discovery || busy) return;
    setModeByView((current) => {
      const next = new Map(current);
      for (const view of discovery.views) {
        if (view.status === "PREPARED" && selectedViewIDs.has(view.view_id)) next.set(view.view_id, mode);
      }
      return next;
    });
  }

  function clearViewSelection() {
    if (busy) return;
    setSelectedViewIDs(new Set());
  }

  async function confirmRegistration() {
    if (!discovery || !discoveryRequestID || busy || phase !== "catalog") return;
    const plan = postgresRegistrationPlan(discovery.views, selectedViewIDs, excludedColumnsByView, modeByView);
    if (plan.length === 0) {
      setFormError(postgresOnboardingLocale.discovery.noSelection);
      return;
    }

    setFormError(null);
    setResult(null);
    setRegistrationResults(plan.map(({ view }) => ({ view, status: "pending", detail: "" })));
    setPhase("registering");

    await runPostgresRegistrationPlan(
      discoveryRequestID,
      snapshot.id,
      plan,
      etag,
      snapshot.revision,
      (outcome) => setRegistrationResults((current) => current.map((row) => (row.view.view_id === outcome.view.view_id ? outcome : row))),
    );

    setPhase("done");
  }

  function retryFailedRegistrations() {
    const failedViewIDs = new Set(registrationResults.filter((row) => row.status === "failure").map((row) => row.view.view_id));
    setSelectedViewIDs(failedViewIDs);
    setRegistrationResults([]);
    setResult(null);
    setPhase("catalog");
  }

  function finishRegistration() {
    if (registrationSuccessCount > 0) {
      onCompleted(postgresOnboardingLocale.completion.resultsSummary(registrationSuccessCount, registrationResults.length));
    } else {
      onClose();
    }
  }

  const activeStep = phase === "connection" || phase === "bootstrapping" ? "connection" : phase === "verifying" || phase === "verifying-submit" ? "verification" : phase === "discovering" ? "discovery" : showingCatalog ? "selection" : "finish";
  const steps = [
    { id: "connection", label: postgresOnboardingLocale.steps.connection },
    { id: "verification", label: postgresOnboardingLocale.steps.verification },
    { id: "discovery", label: postgresOnboardingLocale.steps.discovery },
    { id: "selection", label: postgresOnboardingLocale.steps.selection },
    { id: "finish", label: postgresOnboardingLocale.steps.finish },
  ];

  return (
    <div className="sheet-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }}>
      <section aria-labelledby="postgres-onboarding-title" aria-modal="true" className="source-sheet postgres-sheet" ref={dialogRef} role="dialog" tabIndex={-1}>
        <header className="sheet-header">
          <div>
            <button className="back-link" disabled={busy} onClick={onBack} type="button"><IconChevron up={false} />{postgresOnboardingLocale.backToTypes}</button>
            <p className="eyebrow">{postgresOnboardingLocale.eyebrow}</p>
            <h2 id="postgres-onboarding-title">{postgresOnboardingLocale.title}</h2>
            <p className="sheet-description">{postgresOnboardingLocale.description}</p>
          </div>
          <button aria-label={postgresOnboardingLocale.close} className="close-button" disabled={busy} onClick={onClose} type="button">×</button>
        </header>

        <nav aria-label={postgresOnboardingLocale.title} className="postgres-steps">
          <ol>
            {steps.map((step) => (
              <li aria-current={step.id === activeStep ? "step" : undefined} className={step.id === activeStep ? "postgres-step postgres-step-active" : "postgres-step"} key={step.id}>
                <span>{steps.findIndex((item) => item.id === step.id) + 1}</span>
                <b>{step.label}</b>
              </li>
            ))}
          </ol>
        </nav>

        {(phase === "connection" || phase === "bootstrapping" || phase === "discovering") && (
          <form className="postgres-wizard postgres-connection-form" onSubmit={submitConnection}>
            <div className="postgres-connection-columns">
              <div className="postgres-connection-main">
                <h3>{postgresOnboardingLocale.connection.heading}</h3>
                <p className="postgres-wizard-intro">{postgresOnboardingLocale.connection.intro}</p>
                <label className="field">
                  <span>{postgresOnboardingLocale.connection.nameLabel}</span>
                  <input autoFocus disabled={busy} maxLength={256} onChange={(event) => setName(event.target.value)} placeholder={postgresOnboardingLocale.connection.namePlaceholder} required value={name} />
                  <small>{postgresOnboardingLocale.connection.nameHint}</small>
                </label>
                <label className="field">
                  <span>{postgresOnboardingLocale.connection.databaseIdentityLabel}</span>
                  <input disabled={busy} maxLength={256} onChange={(event) => setDatabaseIdentity(event.target.value)} placeholder={postgresOnboardingLocale.connection.databaseIdentityPlaceholder} required value={databaseIdentity} />
                  <small>{postgresOnboardingLocale.connection.databaseIdentityHint}</small>
                </label>
                <label className="field">
                  <span>{postgresOnboardingLocale.connection.lineageLabel}</span>
                  <input disabled={busy} maxLength={256} onChange={(event) => setLineageID(event.target.value)} placeholder={postgresOnboardingLocale.connection.lineagePlaceholder} required value={lineageID} />
                  <small>{postgresOnboardingLocale.connection.lineageHint}</small>
                </label>
                <label className="field">
                  <span>{postgresOnboardingLocale.connection.credentialLabel}</span>
                  <input disabled={busy} maxLength={128} onChange={(event) => setCredentialReference(event.target.value)} placeholder={postgresOnboardingLocale.connection.credentialPlaceholder} value={credentialReference} />
                  <small>{postgresOnboardingLocale.connection.credentialHint}</small>
                </label>
              </div>
              <aside className="postgres-connection-aside">
                <h3>{postgresOnboardingLocale.connection.privacyHeading}</h3>
                <p>{postgresOnboardingLocale.connection.privacyText}</p>
                <span aria-hidden="true"><IconShield /></span>
              </aside>
            </div>

            {phase === "bootstrapping" && <p className="postgres-progress" role="status">{postgresOnboardingLocale.connection.creating}</p>}
            {phase === "discovering" && (
              <div className="postgres-progress" role="status">
                <strong>{postgresOnboardingLocale.connection.startingDiscovery}</strong>
                <span>{postgresOnboardingLocale.discovery.runningHint}</span>
              </div>
            )}
            {formError && <aside className="plain-note evidence-denied"><span aria-hidden="true"><IconInfo /></span><p>{formError}</p></aside>}
            {discoveryFailure && (
              <aside className="plain-note evidence-denied">
                <span aria-hidden="true"><IconAlertTriangle /></span>
                <div>
                  <p>{discoveryFailure === "expired" ? postgresOnboardingLocale.errors.expired : postgresOnboardingLocale.errors.discoveryFailed}</p>
                  <p>{discoveryFailure === "expired" ? postgresOnboardingLocale.errors.expiredHint : postgresOnboardingLocale.errors.discoveryFailedHint}</p>
                </div>
              </aside>
            )}
            {result && result.kind !== "ok" && <ClosedOrError result={result} />}

            <footer className="sheet-footer postgres-footer">
              <button className="secondary-button" disabled={busy} onClick={onClose} type="button">{postgresOnboardingLocale.close}</button>
              <button className="primary-button" disabled={busy || !name.trim()} type="submit">
                {phase === "bootstrapping" ? postgresOnboardingLocale.connection.creating : phase === "discovering" ? postgresOnboardingLocale.connection.startingDiscovery : postgresOnboardingLocale.connection.submit}
              </button>
            </footer>
          </form>
        )}

        {(phase === "verifying" || phase === "verifying-submit") && (
          <form className="postgres-wizard postgres-trust-form" onSubmit={submitTrustVerification}>
            <div className="postgres-trust-main">
              <h3>{trustVerified ? postgresOnboardingLocale.trust.retryHeading : postgresOnboardingLocale.trust.heading}</h3>
              <p className="postgres-wizard-intro">{trustVerified ? postgresOnboardingLocale.trust.retryIntro : postgresOnboardingLocale.trust.intro}</p>
              {connectionID && (
                <div className="postgres-connection-handoff">
                  <label className="field">
                    <span>Connection ID for your administrator</span>
                    <input onFocus={(event) => event.currentTarget.select()} readOnly value={connectionID} />
                  </label>
                  <button className="secondary-button" onClick={() => void copyConnectionID()} type="button">Copy ID</button>
                  {connectionCopy?.id === connectionID && <p role="status">{connectionCopy.copied ? "Connection ID copied." : "Copy the ID from the field manually."}</p>}
                </div>
              )}
              <label className="field">
                <span>{postgresOnboardingLocale.trust.identityLabel}</span>
                <input disabled={busy} maxLength={512} onChange={(event) => setAttestedConnectorIdentity(event.target.value)} placeholder={postgresOnboardingLocale.trust.identityPlaceholder} required value={attestedConnectorIdentity} />
                <small>{postgresOnboardingLocale.trust.identityHint}</small>
              </label>
              <label className="field">
                <span>{postgresOnboardingLocale.trust.attestedByLabel}</span>
                <input disabled={busy} maxLength={256} onChange={(event) => setAttestedBy(event.target.value)} placeholder={postgresOnboardingLocale.trust.attestedByPlaceholder} required value={attestedBy} />
                <small>{postgresOnboardingLocale.trust.attestedByHint}</small>
              </label>
              <p className="postgres-trust-note"><span aria-hidden="true"><IconInfo /></span><span>{postgresOnboardingLocale.trust.note}</span></p>
            </div>
            {formError && <aside className="plain-note evidence-denied"><span aria-hidden="true"><IconInfo /></span><p>{formError}</p></aside>}
            {discoveryFailure && (
              <aside className="plain-note evidence-denied">
                <span aria-hidden="true"><IconAlertTriangle /></span>
                <div>
                  <p>{discoveryFailure === "expired" ? postgresOnboardingLocale.errors.expired : postgresOnboardingLocale.errors.discoveryFailed}</p>
                  <p>{discoveryFailure === "expired" ? postgresOnboardingLocale.errors.expiredHint : postgresOnboardingLocale.errors.discoveryFailedHint}</p>
                </div>
              </aside>
            )}
            {result?.kind === "failure" && result.status === 403 && (
              <aside className="plain-note evidence-denied"><span aria-hidden="true"><IconAlertTriangle /></span><p>{postgresOnboardingLocale.trust.forbidden}</p></aside>
            )}
            {result && result.kind !== "ok" && !(result.kind === "failure" && result.status === 403) && <ClosedOrError result={result} />}
            <footer className="sheet-footer postgres-footer">
              <button className="secondary-button" disabled={busy} onClick={() => { setFormError(null); setResult(null); setPhase("connection"); }} type="button">{postgresOnboardingLocale.trust.back}</button>
              <button className="primary-button" disabled={busy || (!trustVerified && (!attestedConnectorIdentity.trim() || !attestedBy.trim()))} type="submit">
                {phase === "verifying-submit" ? postgresOnboardingLocale.trust.submitting : trustVerified ? postgresOnboardingLocale.trust.retryDiscovery : postgresOnboardingLocale.trust.submit}
              </button>
            </footer>
          </form>
        )}

        {showingCatalog && discovery && (
          <div className="postgres-wizard postgres-catalog-view">
            <header className="postgres-catalog-header">
              <div>
                <p className="eyebrow">{postgresOnboardingLocale.discovery.eyebrow}</p>
                <h3>{postgresOnboardingLocale.discovery.heading}</h3>
                <p>{postgresOnboardingLocale.discovery.summary(discovery.prepared_view_count, discovery.view_count)}</p>
              </div>
              <div className="postgres-catalog-expiry">
                <span>{postgresOnboardingLocale.discovery.expires}</span>
                <strong>{formatTime(discovery.expires_at)}</strong>
              </div>
            </header>

            {discovery.views.length === 0 ? (
              <div className="postgres-catalog-empty">
                <span aria-hidden="true"><IconTable /></span>
                <strong>{postgresOnboardingLocale.discovery.empty}</strong>
                <p>{postgresOnboardingLocale.discovery.emptyHint}</p>
              </div>
            ) : (
              <>
                <div className="postgres-catalog-toolbar">
                  <label className="postgres-filter-field">
                    <span>{postgresOnboardingLocale.discovery.filterLabel}</span>
                    <input
                      onChange={(event) => setFilterQuery(event.target.value)}
                      placeholder={postgresOnboardingLocale.discovery.filterPlaceholder}
                      type="search"
                      value={filterQuery}
                    />
                  </label>
                  <label className="postgres-sort-field">
                    <span>{postgresOnboardingLocale.discovery.sortLabel}</span>
                    <select onChange={(event) => setSortKey(event.target.value as PostgresViewSortKey)} value={sortKey}>
                      <option value="name">{postgresOnboardingLocale.discovery.sortName}</option>
                      <option value="rows">{postgresOnboardingLocale.discovery.sortRows}</option>
                    </select>
                  </label>
                  <div className="postgres-selection-controls">
                    <span>{postgresOnboardingLocale.discovery.selectedCount(selectedViewIDs.size)}</span>
                    <button className="link-button" disabled={busy} onClick={selectAllReadyViews} type="button">{postgresOnboardingLocale.discovery.selectAll}</button>
                    <label className="postgres-schema-field">
                      <span>{postgresOnboardingLocale.discovery.selectSchemaLabel}</span>
                      <select disabled={busy} onChange={(event) => selectSchemaViews(event.target.value)} value="">
                        <option value="">{postgresOnboardingLocale.discovery.selectSchemaPlaceholder}</option>
                        {postgresSelectableSchemas(discovery.views).map((schema) => (
                          <option key={schema} value={schema}>{schema}</option>
                        ))}
                      </select>
                    </label>
                    <button className="link-button" disabled={busy || selectedViewIDs.size === 0} onClick={() => applyModeToSelection("QUERY_ONLY")} type="button">{postgresOnboardingLocale.discovery.modeBulkQueryOnly}</button>
                    <button className="link-button" disabled={busy || selectedViewIDs.size === 0} onClick={() => applyModeToSelection("INDEXED")} type="button">{postgresOnboardingLocale.discovery.modeBulkIndexed}</button>
                    <button className="link-button" disabled={busy || selectedViewIDs.size === 0} onClick={clearViewSelection} type="button">{postgresOnboardingLocale.discovery.clearSelection}</button>
                  </div>
                </div>

                <div className="postgres-view-grid">
                  {filteredViews.map((view) => (
                    <PostgreSQLDiscoveredViewCard
                      disabled={busy}
                      excludedColumns={excludedColumnsByView.get(view.view_id) ?? []}
                      key={view.view_id}
                      mode={postgresEffectiveRegistrationMode(view, modeByView)}
                      onToggleColumn={toggleColumnExcluded}
                      onToggleMode={toggleViewMode}
                      onToggleSelected={toggleViewSelected}
                      selected={selectedViewIDs.has(view.view_id)}
                      view={view}
                    />
                  ))}
                </div>
              </>
            )}

            {formError && <aside className="plain-note evidence-denied"><span aria-hidden="true"><IconInfo /></span><p>{formError}</p></aside>}
            {result && result.kind !== "ok" && <ClosedOrError result={result} />}

            <footer className="sheet-footer postgres-footer">
              <button className="secondary-button" disabled={busy} onClick={onBack} type="button">{postgresOnboardingLocale.discovery.back}</button>
              <button className="primary-button" disabled={busy || selectedViewIDs.size === 0} onClick={() => void confirmRegistration()} type="button">
                {postgresOnboardingLocale.discovery.registerSelected}
              </button>
            </footer>
          </div>
        )}

        {showingResults && (
          <div className="postgres-wizard postgres-results-view" role="status">
            <header className="postgres-catalog-header">
              <div>
                <p className="eyebrow">{postgresOnboardingLocale.completion.resultsEyebrow}</p>
                <h3>{phase === "registering" ? postgresOnboardingLocale.completion.registering : postgresOnboardingLocale.completion.doneHeading}</h3>
                <p>{postgresOnboardingLocale.completion.resultsSummary(registrationSuccessCount, registrationResults.length)}</p>
              </div>
            </header>

            <ul className="postgres-results-list">
              {registrationResults.map((row) => (
                <li className={`postgres-result-row postgres-result-${row.status}`} key={row.view.view_id}>
                  <span aria-hidden="true">
                    {row.status === "success" ? <IconCheckCircle /> : row.status === "failure" ? <IconAlertTriangle /> : <span className="postgres-result-spinner" />}
                  </span>
                  <div>
                    <code>{postgresViewDisplayName(row.view)}</code>
                    {row.status === "failure" && <p>{row.detail}</p>}
                    {row.status === "success" && <p>{postgresOnboardingLocale.completion.resultSuccessDetail}</p>}
                  </div>
                </li>
              ))}
            </ul>

            <footer className="sheet-footer postgres-footer">
              {phase === "done" && registrationFailureCount > 0 && (
                <button className="secondary-button" onClick={retryFailedRegistrations} type="button">{postgresOnboardingLocale.completion.retryFailed}</button>
              )}
              {phase === "done" && (
                <button className="primary-button" onClick={finishRegistration} type="button">
                  {registrationSuccessCount > 0 ? postgresOnboardingLocale.completion.done : postgresOnboardingLocale.close}
                </button>
              )}
            </footer>
          </div>
        )}
      </section>
    </div>
  );
}

const editableRoles = ["MANAGER", "MEMBER", "VIEWER", "AUDITOR"] as const;
type AccessTab = "people" | "agents" | "journal";

const accessTabs: Array<{ id: AccessTab; label: string }> = [
  { id: "people", label: "People" },
  { id: "agents", label: "Agents" },
  { id: "journal", label: "Activity log" },
];

function handleAccessTabKey(event: ReactKeyboardEvent<HTMLButtonElement>, tabID: AccessTab, setActiveTab: (tab: AccessTab) => void) {
  const currentIndex = accessTabs.findIndex((tab) => tab.id === tabID);
  if (currentIndex < 0) return;
  let nextIndex: number | null = null;
  if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % accessTabs.length;
  if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + accessTabs.length) % accessTabs.length;
  if (event.key === "Home") nextIndex = 0;
  if (event.key === "End") nextIndex = accessTabs.length - 1;
  if (nextIndex === null) return;
  event.preventDefault();
  const nextTab = accessTabs[nextIndex].id;
  setActiveTab(nextTab);
  window.requestAnimationFrame(() => document.getElementById(`access-tab-${nextTab}`)?.focus());
}

// P10b: real authorized member picker. The Access tab adds a person only from
// the live member-candidates read route
// (GET /api/v1/workspaces/{id}/member-candidates?q=<literal>) — never from a
// hand-typed principal-id. The server resolves the caller's manage
// authorization for the target workspace inside that read and returns only
// ACTIVE USER principals of the caller's own organization with an
// already_member flag, so a revoked/role-less viewer gets the honest,
// content-free closed message instead of a cached list. A candidate that is
// already a member is disabled in the list and defensively guarded again in
// the add step; the POST membership mutation itself is unchanged (csrf +
// idempotency key + If-Match against the current snapshot etag).
type MemberCandidateItem = {
  principal_id: string;
  display_name: string;
  already_member: boolean;
};

type MemberCandidateEnvelope = {
  candidates: MemberCandidateItem[];
  truncated: boolean;
};

const MEMBER_QUERY_MIN_RUNES = 2;
const MEMBER_QUERY_MAX_RUNES = 100;

function memberQueryRuneCount(value: string): number {
  // String iteration counts Unicode code points, not UTF-16 code units.
  return Array.from(value).length;
}

function AddMemberPicker({ canManage, etag, memberPrincipalIDs, onAdded, pushToast, workspaceID }: {
  canManage: boolean;
  etag: string;
  memberPrincipalIDs: Set<string>;
  onAdded: () => void;
  pushToast: (kind: "success" | "error", text: string) => void;
  workspaceID: string;
}) {
  const [term, setTerm] = useState("");
  const [results, setResults] = useState<MemberCandidateItem[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [searchState, setSearchState] = useState<"idle" | "searching" | "done">("idle");
  const [searchError, setSearchError] = useState<ApiFailure | ApiBroken | null>(null);
  const [selected, setSelected] = useState<MemberCandidateItem | null>(null);
  const [newRole, setNewRole] = useState<(typeof editableRoles)[number]>("MEMBER");
  const [busy, setBusy] = useState(false);
  const [addResult, setAddResult] = useState<ApiResult<WorkspaceSnapshot> | null>(null);

  // Every candidate read is tagged with a monotonic token. Starting a new
  // search, changing the picker context, or unmounting the picker invalidates
  // whatever read is still in flight, so a stale response can never overwrite
  // the term that is on screen right now.
  const searchToken = useRef(0);
  useEffect(() => {
    searchToken.current += 1;
    setResults(null);
    setTruncated(false);
    setSearchState("idle");
    setSearchError(null);
    setSelected(null);
    setAddResult(null);
    return () => { searchToken.current += 1; };
  }, [canManage, etag, workspaceID]);

  function onTermChange(value: string) {
    searchToken.current += 1;
    setTerm(value);
    // Synchronous invalidation of a prior choice: a candidate that was found
    // under the old term is no longer trustworthy once the query differs, so
    // the person must be re-picked from results the server returns for this
    // term.
    setSelected(null);
    setResults(null);
    setTruncated(false);
    setSearchState("idle");
    setSearchError(null);
    setAddResult(null);
  }

  async function runSearch(event: FormEvent) {
    event.preventDefault();
    const query = term.trim();
    const queryRunes = memberQueryRuneCount(query);
    if (!canManage || !etag || queryRunes < MEMBER_QUERY_MIN_RUNES || queryRunes > MEMBER_QUERY_MAX_RUNES) return;
    const token = ++searchToken.current;
    setSearchState("searching");
    setSearchError(null);
    setSelected(null);
    setResults(null);
    setTruncated(false);
    setAddResult(null);
    const result = await apiGet<MemberCandidateEnvelope>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/member-candidates?q=${encodeURIComponent(query)}`,
    );
    if (token !== searchToken.current) return; // a newer search superseded this one.
    setSearchState("done");
    if (result.kind === "ok") {
      setResults(result.value.candidates);
      setTruncated(result.value.truncated);
    } else {
      setResults(null);
      setTruncated(false);
      setSearchError(result);
    }
  }

  async function addSelected() {
    if (!selected || !etag || busy || !canManage) return;
    // Defensive duplicate guard on top of the server's already_member flag and
    // the disabled option: never POST a principal the snapshot already lists.
    if (selected.already_member || memberPrincipalIDs.has(selected.principal_id)) {
      setSelected(null);
      pushToast("error", "This person is already a workspace member.");
      return;
    }
    setBusy(true);
    setAddResult(null);
    const token = searchToken.current;
    const result = await apiMutation<WorkspaceSnapshot>(
      "POST",
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/members`,
      { principal_id: selected.principal_id, role: newRole },
      newIdempotencyKey(),
      etag,
    );
    if (token !== searchToken.current) {
      setBusy(false);
      return;
    }
    setBusy(false);
    setAddResult(result);
    if (result.kind === "ok") {
      pushToast("success", "Member added.");
      setSelected(null);
      setTerm("");
      setResults(null);
      setTruncated(false);
      setSearchState("idle");
      setNewRole("MEMBER");
      onAdded();
    } else {
      pushToast("error", closedText(result));
    }
  }

  const queryRunes = memberQueryRuneCount(term.trim());
  const searchingDisabled = queryRunes < MEMBER_QUERY_MIN_RUNES || queryRunes > MEMBER_QUERY_MAX_RUNES;

  return (
    <div className="picker-flow">
      <p className="access-form-note">Search your company directory by name or ID, then select a person to add. Existing workspace members cannot be added again.</p>
      <form className="picker-search" onSubmit={runSearch}>
        <label className="sr-only" htmlFor="member-candidate-search">Find a member by name or ID</label>
        <input
          autoComplete="off"
          disabled={busy}
          id="member-candidate-search"
          onChange={(event) => onTermChange(event.target.value)}
          placeholder="Name or ID — at least 2 characters"
          value={term}
        />
        <button className="secondary-button" disabled={searchingDisabled || searchState === "searching" || busy} type="submit">
          {searchState === "searching" ? "Searching…" : "Search"}
        </button>
      </form>

      {searchState === "idle" && !selected && <p className="picker-status">Search by a person's name or usr_… ID.</p>}
      {queryRunes > MEMBER_QUERY_MAX_RUNES && <p className="picker-status">The search is too long. Use no more than 100 characters.</p>}
      {searchState === "searching" && <p className="picker-status">Searching the directory…</p>}
      {searchState === "done" && !searchError && results !== null && results.length === 0 && (
        <p className="picker-status">No one matched “{term.trim()}”. Refine the name or ID and try again.</p>
      )}
      {searchState === "done" && searchError && <ClosedOrError result={searchError} />}

      {results !== null && !selected && (
        <>
          <div className="picker-list" role="group" aria-label="Directory search results">
            {results.map((candidate) => {
              const alreadyMember = candidate.already_member || memberPrincipalIDs.has(candidate.principal_id);
              return (
                <button
                  className="picker-option"
                  disabled={alreadyMember || busy}
                  key={candidate.principal_id}
                  onClick={() => setSelected(candidate)}
                  title={alreadyMember ? "Already a member of this workspace" : "Add this person"}
                  type="button"
                >
                  <span aria-hidden="true" className="member-avatar">{candidate.principal_id.slice(0, 2).toUpperCase()}</span>
                  <span className="picker-option-main">
                    <strong>{candidate.display_name || candidate.principal_id}</strong>
                    <small className="mono">{candidate.principal_id}</small>
                  </span>
                  {alreadyMember && <span className="picker-tag">already a member</span>}
                </button>
              );
            })}
          </div>
          {truncated && results.length > 0 && <p className="picker-status">Only the first results are shown. Refine your search to find other people.</p>}
        </>
      )}

      {selected && (
        <div className="picker-confirm" role="region" aria-label="Add selected member">
          <div className="picker-confirm-summary">
            <span aria-hidden="true" className="member-avatar">{selected.principal_id.slice(0, 2).toUpperCase()}</span>
            <div className="picker-confirm-main">
              <strong>{selected.display_name || selected.principal_id}</strong>
              <small className="mono">{selected.principal_id}</small>
            </div>
          </div>
          <div className="picker-confirm-actions">
            <label className="field">
              <span>Role</span>
              <select disabled={busy} onChange={(event) => setNewRole(event.target.value as (typeof editableRoles)[number])} value={newRole}>
                {editableRoles.map((item) => <option key={item} value={item}>{roleLabel(item)}</option>)}
              </select>
            </label>
            <button className="primary-button" disabled={busy} onClick={() => void addSelected()} type="button">
              {busy ? "Adding…" : "Add member"}
            </button>
            <button className="link-button" disabled={busy} onClick={() => setSelected(null)} type="button">Change selection</button>
          </div>
          {addResult && addResult.kind !== "ok" && <ClosedOrError result={addResult} />}
        </div>
      )}
    </div>
  );
}

function AccessView({ state, role, onChanged, pushToast, refreshVersion, workspaceID }: {
  state: WorkspaceDataState;
  role: string;
  onChanged: () => void;
  pushToast: (kind: "success" | "error", text: string) => void;
  refreshVersion: number;
  // The parent's requested workspace identity. It is deliberately kept under the
  // existing prop name for backward compatibility and is the gate for the
  // transient journal retention, while the owned identity is read from the shown
  // snapshot below.
  workspaceID: string | null;
}) {
  const [busyPrincipal, setBusyPrincipal] = useState<string | null>(null);
  const [mutationResult, setMutationResult] = useState<ApiResult<WorkspaceSnapshot> | null>(null);
  const [editingPrincipal, setEditingPrincipal] = useState<string | null>(null);
  const [roleDraft, setRoleDraft] = useState("");
  const [activeTab, setActiveTab] = useState<AccessTab>("people");
  const canManage = role === "OWNER" || role === "MANAGER";
  const snapshot = state.phase === "loaded" && state.snapshot.kind === "ok" ? state.snapshot.value : null;
  const etag = state.phase === "loaded" && state.snapshot.kind === "ok" ? state.snapshot.etag : undefined;
  // R2 journal-identity fix: the journal belongs to the workspace whose snapshot
  // is currently shown (owned identity, null during the momentary snapshot
  // reload window), while the parent's requested identity gates the transient
  // retention in useWorkspaceJournal, mirroring AskView's requestedWorkspaceID.
  const ownedWorkspaceID = snapshot?.id ?? null;
  const snapshotRejected = state.phase === "loaded" && state.snapshot.kind !== "ok" && !isTransientPageFailure(state.snapshot);
  const [journalState, loadMoreJournal, retryJournalFirstPage] = useWorkspaceJournal(ownedWorkspaceID, workspaceID, activeTab === "journal" && !snapshotRejected, refreshVersion, snapshot?.revision);
  const members = snapshot?.members ?? [];
  const memberPrincipalIDs = useMemo(() => new Set(members.map((member) => member.principal_id)), [members]);

  async function changeRole(principal: string, nextRole: string) {
    if (!snapshot || !etag || busyPrincipal !== null) return;
    setBusyPrincipal(principal);
    setMutationResult(null);
    const result = await apiMutation<WorkspaceSnapshot>(
      "PUT",
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/members/${encodeURIComponent(principal)}`,
      { role: nextRole },
      newIdempotencyKey(),
      etag,
    );
    setBusyPrincipal(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", "Role updated.");
      setEditingPrincipal(null);
      setRoleDraft("");
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  async function removeMember(principal: string) {
    if (!snapshot || !etag || busyPrincipal !== null || !window.confirm(`Remove ${principal} from the workspace?`)) return;
    setBusyPrincipal(principal);
    setMutationResult(null);
    const result = await apiMutation<WorkspaceSnapshot>(
      "DELETE",
      `/api/v1/workspaces/${encodeURIComponent(snapshot.id)}/members/${encodeURIComponent(principal)}`,
      undefined,
      newIdempotencyKey(),
      etag,
    );
    setBusyPrincipal(null);
    setMutationResult(result);
    if (result.kind === "ok") {
      pushToast("success", "Member removed.");
      onChanged();
    } else {
      pushToast("error", closedText(result));
    }
  }

  function beginRoleEdit(principal: string, currentRole: string) {
    if (busyPrincipal !== null) return;
    setMutationResult(null);
    setEditingPrincipal(principal);
    setRoleDraft(currentRole);
  }

  function cancelRoleEdit() {
    if (busyPrincipal !== null) return;
    setEditingPrincipal(null);
    setRoleDraft("");
  }

  return (
    <div className="page access-page">
      <p className="access-summary">Manage members, agents and activity in one place. Roles determine workspace access; source restrictions still apply.</p>
      <nav aria-label="Access sections" className="tabs access-tabs" role="tablist">
        {accessTabs.map((tab) => (
          <button
            aria-controls={`access-panel-${tab.id}`}
            aria-selected={activeTab === tab.id}
            className={activeTab === tab.id ? "active" : undefined}
            id={`access-tab-${tab.id}`}
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            onKeyDown={(event) => handleAccessTabKey(event, tab.id, setActiveTab)}
            role="tab"
            tabIndex={activeTab === tab.id ? 0 : -1}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {activeTab === "people" && (
        <section aria-labelledby="access-tab-people" className="access-tab-panel access-people-panel" id="access-panel-people" role="tabpanel" tabIndex={0}>
          {state.phase === "idle" && <p className="evidence-state">Select a workspace.</p>}
          {state.phase === "loading" && <p className="evidence-state">Loading members…</p>}
          {state.phase === "loaded" && state.snapshot.kind === "ok" && (
            <section aria-labelledby="workspace-members-title" className="access-section">
              <div className="access-section-head">
                <div>
                  <p className="eyebrow">Members</p>
                  <h2 id="workspace-members-title">Workspace members</h2>
                  <p>Each member receives only the permissions of their role. This form cannot change the owner's role.</p>
                </div>
                <span className="state-chip muted">{countLabel(members.length, "member", "members")}</span>
              </div>
              {canManage && etag && snapshot && (
                <details className="access-disclosure">
                  <summary>
                    <span>Add member</span>
                    <small>Select from your company directory</small>
                  </summary>
                  <AddMemberPicker
                    canManage={canManage}
                    etag={etag}
                    memberPrincipalIDs={memberPrincipalIDs}
                    onAdded={onChanged}
                    pushToast={pushToast}
                    workspaceID={snapshot.id}
                  />
                </details>
              )}
              {mutationResult && mutationResult.kind !== "ok" && <ClosedOrError result={mutationResult} />}
              <div className="member-list access-member-list">
                {members.map((member) => (
                  <article className="member-row access-member-row" key={member.principal_id}>
                    <span className="member-avatar" aria-hidden="true">{member.principal_id.slice(0, 2).toUpperCase()}</span>
                    <div className="member-main">
                      <h3>{member.display_name || member.principal_id}</h3>
                      <p className="mono">{member.principal_id}</p>
                      <p>{roleNote(member.role)}</p>
                    </div>
                    {canManage && etag && member.role !== "OWNER" ? (
                      editingPrincipal === member.principal_id ? (
                        <div className="member-actions member-role-editor">
                          <label className="sr-only" htmlFor={`role-${member.principal_id}`}>New role for {member.principal_id}</label>
                          <select disabled={busyPrincipal !== null} id={`role-${member.principal_id}`} onChange={(event) => setRoleDraft(event.target.value)} value={roleDraft}>
                            {editableRoles.map((item) => <option key={item} value={item}>{roleLabel(item)}</option>)}
                          </select>
                          <button aria-label={`Save role for ${member.principal_id}`} className="secondary-button role-save-button" disabled={busyPrincipal !== null || roleDraft === member.role} onClick={() => void changeRole(member.principal_id, roleDraft)} type="button">Save</button>
                          <button className="link-button role-cancel-button" disabled={busyPrincipal !== null} onClick={cancelRoleEdit} type="button">Cancel</button>
                        </div>
                      ) : (
                        <div className="member-actions">
                          <span className="role-badge">{roleLabel(member.role)}</span>
                          <button aria-label={`Edit role for member ${member.principal_id}`} className="link-button role-edit-button" disabled={busyPrincipal !== null} onClick={() => beginRoleEdit(member.principal_id, member.role)} type="button">Edit</button>
                          <button aria-label={`Remove member ${member.principal_id}`} className="icon-button" disabled={busyPrincipal !== null} onClick={() => void removeMember(member.principal_id)} title="Remove member" type="button">×</button>
                        </div>
                      )
                    ) : <span className="role-badge">{roleLabel(member.role)}</span>}
                  </article>
                ))}
              </div>
            </section>
          )}
          {state.phase === "loaded" && state.snapshot.kind !== "ok" && <ClosedOrError result={state.snapshot} />}
        </section>
      )}

      {activeTab === "agents" && (
        <div aria-labelledby="access-tab-agents" className="access-tab-panel" id="access-panel-agents" role="tabpanel" tabIndex={0}>
          {role === "OWNER" && snapshot ? (
            <AccessCodesPanel key={snapshot.id} pushToast={pushToast} workspaceID={snapshot.id} />
          ) : (
            <section className="access-tab-empty">
              <h2>MCP access codes</h2>
              {role !== "OWNER" ? <p>Only the workspace owner can create and revoke access codes.</p> : state.phase === "loading" ? <p>Loading workspace…</p> : state.phase === "idle" ? <p>Select a workspace.</p> : state.snapshot.kind !== "ok" ? <ClosedOrError result={state.snapshot} /> : null}
            </section>
          )}
        </div>
      )}

      {activeTab === "journal" && (
        <div aria-labelledby="access-tab-journal" className="access-tab-panel access-journal-panel" id="access-panel-journal" role="tabpanel" tabIndex={0}>
          {ownedWorkspaceID === null
            ? state.phase === "loaded" && state.snapshot.kind !== "ok"
              ? <ClosedOrError result={state.snapshot} />
              : <p className="evidence-state">Checking activity log access…</p>
            : <AuditView key={ownedWorkspaceID} journalState={journalState} members={members} onLoadMore={loadMoreJournal} onRetryFirstPage={retryJournalFirstPage} workspaceID={ownedWorkspaceID} />}
        </div>
      )}

      <aside className="plain-note">
        <span aria-hidden="true"><IconInfo /></span>
        <p>Organization administrators do not automatically gain access to documents. Access to the security log requires a separate permission.</p>
      </aside>
    </div>
  );
}

// IssueAccessCodeDialog is the one-screen issue window the task contract
// asks for: create -> show once -> hide, all inside a single modal. It never
// re-opens once dismissed -- the code is gone from memory the moment "Hide"
// closes it, matching AccessCode never carrying the raw code again.
function IssueAccessCodeDialog({ workspaceID, onClose, onIssued, pushToast }: {
  workspaceID: string;
  onClose: () => void;
  onIssued: () => void;
  pushToast: (kind: "success" | "error", text: string) => void;
}) {
  const [name, setName] = useState("");
  const [ttlDays, setTtlDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [issueResult, setIssueResult] = useState<ApiResult<AccessCodeIssued> | null>(null);
  const [justIssued, setJustIssued] = useState<AccessCodeIssued | null>(null);
  const dialogRef = useModalDialog(onClose, busy);

  async function issue(event: FormEvent) {
    event.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    setIssueResult(null);
    const result = await apiPost<AccessCodeIssued>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/access-codes`,
      { name: name.trim(), workspace_ids: [workspaceID], ttl_seconds: ttlDays * 86400 },
      newIdempotencyKey(),
    );
    setBusy(false);
    setIssueResult(result);
    if (result.kind === "ok") {
      pushToast("success", `Access code “${result.value.name}” created.`);
      setJustIssued(result.value);
      onIssued();
    } else {
      pushToast("error", closedText(result));
    }
  }

  return (
    <div className="sheet-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose(); }} role="presentation">
      <section aria-labelledby="issue-code-title" aria-modal="true" className="issue-code-dialog" ref={dialogRef} role="dialog" tabIndex={-1}>
        <header className="sheet-header">
          <div>
            <p className="eyebrow">MCP access codes for agents</p>
            <h2 id="issue-code-title">{justIssued ? "Code created" : "New access code"}</h2>
          </div>
          <button aria-label="Close" className="close-button" disabled={busy} onClick={onClose} type="button">×</button>
        </header>
        <div className="sheet-body issue-code-body">
          {justIssued ? (
            <>
              <p><strong>This code is shown only once. Copy it now:</strong></p>
              <code className="mono access-code-value">{justIssued.code}</code>
              <p>Connect using this code:</p>
              <pre className="mono access-code-snippet">{`claude mcp add knowvault --transport http <server-url>/api/v1/mcp \\\n  --header "Authorization: Bearer ${justIssued.code}"`}</pre>
              <footer className="sheet-footer">
                <button className="primary-button" onClick={onClose} type="button">Hide</button>
              </footer>
            </>
          ) : (
            <form onSubmit={issue}>
              <p>An agent connects with an access code and can access only this workspace. Each question and citation read is recorded in the activity log with the SERVICE actor type and code name.</p>
              <label className="field"><span>Name</span><input autoFocus maxLength={256} onChange={(event) => setName(event.target.value)} placeholder="For example, Department assistant" required value={name} /></label>
              <label className="field"><span>Lifetime in days</span><input max={180} min={1} onChange={(event) => setTtlDays(Number(event.target.value) || 1)} type="number" value={ttlDays} /></label>
              {issueResult && issueResult.kind !== "ok" && <ClosedOrError result={issueResult} />}
              <footer className="sheet-footer">
                <button className="secondary-button" disabled={busy} onClick={onClose} type="button">Cancel</button>
                <button className="primary-button" disabled={!name.trim() || busy} type="submit">{busy ? "Creating…" : "Create access code"}</button>
              </footer>
            </form>
          )}
        </div>
      </section>
    </div>
  );
}

// MetricDefinitionsPanel is R2 Outcome 1's owner control for versioned metric
// definitions: an OWNER drafts a definition and approves the current DRAFT,
// inside the existing Sources layout with the existing styles and
// loading/empty/error/denied state conventions. The list is a protected read
// for any workspace member; drafting and approval use the additive REST write
// routes and re-check access server-side. Missing fields render “no data”,
// never an invented value.
function MetricDefinitionsPanel({ workspaceID, canApprove, pushToast }: {
  workspaceID: string;
  canApprove: boolean;
  pushToast: (kind: "success" | "error", text: string) => void;
}) {
  const [definitions, setDefinitions] = useState<MetricDefinition[] | null>(null);
  const [listResult, setListResult] = useState<ApiResult<MetricDefinitionList> | null>(null);
  // A transient same-scope refresh failure (status 0 or >=500) with a list that
  // is already on screen is surfaced as its own refresh-error state instead of
  // as the initial-load ClosedOrError, so every shown definition row stays
  // visible and the single retry re-runs the same protected list read. It is
  // cleared by a successful read and by a fail-closed denial.
  const [refreshError, setRefreshError] = useState(false);
  // R2 superseded-read guard: every reload captures a monotonic request epoch
  // before the awaited protected read and commits nothing — not the
  // definitions, not the list result, not the refresh-error state — once a
  // newer read or a workspace change has advanced the epoch. The workspace
  // effect below bumps the epoch in cleanup, so a response fetched for one
  // workspace can never render in another workspace's panel and is never
  // retained as a shown list.
  const requestEpochRef = useRef(0);
  const [busy, setBusy] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [sourceConnectionID, setSourceConnectionID] = useState("");
  const [projectionVersion, setProjectionVersion] = useState(1);
  const [entityKey, setEntityKey] = useState("");
  const [grain, setGrain] = useState("MONTH");
  const [allowedFilters, setAllowedFilters] = useState("");
  const [unit, setUnit] = useState("");

  async function reload() {
    const epoch = ++requestEpochRef.current;
    const result = await apiGet<MetricDefinitionList>(`/api/v1/workspaces/${encodeURIComponent(workspaceID)}/metric-definitions`);
    // A superseded response is abandoned whole: it commits neither the
    // protected rows nor the list result nor the refresh-error state, so a late
    // answer can never overwrite a newer one or surface a stale failure.
    if (requestEpochRef.current !== epoch) return;
    if (result.kind === "ok") {
      setDefinitions(result.value.definitions);
      setListResult(result);
      setRefreshError(false);
      return;
    }
    // A transient same-scope refresh failure keeps the definitions that are
    // already shown (and the last good result that renders them) and surfaces
    // the failure as the distinct refresh-error state, never as the initial-load
    // error block. Every other refusal — or a transient failure with no shown
    // list — fails closed exactly as before and drops the protected rows.
    if (isTransientPageFailure(result) && listResult?.kind === "ok" && definitions !== null) {
      setRefreshError(true);
      return;
    }
    setDefinitions(null);
    setListResult(result);
    setRefreshError(false);
  }

  useEffect(() => {
    void reload();
    // A workspace change invalidates every in-flight read of the previous
    // workspace, so its response can never commit against the new panel.
    return () => { requestEpochRef.current += 1; };
  }, [workspaceID]);

  async function createDraft(event: FormEvent) {
    event.preventDefault();
    if (busy || !id.trim() || !name.trim() || !sourceConnectionID.trim() || !entityKey.trim()) return;
    setBusy(true);
    const result = await apiPost<MetricDefinition>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/metric-definitions:draft`,
      {
        id: id.trim(),
        name: name.trim(),
        source_connection_id: sourceConnectionID.trim(),
        projection_version: projectionVersion,
        entity_key: entityKey.trim(),
        grain,
        allowed_filters: allowedFilters.split(",").map((item) => item.trim()).filter(Boolean),
        unit: unit.trim(),
      },
      newIdempotencyKey(),
    );
    setBusy(false);
    if (result.kind === "ok") {
      pushToast("success", "Metric definition draft created.");
      setFormOpen(false);
      void reload();
    } else {
      pushToast("error", closedText(result));
    }
  }

  async function approve(definition: MetricDefinition) {
    const metricID = definition.id;
    if (busy || !metricID || !window.confirm(`Approve the draft definition “${metricID}”? An approved version is immutable.`)) return;
    setBusy(true);
    const result = await apiAction<MetricDefinition>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/metric-definitions/${encodeURIComponent(metricID)}:approve`,
      newIdempotencyKey(),
    );
    setBusy(false);
    if (result.kind === "ok") {
      pushToast("success", "Definition version approved.");
      void reload();
    } else {
      pushToast("error", closedText(result));
    }
  }

  return (
    <section aria-labelledby="metric-definitions-title" className="access-section">
      <div className="access-section-head">
        <div>
          <p className="eyebrow">Metric definitions</p>
          <h2 id="metric-definitions-title">Metric definition versions</h2>
          <p>A definition links a metric to a source and an exact projection version. Approved versions are immutable; changes create a new version.</p>
        </div>
        {canApprove && (
          <button className="primary-button" onClick={() => setFormOpen((value) => !value)} type="button">
            {formOpen ? "Hide form" : "New draft"}
          </button>
        )}
      </div>

      {canApprove && formOpen && (
        <form className="verify-trust-form" onSubmit={createDraft}>
          <label className="field"><span>ID</span><input maxLength={256} onChange={(event) => setId(event.target.value)} required value={id} /></label>
          <label className="field"><span>Name</span><input maxLength={200} onChange={(event) => setName(event.target.value)} required value={name} /></label>
          <label className="field"><span>Source connection</span><input maxLength={256} onChange={(event) => setSourceConnectionID(event.target.value)} required value={sourceConnectionID} /></label>
          <label className="field"><span>Projection version</span><input min={1} onChange={(event) => setProjectionVersion(Number(event.target.value) || 1)} required type="number" value={projectionVersion} /></label>
          <label className="field"><span>Entity key</span><input maxLength={256} onChange={(event) => setEntityKey(event.target.value)} required value={entityKey} /></label>
          <label className="field"><span>Period granularity</span>
            <select onChange={(event) => setGrain(event.target.value)} value={grain}>
              {Object.keys(metricGrainLabels).map((value) => <option key={value} value={value}>{metricGrainLabels[value]}</option>)}
            </select>
          </label>
          <label className="field"><span>Allowed filters (comma-separated)</span><input onChange={(event) => setAllowedFilters(event.target.value)} value={allowedFilters} /></label>
          <label className="field"><span>Unit of measure</span><input maxLength={64} onChange={(event) => setUnit(event.target.value)} value={unit} /></label>
          <div className="verify-trust-actions">
            <button className="secondary-button" disabled={busy} onClick={() => setFormOpen(false)} type="button">Cancel</button>
            <button className="primary-button" disabled={busy || !id.trim() || !name.trim() || !sourceConnectionID.trim() || !entityKey.trim()} type="submit">{busy ? "Saving…" : "Create draft"}</button>
          </div>
        </form>
      )}

      {!refreshError && listResult && listResult.kind !== "ok" && <ClosedOrError result={listResult} />}
      {definitions === null && listResult === null && <p className="evidence-state">Loading definitions…</p>}
      {definitions !== null && listResult?.kind === "ok" && definitions.length === 0 && (
        <div className="empty-runs">
          <span className="empty-symbol" aria-hidden="true"><IconSources /></span>
          <div>
            <strong>No metric definitions yet.</strong>
            <p>{canApprove ? "Create and approve a draft so questions can use the definition." : "Ask the workspace owner to create and approve a definition."}</p>
          </div>
        </div>
      )}
      {definitions !== null && listResult?.kind === "ok" && definitions.length > 0 && (
        <ul className="source-rows">
          {definitions.map((definition, index) => {
            const status = definition.status ?? "";
            const approvable = canApprove && status === "DRAFT";
            const dot = status === "APPROVED" ? "ready" : status === "RETIRED" ? "disconnected" : "attention";
            return (
              <li className="source-row" key={`${definition.id ?? "definition"}-${definition.version ?? index}`}>
                <span className={`dot dot-${dot}`} aria-hidden="true" />
                <div className="source-row-main">
                  <div className="source-title-row">
                    <b>{metricDefinitionField(definition.id)}</b>
                    <span className="state-chip muted">{metricDefinitionField(definition.name)}</span>
                    <span className={`state-chip ${status === "APPROVED" ? "ready" : status === "RETIRED" ? "muted" : "attention"}`}>
                      {metricDefinitionStatusLabels[status] ?? (status || "no data")}
                    </span>
                  </div>
                  <p className="source-note">
                    Version: {metricDefinitionField(definition.version)} · Source: {metricDefinitionField(definition.source_connection_id)} · Projection: {metricDefinitionField(definition.projection_version)} · Entity: {metricDefinitionField(definition.entity_key)} · Period: {definition.grain ? (metricGrainLabels[definition.grain] ?? definition.grain) : "no data"} · Unit: {metricDefinitionField(definition.unit)} · Filters: {metricDefinitionFilters(definition.allowed_filters)}
                  </p>
                </div>
                <div className="source-row-actions">
                  {approvable && <button className="primary-button" disabled={busy} onClick={() => void approve(definition)} type="button">Approve</button>}
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {/* R2 refresh/retry split: a transient same-scope refresh failure with a
          list already on screen keeps every shown definition row and is worded
          as its own refresh failure, with exactly one retry that re-runs the
          same protected list read (reload). The initial-load failure and every
          401/403 denial still render through ClosedOrError above. */}
      {refreshError && (
        <div>
          <p className="evidence-state">Could not refresh metric definitions.</p>
          <button className="secondary-button" onClick={() => void reload()} type="button">Retry</button>
        </div>
      )}
    </section>
  );
}

// AccessCodesPanel is the V1-C agent access-code control: an OWNER creates a
// named SERVICE principal scoped to this workspace with a bounded TTL, sees
// the raw code exactly once, and can revoke it later. It never reuses
// apiMutation (which always sends If-Match): the access-code REST actions
// carry no workspace configuration-hash precondition at all.
function AccessCodesPanel({ workspaceID, pushToast }: { workspaceID: string; pushToast: (kind: "success" | "error", text: string) => void }) {
  const [codes, setCodes] = useState<AccessCode[] | null>(null);
  const [listResult, setListResult] = useState<ApiResult<{ access_codes: AccessCode[] }> | null>(null);
  const [busy, setBusy] = useState(false);
  const [issueDialogOpen, setIssueDialogOpen] = useState(false);
  const [clock, setClock] = useState(() => Date.now());

  useEffect(() => {
    const futureExpiries = (codes ?? [])
      .filter((item) => !item.revoked_at)
      .map((item) => new Date(item.expires_at).getTime())
      .filter((expiresAt) => Number.isFinite(expiresAt) && expiresAt > clock);
    if (futureExpiries.length === 0) return;
    const nextExpiry = Math.min(...futureExpiries);
    const delay = Math.max(1000, Math.min(nextExpiry - clock, 60_000));
    const timer = window.setTimeout(() => setClock(Date.now()), delay);
    return () => window.clearTimeout(timer);
  }, [codes, clock]);

  async function reload() {
    const result = await apiGet<{ access_codes: AccessCode[] }>(`/api/v1/workspaces/${encodeURIComponent(workspaceID)}/access-codes`);
    setListResult(result);
    if (result.kind === "ok") setCodes(result.value.access_codes);
  }

  useEffect(() => { void reload(); }, [workspaceID]);

  async function revoke(credentialID: string) {
    if (busy || !window.confirm("Revoke this access code? This cannot be undone.")) return;
    setBusy(true);
    const result = await apiAction<{ revoked: boolean }>(
      `/api/v1/workspaces/${encodeURIComponent(workspaceID)}/access-codes/${encodeURIComponent(credentialID)}:revoke`,
      newIdempotencyKey(),
    );
    setBusy(false);
    if (result.kind === "ok") {
      pushToast("success", "Access code revoked.");
      void reload();
    } else {
      pushToast("error", closedText(result));
    }
  }

  return (
    <section className="access-codes-panel">
      <div className="access-codes-head">
        <div>
          <p className="eyebrow">Agent connections</p>
          <h3>MCP access codes</h3>
          <p>An agent connects with an access code and can access only this workspace.</p>
        </div>
        <div className="access-codes-actions">
          {codes !== null && <span className="state-chip muted">{countLabel(codes.length, "code", "codes")}</span>}
          <button className="primary-button" onClick={() => setIssueDialogOpen(true)} type="button">Create access code</button>
        </div>
      </div>
      {listResult && listResult.kind !== "ok" && <ClosedOrError result={listResult} />}

      {codes && codes.length === 0 && (
        <div className="access-codes-empty">
          <strong>No agent connections yet.</strong>
          <p>Create a separate code for each agent to track its activity and revoke its access when needed.</p>
        </div>
      )}
      {codes && codes.length > 0 && (
        <div className="member-list access-member-list">
          {codes.map((item) => {
            const state = accessCodeState(item, clock);
            return (
              <article className="member-row access-member-row" key={item.credential_id}>
                <span className="member-avatar" aria-hidden="true">{item.name.slice(0, 2).toUpperCase()}</span>
                <div className="member-main">
                  <h3>{item.name}</h3>
                  <p>Created {formatTime(item.created_at)} · expires {formatTime(item.expires_at)}</p>
                </div>
                <span className={`state-chip ${state === "ACTIVE" ? "ready" : state === "EXPIRED" ? "attention" : "muted"}`}>{state === "REVOKED" ? `Revoked ${formatTime(item.revoked_at!)}` : state === "EXPIRED" ? "Expired" : "Active"}</span>
                {state === "ACTIVE" && <button aria-label={`Revoke code “${item.name}”`} className="danger-button access-code-revoke" disabled={busy} onClick={() => void revoke(item.credential_id)} type="button">Revoke</button>}
              </article>
            );
          })}
        </div>
      )}

      {issueDialogOpen && (
        <IssueAccessCodeDialog
          onClose={() => { setIssueDialogOpen(false); void reload(); }}
          onIssued={() => void reload()}
          pushToast={pushToast}
          workspaceID={workspaceID}
        />
      )}
    </section>
  );
}

function isSearchAuditEvent(event: JournalEntry): boolean {
  return event.metadata.reason_codes?.includes("WORKSPACE_SEARCH_REQUEST") === true
    || event.error_code === "WORKSPACE_SEARCH_DENIED" || event.error_code === "WORKSPACE_SEARCH_READ_FAILED";
}

function auditEventCategory(event: JournalEntry): string {
  const action = event.action;
  if (isSearchAuditEvent(event)) return "requests";
  if (action.startsWith("question.") || action.startsWith("search.profile_call_") || action.startsWith("model_run.") || action.startsWith("source.governed_query_")) return "requests";
  if (action.startsWith("evidence.") || action === "citation.opened" || action.startsWith("source.metadata.read.")) return "reads";
  if (action.startsWith("identity.") || action.startsWith("session.") || action.startsWith("policy.") || action.startsWith("workspace.member_") || action === "workspace.role_changed") return "access";
  return "other";
}

function AuditView({ journalState, members, onLoadMore, onRetryFirstPage, workspaceID }: { journalState: JournalState; members: MemberResponse[]; onLoadMore: () => void; onRetryFirstPage: () => void; workspaceID: string | null }) {
  const [category, setCategory] = useState("all");
  const [actor, setActor] = useState("all");
  const [outcome, setOutcome] = useState("all");
  const journal = workspaceID !== null && journalState.phase === "loaded" && journalState.result !== null && journalState.result.kind === "ok" && journalState.result.value.workspace_id === workspaceID ? journalState.result.value : null;
  const events = journal ? journalState.events : [];
  const shownEvents = events.filter((event) => (category === "all" || auditEventCategory(event) === category)
    && (actor === "all" || event.actor_type === actor) && (outcome === "all" || event.outcome === outcome));
  function actorName(event: JournalEntry): string {
    const member = members.find((item) => item.principal_id === event.actor_principal_id);
    return member?.display_name ? `${member.display_name} · ${auditActorTypeLabels[event.actor_type] ?? event.actor_type}` : auditActorLabel(event);
  }

  return (
    <section aria-labelledby="audit-view-title" className="audit-view">
      <div className="audit-title-row">
        <div className="audit-title-copy">
          <h2 id="audit-view-title">Activity log</h2>
          <p>Question text is not stored in the audit log.</p>
          {journal && <p className="audit-scope-note">{`Showing ${shownEvents.length} of ${events.length} loaded events for this workspace${journalState.nextCursor !== null ? "; use Show more for earlier events" : ""}.`}</p>}
        </div>
      </div>

      {journalState.phase === "idle" && <p className="evidence-state">{workspaceID === null ? "Select a workspace." : "Checking activity log access…"}</p>}
      {journalState.phase === "loading" && <p className="evidence-state">Checking activity log access…</p>}
      {journal && (
        <>
          <div className="audit-filters">
            <label className="field"><span>Actions</span><select value={category} onChange={(event) => setCategory(event.target.value)}>
              <option value="all">All actions</option><option value="requests">Questions and search</option><option value="reads">Data reads</option><option value="access">Access</option><option value="other">Changes and maintenance</option>
            </select></label>
            <label className="field"><span>Actor</span><select value={actor} onChange={(event) => setActor(event.target.value)}>
              <option value="all">All</option><option value="HUMAN">People</option><option value="SERVICE">Agents</option><option value="CONNECTOR">Connectors</option><option value="SYSTEM">System</option>
            </select></label>
            <label className="field"><span>Outcome</span><select value={outcome} onChange={(event) => setOutcome(event.target.value)}>
              <option value="all">All outcomes</option><option value="SUCCESS">Succeeded</option><option value="DENIED">Denied</option><option value="FAILED">Failed</option>
            </select></label>
          </div>
          {/* R2 F1: for a workspace with zero events the organization-wide chain head
              must not read as this workspace's continuous chain, so the integrity panel
              is omitted entirely and only the empty-workspace state remains. */}
          {events.length > 0 && (
          <details className="audit-integrity">
            <summary>
              <span className="audit-integrity-copy">
                <strong>Integrity verification data</strong>
                <small>Organization-wide audit chain</small>
              </span>
              <span className="audit-integrity-sequence">Through #{journal.head_sequence}</span>
            </summary>
            <div className="chain-proof">
              <span>Sequence</span>
              <strong>#{journal.head_sequence}</strong>
              <code className="mono" title={journal.head_hash}>{journal.head_hash}</code>
              <p className="muted">Workspace events are a filtered subset, not a continuous chain. The chain head belongs to the whole organization.</p>
            </div>
          </details>
          )}
          {events.length === 0 ? (
            <div className="empty-runs">
              <span className="empty-symbol" aria-hidden="true"><IconJournal /></span>
              <div>
                <strong>No events in this workspace yet.</strong>
              </div>
            </div>
          ) : shownEvents.length === 0 ? (
            <p className="evidence-state">No loaded events match. Change the filters{journalState.nextCursor !== null ? " or load earlier events" : ""}.</p>
          ) : (
            <div className="audit-list" aria-label="Activity events">
              {shownEvents.map((event) => (
                <article className="audit-event" key={event.event_id}>
                  <time dateTime={event.occurred_at}>{formatTime(event.occurred_at)}</time>
                  <div className="audit-line" aria-hidden="true"><span /></div>
                  <div className="audit-content">
                    <p>
                      <strong>{isSearchAuditEvent(event) ? "Search query" : auditActionLabel(event.action)}</strong>{" "}
                      <span className={`state-chip ${event.outcome === "SUCCESS" ? "ready" : event.outcome === "DENIED" ? "attention" : "muted"}`}>
                        {outcomeLabel(event.outcome)}
                      </span>
                    </p>
                    <small>Actor: {actorName(event)}</small>
                    {event.error_code && <p className="audit-error">{event.error_code}</p>}
                    <details className="audit-details">
                      <summary>Technical details</summary>
                      <dl className="audit-detail-list">
                        <div><dt>Action</dt><dd className="mono">{event.action}</dd></div>
                        <div><dt>Resource</dt><dd>{event.resource_type} · <span className="mono">{event.resource_id}</span></dd></div>
                        <div><dt>Event</dt><dd className="mono">{event.event_id} · sequence #{event.sequence}</dd></div>
                        <div><dt>Request ID</dt><dd className="mono">{event.request_id}</dd></div>
                        {event.actor_principal_id && <div><dt>Principal ID</dt><dd className="mono">{event.actor_principal_id}</dd></div>}
                        {event.policy_decision_id && <div><dt>Policy decision</dt><dd className="mono">{event.policy_decision_id}</dd></div>}
                        {event.on_behalf_of_principal_id && <div><dt>On behalf of</dt><dd className="mono">{event.on_behalf_of_principal_id}</dd></div>}
                        {event.error_code && <div><dt>Error code</dt><dd className="mono">{event.error_code}</dd></div>}
                        {event.metadata.reason_codes && event.metadata.reason_codes.length > 0 && (
                          <div><dt>Reason</dt><dd>{event.metadata.reason_codes.map((reason) => <span className="audit-reason" key={reason}>{auditReasonLabel(reason)} <code className="mono" title={reason}>{reason}</code></span>)}</dd></div>
                        )}
                        <div><dt>Organization chain hashes</dt><dd className="mono audit-hash-detail"><span>previous in organization chain: {event.previous_event_hash}</span><span>this event in organization chain: {event.event_hash}</span><span>These hashes belong to the whole organization's chain. Workspace events are a filtered subset, not a continuous chain.</span></dd></div>
                      </dl>
                    </details>
                  </div>
                </article>
              ))}
            </div>
          )}
          {/* R2 refresh/continuation retry split: a transient page failure
              surfaces as continuation "refresh-error" for a first-page refresh
              and "error" for a real continuation, with the shown page and its
              exact cursor retained. A refresh failure is retried as a first page
              (reloadFirstPage) even while the retained page still ends at a
              cursor, so it can never be answered by consuming that cursor with a
              before_sequence append; a real continuation failure retries the
              exact retained cursor via onLoadMore. A retained page with no cursor
              left (an initial load that failed, or a page that ends the list)
              falls back to the first-page retry. A fail-closed 401/403/404 resets
              the continuation to "idle", so no retry control is offered there. */}
          {(journalState.nextCursor !== null
            || journalState.continuation === "error"
            || journalState.continuation === "refresh-error") && (
            <div>
              {journalState.continuation === "error" && (
                <p className="evidence-state">Could not load more conversations.</p>
              )}
              {journalState.continuation === "refresh-error" && (
                <p className="evidence-state">
                  {journalState.events.length > 0
                    ? "Could not refresh the activity log. Previously loaded events are still shown; only the refresh failed."
                    : "Could not refresh the activity log. The retry also failed."}
                </p>
              )}
              {journalState.continuation === "refresh-error" ? (
                <button
                  className="secondary-button"
                  onClick={onRetryFirstPage}
                  type="button"
                >
                  Retry
                </button>
              ) : journalState.nextCursor === null ? (
                <button
                  className="secondary-button"
                  onClick={onRetryFirstPage}
                  type="button"
                >
                  Retry
                </button>
              ) : (
                <button
                  className="secondary-button"
                  disabled={journalState.continuation === "pending"}
                  onClick={onLoadMore}
                  type="button"
                >
                  {journalState.continuation === "pending" ? "Loading…" : journalState.continuation === "error" ? "Retry" : "Show more"}
                </button>
              )}
            </div>
          )}
        </>
      )}
      {journalState.phase === "loaded" && journalState.result !== null && journalState.result.kind !== "ok" && <ClosedOrError result={journalState.result} />}
    </section>
  );
}

// R2 Outcome 3: mount only when a real document root exists. The same module
// is imported by the in-tree answer-result panel probe (which runs under node
// and has no DOM), so an unconditional createRoot would make the pure panel
// projection untestable; browser rendering is unchanged.
const rootElement = typeof document === "undefined" ? null : document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(<App />);
}
