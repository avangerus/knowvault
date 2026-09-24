package workspaceapi

// This adapter exposes the read-only Model Context Protocol envelope over the
// authenticated API boundary. It delegates every question to the same
// QuestionService used by the browser route; it cannot execute SQL, mutate a
// workspace or bypass evidence authorization.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

type mcpRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id"`
	Method  string         `json:"method"`
	Params  jsontext.Value `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id"`
	Result  any            `json:"result,omitempty"`
	Error   *mcpError      `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// Data is R2 Outcome 2's additive, optional member. A typed QueryIntent
	// refusal carries its server-owned, closed-dictionary clarification under
	// data.clarification; every other error leaves Data nil, so its JSON-RPC
	// error object keeps exactly its pre-R2 shape.
	Data *mcpErrorClarification `json:"data,omitempty"`
}

// mcpErrorClarification is the only member this adapter adds to a JSON-RPC
// error object: a content-free refusal text the client may show a human.
type mcpErrorClarification struct {
	Clarification string `json:"clarification"`
}

type mcpToolCallParams struct {
	Name      string         `json:"name"`
	Arguments jsontext.Value `json:"arguments,omitempty"`
}

type mcpQuestionArguments struct {
	WorkspaceID    string `json:"workspace_id"`
	ConversationID string `json:"conversation_id,omitempty"`
	Question       string `json:"question"`
	AnswerMode     string `json:"answer_mode,omitempty"`
}

type mcpConversationArguments struct {
	WorkspaceID    string `json:"workspace_id"`
	ConversationID string `json:"conversation_id,omitempty"`
}

// mcpEvidenceArguments is the closed, two-field argument envelope for the
// knowvault_evidence_get tool. It mirrors the REST evidenceGet route's inputs:
// the requesting workspace and the immutable fragment/citation id.
type mcpEvidenceArguments struct {
	WorkspaceID string `json:"workspace_id"`
	FragmentID  string `json:"fragment_id"`
}

// mcpEvidenceReadArguments is the closed argument envelope for the canonical
// knowvault_read tool (compatibility name knowvault_evidence_read): the same
// workspace/fragment selector as
// knowvault_evidence_get plus an explicit window over the canonical fragment
// text (offset and limit are UTF-8 byte offsets; both are optional) and an
// optional caller-supplied span hash the stored whole-fragment hash must equal.
// A negative offset or limit is rejected before any read; an unknown member is
// rejected by the decoder.
//
// Address is the optional canonical internal/address value (R3a-1 KV-A01c). It
// is parsed with address.Parse, selects the object when fragment_id is absent,
// must name the same source/object/version as the authorized fragment, and its
// span hash is verified against the fragment's canonical text before any page
// is served. A malformed, mismatching or tampered address is refused with a
// typed, content-free error.
type mcpEvidenceReadArguments struct {
	WorkspaceID      string `json:"workspace_id"`
	FragmentID       string `json:"fragment_id"`
	Address          string `json:"address"`
	Offset           int64  `json:"offset"`
	Limit            int64  `json:"limit"`
	ExpectedSpanHash string `json:"expected_span_hash"`
	// Cursor is the optional whole-object page cursor (R3a-1 KV-A02a). Its
	// presence -- even as the empty string, which requests the first page --
	// switches the read from one fragment to the whole source version, whose
	// ordinal-ordered canonical text is returned page by page with a stable
	// cursor and the shared canonical whole-original hash. It is accepted by the
	// server-side decoder and advertised in tools/list, exactly like Address.
	Cursor *string `json:"cursor"`
	// IncludeTextBase64 is the optional additive switch that restores the exact
	// page bytes as the structuredContent text_base64 member for a caller that
	// genuinely wants them. It defaults to false: the text member already
	// carries the exact page text and the compact content[].text channel carries
	// the page itself, so the default response no longer duplicates every page
	// as text plus base64 plus the JSON envelope.
	IncludeTextBase64 bool `json:"include_text_base64"`
}

// The two question tools a V1-C SERVICE principal (agent access code) is
// authorized for, per ADR-0079 §3, plus the workspace knowledge tools R3a-1
// adds around them. mcpServiceKnowledgeTool is the single allow-list that keeps
// tools/list and tools/call on the same set: an agent is shown exactly the
// knowledge tools it may invoke, and every administrative tool stays closed.
const (
	mcpToolQuestion    = "knowvault_question"
	mcpToolEvidenceGet = "knowvault_evidence_get"
)

// mcpToolEvidenceRead is the canonical, paged read of one evidence fragment or
// whole object (R3a-1 Outcome 1; design item 4: knowvault_read by address,
// paged). It resolves through the same authorized Evidence viewer
// (handler.evidence.Read) as knowvault_evidence_get, so admission-before-data
// and the citation.opened outcome audit stay unchanged and no new read path is
// introduced; it only adds an explicit window (offset/limit, next_offset,
// has_more, no silent truncation), the whole-fragment text hash and an address
// naming source, version, object and the fragment's exact span.
const mcpToolEvidenceRead = "knowvault_read"

// mcpToolEvidenceReadCompat is the former advertised name of the same paged
// address-read tool, kept dispatchable for backward compatibility (a client
// that pinned the pre-rename name still reaches the byte-identical
// mcpEvidenceReadPage core with unchanged parameters, projection, pagination
// and error codes). It is deliberately not advertised in mcpToolCatalog: the
// canonical name above is the only one tools/list offers. This mirrors the
// accepted KV-A02b inventory rename.
const mcpToolEvidenceReadCompat = "knowvault_evidence_read"

// Page bounds for knowvault_read. A caller that omits limit gets one
// default page and an explicit next_offset while more remains; a caller that
// asks for more than the maximum is served the maximum page and told so
// through limit/has_more/next_offset rather than silently truncated.
const (
	mcpEvidenceReadDefaultLimit = 4096
	mcpEvidenceReadMaxLimit     = 65536
)

// EvidenceWholeObject is the optional whole-object read capability the paged
// evidence read composes when a request carries a page cursor (R3a-1 Outcome 1 /
// KV-A02a). It is deliberately separate from EvidenceService so every existing
// EvidenceService implementation -- including the REST read boundary and the
// test fakes -- stays source compatible: a service that does not implement it
// leaves whole-object paging failing closed as service unavailable rather than
// widening the required interface. The production *evidence.Viewer implements
// it.
type EvidenceWholeObject interface {
	ReadObject(context.Context, database.AccessContext, string, string) (evidence.WholeObject, error)
}

// evidenceWholeObjectCapability exposes the optional whole-object capability to
// the read core without widening EvidenceService, so a fragment-only service
// keeps serving single-fragment reads and refuses whole-object paging
// content-free.
func (handler *Handler) evidenceWholeObjectCapability() (EvidenceWholeObject, bool) {
	if handler == nil || handler.evidence == nil {
		return nil, false
	}
	capability, ok := handler.evidence.(EvidenceWholeObject)
	return capability, ok
}

// ADR-0087 §1 confirmation tools exposed over the MCP surface. They are the MCP
// equivalent of the REST confirmation-authority actions composed in
// workspaceapi.go (confirmGrantIssue, confirmGrantRevoke, managedSourceConfirm,
// managedConfirmationRevoke): each reaches the same injected WorkspaceAuthority
// runtime, the same ADR-0053 role rules, the same idempotency contract and the
// same content-free error surface. The operator names only the workspace and
// the operation-specific closed body fields; organization and idempotency key
// stay server-derived. No new authority model or bypass is introduced.
const (
	mcpToolConfirmationGrantIssue    = "knowvault_confirmation_grant_issue"
	mcpToolConfirmationGrantRevoke   = "knowvault_confirmation_grant_revoke"
	mcpToolManagedSourceConfirm      = "knowvault_managed_source_confirm"
	mcpToolManagedConfirmationRevoke = "knowvault_managed_confirmation_revoke"
)

// ADR-0087 §2 tool: the MCP equivalent of the REST
// sources/connections/{id}:verify-trust action. It reaches the same injected
// ConnectionTrustAuthority runtime, the same CONNECTOR_ADMIN policy gate, the
// same idempotency contract and the same content-free error surface.
const mcpToolVerifyConnectionTrust = "knowvault_verify_connection_trust"

type mcpVerifyConnectionTrustArguments struct {
	ConnectionID              string `json:"connection_id"`
	AttestedConnectorIdentity string `json:"attested_connector_identity"`
	AttestedBy                string `json:"attested_by"`
	AttestedAt                string `json:"attested_at"`
}

func (arguments mcpVerifyConnectionTrustArguments) valid() bool {
	return arguments.ConnectionID != "" && arguments.AttestedConnectorIdentity != "" &&
		arguments.AttestedBy != "" && arguments.AttestedAt != ""
}

// ADR-0087 §3 tools: the MCP equivalents of the REST bind/re-enable
// (POST /api/v1/workspaces/{id}/sources) and refresh (POST
// /api/v1/sources/{scope}:sync) actions. knowvault_source_enable is the same
// WorkspaceService.AddSource command the REST addSource route composes — an
// operator or agent uses it both to bind a freshly-registered scope for the
// first time and to re-enable a scope a prior RemoveSource disabled, exactly
// as the REST "Enable" control does. knowvault_source_sync is the same
// SourceService.Sync command the REST syncSource route composes.
const (
	mcpToolSourceEnable = "knowvault_source_enable"
	mcpToolSourceSync   = "knowvault_source_sync"
)

// mcpToolGovernedQueryAsk is ADR-0089's governed model-authored SQL ask,
// exactly the same GovernedQueryService.Ask command the REST
// governed-query-connections/{id}:ask action composes. It never accepts SQL
// as an argument: only the target connection and a natural-language
// question. The connection's exposed schema and the read-only, bounded
// execution guarantees are unchanged from the REST path.
const mcpToolGovernedQueryAsk = "knowvault_governed_query_ask"

const (
	mcpToolQueriesList = "knowvault_queries_list"
	mcpToolQueryRun    = "knowvault_query_run"
)

type mcpGovernedQueryAskArguments struct {
	WorkspaceID  string `json:"workspace_id"`
	ConnectionID string `json:"connection_id"`
	Question     string `json:"question"`
}

type mcpQueriesListArguments struct {
	WorkspaceID  string `json:"workspace_id"`
	ConnectionID string `json:"connection_id"`
}

type mcpQueryRunArguments struct {
	WorkspaceID  string `json:"workspace_id"`
	ConnectionID string `json:"connection_id"`
	PresetID     string `json:"preset_id"`
}

// mcpToolSourcesList is the additive, read-only MCP equivalent of the REST
// GET /api/v1/workspaces/{id}/sources read (listSources). It composes exactly
// the same two SourceService reads the REST route composes — ListSources and
// ConfirmationContext — and projects the identical source-inventory/schedule
// field set plus confirmation context, so MCP and REST can never drift. It is a
// read-only workspace knowledge tool (R3a-1 Outcome 3), so a SERVICE agent
// principal may invoke it exactly as a human session does.
//
// The canonical advertised name is knowvault_sources (design item 4(4)). The
// former advertised name knowvault_sources_list stays dispatchable to the
// byte-identical inventory core for clients that pinned it, but is never
// advertised.
const mcpToolSourcesList = "knowvault_sources"

// mcpToolSourcesListCompat is the former advertised name of the same
// source-inventory/schedule tool. It is accepted by tools/call (and by the
// SERVICE knowledge allow-list) for backward compatibility, is never emitted by
// tools/list, and reaches exactly the same implementation as mcpToolSourcesList.
const mcpToolSourcesListCompat = "knowvault_sources_list"

// mcpSourcesListArguments mirrors the REST list route's single path input: the
// workspace whose current source bindings and sync schedule are read.
type mcpSourcesListArguments struct {
	WorkspaceID string `json:"workspace_id"`
}

// mcpToolRefresh is the workspace knowledge refresh tool (R3a-1 Outcome 2 /
// design item 4(4)). It refreshes the sources of one workspace that allow it
// through the same authorized SourceService reads and refresh command the REST
// listSources and syncSource routes compose. It is deliberately distinct from
// the administrative knowvault_source_sync (ADR-0087 §3): that tool is a bare
// per-scope OWNER command and stays closed to a SERVICE principal, while
// knowvault_refresh is workspace-scoped and is offered to a V1-C agent
// access-code principal exactly as the other knowledge tools are.
const mcpToolRefresh = "knowvault_refresh"

// mcpToolWorkspaceContext is ADR-0098's workspace model context knowledge
// tool (S2-CONTRACT.md "MCP" / "Tool parity"): the workspace's explicit
// description, answer rules, glossary and enabled-source notes, never
// evidence.
const mcpToolWorkspaceContext = "knowvault_workspace_context"

// mcpToolSourceSchema is ADR-0097's read-only source schema knowledge tool:
// the tables, columns, types, primary keys and row estimates of one enabled
// PostgreSQL source, plus the workspace model context notes, answered from
// stored projections and discovery metadata only.
const mcpToolSourceSchema = "knowvault_source_schema"

// mcpToolSourceSQL is ADR-0097's agent-authored read-only SQL knowledge tool:
// one SELECT/WITH statement against one enabled PostgreSQL source, executed
// with the source's own query credential through the single governedquery
// path. It is the only workspace knowledge tool that accepts SQL text.
const mcpToolSourceSQL = "knowvault_source_sql"

// mcpRefreshArguments is the closed argument envelope for knowvault_refresh:
// the workspace whose refreshable sources are refreshed, an optional
// source_scope_id narrowing the call to exactly one bound scope, and the
// optional offset/limit page window over the resolved source list. The schema
// is closed (additionalProperties false); a missing workspace_id, a negative
// or wrong-typed offset/limit or any unknown member is refused with -32602
// before the source service is touched.
type mcpRefreshArguments struct {
	WorkspaceID   string `json:"workspace_id"`
	SourceScopeID string `json:"source_scope_id"`
	Offset        int64  `json:"offset"`
	Limit         int64  `json:"limit"`
}

// R2 Outcome 1: the additive, read-only MCP equivalents of the REST
// metric-definition list/get routes (metricdefinitions.go). They reach the same
// injected, access-re-checked MetricDefinitionCatalog the REST routes use and
// project the identical published field set, so MCP and REST can never drift.
// There is deliberately no create/approve/retire tool: the owner authority that
// owns the audit trail keeps those.
const (
	mcpToolMetricDefinitionsList = "knowvault_metric_definitions_list"
	mcpToolMetricDefinitionGet   = "knowvault_metric_definition_get"
)

// mcpMetricDefinitionsListArguments mirrors the REST list route's single path
// input: the workspace whose definitions are read.
type mcpMetricDefinitionsListArguments struct {
	WorkspaceID string `json:"workspace_id"`
}

// mcpMetricDefinitionGetArguments mirrors the REST exact-version read: the
// workspace, the metric id and a canonical version greater than zero. Version
// is an integer, so a fractional or textual member is rejected before the
// catalog is touched.
type mcpMetricDefinitionGetArguments struct {
	WorkspaceID string `json:"workspace_id"`
	MetricID    string `json:"metric_id"`
	Version     int64  `json:"version"`
}

type mcpSourceEnableArguments struct {
	WorkspaceID                        string `json:"workspace_id"`
	ExpectedWorkspaceRevision          int64  `json:"expected_workspace_revision"`
	ExpectedWorkspaceConfigurationHash string `json:"expected_workspace_configuration_hash"`
	SourceScopeID                      string `json:"source_scope_id"`
	SourceScopeRevision                int64  `json:"source_scope_revision"`
	ScopeConfigHash                    string `json:"scope_config_hash"`
	AccessMode                         string `json:"access_mode"`
}

// AccessMode is restricted to WORKSPACE_MANAGED (review remark,
// review-opus-s2-4-5.md, mcp_adapter.go:129): registration serves
// WORKSPACE_MANAGED only (ADR-0074 s1.10, enforced in the registration
// SECURITY DEFINER functions themselves), so no product-registered scope
// ever carries SOURCE_ENFORCED, and this tool must not advertise or accept a
// mode with no product path.
func (arguments mcpSourceEnableArguments) valid() bool {
	return arguments.WorkspaceID != "" && arguments.ExpectedWorkspaceRevision >= 1 &&
		arguments.ExpectedWorkspaceConfigurationHash != "" && arguments.SourceScopeID != "" &&
		arguments.SourceScopeRevision >= 1 && arguments.ScopeConfigHash != "" &&
		arguments.AccessMode == string(workspacerepository.SourceAccessWorkspaceManaged)
}

type mcpSourceSyncArguments struct {
	SourceScopeID string `json:"source_scope_id"`
}

func (arguments mcpSourceSyncArguments) valid() bool {
	return arguments.SourceScopeID != ""
}

// The four confirmation tools carry exactly the closed body fields each REST
// action accepts plus the workspace selector, so tools/call projects the same
// repository command the accepted routes build. Each mirrors the validation the
// REST route applies (see complete() on the REST body types).

type mcpConfirmGrantIssueArguments struct {
	WorkspaceID                        string `json:"workspace_id"`
	ExpectedWorkspaceRevision          int64  `json:"expected_workspace_revision"`
	ExpectedWorkspaceConfigurationHash string `json:"expected_workspace_configuration_hash"`
	TargetPrincipalID                  string `json:"target_principal_id"`
	TTLSeconds                         int64  `json:"ttl_seconds"`
	ExpectedPolicyRevision             string `json:"expected_policy_revision"`
}

func (arguments mcpConfirmGrantIssueArguments) valid() bool {
	return arguments.WorkspaceID != "" &&
		arguments.ExpectedWorkspaceRevision >= 1 && arguments.ExpectedWorkspaceConfigurationHash != "" &&
		arguments.TargetPrincipalID != "" && arguments.TTLSeconds != 0 && arguments.ExpectedPolicyRevision != ""
}

type mcpConfirmGrantRevokeArguments struct {
	WorkspaceID            string `json:"workspace_id"`
	GrantID                string `json:"grant_id"`
	GrantRevision          int64  `json:"grant_revision"`
	GrantHash              string `json:"grant_hash"`
	ExpectedPolicyRevision string `json:"expected_policy_revision"`
}

func (arguments mcpConfirmGrantRevokeArguments) valid() bool {
	return arguments.WorkspaceID != "" && arguments.GrantID != "" && arguments.GrantRevision >= 1 &&
		arguments.GrantHash != "" && arguments.ExpectedPolicyRevision != ""
}

type mcpManagedSourceConfirmArguments struct {
	WorkspaceID                    string `json:"workspace_id"`
	WorkspaceRevision              int64  `json:"workspace_revision"`
	WorkspaceConfigurationHash     string `json:"workspace_configuration_hash"`
	WorkspaceSourceID              string `json:"workspace_source_id"`
	SourceScopeID                  string `json:"source_scope_id"`
	SourceScopeRevision            int64  `json:"source_scope_revision"`
	ScopeConfigHash                string `json:"scope_config_hash"`
	ConfirmationActorGrantID       string `json:"confirmation_actor_grant_id"`
	ConfirmationActorGrantRevision int64  `json:"confirmation_actor_grant_revision"`
	ConfirmationActorGrantHash     string `json:"confirmation_actor_grant_hash"`
	WarningContractHash            string `json:"warning_contract_hash"`
	ExpectedPolicyRevision         string `json:"expected_policy_revision"`
}

func (arguments mcpManagedSourceConfirmArguments) valid() bool {
	return arguments.WorkspaceID != "" && arguments.WorkspaceRevision >= 1 && arguments.WorkspaceConfigurationHash != "" &&
		arguments.WorkspaceSourceID != "" && arguments.SourceScopeID != "" && arguments.SourceScopeRevision >= 1 &&
		arguments.ScopeConfigHash != "" && arguments.ConfirmationActorGrantID != "" &&
		arguments.ConfirmationActorGrantRevision >= 1 && arguments.ConfirmationActorGrantHash != "" &&
		arguments.WarningContractHash != "" && arguments.ExpectedPolicyRevision != ""
}

type mcpManagedConfirmationRevokeArguments struct {
	WorkspaceID            string `json:"workspace_id"`
	ConfirmationID         string `json:"confirmation_id"`
	ConfirmationHash       string `json:"confirmation_hash"`
	ExpectedPolicyRevision string `json:"expected_policy_revision"`
}

func (arguments mcpManagedConfirmationRevokeArguments) valid() bool {
	return arguments.WorkspaceID != "" && arguments.ConfirmationID != "" && arguments.ConfirmationHash != "" && arguments.ExpectedPolicyRevision != ""
}

func (handler *Handler) mcp(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string) {
	// Source and evidence tools are independent of optional question services.
	if handler.questions == nil && handler.conversations == nil && handler.sources == nil && handler.evidence == nil {
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: jsontext.Value("null"), Error: &mcpError{Code: -32000, Message: "service unavailable"}})
		return
	}
	var envelope mcpRequest
	if code := decodeJSON(writer, request, &envelope); code != "" {
		// A malformed HTTP body must still produce a complete JSON-RPC response;
		// returning after decodeJSON would leave a successful HTTP status with an
		// empty body, which is neither a valid MCP response nor safely retryable.
		// Keep the parse failure content-free and use a null id because no valid
		// request envelope has been established.
		writeMCPError(writer, jsontext.Value("null"), -32600, "invalid request")
		return
	}
	if envelope.JSONRPC != "2.0" || !validMCPID(envelope.ID) || envelope.Method == "" || len(envelope.Method) > 128 {
		writeMCPError(writer, envelope.ID, -32600, "invalid request")
		return
	}
	switch envelope.Method {
	case "initialize":
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "knowvault", "version": "1"},
			"instructions":    handler.mcpInstructions(request.Context(), access),
		}})
	case "tools/list":
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{"tools": handler.mcpTools(access)}})
	case "tools/call":
		handler.mcpToolCall(writer, request, access, envelope)
	default:
		writeMCPError(writer, envelope.ID, -32601, "method not found")
	}
}

// mcpTools is the tools/list projection the transport serves. It is the static
// catalogue plus the dynamic R3a-1 search, relation and grep tools, each
// appended only when the mounted evidence service actually implements its
// optional capability so the surface never advertises a tool it cannot serve.
// The canonical names, compatibility aliases, service visibility and capability
// gating come from the single internal/workspacetools registry, so tools/list
// and tools/call cannot drift. The whole projection is then reduced for a
// SERVICE principal, so an agent sees exactly the knowledge tools
// workspacetools permits and no administrative tool.
func (handler *Handler) mcpTools(access database.AccessContext) []any {
	tools := mcpToolCatalog(access)
	if handler.governedQueryIsPresetOnly() {
		filtered := make([]any, 0, len(tools))
		for _, entry := range tools {
			tool, ok := entry.(map[string]any)
			if !ok || tool["name"] != mcpToolGovernedQueryAsk {
				filtered = append(filtered, entry)
			}
		}
		tools = filtered
	}
	if handler.governedPresets != nil && handler.governedPresets.HasPresets() {
		tools = append(tools, mcpGovernedPresetToolDefinitions()...)
	}
	_, searchAvailable := handler.evidenceSearchCapability()
	_, relatedAvailable := handler.evidenceRelatedCapability()
	_, grepAvailable := handler.mcpGrepCapability()
	for _, tool := range workspacetools.KnowledgeTools().Dynamic() {
		switch tool.Capability {
		case workspacetools.CapabilitySearch:
			if searchAvailable {
				tools = append(tools, mcpSearchToolDefinitions()...)
			}
		case workspacetools.CapabilityRelated:
			if relatedAvailable {
				tools = append(tools, mcpRelatedToolDefinitions()...)
			}
		case workspacetools.CapabilityGrep:
			if grepAvailable {
				_, wholeObjectAvailable := handler.evidenceWholeObjectCapability()
				tools = append(tools, mcpGrepToolDefinitions(wholeObjectAvailable)...)
			}
		}
	}
	return mcpToolsForActor(tools, access)
}

// mcpServiceKnowledgeTool is the one authoritative SERVICE (agent access-code)
// allow-list. Outcome 3 of R3a-1 makes the workspace knowledge surface — read
// by address, list, search, related, grep, sources and the two question tools —
// available to an external agent service principal; everything else in the MCP
// catalogue (conversations, confirmation grants, managed-source confirmation,
// connection trust, source enable/sync and metric definitions)
// is administrative and stays closed. The former dispatch-only names stay
// permitted for backward compatibility but are never advertised.
//
// The R3a-1 knowledge set itself is owned by internal/workspacetools, so the
// allow-list cannot drift from the dispatch table. The pilot also exposes the
// read-only SQL ask; workspace opt-in, current membership and database grants
// remain mandatory. SQL administration is not added to the agent surface.
func mcpServiceKnowledgeTool(name string) bool {
	if name == mcpToolQuestion || name == mcpToolEvidenceGet || name == mcpToolGovernedQueryAsk ||
		name == mcpToolQueriesList || name == mcpToolQueryRun {
		return true
	}
	return workspacetools.KnowledgeTools().ServiceKnowledge(name)
}

// mcpToolsForActor applies the SERVICE knowledge allow-list to a tools/list
// projection and returns a non-SERVICE projection unchanged.
func mcpToolsForActor(tools []any, access database.AccessContext) []any {
	if access.EffectiveActorKind() != database.ActorKindService {
		return tools
	}
	filtered := make([]any, 0, len(tools))
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		if mcpServiceKnowledgeTool(name) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// mcpToolCatalog is the static tools/list projection. It carries the whole
// administrative catalogue for a human or operator; mcpToolsForActor reduces it
// for a SERVICE principal to the knowledge tools that principal may invoke, so
// the surface an agent is shown is the surface it may actually call.
func mcpToolCatalog(access database.AccessContext) []any {
	all := []any{
		map[string]any{
			"name": mcpToolQuestion, "description": "Ask a question over the current workspace corpus and receive evidence-backed citations.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "question"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "conversation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}, "question": map[string]any{"type": "string", "minLength": 1, "maxLength": 4096}, "answer_mode": map[string]any{"type": "string", "enum": []string{"EXTRACTIVE", "GENERATIVE", question.AnswerModeToolLoop}},
			}},
		},
		map[string]any{
			"name": "knowvault_conversations_list", "description": "List current-access conversation metadata and authorized Question Run projections for a workspace.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": "knowvault_conversation_get", "description": "Read one current-access conversation and its authorized Question Run projections.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "conversation_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "conversation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			}},
		},
		map[string]any{
			"name": "knowvault_conversation_archive", "description": "Archive one current-access conversation irreversibly with the HTTP Idempotency-Key.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "conversation_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "conversation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			}},
		},
		map[string]any{
			"name": mcpToolEvidenceGet, "description": "Open one evidence fragment by citation id through the same authorized Evidence viewer and audit journal as the REST evidenceGet route.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "fragment_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "fragment_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			}},
		},
		map[string]any{
			"name": mcpToolEvidenceRead, "description": "Read source text by address: copy canonical_address (kv1:...) from search into the address argument and OMIT cursor to read the addressed fragment. Alternatively use fragment_id. Start with limit=4096 bytes; offset/next_offset paginate the fragment if has_more is true. A complete direct fragment page may also include at most previous/next fragment identifiers, ordinals and exact canonical addresses; read those addresses separately when needed. Only when you need the full parent document, use cursor=\"\" and continue with next_cursor: this can read a much larger document than the search hit. In whole-document mode, canonical_address identifies the entire document. To cite text from a returned page, use its matching fragments[].canonical_address; page_offset and length locate that fragment's bytes in the page. A fragment may cross page boundaries; read its address directly or continue the pages to obtain its full text. Returns exact text, address, version, span hash and explicit has_more; no silent truncation. Copy contiguous quotes exactly, without ellipses. Access checks and audit apply to every page.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "anyOf": []any{map[string]any{"required": []string{"address"}}, map[string]any{"required": []string{"fragment_id"}}}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "fragment_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
				"address": map[string]any{"type": "string", "minLength": 1, "description": "The exact canonical_address kv1:... returned by a knowledge tool."},
				"cursor":  map[string]any{"type": "string", "description": "Omit this property entirely for the addressed fragment. An empty string is NOT a default placeholder: it deliberately switches to the whole parent document. Pass next_cursor only to continue that document. Do not combine with nonzero offset."},
				"offset":  map[string]any{"type": "integer", "minimum": 0, "description": "UTF-8 byte offset within the fragment; starts at 0. Copy next_offset for another fragment page."}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": mcpEvidenceReadMaxLimit, "default": mcpEvidenceReadDefaultLimit, "description": "Maximum UTF-8 bytes in this page, not lines or characters. The default 4096 normally reads a complete search fragment."},
				"expected_span_hash":  map[string]any{"type": "string", "minLength": 1},
				"include_text_base64": map[string]any{"type": "boolean"},
			}},
		},
		map[string]any{
			"name": mcpToolConfirmationGrantIssue, "description": "Issue a workspace-managed confirmation grant (IssueConfirmationGrant) through the ADR-0053 authority chain, exactly as the REST confirmation-grants action does.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "expected_workspace_revision", "expected_workspace_configuration_hash", "target_principal_id", "ttl_seconds", "expected_policy_revision"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "expected_workspace_revision": map[string]any{"type": "integer", "minimum": 1}, "expected_workspace_configuration_hash": map[string]any{"type": "string"}, "target_principal_id": map[string]any{"type": "string"}, "ttl_seconds": map[string]any{"type": "integer", "exclusiveMinimum": 0}, "expected_policy_revision": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolConfirmationGrantRevoke, "description": "Revoke a workspace-managed confirmation grant (RevokeConfirmationGrant) through the ADR-0053 authority chain, exactly as the REST :revoke action does.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "grant_id", "grant_revision", "grant_hash", "expected_policy_revision"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "grant_id": map[string]any{"type": "string"}, "grant_revision": map[string]any{"type": "integer", "minimum": 1}, "grant_hash": map[string]any{"type": "string"}, "expected_policy_revision": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolManagedSourceConfirm, "description": "Confirm a workspace-managed source (ConfirmManagedSource) through the ADR-0053 authority chain, exactly as the REST managed-source-confirmations action does.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "workspace_revision", "workspace_configuration_hash", "workspace_source_id", "source_scope_id", "source_scope_revision", "scope_config_hash", "confirmation_actor_grant_id", "confirmation_actor_grant_revision", "confirmation_actor_grant_hash", "warning_contract_hash", "expected_policy_revision"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "workspace_revision": map[string]any{"type": "integer", "minimum": 1}, "workspace_configuration_hash": map[string]any{"type": "string"}, "workspace_source_id": map[string]any{"type": "string"}, "source_scope_id": map[string]any{"type": "string"}, "source_scope_revision": map[string]any{"type": "integer", "minimum": 1}, "scope_config_hash": map[string]any{"type": "string"}, "confirmation_actor_grant_id": map[string]any{"type": "string"}, "confirmation_actor_grant_revision": map[string]any{"type": "integer", "minimum": 1}, "confirmation_actor_grant_hash": map[string]any{"type": "string"}, "warning_contract_hash": map[string]any{"type": "string"}, "expected_policy_revision": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolManagedConfirmationRevoke, "description": "Revoke a workspace-managed source confirmation (RevokeManagedConfirmation) through the ADR-0053 authority chain, exactly as the REST :revoke action does; it is also the reconfirm exit.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "confirmation_id", "confirmation_hash", "expected_policy_revision"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "confirmation_id": map[string]any{"type": "string"}, "confirmation_hash": map[string]any{"type": "string"}, "expected_policy_revision": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolVerifyConnectionTrust, "description": "Verify a source connection's trust (DRAFT->VERIFIED) as CONNECTOR_ADMIN, with a mandatory attestation, exactly as the REST sources/connections/{id}:verify-trust action does (ADR-0087 §2).",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"connection_id", "attested_connector_identity", "attested_by", "attested_at"}, "properties": map[string]any{
				"connection_id": map[string]any{"type": "string"}, "attested_connector_identity": map[string]any{"type": "string"}, "attested_by": map[string]any{"type": "string"}, "attested_at": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolSourceEnable, "description": "Bind a source scope to a workspace, or re-enable a binding a prior remove disabled, exactly as the REST POST /api/v1/workspaces/{id}/sources action does (ADR-0087 §3).",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "expected_workspace_revision", "expected_workspace_configuration_hash", "source_scope_id", "source_scope_revision", "scope_config_hash", "access_mode"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "expected_workspace_revision": map[string]any{"type": "integer", "minimum": 1}, "expected_workspace_configuration_hash": map[string]any{"type": "string"}, "source_scope_id": map[string]any{"type": "string"}, "source_scope_revision": map[string]any{"type": "integer", "minimum": 1}, "scope_config_hash": map[string]any{"type": "string"}, "access_mode": map[string]any{"type": "string", "enum": []string{"WORKSPACE_MANAGED"}},
			}},
		},
		map[string]any{
			"name": mcpToolSourceSync, "description": "Request a fresh full refresh for an already-activated source scope, exactly as the REST POST /api/v1/sources/{scope}:sync action does (ADR-0087 §3).",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"source_scope_id"}, "properties": map[string]any{
				"source_scope_id": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolGovernedQueryAsk, "description": "Ask an ad hoc question over a connection's operator-exposed SQL schema (ADR-0089): the model composes read-only SQL over that schema only, a dedicated least-privilege database role executes it in a bounded read-only transaction, and the exact SQL and result table are returned alongside the answer. No SQL input field; only a natural-language question and the target connection.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "connection_id", "question"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "connection_id": map[string]any{"type": "string"}, "question": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolMetricDefinitionsList, "description": "List every issued version of every MetricDefinition in a workspace through the same access-re-checked catalog as the REST metric-definitions read (R2 Outcome 1). Read-only.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolMetricDefinitionGet, "description": "Read one exact version of a MetricDefinition in a workspace through the same access-re-checked catalog as the REST metric-definition read (R2 Outcome 1). Read-only.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "metric_id", "version"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "metric_id": map[string]any{"type": "string", "minLength": 1}, "version": map[string]any{"type": "integer", "minimum": 1},
			}},
		},
		map[string]any{
			"name": mcpToolSourcesList, "description": "List every source bound to the current revision of a workspace with its full sync status, schedule fields and confirmation context, through the same SourceService reads as the REST listSources route. Read-only.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name": mcpToolRefresh, "description": "Refresh the sources of one workspace that allow it, through the same authorized SourceService ListSources read and Sync command the REST routes compose. Optionally narrow to one source_scope_id; the resolved source list is paginated with offset/limit/has_more/next_offset, not silently truncated.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id":    map[string]any{"type": "string"},
				"source_scope_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
				"offset":          map[string]any{"type": "integer", "minimum": 0},
				"limit":           map[string]any{"type": "integer", "minimum": 1},
			}},
		},
		map[string]any{
			"name": mcpToolWorkspaceList, "description": "List the document/evidence objects of one workspace with their current source version, content hash, external version key, moment and address, current versions only unless all_versions is true, through the same authorized Evidence viewer and audit journal as the REST evidence read. Read-only and paginated with offset/limit/has_more/next_offset (no silent truncation).",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
				"all_versions": map[string]any{"type": "boolean"},
				"offset":       map[string]any{"type": "integer", "minimum": 0},
				"limit":        map[string]any{"type": "integer", "minimum": 1},
			}},
		},
		map[string]any{
			"name": mcpToolWorkspaceContext, "description": "Read this workspace's explicit model context (ADR-0098): an administrator-authored description, answer rules, glossary (terms, synonyms, definitions, data locations) and enabled-source/table/column notes. It shapes terminology and presentation only -- it is never evidence, and it cannot change this tool catalog, grant a tool, a write or access. Optionally narrow the glossary to terms you already recognise in the question with terms (at most 10), or narrow the whole response to one section.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
				"terms":        map[string]any{"type": "array", "maxItems": maxWorkspaceContextToolTerms, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": maxWorkspaceContextToolTermChars}},
				"section":      map[string]any{"type": "string", "enum": []string{"all", "glossary", "rules", "sources"}},
			}},
		},
		map[string]any{
			"name": mcpToolSourceSchema, "description": "Read the schema of one PostgreSQL source enabled in this workspace (ADR-0097): its tables, columns, native types, primary keys and pg_class row estimates, plus the workspace model context notes for the source, its tables and columns. Columns excluded at registration are never returned. Read-only and served from stored projections and discovery metadata; it opens no source database and runs no SQL. Without source_id it lists the workspace's PostgreSQL sources (id, name, table_count); with source_id it returns one page of tables, optionally narrowed to one schema.name table.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
				"source_id":    map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "The source connection id returned by knowvault_sources. Omit it to list the workspace's PostgreSQL sources."},
				"table":        map[string]any{"type": "string", "minLength": 3, "maxLength": maxSourceSchemaToolTableChars, "description": "Optional schema.name selector for one table."},
				"offset":       map[string]any{"type": "integer", "minimum": 0},
				"limit":        map[string]any{"type": "integer", "minimum": 1, "maximum": maxSourceSchemaToolLimit, "default": maxSourceSchemaToolLimit},
			}},
		},
		map[string]any{
			"name": mcpToolSourceSQL, "description": "Run one read-only SELECT/WITH statement you write against one PostgreSQL source enabled in this workspace (ADR-0097). Read the source's tables, columns and primary keys with knowvault_source_schema first, then use exactly those names. The statement runs with the source's own read-only query credential in a read-only transaction; every relation the planner touches must belong to the source, so pg_catalog, information_schema, another schema and a function scan are refused. The whole result table is returned with row_count, sql_hash and result_digest; cite it in the answer. Server-owned limits apply: at most 8192 bytes of SQL, an EXPLAIN cost cap, a statement timeout, a row/byte cap and at most three successful calls per answer. A refusal is returned as a result whose error is one of SQL_REJECTED_STATIC, RELATION_NOT_IN_SOURCE, COST_LIMIT, ROW_LIMIT, TIMEOUT, DATABASE_REJECTED or SOURCE_SQL_NOT_CONFIGURED.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "source_id", "sql"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
				"source_id":    map[string]any{"type": "string", "minLength": 1, "maxLength": maxSourceSQLSourceIDChars, "description": "The source connection id returned by knowvault_sources or knowvault_source_schema."},
				"sql":          map[string]any{"type": "string", "minLength": 1, "maxLength": maxSourceSQLBytes, "description": "Exactly one SELECT or WITH statement. No trailing second statement, no comment, no write or DDL."},
				"purpose":      map[string]any{"type": "string", "maxLength": maxSourceSQLPurposeChars, "description": "Optional short note describing what the statement answers."},
			}},
		},
	}
	return mcpToolsForActor(all, access)
}

func (handler *Handler) mcpToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest) {
	var params mcpToolCallParams
	// MCP request metadata and client extension members belong to the protocol
	// envelope. Tool arguments remain closed and are validated by each tool.
	if err := jsonv2.Unmarshal(envelope.Params, &params, jsontext.AllowDuplicateNames(false)); err != nil || params.Name == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid tool call")
		return
	}
	if (params.Name == mcpToolQueriesList || params.Name == mcpToolQueryRun) &&
		(handler.governedPresets == nil || !handler.governedPresets.HasPresets()) {
		writeMCPError(writer, envelope.ID, -32601, "method not found")
		return
	}
	if params.Name == mcpToolGovernedQueryAsk && handler.governedQueryIsPresetOnly() {
		writeMCPError(writer, envelope.ID, -32601, "method not found")
		return
	}
	// V1-C / R3a-1 Outcome 3: a SERVICE (agent access-code) principal may
	// invoke the workspace knowledge tools — question, evidence read, read by
	// address, inventory, search, related, grep and sources — through the same
	// authorized implementations a human session reaches. Every other name is
	// administrative (conversation management, confirmation, source
	// enable/sync, connection trust, governed query, metric definitions) and
	// stays closed regardless of what its synthetic MEMBER-role membership
	// would otherwise allow at the policy layer. This is checked here, once,
	// before any tool-specific dispatch, rather than trusted to each tool's own
	// downstream role check. The rejection is the identical -32601 "method not
	// found" an unknown tool name gets, so a SERVICE caller cannot use it to
	// distinguish "tool exists but is forbidden" from "no such tool".
	if access.EffectiveActorKind() == database.ActorKindService &&
		!mcpServiceKnowledgeTool(params.Name) {
		handler.auditDeniedAgentCall(request, access, "", "MCP_TOOL_NOT_PERMITTED_FOR_SERVICE")
		writeMCPError(writer, envelope.ID, -32601, "method not found")
		return
	}
	if params.Name == "knowvault_conversations_list" || params.Name == "knowvault_conversation_get" || params.Name == "knowvault_conversation_archive" {
		handler.mcpConversationToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolEvidenceGet {
		handler.mcpEvidenceToolCall(writer, request, access, envelope, params)
		return
	}
	// Every R3a-1 knowledge tool — canonical name or compatibility alias — is
	// resolved through the single internal/workspacetools registry and
	// dispatched to its shared implementation by kind. There is deliberately no
	// name switch here: adding or renaming a knowledge tool happens in the
	// registry, not in the adapter.
	if tool, ok := workspacetools.KnowledgeTools().Lookup(params.Name); ok {
		handler.mcpKnowledgeToolCall(writer, request, access, envelope, params, tool)
		return
	}
	if params.Name == mcpToolConfirmationGrantIssue || params.Name == mcpToolConfirmationGrantRevoke ||
		params.Name == mcpToolManagedSourceConfirm || params.Name == mcpToolManagedConfirmationRevoke {
		handler.mcpAuthorityToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolVerifyConnectionTrust {
		handler.mcpVerifyConnectionTrustToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolSourceEnable {
		handler.mcpSourceEnableToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolSourceSync {
		handler.mcpSourceSyncToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolGovernedQueryAsk {
		handler.mcpGovernedQueryAskToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolQueriesList || params.Name == mcpToolQueryRun {
		handler.mcpGovernedPresetToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name == mcpToolMetricDefinitionsList || params.Name == mcpToolMetricDefinitionGet {
		handler.mcpMetricDefinitionToolCall(writer, request, access, envelope, params)
		return
	}
	if params.Name != mcpToolQuestion {
		writeMCPError(writer, envelope.ID, -32602, "invalid tool call")
		return
	}
	var arguments mcpQuestionArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" || strings.TrimSpace(arguments.Question) == "" || len(arguments.Question) > 4096 {
		writeMCPError(writer, envelope.ID, -32602, "invalid question arguments")
		return
	}
	if arguments.AnswerMode == "" {
		arguments.AnswerMode = handler.defaultQuestionMode(arguments.WorkspaceID)
	}
	if (arguments.AnswerMode != "EXTRACTIVE" && arguments.AnswerMode != "GENERATIVE" && arguments.AnswerMode != question.AnswerModeToolLoop) || handler.questions == nil {
		writeMCPError(writer, envelope.ID, -32602, "unsupported answer mode")
		return
	}
	key, _, code, _ := mutationHeaders(request, false)
	if code != "" {
		writeMCPError(writer, envelope.ID, -32001, "idempotency key required")
		return
	}
	run, err := handler.questions.Create(request.Context(), access, question.CreateRequest{WorkspaceID: arguments.WorkspaceID, ConversationID: arguments.ConversationID, Question: arguments.Question, AnswerMode: arguments.AnswerMode, IdempotencyKey: key})
	if err != nil {
		if question.CodeOf(err) == question.CodeUnsupportedMode {
			// GENERATIVE is a real mode, but it is unavailable until composition
			// wires a qualified Model Gateway adapter/verifier (GEN-1, ADR-0088).
			writeMCPError(writer, envelope.ID, -32602, "answer mode unavailable")
			return
		}
		// A workspace the agent's access code was never granted answers the
		// same content-free "question unavailable" a genuinely unavailable
		// service does, so the caller learns nothing — but the workspace owner
		// must still see the attempt in the journal (V1-C).
		if question.CodeOf(err) == question.CodeDenied || question.CodeOf(err) == question.CodeNotFound {
			handler.auditDeniedAgentCall(request, access, arguments.WorkspaceID, "MCP_WORKSPACE_OUT_OF_SCOPE")
		}
		// R2 Outcome 2: a typed QueryIntent refusal carries a server-owned,
		// closed-dictionary clarification. Add it under the error's data member
		// (the message and code stay exactly as before), so an agent client can
		// show the same text the browser shows instead of only "question
		// unavailable".
		if clarification := question.ClarificationOf(err); clarification != "" {
			writeMCPErrorClarification(writer, envelope.ID, -32000, "question unavailable", clarification)
			return
		}
		writeMCPError(writer, envelope.ID, -32000, "question unavailable")
		return
	}
	content := mcpQuestionContent(run)
	// The Question authority uses the durable terminal status vocabulary
	// COMPLETED/INSUFFICIENT_EVIDENCE/FAILED.  MCP's isError bit must mirror
	// that contract; checking the unrelated legacy SUCCEEDED label would mark
	// every successfully completed run as an error.
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{"content": content, "structuredContent": run, "isError": run.ResultStatus != "COMPLETED"}})
}

// mcpKnowledgeToolCall dispatches one registered R3a-1 knowledge tool to the
// same shared implementation the REST parity route composes. The tool's Kind,
// not its name, selects the core, so a canonical name and its compatibility
// alias reach byte-identical behavior, projection, pagination and error
// mapping. Authorization, admission-before-data and the R1 audit outcome stay
// inside each core exactly as before; this function adds no new read path.
func (handler *Handler) mcpKnowledgeToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams, tool workspacetools.Tool) {
	switch tool.Kind {
	case workspacetools.KindRead:
		handler.mcpEvidenceReadToolCall(writer, request, access, envelope, params)
	case workspacetools.KindSources:
		handler.mcpSourcesListToolCall(writer, request, access, envelope, params)
	case workspacetools.KindRefresh:
		handler.mcpRefreshToolCall(writer, request, access, envelope, params)
	case workspacetools.KindListObjects:
		handler.mcpWorkspaceListToolCall(writer, request, access, envelope, params)
	case workspacetools.KindSearch:
		handler.mcpSearchToolCall(writer, request, access, envelope, params)
	case workspacetools.KindRelated:
		handler.mcpRelatedToolCall(writer, request, access, envelope, params)
	case workspacetools.KindGrep:
		handler.mcpGrepToolCall(writer, request, access, envelope, params)
	case workspacetools.KindWorkspaceContext:
		handler.mcpWorkspaceContextToolCall(writer, request, access, envelope, params)
	case workspacetools.KindSourceSchema:
		handler.mcpSourceSchemaToolCall(writer, request, access, envelope, params)
	case workspacetools.KindSourceSQL:
		handler.mcpSourceSQLToolCall(writer, request, access, envelope, params)
	default:
		writeMCPError(writer, envelope.ID, -32602, "invalid tool call")
	}
}

// mcpQuestionContent renders the answer the way the browser renders it:
// the corpus status ABOVE the prose, as text.
//
// POKA_YOKE QRY-002 requires a partial corpus to be visible above the answer,
// and the UI does exactly that (web/src/main.tsx renders CORPUS_PARTIAL over
// the answer text). The MCP surface carried corpus_status only inside
// structuredContent, and an agent — the very client this surface exists for —
// reads `content`. So the same run that warned a human warned nothing at all
// to an agent, which is QRY-002 not being satisfied on this transport. The
// warning is a fixed, content-free sentence built from the run's own closed
// status vocabulary: no fragment, source name or count is disclosed.
func mcpQuestionContent(run question.Run) []any {
	content := make([]any, 0, 2)
	if run.CorpusStatus != "" && run.CorpusStatus != "COMPLETE" {
		content = append(content, map[string]any{
			"type": "text",
			"text": "Warning: the evidence corpus is incomplete (corpus_status=" + run.CorpusStatus +
				"). The answer does not cover the entire connected corpus; exact numerical totals are not published for an incomplete corpus.",
		})
	}
	return append(content, map[string]any{"type": "text", "text": run.Answer})
}

func (handler *Handler) mcpConversationToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.conversations == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpConversationArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid conversation arguments")
		return
	}
	if params.Name != "knowvault_conversations_list" && arguments.ConversationID == "" {
		writeMCPError(writer, envelope.ID, -32602, "conversation_id is required")
		return
	}
	if params.Name == "knowvault_conversations_list" && arguments.ConversationID != "" {
		writeMCPError(writer, envelope.ID, -32602, "conversation_id is not accepted")
		return
	}
	switch params.Name {
	case "knowvault_conversations_list":
		views, err := handler.conversations.List(request.Context(), access, arguments.WorkspaceID)
		if err != nil {
			writeMCPError(writer, envelope.ID, conversationMCPErrorCode(err), conversationMCPErrorMessage(err))
			return
		}
		// FIX-5 #2: one question.Service.GetBatch call for the whole page
		// instead of one Get() call per turn -- see projectConversations.
		items, projectionErr := handler.projectConversations(request, access, views)
		if projectionErr != nil {
			writeMCPError(writer, envelope.ID, questionMCPErrorCode(projectionErr), "question unavailable")
			return
		}
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{"structuredContent": map[string]any{"conversations": items}, "isError": false}})
	case "knowvault_conversation_get":
		view, err := handler.conversations.Get(request.Context(), access, arguments.WorkspaceID, arguments.ConversationID)
		if err != nil {
			writeMCPError(writer, envelope.ID, conversationMCPErrorCode(err), conversationMCPErrorMessage(err))
			return
		}
		item, projectionErr := handler.projectConversation(request, access, view)
		if projectionErr != nil {
			writeMCPError(writer, envelope.ID, questionMCPErrorCode(projectionErr), "question unavailable")
			return
		}
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{"structuredContent": item, "isError": false}})
	case "knowvault_conversation_archive":
		key, _, code, _ := mutationHeaders(request, false)
		if code != "" {
			writeMCPError(writer, envelope.ID, -32001, "idempotency key required")
			return
		}
		view, err := handler.conversations.Archive(request.Context(), access, conversation.ArchiveRequest{WorkspaceID: arguments.WorkspaceID, ConversationID: arguments.ConversationID, IdempotencyKey: key})
		if err != nil {
			writeMCPError(writer, envelope.ID, conversationMCPErrorCode(err), conversationMCPErrorMessage(err))
			return
		}
		item, projectionErr := handler.projectConversation(request, access, view)
		if projectionErr != nil {
			writeMCPError(writer, envelope.ID, questionMCPErrorCode(projectionErr), "question unavailable")
			return
		}
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{"structuredContent": item, "isError": false}})
	}
}

// mcpEvidenceToolCall opens one evidence fragment by citation (fragment) id
// through the same handler.evidence viewer the REST evidenceGet route uses. It
// never reads a fragment, mutates a workspace or issues its own audit event;
// authorization, decryption and the single citation.opened journal emission all
// live inside the EvidenceService. An unauthorized/cross-tenant/missing/failing
// read is the viewer's one indistinguishable ErrNotFound, mirrored as a single
// content-free not-found so neither surface exposes an existence oracle.
func (handler *Handler) mcpEvidenceToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.evidence == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpEvidenceArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" || arguments.FragmentID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid evidence arguments")
		return
	}
	fragment, err := handler.evidence.Read(request.Context(), access, arguments.WorkspaceID, arguments.FragmentID)
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "evidence not found")
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": string(fragment.Text)}},
		// MCP keeps the closed two-field argument contract and therefore uses
		// the same matched-row default as REST's omitted scope query.
		"structuredContent": handler.evidenceProjection(request.Context(), access, arguments.WorkspaceID, arguments.FragmentID, "", fragment),
		"isError":           false,
	}})
}

// mcpEvidenceReadToolCall is the additive, paged read of one evidence fragment.
// It resolves the fragment through the same handler.evidence viewer the REST
// evidenceGet route and knowvault_evidence_get use, so authorization,
// decryption, the ADR-0077 org-keyed text hash and the admission/outcome audit
// journal are exactly the existing ones and no new read path exists. On top of
// that authorized read it returns:
//
//   - one explicit page of the canonical text (offset/length) plus next_offset,
//     has_more and the effective limit, so a limit is never silent;
//   - the whole-fragment text hash (evidence_fragment.text_hash) and the hash
//     of the exact returned page (page_hash) so every page can be verified;
//   - an address naming source, version, object and the fragment's exact span.
//
// The page is snapshotted to UTF-8 rune boundaries so the text member is always
// valid UTF-8. content[].text is the page text followed by exactly one trailing
// metadata line carrying the same address, window and hashes, so a
// text-channel-only client can reassemble the original; the structuredContent
// text member carries the same exact page text, and the additive
// include_text_base64 argument restores the base64 copy only when a caller
// explicitly asks, so the default response no longer duplicates every page as
// text plus base64 plus the JSON envelope.
// A caller-supplied expected_span_hash that does not equal the stored
// fragment hash is refused with a typed, content-free error and no page text or
// address. Every denial, cross-tenant and cross-workspace read is the viewer's
// single ErrNotFound, mirrored as the existing content-free -32004, so the
// paged surface adds no existence oracle and no workspace echo.
func (handler *Handler) mcpEvidenceReadToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.evidence == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpEvidenceReadArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || (arguments.FragmentID == "" && arguments.Address == "") || arguments.Offset < 0 || arguments.Limit < 0 {
		writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
		return
	}
	// A whole-object page request is driven by the cursor, not by offset; a
	// caller that supplies both is refused before any read rather than silently
	// preferring one.
	if arguments.Cursor != nil && arguments.Offset != 0 {
		writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
		return
	}
	handler.mcpEvidenceReadPage(writer, request, access, envelope, arguments.WorkspaceID, arguments.FragmentID, arguments.Address, arguments.Offset, arguments.Limit, arguments.ExpectedSpanHash, arguments.Cursor, arguments.IncludeTextBase64)
}

// mcpEvidenceReadPage is the single read core of knowvault_read. It
// reads one fragment through the same authorized handler.evidence viewer the
// REST evidenceGet route and knowvault_evidence_get use, then returns the
// explicit page window and the whole-fragment hash described above, reusing the
// canonical admission/outcome audit.
//
// rawAddress is the optional canonical internal/address value (R3a-1 KV-A01c).
// When present it is parsed with address.Parse, selects the object when
// fragmentID is empty, must name the same source/object/version as the
// authorized fragment, and its span hash is re-derived from the fragment's
// canonical text with address.VerifySpan before any page is served. A
// malformed, identity-mismatching or tampered address is a typed, content-free
// refusal that returns no page text and no address; a cross-workspace address
// is denied through the viewer's unchanged content-free ErrNotFound.
//
// cursor, when non-nil, selects whole-object page mode (R3a-1 KV-A02a): the
// address (or fragment_id) resolves the anchor fragment, the whole source
// version's canonical text is reassembled through the optional
// EvidenceWholeObject capability under the same authorized audit path, and the
// pointer's value is the stable page cursor (empty for the first page). Absent
// cursor keeps the single-fragment read byte-for-byte unchanged.
func (handler *Handler) mcpEvidenceReadPage(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, workspaceID, fragmentID, rawAddress string, offset, limit int64, expectedSpanHash string, cursor *string, includeTextBase64 bool) {
	if handler.evidence == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var selector *address.Address
	if rawAddress != "" {
		parsed, parseErr := address.Parse(rawAddress)
		if parseErr != nil {
			writeMCPError(writer, envelope.ID, -32602, "malformed evidence address: copy the complete canonical_address returned by a knowledge tool without shortening or editing it; alternatively supply its fragment_id")
			return
		}
		selector = &parsed
		if fragmentID == "" {
			// The address is the selector: its object names the fragment. The
			// read still goes through the authorized viewer, so a foreign
			// workspace or object is the single content-free denial.
			fragmentID = parsed.Object
		} else if parsed.Object != fragmentID {
			writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
			return
		}
	}
	if workspaceID == "" || fragmentID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
		return
	}
	// A named code-source ref version (R3a-1 KV-A04b) is resolved from
	// object-inventory metadata only, before any fragment content is read, so a
	// ref-scoped canonical address round-trips. A version of a listed object
	// that is neither its immutable source version id nor a matching
	// code-source ref is refused content-free here; an object the inventory does
	// not list falls through to the authorized read's own denial.
	refVersionID := ""
	if selector != nil {
		resolution := handler.mcpReadAddressResolution(request.Context(), access, workspaceID, *selector)
		if resolution.Available && resolution.ObjectSeen && !resolution.VersionKnown {
			// The address names a version of an object this workspace's
			// inventory lists, but it is neither the immutable source version
			// id nor a matching code-source ref: an unknown or foreign ref,
			// refused content-free before any content is read.
			writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
			return
		}
		refVersionID = resolution.RefVersionID
	}
	if cursor != nil {
		handler.mcpEvidenceReadWholeObjectPage(writer, request, access, envelope, workspaceID, fragmentID, selector, refVersionID, *cursor, limit, expectedSpanHash, includeTextBase64)
		return
	}
	fragment, err := handler.readEvidenceSelection(request.Context(), access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "evidence not found")
		return
	}
	// The address must name exactly the object the authorized read resolved,
	// else it names something the caller was not authorized to read: refuse it
	// with a typed, content-free error and no page text and no address.
	if selector != nil {
		if selector.Source != fragment.SourceObjectID || selector.Object != fragment.FragmentID || !mcpReadAddressVersionMatches(*selector, fragment.SourceVersionID, refVersionID) {
			writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
			return
		}
		if !handler.verifyAddressSpan(fragment.Text, *selector) {
			// Grep and whole-object reads emit whole-text addresses. The
			// address is sufficient to select the text; an agent need not
			// know a separate cursor convention to read a valid address.
			if selector.SpanKind == address.SpanKindText && selector.CharEnd > utf8.RuneCount(fragment.Text) {
				if _, available := handler.evidenceWholeObjectCapability(); available {
					handler.mcpEvidenceReadWholeObjectPage(writer, request, access, envelope, workspaceID, fragmentID, selector, refVersionID, "v1:"+strconv.FormatInt(offset, 10), limit, expectedSpanHash, includeTextBase64)
					return
				}
			}
			writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
			return
		}
	}
	// The stored fragment hash is the hash of the whole retrievable object. A
	// caller that demanded a different hash gets a typed, content-free refusal
	// that carries neither the supplied nor the stored hash and no page text.
	if expectedSpanHash != "" && expectedSpanHash != fragment.EvidenceTextHash {
		writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
		return
	}
	canonicalAddress, addressErr := handler.canonicalEvidenceAddress(fragment)
	if addressErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	total := int64(len(fragment.Text))
	if offset > total {
		writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
		return
	}
	start := mcpEvidencePageStart(fragment.Text, int(offset))
	if limit == 0 {
		limit = mcpEvidenceReadDefaultLimit
	}
	if limit > mcpEvidenceReadMaxLimit {
		limit = mcpEvidenceReadMaxLimit
	}
	end := mcpEvidencePageEnd(fragment.Text, start, limit)
	page := fragment.Text[start:end]
	hasMore := int64(end) < total
	var nextOffset any
	if hasMore {
		nextOffset = int64(end)
	}
	pageHash := mcpEvidencePageHash(page)
	addressProjection := mcpEvidenceAddress(fragment)
	var neighbors *readNeighborsProjection
	if start == 0 && !hasMore {
		neighbors = handler.readNeighborsProjection(request.Context(), access, workspaceID, fragment)
	}
	structured := map[string]any{
		"fragment_id":  fragment.FragmentID,
		"text":         string(page),
		"offset":       int64(start),
		"length":       int64(len(page)),
		"next_offset":  nextOffset,
		"has_more":     hasMore,
		"limit":        limit,
		"total_length": total,
		"text_hash":    fragment.EvidenceTextHash,
		"page_hash":    pageHash,
		"address":      addressProjection,
		// canonical_address is the string round-trippable
		// internal/address value of this exact object; address.Parse of
		// this member returns the address verified before the page was
		// served.
		"canonical_address": canonicalAddress.String(),
	}
	if neighbors != nil {
		structured["neighbors"] = neighbors
	}
	pageURL := handler.evidenceSourcePageURL(workspaceID, fragment.FragmentID, canonicalAddress.String())
	if pageURL != "" {
		structured["source_page_url"] = pageURL
	}
	structured["is_current_version"] = fragment.IsCurrentVersion
	if fragment.SourcePath != "" {
		structured["source_path"] = fragment.SourcePath
	}
	if includeTextBase64 {
		structured["text_base64"] = base64.StdEncoding.EncodeToString(page)
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": mcpEvidenceReadPageContent(page, mcpEvidenceReadMetadata(
			" offset="+strconv.FormatInt(int64(start), 10)+
				" length="+strconv.FormatInt(int64(len(page)), 10)+
				" next_offset="+mcpContentCursor(nextOffset)+
				" has_more="+strconv.FormatBool(hasMore)+
				" limit="+strconv.FormatInt(limit, 10)+
				" total_length="+strconv.FormatInt(total, 10)+
				" text_hash="+fragment.EvidenceTextHash+
				" page_hash="+pageHash+mcpSourcePathText(fragment.SourcePath)+mcpEvidenceReadNeighborsMetadata(neighbors)+mcpSourcePageText(pageURL),
			canonicalAddress.String(),
			addressProjection,
		))}},
		"structuredContent": structured,
		"isError":           false,
	}})
}

// mcpEvidenceReadWholeObjectPage is the whole-object page core of
// knowvault_read (R3a-1 KV-A02a). It
// resolves the whole source version through the optional EvidenceWholeObject
// capability (the production *evidence.Viewer.ReadObject), so authorization,
// the ADR-0077 fragment hash and the admission/outcome audit journal are the
// canonical ones and no second read path exists. The address keeps its
// KV-A01c meaning: it must name the same source/object/version as the anchor
// fragment and its span hash must verify against the anchor fragment's
// canonical text (or against the reassembled whole text, for the address this
// mode itself emits). The whole text is paged with address.Read, so every page
// carries offset, total_bytes, has_more, next_cursor and the shared canonical
// whole_hash, and concatenating every page's exact bytes reproduces the whole
// original that hashes to whole_hash. A malformed or foreign cursor is refused
// with the typed, content-free -32602; a tampered address is -32005; a denied or
// foreign workspace is the viewer's single -32004 with no content.
func (handler *Handler) mcpEvidenceReadWholeObjectPage(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, workspaceID, fragmentID string, selector *address.Address, refVersionID, cursor string, limit int64, expectedSpanHash string, includeTextBase64 bool) {
	_, ok := handler.evidenceWholeObjectCapability()
	if !ok {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	object, err := handler.readEvidenceObjectSelection(request.Context(), access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil || object.Fragment.FragmentID == "" {
		writeMCPError(writer, envelope.ID, -32004, "evidence not found")
		return
	}
	if selector != nil {
		if selector.Source != object.Fragment.SourceObjectID || selector.Object != object.Fragment.FragmentID || !mcpReadAddressVersionMatches(*selector, object.Fragment.SourceVersionID, refVersionID) {
			writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
			return
		}
		if !handler.verifyAddressSpan(object.Fragment.Text, *selector) && !handler.verifyAddressSpan(object.Text, *selector) {
			writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
			return
		}
	}
	if expectedSpanHash != "" && expectedSpanHash != object.Fragment.EvidenceTextHash {
		writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
		return
	}
	if limit == 0 {
		limit = mcpEvidenceReadDefaultLimit
	}
	if limit > mcpEvidenceReadMaxLimit {
		limit = mcpEvidenceReadMaxLimit
	}
	page, err := address.Read(object.Text, cursor, int(limit))
	if err != nil {
		writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
		return
	}
	canonicalAddress, addressErr := handler.canonicalEvidenceWholeAddress(object)
	if addressErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	fragments, fragmentErr := handler.readPageFragments(workspaceID, object, page)
	if fragmentErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var nextCursor any
	if page.HasMore {
		nextCursor = page.NextCursor
	}
	pageHash := mcpEvidencePageHash(page.Data)
	addressProjection := mcpEvidenceAddress(object.Fragment)
	structured := map[string]any{
		"fragment_id":         object.Fragment.FragmentID,
		"text":                string(page.Data),
		"offset":              int64(page.Offset),
		"length":              int64(len(page.Data)),
		"next_cursor":         nextCursor,
		"has_more":            page.HasMore,
		"complete":            page.Complete,
		"limit":               limit,
		"total_bytes":         int64(page.TotalBytes),
		"whole_hash":          page.WholeHash,
		"text_representation": object.TextRepresentation(),
		"page_hash":           pageHash,
		"address":             addressProjection,
		// canonical_address is the string round-trippable internal/address
		// value of the WHOLE object: the same source/object/version as the
		// anchor with a half-open span over the reassembled whole text, so
		// address.WholeHash(object.Text) == whole_hash.
		"canonical_address": canonicalAddress.String(),
		"fragment_count":    object.FragmentCount,
		"fragments":         fragments,
		"ordinal_start":     object.FirstOrdinal,
		"ordinal_end":       object.LastOrdinal,
	}
	pageURL := handler.evidenceFragmentPageURL(workspaceID, object.Fragment)
	if pageURL != "" {
		structured["source_page_url"] = pageURL
	}
	structured["is_current_version"] = object.Fragment.IsCurrentVersion
	if object.Fragment.SourcePath != "" {
		structured["source_path"] = object.Fragment.SourcePath
	}
	if includeTextBase64 {
		structured["text_base64"] = base64.StdEncoding.EncodeToString(page.Data)
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": mcpEvidenceReadPageContent(page.Data, mcpEvidenceReadMetadata(
			" offset="+strconv.FormatInt(int64(page.Offset), 10)+
				" length="+strconv.FormatInt(int64(len(page.Data)), 10)+
				" next_cursor="+mcpEvidenceReadTextCursor(nextCursor)+
				" has_more="+strconv.FormatBool(page.HasMore)+
				" complete="+strconv.FormatBool(page.Complete)+
				" limit="+strconv.FormatInt(limit, 10)+
				" total_bytes="+strconv.FormatInt(int64(page.TotalBytes), 10)+
				" whole_hash="+page.WholeHash+
				" text_representation="+string(object.TextRepresentation())+
				" fragments="+mcpContentAddress(fragments)+
				" page_hash="+pageHash+mcpSourcePathText(object.Fragment.SourcePath)+mcpSourcePageText(pageURL),
			canonicalAddress.String(),
			addressProjection,
		))}},
		"structuredContent": structured,
		"isError":           false,
	}})
}

// mcpEvidenceReadPageContent renders the content[].text channel of one
// knowvault_read page: the page text itself followed by exactly one trailing
// metadata line. A client (or a model) that reads only content[].text therefore
// sees the page and can locate the span and continue the pagination without
// parsing structuredContent and without the base64 duplicate. Because the text
// channel is only reached once the authorized page was served, it stays
// content-free on every denial path.
func mcpEvidenceReadPageContent(page []byte, metadata string) string {
	return string(page) + "\n" + metadata
}

// mcpEvidenceReadMetadata is the single trailing line of a knowvault_read text
// page. It carries the mode-specific window and hash members first, then the
// canonical kv1 address string (the exact value of
// structuredContent.canonical_address a client passes back to knowvault_read),
// and closes with the same immutable address value the structuredContent
// channel carries (compact JSON). The address is last so that a JSON string
// value containing a space cannot make the space-separated window members
// ambiguous; the canonical kv1 text-span form is itself space-free.
func mcpEvidenceReadMetadata(rest string, canonicalAddress string, addressProjection any) string {
	return "knowvault_read" + rest + " canonical_address=" + canonicalAddress + " address=" + mcpContentAddress(addressProjection)
}

// mcpEvidenceReadTextCursor renders the whole-object page cursor for the text
// channel: the stable cursor string while more remains, the literal null once
// the page is the end, matching the structuredContent next_cursor.
func mcpEvidenceReadTextCursor(nextCursor any) string {
	if cursor, ok := nextCursor.(string); ok {
		return cursor
	}
	return "null"
}

// mcpEvidenceFragmentAddressBase builds the canonical internal/address value of
// one authorized fragment: source = source_object_id, object = fragment_id,
// version = source_version_id and span = the whole canonical text as a
// half-open character (Unicode code point) range [0, rune count). The base
// carries no span hash; the emitter attaches it with the organization digest
// key (or the anonymous compatibility key when none is wired).
func mcpEvidenceFragmentAddressBase(fragment evidence.Fragment) address.Address {
	return address.Address{
		Source:    fragment.SourceObjectID,
		Object:    fragment.FragmentID,
		Version:   fragment.SourceVersionID,
		SpanKind:  address.SpanKindText,
		CharStart: 0,
		CharEnd:   utf8.RuneCount(fragment.Text),
	}
}

// mcpEvidenceWholeObjectAddressBase builds the canonical internal/address value
// of one whole object: source = source_object_id, object = anchor fragment_id,
// version = source_version_id and span = the whole reassembled canonical text
// as a half-open character (Unicode code point) range [0, rune count).
func mcpEvidenceWholeObjectAddressBase(object evidence.WholeObject) address.Address {
	return address.Address{
		Source:    object.Fragment.SourceObjectID,
		Object:    object.Fragment.FragmentID,
		Version:   object.Fragment.SourceVersionID,
		SpanKind:  address.SpanKindText,
		CharStart: 0,
		CharEnd:   utf8.RuneCount(object.Text),
	}
}

// canonicalEvidenceAddress is the product emitter of one fragment's canonical
// address: the fragment base plus the organization-keyed span digest when
// composition wired the digester, and the package's anonymous compatibility
// digest otherwise.
func (handler *Handler) canonicalEvidenceAddress(fragment evidence.Fragment) (address.Address, error) {
	if handler == nil || handler.spanDigestKey == nil {
		return mcpCanonicalEvidenceAddress(fragment)
	}
	return handler.spanDigestKey.WithSpanHash(mcpEvidenceFragmentAddressBase(fragment), fragment.Text)
}

// canonicalEvidenceWholeAddress is the product emitter of one whole object's
// canonical address: the whole-object base plus the organization-keyed span
// digest of the reassembled whole text when composition wired the digester, and
// the package's anonymous compatibility digest otherwise.
func (handler *Handler) canonicalEvidenceWholeAddress(object evidence.WholeObject) (address.Address, error) {
	if handler == nil || handler.spanDigestKey == nil {
		return mcpCanonicalEvidenceWholeAddress(object)
	}
	return handler.spanDigestKey.WithSpanHash(mcpEvidenceWholeObjectAddressBase(object), object.Text)
}

// verifyAddressSpan accepts an address only when its SpanHash verifies against
// exactly the addressed bytes. A keyed handler verifies through the
// organization key first and then falls back to the anonymous compatibility key
// so an address a previous emitter produced stays readable; a tampered hash
// fails both paths and is still refused.
func (handler *Handler) verifyAddressSpan(original []byte, a address.Address) bool {
	if handler != nil && handler.spanDigestKey != nil {
		if _, err := handler.spanDigestKey.VerifySpan(original, a); err == nil {
			return true
		}
	}
	_, err := address.VerifySpan(original, a)
	return err == nil
}

// mcpCanonicalEvidenceWholeAddress builds the canonical internal/address value
// of one whole object with the package's anonymous compatibility digest. It is
// the direct-call shape focused tests use; a product emitter must dispatch
// through Handler.canonicalEvidenceWholeAddress so the organization key is
// applied.
func mcpCanonicalEvidenceWholeAddress(object evidence.WholeObject) (address.Address, error) {
	return mcpEvidenceWholeObjectAddressBase(object).WithSpanHash(object.Text)
}

// mcpEvidencePageStart snaps a byte offset forward to the next UTF-8 rune
// boundary so a page is always valid UTF-8. A caller paginating through
// next_offset never lands mid-rune, and an out-of-range offset is rejected by
// the caller before this function runs.
func mcpEvidencePageStart(text []byte, offset int) int {
	if offset < 0 {
		return 0
	}
	if offset > len(text) {
		return len(text)
	}
	for offset < len(text) && !utf8.RuneStart(text[offset]) {
		offset++
	}
	return offset
}

// mcpEvidencePageEnd returns the exclusive end of a page starting at a rune
// boundary, snapped back to a rune boundary but always advancing by at least
// one whole rune so pagination can never stall.
func mcpEvidencePageEnd(text []byte, start int, limit int64) int {
	end := start + int(limit)
	if end > len(text) {
		end = len(text)
	}
	for end > start && end < len(text) && !utf8.RuneStart(text[end]) {
		end--
	}
	if end == start && start < len(text) {
		_, size := utf8.DecodeRune(text[start:])
		end = start + size
	}
	return end
}

// mcpEvidencePageHash is the content hash of the exact page bytes, in the same
// "sha256:" form as the catalog hashes, so a client can verify a page before it
// trusts the reassembly.
func mcpEvidencePageHash(page []byte) string {
	sum := sha256.Sum256(page)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// mcpEvidenceAddress renders the immutable address of one authorized fragment:
// source, version, object and the exact span. It carries only ids, hashes and
// the canonical anchor already visible through the gated control-plane surface,
// never source content. The span is the fragment's canonical text itself
// (offset 0, length=total_length=len(text)); a page is the window over it
// reported by offset/length/next_offset on the read result.
func mcpEvidenceAddress(fragment evidence.Fragment) map[string]any {
	return map[string]any{
		"source": map[string]any{
			"source_object_id": fragment.SourceObjectID,
			"connection_id":    fragment.ConnectionID,
		},
		"version": map[string]any{
			"source_version_id":    fragment.SourceVersionID,
			"external_version_key": fragment.ExternalVersionKey,
			"content_hash":         fragment.ContentHash,
			"observed_at":          fragment.ObservedAt.UTC().Format(time.RFC3339),
		},
		"object": map[string]any{
			"extraction_id": fragment.ExtractionID,
			"ordinal":       fragment.Ordinal,
			"fragment_id":   fragment.FragmentID,
		},
		"span": map[string]any{
			"offset":       0,
			"length":       int64(len(fragment.Text)),
			"total_length": int64(len(fragment.Text)),
			"text_hash":    fragment.EvidenceTextHash,
			"anchor":       base64.StdEncoding.EncodeToString(fragment.Anchor),
		},
	}
}

// mcpCanonicalEvidenceAddress builds the canonical internal/address value of
// one authorized fragment with the package's anonymous compatibility digest. It
// is the direct-call shape focused tests use; a product emitter must dispatch
// through Handler.canonicalEvidenceAddress so the organization key is applied.
func mcpCanonicalEvidenceAddress(fragment evidence.Fragment) (address.Address, error) {
	return mcpEvidenceFragmentAddressBase(fragment).WithSpanHash(fragment.Text)
}

// mcpAuthorityToolCall is the MCP equivalent of the four ADR-0087 §1
// confirmation-authority REST actions (ADR-0053 commands). It resolves the same
// injected WorkspaceAuthority runtime the REST routes use and rejects the call
// before any repository touch when the composition did not supply an
// authority-capable workspace service (fail closed). Every tool requires the
// HTTP Idempotency-Key and projects the closed operator body onto the same
// repository command the accepted REST route builds, deriving organization and
// workspace server-side. The repository owns the role rules, issuer/confirmer
// separation, canonical envelope and content-free audit event; this surface only
// maps the repository's content-free error surface onto MCP error codes.
func (handler *Handler) mcpAuthorityToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	authority, ok := handler.authorityCommands()
	if !ok {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	key, _, code, _ := mutationHeaders(request, false)
	if code != "" {
		writeMCPError(writer, envelope.ID, -32001, "idempotency key required")
		return
	}
	var result workspacerepository.AuthorityResult
	var err error
	switch params.Name {
	case mcpToolConfirmationGrantIssue:
		var arguments mcpConfirmGrantIssueArguments
		if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
			writeMCPError(writer, envelope.ID, -32602, "invalid confirmation arguments")
			return
		}
		result, err = authority.IssueConfirmationGrant(request.Context(), access, workspacerepository.IssueGrantRequest{
			IdempotencyKey:                     key,
			OrganizationID:                     access.OrganizationID,
			WorkspaceID:                        arguments.WorkspaceID,
			ExpectedWorkspaceRevision:          arguments.ExpectedWorkspaceRevision,
			ExpectedWorkspaceConfigurationHash: arguments.ExpectedWorkspaceConfigurationHash,
			TargetPrincipalID:                  arguments.TargetPrincipalID,
			TTLSeconds:                         arguments.TTLSeconds,
			ExpectedPolicyRevision:             arguments.ExpectedPolicyRevision,
		})
	case mcpToolConfirmationGrantRevoke:
		var arguments mcpConfirmGrantRevokeArguments
		if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
			writeMCPError(writer, envelope.ID, -32602, "invalid confirmation arguments")
			return
		}
		result, err = authority.RevokeConfirmationGrant(request.Context(), access, workspacerepository.RevokeGrantRequest{
			IdempotencyKey:         key,
			OrganizationID:         access.OrganizationID,
			WorkspaceID:            arguments.WorkspaceID,
			GrantID:                arguments.GrantID,
			GrantRevision:          arguments.GrantRevision,
			GrantHash:              arguments.GrantHash,
			ExpectedPolicyRevision: arguments.ExpectedPolicyRevision,
		})
	case mcpToolManagedSourceConfirm:
		var arguments mcpManagedSourceConfirmArguments
		if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
			writeMCPError(writer, envelope.ID, -32602, "invalid confirmation arguments")
			return
		}
		result, err = authority.ConfirmManagedSource(request.Context(), access, workspacerepository.ConfirmRequest{
			IdempotencyKey:                 key,
			OrganizationID:                 access.OrganizationID,
			WorkspaceID:                    arguments.WorkspaceID,
			WorkspaceRevision:              arguments.WorkspaceRevision,
			WorkspaceConfigurationHash:     arguments.WorkspaceConfigurationHash,
			WorkspaceSourceID:              arguments.WorkspaceSourceID,
			SourceScopeID:                  arguments.SourceScopeID,
			SourceScopeRevision:            arguments.SourceScopeRevision,
			ScopeConfigHash:                arguments.ScopeConfigHash,
			AccessMode:                     managedAccessMode,
			ConfirmationActorGrantID:       arguments.ConfirmationActorGrantID,
			ConfirmationActorGrantRevision: arguments.ConfirmationActorGrantRevision,
			ConfirmationActorGrantHash:     arguments.ConfirmationActorGrantHash,
			WarningVersion:                 managedWarningVersion,
			WarningContractHash:            arguments.WarningContractHash,
			AcknowledgementCode:            managedAcknowledgementCode,
			ExpectedPolicyRevision:         arguments.ExpectedPolicyRevision,
		})
	case mcpToolManagedConfirmationRevoke:
		var arguments mcpManagedConfirmationRevokeArguments
		if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
			writeMCPError(writer, envelope.ID, -32602, "invalid confirmation arguments")
			return
		}
		result, err = authority.RevokeManagedConfirmation(request.Context(), access, workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey:         key,
			OrganizationID:         access.OrganizationID,
			WorkspaceID:            arguments.WorkspaceID,
			ConfirmationID:         arguments.ConfirmationID,
			ConfirmationHash:       arguments.ConfirmationHash,
			ExpectedPolicyRevision: arguments.ExpectedPolicyRevision,
		})
	default:
		writeMCPError(writer, envelope.ID, -32602, "invalid tool call")
		return
	}
	if err != nil {
		code, message := mcpAuthorityError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	// Same result envelope the REST action returns: only the immutable command,
	// operation, result id and hash, never the canonical bytes (ADR-0053).
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"structuredContent": authorityResultResponse(result),
		"isError":           false,
	}})
}

// mcpAuthorityError maps the ADR-0053 authority error surface onto the MCP
// error codes that correspond to the REST action's semantic outcome. Policy
// denial and a hidden/missing authority row both become one identical -32004
// not-found so the MCP surface exposes no role or existence oracle, exactly as
// the REST action collapses them into one 404 NOT_FOUND.
func mcpAuthorityError(err error) (int, string) {
	switch workspacerepository.CodeOf(err) {
	case workspacerepository.CodeAuthorityRequestInvalid:
		return -32602, "invalid confirmation arguments"
	case workspacerepository.CodeAuthorityIdempotencyConflict:
		return -32009, "confirmation idempotency conflict"
	case workspacerepository.CodeAuthorityPreconditionFailed:
		return -32009, "confirmation precondition failed"
	case workspacerepository.CodeAuthorityDenied, workspacerepository.CodeAuthorityNotFound:
		return -32004, "confirmation not found"
	case workspacerepository.CodeAuthorityPersistence:
		return -32000, "service unavailable"
	default:
		return -32000, "service unavailable"
	}
}

// mcpVerifyConnectionTrustToolCall is the MCP equivalent of the REST
// sources/connections/{id}:verify-trust action (ADR-0087 §2). It rejects the
// call before any repository touch when the composition did not supply a
// ConnectionTrustAuthority-capable workspace service (fail closed).
func (handler *Handler) mcpVerifyConnectionTrustToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	authority, ok := handler.connectionTrustAuthority()
	if !ok {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	key, _, code, _ := mutationHeaders(request, false)
	if code != "" {
		writeMCPError(writer, envelope.ID, -32001, "idempotency key required")
		return
	}
	var arguments mcpVerifyConnectionTrustArguments
	if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
		writeMCPError(writer, envelope.ID, -32602, "invalid verify-trust arguments")
		return
	}
	result, err := authority.VerifyConnectionTrust(request.Context(), access, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: key, ConnectionID: arguments.ConnectionID,
		AttestedConnectorIdentity: arguments.AttestedConnectorIdentity,
		AttestedBy:                arguments.AttestedBy,
		AttestedAt:                arguments.AttestedAt,
	})
	if err != nil {
		code, message := mcpConnectionTrustError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"structuredContent": map[string]any{"result_id": result.ResultID, "result_hash": result.ResultHash},
		"isError":           false,
	}})
}

// mcpConnectionTrustError maps the ADR-0087 §2 error surface onto MCP error
// codes, collapsing CodeConnectionTrustDenied/NotFound into one identical
// -32004 not-found so the MCP surface exposes no role or existence oracle,
// exactly as the REST action collapses them into one 404 NOT_FOUND.
func mcpConnectionTrustError(err error) (int, string) {
	switch workspacerepository.CodeOf(err) {
	case workspacerepository.CodeConnectionTrustRequestInvalid:
		return -32602, "invalid verify-trust arguments"
	case workspacerepository.CodeConnectionTrustIdempotencyConflict:
		return -32009, "verify-trust idempotency conflict"
	case workspacerepository.CodeConnectionTrustPreconditionFailed:
		return -32009, "verify-trust precondition failed"
	case workspacerepository.CodeConnectionTrustDenied, workspacerepository.CodeConnectionTrustNotFound:
		return -32004, "connection not found"
	case workspacerepository.CodeConnectionTrustPersistence:
		return -32000, "service unavailable"
	default:
		return -32000, "service unavailable"
	}
}

// mcpSourceEnableToolCall is the MCP equivalent of the REST
// POST /api/v1/workspaces/{id}/sources bind/re-enable action (ADR-0087 §3).
// It reaches the same WorkspaceService.AddSource the REST addSource route
// composes: a first bind of a freshly-registered DRAFT scope, or a re-enable
// of a scope a prior RemoveSource disabled, are the exact same command.
func (handler *Handler) mcpSourceEnableToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	key, _, code, _ := mutationHeaders(request, false)
	if code != "" {
		writeMCPError(writer, envelope.ID, -32001, "idempotency key required")
		return
	}
	var arguments mcpSourceEnableArguments
	if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
		writeMCPError(writer, envelope.ID, -32602, "invalid source enable arguments")
		return
	}
	snapshot, err := handler.service.AddSource(request.Context(), access, workspacerepository.AddSourceRequest{
		IdempotencyKey: key, WorkspaceID: arguments.WorkspaceID,
		ExpectedWorkspaceRevision: arguments.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: arguments.ExpectedWorkspaceConfigurationHash,
		SourceScopeID:             arguments.SourceScopeID, SourceScopeRevision: arguments.SourceScopeRevision,
		ScopeConfigHash: arguments.ScopeConfigHash, AccessMode: workspacerepository.SourceAccessMode(arguments.AccessMode),
	})
	if err != nil {
		code, message := mcpWorkspaceServiceError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"structuredContent": map[string]any{"revision": snapshot.Revision},
		"isError":           false,
	}})
}

// mcpWorkspaceServiceError maps the WorkspaceService error surface onto MCP
// error codes, mirroring serviceErrorResponse's REST mapping for the same
// AddSource/RemoveSource commands (isCreate is always false here: a source
// bind/re-enable never distinguishes "forbidden" from "not found").
func mcpWorkspaceServiceError(err error) (int, string) {
	switch workspacerepository.CodeOf(err) {
	case workspacerepository.CodeRequestInvalid:
		return -32602, "invalid source enable arguments"
	case workspacerepository.CodeDenied, workspacerepository.CodeNotFound:
		return -32004, "source binding not found"
	case workspacerepository.CodeRevisionConflict:
		return -32009, "workspace revision conflict"
	case workspacerepository.CodeIdempotencyConflict:
		return -32009, "idempotency conflict"
	default:
		return -32000, "service unavailable"
	}
}

// mcpSourceSyncToolCall is the MCP equivalent of the REST
// POST /api/v1/sources/{scope}:sync refresh action (ADR-0087 §3). It reaches
// the same SourceService.Sync the REST syncSource route composes.
func (handler *Handler) mcpSourceSyncToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.sources == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	key, _, code, _ := mutationHeaders(request, false)
	if code != "" {
		writeMCPError(writer, envelope.ID, -32001, "idempotency key required")
		return
	}
	var arguments mcpSourceSyncArguments
	if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil || !arguments.valid() {
		writeMCPError(writer, envelope.ID, -32602, "invalid source sync arguments")
		return
	}
	result, err := handler.sources.Sync(request.Context(), access, registration.SyncRequest{
		IdempotencyKey: key, SourceScopeID: arguments.SourceScopeID,
	})
	if err != nil {
		code, message := mcpSourceServiceError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"structuredContent": map[string]any{"job_id": result.JobID},
		"isError":           false,
	}})
}

// mcpGovernedQueryAskToolCall is the MCP equivalent of the REST
// governed-query-connections/{id}:ask action (ADR-0089). It reaches the same
// GovernedQueryService.Ask the REST handler composes; no SQL, DSN or
// credential is ever an accepted argument.
func (handler *Handler) mcpGovernedQueryAskToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.governedQuery == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpGovernedQueryAskArguments
	if parseErr := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); parseErr != nil ||
		arguments.WorkspaceID == "" || arguments.ConnectionID == "" || strings.TrimSpace(arguments.Question) == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid governed query ask arguments")
		return
	}
	result, err := handler.governedQuery.Ask(request.Context(), access, arguments.WorkspaceID, arguments.ConnectionID, arguments.Question)
	if err != nil {
		logGovernedAskFailure("mcp", err, access.RequestID)
		writeMCPError(writer, envelope.ID, -32000, "governed query ask unavailable")
		return
	}
	textResult, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "governed query ask unavailable")
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(textResult)}},
		"structuredContent": result,
		"isError":           false,
	}})
}

func mcpGovernedPresetToolDefinitions() []any {
	return []any{
		map[string]any{
			"name":        mcpToolQueriesList,
			"description": "List the administrator-approved live SQL query presets available for this workspace. Match an exact configured phrase or choose a preset by its description. SQL text and database credentials are never returned.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "connection_id": map[string]any{"type": "string"},
			}},
		},
		map[string]any{
			"name":        mcpToolQueryRun,
			"description": "Run one administrator-approved live SQL query preset by id in the dedicated read-only role. The server enforces workspace access, opt-in, statement timeout, EXPLAIN cost, row and byte limits, and returns a versioned audit receipt. This tool never accepts SQL.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "connection_id", "preset_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"}, "connection_id": map[string]any{"type": "string"}, "preset_id": map[string]any{"type": "string"},
			}},
		},
	}
}

func (handler *Handler) mcpGovernedPresetToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.governedPresets == nil || !handler.governedPresets.HasPresets() {
		writeMCPError(writer, envelope.ID, -32000, "query preset service unavailable")
		return
	}
	if params.Name == mcpToolQueriesList {
		var arguments mcpQueriesListArguments
		if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" {
			writeMCPError(writer, envelope.ID, -32602, "invalid query preset list arguments")
			return
		}
		result, err := handler.governedPresets.ListPresets(request.Context(), access, arguments.WorkspaceID, arguments.ConnectionID)
		if err != nil {
			logGovernedAskFailure("mcp-preset-list", err, access.RequestID)
			writeMCPError(writer, envelope.ID, -32000, "query presets unavailable")
			return
		}
		writeMCPGovernedPresetResult(writer, envelope, result)
		return
	}
	var arguments mcpQueryRunArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" || arguments.ConnectionID == "" || arguments.PresetID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid query preset run arguments")
		return
	}
	result, err := handler.governedPresets.RunPreset(request.Context(), access, arguments.WorkspaceID, arguments.ConnectionID, arguments.PresetID)
	if err != nil {
		logGovernedAskFailure("mcp-preset-run", err, access.RequestID)
		writeMCPError(writer, envelope.ID, -32000, "query preset unavailable")
		return
	}
	writeMCPGovernedPresetResult(writer, envelope, result)
}

func writeMCPGovernedPresetResult(writer http.ResponseWriter, envelope mcpRequest, result any) {
	textResult, err := jsonv2.Marshal(result)
	if err != nil {
		writeMCPError(writer, envelope.ID, -32000, "query preset unavailable")
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": string(textResult)}}, "structuredContent": result, "isError": false,
	}})
}

// mcpMetricDefinitionToolCall is the MCP equivalent of the REST
// metric-definitions list/get routes (R2 Outcome 1). It reaches the same
// injected, access-re-checked MetricDefinitionCatalog the REST routes use,
// forwards the caller's authenticated access context and the validated
// workspace/metric/version, and projects the results through the shared
// projectMetricDefinition, so the MCP field set is the REST field set. It fails
// closed before any catalog touch when composition mounted no capability, and
// it accepts no argument beyond its closed schema. No mutating tool is exposed:
// creating a DRAFT and approving a version stay with the owner authority.
func (handler *Handler) mcpMetricDefinitionToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.metricDefinitions == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if params.Name == mcpToolMetricDefinitionsList {
		var arguments mcpMetricDefinitionsListArguments
		if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" {
			writeMCPError(writer, envelope.ID, -32602, "invalid metric definition arguments")
			return
		}
		definitions, err := handler.metricDefinitions.List(request.Context(), access, arguments.WorkspaceID)
		if err != nil {
			code, message := mcpMetricDefinitionError(err)
			writeMCPError(writer, envelope.ID, code, message)
			return
		}
		items := make([]metricDefinitionResponse, len(definitions))
		for index, definition := range definitions {
			items[index] = projectMetricDefinition(definition)
		}
		writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
			"structuredContent": map[string]any{"definitions": items},
			"isError":           false,
		}})
		return
	}
	var arguments mcpMetricDefinitionGetArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || arguments.MetricID == "" || arguments.Version < 1 {
		writeMCPError(writer, envelope.ID, -32602, "invalid metric definition arguments")
		return
	}
	definition, err := handler.metricDefinitions.GetVersion(request.Context(), access, arguments.WorkspaceID, arguments.MetricID, arguments.Version)
	if err != nil {
		code, message := mcpMetricDefinitionError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"structuredContent": projectMetricDefinition(definition),
		"isError":           false,
	}})
}

// mcpMetricDefinitionError maps the content-free metric-definition failure
// surface onto MCP error codes, mirroring writeMetricDefinitionError's REST
// mapping exactly: denial, an unknown definition/version and an unknown version
// code collapse to one identical -32004 not-found (no role or existence
// oracle), an invalid definition request is -32602 invalid arguments and every
// other failure is a content-free -32000 service unavailable.
func mcpMetricDefinitionError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrMetricDefinitionDenied),
		errors.Is(err, ErrMetricDefinitionNotFound),
		metricdef.CodeOf(err) == metricdef.CodeUnknownVersion:
		return -32004, "metric definition not found"
	case metricdef.CodeOf(err) == metricdef.CodeInvalidDefinition:
		return -32602, "invalid metric definition arguments"
	default:
		return -32000, "service unavailable"
	}
}

// mcpSourcesListToolCall is the MCP equivalent of the REST
// GET /api/v1/workspaces/{id}/sources read (R3a-1 Outcome 2). It reaches the
// same injected SourceService the REST listSources route composes: ListSources
// for the source-inventory/schedule projection and ConfirmationContext for the
// ADR-0087 §1-§2 read. It forwards the caller's authenticated access context to
// both, so authorization, cross-tenant denial and audit stay where the REST
// route leaves them: in the service. The structuredContent projection is built
// from the identical sourceStatusResponse/confirmationContextResponse types the
// REST route uses, so the two surfaces cannot drift. It fails closed before any
// service touch when composition mounted no source capability, and it accepts
// no argument beyond its closed single-field schema.
func (handler *Handler) mcpSourcesListToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.sources == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpSourcesListArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || arguments.WorkspaceID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid sources list arguments")
		return
	}
	statuses, err := handler.sources.ListSources(request.Context(), access, arguments.WorkspaceID)
	if err != nil {
		code, message := mcpWorkspaceSourceToolError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	confirmation, err := handler.sources.ConfirmationContext(request.Context(), access, arguments.WorkspaceID)
	if err != nil {
		code, message := mcpWorkspaceSourceToolError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	items := mcpSourcesListItems(statuses, confirmation)
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": mcpSourcesListText(items)}},
		"structuredContent": mcpSourcesListProjectionFromItems(items, confirmation),
		"isError":           false,
	}})
}

// mcpRefreshToolCall is the MCP dispatch of the workspace knowledge refresh
// tool (R3a-1 Outcome 2 / design item 4(4)). It validates the closed argument
// envelope at the transport boundary and then delegates to the single shared
// workspaceToolRefreshPage core the REST /workspaces/{id}/tools/refresh route
// also composes, so admission-before-data, the R1 audit outcome (including a
// denial with a class), the content-free denial and the projection can never
// drift between the two transports. A denied, unknown or foreign workspace is
// the source service's single content-free not-found (-32004) with no source
// content and no workspace-id echo; a composition mounted without the source
// capability fails closed with -32000 and no content.
func (handler *Handler) mcpRefreshToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.sources == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpRefreshArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || arguments.Offset < 0 || arguments.Limit < 0 || len(arguments.SourceScopeID) > 128 {
		writeMCPError(writer, envelope.ID, -32602, "invalid refresh arguments")
		return
	}
	page, available, err := handler.workspaceToolRefreshPage(request, access, arguments.WorkspaceID, arguments.SourceScopeID, arguments.Offset, arguments.Limit)
	if !available {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if err != nil {
		code, message := mcpWorkspaceSourceToolError(err)
		writeMCPError(writer, envelope.ID, code, message)
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": workspaceRefreshText(page)}},
		"structuredContent": workspaceRefreshProjection(page),
		"isError":           false,
	}})
}

// EnableWorkspaceContext wires ADR-0098's workspacecontext.Reader capability
// (card A's store) into the knowvault_workspace_context / tools/workspace-context
// knowledge tool and the MCP initialize instructions. Composition
// (composition/runtime.go) calls this; a handler with no reader keeps every
// workspace-context surface content-free SERVICE_UNAVAILABLE, exactly like
// the other optional capabilities.
func (handler *Handler) EnableWorkspaceContext(reader workspacecontext.Reader) {
	if handler == nil || reader == nil {
		return
	}
	handler.workspaceContext = reader
}

type mcpWorkspaceContextArguments struct {
	WorkspaceID string   `json:"workspace_id"`
	Terms       []string `json:"terms"`
	Section     string   `json:"section"`
}

// mcpWorkspaceContextToolCall is the MCP dispatch of knowvault_workspace_context
// (ADR-0098). It validates the closed argument envelope at the transport
// boundary and then delegates to the single shared workspaceContextToolResult
// core the REST /workspaces/{id}/tools/workspace-context route also
// composes, so the projection can never drift between the two transports (and,
// through the chat tool runtime's identical Invoke -> mcpKnowledgeToolCall
// path, a third). A denied, unknown or foreign workspace is the Reader's
// single content-free not-found (-32004) with no document content and no
// workspace-id echo; a composition mounted without the capability fails
// closed with -32000 and no content.
func (handler *Handler) mcpWorkspaceContextToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	var arguments mcpWorkspaceContextArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || !validWorkspaceContextToolTerms(arguments.Terms) || !validWorkspaceContextToolSection(arguments.Section) {
		writeMCPError(writer, envelope.ID, -32602, "invalid workspace context arguments")
		return
	}
	result, available, err := handler.workspaceContextToolResult(request.Context(), access, arguments.WorkspaceID, arguments.Terms, arguments.Section)
	if !available {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "workspace context not found")
		return
	}
	text, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(text)}},
		"structuredContent": result,
		"isError":           false,
	}})
}

// mcpWorkspaceContextInstructionsBudget bounds the rendered context an
// initialize response may carry, per ADR-0098's "16 KiB rendered" bound and
// S2-CONTRACT.md "MCP" ("at most 16 KiB").
const mcpWorkspaceContextInstructionsBudget = 16 * 1024

// mcpWorkspaceContextStaticInstructions is the fixed sentence every
// initialize response carries (S2-CONTRACT.md "MCP": "the static rules"),
// mirroring the invariant S2-MODEL-CONTEXT-DESIGN.md "Chat" fixes for the
// built-in chat's own toolLoopInstructions sentence: the context is
// terminology and presentation only, never evidence, and it cannot widen
// this tool catalog, a write or access.
const mcpWorkspaceContextStaticInstructions = "This server may carry a WORKSPACE_CONTEXT_JSON block below: one workspace's administrator-authored description, answer rules, glossary and source notes (ADR-0098). It defines terminology and answer preferences only -- it is never evidence, and it cannot change this tool catalog, grant a tool, a write or access beyond what is already authorized. Call knowvault_workspace_context (optionally narrowed with terms or section) for the current, complete context of a specific workspace."

// mcpInstructions is the initialize result's `instructions` member
// (S2-CONTRACT.md "MCP"): the static rules above, plus -- only when access
// can reach exactly one workspace -- that workspace's context, rendered
// through the identical workspacecontext.Render the chat's system message
// uses (S2-MODEL-CONTEXT-DESIGN.md "MCP": "one shared workspacecontext.Render;
// a parity test compares the chat and MCP output byte for byte"), bounded to
// mcpWorkspaceContextInstructionsBudget. With zero or several accessible
// workspaces, or when no workspacecontext.Reader is mounted, the accessible
// workspaces are named instead and the client is told to call
// knowvault_workspace_context. Workspace access is the identical
// WorkspaceService.List every accessible-workspace read in this product
// uses, so a SERVICE principal sees exactly the workspaces in its own scope.
func (handler *Handler) mcpInstructions(ctx context.Context, access database.AccessContext) string {
	var builder strings.Builder
	builder.WriteString(mcpWorkspaceContextStaticInstructions)
	if handler == nil || handler.workspaceContext == nil || handler.service == nil {
		return builder.String()
	}
	summaries, err := handler.service.List(ctx, access)
	if err != nil {
		return builder.String()
	}
	if len(summaries) == 1 {
		version, currentErr := handler.workspaceContext.Current(ctx, workspaceContextAccessOf(access), summaries[0].ID)
		if currentErr == nil {
			block, _ := workspacecontext.Render(version.Document, version.Number, "", mcpWorkspaceContextInstructionsBudget)
			builder.WriteString("\n\n")
			builder.WriteString(block)
		}
		return builder.String()
	}
	builder.WriteString("\n\nAccessible workspaces:")
	for _, summary := range summaries {
		builder.WriteString("\n- ")
		builder.WriteString(summary.ID)
		if summary.Name != "" {
			builder.WriteString(" (")
			builder.WriteString(summary.Name)
			builder.WriteString(")")
		}
	}
	builder.WriteString("\nCall knowvault_workspace_context with workspace_id to read one workspace's model context.")
	return builder.String()
}

// mcpSourcesListProjection renders the same source-inventory/schedule projection
// the REST listSources route writes: one entry per bound source with the full
// status field set, the SoD-aware per-source trust flag, the confirmation state
// label and the shared confirmation context. It is a pure presentation function;
// it grants nothing and re-decides no authorization.
func mcpSourcesListProjection(statuses []workspacerepository.SourceStatus, confirmation workspacerepository.ConfirmationContext) map[string]any {
	return mcpSourcesListProjectionFromItems(mcpSourcesListItems(statuses, confirmation), confirmation)
}

// mcpSourcesListProjectionFromItems renders the shared source-entry projection
// from the items both channels are built from, so the REST/MCP structuredContent
// body and the MCP content[].text channel can never disagree about an entry.
func mcpSourcesListProjectionFromItems(items []sourceStatusResponse, confirmation workspacerepository.ConfirmationContext) map[string]any {
	return map[string]any{"sources": items, "confirmation_context": confirmationContextResponseFrom(confirmation)}
}

// mcpSourcesListItems builds the shared, fully populated source entries: the
// same sourceStatusResponse values mcpSourcesListProjection serialises and
// mcpSourcesListText renders, so the two channels derive from one projection.
func mcpSourcesListItems(statuses []workspacerepository.SourceStatus, confirmation workspacerepository.ConfirmationContext) []sourceStatusResponse {
	items := make([]sourceStatusResponse, len(statuses))
	for index, status := range statuses {
		items[index] = sourceStatusResponse{
			WorkspaceSourceID: status.WorkspaceSourceID,
			SourceScopeID:     status.SourceScopeID, SourceScopeRevision: status.SourceScopeRevision,
			AccessMode: status.AccessMode, Enabled: status.Enabled, ScopeConfigHash: status.ScopeConfigHash,
			ConnectionID: status.ConnectionID, ConnectionName: status.ConnectionName,
			SourceType: status.SourceType, PostgreSQLSchemaName: status.PostgreSQLSchemaName,
			PostgreSQLRelationName: status.PostgreSQLRelationName,
			ActivationStatus:       status.ActivationStatus, TrustVerified: status.TrustVerified,
			SyncStatus: status.SyncStatus, SyncErrorCode: status.SyncErrorCode,
			SyncStartedAt: status.SyncStartedAt, SyncCompletedAt: status.SyncCompletedAt,
			ObjectsSeen: status.ObjectsSeen, ObjectsIngested: status.ObjectsIngested,
			VersionsCreated: status.VersionsCreated, EvidencePublished: status.EvidencePublished,
			Quarantined: status.Quarantined,
			JobID:       status.JobID, JobStatus: status.JobStatus, JobAttemptCount: status.JobAttemptCount,
			JobMaxAttempts: status.JobMaxAttempts, JobAvailableAt: status.JobAvailableAt,
			JobLeaseExpiresAt: status.JobLeaseExpiresAt, JobLastErrorCode: status.JobLastErrorCode,
			ContentFreshnessSLASeconds: status.ContentFreshnessSLASeconds,
			LastSuccessfulSyncAt:       status.LastSuccessfulSyncAt, FreshnessState: status.FreshnessState,
			SyncIntervalSeconds: status.SyncIntervalSeconds,
			Confirmed:           status.Confirmed,
			ConfirmationState: confirmationStateFor(
				status.Enabled, status.Confirmed, status.TrustVerified, status.ActivationStatus, confirmation.SelfGrant != nil,
			),
			CanVerifyConnectionTrust: confirmation.CanVerifyConnectionTrust && !status.ViewerVerifyConflict,
			SQLAvailable:             status.SQLAvailable,
		}
	}
	return items
}

// mcpSourcesListText renders the content[].text channel of knowvault_sources as
// a compact, model-readable page: a leading context line with the source count,
// then the source entries themselves as exactly one line each,
// carrying the same workspace_source_id, source_scope_id, enabled, activation,
// sync and confirmation status and the same schedule/freshness values
// (sync_status, freshness_state, sync_interval_seconds, last_successful_sync_at)
// the structuredContent entry carries. A client that reads only content[].text
// therefore sees every source and every status without parsing structuredContent,
// and the rendering is only reached once the authorized inventory was read, so a
// denial stays content-free.
func mcpSourcesListText(items []sourceStatusResponse) string {
	var builder strings.Builder
	builder.WriteString("knowvault_sources: ")
	builder.WriteString(strconv.Itoa(len(items)))
	builder.WriteString(" source(s)\n")
	for index, item := range items {
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString("] workspace_source_id=")
		builder.WriteString(item.WorkspaceSourceID)
		builder.WriteString(" source_scope_id=")
		builder.WriteString(item.SourceScopeID)
		builder.WriteString(" source_type=")
		builder.WriteString(item.SourceType)
		builder.WriteString(" postgresql_schema_name=")
		builder.WriteString(mcpSourcesTextString(item.PostgreSQLSchemaName))
		builder.WriteString(" postgresql_relation_name=")
		builder.WriteString(mcpSourcesTextString(item.PostgreSQLRelationName))
		builder.WriteString(" enabled=")
		builder.WriteString(strconv.FormatBool(item.Enabled))
		builder.WriteString(" activation_status=")
		builder.WriteString(item.ActivationStatus)
		builder.WriteString(" sync_status=")
		builder.WriteString(mcpSourcesTextPointer(item.SyncStatus))
		builder.WriteString(" freshness_state=")
		builder.WriteString(item.FreshnessState)
		builder.WriteString(" sync_interval_seconds=")
		builder.WriteString(strconv.FormatInt(item.SyncIntervalSeconds, 10))
		builder.WriteString(" last_successful_sync_at=")
		builder.WriteString(mcpSourcesTextMoment(item.LastSuccessfulSyncAt))
		builder.WriteString(" objects_seen=")
		builder.WriteString(mcpSourcesTextInt64(item.ObjectsSeen))
		builder.WriteString(" objects_ingested=")
		builder.WriteString(mcpSourcesTextInt64(item.ObjectsIngested))
		builder.WriteString(" quarantined=")
		builder.WriteString(mcpSourcesTextInt64(item.Quarantined))
		builder.WriteString(" confirmation_state=")
		builder.WriteString(item.ConfirmationState)
		builder.WriteString("\n")
	}
	return builder.String()
}

// mcpSourcesTextPointer renders an absent optional status member as the literal
// null and a present one verbatim, so the text channel distinguishes "no sync
// yet" from an empty value exactly as the structured channel's JSON does.
func mcpSourcesTextPointer(value *string) string {
	if value == nil {
		return "null"
	}
	return mcpContentSingleLine(*value)
}

// mcpSourcesTextMoment renders an absent optional moment as the literal null and
// a present one in the same canonical UTC RFC3339 form the structured channel
// serialises.
func mcpSourcesTextMoment(value *time.Time) string {
	if value == nil {
		return "null"
	}
	return value.UTC().Format(time.RFC3339)
}

func mcpSourcesTextInt64(value *int64) string {
	if value == nil {
		return "null"
	}
	return strconv.FormatInt(*value, 10)
}

func mcpSourcesTextString(value *string) string {
	if value == nil {
		return "null"
	}
	return mcpContentSingleLine(*value)
}

// mcpSourceServiceError maps the SourceService (registration) error surface
// onto MCP error codes, mirroring sourceServiceErrorResponse's REST mapping
// for the same Activate/Sync commands with isCreate=false.
func mcpSourceServiceError(err error) (int, string) {
	switch registration.CodeOf(err) {
	case registration.CodeRequestInvalid:
		return -32602, "invalid source sync arguments"
	case registration.CodeDenied, registration.CodeNotFound:
		return -32004, "source scope not found"
	case registration.CodeConflict:
		return -32009, "source sync conflict"
	case registration.CodeUnavailable:
		return -32000, "service unavailable"
	default:
		return -32000, "service unavailable"
	}
}

// mcpWorkspaceSourceToolError is the MCP twin of
// handleWorkspaceSourceToolError: it recognises the production source facade's
// typed workspacerepository CodeNotFound/CodeDenied denial (a non-member,
// unknown or foreign workspace) and answers the documented content-free -32004
// "source scope not found", matching the REST 404, while every registration-typed
// error and every other error keeps the existing mcpSourceServiceError mapping.
func mcpWorkspaceSourceToolError(err error) (int, string) {
	if workspaceSourceToolErrorIsDenial(err) {
		return -32004, "source scope not found"
	}
	return mcpSourceServiceError(err)
}

func conversationMCPErrorCode(err error) int {
	switch conversation.CodeOf(err) {
	case conversation.CodeInvalid:
		return -32602
	case conversation.CodeIdempotencyConflict:
		return -32009
	case conversation.CodeDenied, conversation.CodeNotFound:
		return -32004
	default:
		return -32000
	}
}

func conversationMCPErrorMessage(err error) string {
	switch conversation.CodeOf(err) {
	case conversation.CodeInvalid:
		return "invalid conversation arguments"
	case conversation.CodeIdempotencyConflict:
		return "conversation idempotency conflict"
	case conversation.CodeDenied, conversation.CodeNotFound:
		return "conversation not found"
	default:
		return "conversation unavailable"
	}
}

func questionMCPErrorCode(err error) int {
	if question.CodeOf(err) == question.CodeInvalid {
		return -32602
	}
	return -32000
}

func validMCPID(value jsontext.Value) bool {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || len(trimmed) > 128 || !jsontext.Value(trimmed).IsValid(jsontext.AllowDuplicateNames(false)) {
		return false
	}
	kind := jsontext.Value(trimmed).Kind()
	return kind == jsontext.KindString || kind == jsontext.KindNumber
}

func writeMCP(writer http.ResponseWriter, response mcpResponse) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_ = jsonv2.MarshalWrite(writer, response)
}

func writeMCPError(writer http.ResponseWriter, id jsontext.Value, code int, message string) {
	if len(id) == 0 {
		id = jsontext.Value("null")
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{Code: code, Message: message}})
}

// writeMCPErrorClarification is writeMCPError plus R2 Outcome 2's additive
// refusal text. An empty clarification delegates to writeMCPError, so an error
// with no text is byte-for-byte identical to before.
func writeMCPErrorClarification(writer http.ResponseWriter, id jsontext.Value, code int, message, clarification string) {
	if clarification == "" {
		writeMCPError(writer, id, code, message)
		return
	}
	if len(id) == 0 {
		id = jsontext.Value("null")
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: id, Error: &mcpError{
		Code:    code,
		Message: message,
		Data:    &mcpErrorClarification{Clarification: clarification},
	}})
}

// auditDeniedAgentCall journals one refused SERVICE (agent access-code) MCP
// call through the access-code owner, which holds the audit store. It is a
// no-op for human sessions and when no access-code service is composed, and
// its failure never changes the refusal the caller already received.
func (handler *Handler) auditDeniedAgentCall(request *http.Request, access database.AccessContext, workspaceID, reasonCode string) {
	if handler == nil || handler.accessCodes == nil || request == nil ||
		access.EffectiveActorKind() != database.ActorKindService {
		return
	}
	handler.accessCodes.AuditDeniedAgentCall(request.Context(), access, workspaceID, reasonCode)
}
