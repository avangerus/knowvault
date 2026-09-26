// Package workspaceapi exposes the bounded Stage 1 workspace control plane.
// It does not compose tenants, issue cookies, open database transactions, or
// make policy decisions: those responsibilities remain with httpauth and the
// injected workspace service.
package workspaceapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/failurelog"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	sourceupload "knowvault.local/verified-workspace/internal/source/upload"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	apiPrefix            = "/api/v1"
	workspacesPath       = apiPrefix + "/workspaces"
	sourcesPath          = apiPrefix + "/sources"
	sourceConnectorsPath = apiPrefix + "/source-connectors"
	csrfPath             = apiPrefix + "/session/csrf"
	maxBodyBytes         = 32 << 10
	// maxBatchBodyBytes is the body bound of the two card S3.4b batch routes.
	// One request legitimately carries up to 1000 table tuples or 200 view
	// selectors, which cannot fit the single-object 32 KiB limit; every other
	// route keeps that default.
	maxBatchBodyBytes      = 512 << 10
	jsonContentType        = "application/json"
	questionModeExtractive = "EXTRACTIVE"
	// questionModeGenerative is GEN-1 (ADR-0088): accepted at this transport
	// boundary and forwarded unchanged; the question authority itself is the
	// single place that decides whether the capability is actually wired
	// (question.CodeUnsupportedMode otherwise).
	questionModeGenerative = "GENERATIVE"
)

// Authenticator is the only authentication and CSRF boundary used by this
// package. It is deliberately injected so this handler never selects a
// tenant from a header, path, query parameter, or body.
type Authenticator interface {
	Authenticate(*http.Request, string) (httpauth.Authentication, error)
	VerifyCSRF(*http.Request, httpauth.Authentication) error
	// RefreshCookie reissues the session cookie's Max-Age when FIX-7 #3's
	// sliding renewal just extended this exact session; a no-op otherwise
	// (unrenewed session, Bearer transport, or no renewer configured). Its
	// error is deliberately ignored by ServeHTTP: it is a best-effort
	// convenience on an already-authenticated request, never a new way for
	// this request to fail.
	RefreshCookie(http.ResponseWriter, *http.Request, httpauth.Authentication) error
}

// WorkspaceService is the repository boundary required by the control-plane
// routes. Authorization, idempotency persistence, and audit are intentionally
// performed there rather than duplicated in HTTP handlers.
type WorkspaceService interface {
	Create(context.Context, database.AccessContext, workspacerepository.CreateRequest) (workspace.Snapshot, error)
	Get(context.Context, database.AccessContext, string) (workspace.Snapshot, error)
	List(context.Context, database.AccessContext) ([]workspacerepository.Summary, error)
	Update(context.Context, database.AccessContext, workspacerepository.UpdateRequest) (workspace.Snapshot, error)
	Archive(context.Context, database.AccessContext, workspacerepository.ArchiveRequest) (workspace.Snapshot, error)
	AddMember(context.Context, database.AccessContext, workspacerepository.AddMemberRequest) (workspace.Snapshot, error)
	ChangeMemberRole(context.Context, database.AccessContext, workspacerepository.ChangeMemberRoleRequest) (workspace.Snapshot, error)
	RemoveMember(context.Context, database.AccessContext, workspacerepository.RemoveMemberRequest) (workspace.Snapshot, error)
	TransferOwnership(context.Context, database.AccessContext, workspacerepository.TransferOwnershipRequest) (workspace.Snapshot, error)
	AddSource(context.Context, database.AccessContext, workspacerepository.AddSourceRequest) (workspace.Snapshot, error)
	RemoveSource(context.Context, database.AccessContext, workspacerepository.RemoveSourceRequest) (workspace.Snapshot, error)
	AuditJournal(context.Context, database.AccessContext, string) (audit.Journal, error)
}

// WorkspaceAuditJournalBefore is the narrow keyset-continuation capability of
// the audit-journal route. It is satisfied at composition time by the same
// injected workspace repository Store that implements WorkspaceService
// (internal/workspace/repository.Store), and the handler reaches it by a type
// assertion on handler.service exactly like the authority runtimes. A service
// that does not implement it means the continuation runtime was not composed
// under this handler, so a before_sequence request fails closed as a
// content-free SERVICE_UNAVAILABLE rather than falling back to the legacy
// first-page read or bypassing the policy gate. The compile-time assertion
// below proves the production Store really carries this capability, not just
// a test double.
type WorkspaceAuditJournalBefore interface {
	AuditJournalBefore(context.Context, database.AccessContext, string, int64) (audit.Journal, error)
}

var _ WorkspaceAuditJournalBefore = (*workspacerepository.Store)(nil)

// WorkspaceAuthority is the ADR-0053 confirmation-command runtime. It is
// satisfied at composition time by the same injected workspace repository Store
// that implements WorkspaceService (ADR-0087 §1 composes these four operations
// in this package as typed REST actions). The REST layer never re-decides a
// policy or writes an audit event itself: it projects a closed JSON command onto
// the unchanged repository request and maps the repository's content-free error
// surface. Role rules, issuer/confirmer separation, the canonical JCS envelope
// and the content-free audit events all stay inside the repository methods. A
// service that does not implement this interface means the authority runtime was
// not composed under this handler, and the confirmation routes fail closed.
type WorkspaceAuthority interface {
	IssueConfirmationGrant(context.Context, database.AccessContext, workspacerepository.IssueGrantRequest) (workspacerepository.AuthorityResult, error)
	ConfirmManagedSource(context.Context, database.AccessContext, workspacerepository.ConfirmRequest) (workspacerepository.AuthorityResult, error)
	// ConfirmManagedSourcesBatch is card S3.4b's bounded composite of
	// ConfirmManagedSource: up to workspacerepository.MaxBatchConfirmTables
	// tables in one request, each one through the unchanged individual command,
	// with one closed per-table outcome. The name matches the repository's own
	// method so the production Store really satisfies this interface; the
	// compile-time assertion below keeps that from regressing silently.
	ConfirmManagedSourcesBatch(context.Context, database.AccessContext, workspacerepository.BatchConfirmRequest) (workspacerepository.BatchConfirmResult, error)
	RevokeConfirmationGrant(context.Context, database.AccessContext, workspacerepository.RevokeGrantRequest) (workspacerepository.AuthorityResult, error)
	RevokeManagedConfirmation(context.Context, database.AccessContext, workspacerepository.RevokeConfirmationRequest) (workspacerepository.AuthorityResult, error)
}

// The production workspace repository is the one runtime that must satisfy
// WorkspaceAuthority. Card U-1's screen walkthrough found that it did not: the
// interface named ConfirmManagedSourceBatch while the Store implements
// ConfirmManagedSourcesBatch, so the type assertion in authorityCommands()
// failed at run time and every managed-source confirmation (individual and
// batch) answered 503 SERVICE_UNAVAILABLE -- exactly the «Confirm» error the
// owner saw on the demo stand. This assertion makes that mismatch a build
// failure instead of a silent dead route.
var _ WorkspaceAuthority = (*workspacerepository.Store)(nil)

// ConnectionTrustAuthority is the ADR-0087 §2 connection trust verification
// runtime. Like WorkspaceAuthority it is satisfied at composition time by the
// same injected workspace repository Store; a service that does not implement
// it means the runtime was not composed under this handler, and the
// verify-trust route fails closed exactly as the confirmation routes do.
type ConnectionTrustAuthority interface {
	VerifyConnectionTrust(context.Context, database.AccessContext, workspacerepository.VerifyConnectionTrustRequest) (workspacerepository.VerifyConnectionTrustResult, error)
}

// WorkspaceMemberCandidateAuthority is the P10a read boundary for the
// authorized member-candidate picker. It is satisfied at composition time by
// the same injected workspace repository Store that implements WorkspaceService,
// and the route reaches it by type assertion on handler.service exactly like
// the confirmation-authority and connection-trust runtimes. The repository
// performs the OperationWorkspaceManage (OWNER/MANAGER of an ACTIVE workspace)
// authorization and returns only bounded ACTIVE USER principals of the caller's
// own organization, so this handler never re-decides a role rule and never sees
// a foreign tenant, a credential or an external identity link. A service that
// does not implement it means the runtime was not composed under this handler,
// and the member-candidates route fails closed as SERVICE_UNAVAILABLE.
type WorkspaceMemberCandidateAuthority interface {
	MemberCandidates(context.Context, database.AccessContext, string, string) (workspacerepository.MemberCandidateResult, error)
}

// SourceService is the registration boundary required by the source routes.
// The organization-OWNER gate, idempotency persistence, queue placement and
// audit are intentionally performed there rather than duplicated in HTTP
// handlers (ADR-0074).
type SourceService interface {
	Register(context.Context, database.AccessContext, registration.RegisterRequest) (registration.RegisterResult, error)
	Activate(context.Context, database.AccessContext, registration.ActivateRequest) (registration.ActivateResult, error)
	Sync(context.Context, database.AccessContext, registration.SyncRequest) (registration.SyncResult, error)
	ListSources(context.Context, database.AccessContext, string) ([]workspacerepository.SourceStatus, error)
	ConfirmationContext(context.Context, database.AccessContext, string) (workspacerepository.ConfirmationContext, error)
	// UploadDocuments is UPL-1: it stores one browser upload's files as new or
	// updated versions of an already-registered FOLDER source. Unlike every
	// other method here it is not gated by the organization-OWNER policy --
	// only the individual source owner (source_connection.created_by) may
	// call it, which registration.Service enforces itself.
	UploadDocuments(context.Context, database.AccessContext, registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error)
}

// SourceConnectorCatalog is the read-only versioned catalog of the connector
// types the registration surface accepts (GET /api/v1/source-connectors). It is
// a deliberately narrow capability owned by source/registration and exposed in
// production by composition's sourceServiceFacade, which delegates to
// registration.Service.ConnectorCatalog for the same source-management OWNER
// gate every source action uses, so this handler never re-decides eligibility
// and never sees a configured source or credential. A production service that
// does not implement it keeps the onboarding route content-free
// SERVICE_UNAVAILABLE.
type SourceConnectorCatalog interface {
	ConnectorCatalog(context.Context, database.AccessContext) (registration.ConnectorCatalog, error)
}

// SourceConnectionBootstrap is the connection-only PostgreSQL onboarding
// capability. It creates an immutable DRAFT connection revision without a
// scope, activation, workspace binding or content job.
type SourceConnectionBootstrap interface {
	BootstrapPostgreSQLConnection(context.Context, database.AccessContext, registration.PostgreSQLConnectionBootstrapRequest) (registration.PostgreSQLConnectionBootstrapResult, error)
}

// SourceConnectionDrafts is card D-1's workspace-scoped view of unfinished
// PostgreSQL connections plus the pointer-only discard. It is deliberately a
// separate optional capability (exactly like SourceConnectorCatalog and
// SourceDiscovery) so every existing SourceService implementation and test
// fake stays source-compatible: the production facade implements it by pure
// delegation to the workspace repository, and a service that does not means
// the runtime was not composed for this route. Reads audit through the same
// source-metadata boundary as ListSources; both methods return the identical
// content-free CodeNotFound for an unauthorized, unknown or foreign workspace.
type SourceConnectionDrafts interface {
	ListSourceConnectionDrafts(context.Context, database.AccessContext, string) ([]workspacerepository.SourceConnectionDraft, error)
	DiscardSourceConnectionDraft(context.Context, database.AccessContext, string, string) error
}

// SourceDiscovery is the asynchronous connection inventory capability. The
// POST command accepts only a connection reference and idempotency key; the
// GET command returns a bounded server-derived catalog projection.
type SourceDiscovery interface {
	RequestDiscovery(context.Context, database.AccessContext, registration.DiscoveryRequest) (registration.DiscoveryResult, error)
	GetDiscovery(context.Context, database.AccessContext, string) (sourcediscovery.ReadResult, error)
}

// SourceDiscoveryRegistration resolves and registers one server-issued view
// selector. No projection metadata is accepted from the HTTP request; the
// only caller-supplied content is the optional excluded-column-ordinal list
// (ADR-0097), narrowing a base/partitioned-table projection the server
// already discovered, and the optional registration mode (S3 card 4):
// INDEXED (the default) or QUERY_ONLY ("only for SQL queries, not indexed").
type SourceDiscoveryRegistration interface {
	RegisterDiscoveredView(context.Context, database.AccessContext, string, string, []int, string) (registration.RegisterResult, error)
	// RegisterDiscoveredViews is card S3.4b's bounded batch: one server request
	// registers up to registration.MaxBatchRegisterViews selectors with the
	// same per-table rules and a per-table outcome.
	RegisterDiscoveredViews(context.Context, database.AccessContext, string, []registration.BatchRegisterItem) (registration.BatchRegisterResult, error)
}

// SourceSchemaProvider is ADR-0097's optional, read-only source schema
// capability behind the knowvault_source_schema knowledge tool. It is
// discovered on the injected source service exactly like the other optional
// source capabilities, so a service that does not implement it leaves the
// tool failing closed rather than widening the required SourceService
// interface. The production implementation is the workspace repository's
// sourceMetadataRead boundary: authorization, cross-tenant invisibility and
// the source.metadata.read.* audit journal stay there, and neither method
// touches the external source database.
type SourceSchemaProvider interface {
	ListSourceSchemas(context.Context, database.AccessContext, string) ([]workspacerepository.SourceSchemaSource, error)
	SourceSchema(context.Context, database.AccessContext, string, string, string, int, int) (workspacerepository.SourceSchema, error)
}

// EvidenceService is the read boundary for the Evidence viewer route. The
// fail-closed authorization gate (ADR-0073 §1.2) lives inside the viewer:
// every denial is the same ErrNotFound, so this handler must never distinguish
// reasons and maps every viewer error to one identical 404.
type EvidenceService interface {
	Read(context.Context, database.AccessContext, string, string) (evidence.Fragment, error)
}

// EvidenceSearch is the optional additive lexical-search capability of the
// authorized Evidence viewer (R3a-1 Outcome 2). It is deliberately separate
// from EvidenceService so every existing EvidenceService implementation —
// including the REST read boundary and the test fakes — stays source
// compatible: a service that does not implement it leaves the workspace search
// tool unadvertised and failing closed rather than widening the required
// interface. The production *evidence.Viewer implements it.
type EvidenceSearch interface {
	SearchFragments(context.Context, database.AccessContext, string, string, bool, int64, int64) (evidence.SearchPage, error)
}

// The exported relation-direction vocabulary is the same closed set the
// knowvault_related tool accepts (mcp_related.go). It is exported so the
// production relation source composed outside this package selects the related
// endpoint with the identical constants the transport validated, rather than
// re-spelling the vocabulary.
const (
	RelatedDirectionReferencing = mcpRelatedDirectionReferencing
	RelatedDirectionReferences  = mcpRelatedDirectionReferences
	RelatedDirectionBoth        = mcpRelatedDirectionBoth
)

// QuestionService is the single Question Run authority. The HTTP layer only
// validates its closed envelope and projects the typed result; authorization,
// idempotency, retrieval and evidence disclosure stay in internal/question.
type QuestionService interface {
	Create(context.Context, database.AccessContext, question.CreateRequest) (question.Run, error)
	Get(context.Context, database.AccessContext, string, string) (question.Run, error)
	// GetBatch is FIX-5 #2: the same disclosure gate as Get, resolving every
	// run in runIDs inside one transaction instead of one Get() call (and one
	// transaction) per run -- see projectConversations.
	GetBatch(ctx context.Context, access database.AccessContext, workspaceID string, runIDs []string) (map[string]question.Run, error)
	// ProcessingMode is FIX-2 #4: the workspace-scoped generation processing
	// mode (INTERNAL/EXTERNAL/INTERNAL_UNAVAILABLE) and provider name shown
	// on the workspace snapshot.
	ProcessingMode(workspaceID string) (string, string)
	// StructuredRowset is FIX-2 #3 / FIX-7 #1: the tabular evidence for a
	// structured source's Evidence fragment (nil, nil for a document
	// fragment), scoped by the last string argument -- "" or "matched"
	// (default) for the rows the citing answer actually matched, "full" for
	// the source scope's entire current snapshot.
	StructuredRowset(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, scope string) (*question.RowsetEvidence, error)
}

// QuestionFeedbackService is the narrow answer-feedback capability
// (R1.S10.s1.T4). It is satisfied by the production *question.Service and
// reached only by a type assertion on handler.questions; a QuestionService
// that does not implement it fails the feedback/report routes closed as a
// content-free SERVICE_UNAVAILABLE rather than silently no-oping the mark or
// bypassing the workspace.read_content / workspace.manage policy gates that
// live in internal/question.
type QuestionFeedbackService interface {
	SubmitFeedback(ctx context.Context, access database.AccessContext, workspaceID, runID string, verdict question.FeedbackVerdict, comment string) (question.Feedback, error)
	OwnFeedback(ctx context.Context, access database.AccessContext, workspaceID, runID string) (question.Feedback, bool, error)
	FeedbackReport(ctx context.Context, access database.AccessContext, workspaceID string) ([]question.FeedbackReportEntry, error)
}

var _ QuestionFeedbackService = (*question.Service)(nil)

// ConversationService is the single lifecycle/read authority.  It returns
// metadata and opaque Question Run links; handlers enrich those links only via
// the existing QuestionService disclosure gate.
type ConversationService interface {
	List(context.Context, database.AccessContext, string) ([]conversation.View, error)
	Get(context.Context, database.AccessContext, string, string) (conversation.View, error)
	Archive(context.Context, database.AccessContext, conversation.ArchiveRequest) (conversation.View, error)
}

// ConversationPageService is the narrow bounded-pagination capability of the
// GET conversations route (N3). It is satisfied by the real
// *conversation.Service (compile-time assertion below) and is reached only by
// a type assertion on handler.conversations for a request that actually
// carried limit/cursor. A legacy/fake ConversationService without it keeps the
// no-query path through List unchanged, while a paginated request fails closed
// as a content-free SERVICE_UNAVAILABLE rather than falling back to an
// unauthorized in-memory slice or bypassing the workspace gate.
type ConversationPageService interface {
	ListPage(context.Context, database.AccessContext, string, int, string) (conversation.Page, error)
}

var _ ConversationPageService = (*conversation.Service)(nil)

// conversationPageLimitMax mirrors conversation.maxConversationPage: the HTTP
// boundary enforces the same 1..50 bound the service clamps to, so an
// out-of-range limit is refused as REQUEST_INVALID rather than silently
// clamped by the handler.
const conversationPageLimitMax = 50

// AccessCodeService is the V1-C agent access-code authority
// (internal/serviceprincipal). Issue/List/Revoke are OWNER-gated workspace
// control-plane actions; Authenticate is the completely separate pre-session
// resolution path the MCP endpoint alone uses for a Bearer access code (never
// for the browser/API session routes).
type AccessCodeService interface {
	Issue(context.Context, database.AccessContext, serviceprincipal.IssueRequest) (serviceprincipal.IssueResult, error)
	List(context.Context, database.AccessContext, string) ([]serviceprincipal.Credential, error)
	Revoke(context.Context, database.AccessContext, string) error
	Authenticate(ctx context.Context, organizationID, rawCode, requestID string) (database.AccessContext, error)
	// AuditDeniedAgentCall journals a refused SERVICE-principal MCP call
	// content-free (V1-C): the workspace an agent named and one closed reason
	// code, never the question, arguments or the code itself.
	AuditDeniedAgentCall(ctx context.Context, access database.AccessContext, workspaceID, reasonCode string)
}

// Handler is safe for concurrent use once constructed.
type Handler struct {
	authenticator  Authenticator
	service        WorkspaceService
	sources        SourceService
	evidence       EvidenceService
	questions      QuestionService
	conversations  ConversationService
	accessCodes    AccessCodeService
	organizationID string
	requestIDs     requestIDSource
	// governedQuery is ADR-0089's optional capability. It is nil unless
	// EnableGovernedQuery was called by composition after a valid mounted
	// connection and Model Gateway adapter were both loaded; a nil value
	// keeps every governed-query-connections route content-free
	// SERVICE_UNAVAILABLE, mirroring the questions field's own
	// capability-gated shape.
	governedQuery GovernedQueryService
	// governedPresets is the optional, model-independent MCP catalogue of
	// administrator-mounted SQL presets. It is discovered from the same
	// governed service but kept as a narrow interface so existing transports
	// and test doubles do not gain new mandatory methods.
	governedPresets GovernedQueryPresetService
	// governedQueryModePolicy retains the optional mounted-policy authority so
	// each MCP request observes its current decision. Its nil zero value
	// preserves the legacy ad-hoc surface for existing service test doubles.
	governedQueryModePolicy GovernedQueryModePolicy
	// spanDigestKey is R3a-1's organization-scoped ADR-0077 span digest key
	// (the same keyed HMAC family as evidence_fragment.text_hash). When it is
	// wired through EnableSpanDigest every emitted kv1 address carries the
	// organization-keyed SpanHash instead of the package's non-secret
	// anonymous-key compatibility digest, and a keyed address verifies through
	// this key. It is nil for handlers composed without the mounted digester
	// (focused tests and capability-gated deployments); the anonymous
	// compatibility path keeps those surfaces unchanged. It is a pointer so a
	// zero-key-version value can never be mistaken for the wired state.
	spanDigestKey      *address.SpanDigestKey
	evidencePageOrigin string
	// searchProfile is EMB-1s optional capability, wired by composition only
	// when the deployment mounts an embedding channel. A nil value keeps both
	// search-profile routes content-free SERVICE_UNAVAILABLE.
	searchProfile SearchProfileService
	// metricDefinitions is R2 Outcome 1's optional, read-only MetricDefinition
	// capability, wired by composition only when a definition projection is
	// mounted. A nil value keeps both metric-definition routes content-free
	// SERVICE_UNAVAILABLE.
	metricDefinitions MetricDefinitionCatalog
	// metricDefinitionAuthoring is R2 Outcome 1's optional, owner-only write
	// capability (draft a definition, approve its current DRAFT version). It is
	// separate from the read catalog so the read surface keeps its read-only
	// contract and its existing fakes. A nil value keeps both write routes
	// content-free SERVICE_UNAVAILABLE, exactly like the other optional
	// capabilities; the injected implementation owns the workspace access
	// re-check, owner check, audit event and version monotonicity.
	metricDefinitionAuthoring MetricDefinitionAuthoring
	// hybridSearch is S3's optional hybrid retrieval capability, wired by
	// composition only when the deployment mounts an index and (optionally) an
	// embedding channel. A nil value keeps knowvault_search exactly the lexical
	// tool it was, labelled as lexical.
	hybridSearch WorkspaceHybridSearch
	// searchProfiles is the owner-only ablation channel of §7.5. A nil value
	// means a presented profile header is ignored, because granting it without
	// an authority to journal the decision would be an unrecorded ablation.
	searchProfiles SearchProfileChannel
	// modelContext is S2 card A's optional PostgreSQL-backed workspace model
	// context capability (ADR-0098), wired by composition only once
	// internal/workspacecontext.Store is mounted. A nil value keeps every
	// model-context document route content-free SERVICE_UNAVAILABLE.
	modelContext ModelContextService
	// modelContextProposals is card E's optional workspacecontext.ProposalService
	// implementation. A nil value keeps every proposal route content-free
	// SERVICE_UNAVAILABLE, per S2-CONTRACT.md.
	modelContextProposals workspacecontext.ProposalService
	// modelContextProposalExamples is the optional example-dialogue resolver
	// (see model_context.go's file-level deviation note 3). A nil value keeps
	// every listed proposal's examples empty and hidden_examples at 0.
	modelContextProposalExamples ProposalExampleResolver
	// workspaceContext is ADR-0098's optional Reader capability for the
	// knowvault_workspace_context / tools/workspace-context knowledge tool
	// and the MCP initialize instructions' single-workspace rendered
	// context, wired by composition only when a workspacecontext store
	// (card A) is mounted. A nil value keeps every workspace-context surface
	// content-free SERVICE_UNAVAILABLE, exactly like the other optional
	// capabilities; EnableWorkspaceContext (mcp_adapter.go) sets it. It backs
	// both the MCP tool and the REST tool-parity route
	// (endpointWorkspaceToolWorkspaceContext, via workspaceToolDispatch) --
	// the one kept implementation of that path; card A's
	// endpointModelContextTool duplicate was removed during S2 integration
	// (see model_context.go's file-level deviation note 4).
	workspaceContext workspacecontext.Reader
}

// GovernedQueryService is the ADR-0089 orchestration boundary
// (internal/governedask.Service satisfies it). workspaceapi never holds the
// dedicated governed-execution role's connection capability itself and never
// constructs SQL text; it only forwards a natural-language question and the
// operator's own exposed-schema/promotion input to this service.
type GovernedQueryService interface {
	SetLiveQueries(ctx context.Context, access database.AccessContext, workspaceID, connectionID string, enabled bool) error
	RegisterExposedSchema(ctx context.Context, access database.AccessContext, workspaceID, connectionID string, objects []governedquery.ExposedObject) (int64, error)
	Ask(ctx context.Context, access database.AccessContext, workspaceID, connectionID, question string) (governedask.AskResult, error)
	// Promote saves an ALREADY EXECUTED attempt by its server-owned id and the
	// hash the operator was shown. There is deliberately no SQL parameter: the
	// API surface never accepts SQL text (PRODUCT_CONSTITUTION.md §7).
	Promote(ctx context.Context, access database.AccessContext, workspaceID, connectionID, attemptID, expectedSQLHash string) (governedquery.PromotionResult, error)
}

type GovernedQueryPresetService interface {
	HasPresets() bool
	ListPresets(ctx context.Context, access database.AccessContext, workspaceID, connectionID string) (governedask.PresetCatalog, error)
	RunPreset(ctx context.Context, access database.AccessContext, workspaceID, connectionID, presetID string) (governedask.PresetRunResult, error)
	ResolvePresetPhrase(ctx context.Context, access database.AccessContext, workspaceID, phrase string) (governedquery.PresetSummary, bool, error)
}

// GovernedQueryModePolicy is the narrow optional policy projection exposed by
// governedask.Service. Existing GovernedQueryService implementations need not
// implement it and retain the legacy ad-hoc behavior.
type GovernedQueryModePolicy interface {
	PresetOnly() bool
}

// EnableGovernedQuery wires the ADR-0089 governed-query orchestration
// service. Composition calls this when a valid mounted connection exists.
// Ad-hoc ask still requires a Model Gateway adapter; reviewed presets do not.
// Omitting the call keeps every governed-query-connections route a content-free
// SERVICE_UNAVAILABLE.
// EnableSearchProfile wires the EMB-1 retrieval profile authority. Like every
// other optional capability it is composed after a valid mount, never inferred
// from a request.
func (handler *Handler) EnableSearchProfile(service SearchProfileService) {
	if handler == nil || service == nil {
		return
	}
	handler.searchProfile = service
}

func (handler *Handler) EnableGovernedQuery(service GovernedQueryService) {
	if handler == nil || service == nil {
		return
	}
	handler.governedQuery = service
	handler.governedQueryModePolicy = nil
	if policy, ok := service.(GovernedQueryModePolicy); ok {
		handler.governedQueryModePolicy = policy
	}
	if presets, ok := service.(GovernedQueryPresetService); ok && presets.HasPresets() {
		handler.governedPresets = presets
	}
}

func (handler *Handler) governedQueryIsPresetOnly() bool {
	return handler != nil && handler.governedQueryModePolicy != nil && handler.governedQueryModePolicy.PresetOnly()
}

// EnableSpanDigest wires the organization-scoped ADR-0077 span digest key that
// every produced kv1 address must carry (R3a-1). Composition calls it with the
// same mounted source-digest key the ingestion digester and source registration
// already use, so an address span hash is derived from exactly the keyed family
// as evidence_fragment.text_hash and never from a bare plaintext digest. A
// handler composed without the call keeps the package's anonymous compatibility
// digest, so the existing focused surfaces are unchanged.
func (handler *Handler) EnableSpanDigest(key address.SpanDigestKey) {
	if handler == nil {
		return
	}
	handler.spanDigestKey = &key
}

type requestIDSource interface {
	New() (string, error)
}

type cryptoRequestIDSource struct{}

func (cryptoRequestIDSource) New() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

// New constructs the production handler with server-side CSPRNG request IDs.
func New(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService) (*Handler, error) {
	return newHandler(authenticator, service, sources, evidence, cryptoRequestIDSource{})
}

// NewWithQuestions composes the live Question Run authority in addition to the
// existing workspace control-plane routes. New remains available for focused
// control-plane tests and deliberately leaves the question route unavailable.
func NewWithQuestions(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService, questions QuestionService) (*Handler, error) {
	return newHandlerWithQuestionsAndConversations(authenticator, service, sources, evidence, questions, nil, cryptoRequestIDSource{})
}

// NewWithQuestionsAndConversations composes the live Question and conversation
// authorities.  Both HTTP and MCP call these same injected services.
func NewWithQuestionsAndConversations(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService, questions QuestionService, conversations ConversationService) (*Handler, error) {
	return newHandlerWithQuestionsAndConversations(authenticator, service, sources, evidence, questions, conversations, cryptoRequestIDSource{})
}

// NewWithServiceAccess additionally composes the V1-C agent access-code
// authority: the REST issue/list/revoke routes and the MCP Bearer-access-code
// authenticator. organizationID is the deployment's one fixed tenant (the
// same single-tenant identity every other mounted capability already binds
// to at composition time); it is never derived from a request.
func NewWithServiceAccess(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService, questions QuestionService, conversations ConversationService, accessCodes AccessCodeService, organizationID string) (*Handler, error) {
	handler, err := newHandlerWithQuestionsAndConversations(authenticator, service, sources, evidence, questions, conversations, cryptoRequestIDSource{})
	if err != nil {
		return nil, err
	}
	if accessCodes == nil || !validOpaqueID(organizationID) {
		return nil, errors.New("workspaceapi service-access dependencies are required")
	}
	handler.accessCodes = accessCodes
	handler.organizationID = organizationID
	return handler, nil
}

func newHandler(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService, requestIDs requestIDSource) (*Handler, error) {
	return newHandlerWithQuestions(authenticator, service, sources, evidence, nil, requestIDs)
}

func newHandlerWithQuestions(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService, questions QuestionService, requestIDs requestIDSource) (*Handler, error) {
	return newHandlerWithQuestionsAndConversations(authenticator, service, sources, evidence, questions, nil, requestIDs)
}

func newHandlerWithQuestionsAndConversations(authenticator Authenticator, service WorkspaceService, sources SourceService, evidence EvidenceService, questions QuestionService, conversations ConversationService, requestIDs requestIDSource) (*Handler, error) {
	if authenticator == nil || service == nil || sources == nil || evidence == nil || requestIDs == nil {
		return nil, errors.New("workspaceapi dependencies are required")
	}
	return &Handler{authenticator: authenticator, service: service, sources: sources, evidence: evidence, questions: questions, conversations: conversations, requestIDs: requestIDs}, nil
}

// ServeHTTP authenticates every exact API route before it reads a request body
// or invokes the service. Non-matching or ambiguous paths are never cleaned,
// decoded into aliases, or sent to the service.
func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.authenticator == nil || handler.service == nil || handler.sources == nil || handler.requestIDs == nil || request == nil {
		setServerFailureCause(writer, "workspace handler dependency missing", "unwired boundary")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "")
		return
	}
	endpoint, pathCode := parseEndpoint(request)
	requestID, requestIDErr := handler.requestIDs.New()
	if requestIDErr != nil || !validRequestID(requestID) {
		setServerFailureCause(writer, "workspace request id generation failed", "ENTROPY_UNAVAILABLE")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "")
		return
	}
	writer.Header().Set("X-Request-ID", requestID)
	if pathCode != "" {
		writeError(writer, statusForPathCode(pathCode), pathCode, requestID)
		return
	}
	// V1-C agent access codes: MCP alone accepts a SERVICE credential as
	// `Authorization: Bearer kva_...`, resolved by a completely separate
	// authenticator (internal/serviceprincipal) from the human session
	// authenticator below. It is a non-browser bearer transport exactly like
	// the existing session-bearer form, so it must never be combined with a
	// cookie or an Origin/CSRF header, and it skips CSRF verification for the
	// same reason httpauth's own apiBearer form does.
	if endpoint.kind == endpointMCP && handler.accessCodes != nil {
		if code, ok := serviceAccessCodeBearer(request); ok {
			if !methodAllowed(endpoint, request.Method) {
				writer.Header().Set("Allow", allowedMethods(endpoint))
				writeError(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", requestID)
				return
			}
			access, authErr := handler.accessCodes.Authenticate(request.Context(), handler.organizationID, code, requestID)
			if authErr != nil {
				writeError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", requestID)
				return
			}
			handler.mcp(writer, request, access, requestID)
			return
		}
	}

	authentication, err := handler.authenticator.Authenticate(request, requestID)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", requestID)
		return
	}
	_ = handler.authenticator.RefreshCookie(writer, request, authentication)
	if unsafeMethod(request.Method) {
		if err := handler.authenticator.VerifyCSRF(request, authentication); err != nil {
			writeError(writer, http.StatusForbidden, "CSRF_REJECTED", requestID)
			return
		}
	}
	if !methodAllowed(endpoint, request.Method) {
		writer.Header().Set("Allow", allowedMethods(endpoint))
		writeError(writer, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", requestID)
		return
	}

	access := authentication.Session().Access
	switch endpoint.kind {
	case endpointCSRF:
		writeJSON(writer, http.StatusOK, map[string]string{"csrf_token": authentication.CSRFToken()})
	case endpointWorkspaceList:
		handler.list(writer, request, access, requestID)
	case endpointWorkspaceCreate:
		handler.create(writer, request, access, requestID)
	case endpointWorkspaceGet:
		handler.get(writer, request, access, requestID, endpoint.workspaceID)
	case endpointWorkspaceUpdate:
		handler.update(writer, request, access, requestID, endpoint.workspaceID)
	case endpointWorkspaceArchive:
		handler.archive(writer, request, access, requestID, endpoint.workspaceID)
	case endpointMemberAdd:
		handler.addMember(writer, request, access, requestID, endpoint.workspaceID)
	case endpointMemberChange:
		handler.changeMemberRole(writer, request, access, requestID, endpoint.workspaceID, endpoint.principalID)
	case endpointMemberRemove:
		handler.removeMember(writer, request, access, requestID, endpoint.workspaceID, endpoint.principalID)
	case endpointOwnershipTransfer:
		handler.transferOwnership(writer, request, access, requestID, endpoint.workspaceID)
	case endpointSourceRegister:
		handler.registerSource(writer, request, access, requestID)
	case endpointSourceConnectionBootstrap:
		handler.bootstrapPostgreSQLConnection(writer, request, access, requestID)
	case endpointSourceDiscoveryRequest:
		handler.requestSourceDiscovery(writer, request, access, requestID, endpoint.connectionID)
	case endpointSourceDiscoveryGet:
		handler.getSourceDiscovery(writer, request, access, requestID, endpoint.discoveryRequestID)
	case endpointSourceDiscoveryRegister:
		handler.registerSourceDiscoveryView(writer, request, access, requestID,
			endpoint.discoveryRequestID, endpoint.discoveryViewID)
	case endpointSourceDiscoveryRegisterBatch:
		handler.registerSourceDiscoveryViewBatch(writer, request, access, requestID, endpoint.discoveryRequestID)
	case endpointSourceActivate:
		handler.activateSource(writer, request, access, requestID, endpoint.sourceScopeID)
	case endpointSourceSync:
		handler.syncSource(writer, request, access, requestID, endpoint.sourceScopeID)
	case endpointSourceUploadDocuments:
		handler.uploadDocuments(writer, request, access, requestID, endpoint.sourceScopeID)
	case endpointWorkspaceSources:
		if request.Method == http.MethodGet {
			handler.listSources(writer, request, access, requestID, endpoint.workspaceID)
		} else {
			handler.addSource(writer, request, access, requestID, endpoint.workspaceID)
		}
	case endpointWorkspaceSourceRemove:
		handler.removeSource(writer, request, access, requestID, endpoint.workspaceID, endpoint.sourceScopeID)
	case endpointWorkspaceSourceDrafts:
		handler.listSourceConnectionDrafts(writer, request, access, requestID, endpoint.workspaceID)
	case endpointWorkspaceSourceDraftDiscard:
		handler.discardSourceConnectionDraft(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointEvidenceGet:
		handler.evidenceGet(writer, request, access, requestID, endpoint.workspaceID, endpoint.fragmentID)
	case endpointWorkspaceAuditEvents:
		handler.auditJournal(writer, request, access, requestID, endpoint.workspaceID, endpoint.journalBeforeSequence)
	case endpointQuestionCreate:
		handler.questionCreate(writer, request, access, requestID, endpoint.workspaceID)
	case endpointQuestionGet:
		handler.questionGet(writer, request, access, requestID, endpoint.workspaceID, endpoint.questionRunID)
	case endpointQuestionFeedback:
		if request.Method == http.MethodGet {
			handler.questionFeedbackGet(writer, request, access, requestID, endpoint.workspaceID, endpoint.questionRunID)
		} else {
			handler.questionFeedbackSubmit(writer, request, access, requestID, endpoint.workspaceID, endpoint.questionRunID)
		}
	case endpointQuestionFeedbackReport:
		handler.questionFeedbackReport(writer, request, access, requestID, endpoint.workspaceID)
	case endpointConversationList:
		handler.conversationList(writer, request, access, requestID, endpoint.workspaceID, endpoint.conversationPaginated, endpoint.conversationPageLimit, endpoint.conversationCursor)
	case endpointConversationGet:
		handler.conversationGet(writer, request, access, requestID, endpoint.workspaceID, endpoint.conversationID)
	case endpointConversationArchive:
		handler.conversationArchive(writer, request, access, requestID, endpoint.workspaceID, endpoint.conversationID)
	case endpointMCP:
		handler.mcp(writer, request, access, requestID)
	case endpointConfirmGrantIssue:
		handler.confirmGrantIssue(writer, request, access, requestID, endpoint.workspaceID)
	case endpointConfirmGrantRevoke:
		handler.confirmGrantRevoke(writer, request, access, requestID, endpoint.workspaceID, endpoint.authorityID)
	case endpointManagedSourceConfirm:
		handler.managedSourceConfirm(writer, request, access, requestID, endpoint.workspaceID)
	case endpointManagedSourceConfirmBatch:
		handler.managedSourceConfirmBatch(writer, request, access, requestID, endpoint.workspaceID)
	case endpointManagedConfirmationRevoke:
		handler.managedConfirmationRevoke(writer, request, access, requestID, endpoint.workspaceID, endpoint.authorityID)
	case endpointSourceConnectionVerifyTrust:
		handler.verifyConnectionTrust(writer, request, access, requestID, endpoint.connectionID)
	case endpointSourceQueryCredentialSet:
		handler.setSourceQueryCredential(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointSourceQueryCredentialClear:
		handler.clearSourceQueryCredential(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointAccessCodes:
		if request.Method == http.MethodGet {
			handler.accessCodeList(writer, request, access, requestID, endpoint.workspaceID)
		} else {
			handler.accessCodeIssue(writer, request, access, requestID, endpoint.workspaceID)
		}
	case endpointAccessCodeRevoke:
		handler.accessCodeRevoke(writer, request, access, requestID, endpoint.workspaceID, endpoint.credentialID)
	case endpointSearchProfile:
		handler.searchProfileStatus(writer, request, access, requestID, endpoint.workspaceID)
	case endpointSearchProfileRevise:
		handler.searchProfileRevise(writer, request, access, requestID, endpoint.workspaceID)
	case endpointGovernedQuerySetLiveQueries:
		handler.governedQuerySetLiveQueries(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointGovernedQueryExposedSchema:
		handler.governedQueryExposedSchema(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointGovernedQueryAsk:
		handler.governedQueryAsk(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointGovernedQueryPromote:
		handler.governedQueryPromote(writer, request, access, requestID, endpoint.workspaceID, endpoint.connectionID)
	case endpointSourceConnectors:
		handler.sourceConnectors(writer, request, access, requestID)
	case endpointMemberCandidates:
		handler.memberCandidates(writer, request, access, requestID, endpoint.workspaceID)
	case endpointMetricDefinitions:
		handler.metricDefinitionList(writer, request, access, requestID, endpoint.workspaceID)
	case endpointMetricDefinitionGet:
		handler.metricDefinitionGet(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.metricDefinitionID, endpoint.metricDefinitionVersion)
	case endpointMetricDefinitionDraft:
		handler.metricDefinitionDraft(writer, request, access, requestID, endpoint.workspaceID)
	case endpointMetricDefinitionApprove:
		handler.metricDefinitionApprove(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.metricDefinitionID)
	case endpointModelContextGet:
		handler.modelContextGet(writer, request, access, requestID, endpoint.workspaceID)
	case endpointModelContextSave:
		handler.modelContextSave(writer, request, access, requestID, endpoint.workspaceID)
	case endpointModelContextVersions:
		handler.modelContextVersionsList(writer, request, access, requestID, endpoint.workspaceID)
	case endpointModelContextVersionGet:
		handler.modelContextVersionGet(writer, request, access, requestID, endpoint.workspaceID, endpoint.modelContextVersion)
	case endpointModelContextRestore:
		handler.modelContextRestore(writer, request, access, requestID, endpoint.workspaceID, endpoint.modelContextVersion)
	case endpointModelContextProposals:
		handler.modelContextProposalsList(writer, request, access, requestID, endpoint.workspaceID)
	case endpointModelContextProposalAccept:
		handler.modelContextProposalAccept(writer, request, access, requestID, endpoint.workspaceID, endpoint.modelContextProposalID)
	case endpointModelContextProposalReject:
		handler.modelContextProposalReject(writer, request, access, requestID, endpoint.workspaceID, endpoint.modelContextProposalID)
	case endpointWorkspaceToolListObjects, endpointWorkspaceToolSearch, endpointWorkspaceToolGrep,
		endpointWorkspaceToolRelated, endpointWorkspaceToolRead, endpointWorkspaceToolSources, endpointWorkspaceToolRefresh,
		endpointWorkspaceToolWorkspaceContext, endpointWorkspaceToolSourceSchema, endpointWorkspaceToolSourceSQL:
		handler.workspaceToolDispatch(writer, request, access, requestID, endpoint)
	default:
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	}
}

type endpointKind uint8

const (
	endpointCSRF endpointKind = iota + 1
	endpointWorkspaceList
	endpointWorkspaceCreate
	endpointWorkspaceGet
	endpointWorkspaceUpdate
	endpointWorkspaceArchive
	endpointMemberAdd
	endpointMemberChange
	endpointMemberRemove
	endpointOwnershipTransfer
	endpointSourceRegister
	endpointSourceConnectionBootstrap
	endpointSourceDiscoveryRequest
	endpointSourceDiscoveryGet
	endpointSourceDiscoveryRegister
	endpointSourceActivate
	endpointSourceSync
	endpointWorkspaceSources
	endpointWorkspaceSourceRemove
	// endpointWorkspaceSourceDrafts is card D-1's workspace-scoped read of the
	// unfinished PostgreSQL connections the workspace started
	// (GET /api/v1/workspaces/{workspace_id}/source-drafts). It is a separate
	// route rather than a field of the sources envelope so the MCP
	// sources/list projection stays byte-identical to its own contract.
	endpointWorkspaceSourceDrafts
	// endpointWorkspaceSourceDraftDiscard removes one workspace-scoped draft
	// pointer (DELETE /api/v1/workspaces/{workspace_id}/source-drafts/{connection_id}).
	endpointWorkspaceSourceDraftDiscard
	endpointEvidenceGet
	endpointWorkspaceAuditEvents
	endpointQuestionCreate
	endpointQuestionGet
	endpointConversationList
	endpointConversationGet
	endpointConversationArchive
	endpointMCP
	endpointConfirmGrantIssue
	endpointConfirmGrantRevoke
	endpointManagedSourceConfirm
	endpointManagedConfirmationRevoke
	endpointSourceConnectionVerifyTrust
	endpointAccessCodes
	endpointAccessCodeRevoke
	endpointSearchProfile
	endpointSearchProfileRevise
	endpointGovernedQuerySetLiveQueries
	endpointGovernedQueryExposedSchema
	endpointGovernedQueryAsk
	endpointGovernedQueryPromote
	endpointSourceUploadDocuments
	// endpointSourceConnectors is the read-only onboarding catalog
	// (GET /api/v1/source-connectors): a deterministic, content-free versioned
	// registry of the connector types registration accepts, gated by the
	// same source-management OWNER policy every source action uses.
	endpointSourceConnectors
	// endpointMemberCandidates is the P10a authorized member-candidate picker
	// (GET /api/v1/workspaces/{workspace_id}/member-candidates?q=<text>): a
	// read-only, bounded search of ACTIVE USER principals in the caller's own
	// organization, authorized to the workspace's OWNER/MANAGER.
	endpointMemberCandidates
	// endpointMetricDefinitions is R2 Outcome 1's read-only version catalog
	// (GET /api/v1/workspaces/{workspace_id}/metric-definitions): every issued
	// MetricDefinition version of a workspace, access-re-checked by the
	// injected catalog exactly like any other protected read.
	endpointMetricDefinitions
	// endpointMetricDefinitionGet is the exact-version read
	// (GET /api/v1/workspaces/{workspace_id}/metric-definitions/{metric_id}/versions/{version}).
	endpointMetricDefinitionGet
	// endpointMetricDefinitionDraft is R2 Outcome 1's additive, owner-only
	// draft write (POST /api/v1/workspaces/{workspace_id}/metric-definitions:draft):
	// it creates version 1 of a new definition id, or a new monotonic DRAFT
	// version when the current version of that id is APPROVED. The workspace
	// access re-check, the owner check, the approval/audit boundary and version
	// monotonicity all live in the injected authoring capability.
	endpointMetricDefinitionDraft
	// endpointMetricDefinitionApprove is the additive, owner-only approval of
	// the current DRAFT version
	// (POST /api/v1/workspaces/{workspace_id}/metric-definitions/{metric_id}:approve).
	endpointMetricDefinitionApprove
	// endpointWorkspaceToolListObjects is R3a-1 KV-A02's REST parity route for
	// the knowvault_list_objects workspace object-inventory knowledge tool
	// (GET /api/v1/workspaces/{workspace_id}/tools/list-objects). It is a
	// read-only, workspace-scoped surface that dispatches through the identical
	// authorized Evidence viewer capability the MCP tool composes, so the
	// admission-before-data journal, the content-free denial and the paginated
	// version/moment/address projection are the same implementation, not a
	// re-derivation.
	endpointWorkspaceToolListObjects
	// endpointWorkspaceToolSearch is R3a-1 KV-A03's REST parity route for the
	// knowvault_search workspace lexical-search knowledge tool
	// (GET/POST /api/v1/workspaces/{workspace_id}/tools/search). It is a
	// read-only, workspace-scoped surface that dispatches through the identical
	// authorized Evidence viewer search capability the MCP tool composes, so the
	// admission-before-data journal, the content-free denial and the paginated
	// excerpt/score/address projection are the same implementation, not a
	// re-derivation.
	endpointWorkspaceToolSearch
	// endpointWorkspaceToolGrep is R3a-1 KV-A02c's REST parity route for the
	// knowvault_grep workspace exact-regex knowledge tool
	// (GET/POST /api/v1/workspaces/{workspace_id}/tools/grep). It is a
	// read-only, workspace-scoped surface that dispatches through the identical
	// authorized EvidenceGrep capability the MCP tool composes, so the
	// admission-before-data journal, the content-free denial and the paginated
	// offset/length/excerpt/address projection are the same implementation, not
	// a re-derivation.
	endpointWorkspaceToolGrep
	// endpointWorkspaceToolRelated is R3a-1's REST parity route for the
	// knowvault_related workspace cross-source relation knowledge tool
	// (GET/POST /api/v1/workspaces/{workspace_id}/tools/related). It is a
	// read-only, workspace-scoped surface that dispatches through the identical
	// authorized EvidenceRelated capability the MCP tool composes, so the
	// admission-before-data journal, the content-free denial and the paginated
	// relation-kind/excerpt/address projection are the same implementation, not
	// a re-derivation.
	endpointWorkspaceToolRelated
	// endpointWorkspaceToolRead is R3a-1 Outcome 1's REST parity route for the
	// knowvault_read paged address-read knowledge tool
	// (GET/POST /api/v1/workspaces/{workspace_id}/tools/read). It is a
	// read-only, workspace-scoped surface that dispatches through the identical
	// authorized Evidence viewer (fragment-page mode) and EvidenceWholeObject
	// capability plus address.Read (whole-object cursor mode) the MCP tool
	// composes, so authorization, the admission-before-data journal, the
	// content-free denial and the span-hash refusal are the same implementation,
	// not a re-derivation.
	endpointWorkspaceToolRead
	// endpointWorkspaceToolSources is R3a-1 Outcome 2's REST parity route for
	// the knowvault_sources_list source-inventory/schedule knowledge tool
	// (GET/POST /api/v1/workspaces/{workspace_id}/tools/sources). It is a
	// read-only, workspace-scoped surface that composes the identical injected
	// SourceService.ListSources + ConfirmationContext reads and the identical
	// mcpSourcesListProjection the MCP tool and the existing
	// GET /workspaces/{id}/sources route use, so the projection, the
	// content-free denial and the source-service error mapping are the same
	// implementation, not a re-derivation.
	endpointWorkspaceToolSources
	// endpointWorkspaceToolRefresh is R3a-1 Outcome 2's REST parity route for
	// the knowvault_refresh workspace source-refresh knowledge tool
	// (GET/POST /api/v1/workspaces/{workspace_id}/tools/refresh). It is a
	// workspace-scoped surface that dispatches through the identical authorized
	// SourceService.ListSources read and SourceService.Sync command the MCP tool
	// composes, so the admission-before-data audit journal, the content-free
	// denial and the projection are the same implementation, not a
	// re-derivation.
	endpointWorkspaceToolRefresh
	// endpointModelContextGet/endpointModelContextSave are S2 card A's
	// (ADR-0098) current-context routes on the same path
	// (GET / PUT /api/v1/workspaces/{workspace_id}/model-context), split into
	// two kinds exactly like endpointWorkspaceGet/endpointWorkspaceUpdate so
	// each keeps its own single HTTP method.
	endpointModelContextGet
	endpointModelContextSave
	// endpointModelContextVersions is the read-only history list
	// (GET .../model-context/versions).
	endpointModelContextVersions
	// endpointModelContextVersionGet is the exact-version read
	// (GET .../model-context/versions/{version}).
	endpointModelContextVersionGet
	// endpointModelContextRestore mints a new version from a historical one
	// (POST .../model-context/versions/{version}:restore).
	endpointModelContextRestore
	// endpointModelContextProposals is the OWNER/MANAGER-only proposal review
	// queue (GET .../model-context/proposals).
	endpointModelContextProposals
	// endpointModelContextProposalAccept/endpointModelContextProposalReject are
	// the OWNER/MANAGER-only proposal decisions
	// (POST .../model-context/proposals/{proposal_id}:accept|:reject).
	endpointModelContextProposalAccept
	endpointModelContextProposalReject
	// endpointWorkspaceToolWorkspaceContext is ADR-0098's REST tool-parity
	// route for the knowvault_workspace_context knowledge tool
	// (POST /api/v1/workspaces/{workspace_id}/tools/workspace-context, the
	// only workspace tool-parity route that is POST-only: its optional
	// terms/section filter travels in a JSON body, not a query string). It
	// dispatches through the identical injected workspacecontext.Reader the
	// MCP tool and the chat tool runtime compose, so the projection and the
	// content-free denial are the same implementation, not a re-derivation.
	//
	// S2 integration note: card A also implemented this same REST path as a
	// dedicated endpointModelContextTool kind backed by ModelContextService,
	// which duplicated this projection outside the shared
	// workspacecontext.Reader/MatchTerms path the MCP tool and the chat tool
	// runtime use. That duplicate was removed during merge so
	// tools/workspace-context has exactly one implementation, the one that
	// is byte-identical with MCP and chat (S2-CONTRACT.md "Tool parity").
	endpointWorkspaceToolWorkspaceContext
	// endpointWorkspaceToolSourceSchema is ADR-0097's REST tool-parity route
	// for the knowvault_source_schema knowledge tool
	// (POST /api/v1/workspaces/{workspace_id}/tools/source-schema, POST-only
	// like the workspace-context route: its optional source_id/table/offset/
	// limit arguments travel in a JSON body). It dispatches through the
	// identical injected SourceSchemaProvider and shared
	// sourceSchemaToolResult core the MCP tool and the chat tool runtime
	// compose, so the projection, the page window and the content-free denial
	// are the same implementation, not a re-derivation.
	endpointWorkspaceToolSourceSchema
	// endpointWorkspaceToolSourceSQL is ADR-0097's REST tool-parity route for
	// the knowvault_source_sql knowledge tool
	// (POST /api/v1/workspaces/{workspace_id}/tools/source-sql, POST-only like
	// the source-schema route: its source_id/sql/purpose arguments travel in a
	// JSON body). It dispatches through the identical injected
	// SourceSQLProvider and shared sourceSQLToolResult core the MCP tool and
	// the chat tool runtime compose, so the projection, the closed refusal
	// vocabulary and the content-free denial are the same implementation, not
	// a re-derivation. The route is the agent-facing parity surface ADR-0097
	// §2 permits; no UI, operator or user-facing field accepts SQL.
	endpointWorkspaceToolSourceSQL
	// endpointSourceQueryCredentialSet is S3 card 2b's organization-OWNER
	// control that sets or clears the opaque SQL query credential reference of
	// one PostgreSQL source connection
	// (POST /api/v1/workspaces/{workspace_id}/source-connections/{connection_id}:set-query-credential).
	// The reference is an opaque 'cred' id; no DSN, password or secret value is
	// ever accepted or returned. A non-owner, an unknown workspace and a
	// foreign connection are one content-free 404, like every other OWNER
	// source operation.
	endpointSourceQueryCredentialSet
	// endpointSourceQueryCredentialClear is the removal half
	// (POST /api/v1/workspaces/{workspace_id}/source-connections/{connection_id}:clear-query-credential).
	// After it the tool answers SOURCE_SQL_NOT_CONFIGURED and the Sources card
	// shows "SQL not configured".
	endpointSourceQueryCredentialClear
	// endpointManagedSourceConfirmBatch is card S3.4b's bounded batch of
	// WORKSPACE_MANAGED_CONFIRM commands
	// (POST /api/v1/workspaces/{workspace_id}/managed-source-confirmations:batch).
	// It is a composite of the single confirm route, not a new ADR-0053
	// operation: the repository confirms each named table through the unchanged
	// individual command and returns one closed per-table outcome, so every
	// table keeps the identical decision phase, confirmation document, audit
	// event and replay receipt. At most MaxBatchConfirmTables tables per
	// request; a larger request is refused as a whole.
	endpointManagedSourceConfirmBatch
	// endpointSourceDiscoveryRegisterBatch is card S3.4b's bounded batch of
	// discovered-view registrations
	// (POST /api/v1/sources/discovery/{request_id}:register-batch). It accepts
	// at most registration.MaxBatchRegisterViews selectors and returns one
	// per-view outcome, so registering hundreds of discovered tables from the
	// wizard is one server request per batch instead of one request per table.
	endpointSourceDiscoveryRegisterBatch
	// endpointQuestionFeedback is R1.S10.s1.T4's answer-feedback mark
	// (GET/POST /api/v1/workspaces/{workspace_id}/questions/{question_run_id}:feedback).
	// GET returns the caller's own current mark, if any; POST sets or changes
	// it. Access mirrors the answer's own visibility (workspace.read_content).
	endpointQuestionFeedback
	// endpointQuestionFeedbackReport is the workspace OWNER/MANAGER
	// error-review report
	// (GET /api/v1/workspaces/{workspace_id}/questions:feedback-report): every
	// member's current feedback with the question, the answer and the
	// decrypted comment.
	endpointQuestionFeedbackReport
	// endpointKindSentinel is not a route. It is the upper bound the OpenAPI
	// drift gate iterates to (openapi_drift_test.go), so ADR-0086's ARC-007
	// "CI forbids drift" is enforced by construction: a new endpoint kind
	// added above this line has no OpenAPI entry and fails the gate until
	// api/openapi.yaml describes it. Keep it last.
	endpointKindSentinel
)

// workspaceToolEndpointKind maps a registered knowledge tool kind onto the
// endpointKind whose OpenAPI path describes its workspace REST parity route.
// It is the only place a registry kind meets the dispatcher enum: the route
// recognition resolves the tools/{segment} through the workspacetools registry
// and then asks this one function for the route identity, so a tool added to
// the registry without a REST route is refused as NOT_FOUND instead of being
// silently unrouted (and a route added without a registry entry cannot be
// recognised at all).
func workspaceToolEndpointKind(kind workspacetools.Kind) (endpointKind, bool) {
	switch kind {
	case workspacetools.KindListObjects:
		return endpointWorkspaceToolListObjects, true
	case workspacetools.KindSearch:
		return endpointWorkspaceToolSearch, true
	case workspacetools.KindGrep:
		return endpointWorkspaceToolGrep, true
	case workspacetools.KindRelated:
		return endpointWorkspaceToolRelated, true
	case workspacetools.KindRead:
		return endpointWorkspaceToolRead, true
	case workspacetools.KindSources:
		return endpointWorkspaceToolSources, true
	case workspacetools.KindRefresh:
		return endpointWorkspaceToolRefresh, true
	case workspacetools.KindWorkspaceContext:
		return endpointWorkspaceToolWorkspaceContext, true
	case workspacetools.KindSourceSchema:
		return endpointWorkspaceToolSourceSchema, true
	case workspacetools.KindSourceSQL:
		return endpointWorkspaceToolSourceSQL, true
	default:
		return 0, false
	}
}

type endpoint struct {
	kind               endpointKind
	workspaceID        string
	principalID        string
	sourceScopeID      string
	fragmentID         string
	questionRunID      string
	conversationID     string
	authorityID        string
	connectionID       string
	credentialID       string
	discoveryRequestID string
	discoveryViewID    string
	// metricDefinitionID and metricDefinitionVersion are the parsed exact
	// definition-version read target. version is a validated positive decimal
	// int64; an unparsable segment never reaches here as a route.
	metricDefinitionID      string
	metricDefinitionVersion int64
	// modelContextVersion is the parsed exact-version read/restore target for
	// GET/POST .../model-context/versions/{version}[:restore] (S2 card A): a
	// validated positive decimal int64, exactly like metricDefinitionVersion.
	// modelContextProposalID is the parsed {proposal_id} segment of
	// .../model-context/proposals/{proposal_id}:accept|:reject.
	modelContextVersion    int64
	modelContextProposalID string
	// journalBeforeSequence is the parsed, validated before_sequence cursor for
	// the audit-journal continuation route. It is nil for the legacy first
	// screen (no query) and never carries a client value the route did not
	// strictly validate.
	journalBeforeSequence *int64
	// conversationPaginated is true only when the conversations read route
	// carried a strictly validated limit/cursor query. conversationPageLimit
	// and conversationCursor are then the parsed values; the legacy no-query
	// path leaves all three zero and calls List unchanged.
	conversationPaginated bool
	conversationPageLimit int
	conversationCursor    string
	// listObjectsOffset, listObjectsLimit and listObjectsAllVersions are the
	// strictly parsed GET list-objects page window. An absent query leaves them
	// zero/false (the legacy first page); the handler applies the same default
	// and maximum bounds as the MCP tool.
	listObjectsOffset      int64
	listObjectsLimit       int64
	listObjectsAllVersions bool
	// searchQuery, searchOffset, searchLimit and searchAllVersions are the
	// strictly parsed tools/search parameters. searchQuery is required and
	// non-empty; the page window carries the same default and maximum bounds as
	// the MCP knowvault_search tool.
	searchQuery       string
	searchOffset      int64
	searchLimit       int64
	searchAllVersions bool
	// grepPattern, grepRef, grepAddress, grepOffset, grepLimit and grepAllVersions are the
	// strictly parsed tools/grep parameters. grepPattern is required and
	// non-empty; grepRef is the optional named code-source ref (empty = no ref
	// scoping); grepAddress is an optional complete canonical exact-object
	// selector; the page window carries the same default and maximum bounds as
	// the MCP knowvault_grep tool.
	grepPattern     string
	grepRef         string
	grepAddress     string
	grepOffset      int64
	grepLimit       int64
	grepAllVersions bool
	// relatedFragmentID, relatedAddress, relatedDirection, relatedOffset and
	// relatedLimit are the strictly parsed tools/related parameters. The
	// selector is fragment_id or the canonical kv1 address (at least one is
	// required); direction is the resolved closed vocabulary (default both);
	// cursor is resolved to relatedOffset through the stable v1: cursor form.
	relatedFragmentID string
	relatedAddress    string
	relatedDirection  string
	relatedOffset     int64
	relatedLimit      int64
	// readFragmentID, readAddress, readOffset, readLimit and
	// readExpectedSpanHash are the strictly parsed tools/read parameters. The
	// selector is fragment_id or the canonical kv1 address (at least one is
	// required); offset/limit are the UTF-8 byte page window and
	// expected_span_hash is the optional caller-supplied whole-fragment text
	// hash. readCursor is non-nil exactly when the request carried a canonical
	// v1:<offset> cursor, which switches the read to the whole-object page mode
	// exactly as the MCP knowvault_read cursor member does; an absent cursor
	// keeps the single-fragment read.
	readFragmentID       string
	readAddress          string
	readOffset           int64
	readLimit            int64
	readExpectedSpanHash string
	readCursor           *string
	// refreshSourceScopeID, refreshOffset and refreshLimit are the strictly
	// parsed tools/refresh parameters. An explicit source_scope_id narrows the
	// refresh to exactly one bound scope; offset/limit page the resolved source
	// list with the same default and maximum bounds as the MCP tool.
	refreshSourceScopeID string
	refreshOffset        int64
	refreshLimit         int64
	// workspaceToolKind is the registry-resolved kind of the tools/{segment}
	// REST parity route (R3a-1). Route recognition resolves the segment through
	// workspacetools.KnowledgeTools().LookupREST, so the dispatcher can route
	// the seven tool endpoint kinds through one registry-driven entry point
	// that switches on this kind rather than on the endpoint kind.
	workspaceToolKind workspacetools.Kind
}

// parseEndpoint resolves the route and validates its query parameters.
// Member candidates accept q; evidence reads accept an optional scope; the
// audit journal accepts an optional before_sequence cursor; GET conversations
// accepts an optional limit/cursor pair. Other routes reject query strings.
// Each handler validates parameter values.
func parseEndpoint(request *http.Request) (endpoint, string) {
	if request.URL == nil {
		return endpoint{}, "REQUEST_INVALID"
	}
	result, code := parseEndpointPath(request)
	if code != "" {
		return result, code
	}
	if result.kind == endpointMemberCandidates {
		// P10a is the second deliberate query-string exception (after the
		// evidence scope): it accepts exactly one "q" query parameter with
		// exactly one value. Any other shape — a duplicate q, a second key,
		// an empty value — is rejected here exactly as every other route's
		// query string is, so the value itself is the repository's own
		// content-free validation.
		if !validMemberCandidateQueryString(request.URL) {
			return endpoint{}, "REQUEST_INVALID"
		}
		return result, ""
	}
	if result.kind == endpointEvidenceGet {
		if !validRowsetScopeQuery(request.URL) {
			return endpoint{}, "REQUEST_INVALID"
		}
		return result, ""
	}
	if result.kind == endpointWorkspaceAuditEvents {
		before, ok := validAuditJournalQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.journalBeforeSequence = before
		return result, ""
	}
	if result.kind == endpointConversationList {
		limit, cursor, paginated, ok := validConversationListQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.conversationPaginated = paginated
		result.conversationPageLimit = limit
		result.conversationCursor = cursor
		return result, ""
	}
	if result.kind == endpointModelContextProposals {
		// The proposal review queue is the model-context route that carries a
		// query string (?status=&limit=&cursor=); modelContextProposalsList
		// re-parses it with the same closed validator. Without this branch the
		// generic "no query string" rule below rejected the web interface's
		// ?status=PROPOSED with REQUEST_INVALID, so the queue never loaded
		// (found by card U-1's screen walkthrough).
		if _, _, _, ok := validModelContextProposalsQuery(request.URL); !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		return result, ""
	}
	if result.kind == endpointWorkspaceToolListObjects {
		offset, limit, allVersions, ok := validListObjectsQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.listObjectsOffset = offset
		result.listObjectsLimit = limit
		result.listObjectsAllVersions = allVersions
		return result, ""
	}
	if result.kind == endpointWorkspaceToolSearch {
		search, ok := validWorkspaceToolSearchQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.searchQuery = search.query
		result.searchOffset = search.offset
		result.searchLimit = search.limit
		result.searchAllVersions = search.allVersions
		return result, ""
	}
	if result.kind == endpointWorkspaceToolGrep {
		grep, ok := validWorkspaceToolGrepQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.grepPattern = grep.pattern
		result.grepRef = grep.ref
		result.grepAddress = grep.address
		result.grepOffset = grep.offset
		result.grepLimit = grep.limit
		result.grepAllVersions = grep.allVersions
		return result, ""
	}
	if result.kind == endpointWorkspaceToolRelated {
		related, ok := validWorkspaceToolRelatedQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.relatedFragmentID = related.fragmentID
		result.relatedAddress = related.address
		result.relatedDirection = related.direction
		result.relatedOffset = related.offset
		result.relatedLimit = related.limit
		return result, ""
	}
	if result.kind == endpointWorkspaceToolRead {
		read, ok := validWorkspaceToolReadQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.readFragmentID = read.fragmentID
		result.readAddress = read.address
		result.readOffset = read.offset
		result.readLimit = read.limit
		result.readExpectedSpanHash = read.expectedSpanHash
		result.readCursor = read.cursor
		return result, ""
	}
	if result.kind == endpointWorkspaceToolRefresh {
		refresh, ok := validWorkspaceToolRefreshQuery(request.URL)
		if !ok {
			return endpoint{}, "REQUEST_INVALID"
		}
		result.refreshSourceScopeID = refresh.sourceScopeID
		result.refreshOffset = refresh.offset
		result.refreshLimit = refresh.limit
		return result, ""
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		return endpoint{}, "REQUEST_INVALID"
	}
	return result, ""
}

// validConversationListQuery strictly validates the GET conversations query
// string. Only this route accepts it: an absent query is the legacy List first
// screen, while a present query may carry at most one optional limit and one
// optional cursor. limit is a bare decimal integer in 1..50 (no sign, no
// leading plus, no whitespace, no overflow); cursor is exactly one non-empty
// opaque conversation ID. Unknown keys, duplicates, an empty value, a bare
// "?", a malformed escape and a stray semicolon are all rejected here. The
// string is parsed with url.ParseQuery -- deliberately not URL.Query(), which
// silently drops a malformed component -- so a syntactically broken query is
// refused instead of being read as if only the well-formed part existed.
func validConversationListQuery(requestURL *url.URL) (int, string, bool, bool) {
	if requestURL == nil {
		return 0, "", false, false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return 0, "", false, true
	}
	if requestURL.ForceQuery {
		return 0, "", false, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return 0, "", false, false
	}
	if len(values) == 0 || len(values) > 2 {
		return 0, "", false, false
	}
	limit := 0
	cursor := ""
	for key, rawValues := range values {
		if key != "limit" && key != "cursor" {
			return 0, "", false, false
		}
		if len(rawValues) != 1 {
			return 0, "", false, false
		}
		raw := rawValues[0]
		if raw == "" {
			return 0, "", false, false
		}
		if key == "limit" {
			if len(raw) > 2 {
				return 0, "", false, false
			}
			for index := 0; index < len(raw); index++ {
				if raw[index] < '0' || raw[index] > '9' {
					return 0, "", false, false
				}
			}
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > conversationPageLimitMax {
				return 0, "", false, false
			}
			limit = parsed
			continue
		}
		if !validOpaqueID(raw) {
			return 0, "", false, false
		}
		cursor = raw
	}
	return limit, cursor, true, true
}

// validAuditJournalQuery strictly validates the audit-journal query string.
// The route accepts at most one before_sequence parameter holding exactly one
// positive decimal int64 value; an absent query is the legacy first screen.
// Every other shape is rejected: a bare "?", a malformed escape or a stray
// semicolon (url.ParseQuery reports both), a duplicate key, an unknown key
// such as limit, an empty value, a sign, a non-decimal string, zero and an
// int64 overflow. The value is parsed once here so the handler never re-reads
// the raw query and never lets URL.Query() hide a malformed component.
func validAuditJournalQuery(requestURL *url.URL) (*int64, bool) {
	if requestURL == nil {
		return nil, false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return nil, true
	}
	if requestURL.ForceQuery {
		return nil, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return nil, false
	}
	if len(values) != 1 {
		return nil, false
	}
	rawValues, ok := values["before_sequence"]
	if !ok || len(rawValues) != 1 {
		return nil, false
	}
	raw := rawValues[0]
	if raw == "" || len(raw) > 19 {
		return nil, false
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return nil, false
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return nil, false
	}
	return &value, true
}

// validMemberCandidateQueryString strictly rejects a malformed or unexpected
// member-candidate query string. A member-candidate request must carry exactly
// one well-formed "q" parameter with exactly one value; absent, duplicate,
// unknown, empty or malformed query shapes are all refused. The string is
// parsed with url.ParseQuery -- deliberately not URL.Query(), which silently
// drops a malformed escape (and a stray semicolon) instead of reporting it --
// so a syntactically broken query is rejected as malformed rather than let
// through as if only the well-formed portion existed. The value's length stays
// the repository's own validation.
func validMemberCandidateQueryString(requestURL *url.URL) bool {
	if requestURL == nil {
		return false
	}
	if requestURL.ForceQuery {
		return false
	}
	if requestURL.RawQuery == "" {
		return false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return false
	}
	if len(values) != 1 {
		return false
	}
	queryValues, ok := values["q"]
	return ok && len(queryValues) == 1
}

// validRowsetScopeQuery accepts optional scope and exact canonical address
// parameters. Malformed encoding, bare question marks, duplicate parameters
// and unknown keys are rejected before the evidence reader runs.
// evidenceGet owns scope-value validation, including empty values.
func validRowsetScopeQuery(requestURL *url.URL) bool {
	if requestURL == nil {
		return false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return true
	}
	if requestURL.ForceQuery {
		return false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return false
	}
	if len(values) == 0 || len(values) > 2 {
		return false
	}
	for key, entries := range values {
		if (key != "scope" && key != "address") || len(entries) != 1 || (key == "address" && entries[0] == "") {
			return false
		}
	}
	return true
}

// validListObjectsQuery strictly validates the GET list-objects query string,
// the REST parity of the knowvault_list_objects MCP arguments. No query is the
// legacy first page. A present query may carry at most one each of offset,
// limit and all_versions. offset and limit are unsigned decimal int64 strings
// (no sign, no whitespace, no overflow) with limit 0 meaning the tool's default
// page; all_versions is exactly "true" or "false". Unknown keys, duplicates, an
// empty value, a bare "?", a malformed escape and a stray semicolon are all
// rejected here as REQUEST_INVALID before the inventory read is touched, using
// url.ParseQuery deliberately rather than URL.Query(), which silently drops a
// malformed component.
func validListObjectsQuery(requestURL *url.URL) (int64, int64, bool, bool) {
	if requestURL == nil {
		return 0, 0, false, false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return 0, 0, false, true
	}
	if requestURL.ForceQuery {
		return 0, 0, false, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 3 {
		return 0, 0, false, false
	}
	var offset, limit int64
	allVersions := false
	for key, rawValues := range values {
		if len(rawValues) != 1 {
			return 0, 0, false, false
		}
		raw := rawValues[0]
		if raw == "" {
			return 0, 0, false, false
		}
		switch key {
		case "offset":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return 0, 0, false, false
			}
			offset = parsed
		case "limit":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return 0, 0, false, false
			}
			limit = parsed
		case "all_versions":
			switch raw {
			case "true":
				allVersions = true
			case "false":
				allVersions = false
			default:
				return 0, 0, false, false
			}
		default:
			return 0, 0, false, false
		}
	}
	return offset, limit, allVersions, true
}

// workspaceToolRefreshQuery is the strictly parsed parameter set of the
// tools/refresh REST route.
type workspaceToolRefreshQuery struct {
	sourceScopeID string
	offset        int64
	limit         int64
}

// validWorkspaceToolRefreshQuery strictly validates the tools/refresh query
// string, the REST parity of the knowvault_refresh MCP arguments. No query is
// the whole-workspace first page. A present query may carry at most one each of
// source_scope_id, offset and limit. source_scope_id is a non-empty opaque id
// bounded by the MCP tool's 128-character maximum; offset and limit are
// unsigned decimal int64 strings (no sign, no whitespace, no overflow) with
// limit 0 meaning the tool's default page. Unknown keys, duplicates, an empty
// value, a bare "?", a malformed escape and a stray semicolon are all rejected
// here as REQUEST_INVALID before the source service is touched, using
// url.ParseQuery deliberately rather than URL.Query(), which silently drops a
// malformed component.
func validWorkspaceToolRefreshQuery(requestURL *url.URL) (workspaceToolRefreshQuery, bool) {
	if requestURL == nil {
		return workspaceToolRefreshQuery{}, false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return workspaceToolRefreshQuery{}, true
	}
	if requestURL.ForceQuery {
		return workspaceToolRefreshQuery{}, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 3 {
		return workspaceToolRefreshQuery{}, false
	}
	result := workspaceToolRefreshQuery{}
	for key, rawValues := range values {
		if len(rawValues) != 1 {
			return workspaceToolRefreshQuery{}, false
		}
		raw := rawValues[0]
		if raw == "" {
			return workspaceToolRefreshQuery{}, false
		}
		switch key {
		case "source_scope_id":
			if len(raw) > 128 {
				return workspaceToolRefreshQuery{}, false
			}
			result.sourceScopeID = raw
		case "offset":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolRefreshQuery{}, false
			}
			result.offset = parsed
		case "limit":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolRefreshQuery{}, false
			}
			result.limit = parsed
		default:
			return workspaceToolRefreshQuery{}, false
		}
	}
	return result, true
}

// workspaceToolSearchQuery is the strictly parsed parameter set of the
// tools/search REST route.
type workspaceToolSearchQuery struct {
	query       string
	offset      int64
	limit       int64
	allVersions bool
}

// validWorkspaceToolSearchQuery strictly validates the tools/search query
// string, the REST parity of the knowvault_search MCP arguments. The query is
// required and non-empty (a missing or whitespace-only query is refused before
// any fragment is read). It may also carry at most one each of offset, limit and
// all_versions. offset and limit are unsigned decimal int64 strings (no sign, no
// whitespace, no overflow) with limit 0 meaning the tool's default page;
// all_versions is exactly "true" or "false". Unknown keys, duplicates, an empty
// value, a bare "?", a malformed escape and a stray semicolon are all rejected
// here as REQUEST_INVALID before the search read is touched, using url.ParseQuery
// deliberately rather than URL.Query(), which silently drops a malformed
// component.
func validWorkspaceToolSearchQuery(requestURL *url.URL) (workspaceToolSearchQuery, bool) {
	if requestURL == nil || requestURL.ForceQuery {
		return workspaceToolSearchQuery{}, false
	}
	if requestURL.RawQuery == "" {
		return workspaceToolSearchQuery{}, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 4 {
		return workspaceToolSearchQuery{}, false
	}
	result := workspaceToolSearchQuery{}
	hasQuery := false
	for key, rawValues := range values {
		if len(rawValues) != 1 {
			return workspaceToolSearchQuery{}, false
		}
		raw := rawValues[0]
		if raw == "" {
			return workspaceToolSearchQuery{}, false
		}
		switch key {
		case "query":
			if strings.TrimSpace(raw) == "" || len(raw) > mcpSearchQueryMaxLength {
				return workspaceToolSearchQuery{}, false
			}
			result.query = raw
			hasQuery = true
		case "offset":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolSearchQuery{}, false
			}
			result.offset = parsed
		case "limit":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolSearchQuery{}, false
			}
			result.limit = parsed
		case "all_versions":
			switch raw {
			case "true":
				result.allVersions = true
			case "false":
				result.allVersions = false
			default:
				return workspaceToolSearchQuery{}, false
			}
		default:
			return workspaceToolSearchQuery{}, false
		}
	}
	if !hasQuery {
		return workspaceToolSearchQuery{}, false
	}
	return result, true
}

// workspaceToolGrepQuery is the strictly parsed parameter set of the
// tools/grep REST route.
type workspaceToolGrepQuery struct {
	pattern     string
	ref         string
	address     string
	offset      int64
	limit       int64
	allVersions bool
}

// validWorkspaceToolGrepQuery strictly validates the tools/grep query string,
// the REST parity of the knowvault_grep MCP arguments. The pattern is required
// and non-empty (a missing or whitespace-only pattern is refused before any
// object row is read) and bounded by the same 4096-character maximum as the MCP
// tool. It may also carry at most one each of ref, address, offset, limit and
// all_versions. ref is the optional named code-source ref and is bounded and
// shape-checked by the same mcpGrepRefValid rule the MCP tool applies, so the
// two transports accept exactly the same values. offset and limit are unsigned
// decimal int64 strings (no sign, no whitespace, no overflow) with limit 0
// meaning the tool's default page; all_versions is exactly "true" or "false".
// address is a complete canonical text address and is mutually exclusive with
// ref and all_versions because it already names one immutable version.
// Unknown keys, duplicates, an empty value, a bare "?", a malformed escape and a
// stray semicolon are all rejected here as REQUEST_INVALID before the grep read
// is touched, using url.ParseQuery deliberately rather than URL.Query(), which
// silently drops a malformed component.
func validWorkspaceToolGrepQuery(requestURL *url.URL) (workspaceToolGrepQuery, bool) {
	if requestURL == nil || requestURL.ForceQuery {
		return workspaceToolGrepQuery{}, false
	}
	if requestURL.RawQuery == "" {
		return workspaceToolGrepQuery{}, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 6 {
		return workspaceToolGrepQuery{}, false
	}
	result := workspaceToolGrepQuery{}
	hasPattern := false
	for key, rawValues := range values {
		if len(rawValues) != 1 {
			return workspaceToolGrepQuery{}, false
		}
		raw := rawValues[0]
		if raw == "" {
			return workspaceToolGrepQuery{}, false
		}
		switch key {
		case "pattern":
			if strings.TrimSpace(raw) == "" || len(raw) > mcpGrepPatternMaxLength {
				return workspaceToolGrepQuery{}, false
			}
			result.pattern = raw
			hasPattern = true
		case "ref":
			if !mcpGrepRefValid(raw) {
				return workspaceToolGrepQuery{}, false
			}
			result.ref = raw
		case "address":
			if _, selectorErr := mcpGrepAddressSelector(raw); selectorErr != nil {
				return workspaceToolGrepQuery{}, false
			}
			result.address = raw
		case "offset":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolGrepQuery{}, false
			}
			result.offset = parsed
		case "limit":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolGrepQuery{}, false
			}
			result.limit = parsed
		case "all_versions":
			switch raw {
			case "true":
				result.allVersions = true
			case "false":
				result.allVersions = false
			default:
				return workspaceToolGrepQuery{}, false
			}
		default:
			return workspaceToolGrepQuery{}, false
		}
	}
	if !hasPattern {
		return workspaceToolGrepQuery{}, false
	}
	if result.address != "" && (result.ref != "" || result.allVersions) {
		return workspaceToolGrepQuery{}, false
	}
	return result, true
}

// workspaceToolRelatedQuery is the strictly parsed parameter set of the
// tools/related REST route.
type workspaceToolRelatedQuery struct {
	fragmentID string
	address    string
	direction  string
	offset     int64
	limit      int64
}

// validWorkspaceToolRelatedQuery strictly validates the tools/related query
// string, the REST parity of the knowvault_related MCP arguments. The object is
// selected by fragment_id or by the canonical kv1 address (at least one is
// required); it may also carry at most one each of direction, cursor and limit.
// direction is exactly referencing, references or both (an absent direction is
// resolved to both); cursor must be the stable v1:<offset> form this server
// produced; limit is an unsigned decimal int64 with 0 meaning the tool's
// default page. Unknown keys, duplicates, an empty value, a bare "?", a
// malformed escape and a stray semicolon are all rejected here as
// REQUEST_INVALID before the relation source is touched, using url.ParseQuery
// deliberately rather than URL.Query(), which silently drops a malformed
// component. The address/object consistency check happens in the handler,
// before the capability is touched, exactly as the MCP tool refuses it.
func validWorkspaceToolRelatedQuery(requestURL *url.URL) (workspaceToolRelatedQuery, bool) {
	if requestURL == nil || requestURL.ForceQuery {
		return workspaceToolRelatedQuery{}, false
	}
	if requestURL.RawQuery == "" {
		return workspaceToolRelatedQuery{}, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 5 {
		return workspaceToolRelatedQuery{}, false
	}
	result := workspaceToolRelatedQuery{}
	hasSelector := false
	for key, rawValues := range values {
		if len(rawValues) != 1 {
			return workspaceToolRelatedQuery{}, false
		}
		raw := rawValues[0]
		if raw == "" {
			return workspaceToolRelatedQuery{}, false
		}
		switch key {
		case "fragment_id":
			if len(raw) > 128 {
				return workspaceToolRelatedQuery{}, false
			}
			result.fragmentID = raw
			hasSelector = true
		case "address":
			result.address = raw
			hasSelector = true
		case "direction":
			resolved, ok := mcpRelatedDirection(raw)
			if !ok {
				return workspaceToolRelatedQuery{}, false
			}
			result.direction = resolved
		case "cursor":
			offset, ok := mcpRelatedCursorOffset(raw)
			if !ok {
				return workspaceToolRelatedQuery{}, false
			}
			result.offset = offset
		case "limit":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolRelatedQuery{}, false
			}
			result.limit = parsed
		default:
			return workspaceToolRelatedQuery{}, false
		}
	}
	if !hasSelector {
		return workspaceToolRelatedQuery{}, false
	}
	if result.direction == "" {
		result.direction = mcpRelatedDirectionBoth
	}
	return result, true
}

// workspaceToolReadQuery is the strictly parsed parameter set of the
// tools/read REST route.
type workspaceToolReadQuery struct {
	fragmentID       string
	address          string
	offset           int64
	limit            int64
	expectedSpanHash string
	cursor           *string
}

// validWorkspaceToolReadQuery strictly validates the tools/read query string,
// the REST parity of the knowvault_read MCP arguments. The object is selected
// by fragment_id or by the canonical kv1 address (at least one is required); it
// may also carry at most one each of offset, limit, expected_span_hash and
// cursor. offset and limit are unsigned decimal int64 (0 means the MCP default
// page); expected_span_hash must be non-empty; cursor is the canonical
// v1:<offset> whole-object page form this server produces and switches the read
// to whole-object page mode, so it is mutually exclusive with a non-zero
// offset. Unknown keys, duplicates, an empty value, a bare "?", a malformed
// escape and a stray semicolon are all rejected here as REQUEST_INVALID before
// the viewer is touched, using url.ParseQuery deliberately rather than
// URL.Query(), which silently drops a malformed component. The
// address/object consistency and address.Parse checks happen in the handler,
// before the capability is touched, exactly as the MCP tool refuses them.
func validWorkspaceToolReadQuery(requestURL *url.URL) (workspaceToolReadQuery, bool) {
	if requestURL == nil || requestURL.ForceQuery {
		return workspaceToolReadQuery{}, false
	}
	if requestURL.RawQuery == "" {
		return workspaceToolReadQuery{}, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 6 {
		return workspaceToolReadQuery{}, false
	}
	result := workspaceToolReadQuery{}
	hasSelector := false
	for key, rawValues := range values {
		if len(rawValues) != 1 {
			return workspaceToolReadQuery{}, false
		}
		raw := rawValues[0]
		if raw == "" {
			return workspaceToolReadQuery{}, false
		}
		switch key {
		case "fragment_id":
			if len(raw) > 128 {
				return workspaceToolReadQuery{}, false
			}
			result.fragmentID = raw
			hasSelector = true
		case "address":
			result.address = raw
			hasSelector = true
		case "offset":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolReadQuery{}, false
			}
			result.offset = parsed
		case "limit":
			parsed, ok := parseUnsignedInt64(raw)
			if !ok {
				return workspaceToolReadQuery{}, false
			}
			result.limit = parsed
		case "expected_span_hash":
			result.expectedSpanHash = raw
		case "cursor":
			if !validWorkspaceToolReadCursor(raw) {
				return workspaceToolReadQuery{}, false
			}
			cursor := raw
			result.cursor = &cursor
		default:
			return workspaceToolReadQuery{}, false
		}
	}
	if !hasSelector {
		return workspaceToolReadQuery{}, false
	}
	if result.cursor != nil && result.offset != 0 {
		return workspaceToolReadQuery{}, false
	}
	return result, true
}

// validWorkspaceToolReadCursor accepts exactly the canonical whole-object page
// cursor form address.Read consumes and produces: "v1:" followed by one to
// nineteen decimal digits (offset 0 included, so the first whole-object page is
// requested as cursor=v1:0). Anything else -- a bare "v1:", a sign, whitespace,
// a non-decimal or an overflowing offset -- is refused before any read.
func validWorkspaceToolReadCursor(raw string) bool {
	const cursorPrefix = "v1:"
	if len(raw) <= len(cursorPrefix) || raw[:len(cursorPrefix)] != cursorPrefix {
		return false
	}
	_, ok := parseUnsignedInt64(raw[len(cursorPrefix):])
	return ok
}

// parseUnsignedInt64 parses a canonical unsigned decimal int64: at least one
// digit, no sign, no whitespace and no overflow.
func parseUnsignedInt64(raw string) (int64, bool) {
	if raw == "" || len(raw) > 19 {
		return 0, false
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

func parseEndpointPath(request *http.Request) (endpoint, string) {
	path := request.URL.EscapedPath()
	if !strings.HasPrefix(path, apiPrefix+"/") {
		return endpoint{}, "NOT_FOUND"
	}
	if strings.ContainsAny(path, "%\\") {
		return endpoint{}, "NOT_FOUND"
	}
	if path == csrfPath {
		return endpoint{kind: endpointCSRF}, ""
	}
	if path == apiPrefix+"/mcp" {
		return endpoint{kind: endpointMCP}, ""
	}
	if path == sourceConnectorsPath {
		return endpoint{kind: endpointSourceConnectors}, ""
	}
	if path == sourcesPath {
		return endpoint{kind: endpointSourceRegister}, ""
	}
	if path == sourcesPath+"/connections" {
		return endpoint{kind: endpointSourceConnectionBootstrap}, ""
	}
	const sourcePrefix = sourcesPath + "/"
	if strings.HasPrefix(path, sourcePrefix) {
		remainder := strings.TrimPrefix(path, sourcePrefix)
		const discoveryPrefix = "discovery/"
		if strings.HasPrefix(remainder, discoveryPrefix) {
			discoveryPath := strings.TrimPrefix(remainder, discoveryPrefix)
			const viewMarker = "/views/"
			const registerSuffix = ":register"
			// Card S3.4b: one server request registers a whole batch of
			// discovered tables (.../discovery/{request_id}:register-batch).
			// It is checked before the plain discovery-read fallback because a
			// batch id is itself a valid opaque id, so an unordered match would
			// silently route it to the read.
			const registerBatchSuffix = ":register-batch"
			if !strings.Contains(discoveryPath, "/") && strings.HasSuffix(discoveryPath, registerBatchSuffix) {
				requestID := strings.TrimSuffix(discoveryPath, registerBatchSuffix)
				if validOpaqueID(requestID) {
					return endpoint{kind: endpointSourceDiscoveryRegisterBatch, discoveryRequestID: requestID}, ""
				}
				return endpoint{}, "NOT_FOUND"
			}
			if strings.Contains(discoveryPath, viewMarker) && strings.HasSuffix(discoveryPath, registerSuffix) {
				parts := strings.SplitN(discoveryPath, viewMarker, 2)
				viewID := strings.TrimSuffix(parts[1], registerSuffix)
				if validOpaqueID(parts[0]) && validOpaqueID(viewID) && !strings.Contains(viewID, "/") {
					return endpoint{kind: endpointSourceDiscoveryRegister,
						discoveryRequestID: parts[0], discoveryViewID: viewID}, ""
				}
				return endpoint{}, "NOT_FOUND"
			}
			requestID := discoveryPath
			if !strings.Contains(requestID, "/") && validOpaqueID(requestID) {
				return endpoint{kind: endpointSourceDiscoveryGet, discoveryRequestID: requestID}, ""
			}
			return endpoint{}, "NOT_FOUND"
		}
		if strings.HasSuffix(remainder, ":activate") && !strings.Contains(remainder, "/") {
			sourceScopeID := strings.TrimSuffix(remainder, ":activate")
			if validOpaqueID(sourceScopeID) {
				return endpoint{kind: endpointSourceActivate, sourceScopeID: sourceScopeID}, ""
			}
		}
		if strings.HasSuffix(remainder, ":sync") && !strings.Contains(remainder, "/") {
			sourceScopeID := strings.TrimSuffix(remainder, ":sync")
			if validOpaqueID(sourceScopeID) {
				return endpoint{kind: endpointSourceSync, sourceScopeID: sourceScopeID}, ""
			}
		}
		// UPL-1: POST /api/v1/sources/{source_scope_id}/documents. A browser
		// upload targets the scope exactly like :activate/:sync, so it stays a
		// sub-path of sourcesPath rather than moving under one workspace.
		const documentsSuffix = "/documents"
		if strings.HasSuffix(remainder, documentsSuffix) {
			sourceScopeID := strings.TrimSuffix(remainder, documentsSuffix)
			if validOpaqueID(sourceScopeID) {
				return endpoint{kind: endpointSourceUploadDocuments, sourceScopeID: sourceScopeID}, ""
			}
			return endpoint{}, "NOT_FOUND"
		}
		// ADR-0087 §2: POST /api/v1/sources/connections/{connectionID}:verify-trust.
		// A connection is registration's own lineage, distinct from the
		// activate/sync scope routes above, so it gets its own sub-path rather
		// than a bare suffix on sourcesPath.
		const connectionsPrefix = "connections/"
		if strings.HasPrefix(remainder, connectionsPrefix) {
			sub := strings.TrimPrefix(remainder, connectionsPrefix)
			if strings.HasSuffix(sub, ":discover") && !strings.Contains(sub, "/") {
				connectionID := strings.TrimSuffix(sub, ":discover")
				if validOpaqueID(connectionID) {
					return endpoint{kind: endpointSourceDiscoveryRequest, connectionID: connectionID}, ""
				}
			}
			if strings.HasSuffix(sub, ":verify-trust") && !strings.Contains(sub, "/") {
				connectionID := strings.TrimSuffix(sub, ":verify-trust")
				if validOpaqueID(connectionID) {
					return endpoint{kind: endpointSourceConnectionVerifyTrust, connectionID: connectionID}, ""
				}
			}
			return endpoint{}, "NOT_FOUND"
		}
		return endpoint{}, "NOT_FOUND"
	}
	if path == workspacesPath {
		if request.Method == http.MethodGet {
			return endpoint{kind: endpointWorkspaceList}, ""
		}
		return endpoint{kind: endpointWorkspaceCreate}, ""
	}
	const workspacePrefix = workspacesPath + "/"
	if !strings.HasPrefix(path, workspacePrefix) || strings.HasSuffix(path, "/") {
		return endpoint{}, "NOT_FOUND"
	}
	remainder := strings.TrimPrefix(path, workspacePrefix)
	if strings.HasSuffix(remainder, ":archive") && !strings.Contains(remainder, "/") {
		workspaceID := strings.TrimSuffix(remainder, ":archive")
		if validOpaqueID(workspaceID) {
			return endpoint{kind: endpointWorkspaceArchive, workspaceID: workspaceID}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	if strings.HasSuffix(remainder, ":transfer-ownership") && !strings.Contains(remainder, "/") {
		workspaceID := strings.TrimSuffix(remainder, ":transfer-ownership")
		if validOpaqueID(workspaceID) {
			return endpoint{kind: endpointOwnershipTransfer, workspaceID: workspaceID}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	parts := strings.Split(remainder, "/")
	if len(parts) == 1 && validOpaqueID(parts[0]) {
		if request.Method == http.MethodGet {
			return endpoint{kind: endpointWorkspaceGet, workspaceID: parts[0]}, ""
		}
		return endpoint{kind: endpointWorkspaceUpdate, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "sources" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointWorkspaceSources, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "source-drafts" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointWorkspaceSourceDrafts, workspaceID: parts[0]}, ""
	}
	// S3 card 2b: the organization-OWNER control over one source connection's
	// SQL query credential (ADR-0097). The connection id is the same
	// workspace source id the Sources card shows.
	if len(parts) == 3 && parts[1] == "source-connections" && validOpaqueID(parts[0]) {
		if strings.HasSuffix(parts[2], ":set-query-credential") {
			connectionID := strings.TrimSuffix(parts[2], ":set-query-credential")
			if validOpaqueID(connectionID) {
				return endpoint{kind: endpointSourceQueryCredentialSet, workspaceID: parts[0], connectionID: connectionID}, ""
			}
		}
		if strings.HasSuffix(parts[2], ":clear-query-credential") {
			connectionID := strings.TrimSuffix(parts[2], ":clear-query-credential")
			if validOpaqueID(connectionID) {
				return endpoint{kind: endpointSourceQueryCredentialClear, workspaceID: parts[0], connectionID: connectionID}, ""
			}
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 3 && parts[1] == "source-drafts" && validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		if request.Method == http.MethodDelete {
			return endpoint{kind: endpointWorkspaceSourceDraftDiscard, workspaceID: parts[0], connectionID: parts[2]}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 3 && parts[1] == "sources" && validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		if request.Method == http.MethodDelete {
			return endpoint{kind: endpointWorkspaceSourceRemove, workspaceID: parts[0], sourceScopeID: parts[2]}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 2 && parts[1] == "search-profile" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointSearchProfile, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "search-profile:revise" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointSearchProfileRevise, workspaceID: parts[0]}, ""
	}
	// R2 Outcome 1: the additive, read-only MetricDefinition version surface.
	// The list names the workspace's version catalog; the exact-version read
	// additionally names the definition id and a canonical positive version.
	// Both delegate the workspace access re-check to the injected catalog.
	if len(parts) == 2 && parts[1] == "metric-definitions" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointMetricDefinitions, workspaceID: parts[0]}, ""
	}
	// R2 Outcome 1 additive writes, deliberately on their own colon paths so
	// the GET routes above keep their read-only contract (POST stays 405 with
	// Allow: GET). A definition id may contain ':', so the approve suffix is
	// stripped before the id is validated.
	if len(parts) == 2 && parts[1] == "metric-definitions:draft" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointMetricDefinitionDraft, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "metric-definitions" && validOpaqueID(parts[0]) &&
		strings.HasSuffix(parts[2], ":approve") && len(parts[2]) > len(":approve") {
		metricID := strings.TrimSuffix(parts[2], ":approve")
		if validOpaqueID(metricID) {
			return endpoint{kind: endpointMetricDefinitionApprove, workspaceID: parts[0], metricDefinitionID: metricID}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 5 && parts[1] == "metric-definitions" && parts[3] == "versions" &&
		validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		version, ok := parseMetricDefinitionVersion(parts[4])
		if !ok {
			return endpoint{}, "NOT_FOUND"
		}
		return endpoint{kind: endpointMetricDefinitionGet, workspaceID: parts[0],
			metricDefinitionID: parts[2], metricDefinitionVersion: version}, ""
	}
	// S2 card A (ADR-0098): the workspace model context document, its version
	// history and its deterministic-proposal review queue. GET/PUT share one
	// path exactly like the bare workspace route above; every other action is
	// its own colon path so the GET routes keep 405-on-POST.
	if len(parts) == 2 && parts[1] == "model-context" && validOpaqueID(parts[0]) {
		if request.Method == http.MethodGet {
			return endpoint{kind: endpointModelContextGet, workspaceID: parts[0]}, ""
		}
		return endpoint{kind: endpointModelContextSave, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "model-context" && parts[2] == "versions" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointModelContextVersions, workspaceID: parts[0]}, ""
	}
	if len(parts) == 4 && parts[1] == "model-context" && parts[2] == "versions" && validOpaqueID(parts[0]) {
		if strings.HasSuffix(parts[3], ":restore") && len(parts[3]) > len(":restore") {
			version, ok := modelContextVersionSegment(strings.TrimSuffix(parts[3], ":restore"))
			if !ok {
				return endpoint{}, "NOT_FOUND"
			}
			return endpoint{kind: endpointModelContextRestore, workspaceID: parts[0], modelContextVersion: version}, ""
		}
		version, ok := modelContextVersionSegment(parts[3])
		if !ok {
			return endpoint{}, "NOT_FOUND"
		}
		return endpoint{kind: endpointModelContextVersionGet, workspaceID: parts[0], modelContextVersion: version}, ""
	}
	if len(parts) == 3 && parts[1] == "model-context" && parts[2] == "proposals" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointModelContextProposals, workspaceID: parts[0]}, ""
	}
	if len(parts) == 4 && parts[1] == "model-context" && parts[2] == "proposals" && validOpaqueID(parts[0]) {
		if strings.HasSuffix(parts[3], ":accept") && len(parts[3]) > len(":accept") {
			proposalID := strings.TrimSuffix(parts[3], ":accept")
			if validOpaqueID(proposalID) {
				return endpoint{kind: endpointModelContextProposalAccept, workspaceID: parts[0], modelContextProposalID: proposalID}, ""
			}
			return endpoint{}, "NOT_FOUND"
		}
		if strings.HasSuffix(parts[3], ":reject") && len(parts[3]) > len(":reject") {
			proposalID := strings.TrimSuffix(parts[3], ":reject")
			if validOpaqueID(proposalID) {
				return endpoint{kind: endpointModelContextProposalReject, workspaceID: parts[0], modelContextProposalID: proposalID}, ""
			}
			return endpoint{}, "NOT_FOUND"
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 2 && parts[1] == "access-codes" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointAccessCodes, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "access-codes" && validOpaqueID(parts[0]) &&
		strings.HasSuffix(parts[2], ":revoke") && len(parts[2]) > len(":revoke") {
		credentialID := strings.TrimSuffix(parts[2], ":revoke")
		if validOpaqueID(credentialID) {
			return endpoint{kind: endpointAccessCodeRevoke, workspaceID: parts[0], credentialID: credentialID}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 2 && parts[1] == "members" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointMemberAdd, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "members" && validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		if request.Method == http.MethodDelete {
			return endpoint{kind: endpointMemberRemove, workspaceID: parts[0], principalID: parts[2]}, ""
		}
		return endpoint{kind: endpointMemberChange, workspaceID: parts[0], principalID: parts[2]}, ""
	}
	if len(parts) == 3 && parts[1] == "evidence" && validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		return endpoint{kind: endpointEvidenceGet, workspaceID: parts[0], fragmentID: parts[2]}, ""
	}
	// R3a-1: the workspace-scoped REST parity surface of the workspace
	// knowledge tools. Every tools/{segment} subpath is resolved through the
	// one workspacetools registry, and the resolved kind (not the segment) is
	// what the dispatcher routes on, so the REST and MCP surfaces cannot drift
	// on which tool a name or a subpath resolves to. An unregistered segment is
	// the existing content-free NOT_FOUND.
	if len(parts) == 3 && parts[1] == "tools" && validOpaqueID(parts[0]) {
		tool, ok := workspacetools.KnowledgeTools().LookupREST(parts[2])
		if !ok {
			return endpoint{}, "NOT_FOUND"
		}
		kind, ok := workspaceToolEndpointKind(tool.Kind)
		if !ok {
			return endpoint{}, "NOT_FOUND"
		}
		return endpoint{kind: kind, workspaceID: parts[0], workspaceToolKind: tool.Kind}, ""
	}
	if len(parts) == 2 && parts[1] == "member-candidates" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointMemberCandidates, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "audit-events" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointWorkspaceAuditEvents, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "questions" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointQuestionCreate, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "questions:feedback-report" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointQuestionFeedbackReport, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "questions" && validOpaqueID(parts[0]) && strings.HasSuffix(parts[2], ":feedback") {
		runID := strings.TrimSuffix(parts[2], ":feedback")
		if validOpaqueID(runID) {
			return endpoint{kind: endpointQuestionFeedback, workspaceID: parts[0], questionRunID: runID}, ""
		}
		return endpoint{}, "NOT_FOUND"
	}
	if len(parts) == 3 && parts[1] == "questions" && validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		return endpoint{kind: endpointQuestionGet, workspaceID: parts[0], questionRunID: parts[2]}, ""
	}
	if len(parts) == 2 && parts[1] == "conversations" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointConversationList, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "conversations" && validOpaqueID(parts[0]) {
		if strings.HasSuffix(parts[2], ":archive") {
			conversationID := strings.TrimSuffix(parts[2], ":archive")
			if validOpaqueID(conversationID) {
				return endpoint{kind: endpointConversationArchive, workspaceID: parts[0], conversationID: conversationID}, ""
			}
			return endpoint{}, "NOT_FOUND"
		}
		if validOpaqueID(parts[2]) {
			return endpoint{kind: endpointConversationGet, workspaceID: parts[0], conversationID: parts[2]}, ""
		}
	}
	// ADR-0087 §1 confirmation-authority REST actions (ADR-0053 commands
	// composed in this package): grant issue, managed-source confirmation, and
	// their revocations. Each is a typed POST on a workspace; the closed command
	// body carries the operation-specific canonical fields and the repository
	// owns policy, the canonical envelope and the audit event.
	if len(parts) == 2 && parts[1] == "confirmation-grants" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointConfirmGrantIssue, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "confirmation-grants" && validOpaqueID(parts[0]) &&
		strings.HasSuffix(parts[2], ":revoke") && len(parts[2]) > len(":revoke") {
		grantID := strings.TrimSuffix(parts[2], ":revoke")
		if validOpaqueID(grantID) {
			return endpoint{kind: endpointConfirmGrantRevoke, workspaceID: parts[0], authorityID: grantID}, ""
		}
	}
	if len(parts) == 2 && parts[1] == "managed-source-confirmations:batch" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointManagedSourceConfirmBatch, workspaceID: parts[0]}, ""
	}
	if len(parts) == 2 && parts[1] == "managed-source-confirmations" && validOpaqueID(parts[0]) {
		return endpoint{kind: endpointManagedSourceConfirm, workspaceID: parts[0]}, ""
	}
	if len(parts) == 3 && parts[1] == "managed-source-confirmations" && validOpaqueID(parts[0]) &&
		strings.HasSuffix(parts[2], ":revoke") && len(parts[2]) > len(":revoke") {
		confirmationID := strings.TrimSuffix(parts[2], ":revoke")
		if validOpaqueID(confirmationID) {
			return endpoint{kind: endpointManagedConfirmationRevoke, workspaceID: parts[0], authorityID: confirmationID}, ""
		}
	}
	// ADR-0089: governed model-authored SQL over an operator-exposed schema.
	// The connection id is the fixed, mounted ADR-0089 connection; this
	// surface never accepts SQL, a DSN or a credential as input, only the
	// operator's exposed-schema annotations, the live-queries flag, a natural
	// -language question and, for promotion, a server-owned attempt id plus its
	// reviewed SQL hash. SQL text is never accepted by this transport.
	if len(parts) == 3 && parts[1] == "governed-query-connections" && validOpaqueID(parts[0]) {
		if strings.HasSuffix(parts[2], ":set-live-queries") {
			connectionID := strings.TrimSuffix(parts[2], ":set-live-queries")
			if validOpaqueID(connectionID) {
				return endpoint{kind: endpointGovernedQuerySetLiveQueries, workspaceID: parts[0], connectionID: connectionID}, ""
			}
		}
		if strings.HasSuffix(parts[2], ":ask") {
			connectionID := strings.TrimSuffix(parts[2], ":ask")
			if validOpaqueID(connectionID) {
				return endpoint{kind: endpointGovernedQueryAsk, workspaceID: parts[0], connectionID: connectionID}, ""
			}
		}
		if strings.HasSuffix(parts[2], ":promote") {
			connectionID := strings.TrimSuffix(parts[2], ":promote")
			if validOpaqueID(connectionID) {
				return endpoint{kind: endpointGovernedQueryPromote, workspaceID: parts[0], connectionID: connectionID}, ""
			}
		}
	}
	if len(parts) == 4 && parts[1] == "governed-query-connections" && parts[3] == "exposed-schema" &&
		validOpaqueID(parts[0]) && validOpaqueID(parts[2]) {
		return endpoint{kind: endpointGovernedQueryExposedSchema, workspaceID: parts[0], connectionID: parts[2]}, ""
	}
	return endpoint{}, "NOT_FOUND"
}

func methodAllowed(endpoint endpoint, method string) bool {
	switch endpoint.kind {
	case endpointCSRF, endpointWorkspaceList, endpointWorkspaceGet, endpointEvidenceGet, endpointWorkspaceAuditEvents, endpointQuestionGet, endpointConversationList, endpointConversationGet, endpointSearchProfile, endpointSourceConnectors, endpointMemberCandidates, endpointSourceDiscoveryGet, endpointMetricDefinitions, endpointMetricDefinitionGet,
		endpointModelContextGet, endpointModelContextVersions, endpointModelContextVersionGet, endpointModelContextProposals, endpointWorkspaceSourceDrafts, endpointQuestionFeedbackReport:
		return method == http.MethodGet
	case endpointWorkspaceSources, endpointAccessCodes, endpointWorkspaceToolListObjects, endpointWorkspaceToolSearch, endpointWorkspaceToolGrep, endpointWorkspaceToolRelated, endpointWorkspaceToolRead, endpointWorkspaceToolSources, endpointWorkspaceToolRefresh, endpointQuestionFeedback:
		return method == http.MethodGet || method == http.MethodPost
	case endpointWorkspaceToolWorkspaceContext, endpointWorkspaceToolSourceSchema, endpointWorkspaceToolSourceSQL:
		// ADR-0098's tool-parity route is POST-only (S2-CONTRACT.md "Tool
		// parity"): its optional filter travels in a JSON body, unlike the
		// other six GET/POST workspace tool-parity routes. ADR-0097's
		// source-schema and source-sql routes follow the same shape.
		return method == http.MethodPost
	case endpointWorkspaceSourceRemove:
		return method == http.MethodDelete
	case endpointWorkspaceSourceDraftDiscard:
		return method == http.MethodDelete
	case endpointMCP:
		return method == http.MethodPost
	case endpointWorkspaceCreate, endpointWorkspaceArchive, endpointMemberAdd, endpointOwnershipTransfer, endpointSourceRegister, endpointSourceConnectionBootstrap, endpointSourceDiscoveryRequest, endpointSourceDiscoveryRegister, endpointSourceDiscoveryRegisterBatch, endpointSourceActivate, endpointSourceSync, endpointQuestionCreate, endpointConversationArchive,
		endpointConfirmGrantIssue, endpointConfirmGrantRevoke, endpointManagedSourceConfirm, endpointManagedSourceConfirmBatch, endpointManagedConfirmationRevoke, endpointSourceConnectionVerifyTrust, endpointAccessCodeRevoke,
		endpointGovernedQuerySetLiveQueries, endpointGovernedQueryExposedSchema, endpointGovernedQueryAsk, endpointGovernedQueryPromote, endpointSearchProfileRevise, endpointSourceUploadDocuments,
		endpointSourceQueryCredentialSet, endpointSourceQueryCredentialClear,
		endpointMetricDefinitionDraft, endpointMetricDefinitionApprove,
		endpointModelContextRestore, endpointModelContextProposalAccept, endpointModelContextProposalReject:
		return method == http.MethodPost
	case endpointWorkspaceUpdate, endpointMemberChange, endpointModelContextSave:
		return method == http.MethodPut
	case endpointMemberRemove:
		return method == http.MethodDelete
	default:
		return false
	}
}

func allowedMethods(endpoint endpoint) string {
	switch endpoint.kind {
	case endpointCSRF, endpointWorkspaceList, endpointWorkspaceGet, endpointEvidenceGet, endpointWorkspaceAuditEvents, endpointQuestionGet, endpointConversationList, endpointConversationGet, endpointSearchProfile, endpointSourceConnectors, endpointMemberCandidates, endpointSourceDiscoveryGet, endpointMetricDefinitions, endpointMetricDefinitionGet,
		endpointModelContextGet, endpointModelContextVersions, endpointModelContextVersionGet, endpointModelContextProposals, endpointQuestionFeedbackReport:
		return http.MethodGet
	case endpointWorkspaceSources, endpointAccessCodes, endpointWorkspaceToolListObjects, endpointWorkspaceToolSearch, endpointWorkspaceToolGrep, endpointWorkspaceToolRelated, endpointWorkspaceToolRead, endpointWorkspaceToolSources, endpointWorkspaceToolRefresh, endpointQuestionFeedback:
		return http.MethodGet + ", " + http.MethodPost
	case endpointWorkspaceToolWorkspaceContext, endpointWorkspaceToolSourceSchema, endpointWorkspaceToolSourceSQL:
		return http.MethodPost
	case endpointWorkspaceSourceDrafts:
		return http.MethodGet
	case endpointWorkspaceSourceDraftDiscard:
		return http.MethodDelete
	case endpointWorkspaceSourceRemove:
		return http.MethodDelete
	case endpointMCP:
		return http.MethodPost
	case endpointWorkspaceCreate, endpointWorkspaceArchive, endpointMemberAdd, endpointOwnershipTransfer, endpointSourceRegister, endpointSourceConnectionBootstrap, endpointSourceDiscoveryRequest, endpointSourceDiscoveryRegister, endpointSourceDiscoveryRegisterBatch, endpointSourceActivate, endpointSourceSync, endpointQuestionCreate, endpointConversationArchive,
		endpointConfirmGrantIssue, endpointConfirmGrantRevoke, endpointManagedSourceConfirm, endpointManagedSourceConfirmBatch, endpointManagedConfirmationRevoke, endpointSourceConnectionVerifyTrust, endpointAccessCodeRevoke,
		endpointGovernedQuerySetLiveQueries, endpointGovernedQueryExposedSchema, endpointGovernedQueryAsk, endpointGovernedQueryPromote, endpointSearchProfileRevise, endpointSourceUploadDocuments,
		endpointSourceQueryCredentialSet, endpointSourceQueryCredentialClear,
		endpointMetricDefinitionDraft, endpointMetricDefinitionApprove,
		endpointModelContextRestore, endpointModelContextProposalAccept, endpointModelContextProposalReject:
		return http.MethodPost
	case endpointWorkspaceUpdate, endpointMemberChange, endpointModelContextSave:
		return http.MethodPut
	case endpointMemberRemove:
		return http.MethodDelete
	default:
		return ""
	}
}

func unsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (handler *Handler) list(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string) {
	summaries, err := handler.service.List(request.Context(), access)
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	items := make([]summaryResponse, len(summaries))
	for index, summary := range summaries {
		items[index] = summaryResponse{
			ID: summary.ID, Name: summary.Name, Status: summary.Status, Revision: summary.Revision, Role: summary.Role,
		}
		if summary.Degraded {
			degraded := true
			reason := summary.DegradedReason
			items[index].Degraded = &degraded
			items[index].DegradedReason = &reason
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"workspaces": items})
}

func (handler *Handler) get(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	snapshot, err := handler.service.Get(request.Context(), access, workspaceID)
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) create(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string) {
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body metadataBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	snapshot, err := handler.service.Create(request.Context(), access, workspacerepository.CreateRequest{IdempotencyKey: key, Name: *body.Name, Description: *body.Description, RetentionPolicyID: *body.RetentionPolicyID})
	if err != nil {
		handleServiceError(writer, err, requestID, true)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) update(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body metadataBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	snapshot, err := handler.service.Update(request.Context(), access, workspacerepository.UpdateRequest{IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: expectedHash, Name: *body.Name, Description: *body.Description, RetentionPolicyID: *body.RetentionPolicyID})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) archive(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	snapshot, err := handler.service.Archive(request.Context(), access, workspacerepository.ArchiveRequest{IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: expectedHash})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) addMember(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body addMemberBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.PrincipalID == nil || body.Role == nil {
		var fields []string
		if body.PrincipalID == nil {
			fields = append(fields, "principal_id")
		}
		if body.Role == nil {
			fields = append(fields, "role")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", fields)
		return
	}
	snapshot, err := handler.service.AddMember(request.Context(), access, workspacerepository.AddMemberRequest{IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: expectedHash, PrincipalID: *body.PrincipalID, Role: *body.Role})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) changeMemberRole(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, principalID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body memberRoleBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.Role == nil {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"role"})
		return
	}
	snapshot, err := handler.service.ChangeMemberRole(request.Context(), access, workspacerepository.ChangeMemberRoleRequest{IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: expectedHash, PrincipalID: principalID, Role: *body.Role})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) removeMember(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, principalID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	snapshot, err := handler.service.RemoveMember(request.Context(), access, workspacerepository.RemoveMemberRequest{IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: expectedHash, PrincipalID: principalID})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

func (handler *Handler) transferOwnership(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body transferOwnershipBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.NewOwnerPrincipalID == nil {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"new_owner_principal_id"})
		return
	}
	snapshot, err := handler.service.TransferOwnership(request.Context(), access, workspacerepository.TransferOwnershipRequest{IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: expectedHash, NewOwnerPrincipalID: *body.NewOwnerPrincipalID})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

// memberCandidateResponse is the bounded P10a candidate projection: only the
// two display surfaces and the already_member flag the member picker needs.
type memberCandidateResponse struct {
	PrincipalID   string `json:"principal_id"`
	DisplayName   string `json:"display_name"`
	AlreadyMember bool   `json:"already_member"`
}

// memberCandidates serves GET /api/v1/workspaces/{workspace_id}/member-
// candidates?q=<text>. It reaches the injected repository Store through the
// WorkspaceMemberCandidateAuthority capability (a handler whose service does
// not implement it fails closed as SERVICE_UNAVAILABLE), passes the single
// "q" value onward untouched, and maps the repository's content-free error
// surface exactly like every other read: a denial and a missing/revoked/
// archived workspace are the same NOT_FOUND, and an out-of-range term is
// REQUEST_INVALID. The response is deterministic and bounded to 20 candidates
// with a truthful "truncated" flag.
func (handler *Handler) memberCandidates(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	provider, ok := handler.service.(WorkspaceMemberCandidateAuthority)
	if !ok {
		setServerFailureCause(writer, "workspace service capability missing", "WorkspaceMemberCandidateAuthority")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	result, err := provider.MemberCandidates(request.Context(), access, workspaceID, request.URL.Query().Get("q"))
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	items := make([]memberCandidateResponse, len(result.Candidates))
	for index, candidate := range result.Candidates {
		items[index] = memberCandidateResponse{
			PrincipalID: candidate.PrincipalID, DisplayName: candidate.DisplayName, AlreadyMember: candidate.AlreadyMember,
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"candidates": items, "truncated": result.Truncated})
}

// registerSource creates one source registration. It deliberately has
// no idempotency key header: registration converges on content-derived ids, so
// a replay of the same body is the same lineage (ADR-0074 s1.2).
func (handler *Handler) registerSource(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string) {
	if headerPresent(request.Header, "Idempotency-Key") || headerPresent(request.Header, "If-Match") {
		var fields []string
		if headerPresent(request.Header, "Idempotency-Key") {
			fields = append(fields, "Idempotency-Key")
		}
		if headerPresent(request.Header, "If-Match") {
			fields = append(fields, "If-Match")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", fields)
		return
	}
	var body sourceRegisterBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	var requestModel registration.RegisterRequest
	sourceType := "FOLDER"
	if body.SourceType != nil {
		sourceType = *body.SourceType
	}
	if sourceType == "POSTGRESQL_QUERY" {
		if !body.postgreSQLComplete() {
			writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingPostgreSQLFields())
			return
		}
		credentialReference := ""
		if body.CredentialReference != nil {
			credentialReference = *body.CredentialReference
		}
		requestModel = registration.RegisterRequest{
			SourceType: sourceType, Name: *body.Name, Kind: *body.Kind,
			DatabaseIdentity: *body.DatabaseIdentity, CredentialReference: credentialReference, LineageID: *body.LineageID,
			ProjectionRevision: *body.ProjectionRevision, ContractHash: *body.ContractHash,
			SchemaName: *body.SchemaName, RelationName: *body.RelationName, RelationKind: *body.RelationKind,
			Columns: body.postgreSQLColumns(), EmptySnapshotPolicy: *body.EmptySnapshotPolicy,
		}
		if body.MaxRows != nil {
			requestModel.MaxRows = *body.MaxRows
		}
		if body.MaxColumns != nil {
			requestModel.MaxColumns = *body.MaxColumns
		}
		if body.MaxFieldBytes != nil {
			requestModel.MaxFieldBytes = *body.MaxFieldBytes
		}
		if body.MaxRowBytes != nil {
			requestModel.MaxRowBytes = *body.MaxRowBytes
		}
		if body.MaxTotalBytes != nil {
			requestModel.MaxTotalBytes = *body.MaxTotalBytes
		}
		if body.StatementTimeoutMS != nil {
			requestModel.StatementTimeoutMS = *body.StatementTimeoutMS
		}
		if body.SyncIntervalSeconds != nil {
			requestModel.SyncIntervalSeconds = *body.SyncIntervalSeconds
		}
	} else if sourceType == "GIT" || sourceType == "MAIL" {
		if !body.remoteComplete(sourceType) {
			writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingRemoteFields(sourceType))
			return
		}
		var since *time.Time
		if body.Since != nil && *body.Since != "" {
			parsed, parseErr := time.Parse(time.RFC3339Nano, *body.Since)
			if parseErr != nil {
				writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"since"})
				return
			}
			parsed = parsed.UTC()
			since = &parsed
		}
		requestModel = registration.RegisterRequest{
			SourceType: sourceType, Name: *body.Name, Kind: *body.Kind,
			CredentialReference: valueOrEmpty(body.CredentialReference), Provider: valueOrEmpty(body.Provider),
			Endpoint: valueOrEmpty(body.Endpoint), WebBaseURL: valueOrEmpty(body.WebBaseURL),
			RepositoryID: valueOrEmpty(body.RepositoryID), BranchName: valueOrEmpty(body.BranchName),
			IncludeGlobs: valueOrSlice(body.IncludeGlobs), ExcludeGlobs: valueOrSlice(body.ExcludeGlobs),
			TextMediaTypes: valueOrSlice(body.TextMediaTypes), MaxBlobBytes: valueOrInt64(body.MaxBlobBytes),
			Mailbox: valueOrEmpty(body.Mailbox), Folder: valueOrEmpty(body.Folder), Username: valueOrEmpty(body.Username), Since: since,
			IncludeAttachments: valueOrBool(body.IncludeAttachments), MaxMessageBytes: valueOrInt64(body.MaxMessageBytes),
			MaxAttachmentBytes: valueOrInt64(body.MaxAttachmentBytes), AttachmentMediaTypes: valueOrSlice(body.AttachmentMediaTypes),
		}
	} else if sourceType == "FOLDER" {
		if !body.complete() {
			writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFOLDERFields())
			return
		}
		requestModel = registration.RegisterRequest{
			SourceType: "FOLDER", Name: *body.Name, RootAlias: *body.RootAlias, RootIdentity: *body.RootIdentity, RelativeRoot: *body.RelativeRoot,
			Kind: *body.Kind, Recursive: *body.Recursive, IncludeGlobs: *body.IncludeGlobs, ExcludeGlobs: *body.ExcludeGlobs,
			MaxFileBytes: *body.MaxFileBytes, OCRMode: *body.OCRMode, Formats: *body.Formats,
		}
	} else {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"source_type"})
		return
	}
	result, err := handler.sources.Register(request.Context(), access, requestModel)
	if err != nil {
		handleSourceServiceError(writer, err, requestID, true)
		return
	}
	writeJSON(writer, http.StatusOK, sourceRegisterResponse{
		ConnectionID: result.ConnectionID, SourceScopeID: result.SourceScopeID,
		DiscoveredScopeID: result.DiscoveredScopeID, Revision: result.Revision,
		CredentialReference: result.CredentialReference, ScopeConfigHash: result.ScopeConfigHash,
		AccessMode: result.AccessMode, Created: result.Created,
	})
}

// bootstrapPostgreSQLConnection configures the source-owned DRAFT connection
// needed by discovery. The body contains no scope, columns, SQL, DSN or secret
// bytes; replay converges on the content-derived connection lineage.
func (handler *Handler) bootstrapPostgreSQLConnection(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string) {
	if headerPresent(request.Header, "Idempotency-Key") || headerPresent(request.Header, "If-Match") {
		var fields []string
		if headerPresent(request.Header, "Idempotency-Key") {
			fields = append(fields, "Idempotency-Key")
		}
		if headerPresent(request.Header, "If-Match") {
			fields = append(fields, "If-Match")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", fields)
		return
	}
	provider, ok := handler.sources.(SourceConnectionBootstrap)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	var body postgreSQLConnectionBootstrapBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	result, err := provider.BootstrapPostgreSQLConnection(request.Context(), access,
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: *body.Name, DatabaseIdentity: *body.DatabaseIdentity,
			LineageID: *body.LineageID, CredentialReference: valueOrEmpty(body.CredentialReference),
			WorkspaceID: valueOrEmpty(body.WorkspaceID),
		})
	if err != nil {
		handleSourceServiceError(writer, err, requestID, true)
		return
	}
	writeJSON(writer, http.StatusOK, postgreSQLConnectionBootstrapResponse{
		ConnectionID: result.ConnectionID, ConnectionRevision: result.ConnectionRevision,
		CredentialReference: result.CredentialReference, Created: result.Created,
	})
}

func (handler *Handler) requestSourceDiscovery(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, connectionID string) {
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	provider, ok := handler.sources.(SourceDiscovery)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	result, err := provider.RequestDiscovery(request.Context(), access, registration.DiscoveryRequest{
		ConnectionID: connectionID, IdempotencyKey: key,
	})
	if err != nil {
		handleSourceServiceError(writer, err, requestID, true)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]any{
		"request_id": result.RequestID, "created": result.Created,
	})
}

func (handler *Handler) getSourceDiscovery(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, discoveryRequestID string) {
	provider, ok := handler.sources.(SourceDiscovery)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	result, err := provider.GetDiscovery(request.Context(), access, discoveryRequestID)
	if err != nil {
		switch sourcediscovery.CodeOf(err) {
		case sourcediscovery.CodeInvalid:
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		case sourcediscovery.CodeNotFound, sourcediscovery.CodeExpired, sourcediscovery.CodeTrustStale:
			writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		default:
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		}
		return
	}
	views := make([]sourceDiscoveryViewResponse, len(result.Views))
	for index, view := range result.Views {
		columns := make([]sourceDiscoveryColumnResponse, len(view.Columns))
		for columnIndex, column := range view.Columns {
			roles := make([]postgresqlquery.Role, len(column.Roles))
			copy(roles, column.Roles)
			columns[columnIndex] = sourceDiscoveryColumnResponse{
				Ordinal: column.Ordinal, Name: column.Name, TypeName: column.TypeName,
				LogicalType: column.LogicalType, Nullable: column.Nullable,
				Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes,
				Comment: column.Comment, Roles: roles, PrimaryKey: column.PrimaryKey,
			}
		}
		views[index] = sourceDiscoveryViewResponse{
			Selector: view.Selector, SchemaName: view.SchemaName,
			RelationName: view.RelationName, RelationKind: view.RelationKind,
			Comment: view.Comment, ApproxRowCount: view.ApproxRowCount, Status: view.Status,
			Interpretation: view.Interpretation, Columns: columns,
			ExcludedColumns: sourceDiscoveryExcludedColumnResponses(view.ExcludedColumns),
		}
	}
	writeJSON(writer, http.StatusOK, sourceDiscoveryResponse{
		RequestID: result.RequestID, RequestStatus: result.RequestStatus,
		ResultID: result.ResultID, ResultStatus: result.ResultStatus,
		ViewCount: result.ViewCount, PreparedViewCount: result.PreparedViewCount,
		NeedsInterpretationViewCount: result.NeedsInterpretationViewCount,
		FailureCode:                  result.FailureCode, ExpiresAt: result.ExpiresAt, Views: views,
	})
}

func (handler *Handler) registerSourceDiscoveryView(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, discoveryRequestID, viewID string) {
	if headerPresent(request.Header, "Idempotency-Key") || headerPresent(request.Header, "If-Match") {
		var fields []string
		if headerPresent(request.Header, "Idempotency-Key") {
			fields = append(fields, "Idempotency-Key")
		}
		if headerPresent(request.Header, "If-Match") {
			fields = append(fields, "If-Match")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", fields)
		return
	}
	var body sourceDiscoveryRegisterBody
	if code := decodeOptionalJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !postgresqlquery.ValidProjectionMode(body.Mode) {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"mode"})
		return
	}
	provider, ok := handler.sources.(SourceDiscoveryRegistration)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	result, err := provider.RegisterDiscoveredView(request.Context(), access, discoveryRequestID, viewID, body.ExcludedColumns, body.Mode)
	if err != nil {
		switch sourcediscovery.CodeOf(err) {
		case sourcediscovery.CodeInvalid:
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		case sourcediscovery.CodeNotFound, sourcediscovery.CodeExpired, sourcediscovery.CodeTrustStale:
			writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		default:
			handleSourceServiceError(writer, err, requestID, true)
		}
		return
	}
	writeJSON(writer, http.StatusOK, sourceRegisterResponse{
		ConnectionID: result.ConnectionID, SourceScopeID: result.SourceScopeID,
		DiscoveredScopeID: result.DiscoveredScopeID, Revision: result.Revision,
		ScopeConfigHash: result.ScopeConfigHash, AccessMode: result.AccessMode,
		Created: result.Created,
	})
}

// sourceDiscoveryRegisterBatchBody is card S3.4b's batch registration body: a
// bounded list of server-issued selectors, each with the same two optional
// narrowing choices the single-view route accepts. No schema, relation, column
// name, role, hash or SQL is ever accepted.
type sourceDiscoveryRegisterBatchBody struct {
	Items []sourceDiscoveryRegisterBatchItem `json:"items"`
}

type sourceDiscoveryRegisterBatchItem struct {
	ViewID          string `json:"view_id"`
	ExcludedColumns []int  `json:"excluded_columns"`
	Mode            string `json:"mode"`
}

type sourceDiscoveryRegisterBatchResponse struct {
	RegisteredCount int                                  `json:"registered_count"`
	RefusedCount    int                                  `json:"refused_count"`
	Results         []sourceDiscoveryRegisterBatchResult `json:"results"`
}

type sourceDiscoveryRegisterBatchResult struct {
	ViewID       string                  `json:"view_id"`
	Outcome      string                  `json:"outcome"`
	ReasonCode   string                  `json:"reason_code,omitempty"`
	Registration *sourceRegisterResponse `json:"registration,omitempty"`
}

// registerSourceDiscoveryViewBatch is card S3.4b's one-request-per-batch
// registration: up to registration.MaxBatchRegisterViews selectors, each
// registered through the unchanged single-table path, with one per-view
// outcome. A larger request is refused as a whole before any selector reaches
// the registration service.
func (handler *Handler) registerSourceDiscoveryViewBatch(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, discoveryRequestID string) {
	if headerPresent(request.Header, "Idempotency-Key") || headerPresent(request.Header, "If-Match") {
		var fields []string
		if headerPresent(request.Header, "Idempotency-Key") {
			fields = append(fields, "Idempotency-Key")
		}
		if headerPresent(request.Header, "If-Match") {
			fields = append(fields, "If-Match")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", fields)
		return
	}
	var body sourceDiscoveryRegisterBatchBody
	if code := decodeJSONLimited(writer, request, &body, maxBatchBodyBytes); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if len(body.Items) < 1 || len(body.Items) > registration.MaxBatchRegisterViews {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"items"})
		return
	}
	items := make([]registration.BatchRegisterItem, len(body.Items))
	for index, item := range body.Items {
		if item.ViewID == "" || !postgresqlquery.ValidProjectionMode(item.Mode) {
			writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"items"})
			return
		}
		items[index] = registration.BatchRegisterItem{
			ViewID: item.ViewID, ExcludedColumnOrdinals: item.ExcludedColumns, Mode: item.Mode,
		}
	}
	provider, ok := handler.sources.(SourceDiscoveryRegistration)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	result, err := provider.RegisterDiscoveredViews(request.Context(), access, discoveryRequestID, items)
	if err != nil {
		switch sourcediscovery.CodeOf(err) {
		case sourcediscovery.CodeInvalid:
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		case sourcediscovery.CodeNotFound, sourcediscovery.CodeExpired, sourcediscovery.CodeTrustStale:
			writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		default:
			handleSourceServiceError(writer, err, requestID, true)
		}
		return
	}
	results := make([]sourceDiscoveryRegisterBatchResult, len(result.Outcomes))
	for index, outcome := range result.Outcomes {
		result := sourceDiscoveryRegisterBatchResult{ViewID: outcome.ViewID}
		if outcome.Registered {
			registered := sourceRegisterResponse{
				ConnectionID: outcome.Result.ConnectionID, SourceScopeID: outcome.Result.SourceScopeID,
				DiscoveredScopeID: outcome.Result.DiscoveredScopeID, Revision: outcome.Result.Revision,
				ScopeConfigHash: outcome.Result.ScopeConfigHash, AccessMode: outcome.Result.AccessMode,
				Created: outcome.Result.Created,
			}
			result.Outcome = "REGISTERED"
			result.Registration = &registered
		} else {
			result.Outcome = "REFUSED"
			result.ReasonCode = outcome.ReasonCode
		}
		results[index] = result
	}
	writeJSON(writer, http.StatusOK, sourceDiscoveryRegisterBatchResponse{
		RegisteredCount: result.RegisteredCount, RefusedCount: result.RefusedCount, Results: results,
	})
}

// activateSource requests activation of one DRAFT lineage. The client
// idempotency key becomes the durable queue key of the SOURCE_SCOPE_SYNC job.
func (handler *Handler) activateSource(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, sourceScopeID string) {
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	result, err := handler.sources.Activate(request.Context(), access, registration.ActivateRequest{
		IdempotencyKey: key, SourceScopeID: sourceScopeID,
	})
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"job_id": result.JobID})
}

// syncSource requests a fresh full sync for an already READY source revision.
// It uses the same CSRF/idempotency boundary as activation; the registration
// service owns authorization, single-flight and durable queue placement.
func (handler *Handler) syncSource(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, sourceScopeID string) {
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	result, err := handler.sources.Sync(request.Context(), access, registration.SyncRequest{
		IdempotencyKey: key, SourceScopeID: sourceScopeID,
	})
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"job_id": result.JobID})
}

// uploadDocumentsResponse and uploadedDocumentResponse are UPL-1's upload
// result: the connection identity plus, per accepted file, the object key,
// declared format and version the file settled at (a re-uploaded name is a
// new version of the same object, never a duplicate source).
type uploadDocumentsResponse struct {
	ConnectionID string                     `json:"connection_id"`
	Uploaded     []uploadedDocumentResponse `json:"uploaded"`
}

type uploadedDocumentResponse struct {
	Name      string `json:"name"`
	ObjectKey string `json:"object_key"`
	Version   int64  `json:"version"`
	Format    string `json:"format"`
	ByteSize  int64  `json:"byte_size"`
}

// uploadDocuments is UPL-1: POST /api/v1/sources/{source_scope_id}/documents,
// multipart/form-data. Unlike activate/sync this is not an empty-body
// command -- the request body is the files themselves -- so there is no
// Idempotency-Key/If-Match pair to require: re-uploading the same name is
// itself the safe, content-addressed operation (a new version row, never a
// duplicate source). Every accepted byte still goes through
// internal/source/upload's content-over-extension validation and
// registration.Service's owner-only authorization and audit.
func (handler *Handler) uploadDocuments(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, sourceScopeID string) {
	request.Body = http.MaxBytesReader(writer, request.Body, sourceupload.MaxTotalBytes+(8<<20))
	if err := request.ParseMultipartForm(32 << 20); err != nil {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	defer func() {
		if request.MultipartForm != nil {
			_ = request.MultipartForm.RemoveAll()
		}
	}()
	if request.MultipartForm == nil || len(request.MultipartForm.File) == 0 {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	var files []registration.UploadFile
	for _, headers := range request.MultipartForm.File {
		for _, header := range headers {
			if len(files) >= sourceupload.MaxFilesPerRequest {
				writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
				return
			}
			opened, openErr := header.Open()
			if openErr != nil {
				writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
				return
			}
			content, readErr := io.ReadAll(io.LimitReader(opened, sourceupload.MaxFileBytes+1))
			closeErr := opened.Close()
			if readErr != nil || closeErr != nil {
				writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
				return
			}
			files = append(files, registration.UploadFile{Name: header.Filename, Content: content})
		}
	}
	result, err := handler.sources.UploadDocuments(request.Context(), access, registration.UploadDocumentsRequest{
		SourceScopeID: sourceScopeID, Files: files,
	})
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	uploaded := make([]uploadedDocumentResponse, len(result.Uploaded))
	for i, document := range result.Uploaded {
		uploaded[i] = uploadedDocumentResponse{
			Name: document.Name, ObjectKey: document.ObjectKey, Version: document.Version,
			Format: document.Format, ByteSize: document.ByteSize,
		}
	}
	writeJSON(writer, http.StatusOK, uploadDocumentsResponse{ConnectionID: result.ConnectionID, Uploaded: uploaded})
}

// ADR-0087 §1 confirmation-authority REST actions. Each handler reaches the
// ADR-0053 authority runtime through the same injected workspace repository
// Store that implements WorkspaceService, projects a strictly closed JSON body
// (organization and idempotency are server-derived, never client-supplied), and
// maps the repository's content-free error surface. No new authority model,
// policy matrix, canonical envelope or audit action is introduced here: grant,
// confirm, revoke and reconfirm keep exactly the role rules, issuer/confirmer
// separation and content-free audit events ADR-0053 froze in
// internal/workspace/repository/authority_commands.go.

// Closed literals ConfirmManagedSource requires to build its canonical request.
// They are not operator choices; the handler fills them so the operator only
// names the binding, the source and the grant it holds.
const (
	managedAccessMode          = "WORKSPACE_MANAGED"
	managedWarningVersion      = "workspace-managed-risk-v1"
	managedAcknowledgementCode = "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
)

// handleAuthorityError maps the ADR-0053 authority error surface onto a
// content-free HTTP response. Policy denial and a hidden/missing authority row
// both become one identical 404 so the route exposes no existence oracle and no
// role oracle; the handler never distinguishes a wrong role from a missing
// grant, confirmation, binding or policy.
func handleAuthorityError(writer http.ResponseWriter, err error, requestID string) {
	code := workspacerepository.CodeOf(err)
	status, publicCode := authorityErrorResponse(code)
	if status >= http.StatusInternalServerError {
		setServerFailureCause(writer, "workspace authority", string(code))
	}
	writeError(writer, status, publicCode, requestID)
}

func authorityErrorResponse(code workspacerepository.ErrorCode) (int, string) {
	switch code {
	case workspacerepository.CodeAuthorityRequestInvalid:
		return http.StatusBadRequest, "REQUEST_INVALID"
	case workspacerepository.CodeAuthorityIdempotencyConflict:
		return http.StatusConflict, "WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT"
	case workspacerepository.CodeAuthorityDenied, workspacerepository.CodeAuthorityNotFound:
		// Absence and policy denial are intentionally indistinguishable (closed
		// surface, ADR-0053): neither reveals the role rule or the row state.
		return http.StatusNotFound, "NOT_FOUND"
	case workspacerepository.CodeAuthorityPreconditionFailed:
		return http.StatusConflict, "WORKSPACE_AUTHORITY_PRECONDITION_FAILED"
	case workspacerepository.CodeAuthorityPersistence:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	default:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	}
}

// authorityCommands returns the ADR-0053 runtime reached through the injected
// workspace service. When the composition did not supply an authority-capable
// service the routes fail closed rather than degrade.
func (handler *Handler) authorityCommands() (WorkspaceAuthority, bool) {
	authority, ok := handler.service.(WorkspaceAuthority)
	return authority, ok
}

func (handler *Handler) requireAuthority(writer http.ResponseWriter, requestID string) (WorkspaceAuthority, bool) {
	authority, ok := handler.authorityCommands()
	if !ok {
		// The exact cause of the demo-stand 503: the injected storage service
		// stopped satisfying the WorkspaceAuthority capability (a rename that
		// was otherwise invisible). Name it in the log line instead of leaving
		// a bare SERVICE_UNAVAILABLE.
		setServerFailureCause(writer, "workspace service capability missing", "WorkspaceAuthority")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return nil, false
	}
	return authority, true
}

// connectionTrustAuthority returns the ADR-0087 §2 runtime reached through the
// injected workspace service, mirroring authorityCommands/requireAuthority.
func (handler *Handler) connectionTrustAuthority() (ConnectionTrustAuthority, bool) {
	authority, ok := handler.service.(ConnectionTrustAuthority)
	return authority, ok
}

func (handler *Handler) requireConnectionTrustAuthority(writer http.ResponseWriter, requestID string) (ConnectionTrustAuthority, bool) {
	authority, ok := handler.connectionTrustAuthority()
	if !ok {
		setServerFailureCause(writer, "workspace service capability missing", "ConnectionTrustAuthority")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return nil, false
	}
	return authority, true
}

type verifyConnectionTrustBody struct {
	AttestedConnectorIdentity string `json:"attested_connector_identity"`
	AttestedBy                string `json:"attested_by"`
	AttestedAt                string `json:"attested_at"`
}

func (body verifyConnectionTrustBody) complete() bool {
	return body.AttestedConnectorIdentity != "" && body.AttestedBy != "" && body.AttestedAt != ""
}

func (body verifyConnectionTrustBody) missingFields() []string {
	var fields []string
	if body.AttestedConnectorIdentity == "" {
		fields = append(fields, "attested_connector_identity")
	}
	if body.AttestedBy == "" {
		fields = append(fields, "attested_by")
	}
	if body.AttestedAt == "" {
		fields = append(fields, "attested_at")
	}
	return fields
}

// verifyConnectionTrust exposes ADR-0087 §2's CONNECTOR_ADMIN-gated
// DRAFT->VERIFIED transition. The operator supplies only the mandatory
// attestation (who verified the connector, the exact connector identity
// attested, and when); organization and idempotency stay server-derived, and
// the repository owns the CONNECTOR_ADMIN policy gate, the SECURITY DEFINER
// door and the content-free audit event.
// serviceAccessCodeBearer extracts a V1-C agent access code from
// `Authorization: Bearer kva_...`. It is deliberately as strict as httpauth's
// own apiBearer form: exactly one Authorization header, and never combined
// with a Cookie or an Origin/CSRF header (a request that fails this shape
// check simply falls through to the ordinary human session authenticator,
// which fails it on its own terms).
func serviceAccessCodeBearer(request *http.Request) (string, bool) {
	value, ok := exactHeader(request.Header, "Authorization")
	if !ok || headerPresent(request.Header, "Cookie") || headerPresent(request.Header, "Origin") || headerPresent(request.Header, httpauth.CSRFHeader) {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	code := value[len(prefix):]
	if strings.TrimSpace(code) != code || !serviceprincipal.ValidCodeShape(code) {
		return "", false
	}
	return code, true
}

type accessCodeIssueBody struct {
	Name         string   `json:"name"`
	WorkspaceIDs []string `json:"workspace_ids"`
	TTLSeconds   int64    `json:"ttl_seconds"`
}

func (body accessCodeIssueBody) complete() bool {
	return strings.TrimSpace(body.Name) != "" && len(body.WorkspaceIDs) > 0 && body.TTLSeconds > 0
}

func (body accessCodeIssueBody) missingFields() []string {
	var fields []string
	if strings.TrimSpace(body.Name) == "" {
		fields = append(fields, "name")
	}
	if len(body.WorkspaceIDs) == 0 {
		fields = append(fields, "workspace_ids")
	}
	if body.TTLSeconds <= 0 {
		fields = append(fields, "ttl_seconds")
	}
	return fields
}

// accessCodeIssue is the OWNER-only V1-C action: create a named SERVICE
// principal, scope it to the requested workspaces (this one plus any other
// the same OWNER selects) and return the raw code exactly once.
// AccessCodeService.Issue itself re-authorizes OWNER on every requested
// workspace; this handler adds no separate policy decision.
func (handler *Handler) accessCodeIssue(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	if handler.accessCodes == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	// The Idempotency-Key header is required for the same client-contract
	// consistency every other mutation route enforces. FIX-1 #2:
	// internal/serviceprincipal now keeps a durable idempotency receipt
	// keyed on it -- an exact retry with the same key and body never mints a
	// second principal/credential; it cannot replay the raw code itself
	// (never persisted), so it answers the typed SERVICE_PRINCIPAL_ALREADY_ISSUED
	// outcome instead.
	idempotencyKey, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body accessCodeIssueBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	workspaceIDs := body.WorkspaceIDs
	found := false
	for _, id := range workspaceIDs {
		if id == workspaceID {
			found = true
			break
		}
	}
	if !found {
		workspaceIDs = append([]string{workspaceID}, workspaceIDs...)
	}
	result, err := handler.accessCodes.Issue(request.Context(), access, serviceprincipal.IssueRequest{
		Name: body.Name, WorkspaceIDs: workspaceIDs, TTLSeconds: body.TTLSeconds, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		writeError(writer, accessCodeErrorStatus(serviceprincipal.CodeOf(err)), string(serviceprincipal.CodeOf(err)), requestID)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{
		"credential_id": result.CredentialID,
		"principal_id":  result.PrincipalID,
		"name":          result.Name,
		"code":          result.Code,
		"workspace_ids": result.WorkspaceIDs,
		"expires_at":    result.ExpiresAt.Format(time.RFC3339),
	})
}

func (handler *Handler) accessCodeList(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	if handler.accessCodes == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	credentials, err := handler.accessCodes.List(request.Context(), access, workspaceID)
	if err != nil {
		writeError(writer, accessCodeErrorStatus(serviceprincipal.CodeOf(err)), string(serviceprincipal.CodeOf(err)), requestID)
		return
	}
	items := make([]map[string]any, 0, len(credentials))
	for _, credential := range credentials {
		item := map[string]any{
			"credential_id": credential.CredentialID,
			"principal_id":  credential.PrincipalID,
			"name":          credential.Name,
			"workspace_ids": credential.WorkspaceIDs,
			"created_at":    credential.CreatedAt.Format(time.RFC3339),
			"expires_at":    credential.ExpiresAt.Format(time.RFC3339),
		}
		if credential.RevokedAt != nil {
			item["revoked_at"] = credential.RevokedAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"access_codes": items})
}

func (handler *Handler) accessCodeRevoke(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, credentialID string) {
	if handler.accessCodes == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if err := handler.accessCodes.Revoke(request.Context(), access, credentialID); err != nil {
		writeError(writer, accessCodeErrorStatus(serviceprincipal.CodeOf(err)), string(serviceprincipal.CodeOf(err)), requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"revoked": true})
}

func accessCodeErrorStatus(code serviceprincipal.ErrorCode) int {
	switch code {
	case serviceprincipal.CodeInvalid:
		return http.StatusBadRequest
	case serviceprincipal.CodeDenied, serviceprincipal.CodeNotFound:
		return http.StatusNotFound
	case serviceprincipal.CodeAlreadyIssued, serviceprincipal.CodeIdempotencyConflict:
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}

func (handler *Handler) verifyConnectionTrust(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, connectionID string) {
	authority, ok := handler.requireConnectionTrustAuthority(writer, requestID)
	if !ok {
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body verifyConnectionTrustBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	result, err := authority.VerifyConnectionTrust(request.Context(), access, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: key, ConnectionID: connectionID,
		AttestedConnectorIdentity: body.AttestedConnectorIdentity,
		AttestedBy:                body.AttestedBy,
		AttestedAt:                body.AttestedAt,
	})
	if err != nil {
		handleConnectionTrustError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"result_id": result.ResultID, "result_hash": result.ResultHash})
}

// handleConnectionTrustError maps the ADR-0087 §2 error surface onto a
// content-free HTTP response. A policy denial and a hidden/missing connection
// both become one identical 404 so the route exposes no role or existence
// oracle, exactly as handleAuthorityError collapses the four confirmation
// actions' CodeAuthorityDenied/CodeAuthorityNotFound.
func handleConnectionTrustError(writer http.ResponseWriter, err error, requestID string) {
	code := workspacerepository.CodeOf(err)
	status, publicCode := connectionTrustErrorResponse(code)
	if status >= http.StatusInternalServerError {
		setServerFailureCause(writer, "workspace connection trust", string(code))
	}
	writeError(writer, status, publicCode, requestID)
}

func connectionTrustErrorResponse(code workspacerepository.ErrorCode) (int, string) {
	switch code {
	case workspacerepository.CodeConnectionTrustRequestInvalid:
		return http.StatusBadRequest, "REQUEST_INVALID"
	case workspacerepository.CodeConnectionTrustIdempotencyConflict:
		return http.StatusConflict, "WORKSPACE_CONNECTION_TRUST_IDEMPOTENCY_CONFLICT"
	case workspacerepository.CodeConnectionTrustDenied, workspacerepository.CodeConnectionTrustNotFound:
		return http.StatusNotFound, "NOT_FOUND"
	case workspacerepository.CodeConnectionTrustPreconditionFailed:
		return http.StatusConflict, "WORKSPACE_CONNECTION_TRUST_PRECONDITION_FAILED"
	case workspacerepository.CodeConnectionTrustPersistence:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	default:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	}
}

type confirmGrantIssueBody struct {
	ExpectedWorkspaceRevision          int64  `json:"expected_workspace_revision"`
	ExpectedWorkspaceConfigurationHash string `json:"expected_workspace_configuration_hash"`
	TargetPrincipalID                  string `json:"target_principal_id"`
	TTLSeconds                         int64  `json:"ttl_seconds"`
	ExpectedPolicyRevision             string `json:"expected_policy_revision"`
}

func (body confirmGrantIssueBody) complete() bool {
	return body.ExpectedWorkspaceRevision >= 1 && body.ExpectedWorkspaceConfigurationHash != "" &&
		body.TargetPrincipalID != "" && body.TTLSeconds != 0 && body.ExpectedPolicyRevision != ""
}

func (body confirmGrantIssueBody) missingFields() []string {
	var fields []string
	if body.ExpectedWorkspaceRevision < 1 {
		fields = append(fields, "expected_workspace_revision")
	}
	if body.ExpectedWorkspaceConfigurationHash == "" {
		fields = append(fields, "expected_workspace_configuration_hash")
	}
	if body.TargetPrincipalID == "" {
		fields = append(fields, "target_principal_id")
	}
	if body.TTLSeconds == 0 {
		fields = append(fields, "ttl_seconds")
	}
	if body.ExpectedPolicyRevision == "" {
		fields = append(fields, "expected_policy_revision")
	}
	return fields
}

// confirmGrantIssue exposes WORKSPACE_CONFIRMATION_GRANT_ISSUE (IssueConfirmationGrant).
func (handler *Handler) confirmGrantIssue(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	authority, ok := handler.requireAuthority(writer, requestID)
	if !ok {
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body confirmGrantIssueBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	result, err := authority.IssueConfirmationGrant(request.Context(), access, workspacerepository.IssueGrantRequest{
		IdempotencyKey:                     key,
		OrganizationID:                     access.OrganizationID,
		WorkspaceID:                        workspaceID,
		ExpectedWorkspaceRevision:          body.ExpectedWorkspaceRevision,
		ExpectedWorkspaceConfigurationHash: body.ExpectedWorkspaceConfigurationHash,
		TargetPrincipalID:                  body.TargetPrincipalID,
		TTLSeconds:                         body.TTLSeconds,
		ExpectedPolicyRevision:             body.ExpectedPolicyRevision,
	})
	if err != nil {
		handleAuthorityError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, authorityResultResponse(result))
}

type confirmGrantRevokeBody struct {
	GrantID                string `json:"grant_id"`
	GrantRevision          int64  `json:"grant_revision"`
	GrantHash              string `json:"grant_hash"`
	ExpectedPolicyRevision string `json:"expected_policy_revision"`
}

func (body confirmGrantRevokeBody) complete() bool {
	return body.GrantID != "" && body.GrantRevision >= 1 && body.GrantHash != "" && body.ExpectedPolicyRevision != ""
}

func (body confirmGrantRevokeBody) missingFields(pathGrantID string) []string {
	return missingFieldNames([]fieldPresence{
		{body.GrantID != "" && body.GrantID == pathGrantID, "grant_id"},
		{body.GrantRevision >= 1, "grant_revision"}, {body.GrantHash != "", "grant_hash"},
		{body.ExpectedPolicyRevision != "", "expected_policy_revision"},
	})
}

// confirmGrantRevoke exposes WORKSPACE_CONFIRMATION_GRANT_REVOKE (RevokeConfirmationGrant).
func (handler *Handler) confirmGrantRevoke(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, grantID string) {
	authority, ok := handler.requireAuthority(writer, requestID)
	if !ok {
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body confirmGrantRevokeBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() || body.GrantID != grantID {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields(grantID))
		return
	}
	result, err := authority.RevokeConfirmationGrant(request.Context(), access, workspacerepository.RevokeGrantRequest{
		IdempotencyKey:         key,
		OrganizationID:         access.OrganizationID,
		WorkspaceID:            workspaceID,
		GrantID:                body.GrantID,
		GrantRevision:          body.GrantRevision,
		GrantHash:              body.GrantHash,
		ExpectedPolicyRevision: body.ExpectedPolicyRevision,
	})
	if err != nil {
		handleAuthorityError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, authorityResultResponse(result))
}

type managedSourceConfirmBody struct {
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

func (body managedSourceConfirmBody) complete() bool {
	return body.WorkspaceRevision >= 1 && body.WorkspaceConfigurationHash != "" &&
		body.WorkspaceSourceID != "" && body.SourceScopeID != "" && body.SourceScopeRevision >= 1 &&
		body.ScopeConfigHash != "" && body.ConfirmationActorGrantID != "" &&
		body.ConfirmationActorGrantRevision >= 1 && body.ConfirmationActorGrantHash != "" &&
		body.WarningContractHash != "" && body.ExpectedPolicyRevision != ""
}

func (body managedSourceConfirmBody) missingFields() []string {
	var fields []string
	if body.WorkspaceRevision < 1 {
		fields = append(fields, "workspace_revision")
	}
	if body.WorkspaceConfigurationHash == "" {
		fields = append(fields, "workspace_configuration_hash")
	}
	if body.WorkspaceSourceID == "" {
		fields = append(fields, "workspace_source_id")
	}
	if body.SourceScopeID == "" {
		fields = append(fields, "source_scope_id")
	}
	if body.SourceScopeRevision < 1 {
		fields = append(fields, "source_scope_revision")
	}
	if body.ScopeConfigHash == "" {
		fields = append(fields, "scope_config_hash")
	}
	if body.ConfirmationActorGrantID == "" {
		fields = append(fields, "confirmation_actor_grant_id")
	}
	if body.ConfirmationActorGrantRevision < 1 {
		fields = append(fields, "confirmation_actor_grant_revision")
	}
	if body.ConfirmationActorGrantHash == "" {
		fields = append(fields, "confirmation_actor_grant_hash")
	}
	if body.WarningContractHash == "" {
		fields = append(fields, "warning_contract_hash")
	}
	if body.ExpectedPolicyRevision == "" {
		fields = append(fields, "expected_policy_revision")
	}
	return fields
}

// managedSourceConfirm exposes WORKSPACE_MANAGED_CONFIRM (ConfirmManagedSource).
// The closed access-mode, warning-version and acknowledgement literals are
// server constants; the operator names the binding, the source and the grant it
// holds, and the repository enforces the actor-grant role and issuer/confirmer
// separation and appends the content-free confirmation audit event.
func (handler *Handler) managedSourceConfirm(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	authority, ok := handler.requireAuthority(writer, requestID)
	if !ok {
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body managedSourceConfirmBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	result, err := authority.ConfirmManagedSource(request.Context(), access, workspacerepository.ConfirmRequest{
		IdempotencyKey:                 key,
		OrganizationID:                 access.OrganizationID,
		WorkspaceID:                    workspaceID,
		WorkspaceRevision:              body.WorkspaceRevision,
		WorkspaceConfigurationHash:     body.WorkspaceConfigurationHash,
		WorkspaceSourceID:              body.WorkspaceSourceID,
		SourceScopeID:                  body.SourceScopeID,
		SourceScopeRevision:            body.SourceScopeRevision,
		ScopeConfigHash:                body.ScopeConfigHash,
		AccessMode:                     managedAccessMode,
		ConfirmationActorGrantID:       body.ConfirmationActorGrantID,
		ConfirmationActorGrantRevision: body.ConfirmationActorGrantRevision,
		ConfirmationActorGrantHash:     body.ConfirmationActorGrantHash,
		WarningVersion:                 managedWarningVersion,
		WarningContractHash:            body.WarningContractHash,
		AcknowledgementCode:            managedAcknowledgementCode,
		ExpectedPolicyRevision:         body.ExpectedPolicyRevision,
	})
	if err != nil {
		handleAuthorityError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, authorityResultResponse(result))
}

// managedSourceConfirmBatchBody is card S3.4b's closed batch confirmation
// command: the shared grant/warning/policy fields every table of the request
// confirms under, plus the bounded list of exact binding tuples. The closed
// access-mode, warning-version and acknowledgement literals stay server
// constants, exactly as on the single-table route.
type managedSourceConfirmBatchBody struct {
	WorkspaceRevision              int64                            `json:"workspace_revision"`
	WorkspaceConfigurationHash     string                           `json:"workspace_configuration_hash"`
	ConfirmationActorGrantID       string                           `json:"confirmation_actor_grant_id"`
	ConfirmationActorGrantRevision int64                            `json:"confirmation_actor_grant_revision"`
	ConfirmationActorGrantHash     string                           `json:"confirmation_actor_grant_hash"`
	WarningContractHash            string                           `json:"warning_contract_hash"`
	ExpectedPolicyRevision         string                           `json:"expected_policy_revision"`
	Tables                         []managedSourceConfirmBatchTable `json:"tables"`
}

type managedSourceConfirmBatchTable struct {
	WorkspaceSourceID   string `json:"workspace_source_id"`
	SourceScopeID       string `json:"source_scope_id"`
	SourceScopeRevision int64  `json:"source_scope_revision"`
	ScopeConfigHash     string `json:"scope_config_hash"`
}

func (body managedSourceConfirmBatchBody) complete() bool {
	if body.WorkspaceRevision < 1 || body.WorkspaceConfigurationHash == "" ||
		body.ConfirmationActorGrantID == "" || body.ConfirmationActorGrantRevision < 1 ||
		body.ConfirmationActorGrantHash == "" || body.WarningContractHash == "" ||
		body.ExpectedPolicyRevision == "" ||
		len(body.Tables) < 1 || len(body.Tables) > workspacerepository.MaxBatchConfirmTables {
		return false
	}
	for _, table := range body.Tables {
		if table.WorkspaceSourceID == "" || table.SourceScopeID == "" ||
			table.SourceScopeRevision < 1 || table.ScopeConfigHash == "" {
			return false
		}
	}
	return true
}

type managedSourceConfirmBatchResponse struct {
	ConfirmedCount int                               `json:"confirmed_count"`
	RefusedCount   int                               `json:"refused_count"`
	Results        []managedSourceConfirmBatchResult `json:"results"`
}

type managedSourceConfirmBatchResult struct {
	SourceScopeID    string `json:"source_scope_id"`
	Outcome          string `json:"outcome"`
	ReasonCode       string `json:"reason_code,omitempty"`
	ConfirmationID   string `json:"confirmation_id,omitempty"`
	ConfirmationHash string `json:"confirmation_hash,omitempty"`
}

// managedSourceConfirmBatch exposes card S3.4b's bounded batch of
// WORKSPACE_MANAGED_CONFIRM commands. The repository confirms each named table
// through the unchanged individual command, so every table keeps the identical
// checks, confirmation record and audit event; this handler only projects the
// closed per-table outcome.
func (handler *Handler) managedSourceConfirmBatch(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	authority, ok := handler.requireAuthority(writer, requestID)
	if !ok {
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body managedSourceConfirmBatchBody
	if code := decodeJSONLimited(writer, request, &body, maxBatchBodyBytes); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"tables"})
		return
	}
	tables := make([]workspacerepository.BatchConfirmTable, len(body.Tables))
	for index, table := range body.Tables {
		tables[index] = workspacerepository.BatchConfirmTable{
			WorkspaceSourceID: table.WorkspaceSourceID, SourceScopeID: table.SourceScopeID,
			SourceScopeRevision: table.SourceScopeRevision, ScopeConfigHash: table.ScopeConfigHash,
		}
	}
	result, err := authority.ConfirmManagedSourcesBatch(request.Context(), access, workspacerepository.BatchConfirmRequest{
		IdempotencyKey:                 key,
		OrganizationID:                 access.OrganizationID,
		WorkspaceID:                    workspaceID,
		WorkspaceRevision:              body.WorkspaceRevision,
		WorkspaceConfigurationHash:     body.WorkspaceConfigurationHash,
		ConfirmationActorGrantID:       body.ConfirmationActorGrantID,
		ConfirmationActorGrantRevision: body.ConfirmationActorGrantRevision,
		ConfirmationActorGrantHash:     body.ConfirmationActorGrantHash,
		WarningVersion:                 managedWarningVersion,
		WarningContractHash:            body.WarningContractHash,
		AcknowledgementCode:            managedAcknowledgementCode,
		ExpectedPolicyRevision:         body.ExpectedPolicyRevision,
		Tables:                         tables,
	})
	if err != nil {
		handleAuthorityError(writer, err, requestID)
		return
	}
	results := make([]managedSourceConfirmBatchResult, len(result.Outcomes))
	for index, outcome := range result.Outcomes {
		item := managedSourceConfirmBatchResult{SourceScopeID: outcome.SourceScopeID}
		if outcome.Confirmed {
			item.Outcome = "CONFIRMED"
			item.ConfirmationID = outcome.ConfirmationID
			item.ConfirmationHash = outcome.ConfirmationHash
		} else {
			item.Outcome = "REFUSED"
			item.ReasonCode = outcome.ReasonCode
		}
		results[index] = item
	}
	writeJSON(writer, http.StatusOK, managedSourceConfirmBatchResponse{
		ConfirmedCount: result.ConfirmedCount, RefusedCount: result.RefusedCount, Results: results,
	})
}

type managedConfirmationRevokeBody struct {
	ConfirmationID         string `json:"confirmation_id"`
	ConfirmationHash       string `json:"confirmation_hash"`
	ExpectedPolicyRevision string `json:"expected_policy_revision"`
}

func (body managedConfirmationRevokeBody) complete() bool {
	return body.ConfirmationID != "" && body.ConfirmationHash != "" && body.ExpectedPolicyRevision != ""
}

func (body managedConfirmationRevokeBody) missingFields(pathConfirmationID string) []string {
	return missingFieldNames([]fieldPresence{
		{body.ConfirmationID != "" && body.ConfirmationID == pathConfirmationID, "confirmation_id"},
		{body.ConfirmationHash != "", "confirmation_hash"}, {body.ExpectedPolicyRevision != "", "expected_policy_revision"},
	})
}

// managedConfirmationRevoke exposes WORKSPACE_MANAGED_CONFIRM_REVOKE
// (RevokeManagedConfirmation). It is also the "reconfirm" exit: once a live
// confirmation is revoked the operator may issue a fresh grant and confirm
// again through the same confirm route.
func (handler *Handler) managedConfirmationRevoke(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, confirmationID string) {
	authority, ok := handler.requireAuthority(writer, requestID)
	if !ok {
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body managedConfirmationRevokeBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() || body.ConfirmationID != confirmationID {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields(confirmationID))
		return
	}
	result, err := authority.RevokeManagedConfirmation(request.Context(), access, workspacerepository.RevokeConfirmationRequest{
		IdempotencyKey:         key,
		OrganizationID:         access.OrganizationID,
		WorkspaceID:            workspaceID,
		ConfirmationID:         body.ConfirmationID,
		ConfirmationHash:       body.ConfirmationHash,
		ExpectedPolicyRevision: body.ExpectedPolicyRevision,
	})
	if err != nil {
		handleAuthorityError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, authorityResultResponse(result))
}

type authorityCommandResponse struct {
	CommandID  string `json:"command_id"`
	Operation  string `json:"operation"`
	ResultID   string `json:"result_id"`
	ResultHash string `json:"result_hash"`
}

func authorityResultResponse(result workspacerepository.AuthorityResult) authorityCommandResponse {
	// CanonicalBytes stay server-side; a transport surface returns only the
	// immutable IDs and hashes (ADR-0053).
	return authorityCommandResponse{CommandID: result.CommandID, Operation: result.Operation, ResultID: result.ResultID, ResultHash: result.ResultHash}
}

// listSources returns the current sync status of every source bound to the
// current revision of one workspace (ADR-0074 D3-3).
func (handler *Handler) listSources(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	statuses, err := handler.sources.ListSources(request.Context(), access, workspaceID)
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	confirmation, err := handler.sources.ConfirmationContext(request.Context(), access, workspaceID)
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
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
			QueryOnly:                status.QueryOnly,
		}
	}
	response := map[string]any{"sources": items, "confirmation_context": confirmationContextResponseFrom(confirmation)}
	writeJSON(writer, http.StatusOK, response)
}

// sourceConnectionDraftResponse is card D-1's content-free draft row: the
// identifiers the wizard resumes with, the connection's display name, and the
// server-derived state. It carries no credential, address, trust hash or
// source content.
type sourceConnectionDraftResponse struct {
	ConnectionID       string    `json:"connection_id"`
	ConnectionRevision int64     `json:"connection_revision"`
	ConnectionName     string    `json:"connection_name"`
	SourceType         string    `json:"source_type"`
	TrustStatus        string    `json:"trust_status"`
	State              string    `json:"state"`
	CreatedAt          time.Time `json:"created_at"`
}

type sourceConnectionDraftListResponse struct {
	Drafts []sourceConnectionDraftResponse `json:"drafts"`
}

// listSourceConnectionDrafts serves GET
// /api/v1/workspaces/{workspace_id}/source-drafts (card D-1). It composes the
// same optional SourceConnectionDrafts capability the discard route does and
// fails closed as SERVICE_UNAVAILABLE when composition did not mount it. A
// non-member, unknown or foreign workspace is the repository's single
// content-free NOT_FOUND.
func (handler *Handler) listSourceConnectionDrafts(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	provider, ok := handler.sources.(SourceConnectionDrafts)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	drafts, err := provider.ListSourceConnectionDrafts(request.Context(), access, workspaceID)
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	items := make([]sourceConnectionDraftResponse, len(drafts))
	for index, draft := range drafts {
		items[index] = sourceConnectionDraftResponse{
			ConnectionID: draft.ConnectionID, ConnectionRevision: draft.ConnectionRevision,
			ConnectionName: draft.ConnectionName, SourceType: draft.SourceType,
			TrustStatus: draft.TrustStatus, State: draft.State, CreatedAt: draft.CreatedAt,
		}
	}
	writeJSON(writer, http.StatusOK, sourceConnectionDraftListResponse{Drafts: items})
}

// discardSourceConnectionDraft serves DELETE
// /api/v1/workspaces/{workspace_id}/source-drafts/{connection_id} (card D-1).
// It deletes only the workspace's pointer to an unfinished connection: the
// immutable connection lineage, trust material and any registered scope stay
// untouched. The request shape is the same idempotency-key-only envelope the
// other body-less source actions use.
func (handler *Handler) discardSourceConnectionDraft(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	provider, ok := handler.sources.(SourceConnectionDrafts)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if err := provider.DiscardSourceConnectionDraft(request.Context(), access, workspaceID, connectionID); err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"connection_id": connectionID, "discarded": true})
}

func confirmationContextResponseFrom(context workspacerepository.ConfirmationContext) confirmationContextResponse {
	response := confirmationContextResponse{
		ExpectedPolicyRevision: context.ExpectedPolicyRevision,
		WarningContract: warningContractResponse{
			WarningVersion: context.WarningVersion, WarningContractHash: context.WarningContractHash,
		},
		ViewerPrincipalID:         context.ViewerPrincipalID,
		CanIssueConfirmationGrant: context.CanIssueConfirmationGrant,
		CanVerifyConnectionTrust:  context.CanVerifyConnectionTrust,
	}
	if context.SelfGrant != nil {
		response.SelfGrant = &selfConfirmationGrantResponse{
			GrantID: context.SelfGrant.GrantID, GrantRevision: context.SelfGrant.GrantRevision,
			GrantHash: context.SelfGrant.GrantHash, ValidUntil: context.SelfGrant.ValidUntil,
		}
	}
	return response
}

// sourceConnectors serves the read-only onboarding catalog
// (GET /api/v1/source-connectors). The catalog is versioned, content-free and
// owned by source/registration; this handler only projects the injected
// service onto the registration surface, which performs the source-management
// OWNER authorization. It carries no credentials and never reflects a
// configured source. A denial follows the existing source read policy -- one
// content-free NOT_FOUND, never a leak -- and a production service that does
// not expose the catalog capability is not composed for the route and fails
// closed as SERVICE_UNAVAILABLE, matching every other capability-gated surface.
func (handler *Handler) sourceConnectors(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string) {
	provider, ok := handler.sources.(SourceConnectorCatalog)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	catalog, err := provider.ConnectorCatalog(request.Context(), access)
	if err != nil {
		handleSourceServiceError(writer, err, requestID, false)
		return
	}
	writeJSON(writer, http.StatusOK, catalog)
}

func (handler *Handler) addSource(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body sourceBindBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() || *body.ExpectedWorkspaceRevision < 1 {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields())
		return
	}
	snapshot, err := handler.service.AddSource(request.Context(), access, workspacerepository.AddSourceRequest{
		IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedWorkspaceRevision: *body.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: expectedHash, SourceScopeID: *body.SourceScopeID,
		SourceScopeRevision: *body.SourceScopeRevision, ScopeConfigHash: *body.ScopeConfigHash,
		AccessMode: workspacerepository.SourceAccessMode(*body.AccessMode),
	})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

// removeSource disables a binding while retaining its immutable lineage. The
// exact tuple is repeated in the request so a stale client cannot accidentally
// revoke a newly-created projection; the repository performs the final
// workspace/RBAC/confirmation checks inside one transaction.
func (handler *Handler) removeSource(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, sourceScopeID string) {
	key, expectedHash, code, fields := conditionalMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body sourceRemoveBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() || *body.SourceScopeID != sourceScopeID || *body.ExpectedWorkspaceRevision < 1 {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", body.missingFields(sourceScopeID))
		return
	}
	snapshot, err := handler.service.RemoveSource(request.Context(), access, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedWorkspaceRevision: *body.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: expectedHash, WorkspaceSourceID: *body.WorkspaceSourceID,
		SourceScopeID: *body.SourceScopeID, SourceScopeRevision: *body.SourceScopeRevision,
		ScopeConfigHash: *body.ScopeConfigHash, AccessMode: workspacerepository.SourceAccessMode(*body.AccessMode),
	})
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	handler.writeSnapshot(writer, access, snapshot, requestID)
}

// evidenceProjection is the single public projection for an authorized
// Evidence fragment. Both REST and MCP call it only after EvidenceService.Read
// has completed, so the same access context governs the optional structured
// rowset as the fragment text. An empty scope is deliberate: it is the
// existing matched-row default and MCP has no separate scope argument.
func (handler *Handler) evidenceProjection(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, scope string, fragment evidence.Fragment) map[string]any {
	response := map[string]any{
		"fragment_id":        fragment.FragmentID,
		"text":               string(fragment.Text),
		"anchor":             base64.StdEncoding.EncodeToString(fragment.Anchor),
		"address":            mcpEvidenceAddress(fragment),
		"is_current_version": fragment.IsCurrentVersion,
		"provenance": map[string]any{
			"extraction_id":        fragment.ExtractionID,
			"source_version_id":    fragment.SourceVersionID,
			"ordinal":              fragment.Ordinal,
			"external_version_key": fragment.ExternalVersionKey,
			"content_hash":         fragment.ContentHash,
			"observed_at":          fragment.ObservedAt.UTC().Format(time.RFC3339),
			"source_object_id":     fragment.SourceObjectID,
			"connection_id":        fragment.ConnectionID,
		},
	}
	if canonical, err := handler.canonicalEvidenceAddress(fragment); err == nil {
		response["canonical_address"] = canonical.String()
		if pageURL := handler.evidenceSourcePageURL(workspaceID, fragment.FragmentID, canonical.String()); pageURL != "" {
			response["source_page_url"] = pageURL
		}
	}
	// The viewer has already authorized and decrypted this source identity
	// together with the fragment. Never infer it from index metadata or text.
	if fragment.SourcePath != "" {
		response["source_path"] = fragment.SourcePath
	}
	// A structured-source fragment additionally carries its current,
	// re-authorized rowset. Rowset failures remain fail-safe and preserve the
	// fragment projection, matching the existing REST behavior for unavailable
	// structured evidence and for document fragments.
	if handler.questions != nil {
		if rowset, rowsetErr := handler.questions.StructuredRowset(ctx, access, workspaceID, fragmentID, scope); rowsetErr == nil && rowset != nil {
			response["rowset"] = rowset
		}
	}
	return response
}

// evidenceGet returns one Evidence fragment through the fail-closed viewer
// gate (ADR-0073 §1.2). Every viewer outcome — denied, missing, cross-tenant
// or failing — is one identical 404 so the route exposes no existence oracle.
// The response carries the decrypted normalized text, the canonical anchor
// and only non-content provenance metadata; source content beyond the allowed
// fragment is never fetched here.
func (handler *Handler) evidenceGet(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, fragmentID string) {
	// FIX-7 #1: scope is closed to {"", "matched", "full"} -- "" and
	// "matched" both mean the default (only the rows that gave the answer),
	// "full" is the explicit escape hatch to the whole source snapshot. Any
	// other value is a named validation failure, not a silent fallback.
	scope := strings.TrimSpace(request.URL.Query().Get("scope"))
	if scope != "" && scope != question.RowsetScopeMatched && scope != question.RowsetScopeFull {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"scope"})
		return
	}
	var selector *address.Address
	if raw := request.URL.Query().Get("address"); raw != "" {
		parsed, parseErr := address.Parse(raw)
		if parseErr != nil || parsed.Object != fragmentID {
			writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
			return
		}
		selector = &parsed
	}
	fragment, err := handler.readEvidencePageSelection(request.Context(), access, workspaceID, fragmentID, selector)
	if err != nil {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	response := handler.evidenceProjection(request.Context(), access, workspaceID, fragmentID, scope, fragment)
	writeJSON(writer, http.StatusOK, response)
}

func (handler *Handler) questionCreate(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	if handler.questions == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body questionCreateBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	mode := handler.defaultQuestionMode(workspaceID)
	if body.AnswerMode != nil {
		mode = *body.AnswerMode
	}
	modelProfileID := ""
	if len(body.ModelProfileID) > 0 {
		if jsonv2.Unmarshal(body.ModelProfileID, &modelProfileID) != nil || !question.ValidModelProfileID(modelProfileID) || body.AnswerMode != nil && mode != question.AnswerModeToolLoop {
			writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"model_profile_id"})
			return
		}
		mode = question.AnswerModeToolLoop
	}
	// Reject any mode outside the closed {EXTRACTIVE, GENERATIVE} vocabulary at
	// the transport boundary before invoking an injected service, so a stale or
	// alternate implementation cannot silently widen the public API beyond the
	// OpenAPI contract. Whether GENERATIVE is actually available is decided
	// solely by question.Service (GEN-1, ADR-0088), not here.
	if body.Question == nil || strings.TrimSpace(*body.Question) == "" ||
		(mode != questionModeExtractive && mode != questionModeGenerative && mode != question.AnswerModeToolLoop) {
		var invalidFields []string
		if body.Question == nil || strings.TrimSpace(*body.Question) == "" {
			invalidFields = append(invalidFields, "question")
		}
		if mode != questionModeExtractive && mode != questionModeGenerative && mode != question.AnswerModeToolLoop {
			invalidFields = append(invalidFields, "answer_mode")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", invalidFields)
		return
	}
	createContext := request.Context()
	var stream *questionEventStream
	var streamWriteFailed atomic.Bool
	if acceptsQuestionEventStream(request.Header.Get("Accept")) {
		var cancel context.CancelFunc
		createContext, cancel = context.WithCancel(createContext)
		defer cancel()
		stream = newQuestionEventStream(writer)
		createContext = question.WithActionObserver(createContext, func(event question.ActionEvent) {
			if err := stream.action(event); err != nil {
				streamWriteFailed.Store(true)
				cancel()
			}
		})
	}
	run, err := handler.questions.Create(createContext, access, question.CreateRequest{
		WorkspaceID: workspaceID, ConversationID: valueOrEmpty(body.ConversationID), Question: *body.Question, AnswerMode: mode, ModelProfileID: modelProfileID, IdempotencyKey: key,
	})
	if stream != nil {
		if streamWriteFailed.Load() || createContext.Err() != nil {
			return
		}
		if err != nil {
			_ = stream.failure(requestID)
			return
		}
		_ = stream.result(run)
		return
	}
	if err != nil {
		handleQuestionError(writer, err, requestID, true)
		return
	}
	writeJSON(writer, http.StatusOK, run)
}

func acceptsQuestionEventStream(accept string) bool {
	for _, offered := range strings.Split(accept, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(offered))
		if err != nil || mediaType != questionStreamContentType {
			continue
		}
		if quality, hasQuality := params["q"]; hasQuality {
			value, err := strconv.ParseFloat(quality, 64)
			if err != nil || !(value > 0 && value <= 1) {
				continue
			}
		}
		return true
	}
	return false
}

func (handler *Handler) questionGet(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, runID string) {
	if handler.questions == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	run, err := handler.questions.Get(request.Context(), access, workspaceID, runID)
	if err != nil {
		handleQuestionError(writer, err, requestID, false)
		return
	}
	writeJSON(writer, http.StatusOK, run)
}

// questionFeedbackBody is the closed submit/change body: verdict is
// mandatory, comment is mandatory only when verdict is INCORRECT and ignored
// (cleared) otherwise. The comment is never echoed back.
type questionFeedbackBody struct {
	Verdict *string `json:"verdict"`
	Comment *string `json:"comment"`
}

// questionFeedbackResponse is the caller's own current mark, or Marked=false
// when none exists yet.
type questionFeedbackResponse struct {
	Marked     bool   `json:"marked"`
	Verdict    string `json:"verdict,omitempty"`
	HasComment bool   `json:"has_comment,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

func feedbackResponseFrom(feedback question.Feedback) questionFeedbackResponse {
	return questionFeedbackResponse{Marked: true, Verdict: string(feedback.Verdict), HasComment: feedback.HasComment,
		UpdatedAt: feedback.UpdatedAt.Format(time.RFC3339)}
}

func (handler *Handler) questionFeedbackCapability() (QuestionFeedbackService, bool) {
	capability, ok := handler.questions.(QuestionFeedbackService)
	return capability, ok
}

func (handler *Handler) questionFeedbackGet(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, runID string) {
	capability, ok := handler.questionFeedbackCapability()
	if !ok {
		setServerFailureCause(writer, "question service capability missing", "QuestionFeedbackService")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	feedback, found, err := capability.OwnFeedback(request.Context(), access, workspaceID, runID)
	if err != nil {
		handleQuestionError(writer, err, requestID, false)
		return
	}
	if !found {
		writeJSON(writer, http.StatusOK, questionFeedbackResponse{Marked: false})
		return
	}
	writeJSON(writer, http.StatusOK, feedbackResponseFrom(feedback))
}

func (handler *Handler) questionFeedbackSubmit(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, runID string) {
	capability, ok := handler.questionFeedbackCapability()
	if !ok {
		setServerFailureCause(writer, "question service capability missing", "QuestionFeedbackService")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	var body questionFeedbackBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.Verdict == nil || (*body.Verdict != string(question.FeedbackCorrect) && *body.Verdict != string(question.FeedbackIncorrect)) {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"verdict"})
		return
	}
	comment := ""
	if body.Comment != nil {
		comment = *body.Comment
	}
	feedback, err := capability.SubmitFeedback(request.Context(), access, workspaceID, runID, question.FeedbackVerdict(*body.Verdict), comment)
	if err != nil {
		if question.CodeOf(err) == question.CodeInvalid {
			writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"comment"})
			return
		}
		handleQuestionError(writer, err, requestID, false)
		return
	}
	writeJSON(writer, http.StatusOK, feedbackResponseFrom(feedback))
}

// questionFeedbackReportEntryResponse is one row of the OWNER/MANAGER
// error-review report: the exact question/answer/comment text the mark
// refers to, decrypted only for this authorized read.
type questionFeedbackReportEntryResponse struct {
	QuestionRunID     string `json:"question_run_id"`
	Question          string `json:"question"`
	Answer            string `json:"answer"`
	Verdict           string `json:"verdict"`
	Comment           string `json:"comment,omitempty"`
	AuthorPrincipalID string `json:"author_principal_id"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type questionFeedbackReportResponse struct {
	WorkspaceID string                                `json:"workspace_id"`
	Entries     []questionFeedbackReportEntryResponse `json:"entries"`
}

func (handler *Handler) questionFeedbackReport(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	capability, ok := handler.questionFeedbackCapability()
	if !ok {
		setServerFailureCause(writer, "question service capability missing", "QuestionFeedbackService")
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	entries, err := capability.FeedbackReport(request.Context(), access, workspaceID)
	if err != nil {
		handleQuestionError(writer, err, requestID, false)
		return
	}
	response := questionFeedbackReportResponse{WorkspaceID: workspaceID, Entries: make([]questionFeedbackReportEntryResponse, 0, len(entries))}
	for _, entry := range entries {
		response.Entries = append(response.Entries, questionFeedbackReportEntryResponse{
			QuestionRunID: entry.QuestionRunID, Question: entry.Question, Answer: entry.Answer,
			Verdict: string(entry.Verdict), Comment: entry.Comment, AuthorPrincipalID: entry.AuthorPrincipalID,
			CreatedAt: entry.CreatedAt.Format(time.RFC3339), UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *Handler) conversationList(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string, paginated bool, limit int, cursor string) {
	if handler.conversations == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	var views []conversation.View
	nextCursor := ""
	if !paginated {
		// No query: the legacy first screen keeps calling List byte-for-byte.
		var err error
		views, err = handler.conversations.List(request.Context(), access, workspaceID)
		if err != nil {
			handleConversationError(writer, err, requestID)
			return
		}
	} else {
		// A limit/cursor request needs the narrow server-side keyset capability.
		// A service without it was not composed for real pagination, so the
		// request fails closed as a content-free SERVICE_UNAVAILABLE instead of
		// slicing the already-capped legacy List (an in-memory "page" that can
		// never reach row 101) or bypassing the workspace policy gate.
		pager, ok := handler.conversations.(ConversationPageService)
		if !ok {
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
			return
		}
		page, err := pager.ListPage(request.Context(), access, workspaceID, limit, cursor)
		if err != nil {
			handleConversationError(writer, err, requestID)
			return
		}
		views = page.Conversations
		nextCursor = page.NextCursor
	}
	// FIX-5 #2: project every returned conversation's turns in ONE call to
	// question.Service.GetBatch instead of one Get() call per turn (see
	// projectConversations) -- the N+1 that made this endpoint's own latency
	// scale with how many turns the returned page happened to carry.
	items, projectionErr := handler.projectConversations(request, access, views)
	if projectionErr != nil {
		handleConversationProjectionError(writer, projectionErr, requestID)
		return
	}
	response := map[string]any{"conversations": items}
	if nextCursor != "" {
		response["next_cursor"] = nextCursor
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *Handler) conversationGet(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, conversationID string) {
	if handler.conversations == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	view, err := handler.conversations.Get(request.Context(), access, workspaceID, conversationID)
	if err != nil {
		handleConversationError(writer, err, requestID)
		return
	}
	item, err := handler.projectConversation(request, access, view)
	if err != nil {
		handleConversationProjectionError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (handler *Handler) conversationArchive(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, conversationID string) {
	if handler.conversations == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	key, _, code, fields := mutationHeaders(request, false)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	view, err := handler.conversations.Archive(request.Context(), access, conversation.ArchiveRequest{
		WorkspaceID: workspaceID, ConversationID: conversationID, IdempotencyKey: key,
	})
	if err != nil {
		handleConversationError(writer, err, requestID)
		return
	}
	item, err := handler.projectConversation(request, access, view)
	if err != nil {
		handleConversationProjectionError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

// projectConversation projects one conversation. It is a thin wrapper over
// projectConversations for the single-conversation REST/MCP routes (Get,
// Archive); GET conversations (List) uses projectConversations directly so
// every turn across the whole returned page resolves through one
// question.Service.GetBatch call instead of one per conversation.
func (handler *Handler) projectConversation(request *http.Request, access database.AccessContext, view conversation.View) (conversationResponse, error) {
	items, err := handler.projectConversations(request, access, []conversation.View{view})
	if err != nil {
		return conversationResponse{}, err
	}
	return items[0], nil
}

// projectConversations projects a whole page of conversations at once. FIX-5
// #2's fix for the N+1 this used to be: projectConversation previously called
// question.Service.Get once PER TURN, each its own transaction -- for GET
// conversations' up to maxConversations conversations with several turns
// each, that meant one new transaction (and, before, one new connection-pool
// acquisition) per turn just to render the list. This instead collects every
// distinct Question Run id across every conversation's turns -- List/Get/
// Archive all resolve exactly one workspace per call, so every view here
// shares the same WorkspaceID -- and resolves them all through ONE
// question.Service.GetBatch call.
//
// A turn whose run GetBatch did not return (not readable, raced revocation,
// purge) is dropped from the response exactly as the old per-turn Get() loop
// dropped it on a NotFound/Denied error -- same observable behaviour, fewer
// round trips.
func (handler *Handler) projectConversations(request *http.Request, access database.AccessContext, views []conversation.View) ([]conversationResponse, error) {
	results := make([]conversationResponse, len(views))
	if len(views) == 0 {
		return results, nil
	}
	for index, view := range views {
		results[index] = conversationResponse{
			ConversationID: view.ID, WorkspaceID: view.WorkspaceID, WorkspaceRevision: view.WorkspaceRevision,
			CreatedBy: view.CreatedBy, CreatedAt: view.CreatedAt, ArchivedAt: view.ArchivedAt,
			Turns: make([]conversationTurnResponse, 0, len(view.Turns)),
		}
	}
	if handler.questions == nil {
		for index, view := range views {
			for _, turn := range view.Turns {
				results[index].Turns = append(results[index].Turns, conversationTurnResponse{
					TurnID: turn.ID, QuestionRunID: turn.QuestionRunID, TurnIndex: turn.TurnIndex, CreatedAt: turn.CreatedAt,
				})
			}
		}
		return results, nil
	}
	var workspaceID string
	seenRunIDs := make(map[string]bool)
	runIDs := make([]string, 0)
	for _, view := range views {
		if workspaceID == "" {
			workspaceID = view.WorkspaceID
		}
		for _, turn := range view.Turns {
			if !seenRunIDs[turn.QuestionRunID] {
				seenRunIDs[turn.QuestionRunID] = true
				runIDs = append(runIDs, turn.QuestionRunID)
			}
		}
	}
	runsByID, err := handler.questions.GetBatch(request.Context(), access, workspaceID, runIDs)
	if err != nil {
		return nil, err
	}
	for index, view := range views {
		for _, turn := range view.Turns {
			run, ok := runsByID[turn.QuestionRunID]
			if !ok {
				// A raced revocation/purge removes the linked projection rather
				// than leaking a dangling plaintext turn.
				continue
			}
			results[index].Turns = append(results[index].Turns, conversationTurnResponse{
				TurnID: turn.ID, QuestionRunID: turn.QuestionRunID, TurnIndex: turn.TurnIndex, CreatedAt: turn.CreatedAt, QuestionRun: &run,
			})
		}
	}
	return results, nil
}

// auditJournal returns one workspace-scoped page of the audit stream. The
// authorization gate and the audit.viewed event live in the workspace
// repository; this handler only projects the returned journal. Absence and
// policy denial arrive as one identical typed error, so the route exposes no
// existence oracle, and the workspace id in the body is the server-resolved
// value from the repository rather than the path segment.
//
// beforeSequence is the strictly validated cursor for a continuation read. A
// nil cursor keeps the legacy AuditJournal path byte-for-byte. A non-nil
// cursor requires the narrow WorkspaceAuditJournalBefore capability: a
// service without it was not composed for continuation, so the request fails
// closed as a content-free SERVICE_UNAVAILABLE instead of falling back to the
// first page or reading without the policy gate.
func (handler *Handler) auditJournal(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string, beforeSequence *int64) {
	var journal audit.Journal
	var err error
	if beforeSequence == nil {
		journal, err = handler.service.AuditJournal(request.Context(), access, workspaceID)
	} else {
		pager, ok := handler.service.(WorkspaceAuditJournalBefore)
		if !ok {
			setServerFailureCause(writer, "workspace service capability missing", "WorkspaceAuditJournalBefore")
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
			return
		}
		journal, err = pager.AuditJournalBefore(request.Context(), access, workspaceID, *beforeSequence)
	}
	if err != nil {
		handleServiceError(writer, err, requestID, false)
		return
	}
	events := journal.Events
	if events == nil {
		// The repository initializes an empty page as an empty slice, so a nil
		// page cannot arise from the system; the handler still normalizes it
		// rather than serialize "events":null.
		events = []audit.JournalEntry{}
	}
	response := auditJournalResponse{
		WorkspaceID:  journal.WorkspaceID,
		HeadSequence: journal.HeadSequence,
		HeadHash:     journal.HeadHash,
		Events:       events,
		Truncated:    journal.Truncated,
	}
	// The cursor is projected as a decimal string, never a JSON number, so an
	// int64 sequence beyond 2^53 survives the round trip to a browser.
	if journal.NextBeforeSequence != nil {
		response.NextBeforeSequence = strconv.FormatInt(*journal.NextBeforeSequence, 10)
	}
	writeJSON(writer, http.StatusOK, response)
}

type auditJournalResponse struct {
	WorkspaceID  string               `json:"workspace_id"`
	HeadSequence int64                `json:"head_sequence"`
	HeadHash     string               `json:"head_hash"`
	Events       []audit.JournalEntry `json:"events"`
	Truncated    bool                 `json:"truncated"`
	// NextBeforeSequence is present only when the server proved a next page.
	// It is an opaque decimal string the client passes back unchanged.
	NextBeforeSequence string `json:"next_before_sequence,omitempty"`
}

type conversationResponse struct {
	ConversationID    string                     `json:"conversation_id"`
	WorkspaceID       string                     `json:"workspace_id"`
	WorkspaceRevision int64                      `json:"workspace_revision"`
	CreatedBy         string                     `json:"created_by"`
	CreatedAt         time.Time                  `json:"created_at"`
	ArchivedAt        *time.Time                 `json:"archived_at,omitempty"`
	Turns             []conversationTurnResponse `json:"turns"`
}

type conversationTurnResponse struct {
	TurnID        string        `json:"turn_id"`
	QuestionRunID string        `json:"question_run_id"`
	TurnIndex     int64         `json:"turn_index"`
	CreatedAt     time.Time     `json:"created_at"`
	QuestionRun   *question.Run `json:"question_run,omitempty"`
}

// sourceDiscoveryRegisterBody is the only caller-supplied content the
// discovered-view register route accepts. excluded_columns are ordinals from
// the sealed discovery result (ADR-0097); every other projection field stays
// server-owned. An empty or absent body registers the table unnarrowed. mode
// (S3 card 4) is INDEXED when absent and QUERY_ONLY for the "only for SQL
// queries, not indexed" registration; any other value is refused.
type sourceDiscoveryRegisterBody struct {
	ExcludedColumns []int  `json:"excluded_columns"`
	Mode            string `json:"mode"`
}

type sourceRegisterBody struct {
	SourceType          *string                 `json:"source_type"`
	Name                *string                 `json:"name"`
	RootAlias           *string                 `json:"root_alias"`
	RootIdentity        *string                 `json:"root_identity"`
	RelativeRoot        *string                 `json:"relative_root"`
	Kind                *string                 `json:"kind"`
	Recursive           *bool                   `json:"recursive"`
	IncludeGlobs        *[]string               `json:"include_globs"`
	ExcludeGlobs        *[]string               `json:"exclude_globs"`
	MaxFileBytes        *int64                  `json:"max_file_bytes"`
	OCRMode             *string                 `json:"ocr_mode"`
	Formats             *[]string               `json:"formats"`
	DatabaseIdentity    *string                 `json:"database_identity"`
	CredentialReference *string                 `json:"credential_reference"`
	LineageID           *string                 `json:"lineage_id"`
	ProjectionRevision  *int64                  `json:"projection_revision"`
	ContractHash        *string                 `json:"contract_hash"`
	SchemaName          *string                 `json:"schema_name"`
	RelationName        *string                 `json:"relation_name"`
	RelationKind        *string                 `json:"relation_kind"`
	Columns             *[]postgresqlColumnBody `json:"columns"`
	EmptySnapshotPolicy *string                 `json:"empty_snapshot_policy"`
	MaxRows             *int64                  `json:"max_rows"`
	MaxColumns          *int                    `json:"max_columns"`
	MaxFieldBytes       *int64                  `json:"max_field_bytes"`
	MaxRowBytes         *int64                  `json:"max_row_bytes"`
	MaxTotalBytes       *int64                  `json:"max_total_bytes"`
	StatementTimeoutMS  *int                    `json:"statement_timeout_ms"`
	// SyncIntervalSeconds is the operator-chosen POSTGRESQL_QUERY schedule
	// (V1-A). Omitted keeps the existing fixed default.
	SyncIntervalSeconds *int `json:"sync_interval_seconds"`
	// Git/IMAP registration fields. Secrets are never accepted; only the
	// opaque credential reference is projected to the registration service.
	Provider             *string   `json:"provider"`
	Endpoint             *string   `json:"endpoint"`
	WebBaseURL           *string   `json:"web_base_url"`
	RepositoryID         *string   `json:"repository_id"`
	BranchName           *string   `json:"branch_name"`
	TextMediaTypes       *[]string `json:"text_media_types"`
	MaxBlobBytes         *int64    `json:"max_blob_bytes"`
	Mailbox              *string   `json:"mailbox"`
	Folder               *string   `json:"folder"`
	Username             *string   `json:"username"`
	Since                *string   `json:"since"`
	IncludeAttachments   *bool     `json:"include_attachments"`
	MaxMessageBytes      *int64    `json:"max_message_bytes"`
	MaxAttachmentBytes   *int64    `json:"max_attachment_bytes"`
	AttachmentMediaTypes *[]string `json:"attachment_media_types"`
}

type postgreSQLConnectionBootstrapBody struct {
	Name                *string `json:"name"`
	DatabaseIdentity    *string `json:"database_identity"`
	LineageID           *string `json:"lineage_id"`
	CredentialReference *string `json:"credential_reference"`
	// WorkspaceID is optional card D-1 context: when present the unfinished
	// connection is registered as that workspace's draft and appears in its
	// Sources surface. The connection lineage itself stays organization-scoped.
	WorkspaceID *string `json:"workspace_id"`
}

func (body postgreSQLConnectionBootstrapBody) complete() bool {
	return body.Name != nil && body.DatabaseIdentity != nil && body.LineageID != nil
}

func (body postgreSQLConnectionBootstrapBody) missingFields() []string {
	return missingFieldNames([]fieldPresence{
		{body.Name != nil, "name"}, {body.DatabaseIdentity != nil, "database_identity"},
		{body.LineageID != nil, "lineage_id"},
	})
}

type sourceBindBody struct {
	ExpectedWorkspaceRevision *int64  `json:"expected_workspace_revision"`
	SourceScopeID             *string `json:"source_scope_id"`
	SourceScopeRevision       *int64  `json:"source_scope_revision"`
	ScopeConfigHash           *string `json:"scope_config_hash"`
	AccessMode                *string `json:"access_mode"`
}

type sourceRemoveBody struct {
	ExpectedWorkspaceRevision *int64  `json:"expected_workspace_revision"`
	WorkspaceSourceID         *string `json:"workspace_source_id"`
	SourceScopeID             *string `json:"source_scope_id"`
	SourceScopeRevision       *int64  `json:"source_scope_revision"`
	ScopeConfigHash           *string `json:"scope_config_hash"`
	AccessMode                *string `json:"access_mode"`
}

func (body sourceRemoveBody) complete() bool {
	return body.ExpectedWorkspaceRevision != nil && body.WorkspaceSourceID != nil && body.SourceScopeID != nil &&
		body.SourceScopeRevision != nil && body.ScopeConfigHash != nil && body.AccessMode != nil
}

func (body sourceRemoveBody) missingFields(pathSourceScopeID string) []string {
	return missingFieldNames([]fieldPresence{
		{body.ExpectedWorkspaceRevision != nil && *body.ExpectedWorkspaceRevision >= 1, "expected_workspace_revision"},
		{body.WorkspaceSourceID != nil, "workspace_source_id"},
		{body.SourceScopeID != nil && *body.SourceScopeID == pathSourceScopeID, "source_scope_id"},
		{body.SourceScopeRevision != nil, "source_scope_revision"}, {body.ScopeConfigHash != nil, "scope_config_hash"},
		{body.AccessMode != nil, "access_mode"},
	})
}

func (body sourceBindBody) complete() bool {
	return body.ExpectedWorkspaceRevision != nil && body.SourceScopeID != nil && body.SourceScopeRevision != nil &&
		body.ScopeConfigHash != nil && body.AccessMode != nil
}

func (body sourceBindBody) missingFields() []string {
	return missingFieldNames([]fieldPresence{
		{body.ExpectedWorkspaceRevision != nil && *body.ExpectedWorkspaceRevision >= 1, "expected_workspace_revision"},
		{body.SourceScopeID != nil, "source_scope_id"}, {body.SourceScopeRevision != nil, "source_scope_revision"},
		{body.ScopeConfigHash != nil, "scope_config_hash"}, {body.AccessMode != nil, "access_mode"},
	})
}

type questionCreateBody struct {
	Question       *string        `json:"question"`
	AnswerMode     *string        `json:"answer_mode"`
	ConversationID *string        `json:"conversation_id"`
	ModelProfileID jsontext.Value `json:"model_profile_id"`
}

func (body sourceRegisterBody) complete() bool {
	return body.Name != nil && body.RootAlias != nil && body.RootIdentity != nil && body.RelativeRoot != nil &&
		body.Kind != nil && body.Recursive != nil && body.IncludeGlobs != nil && body.ExcludeGlobs != nil &&
		body.MaxFileBytes != nil && body.OCRMode != nil && body.Formats != nil
}

// missingFOLDERFields is FIX-7 #2's companion to complete() (the FOLDER
// branch): the exact JSON field names found absent, never their values.
func (body sourceRegisterBody) missingFOLDERFields() []string {
	return missingFieldNames([]fieldPresence{
		{body.Name != nil, "name"}, {body.RootAlias != nil, "root_alias"}, {body.RootIdentity != nil, "root_identity"},
		{body.RelativeRoot != nil, "relative_root"}, {body.Kind != nil, "kind"}, {body.Recursive != nil, "recursive"},
		{body.IncludeGlobs != nil, "include_globs"}, {body.ExcludeGlobs != nil, "exclude_globs"},
		{body.MaxFileBytes != nil, "max_file_bytes"}, {body.OCRMode != nil, "ocr_mode"}, {body.Formats != nil, "formats"},
	})
}

func (body sourceRegisterBody) postgreSQLComplete() bool {
	return body.SourceType != nil && *body.SourceType == "POSTGRESQL_QUERY" && body.Name != nil && body.Kind != nil &&
		body.DatabaseIdentity != nil && body.LineageID != nil && body.ProjectionRevision != nil && body.ContractHash != nil &&
		body.SchemaName != nil && body.RelationName != nil && body.RelationKind != nil && body.Columns != nil &&
		body.EmptySnapshotPolicy != nil
}

func (body sourceRegisterBody) missingPostgreSQLFields() []string {
	return missingFieldNames([]fieldPresence{
		{body.SourceType != nil && *body.SourceType == "POSTGRESQL_QUERY", "source_type"},
		{body.Name != nil, "name"}, {body.Kind != nil, "kind"}, {body.DatabaseIdentity != nil, "database_identity"},
		{body.LineageID != nil, "lineage_id"}, {body.ProjectionRevision != nil, "projection_revision"},
		{body.ContractHash != nil, "contract_hash"}, {body.SchemaName != nil, "schema_name"},
		{body.RelationName != nil, "relation_name"}, {body.RelationKind != nil, "relation_kind"},
		{body.Columns != nil, "columns"}, {body.EmptySnapshotPolicy != nil, "empty_snapshot_policy"},
	})
}

func (body sourceRegisterBody) remoteComplete(sourceType string) bool {
	if body.SourceType == nil || *body.SourceType != sourceType || body.Name == nil || body.Kind == nil || body.Endpoint == nil {
		return false
	}
	switch sourceType {
	case "GIT":
		return body.Provider != nil && body.RepositoryID != nil && body.BranchName != nil &&
			body.IncludeGlobs != nil && body.ExcludeGlobs != nil && body.TextMediaTypes != nil && body.MaxBlobBytes != nil
	case "MAIL":
		return body.Mailbox != nil && body.Folder != nil && body.Username != nil && body.IncludeAttachments != nil
	default:
		return false
	}
}

func (body sourceRegisterBody) missingRemoteFields(sourceType string) []string {
	base := []fieldPresence{
		{body.SourceType != nil && *body.SourceType == sourceType, "source_type"},
		{body.Name != nil, "name"}, {body.Kind != nil, "kind"}, {body.Endpoint != nil, "endpoint"},
	}
	switch sourceType {
	case "GIT":
		base = append(base,
			fieldPresence{body.Provider != nil, "provider"}, fieldPresence{body.RepositoryID != nil, "repository_id"},
			fieldPresence{body.BranchName != nil, "branch_name"}, fieldPresence{body.IncludeGlobs != nil, "include_globs"},
			fieldPresence{body.ExcludeGlobs != nil, "exclude_globs"}, fieldPresence{body.TextMediaTypes != nil, "text_media_types"},
			fieldPresence{body.MaxBlobBytes != nil, "max_blob_bytes"},
		)
	case "MAIL":
		base = append(base,
			fieldPresence{body.Mailbox != nil, "mailbox"}, fieldPresence{body.Folder != nil, "folder"},
			fieldPresence{body.Username != nil, "username"}, fieldPresence{body.IncludeAttachments != nil, "include_attachments"},
		)
	}
	return missingFieldNames(base)
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func valueOrSlice(value *[]string) []string {
	if value == nil {
		return nil
	}
	return append([]string(nil), (*value)...)
}

func valueOrInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

func valueOrBool(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

type postgresqlColumnBody struct {
	Ordinal         int                         `json:"ordinal"`
	Name            string                      `json:"name"`
	TypeFingerprint string                      `json:"type_fingerprint"`
	LogicalType     postgresqlquery.LogicalType `json:"logical_type"`
	Roles           []postgresqlquery.Role      `json:"roles"`
	Nullable        bool                        `json:"nullable"`
	Precision       int                         `json:"precision"`
	Scale           int                         `json:"scale"`
	MaxBytes        int                         `json:"max_bytes"`
}

func (body sourceRegisterBody) postgreSQLColumns() []postgresqlquery.Column {
	if body.Columns == nil {
		return nil
	}
	columns := make([]postgresqlquery.Column, len(*body.Columns))
	for index, column := range *body.Columns {
		columns[index] = postgresqlquery.Column{
			Ordinal: column.Ordinal, Name: column.Name, TypeFingerprint: column.TypeFingerprint,
			LogicalType: column.LogicalType, Roles: append([]postgresqlquery.Role(nil), column.Roles...),
			Nullable: column.Nullable, Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes,
		}
	}
	return columns
}

type sourceRegisterResponse struct {
	ConnectionID        string `json:"connection_id"`
	CredentialReference string `json:"credential_reference,omitempty"`
	SourceScopeID       string `json:"source_scope_id"`
	DiscoveredScopeID   string `json:"discovered_scope_id"`
	Revision            int64  `json:"revision"`
	ScopeConfigHash     string `json:"scope_config_hash"`
	AccessMode          string `json:"access_mode"`
	Created             bool   `json:"created"`
}

type postgreSQLConnectionBootstrapResponse struct {
	ConnectionID        string `json:"connection_id"`
	ConnectionRevision  int64  `json:"connection_revision"`
	CredentialReference string `json:"credential_reference"`
	Created             bool   `json:"created"`
}

type sourceDiscoveryResponse struct {
	RequestID                    string                        `json:"request_id"`
	RequestStatus                string                        `json:"request_status"`
	ResultID                     string                        `json:"result_id,omitempty"`
	ResultStatus                 string                        `json:"result_status,omitempty"`
	ViewCount                    int                           `json:"view_count"`
	PreparedViewCount            int                           `json:"prepared_view_count"`
	NeedsInterpretationViewCount int                           `json:"needs_interpretation_view_count"`
	FailureCode                  string                        `json:"failure_code,omitempty"`
	ExpiresAt                    time.Time                     `json:"expires_at"`
	Views                        []sourceDiscoveryViewResponse `json:"views"`
}

type sourceDiscoveryViewResponse struct {
	Selector     string `json:"view_id"`
	SchemaName   string `json:"schema_name"`
	RelationName string `json:"relation_name"`
	RelationKind string `json:"relation_kind"`
	Comment      string `json:"comment,omitempty"`
	// ApproxRowCount is pg_class.reltuples, rounded; -1 means PostgreSQL has
	// not analyzed the relation yet. It is display metadata, never a security
	// or capacity decision (ADR-0097).
	ApproxRowCount int64                                `json:"approx_row_count"`
	Status         postgresqlquery.DiscoveryStatus      `json:"status"`
	Interpretation postgresqlquery.InterpretationReason `json:"interpretation,omitempty"`
	Columns        []sourceDiscoveryColumnResponse      `json:"columns"`
	// ExcludedColumns are observed base-table columns the server could not
	// project (D-1). They are display-only metadata with a reason; they are
	// never part of the registration projection and never appear in reads,
	// search, the schema tool or SQL results.
	ExcludedColumns []sourceDiscoveryExcludedColumnResponse `json:"excluded_columns,omitempty"`
}

// sourceDiscoveryExcludedColumnResponse is the browser-safe projection of one
// auto-excluded column: identity and the bounded reason, never a type
// fingerprint, value or comment.
type sourceDiscoveryExcludedColumnResponse struct {
	Ordinal     int                                  `json:"ordinal"`
	Name        string                               `json:"name"`
	TypeName    string                               `json:"type_name"`
	LogicalType postgresqlquery.LogicalType          `json:"logical_type,omitempty"`
	PrimaryKey  bool                                 `json:"primary_key,omitempty"`
	Reason      postgresqlquery.InterpretationReason `json:"reason"`
}

func sourceDiscoveryExcludedColumnResponses(columns []postgresqlquery.ExcludedColumn) []sourceDiscoveryExcludedColumnResponse {
	if len(columns) == 0 {
		return nil
	}
	result := make([]sourceDiscoveryExcludedColumnResponse, len(columns))
	for index, column := range columns {
		result[index] = sourceDiscoveryExcludedColumnResponse{
			Ordinal: column.Ordinal, Name: column.Name, TypeName: column.TypeName,
			LogicalType: column.LogicalType, PrimaryKey: column.PrimaryKey, Reason: column.Reason,
		}
	}
	return result
}

type sourceDiscoveryColumnResponse struct {
	Ordinal     int                         `json:"ordinal"`
	Name        string                      `json:"name"`
	TypeName    string                      `json:"type_name"`
	LogicalType postgresqlquery.LogicalType `json:"logical_type"`
	Nullable    bool                        `json:"nullable"`
	Precision   int                         `json:"precision,omitempty"`
	Scale       int                         `json:"scale,omitempty"`
	MaxBytes    int                         `json:"max_bytes,omitempty"`
	Comment     string                      `json:"comment,omitempty"`
	Roles       []postgresqlquery.Role      `json:"roles"`
	// PrimaryKey is native primary-key membership (ADR-0097). It is always
	// false for a VIEW/MATERIALIZED_VIEW column.
	PrimaryKey bool `json:"primary_key"`
}

type sourceStatusResponse struct {
	WorkspaceSourceID          string     `json:"workspace_source_id"`
	SourceScopeID              string     `json:"source_scope_id"`
	SourceScopeRevision        int64      `json:"source_scope_revision"`
	AccessMode                 string     `json:"access_mode"`
	Enabled                    bool       `json:"enabled"`
	ScopeConfigHash            string     `json:"scope_config_hash"`
	ConnectionID               string     `json:"connection_id"`
	ConnectionName             string     `json:"connection_name"`
	SourceType                 string     `json:"source_type"`
	PostgreSQLSchemaName       *string    `json:"postgresql_schema_name"`
	PostgreSQLRelationName     *string    `json:"postgresql_relation_name"`
	ActivationStatus           string     `json:"activation_status"`
	TrustVerified              bool       `json:"trust_verified"`
	SyncStatus                 *string    `json:"sync_status"`
	SyncErrorCode              *string    `json:"sync_error_code"`
	SyncStartedAt              *time.Time `json:"sync_started_at"`
	SyncCompletedAt            *time.Time `json:"sync_completed_at"`
	ObjectsSeen                *int64     `json:"objects_seen"`
	ObjectsIngested            *int64     `json:"objects_ingested"`
	VersionsCreated            *int64     `json:"versions_created"`
	EvidencePublished          *int64     `json:"evidence_published"`
	Quarantined                *int64     `json:"quarantined"`
	JobID                      *string    `json:"job_id"`
	JobStatus                  *string    `json:"job_status"`
	JobAttemptCount            *int64     `json:"job_attempt_count"`
	JobMaxAttempts             *int64     `json:"job_max_attempts"`
	JobAvailableAt             *time.Time `json:"job_available_at"`
	JobLeaseExpiresAt          *time.Time `json:"job_lease_expires_at"`
	JobLastErrorCode           *string    `json:"job_last_error_code"`
	ContentFreshnessSLASeconds int64      `json:"content_freshness_sla_seconds"`
	LastSuccessfulSyncAt       *time.Time `json:"last_successful_sync_at"`
	FreshnessState             string     `json:"freshness_state"`
	SyncIntervalSeconds        int64      `json:"sync_interval_seconds"`
	Confirmed                  bool       `json:"confirmed"`
	ConfirmationState          string     `json:"confirmation_state"`
	// CanVerifyConnectionTrust is this source's own, SoD-aware refinement of
	// confirmation_context.can_verify_connection_trust (review-opus-s2-6-7.md
	// remark): the workspace-wide context field reflects only the viewer's
	// CONNECTOR_ADMIN role, not whether ADR-0087 §2's verifier/confirmer
	// separation of duty would deny THIS source's own connection. This field
	// is false whenever the role-only context field is false, and also false
	// when the viewer has already confirmed a WORKSPACE_MANAGED binding of
	// some scope of this source's connection (workspacerepository.SourceStatus.
	// ViewerVerifyConflict) -- exactly the case app.source_connection_trust_
	// verify's own separation-of-duty check (migration 000059) would refuse.
	// The UI must gate the "Verify trust" action on this field, not on
	// the workspace-wide one, so the button is never shown to a viewer the
	// database would then deny.
	CanVerifyConnectionTrust bool `json:"can_verify_connection_trust"`
	// SQLAvailable reports ADR-0097's per-connection "SQL available" state:
	// the connection revision carries a separate query credential, so the
	// knowvault_source_sql tool can run for its enabled sources. A false value
	// means "SQL not configured" and the tool answers
	// SOURCE_SQL_NOT_CONFIGURED. It is a display fact, never an authorization.
	SQLAvailable bool `json:"sql_available"`
	// QueryOnly is S3 card 4's registration mode of the bound relation: true
	// means "only for SQL queries (not indexed)". The Sources card renders it
	// as "только SQL" and shows no sync freshness for the source.
	QueryOnly bool `json:"query_only"`
}

// confirmationStateFor derives the ADR-0087 operator-visible pending state of
// one managed source from facts the response already carries: whether a live
// confirmation grant exists for the caller (contextHasSelfGrant), whether the
// binding is already confirmed, trusted and enabled, and its activation
// status. It is a pure presentation label; it grants nothing and is never
// consulted by any command's own authorization.
//
// The confirmed check runs before the enabled check (review blocker B1): for
// a disabled binding, `confirmed` (workspacerepository.SourceStatus.Confirmed)
// is re-derived from the exact live-confirmation fact mutateSource's re-enable
// gate itself requires, so "DISABLED" means only "one click from re-enabling"
// and a binding a re-enable attempt would still fail-closed reject instead
// surfaces NEEDS_CONFIRMATION/NEEDS_GRANT -- the content-free signal that
// re-enable needs a fresh confirmation before "Enable" will succeed.
func confirmationStateFor(enabled, confirmed, trustVerified bool, activationStatus string, contextHasSelfGrant bool) string {
	switch {
	case !confirmed && contextHasSelfGrant:
		return "NEEDS_CONFIRMATION"
	case !confirmed:
		return "NEEDS_GRANT"
	case !enabled:
		return "DISABLED"
	case !trustVerified:
		return "NEEDS_TRUST_VERIFICATION"
	case activationStatus != "READY":
		return "READY_TO_ACTIVATE"
	default:
		return "ACTIVE"
	}
}

// warningContractResponse is the current, immutable-registry-head warning
// contract an operator must acknowledge to confirm a WORKSPACE_MANAGED
// binding: its version and content hash, never the risk text itself (that
// stays server-side canon; the hash is what the confirm command carries).
type warningContractResponse struct {
	WarningVersion      string `json:"warning_version"`
	WarningContractHash string `json:"warning_contract_hash"`
}

// selfConfirmationGrantResponse is the caller's own live, unrevoked, unexpired
// workspace.source.confirm grant, if any. Present, it lets the UI call
// ConfirmManagedSource directly; absent, the UI must issue a grant first (if
// eligible) or explain who can.
type selfConfirmationGrantResponse struct {
	GrantID       string `json:"grant_id"`
	GrantRevision int64  `json:"grant_revision"`
	GrantHash     string `json:"grant_hash"`
	ValidUntil    string `json:"valid_until"`
}

// confirmationContextResponse is the ADR-0087 §1-§2 read: everything an
// operator or agent needs to build a confirmation-grant,
// managed-source-confirmation or verify-trust command body without a
// database session, plus the caller's own eligibility so a denied action can
// be explained instead of only refused.
type confirmationContextResponse struct {
	ExpectedPolicyRevision    string                         `json:"expected_policy_revision"`
	WarningContract           warningContractResponse        `json:"warning_contract"`
	ViewerPrincipalID         string                         `json:"viewer_principal_id"`
	CanIssueConfirmationGrant bool                           `json:"can_issue_confirmation_grant"`
	CanVerifyConnectionTrust  bool                           `json:"can_verify_connection_trust"`
	SelfGrant                 *selfConfirmationGrantResponse `json:"self_grant"`
}

func handleSourceServiceError(writer http.ResponseWriter, err error, requestID string, isCreate bool) {
	code := registration.CodeOf(err)
	status, publicCode := sourceServiceErrorResponse(code, isCreate)
	if status >= http.StatusInternalServerError {
		setServerFailureCause(writer, "source service", string(code))
	}
	writeError(writer, status, publicCode, requestID)
}

func sourceServiceErrorResponse(code registration.ErrorCode, isCreate bool) (int, string) {
	switch code {
	case registration.CodeRequestInvalid:
		return http.StatusBadRequest, "REQUEST_INVALID"
	case registration.CodeDenied:
		if isCreate {
			return http.StatusForbidden, "FORBIDDEN"
		}
		return http.StatusNotFound, "NOT_FOUND"
	case registration.CodeNotFound:
		return http.StatusNotFound, "NOT_FOUND"
	case registration.CodeConflict:
		return http.StatusConflict, "SOURCE_CONFLICT"
	case registration.CodeUnavailable:
		return http.StatusServiceUnavailable, "SOURCE_UNAVAILABLE"
	case registration.CodeUploadRejected:
		return http.StatusBadRequest, "UPLOAD_REJECTED"
	default:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	}
}

type metadataBody struct {
	Name              *string `json:"name"`
	Description       *string `json:"description"`
	RetentionPolicyID *string `json:"retention_policy_id"`
}

func (body metadataBody) complete() bool {
	return body.Name != nil && body.Description != nil && body.RetentionPolicyID != nil
}

// missingFields is FIX-7 #2: the exact JSON field names complete() found
// absent, never their values.
func (body metadataBody) missingFields() []string {
	var fields []string
	if body.Name == nil {
		fields = append(fields, "name")
	}
	if body.Description == nil {
		fields = append(fields, "description")
	}
	if body.RetentionPolicyID == nil {
		fields = append(fields, "retention_policy_id")
	}
	return fields
}

type addMemberBody struct {
	PrincipalID *string         `json:"principal_id"`
	Role        *workspace.Role `json:"role"`
}

type memberRoleBody struct {
	Role *workspace.Role `json:"role"`
}

type transferOwnershipBody struct {
	NewOwnerPrincipalID *string `json:"new_owner_principal_id"`
}

// mutationHeaders validates the Idempotency-Key/If-Match transport headers
// every mutation route requires and returns FIX-7 #2's field names alongside
// any failure code (the exact header name(s) that failed, never their
// values) so the caller can pass them straight to writeValidationError.
func mutationHeaders(request *http.Request, requireMatch bool) (key, hash, code string, fields []string) {
	var ok bool
	key, ok = exactHeader(request.Header, "Idempotency-Key")
	if !ok || !validIdempotencyKey(key) {
		return "", "", "REQUEST_INVALID", []string{"Idempotency-Key"}
	}
	if !requireMatch {
		if headerPresent(request.Header, "If-Match") {
			return "", "", "REQUEST_INVALID", []string{"If-Match"}
		}
		return key, "", "", nil
	}
	if !headerPresent(request.Header, "If-Match") {
		return "", "", "PRECONDITION_REQUIRED", []string{"If-Match"}
	}
	match, exact := exactHeader(request.Header, "If-Match")
	if !exact {
		return "", "", "REQUEST_INVALID", []string{"If-Match"}
	}
	if len(match) != len("\"sha256:\"")+64 || !strings.HasPrefix(match, "\"sha256:") || !strings.HasSuffix(match, "\"") {
		return "", "", "REQUEST_INVALID", []string{"If-Match"}
	}
	hash = match[1 : len(match)-1]
	if !workspace.IsConfigurationHash(hash) {
		return "", "", "REQUEST_INVALID", []string{"If-Match"}
	}
	return key, hash, "", nil
}

func conditionalMutationHeaders(request *http.Request) (string, string, string, []string) {
	return mutationHeaders(request, true)
}

// decodeJSON validates the transport envelope and decodes destination.
// Its failures are shape-level (unsupported encoding/media type, oversized,
// unparseable or unknown-shaped body) rather than attributable to one named
// field, so FIX-7 #2's fields return is deliberately empty here -- a route's
// OWN required-field check after a successful decode is where a specific
// field name is known.
func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) string {
	return decodeJSONLimited(writer, request, destination, maxBodyBytes)
}

// decodeJSONLimited is decodeJSON with an explicit byte bound. Card S3.4b's two
// batch routes carry one bounded list (up to 1000 tables or 200 views) in one
// request, which legitimately exceeds the 32 KiB single-object limit every other
// route keeps; only those two routes raise their own bound, and an oversized
// body is refused as a whole before any field is decoded.
func decodeJSONLimited(writer http.ResponseWriter, request *http.Request, destination any, limit int64) string {
	if headerPresent(request.Header, "Content-Encoding") {
		return "REQUEST_INVALID"
	}
	if request.ContentLength > limit {
		return "PAYLOAD_TOO_LARGE"
	}
	contentType, ok := exactHeader(request.Header, "Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if !ok || err != nil || mediaType != jsonContentType {
		return "UNSUPPORTED_MEDIA_TYPE"
	}
	body := http.MaxBytesReader(writer, request.Body, limit)
	raw, err := io.ReadAll(body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return "PAYLOAD_TOO_LARGE"
		}
		return "REQUEST_INVALID"
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "REQUEST_INVALID"
	}
	if err := jsonv2.Unmarshal(trimmed, destination,
		jsonv2.RejectUnknownMembers(true),
		jsonv2.MatchCaseInsensitiveNames(false),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
	); err != nil {
		return "REQUEST_INVALID"
	}
	return ""
}

// decodeOptionalJSON is decodeJSON for a route whose body is optional: no
// body (or a body that trims to zero bytes) leaves destination at its zero
// value and returns no error, matching how an omitted excluded_columns list
// means "register unnarrowed." A present body must still be valid
// application/json, decoded under the same strict rules as decodeJSON.
func decodeOptionalJSON(writer http.ResponseWriter, request *http.Request, destination any) string {
	if headerPresent(request.Header, "Content-Encoding") {
		return "REQUEST_INVALID"
	}
	if request.ContentLength > maxBodyBytes {
		return "PAYLOAD_TOO_LARGE"
	}
	if request.Body == nil || request.Body == http.NoBody {
		return ""
	}
	body := http.MaxBytesReader(writer, request.Body, maxBodyBytes)
	raw, err := io.ReadAll(body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return "PAYLOAD_TOO_LARGE"
		}
		return "REQUEST_INVALID"
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	contentType, ok := exactHeader(request.Header, "Content-Type")
	mediaType, _, mimeErr := mime.ParseMediaType(contentType)
	if !ok || mimeErr != nil || mediaType != jsonContentType {
		return "UNSUPPORTED_MEDIA_TYPE"
	}
	if trimmed[0] != '{' {
		return "REQUEST_INVALID"
	}
	if err := jsonv2.Unmarshal(trimmed, destination,
		jsonv2.RejectUnknownMembers(true),
		jsonv2.MatchCaseInsensitiveNames(false),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
	); err != nil {
		return "REQUEST_INVALID"
	}
	return ""
}

// emptyBody validates that a route requiring no body was sent none, and
// names FIX-7 #2's synthetic "body" field when a non-empty one was rejected.
func emptyBody(writer http.ResponseWriter, request *http.Request) (string, []string) {
	if headerPresent(request.Header, "Content-Encoding") {
		return "REQUEST_INVALID", []string{"Content-Encoding"}
	}
	if request.ContentLength > maxBodyBytes {
		return "PAYLOAD_TOO_LARGE", []string{"body"}
	}
	if request.Body == nil || request.Body == http.NoBody {
		return "", nil
	}
	body := http.MaxBytesReader(writer, request.Body, maxBodyBytes)
	raw, err := io.ReadAll(body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return "PAYLOAD_TOO_LARGE", []string{"body"}
		}
		return "REQUEST_INVALID", []string{"body"}
	}
	if len(raw) != 0 {
		return "REQUEST_INVALID", []string{"body"}
	}
	return "", nil
}

func exactHeader(header http.Header, name string) (string, bool) {
	var values []string
	for key, candidates := range header {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	if len(values) != 1 || values[0] == "" || strings.ContainsRune(values[0], ',') {
		return "", false
	}
	return values[0], true
}

func headerPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func validIdempotencyKey(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validRequestID(value string) bool { return validOpaqueID(value) }

func statusForPathCode(code string) int {
	if code == "REQUEST_INVALID" {
		return http.StatusBadRequest
	}
	return http.StatusNotFound
}

func statusForMutationCode(code string) int {
	switch code {
	case "UNSUPPORTED_MEDIA_TYPE":
		return http.StatusUnsupportedMediaType
	case "PAYLOAD_TOO_LARGE":
		return http.StatusRequestEntityTooLarge
	case "PRECONDITION_REQUIRED":
		return http.StatusPreconditionRequired
	default:
		return http.StatusBadRequest
	}
}

func handleServiceError(writer http.ResponseWriter, err error, requestID string, isCreate bool) {
	code := workspacerepository.CodeOf(err)
	status, publicCode := serviceErrorResponse(code, isCreate)
	if status >= http.StatusInternalServerError {
		setServerFailureCause(writer, "workspace service", string(code))
	}
	writeError(writer, status, publicCode, requestID)
}

func handleQuestionError(writer http.ResponseWriter, err error, requestID string, isCreate bool) {
	code := question.CodeOf(err)
	status, publicCode := questionErrorResponse(code, isCreate)
	if status >= http.StatusInternalServerError {
		setServerFailureCause(writer, "question authority", string(code))
	}
	// R2 Outcome 2: a typed QueryIntent refusal already carries a server-owned,
	// closed-dictionary clarification. Surface it additively beside the
	// unchanged status/code so the browser can show it instead of only the
	// generic code sentence. Every other question error returns "" here, so
	// the field is omitted and the response body is byte-for-byte unchanged.
	writeErrorClarification(writer, status, publicCode, requestID, question.ClarificationOf(err))
}

func handleConversationError(writer http.ResponseWriter, err error, requestID string) {
	code := conversation.CodeOf(err)
	switch code {
	case conversation.CodeInvalid:
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
	case conversation.CodeDenied, conversation.CodeNotFound:
		// Absence and policy denial are intentionally indistinguishable to
		// prevent a conversation/workspace existence oracle.
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	case conversation.CodeIdempotencyConflict:
		writeError(writer, http.StatusConflict, "CONVERSATION_IDEMPOTENCY_CONFLICT", requestID)
	default:
		setServerFailureCause(writer, "conversation service", string(code))
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
	}
}

func handleConversationProjectionError(writer http.ResponseWriter, err error, requestID string) {
	if question.CodeOf(err) != question.CodeUnavailable {
		handleQuestionError(writer, err, requestID, false)
		return
	}
	setServerFailureCause(writer, "conversation projection", string(question.CodeOf(err)))
	writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
}

func questionErrorResponse(code question.ErrorCode, isCreate bool) (int, string) {
	switch code {
	case question.CodeInvalid:
		return http.StatusBadRequest, "REQUEST_INVALID"
	case question.CodeUnsupportedMode:
		// GENERATIVE is a real mode, but it is unavailable until composition
		// wires a qualified Model Gateway adapter/verifier (GEN-1, ADR-0088).
		return http.StatusBadRequest, "QUESTION_MODE_UNSUPPORTED"
	case question.CodeDenied:
		if isCreate {
			return http.StatusForbidden, "FORBIDDEN"
		}
		return http.StatusNotFound, "NOT_FOUND"
	case question.CodeNotFound:
		return http.StatusNotFound, "NOT_FOUND"
	case question.CodeIdempotencyConflict:
		return http.StatusConflict, "QUESTION_IDEMPOTENCY_CONFLICT"
	default:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	}
}

func serviceErrorResponse(code workspacerepository.ErrorCode, isCreate bool) (int, string) {
	switch code {
	case workspacerepository.CodeRequestInvalid:
		return http.StatusBadRequest, "REQUEST_INVALID"
	case workspacerepository.CodeDenied:
		if isCreate {
			return http.StatusForbidden, "FORBIDDEN"
		}
		return http.StatusNotFound, "NOT_FOUND"
	case workspacerepository.CodeNotFound:
		return http.StatusNotFound, "NOT_FOUND"
	case workspacerepository.CodeRevisionConflict:
		return http.StatusPreconditionFailed, "WORKSPACE_REVISION_CONFLICT"
	case workspacerepository.CodeIdempotencyConflict:
		return http.StatusConflict, "WORKSPACE_IDEMPOTENCY_CONFLICT"
	default:
		return http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"
	}
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
		// Fields is FIX-7 #2: the exact names of the request fields that
		// failed validation (header or JSON body), never their values. Set
		// only by writeValidationError; every other error path leaves it
		// absent, exactly like today.
		Fields []string `json:"fields,omitempty"`
		// Clarification is R2 Outcome 2's additive, optional member: the
		// server-owned, closed-dictionary text a typed QueryIntent refusal
		// carries for a human. It is set only by writeErrorClarification and
		// omitted when empty, so every pre-R2 error body keeps its exact shape.
		Clarification string `json:"clarification,omitempty"`
	} `json:"error"`
}

// setServerFailureCause records the content-free cause of a failure this
// handler is about to answer with 5xx. It is called only with a server-owned
// scope and the typed code of the underlying error -- never with an error
// message, request field or body -- so the one server-log line the HTTP
// boundary emits for the response can name what failed without carrying tenant
// content. It is a no-op on the writers test harnesses use directly.
func setServerFailureCause(writer http.ResponseWriter, scope, code string) {
	failurelog.Set(writer, strings.TrimSpace(scope+": "+code))
}

func writeError(writer http.ResponseWriter, status int, code, requestID string) {
	if status >= http.StatusInternalServerError {
		// Fallback for a route whose refusal is "this capability is not
		// wired": the typed cause set by the caller (if any) already won, and
		// the route in the log line names the endpoint.
		setServerFailureCause(writer, "response", code)
	}
	response := errorEnvelope{}
	response.Error.Code = code
	response.Error.RequestID = requestID
	writeJSON(writer, status, response)
}

// writeErrorClarification is writeError plus R2 Outcome 2's additive
// clarification text. An empty clarification delegates to writeError so a
// response with no refusal text is byte-for-byte identical to before.
func writeErrorClarification(writer http.ResponseWriter, status int, code, requestID, clarification string) {
	if clarification == "" {
		writeError(writer, status, code, requestID)
		return
	}
	response := errorEnvelope{}
	response.Error.Code = code
	response.Error.RequestID = requestID
	response.Error.Clarification = clarification
	writeJSON(writer, status, response)
}

// writeValidationError is FIX-7 #2's fix for a diagnosis gap the owner hit
// live: a REQUEST_INVALID response with not one matching line in the
// server's own logs for its request_id, because the transport-validation
// path (mutationHeaders/decodeJSON/emptyBody and each route's own required-
// field check) only ever wrote the response, never a log line. Every one of
// those call sites now goes through this instead of the bare writeError:
// it logs one content-free WARN (request_id, the exact route, the code and
// the field NAMES that failed -- never a header, body or query VALUE) and
// returns those same names in the body's error.fields, so an owner who only
// has their own request_id can find and understand the rejection in the
// server's own logs without anyone reproducing it live. fields may be nil
// for a failure that names no specific field (an unparseable body, an
// unsupported Content-Type).
// fieldPresence and missingFieldNames are FIX-7 #2's shared shape for every
// body type's own missingFields()-style method: name a field, say whether it
// was present, and get back exactly the absent ones' names, never a value.
type fieldPresence struct {
	present bool
	name    string
}

func missingFieldNames(fields []fieldPresence) []string {
	var missing []string
	for _, field := range fields {
		if !field.present {
			missing = append(missing, field.name)
		}
	}
	return missing
}

func writeValidationError(writer http.ResponseWriter, request *http.Request, requestID, code string, fields []string) {
	slog.Warn("request validation failed",
		"request_id", requestID, "route", request.Method+" "+request.URL.Path, "code", code, "fields", fields)
	response := errorEnvelope{}
	response.Error.Code = code
	response.Error.RequestID = requestID
	response.Error.Fields = fields
	writeJSON(writer, statusForMutationCode(code), response)
}

func (handler *Handler) writeSnapshot(writer http.ResponseWriter, access database.AccessContext, snapshot workspace.Snapshot, requestID string) {
	hash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	writer.Header().Set("ETag", "\""+hash+"\"")
	members := make([]memberResponse, len(snapshot.Members))
	for index, member := range snapshot.Members {
		members[index] = memberResponse{PrincipalID: member.PrincipalID, DisplayName: member.DisplayName, Role: member.Role}
	}
	// FIX-2 #4: content-free -- mode plus a model id, never an endpoint,
	// credential or mount path. Content-free INTERNAL_UNAVAILABLE (no
	// questions capability wired) rather than omitting the field.
	processingMode := processingModeResponse{Mode: question.ProcessingModeInternalUnavailable}
	if handler.questions != nil {
		processingMode.Mode, processingMode.Provider = handler.questions.ProcessingMode(snapshot.ID)
	}
	// This content-free catalogue is projected only after the existing live
	// workspace authorization. The default processing mode remains unchanged;
	// an individual answer carries its own persisted model selection.
	modelProfiles := []question.ModelProfileOption{}
	canAsk := false
	if access.OrganizationID == snapshot.OrganizationID {
		for _, member := range snapshot.Members {
			if member.PrincipalID == access.PrincipalID {
				canAsk = policy.RoleCanAsk(policy.WorkspaceStatus(snapshot.Status), policy.WorkspaceRole(member.Role))
				break
			}
		}
	}
	if catalog, ok := handler.questions.(interface {
		ModelProfiles(string) []question.ModelProfileOption
	}); ok && canAsk {
		modelProfiles = append(modelProfiles, catalog.ModelProfiles(snapshot.ID)...)
	}
	writeJSON(writer, http.StatusOK, workspaceResponse{
		ID: snapshot.ID, Name: snapshot.Name, Description: snapshot.Description, Status: snapshot.Status, Revision: snapshot.Revision,
		OwnerPrincipalID: snapshot.OwnerPrincipalID, RetentionPolicyID: snapshot.RetentionPolicyID, Members: members,
		ProcessingMode: processingMode,
		ModelProfiles:  modelProfiles,
	})
}

type processingModeResponse struct {
	Mode     string `json:"mode"`
	Provider string `json:"provider,omitempty"`
}

type summaryResponse struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Status   workspace.Status `json:"status"`
	Revision int64            `json:"revision"`
	Role     workspace.Role   `json:"role"`
	// Degraded is additive: a healthy workspace omits both fields, so its
	// projection stays byte-identical to the pre-guard response. Pointers make
	// the omission independent of the JSON encoder's empty-value rules.
	Degraded       *bool   `json:"degraded,omitempty"`
	DegradedReason *string `json:"degraded_reason,omitempty"`
}

type memberResponse struct {
	PrincipalID string         `json:"principal_id"`
	DisplayName string         `json:"display_name"`
	Role        workspace.Role `json:"role"`
}

type workspaceResponse struct {
	ID                string                        `json:"id"`
	Name              string                        `json:"name"`
	Description       string                        `json:"description"`
	Status            workspace.Status              `json:"status"`
	Revision          int64                         `json:"revision"`
	OwnerPrincipalID  string                        `json:"owner_principal_id"`
	RetentionPolicyID string                        `json:"retention_policy_id"`
	Members           []memberResponse              `json:"members"`
	ProcessingMode    processingModeResponse        `json:"processing_mode"`
	ModelProfiles     []question.ModelProfileOption `json:"model_profiles"`
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = jsonv2.MarshalWrite(writer, value)
}
