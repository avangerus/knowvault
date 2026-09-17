// Package audit builds and appends the content-free, append-only security
// event stream. It never accepts arbitrary metadata or a caller-supplied hash.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	schemaVersion = "audit-event-v1"
	zeroHash      = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	maxAttempts   = 3
	maxSafeInt64  = int64(9007199254740991)
)

// ErrorCode is intentionally content-free and safe for logs/API mapping.
type ErrorCode string

const (
	CodeInvalidEvent    ErrorCode = "AUDIT_EVENT_INVALID"
	CodeAppendFailed    ErrorCode = "AUDIT_APPEND_FAILED"
	CodeAppendContended ErrorCode = "AUDIT_APPEND_CONTENDED"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var auditError *Error
	if errors.As(err, &auditError) {
		return auditError.code
	}
	return CodeAppendFailed
}

type ActorType string

const (
	ActorHuman     ActorType = "HUMAN"
	ActorService   ActorType = "SERVICE"
	ActorConnector ActorType = "CONNECTOR"
	ActorSystem    ActorType = "SYSTEM"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "SUCCESS"
	OutcomeDenied  Outcome = "DENIED"
	OutcomeFailed  Outcome = "FAILED"
)

type ResourceType string

const (
	ResourceOrganization     ResourceType = "ORGANIZATION"
	ResourceIdentity         ResourceType = "IDENTITY"
	ResourceWorkspace        ResourceType = "WORKSPACE"
	ResourceWorkspaceMember  ResourceType = "WORKSPACE_MEMBER"
	ResourceWorkspaceSource  ResourceType = "WORKSPACE_SOURCE"
	ResourceSourceConnection ResourceType = "SOURCE_CONNECTION"
	ResourceSourceScope      ResourceType = "SOURCE_SCOPE"
	ResourceSourceObject     ResourceType = "SOURCE_OBJECT"
	ResourceConversation     ResourceType = "CONVERSATION"
	ResourceQuestionRun      ResourceType = "QUESTION_RUN"
	ResourceAnswerDocument   ResourceType = "ANSWER_DOCUMENT"
	ResourceCitation         ResourceType = "CITATION"
	ResourceModelRun         ResourceType = "MODEL_RUN"
	ResourcePolicy           ResourceType = "POLICY"
	ResourceSigningKey       ResourceType = "SIGNING_KEY"
	ResourceAuditCheckpoint  ResourceType = "AUDIT_CHECKPOINT"
)

// Action is a closed, server-owned registry. A transport handler must choose
// one of these constants; raw client action strings are never audited.
type Action string

const (
	ActionIdentityLogin             Action = "identity.login"
	ActionIdentityLoginFailed       Action = "identity.login_failed"
	ActionIdentityDeprovisioned     Action = "identity.deprovisioned"
	ActionSessionTerminated         Action = "session.terminated"
	ActionAnswerDocumentAmended     Action = "answer.document.amended"
	ActionWorkspaceCreated          Action = "workspace.created"
	ActionWorkspaceUpdated          Action = "workspace.updated"
	ActionWorkspaceArchived         Action = "workspace.archived"
	ActionWorkspaceMemberAdded      Action = "workspace.member_added"
	ActionWorkspaceMemberRemoved    Action = "workspace.member_removed"
	ActionWorkspaceRoleChanged      Action = "workspace.role_changed"
	ActionWorkspaceSourceAdded      Action = "workspace.source_added"
	ActionWorkspaceSourceRemoved    Action = "workspace.source_removed"
	ActionPolicyDecision            Action = "policy.decision"
	ActionAuditViewed               Action = "audit.viewed"
	ActionAuditExported             Action = "audit.exported"
	ActionSourceScopeChanged        Action = "source.scope_changed"
	ActionSourceScopeActivated      Action = "source.scope_activated"
	ActionSourceRegistrationCreated Action = "source.registration_created"
	ActionSourceActivationRequested Action = "source.activation_requested"
	ActionSourceObjectIngested      Action = "source.object_ingested"
	ActionSourceObjectDeleted       Action = "source.object_deleted"
	ActionSourceObjectMissing       Action = "source.object_missing"
	ActionSourceObjectRestored      Action = "source.object_restored"
	ActionSourceVersionCreated      Action = "source.version_created"
	ActionSourceVersionPurging      Action = "source.version_purging"
	ActionSourceVersionPurged       Action = "source.version_purged"
	ActionSourceExtractionActive    Action = "source.extraction_activated"
	ActionQuestionCreated           Action = "question.created"
	ActionQuestionCompleted         Action = "question.completed"
	ActionQuestionFailed            Action = "question.failed"
	// ActionModelGatewayAttempt is content-free: it never carries question
	// text, Evidence text or model output (GEN-1, ADR-0088, MOD-007/MOD-008).
	ActionModelGatewayAttempt  Action = "model_run.gateway_attempt"
	ActionConversationArchived Action = "conversation.archived"
	ActionConversationPurging  Action = "conversation.purging"
	ActionConversationPurged   Action = "conversation.purged"
	ActionCitationOpened       Action = "citation.opened"
	// Outcome 2 (audit before data): the admission event persisted before an
	// authorized evidence read fetches any fragment content, and the matching
	// failure outcome appended when a read fails after that admission. Both are
	// content-free and reuse the existing CITATION resource and outcome column.
	ActionEvidenceReadAdmitted Action = "evidence.read.admitted"
	ActionEvidenceReadFailed   Action = "evidence.read.failed"
	// Source metadata is protected knowledge too. These events name only the
	// workspace, caller and closed read kind, never connection names or status.
	ActionSourceMetadataReadAdmitted  Action = "source.metadata.read.admitted"
	ActionSourceMetadataReadCompleted Action = "source.metadata.read.completed"
	ActionSourceMetadataReadFailed    Action = "source.metadata.read.failed"
	// Outcome 2 (audit before data): the admission event persisted before a
	// governed workspace question run reads or returns any data. It records the
	// actor kind (HUMAN | SERVICE) and the access decision and carries no
	// question, answer or source content. The existing question.created /
	// question.completed / question.failed outcome events are unchanged.
	ActionQuestionRunAdmitted Action = "question.run.admitted"
	// Outcome 2 (audit before data): the admission event persisted before a
	// governed model-authored SQL query reads or executes anything. It records
	// the actor kind (HUMAN | SERVICE) and the access decision (SUCCESS =
	// admitted) and names the workspace as its resource; it carries no SQL
	// text, schema, row or model content. The existing
	// source.governed_query_attempted outcome event is unchanged.
	ActionGovernedQueryAdmitted Action = "source.governed_query_admitted"
	// ADR-0087 §2: CONNECTOR_ADMIN-gated source connection trust verification
	// (DRAFT -> VERIFIED). See TrustVerificationID/TrustVerificationHash below.
	ActionSourceConnectionTrustVerified Action = "source.connection_trust_verified"
)

// Metadata is an allowlisted projection only. It intentionally has no title,
// path, source body, prompt, answer, token, credential or free-text field.
type Metadata struct {
	WorkspaceRevision   *int64   `json:"workspace_revision,omitempty"`
	WorkspaceSourceID   *string  `json:"workspace_source_id,omitempty"`
	SourceScopeID       *string  `json:"source_scope_id,omitempty"`
	SourceScopeRevision *int64   `json:"source_scope_revision,omitempty"`
	ScopeConfigHash     *string  `json:"scope_config_hash,omitempty"`
	AccessMode          *string  `json:"access_mode,omitempty"`
	Enabled             *bool    `json:"enabled,omitempty"`
	SourceConnectionID  *string  `json:"source_connection_id,omitempty"`
	ConnectorJobID      *string  `json:"connector_job_id,omitempty"`
	SyncRunID           *string  `json:"sync_run_id,omitempty"`
	QuestionRunID       *string  `json:"question_run_id,omitempty"`
	ModelRunID          *string  `json:"model_run_id,omitempty"`
	CitationNumber      *int64   `json:"citation_number,omitempty"`
	ManifestHash        *string  `json:"manifest_hash,omitempty"`
	PolicyRevision      *string  `json:"policy_revision,omitempty"`
	ReasonCodes         []string `json:"reason_codes,omitempty"`
	RemoteAddressDigest *string  `json:"remote_address_digest,omitempty"`
	UserAgentFamily     *string  `json:"user_agent_family,omitempty"`

	// Protected answer-document amendment vocabulary (ADR-0076). Reserved to
	// the answer.document.amended action: the server-owned version number and
	// the closed amendment class, never request-supplied text or content.
	AnswerDocumentVersion *int64  `json:"answer_document_version,omitempty"`
	AmendmentClass        *string `json:"amendment_class,omitempty"`

	// Workspace-managed authority command vocabulary (ADR-0053). Reserved to
	// the four authority actions; see validAuthorityProjection. Every value is
	// a server-owned ID, hash or closed code — never request-supplied text.
	AuthorityOperation             *string `json:"authority_operation,omitempty"`
	AuthorityResultID              *string `json:"authority_result_id,omitempty"`
	AuthorityResultHash            *string `json:"authority_result_hash,omitempty"`
	AuthorityParentID              *string `json:"authority_parent_id,omitempty"`
	AuthorityParentHash            *string `json:"authority_parent_hash,omitempty"`
	AuthorityRevocationID          *string `json:"authority_revocation_id,omitempty"`
	AuthorityRevocationHash        *string `json:"authority_revocation_hash,omitempty"`
	AuthorityReasonCode            *string `json:"authority_reason_code,omitempty"`
	TargetPrincipalID              *string `json:"target_principal_id,omitempty"`
	WorkspaceConfigurationHash     *string `json:"workspace_configuration_hash,omitempty"`
	ConfirmationActorGrantID       *string `json:"confirmation_actor_grant_id,omitempty"`
	ConfirmationActorGrantRevision *int64  `json:"confirmation_actor_grant_revision,omitempty"`
	ConfirmationActorGrantHash     *string `json:"confirmation_actor_grant_hash,omitempty"`
	WarningVersion                 *string `json:"warning_version,omitempty"`
	WarningContractHash            *string `json:"warning_contract_hash,omitempty"`
	AcknowledgementCode            *string `json:"acknowledgement_code,omitempty"`

	// Deployment secret rotation vocabulary (ADR-0070). Reserved to the two
	// key.rotation actions; see validRotationProjection.
	RotationDomain *string `json:"rotation_domain,omitempty"`
	KeyReference   *string `json:"key_reference,omitempty"`
	KeyVersion     *int64  `json:"key_version,omitempty"`

	// Connection trust verification vocabulary (ADR-0087 §2). Reserved to
	// source.connection_trust_verified: the server-owned verification id and
	// its canonical hash, never the attestation text itself.
	TrustVerificationID   *string `json:"trust_verification_id,omitempty"`
	TrustVerificationHash *string `json:"trust_verification_hash,omitempty"`

	// Governed-query attempt vocabulary (ADR-0089 §4). Reserved to
	// source.governed_query_attempted: the exposed-schema revision, a
	// content-free hash of the exact model-authored SQL text, the EXPLAIN
	// cost estimate, row count, a content-free result digest and the closed
	// outcome vocabulary. Row values and the SQL text itself never appear
	// here — only their hashes/counts (MOD-007/MOD-008 discipline).
	GovernedQueryConnectionID          *string `json:"governed_query_connection_id,omitempty"`
	GovernedQueryExposedSchemaRevision *int64  `json:"governed_query_exposed_schema_revision,omitempty"`
	GovernedQuerySQLHash               *string `json:"governed_query_sql_hash,omitempty"`
	GovernedQueryCostEstimate          *int64  `json:"governed_query_cost_estimate,omitempty"`
	GovernedQueryRowCount              *int64  `json:"governed_query_row_count,omitempty"`
	GovernedQueryResultDigest          *string `json:"governed_query_result_digest,omitempty"`
	GovernedQueryOutcome               *string `json:"governed_query_outcome,omitempty"`
}

// EventInput is the trusted application intent. Organization and actor values
// must exact-match database.AccessContext before an append is attempted.
type EventInput struct {
	EventID               string
	WorkspaceID           *string
	ActorType             ActorType
	ActorPrincipalID      *string
	OnBehalfOfPrincipalID *string
	Action                Action
	ResourceType          ResourceType
	ResourceID            string
	RequestID             string
	PolicyDecisionID      *string
	Outcome               Outcome
	ErrorCode             *string
	ReferencedEvidenceIDs []string
	Metadata              Metadata
	OccurredAt            time.Time
}

// Event is exactly the persisted audit-event-v1 projection, plus its
// canonical bytes. CanonicalBytes are never returned by an HTTP handler.
type Event struct {
	SchemaVersion         string
	EventID               string
	OrganizationID        string
	Sequence              int64
	WorkspaceID           *string
	ActorType             ActorType
	ActorPrincipalID      *string
	OnBehalfOfPrincipalID *string
	Action                Action
	ResourceType          ResourceType
	ResourceID            string
	RequestID             string
	PolicyDecisionID      *string
	Outcome               Outcome
	ErrorCode             *string
	ReferencedEvidenceIDs []string
	Metadata              Metadata
	PreviousEventHash     string
	EventHash             string
	OccurredAt            time.Time
	CanonicalBytes        []byte
}

type chainHead struct {
	Sequence int64
	Hash     string
}

// Build validates the entire input and derives sequence, previous hash,
// canonical JCS bytes and SHA-256 itself. The caller cannot provide a hash.
func Build(organizationID string, input EventInput, headSequence int64, headHash string) (Event, error) {
	if !validID(organizationID) || headSequence < 0 || (headSequence > 0 && !validHash(headHash)) || (headSequence == 0 && headHash != "" && headHash != zeroHash) {
		return Event{}, &Error{code: CodeInvalidEvent}
	}
	if headSequence == 0 {
		headHash = zeroHash
	}
	if err := validateInput(input); err != nil {
		return Event{}, err
	}

	event := Event{
		SchemaVersion: schemaVersion, EventID: input.EventID, OrganizationID: organizationID,
		Sequence: headSequence + 1, WorkspaceID: cloneString(input.WorkspaceID), ActorType: input.ActorType,
		ActorPrincipalID: cloneString(input.ActorPrincipalID), OnBehalfOfPrincipalID: cloneString(input.OnBehalfOfPrincipalID),
		Action: input.Action, ResourceType: input.ResourceType, ResourceID: input.ResourceID, RequestID: input.RequestID,
		PolicyDecisionID: cloneString(input.PolicyDecisionID), Outcome: input.Outcome, ErrorCode: cloneString(input.ErrorCode),
		ReferencedEvidenceIDs: canonicalEvidenceIDs(input.ReferencedEvidenceIDs), Metadata: cloneMetadata(input.Metadata),
		PreviousEventHash: headHash, OccurredAt: input.OccurredAt.UTC(),
	}
	canonical, err := canonicalEvent(event, false)
	if err != nil {
		return Event{}, &Error{code: CodeInvalidEvent}
	}
	event.CanonicalBytes = canonical
	event.EventHash = hash(canonical)
	return event, nil
}

// Store is the only persistence adapter for audit events. It receives the
// private database boundary rather than a connection/pool, so every append is
// tenant-scoped and transaction-local request context is installed first.
type Store struct{ database *database.Store }

func NewStore(store *database.Store) (*Store, error) {
	if store == nil {
		return nil, &Error{code: CodeAppendFailed}
	}
	return &Store{database: store}, nil
}

// Append replays a whole transaction only for the trigger's serialization
// signal. It never replays an arbitrary database failure and returns a
// content-free error after the small bounded retry budget is exhausted.
func (store *Store) Append(ctx context.Context, access database.AccessContext, input EventInput) (Event, error) {
	if err := store.validateAppend(access, input); err != nil {
		return Event{}, err
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var result Event
		err := store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
			event, appendErr := store.AppendInTransaction(transactionContext, access, transaction, input)
			if appendErr != nil {
				return appendErr
			}
			result = event
			return nil
		})
		if err == nil {
			return result, nil
		}
		if CodeOf(err) == CodeInvalidEvent {
			return Event{}, err
		}
		if !database.IsSerializationFailure(err) {
			return Event{}, &Error{code: CodeAppendFailed}
		}
	}
	return Event{}, &Error{code: CodeAppendContended}
}

// AppendInTransaction appends an event to the caller's authorized write
// transaction. It does not start, commit or retry a transaction: the caller
// must return any error so its business mutation and audit event roll back
// together. External interfaces must map errors through CodeOf and must never
// expose database causes.
func (store *Store) AppendInTransaction(ctx context.Context, access database.AccessContext, transaction database.Transaction, input EventInput) (Event, error) {
	if err := store.validateAppend(access, input); err != nil {
		return Event{}, err
	}
	if ctx == nil || !transaction.Valid() {
		return Event{}, &Error{code: CodeAppendFailed}
	}

	event, err := store.appendInTransaction(ctx, access, transaction, input)
	if err == nil || CodeOf(err) == CodeInvalidEvent {
		return event, err
	}
	return Event{}, &Error{code: CodeAppendFailed, cause: err}
}

func (store *Store) validateAppend(access database.AccessContext, input EventInput) error {
	if store == nil || store.database == nil || access.Validate() != nil || access.OrganizationID == "" || access.PrincipalID == "" {
		return &Error{code: CodeAppendFailed}
	}
	if input.RequestID != access.RequestID || (input.ActorType != ActorSystem && (input.ActorPrincipalID == nil || *input.ActorPrincipalID != access.PrincipalID)) {
		return &Error{code: CodeInvalidEvent}
	}
	return nil
}

func (store *Store) appendInTransaction(ctx context.Context, access database.AccessContext, transaction database.Transaction, input EventInput) (Event, error) {
	// Build must observe the head while owning the same append window as the
	// INSERT. Locking only in the trigger is too late: competing callers have
	// already hashed the same next sequence, and caller-owned transactions
	// cannot be retried here. The transaction lock also covers an absent genesis
	// row; only the existing append trigger may create or mutate that row.
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
		pg_catalog.hashtextextended('knowvault:audit-chain:' || $1, 0))`, access.OrganizationID); err != nil {
		return Event{}, err
	}
	var head chainHead
	if err := transaction.QueryRow(ctx, `
		WITH locked_head AS MATERIALIZED (
			SELECT last_sequence, last_event_hash FROM public.audit_chain_head
			WHERE organization_id = $1 FOR UPDATE
		)
		SELECT COALESCE((SELECT last_sequence FROM locked_head), 0),
		       COALESCE((SELECT last_event_hash FROM locked_head), $2)
	`, access.OrganizationID, zeroHash).Scan(&head.Sequence, &head.Hash); err != nil {
		return Event{}, err
	}

	event, err := Build(access.OrganizationID, input, head.Sequence, head.Hash)
	if err != nil {
		return Event{}, err
	}
	evidenceJSON, err := json.Marshal(event.ReferencedEvidenceIDs)
	if err != nil {
		return Event{}, &Error{code: CodeInvalidEvent}
	}
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return Event{}, &Error{code: CodeInvalidEvent}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.audit_event (
			id, schema_version, organization_id, sequence, workspace_id,
			actor_type, actor_principal_id, on_behalf_of_principal_id,
			action, resource_type, resource_id, request_id, policy_decision_id,
			outcome, error_code, referenced_evidence_ids_json, metadata_json,
			canonical_bytes, previous_event_hash, event_hash, occurred_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			$14, $15, $16::jsonb, $17::jsonb, $18, $19, $20, $21
		)
	`,
		event.EventID, event.SchemaVersion, event.OrganizationID, event.Sequence, event.WorkspaceID,
		event.ActorType, event.ActorPrincipalID, event.OnBehalfOfPrincipalID, event.Action, event.ResourceType,
		event.ResourceID, event.RequestID, event.PolicyDecisionID, event.Outcome, event.ErrorCode,
		string(evidenceJSON), string(metadataJSON), event.CanonicalBytes, event.PreviousEventHash, event.EventHash, event.OccurredAt,
	); err != nil {
		return Event{}, err
	}
	return event, nil
}

func validateInput(input EventInput) error {
	if !validID(input.EventID) || !validID(input.ResourceID) || !validID(input.RequestID) ||
		!validActor(input.ActorType) || !validAction(input.Action) || !validResource(input.ResourceType) ||
		!validOutcome(input.Outcome) || input.OccurredAt.IsZero() {
		return &Error{code: CodeInvalidEvent}
	}
	if (input.ActorType == ActorSystem) != (input.ActorPrincipalID == nil) ||
		(input.Outcome == OutcomeSuccess) != (input.ErrorCode == nil) {
		return &Error{code: CodeInvalidEvent}
	}
	for _, value := range []*string{input.WorkspaceID, input.ActorPrincipalID, input.OnBehalfOfPrincipalID, input.PolicyDecisionID, input.ErrorCode} {
		if value != nil && !validID(*value) {
			return &Error{code: CodeInvalidEvent}
		}
	}
	if input.ErrorCode != nil && !validErrorCode(*input.ErrorCode) {
		return &Error{code: CodeInvalidEvent}
	}
	if !canonicalEvidence(input.ReferencedEvidenceIDs) || !validMetadata(input.Metadata) || !validActionProjection(input) {
		return &Error{code: CodeInvalidEvent}
	}
	return nil
}

func canonicalEvent(event Event, includeHash bool) ([]byte, error) {
	type serializableEvent struct {
		SchemaVersion         string       `json:"schema_version"`
		EventID               string       `json:"event_id"`
		OrganizationID        string       `json:"organization_id"`
		Sequence              int64        `json:"sequence"`
		WorkspaceID           *string      `json:"workspace_id"`
		ActorType             ActorType    `json:"actor_type"`
		ActorPrincipalID      *string      `json:"actor_principal_id"`
		OnBehalfOfPrincipalID *string      `json:"on_behalf_of_principal_id"`
		Action                Action       `json:"action"`
		ResourceType          ResourceType `json:"resource_type"`
		ResourceID            string       `json:"resource_id"`
		RequestID             string       `json:"request_id"`
		PolicyDecisionID      *string      `json:"policy_decision_id"`
		Outcome               Outcome      `json:"outcome"`
		ErrorCode             *string      `json:"error_code"`
		ReferencedEvidenceIDs []string     `json:"referenced_evidence_ids"`
		Metadata              Metadata     `json:"metadata"`
		PreviousEventHash     string       `json:"previous_event_hash"`
		EventHash             *string      `json:"event_hash,omitempty"`
		OccurredAt            string       `json:"occurred_at"`
	}
	value := serializableEvent{
		SchemaVersion: event.SchemaVersion, EventID: event.EventID, OrganizationID: event.OrganizationID, Sequence: event.Sequence,
		WorkspaceID: event.WorkspaceID, ActorType: event.ActorType, ActorPrincipalID: event.ActorPrincipalID,
		OnBehalfOfPrincipalID: event.OnBehalfOfPrincipalID, Action: event.Action, ResourceType: event.ResourceType,
		ResourceID: event.ResourceID, RequestID: event.RequestID, PolicyDecisionID: event.PolicyDecisionID, Outcome: event.Outcome,
		ErrorCode: event.ErrorCode, ReferencedEvidenceIDs: event.ReferencedEvidenceIDs, Metadata: event.Metadata,
		PreviousEventHash: event.PreviousEventHash, OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano),
	}
	if includeHash {
		value.EventHash = &event.EventHash
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func hash(bytes []byte) string {
	digest := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func canonicalEvidence(ids []string) bool {
	if len(ids) > 128 {
		return false
	}
	previous := ""
	for _, id := range ids {
		if !validID(id) || (previous != "" && id <= previous) {
			return false
		}
		previous = id
	}
	return true
}

func canonicalEvidenceIDs(ids []string) []string {
	// The schema requires an array even when the event has no evidence. A nil
	// slice would serialize as JSON null and weaken the event contract.
	result := make([]string, len(ids))
	copy(result, ids)
	return result
}

func validID(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}

func validHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validActor(actor ActorType) bool {
	return actor == ActorHuman || actor == ActorService || actor == ActorConnector || actor == ActorSystem
}

func validOutcome(outcome Outcome) bool {
	return outcome == OutcomeSuccess || outcome == OutcomeDenied || outcome == OutcomeFailed
}

func validResource(resource ResourceType) bool {
	switch resource {
	case ResourceOrganization, ResourceIdentity, ResourceWorkspace, ResourceWorkspaceMember, ResourceWorkspaceSource, ResourceWorkspaceAuthorityCommand, ResourceSourceConnection, ResourceSourceScope, ResourceSourceObject, ResourceConversation, ResourceQuestionRun, ResourceAnswerDocument, ResourceCitation, ResourceModelRun, ResourcePolicy, ResourceSigningKey, ResourceAuditCheckpoint, ResourceCryptoKey, ResourceGovernedQueryAttempt, ResourceSearchProfile:
		return true
	default:
		return false
	}
}

func validAction(action Action) bool {
	switch action {
	case ActionSourceObjectMissing, ActionSourceObjectRestored:
		return true
	case ActionSourceMetadataReadAdmitted, ActionSourceMetadataReadCompleted, ActionSourceMetadataReadFailed:
		return true
	case ActionIdentityLogin, ActionIdentityLoginFailed, ActionIdentityDeprovisioned, ActionSessionTerminated, ActionWorkspaceCreated, ActionWorkspaceUpdated, ActionWorkspaceArchived, ActionWorkspaceMemberAdded, ActionWorkspaceMemberRemoved, ActionWorkspaceRoleChanged, ActionWorkspaceSourceAdded, ActionWorkspaceSourceRemoved, ActionWorkspaceSourceConfirmationGrantIssued, ActionWorkspaceSourceConfirmationGrantRevoked, ActionWorkspaceSourceConfirmed, ActionWorkspaceSourceConfirmationRevoked, ActionPolicyDecision, ActionAuditViewed, ActionAuditExported, ActionSourceScopeChanged, ActionSourceScopeActivated, ActionSourceRegistrationCreated, ActionSourceActivationRequested, ActionSourceObjectIngested, ActionSourceObjectDeleted, ActionSourceVersionCreated, ActionSourceVersionPurging, ActionSourceVersionPurged, ActionSourceExtractionActive, ActionQuestionCreated, ActionQuestionCompleted, ActionQuestionFailed, ActionModelGatewayAttempt, ActionConversationArchived, ActionConversationPurging, ActionConversationPurged, ActionCitationOpened, ActionEvidenceReadAdmitted, ActionEvidenceReadFailed, ActionQuestionRunAdmitted, ActionGovernedQueryAdmitted, ActionAnswerDocumentAmended, ActionKeyRotationBegin, ActionKeyRotationComplete, ActionSourceConnectionTrustVerified, ActionGovernedQueryAttempted, ActionSearchProfileRevisionRequested, ActionSearchProfileCallLexical, ActionSearchProfileCallVector, ActionSearchProfileCallHybrid:
		return true
	default:
		return false
	}
}

func validErrorCode(value string) bool {
	if len(value) < 2 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' {
			return false
		}
	}
	return value[0] >= 'A' && value[0] <= 'Z'
}

func validMetadata(metadata Metadata) bool {
	for _, value := range []*string{metadata.WorkspaceSourceID, metadata.SourceScopeID, metadata.SourceConnectionID, metadata.ConnectorJobID, metadata.SyncRunID, metadata.QuestionRunID, metadata.ModelRunID, metadata.ManifestHash, metadata.PolicyRevision, metadata.RemoteAddressDigest, metadata.UserAgentFamily, metadata.TrustVerificationID} {
		if value != nil && !validID(*value) {
			return false
		}
	}
	if metadata.WorkspaceRevision != nil && (*metadata.WorkspaceRevision < 1 || *metadata.WorkspaceRevision > maxSafeInt64) ||
		metadata.SourceScopeRevision != nil && (*metadata.SourceScopeRevision < 1 || *metadata.SourceScopeRevision > maxSafeInt64) ||
		metadata.CitationNumber != nil && (*metadata.CitationNumber < 1 || *metadata.CitationNumber > maxSafeInt64) ||
		metadata.AnswerDocumentVersion != nil && (*metadata.AnswerDocumentVersion < 1 || *metadata.AnswerDocumentVersion > maxSafeInt64) || len(metadata.ReasonCodes) > 32 {
		return false
	}
	if metadata.AmendmentClass != nil && !validAmendmentClass(*metadata.AmendmentClass) {
		return false
	}
	previous := ""
	for _, code := range metadata.ReasonCodes {
		if !validErrorCode(code) || (previous != "" && code <= previous) {
			return false
		}
		previous = code
	}
	if metadata.ScopeConfigHash != nil && !validHash(*metadata.ScopeConfigHash) || metadata.ManifestHash != nil && !validHash(*metadata.ManifestHash) || metadata.RemoteAddressDigest != nil && !validHash(*metadata.RemoteAddressDigest) {
		return false
	}
	if metadata.TrustVerificationHash != nil && !validHash(*metadata.TrustVerificationHash) {
		return false
	}
	if metadata.AccessMode != nil && *metadata.AccessMode != "WORKSPACE_MANAGED" && *metadata.AccessMode != "SOURCE_ENFORCED" {
		return false
	}
	if !validAuthorityMetadataFields(metadata) || !validRotationMetadataFields(metadata) {
		return false
	}
	if !validGovernedQueryMetadataFields(metadata) {
		return false
	}
	return true
}

// validAmendmentClass admits only the closed ADR-0076 amendment vocabulary.
func validAmendmentClass(class string) bool {
	return class == "SUPERSEDE" || class == "RETRACT" || class == "REDACT"
}

// hasAnswerMetadata reports whether any protected answer-document amendment
// field is present. Reserved to the answer.document.amended action.
func hasAnswerMetadata(metadata Metadata) bool {
	return metadata.AnswerDocumentVersion != nil || metadata.AmendmentClass != nil
}

// answerAmendmentMetadataOnly admits exactly the protected amendment fields:
// the server-owned version and the closed class, nothing else.
func answerAmendmentMetadataOnly(metadata Metadata) bool {
	return metadata.WorkspaceRevision == nil && metadata.WorkspaceSourceID == nil && metadata.SourceScopeID == nil &&
		metadata.SourceScopeRevision == nil && metadata.ScopeConfigHash == nil && metadata.AccessMode == nil &&
		metadata.Enabled == nil && metadata.SourceConnectionID == nil && metadata.ConnectorJobID == nil &&
		metadata.SyncRunID == nil && metadata.QuestionRunID == nil && metadata.ModelRunID == nil &&
		metadata.CitationNumber == nil && metadata.ManifestHash == nil && metadata.PolicyRevision == nil &&
		len(metadata.ReasonCodes) == 0 && metadata.RemoteAddressDigest == nil && metadata.UserAgentFamily == nil &&
		!hasAuthorityMetadata(metadata) && !hasRotationMetadata(metadata) && !hasTrustVerificationMetadata(metadata) && !hasGovernedQueryMetadata(metadata)
}

// hasTrustVerificationMetadata reports whether any protected connection trust
// verification field is present. Reserved to the
// source.connection_trust_verified action.
func hasTrustVerificationMetadata(metadata Metadata) bool {
	return metadata.TrustVerificationID != nil || metadata.TrustVerificationHash != nil
}

// validAnswerAmendmentProjection pins the answer amendment audit shape: the
// action names the exact resource, carries the server-owned version and never
// the amended content, and a successful amendment must name its workspace.
func validAnswerAmendmentProjection(input EventInput) bool {
	if input.ResourceType != ResourceAnswerDocument || !answerAmendmentMetadataOnly(input.Metadata) ||
		input.Metadata.AnswerDocumentVersion == nil {
		return false
	}
	return input.Outcome != OutcomeSuccess || input.WorkspaceID != nil
}

// validActionProjection prevents the source-binding audit vocabulary from
// becoming a generic bag of metadata. Every terminal source command, including
// a denied or failed attempt, names the exact immutable workspace and scope
// revisions it targeted. Outcome/error-code consistency is enforced by the
// common event validator; the projection shape remains identical for every
// outcome and never carries policy, evidence or content fields. A successful
// mutation must name its workspace, while a denied/failed attempt may omit it
// so that auditing an unknown or hidden target does not create an existence
// oracle through the workspace foreign key.
func validActionProjection(input EventInput) bool {
	if input.Action == ActionSourceMetadataReadAdmitted || input.Action == ActionSourceMetadataReadCompleted || input.Action == ActionSourceMetadataReadFailed {
		return validSourceMetadataReadProjection(input)
	}
	if isAuthorityAction(input.Action) || input.ResourceType == ResourceWorkspaceAuthorityCommand {
		return validAuthorityProjection(input)
	}
	if isRotationAction(input.Action) || input.ResourceType == ResourceCryptoKey {
		return validRotationProjection(input)
	}
	if input.Action == ActionAnswerDocumentAmended {
		return validAnswerAmendmentProjection(input)
	}
	if isGovernedQueryAction(input.Action) || input.ResourceType == ResourceGovernedQueryAttempt {
		return validGovernedQueryProjection(input)
	}
	if isSearchProfileAction(input.Action) || input.ResourceType == ResourceSearchProfile {
		return validSearchProfileProjection(input)
	}
	if input.Action != ActionWorkspaceSourceAdded && input.Action != ActionWorkspaceSourceRemoved {
		return input.ResourceType != ResourceWorkspaceSource && !hasAuthorityMetadata(input.Metadata) && !hasRotationMetadata(input.Metadata) && !hasAnswerMetadata(input.Metadata) && !hasGovernedQueryMetadata(input.Metadata)
	}
	metadata := input.Metadata
	if input.ResourceType != ResourceWorkspaceSource || input.Outcome == OutcomeSuccess && input.WorkspaceID == nil ||
		len(input.ReferencedEvidenceIDs) != 0 ||
		input.PolicyDecisionID != nil || metadata.WorkspaceRevision == nil || metadata.WorkspaceSourceID == nil ||
		metadata.SourceScopeID == nil || metadata.SourceScopeRevision == nil || metadata.ScopeConfigHash == nil ||
		metadata.AccessMode == nil || metadata.Enabled == nil || metadata.PolicyRevision != nil ||
		input.ResourceID != *metadata.WorkspaceSourceID {
		return false
	}
	wantEnabled := input.Action == ActionWorkspaceSourceAdded
	return *metadata.Enabled == wantEnabled && sourceMutationMetadataOnly(metadata)
}

func sourceMutationMetadataOnly(metadata Metadata) bool {
	return metadata.SourceConnectionID == nil && metadata.ConnectorJobID == nil && metadata.SyncRunID == nil &&
		metadata.QuestionRunID == nil && metadata.ModelRunID == nil && metadata.CitationNumber == nil &&
		metadata.ManifestHash == nil && len(metadata.ReasonCodes) == 0 && metadata.RemoteAddressDigest == nil &&
		metadata.UserAgentFamily == nil && metadata.AnswerDocumentVersion == nil && metadata.AmendmentClass == nil &&
		!hasAuthorityMetadata(metadata) && !hasRotationMetadata(metadata) && !hasTrustVerificationMetadata(metadata) && !hasGovernedQueryMetadata(metadata)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneMetadata(value Metadata) Metadata {
	copy := value
	copy.WorkspaceRevision = cloneInt64(value.WorkspaceRevision)
	copy.WorkspaceSourceID = cloneString(value.WorkspaceSourceID)
	copy.SourceScopeID = cloneString(value.SourceScopeID)
	copy.SourceScopeRevision = cloneInt64(value.SourceScopeRevision)
	copy.ScopeConfigHash = cloneString(value.ScopeConfigHash)
	copy.AccessMode = cloneString(value.AccessMode)
	copy.Enabled = cloneBool(value.Enabled)
	copy.SourceConnectionID = cloneString(value.SourceConnectionID)
	copy.ConnectorJobID = cloneString(value.ConnectorJobID)
	copy.SyncRunID = cloneString(value.SyncRunID)
	copy.QuestionRunID = cloneString(value.QuestionRunID)
	copy.ModelRunID = cloneString(value.ModelRunID)
	copy.CitationNumber = cloneInt64(value.CitationNumber)
	copy.ManifestHash = cloneString(value.ManifestHash)
	copy.PolicyRevision = cloneString(value.PolicyRevision)
	copy.ReasonCodes = append([]string(nil), value.ReasonCodes...)
	copy.RemoteAddressDigest = cloneString(value.RemoteAddressDigest)
	copy.UserAgentFamily = cloneString(value.UserAgentFamily)
	copy.AnswerDocumentVersion = cloneInt64(value.AnswerDocumentVersion)
	copy.AmendmentClass = cloneString(value.AmendmentClass)
	copy.AuthorityOperation = cloneString(value.AuthorityOperation)
	copy.AuthorityResultID = cloneString(value.AuthorityResultID)
	copy.AuthorityResultHash = cloneString(value.AuthorityResultHash)
	copy.AuthorityParentID = cloneString(value.AuthorityParentID)
	copy.AuthorityParentHash = cloneString(value.AuthorityParentHash)
	copy.AuthorityRevocationID = cloneString(value.AuthorityRevocationID)
	copy.AuthorityRevocationHash = cloneString(value.AuthorityRevocationHash)
	copy.AuthorityReasonCode = cloneString(value.AuthorityReasonCode)
	copy.TargetPrincipalID = cloneString(value.TargetPrincipalID)
	copy.WorkspaceConfigurationHash = cloneString(value.WorkspaceConfigurationHash)
	copy.ConfirmationActorGrantID = cloneString(value.ConfirmationActorGrantID)
	copy.ConfirmationActorGrantRevision = cloneInt64(value.ConfirmationActorGrantRevision)
	copy.ConfirmationActorGrantHash = cloneString(value.ConfirmationActorGrantHash)
	copy.WarningVersion = cloneString(value.WarningVersion)
	copy.WarningContractHash = cloneString(value.WarningContractHash)
	copy.AcknowledgementCode = cloneString(value.AcknowledgementCode)
	copy.RotationDomain = cloneString(value.RotationDomain)
	copy.KeyReference = cloneString(value.KeyReference)
	copy.KeyVersion = cloneInt64(value.KeyVersion)
	copy.GovernedQueryConnectionID = cloneString(value.GovernedQueryConnectionID)
	copy.GovernedQueryExposedSchemaRevision = cloneInt64(value.GovernedQueryExposedSchemaRevision)
	copy.GovernedQuerySQLHash = cloneString(value.GovernedQuerySQLHash)
	copy.GovernedQueryCostEstimate = cloneInt64(value.GovernedQueryCostEstimate)
	copy.GovernedQueryRowCount = cloneInt64(value.GovernedQueryRowCount)
	copy.GovernedQueryResultDigest = cloneString(value.GovernedQueryResultDigest)
	copy.GovernedQueryOutcome = cloneString(value.GovernedQueryOutcome)
	return copy
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
