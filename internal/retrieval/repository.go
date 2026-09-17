// Package retrieval is the typed persistence boundary for retrieval
// authorization snapshots.  It stores only tenant-bound hashes, references and
// trusted catalog projections; model-visible candidate text is carried through
// the encrypted candidate-set owner branch.
package retrieval

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	artifactrepository "knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

const maximumGeneration = int64(9007199254740991)

// ErrorCode is safe to map to metrics or a transport response.  Causes stay
// inside trusted diagnostics and never expose SQL, identifiers or plaintext.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "RETRIEVAL_SNAPSHOT_INVALID"
	CodePersistence ErrorCode = "RETRIEVAL_SNAPSHOT_PERSISTENCE_FAILED"
	CodeDenied      ErrorCode = "RETRIEVAL_SNAPSHOT_DENIED"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodePersistence
}

// Repository holds the one encrypted owner branch needed by the candidate
// artifact.  All row writes happen in the caller's already-authorized app
// transaction; there is no pool or raw SQL escape hatch here.
type Repository struct {
	artifacts *artifactrepository.Repository
}

func NewRepository() (*Repository, error) {
	binding, err := artifactrepository.NewBinding(
		artifactcrypto.AuthorizedCandidateSet,
		"app.question_authorized_candidate_set_bind_canonical",
		"app.question_authorized_candidate_set_read_canonical",
		authorizeCandidateSet,
	)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	store, err := artifactrepository.New(binding)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	return &Repository{artifacts: store}, nil
}

type CorpusSnapshot struct {
	ID                  string
	OrganizationID      string
	QuestionRunID       string
	SourceScopeID       string
	SourceScopeRevision int64
	AccessMode          string
	ScopeConfigHash     string
	ConnectorType       string
	ConnectorVersion    string
	Health              string
	ContentWatermark    int64
	LastSuccessfulSync  *time.Time
	ACLFreshAt          *time.Time
	CapturedAt          time.Time
}

type CandidateSet struct {
	OrganizationID   string
	QuestionRunID    string
	CandidateCount   int64
	CandidateSetHash string
	CanonicalBytes   []byte
}

type Candidate struct {
	OrganizationID         string
	QuestionRunID          string
	Ordinal                int64
	EvidenceFragmentID     string
	SourceVersionID        string
	ExtractionID           string
	EvidenceTextHash       string
	ExactContextHash       string
	AuthorizationGrantHash string
}

type ContextEntry struct {
	OrganizationID                  string
	QuestionRunID                   string
	Ordinal                         int64
	SourceObjectID                  string
	SourceVersionID                 string
	SourceVersionState              string
	SourceVersionRetentionState     string
	SourceVersionQueryable          bool
	SourceVersionRetentionFence     int64
	ExtractionID                    string
	ActiveExtractionID              string
	ActivationRevision              int64
	ExtractionRetentionState        string
	ExtractionQueryable             bool
	ExtractionRetentionFenceAtStart int64
	EvidenceFragmentID              string
	ExtractionProfileHash           string
	SourceVersionContentHash        string
	EvidenceTextHash                string
	AnchorHash                      string
	ExactContextHash                string
	SourceScopeID                   string
	SourceScopeRevision             int64
	AccessMode                      string
	MembershipState                 string
	PolicyDecisionID                string
	PolicyDecision                  string
	PrincipalSetSnapshotID          string
	PrincipalSetSnapshotHash        string
	PrincipalSetCapturedAt          time.Time
	PrincipalSetExpiresAt           time.Time
	AuthorizedAt                    time.Time
	ACLSnapshotID                   string
	ACLSnapshotHash                 string
	ACLSnapshotStatus               string
	ACLResolvedAt                   time.Time
	ACLExpiresAt                    time.Time
}

type AuthorizationSnapshot struct {
	OrganizationID             string
	QuestionRunID              string
	CapturedAt                 time.Time
	PipelineVersion            string
	PipelineProfileHash        string
	ModelExecutionPlanHash     string
	EmbeddingModelRunID        string
	EmbeddingOutputHash        string
	AuthorizedCandidateSetHash string
	RerankingModelRunID        string
	RerankingOutputHash        string
	AuthorizedCandidateCount   int64
	ContextCount               int64
	Truncated                  bool
	TruncationReason           string
	ErrorCodes                 []string
	CanonicalBytes             []byte
	SnapshotHash               string
}

// AccessProvenance is the server-owned identity and policy decision captured
// for one Question Run. IDs are minted here, while every other value is read
// from the trusted PostgreSQL projections in the same transaction.
type AccessProvenance struct {
	PolicyDecisionID         string
	PolicyRevisionID         string
	PolicyRevision           int64
	PolicyHash               string
	PrincipalSetSnapshotID   string
	PrincipalSetSnapshotHash string
	PrincipalID              string
	PrincipalStatus          string
	PrincipalSessionRevision int64
	MembershipID             string
	MembershipRole           string
	CapturedAt               time.Time
	ExpiresAt                time.Time
}

type principalSetEntry struct {
	Namespace        string `json:"namespace"`
	Type             string `json:"type"`
	SubjectDigest    string `json:"subject_digest"`
	DigestKeyVersion int64  `json:"digest_key_version"`
	ProviderRevision int64  `json:"provider_revision"`
}

// CaptureAccessProvenance records the exact principal, membership and policy
// facts used to admit a Question Run. It deliberately has no caller-supplied
// ID or hash fields: IDs are server-generated and hashes cover canonical bytes
// made from the rows read in this transaction.
func (repository *Repository) CaptureAccessProvenance(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, questionRunID string, capturedAt time.Time) (AccessProvenance, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(questionRunID) || capturedAt.IsZero() {
		return AccessProvenance{}, &Error{code: CodeInvalid}
	}
	var (
		workspaceID, principalID, principalStatus, membershipID, membershipRole string
		policyID, policyHash                                                    string
		workspaceRevision, policyRevision, sessionRevision                      int64
	)
	err := transaction.QueryRow(ctx, `
		SELECT run.workspace_id, run.workspace_revision, run.created_by,
		       principal.status, principal.session_revision,
		       member.id, member.role,
		       policy.policy_revision_id, policy.revision, policy.policy_hash
		  FROM public.question_run run
		  JOIN public.principal principal
		    ON principal.organization_id = run.organization_id
		   AND principal.id = run.created_by
		  JOIN public.workspace_member member
		    ON member.organization_id = run.organization_id
		   AND member.workspace_id = run.workspace_id
		   AND member.principal_id = run.created_by
		   AND member.removed_at IS NULL
		  JOIN public.organization organization
		    ON organization.id = run.organization_id
		  JOIN public.organization_policy_revision policy
		    ON policy.organization_id = organization.id
		   AND policy.revision = organization.policy_revision
		 WHERE run.organization_id = $1 AND run.id = $2
		   AND run.result_status IN ('QUEUED', 'RUNNING')
		   AND run.created_by = $3
		   AND member.role IN ('OWNER', 'MANAGER', 'MEMBER')
		   AND organization.status = 'ACTIVE'
		   AND run.started_at = $4
		FOR SHARE OF run`, access.OrganizationID, questionRunID, access.PrincipalID, capturedAt).Scan(
		&workspaceID, &workspaceRevision, &principalID, &principalStatus, &sessionRevision,
		&membershipID, &membershipRole, &policyID, &policyRevision, &policyHash)
	if err != nil {
		if database.IsNotFound(err) {
			return AccessProvenance{}, &Error{code: CodeDenied}
		}
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	principalSnapshotID, err := ids.New("pss")
	if err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	policyDecisionID, err := ids.New("pdec")
	if err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	expiresAt := capturedAt.UTC().Add(24 * time.Hour)
	principalEntries, identityProviderRevision, err := activePrincipalSetEntries(ctx, transaction, access.OrganizationID, principalID)
	if err != nil {
		return AccessProvenance{}, err
	}
	principalBytes, err := canon.CanonicalJSON(struct {
		SchemaVersion            string              `json:"schema_version"`
		OrganizationID           string              `json:"organization_id"`
		HumanPrincipalID         string              `json:"human_principal_id"`
		IdentityProviderRevision int64               `json:"identity_provider_revision"`
		SessionRevision          int64               `json:"session_revision"`
		EffectivePrincipals      []principalSetEntry `json:"effective_principals"`
		CapturedAt               time.Time           `json:"captured_at"`
		ExpiresAt                time.Time           `json:"expires_at"`
	}{"question-principal-set-v1", access.OrganizationID, principalID, identityProviderRevision, sessionRevision,
		principalEntries, capturedAt.UTC(), expiresAt})
	if err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	principalHash := hashBytes(principalBytes)
	decisionBytes, err := canon.CanonicalJSON(struct {
		SchemaVersion            string    `json:"schema_version"`
		OrganizationID           string    `json:"organization_id"`
		QuestionRunID            string    `json:"question_run_id"`
		WorkspaceID              string    `json:"workspace_id"`
		WorkspaceRevision        int64     `json:"workspace_revision"`
		PrincipalID              string    `json:"principal_id"`
		MembershipID             string    `json:"membership_id"`
		MembershipRole           string    `json:"membership_role"`
		PolicyRevisionID         string    `json:"policy_revision_id"`
		PolicyRevision           int64     `json:"policy_revision"`
		PolicyHash               string    `json:"policy_hash"`
		Decision                 string    `json:"decision"`
		Operation                string    `json:"operation"`
		ResourceType             string    `json:"resource_type"`
		PrincipalSetSnapshotID   string    `json:"principal_set_snapshot_id"`
		PrincipalSetSnapshotHash string    `json:"principal_set_snapshot_hash"`
		DecidedAt                time.Time `json:"decided_at"`
	}{"question-policy-decision-v1", access.OrganizationID, questionRunID, workspaceID, workspaceRevision,
		principalID, membershipID, membershipRole, policyID, policyRevision, policyHash, "ALLOW",
		"question.evidence.read", "QUESTION_RUN", principalSnapshotID, principalHash, capturedAt.UTC()})
	if err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	decisionHash := hashBytes(decisionBytes)
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.principal_set_snapshot
			(organization_id, id, human_principal_id, identity_provider_revision,
			 session_revision, captured_at, expires_at, status, canonical_bytes, content_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'RESOLVED',$8,$9)`,
		access.OrganizationID, principalSnapshotID, principalID, identityProviderRevision,
		sessionRevision, capturedAt.UTC(), expiresAt, principalBytes, principalHash); err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	for _, entry := range principalEntries {
		if _, err := transaction.Exec(ctx, `
			INSERT INTO public.principal_set_snapshot_entry
				(organization_id, principal_set_snapshot_id, namespace, type,
				 subject_digest, digest_key_version, provider_revision)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, access.OrganizationID, principalSnapshotID,
			entry.Namespace, entry.Type, entry.SubjectDigest, entry.DigestKeyVersion, entry.ProviderRevision); err != nil {
			return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
		}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.policy_decision
			(organization_id, id, actor_principal_id, operation, resource_type,
			 resource_id, workspace_id, workspace_revision, policy_revision,
			 policy_revision_number, policy_hash, decision, membership_id,
			 membership_role, principal_set_snapshot_id, principal_set_snapshot_hash,
			 decided_at, canonical_bytes, decision_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		access.OrganizationID, policyDecisionID, principalID, "question.evidence.read", "QUESTION_RUN",
		questionRunID, workspaceID, workspaceRevision, policyID, policyRevision, policyHash, "ALLOW",
		membershipID, membershipRole, principalSnapshotID, principalHash, capturedAt.UTC(), decisionBytes, decisionHash); err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	provenanceBytes, err := canon.CanonicalJSON(struct {
		SchemaVersion            string    `json:"schema_version"`
		OrganizationID           string    `json:"organization_id"`
		QuestionRunID            string    `json:"question_run_id"`
		PolicyDecisionID         string    `json:"policy_decision_id"`
		PolicyRevisionID         string    `json:"policy_revision_id"`
		PolicyRevision           int64     `json:"policy_revision"`
		PolicyHash               string    `json:"policy_hash"`
		PrincipalSetSnapshotID   string    `json:"principal_set_snapshot_id"`
		PrincipalSetSnapshotHash string    `json:"principal_set_snapshot_hash"`
		PrincipalID              string    `json:"principal_id"`
		PrincipalStatus          string    `json:"principal_status"`
		PrincipalSessionRevision int64     `json:"principal_session_revision"`
		MembershipID             string    `json:"membership_id"`
		MembershipRole           string    `json:"membership_role"`
		CapturedAt               time.Time `json:"captured_at"`
		ExpiresAt                time.Time `json:"expires_at"`
	}{"question-access-provenance-v1", access.OrganizationID, questionRunID, policyDecisionID,
		policyID, policyRevision, policyHash, principalSnapshotID, principalHash, principalID,
		principalStatus, sessionRevision, membershipID, membershipRole, capturedAt.UTC(), expiresAt})
	if err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	provenanceHash := hashBytes(provenanceBytes)
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.question_access_provenance
			(organization_id, question_run_id, policy_decision_id, policy_revision_id,
			 policy_revision, policy_hash, principal_set_snapshot_id,
			principal_set_snapshot_hash, principal_id, principal_status,
			principal_session_revision, membership_id, membership_role,
			captured_at, expires_at, principal_canonical_bytes,
			policy_canonical_bytes, provenance_canonical_bytes, provenance_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
		access.OrganizationID, questionRunID, policyDecisionID, policyID, policyRevision, policyHash,
		principalSnapshotID, principalHash, principalID, principalStatus, sessionRevision,
		membershipID, membershipRole, capturedAt.UTC(), expiresAt, principalBytes, decisionBytes,
		provenanceBytes, provenanceHash); err != nil {
		return AccessProvenance{}, &Error{code: CodePersistence, cause: err}
	}
	return AccessProvenance{PolicyDecisionID: policyDecisionID, PolicyRevisionID: policyID,
		PolicyRevision: policyRevision, PolicyHash: policyHash, PrincipalSetSnapshotID: principalSnapshotID,
		PrincipalSetSnapshotHash: principalHash, PrincipalID: principalID, PrincipalStatus: principalStatus,
		PrincipalSessionRevision: sessionRevision, MembershipID: membershipID, MembershipRole: membershipRole,
		CapturedAt: capturedAt.UTC(), ExpiresAt: expiresAt}, nil
}

func activePrincipalSetEntries(ctx context.Context, transaction database.Transaction, organizationID, principalID string) ([]principalSetEntry, int64, error) {
	rows, err := transaction.Query(ctx, `
		SELECT 'oidc:' || provider.id, principal.type,
		       identity.external_subject_digest, identity.digest_key_version,
		       provider.current_revision
		  FROM public.external_identity identity
		  JOIN public.principal principal
		    ON principal.organization_id = identity.organization_id
		   AND principal.id = identity.principal_id
		  JOIN public.oidc_provider provider
		    ON provider.organization_id = identity.organization_id
		   AND provider.id = identity.provider_id
		 WHERE identity.organization_id = $1
		   AND identity.principal_id = $2
		   AND identity.status = 'ACTIVE'
		   AND provider.status = 'ACTIVE'
		 ORDER BY provider.id, identity.external_subject_digest`, organizationID, principalID)
	if err != nil {
		return nil, 0, &Error{code: CodePersistence, cause: err}
	}
	entries := make([]principalSetEntry, 0)
	var providerRevision int64
	for rows.Next() {
		var entry principalSetEntry
		if err := rows.Scan(&entry.Namespace, &entry.Type, &entry.SubjectDigest, &entry.DigestKeyVersion, &entry.ProviderRevision); err != nil {
			rows.Close()
			return nil, 0, &Error{code: CodePersistence, cause: err}
		}
		if entry.ProviderRevision > providerRevision {
			providerRevision = entry.ProviderRevision
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, &Error{code: CodePersistence, cause: err}
	}
	rows.Close()
	return entries, providerRevision, nil
}

// ResolveEvidence returns only the trusted catalog projection needed to form
// one candidate/context pair. It is the materializer used by Question Run;
// caller-provided hashes or policy strings cannot enter this projection.
func (repository *Repository) ResolveEvidence(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, questionRunID, evidenceID string, ordinal int64, authorizedAt time.Time) (Candidate, ContextEntry, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil || !validOpaque(questionRunID) ||
		!validOpaque(evidenceID) || ordinal < 1 || ordinal > maximumGeneration || authorizedAt.IsZero() {
		return Candidate{}, ContextEntry{}, &Error{code: CodeInvalid}
	}
	var (
		entry                                                                  ContextEntry
		principalStatus, policyDecision, policyDecisionID, principalSnapshotID string
		principalSnapshotHash                                                  string
		aclID, aclHash, aclStatus                                              sql.NullString
		aclResolved, aclExpires                                                sql.NullTime
	)
	err := transaction.QueryRow(ctx, `
		SELECT o.id, v.id, v.state, vr.state, vr.queryable, vr.retention_fence,
		       e.id, ae.extraction_id, er.state, er.queryable, e.retention_fence_at_start,
		       f.id, e.profile_hash, v.content_hash, f.text_hash, f.anchor_hash,
		       m.source_scope_id, m.source_scope_revision, b.access_mode, m.membership_state,
		       p.policy_decision_id, pd.decision, p.principal_set_snapshot_id,
		       p.principal_set_snapshot_hash, p.captured_at, p.expires_at, p.principal_status,
		       a.id, a.content_hash, a.status, a.resolved_at, a.expires_at
		  FROM public.question_run run
		  JOIN public.evidence_fragment f ON f.organization_id=run.organization_id AND f.id=$3
		  JOIN public.source_version v ON v.organization_id=f.organization_id AND v.id=f.source_version_id
		  JOIN public.source_object o ON o.organization_id=v.organization_id AND o.id=v.source_object_id
		  JOIN public.source_version_retention vr ON vr.organization_id=v.organization_id AND vr.source_version_id=v.id
		  JOIN public.source_extraction e ON e.organization_id=f.organization_id AND e.id=f.extraction_id
		  JOIN public.source_extraction_retention er ON er.organization_id=e.organization_id AND er.extraction_id=e.id
		  JOIN public.source_version_active_extraction ae ON ae.organization_id=v.organization_id AND ae.source_version_id=v.id AND ae.extraction_id=e.id
		  JOIN public.source_object_scope m ON m.organization_id=o.organization_id AND m.source_object_id=o.id AND m.membership_state='ACTIVE'
		  JOIN public.workspace_revision_source b ON b.organization_id=m.organization_id AND b.workspace_id=run.workspace_id AND b.workspace_revision=run.workspace_revision AND b.source_scope_id=m.source_scope_id AND b.source_scope_revision=m.source_scope_revision AND b.enabled
		  JOIN public.question_access_provenance p ON p.organization_id=run.organization_id AND p.question_run_id=run.id
		  JOIN public.policy_decision pd ON pd.organization_id=p.organization_id AND pd.id=p.policy_decision_id
		  JOIN public.principal_set_snapshot ps ON ps.organization_id=p.organization_id AND ps.id=p.principal_set_snapshot_id
		  JOIN public.principal actor ON actor.organization_id=ps.organization_id AND actor.id=ps.human_principal_id AND actor.status='ACTIVE' AND actor.session_revision=p.principal_session_revision
		  JOIN public.organization organization ON organization.id=run.organization_id AND organization.status='ACTIVE'
		  JOIN public.organization_policy_revision current_policy ON current_policy.organization_id=organization.id AND current_policy.revision=organization.policy_revision AND current_policy.policy_revision_id=pd.policy_revision AND current_policy.policy_hash=pd.policy_hash
		  JOIN public.workspace_member current_member ON current_member.organization_id=run.organization_id AND current_member.id=p.membership_id AND current_member.workspace_id=run.workspace_id AND current_member.principal_id=actor.id AND current_member.role IN ('OWNER','MANAGER','MEMBER') AND current_member.removed_at IS NULL AND current_member.valid_from_revision <= run.workspace_revision AND (current_member.valid_to_revision IS NULL OR current_member.valid_to_revision >= run.workspace_revision)
		  LEFT JOIN LATERAL app.question_acl_snapshot(o.id) a ON true
		 WHERE run.organization_id=$1 AND run.id=$2 AND run.result_status IN ('QUEUED','RUNNING')
		   AND run.created_by=actor.id AND run.started_at=p.captured_at
		   AND app.evidence_fragment_readable(f.id, run.workspace_id)
		   AND pd.decision='ALLOW' AND pd.operation='question.evidence.read' AND pd.resource_type='QUESTION_RUN' AND pd.resource_id=run.id
		   AND ps.status='RESOLVED' AND ps.content_hash=p.principal_set_snapshot_hash
		   AND p.policy_revision_id=pd.policy_revision AND p.policy_revision=pd.policy_revision_number AND p.policy_hash=pd.policy_hash
		   AND $4 >= p.captured_at AND $4 < p.expires_at
		 ORDER BY m.source_scope_id LIMIT 1`, access.OrganizationID, questionRunID, evidenceID, authorizedAt.UTC()).Scan(
		&entry.SourceObjectID, &entry.SourceVersionID, &entry.SourceVersionState, &entry.SourceVersionRetentionState,
		&entry.SourceVersionQueryable, &entry.SourceVersionRetentionFence, &entry.ExtractionID, &entry.ActiveExtractionID,
		&entry.ExtractionRetentionState, &entry.ExtractionQueryable, &entry.ExtractionRetentionFenceAtStart,
		&entry.EvidenceFragmentID, &entry.ExtractionProfileHash, &entry.SourceVersionContentHash, &entry.EvidenceTextHash,
		&entry.AnchorHash, &entry.SourceScopeID, &entry.SourceScopeRevision, &entry.AccessMode, &entry.MembershipState,
		&policyDecisionID, &policyDecision, &principalSnapshotID, &principalSnapshotHash, &entry.PrincipalSetCapturedAt,
		&entry.PrincipalSetExpiresAt, &principalStatus, &aclID, &aclHash, &aclStatus, &aclResolved, &aclExpires)
	if err != nil {
		if database.IsNotFound(err) {
			return Candidate{}, ContextEntry{}, &Error{code: CodeDenied}
		}
		return Candidate{}, ContextEntry{}, &Error{code: CodePersistence, cause: err}
	}
	entry.OrganizationID, entry.QuestionRunID, entry.Ordinal = access.OrganizationID, questionRunID, ordinal
	entry.ActivationRevision = 1
	// Resolve the exact active-extraction revision separately so the entry is
	// never allowed to invent a catalog ordinal.
	if err := transaction.QueryRow(ctx, `SELECT activation_revision FROM public.source_version_active_extraction WHERE organization_id=$1 AND source_version_id=$2 AND extraction_id=$3`, access.OrganizationID, entry.SourceVersionID, entry.ExtractionID).Scan(&entry.ActivationRevision); err != nil {
		return Candidate{}, ContextEntry{}, &Error{code: CodePersistence, cause: err}
	}
	entry.PolicyDecisionID, entry.PolicyDecision = policyDecisionID, policyDecision
	entry.PrincipalSetSnapshotID, entry.PrincipalSetSnapshotHash = principalSnapshotID, principalSnapshotHash
	entry.AuthorizedAt = authorizedAt.UTC()
	if aclID.Valid {
		entry.ACLSnapshotID, entry.ACLSnapshotHash, entry.ACLSnapshotStatus = aclID.String, aclHash.String, aclStatus.String
		entry.ACLResolvedAt, entry.ACLExpiresAt = aclResolved.Time, aclExpires.Time
	}
	contextBytes, err := canon.CanonicalJSON(struct {
		EvidenceID, SourceVersionID, ExtractionID, SourceScopeID, AccessMode string
		EvidenceTextHash, AnchorHash, ContentHash, PrincipalSetSnapshotHash  string
		PolicyDecisionID                                                     string
		Ordinal, SourceScopeRevision                                         int64
	}{entry.EvidenceFragmentID, entry.SourceVersionID, entry.ExtractionID, entry.SourceScopeID, entry.AccessMode,
		entry.EvidenceTextHash, entry.AnchorHash, entry.SourceVersionContentHash, entry.PrincipalSetSnapshotHash,
		entry.PolicyDecisionID, entry.Ordinal, entry.SourceScopeRevision})
	if err != nil {
		return Candidate{}, ContextEntry{}, &Error{code: CodePersistence, cause: err}
	}
	entry.ExactContextHash = hashBytes(contextBytes)
	grantBytes, err := canon.CanonicalJSON(struct {
		PolicyDecisionID, PrincipalSetSnapshotID, EvidenceID string
		AuthorizedAt                                         time.Time
	}{entry.PolicyDecisionID, entry.PrincipalSetSnapshotID, entry.EvidenceFragmentID, entry.AuthorizedAt})
	if err != nil {
		return Candidate{}, ContextEntry{}, &Error{code: CodePersistence, cause: err}
	}
	candidate := Candidate{OrganizationID: access.OrganizationID, QuestionRunID: questionRunID, Ordinal: ordinal,
		EvidenceFragmentID: entry.EvidenceFragmentID, SourceVersionID: entry.SourceVersionID, ExtractionID: entry.ExtractionID,
		EvidenceTextHash: entry.EvidenceTextHash, ExactContextHash: entry.ExactContextHash, AuthorizationGrantHash: hashBytes(grantBytes)}
	return candidate, entry, nil
}

func (repository *Repository) CreateCorpusSnapshot(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, snapshot CorpusSnapshot) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		snapshot.OrganizationID != access.OrganizationID || !validOpaque(snapshot.ID) ||
		!validOpaque(snapshot.QuestionRunID) || !validOpaque(snapshot.SourceScopeID) ||
		snapshot.SourceScopeRevision < 1 || snapshot.SourceScopeRevision > maximumGeneration ||
		!validSHA256(snapshot.ScopeConfigHash) || !validOpaque(snapshot.ConnectorVersion) ||
		snapshot.ContentWatermark < 0 || snapshot.ContentWatermark > maximumGeneration || snapshot.CapturedAt.IsZero() {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.question_corpus_snapshot
			(organization_id, id, question_run_id, source_scope_id, source_scope_revision,
			 access_mode, scope_config_hash, connector_type, connector_version, health,
			 content_watermark, last_successful_sync, acl_fresh_at, captured_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		snapshot.OrganizationID, snapshot.ID, snapshot.QuestionRunID, snapshot.SourceScopeID,
		snapshot.SourceScopeRevision, snapshot.AccessMode, snapshot.ScopeConfigHash,
		snapshot.ConnectorType, snapshot.ConnectorVersion, snapshot.Health, snapshot.ContentWatermark,
		snapshot.LastSuccessfulSync, snapshot.ACLFreshAt, snapshot.CapturedAt); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func (repository *Repository) CreateCandidateSet(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, set CandidateSet) error {
	if repository == nil || repository.artifacts == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		set.OrganizationID != access.OrganizationID || !validOpaque(set.QuestionRunID) ||
		set.CandidateCount < 0 || set.CandidateCount > maximumGeneration || !validSHA256(set.CandidateSetHash) ||
		len(set.CanonicalBytes) == 0 || len(set.CanonicalBytes) > 1<<20 {
		return &Error{code: CodeInvalid}
	}
	if hashBytes(set.CanonicalBytes) != set.CandidateSetHash {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.question_authorized_candidate_set
			(organization_id, question_run_id, candidate_count, canonical_artifact_id, candidate_set_hash)
		VALUES ($1,$2,$3,NULL,$4)`, set.OrganizationID, set.QuestionRunID, set.CandidateCount, set.CandidateSetHash); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// BindCandidateSetArtifact completes a row inserted by CreateCandidateSet.
// Keeping sealing/binding explicit avoids making this repository a key holder.
func (repository *Repository) BindCandidateSetArtifact(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, questionRunID, artifactID string, envelope artifactcrypto.Envelope) error {
	if repository == nil || repository.artifacts == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(questionRunID) || !validOpaque(artifactID) || !envelope.Valid() ||
		envelope.OrganizationID() != access.OrganizationID || envelope.ResourceID() != questionRunID {
		return &Error{code: CodeInvalid}
	}
	var candidateSetHash string
	if err := transaction.QueryRow(ctx, `
		SELECT candidate_set_hash
		  FROM public.question_authorized_candidate_set
		 WHERE organization_id=$1 AND question_run_id=$2`, access.OrganizationID, questionRunID).Scan(&candidateSetHash); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if envelope.PlaintextHash() != candidateSetHash {
		return &Error{code: CodeInvalid}
	}
	if err := repository.artifacts.Store(ctx, transaction, access, artifactcrypto.AuthorizedCandidateSet,
		questionRunID, artifactID, envelope); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func (repository *Repository) AddCandidate(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, candidate Candidate) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		candidate.OrganizationID != access.OrganizationID || !validOpaque(candidate.QuestionRunID) ||
		candidate.Ordinal < 1 || candidate.Ordinal > maximumGeneration || !validOpaque(candidate.EvidenceFragmentID) ||
		!validOpaque(candidate.SourceVersionID) || !validOpaque(candidate.ExtractionID) ||
		!validHMAC(candidate.EvidenceTextHash) || !validSHA256(candidate.ExactContextHash) ||
		!validSHA256(candidate.AuthorizationGrantHash) {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.question_authorized_candidate
			(organization_id, question_run_id, ordinal, evidence_fragment_id, source_version_id,
			 extraction_id, evidence_text_hash, exact_context_hash, authorization_grant_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		candidate.OrganizationID, candidate.QuestionRunID, candidate.Ordinal, candidate.EvidenceFragmentID,
		candidate.SourceVersionID, candidate.ExtractionID, candidate.EvidenceTextHash,
		candidate.ExactContextHash, candidate.AuthorizationGrantHash); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func (repository *Repository) AddContextEntry(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, entry ContextEntry) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		entry.OrganizationID != access.OrganizationID || !validOpaque(entry.QuestionRunID) ||
		entry.Ordinal < 1 || entry.Ordinal > maximumGeneration || entry.ActivationRevision < 1 ||
		entry.SourceScopeRevision < 1 || entry.SourceVersionRetentionFence < 0 ||
		entry.ExtractionRetentionFenceAtStart < 0 || entry.PrincipalSetCapturedAt.IsZero() ||
		entry.PrincipalSetExpiresAt.IsZero() || entry.AuthorizedAt.IsZero() ||
		!validHMAC(entry.EvidenceTextHash) || !validHMAC(entry.AnchorHash) ||
		!validSHA256(entry.ExtractionProfileHash) || !validSHA256(entry.SourceVersionContentHash) ||
		!validSHA256(entry.ExactContextHash) || !validSHA256(entry.PrincipalSetSnapshotHash) ||
		(entry.ACLSnapshotHash != "" && !validSHA256(entry.ACLSnapshotHash)) {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.question_retrieval_context_entry
			(organization_id, question_run_id, ordinal, source_object_id, source_version_id,
			 source_version_state, source_version_retention_state, source_version_queryable,
			 source_version_retention_fence, extraction_id, active_extraction_id,
			 activation_revision, extraction_retention_state, extraction_queryable,
			 extraction_retention_fence_at_start, evidence_fragment_id, extraction_profile_hash,
			 source_version_content_hash, evidence_text_hash, anchor_hash, exact_context_hash,
			 source_scope_id, source_scope_revision, access_mode, membership_state,
			 policy_decision_id, policy_decision, principal_set_snapshot_id,
			 principal_set_snapshot_hash, principal_set_captured_at, principal_set_expires_at,
			 authorized_at, acl_snapshot_id, acl_snapshot_hash, acl_snapshot_status,
			 acl_resolved_at, acl_expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37)`,
		entry.OrganizationID, entry.QuestionRunID, entry.Ordinal, entry.SourceObjectID, entry.SourceVersionID,
		entry.SourceVersionState, entry.SourceVersionRetentionState, entry.SourceVersionQueryable,
		entry.SourceVersionRetentionFence, entry.ExtractionID, entry.ActiveExtractionID,
		entry.ActivationRevision, entry.ExtractionRetentionState, entry.ExtractionQueryable,
		entry.ExtractionRetentionFenceAtStart, entry.EvidenceFragmentID, entry.ExtractionProfileHash,
		entry.SourceVersionContentHash, entry.EvidenceTextHash, entry.AnchorHash, entry.ExactContextHash,
		entry.SourceScopeID, entry.SourceScopeRevision, entry.AccessMode, entry.MembershipState,
		entry.PolicyDecisionID, entry.PolicyDecision, entry.PrincipalSetSnapshotID,
		entry.PrincipalSetSnapshotHash, entry.PrincipalSetCapturedAt, entry.PrincipalSetExpiresAt,
		entry.AuthorizedAt, nullableID(entry.ACLSnapshotID), nullableHash(entry.ACLSnapshotHash), nullableText(entry.ACLSnapshotStatus),
		nullableTime(entry.ACLResolvedAt), nullableTime(entry.ACLExpiresAt)); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func (repository *Repository) CreateAuthorizationSnapshot(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, snapshot AuthorizationSnapshot) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		snapshot.OrganizationID != access.OrganizationID || !validOpaque(snapshot.QuestionRunID) ||
		snapshot.CapturedAt.IsZero() || !validOpaque(snapshot.PipelineVersion) ||
		!validSHA256(snapshot.PipelineProfileHash) || !validSHA256(snapshot.AuthorizedCandidateSetHash) ||
		snapshot.AuthorizedCandidateCount < 0 || snapshot.ContextCount < 0 ||
		snapshot.AuthorizedCandidateCount > maximumGeneration || snapshot.ContextCount > maximumGeneration ||
		len(snapshot.CanonicalBytes) == 0 || len(snapshot.CanonicalBytes) > 1<<20 ||
		!validSHA256(snapshot.SnapshotHash) || hashBytes(snapshot.CanonicalBytes) != snapshot.SnapshotHash {
		return &Error{code: CodeInvalid}
	}
	if snapshot.ModelExecutionPlanHash != "" && !validSHA256(snapshot.ModelExecutionPlanHash) ||
		(snapshot.EmbeddingModelRunID == "") != (snapshot.EmbeddingOutputHash == "") ||
		(snapshot.RerankingModelRunID == "") != (snapshot.RerankingOutputHash == "") {
		return &Error{code: CodeInvalid}
	}
	if len(snapshot.ErrorCodes) > 32 {
		return &Error{code: CodeInvalid}
	}
	errorCodesValue := snapshot.ErrorCodes
	if errorCodesValue == nil {
		errorCodesValue = []string{}
	}
	errorCodes, err := json.Marshal(errorCodesValue)
	if err != nil {
		return &Error{code: CodeInvalid, cause: err}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.question_retrieval_authorization_snapshot
			(organization_id, question_run_id, captured_at, pipeline_version,
			 pipeline_profile_hash, model_execution_plan_hash, embedding_model_run_id,
			 embedding_output_hash, authorized_candidate_set_hash, reranking_model_run_id,
			 reranking_output_hash, authorized_candidate_count, context_count,
			 truncated, truncation_reason, error_codes_json, canonical_bytes, snapshot_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		snapshot.OrganizationID, snapshot.QuestionRunID, snapshot.CapturedAt, snapshot.PipelineVersion,
		snapshot.PipelineProfileHash, nullableHash(snapshot.ModelExecutionPlanHash), nullableID(snapshot.EmbeddingModelRunID),
		nullableHash(snapshot.EmbeddingOutputHash), snapshot.AuthorizedCandidateSetHash,
		nullableID(snapshot.RerankingModelRunID), nullableHash(snapshot.RerankingOutputHash),
		snapshot.AuthorizedCandidateCount, snapshot.ContextCount, snapshot.Truncated,
		nullableText(snapshot.TruncationReason), errorCodes, snapshot.CanonicalBytes, snapshot.SnapshotHash); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func authorizeCandidateSet(ctx context.Context, transaction database.Transaction, access database.AccessContext, owningRowID string) error {
	if access.Validate() != nil || !validOpaque(owningRowID) {
		return &Error{code: CodeDenied}
	}
	var allowed bool
	if err := transaction.QueryRow(ctx, `
		SELECT session_user = 'knowvault_app'
		   AND app.current_organization_id() = $1
		   AND EXISTS (
		       SELECT 1 FROM public.question_run
		        WHERE organization_id = $1 AND id = $2
		          AND result_status IN ('QUEUED', 'RUNNING')
		   )`, access.OrganizationID, owningRowID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return &Error{code: CodeDenied}
	}
	return nil
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validHMAC(value string) bool {
	const prefix = "hmac-sha256:k"
	if len(value) < len(prefix)+2+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	remainder := value[len(prefix):]
	separator := strings.IndexByte(remainder, ':')
	if separator < 1 || separator > 9 || separator+1+64 != len(remainder) {
		return false
	}
	version := remainder[:separator]
	if version[0] == '0' {
		return false
	}
	for _, character := range version {
		if character < '0' || character > '9' {
			return false
		}
	}
	for _, character := range remainder[separator+1:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func nullableID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableHash(value string) any { return nullableID(value) }
func nullableText(value string) any { return nullableID(value) }

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
