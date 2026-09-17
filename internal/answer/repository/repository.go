// Package repository persists the protected answer-document amendment layer
// (ADR-0076). Published versions are immutable: the repository only inserts
// superseding versions through the owner path with a hash chain and a closed
// amendment class, and every open re-checks fragment access. Question Run
// activation, search and the answer surface stay outside this boundary.
package repository

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// ErrorCode is content-free and is the only repository result suitable for a
// transport response or regular log.
type ErrorCode string

const (
	CodeRequestInvalid    ErrorCode = "ANSWER_REPOSITORY_REQUEST_INVALID"
	CodeDenied            ErrorCode = "ANSWER_REPOSITORY_DENIED"
	CodeUnavailable       ErrorCode = "ANSWER_REPOSITORY_UNAVAILABLE"
	CodeNotOwner          ErrorCode = "ANSWER_REPOSITORY_NOT_OWNER"
	CodeDocumentImmutable ErrorCode = "ANSWER_REPOSITORY_DOCUMENT_IMMUTABLE"
	CodeAmendmentRejected ErrorCode = "ANSWER_REPOSITORY_AMENDMENT_REJECTED"
)

// AmendmentClass is the closed amendment class set (ADR-0076 §1.2). A class
// outside this list is rejected by validation and by the database gate.
type AmendmentClass string

const (
	AmendmentSupersede AmendmentClass = "SUPERSEDE"
	AmendmentRetract   AmendmentClass = "RETRACT"
	AmendmentRedact    AmendmentClass = "REDACT"
)

func (class AmendmentClass) valid() bool {
	switch class {
	case AmendmentSupersede, AmendmentRetract, AmendmentRedact:
		return true
	}
	return false
}

type Error struct {
	code  ErrorCode
	cause error
}

func (errorValue *Error) Error() string { return string(errorValue.code) }
func (errorValue *Error) Unwrap() error { return errorValue.cause }

func CodeOf(err error) ErrorCode {
	var repositoryError *Error
	if errors.As(err, &repositoryError) {
		return repositoryError.code
	}
	return CodeUnavailable
}

// Store is the only answer-document persistence adapter. It owns the database
// and audit stores together so an amendment cannot commit without its audit
// event.
type Store struct {
	database *database.Store
	audit    *audit.Store
	now      func() time.Time
}

func New(databaseStore *database.Store, auditStore *audit.Store) (*Store, error) {
	if databaseStore == nil || auditStore == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return &Store{database: databaseStore, audit: auditStore, now: time.Now}, nil
}

// CitationRef binds one citation of the amended version to the exact evidence
// fragment it quotes. The cited excerpt and anchors live in the signed
// manifest; this boundary keeps only the re-check projection.
type CitationRef struct {
	Number             int64
	EvidenceFragmentID string
}

// AmendDocumentRequest describes one amendment insertion. The manifest itself
// (contents, claims, signature) is verified and stored by the future Question
// Run surface; this repository persists only the immutable version record.
type AmendDocumentRequest struct {
	OrganizationID      string
	WorkspaceID         string
	AnswerDocumentID    string
	Version             int64
	PreviousVersionHash *string
	AmendmentClass      *string
	AmendmentReason     *string
	ManifestHash        string
	ActorPrincipalID    string
	RequestID           string
	AuditEventID        string
	Citations           []CitationRef
}

// OpenDocumentRequest asks for the latest provable version of one document.
type OpenDocumentRequest struct {
	OrganizationID   string
	WorkspaceID      string
	AnswerDocumentID string
	RequestID        string
}

// OpenDocumentOutcome is the version record the read path admits as proof.
type OpenDocumentOutcome struct {
	Version        int64
	AmendmentClass *string
	ManifestHash   string
}

var manifestHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// AmendDocument inserts the version record, its citation projection and the
// success audit event in one transaction. The database gate accepts only the
// owner path with an exact hash chain, so a rejected amendment cannot leave a
// partial record or an event behind.
func (store *Store) AmendDocument(ctx context.Context, request AmendDocumentRequest) error {
	if err := store.validateAmend(request); err != nil {
		return err
	}
	access := database.AccessContext{
		OrganizationID: request.OrganizationID,
		PrincipalID:    request.ActorPrincipalID,
		RequestID:      request.RequestID,
	}
	return normalizeError(store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		if _, err := transaction.Exec(transactionContext, `
			INSERT INTO public.answer_document_version
				(organization_id, workspace_id, answer_document_id, version,
				 previous_version_hash, amendment_class, amendment_reason,
				 manifest_hash, actor_principal_id, request_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, request.OrganizationID, request.WorkspaceID, request.AnswerDocumentID, request.Version,
			request.PreviousVersionHash, request.AmendmentClass, request.AmendmentReason,
			request.ManifestHash, request.ActorPrincipalID, request.RequestID); err != nil {
			return err
		}
		for _, citation := range request.Citations {
			if _, err := transaction.Exec(transactionContext, `
				INSERT INTO public.answer_document_citation
					(organization_id, answer_document_id, version, citation_number, evidence_fragment_id)
				VALUES ($1, $2, $3, $4, $5)
			`, request.OrganizationID, request.AnswerDocumentID, request.Version,
				citation.Number, citation.EvidenceFragmentID); err != nil {
				return err
			}
		}
		version := request.Version
		if _, err := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
			EventID: request.AuditEventID, ActorType: audit.ActorHuman, ActorPrincipalID: pointer(request.ActorPrincipalID),
			WorkspaceID:  pointer(request.WorkspaceID),
			Action:       audit.ActionAnswerDocumentAmended,
			ResourceType: audit.ResourceAnswerDocument, ResourceID: request.AnswerDocumentID, RequestID: request.RequestID,
			Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
			Metadata: audit.Metadata{
				AnswerDocumentVersion: &version,
				AmendmentClass:        request.AmendmentClass,
			},
		}); err != nil {
			return err
		}
		return nil
	}))
}

// OpenDocument opens the latest version as proof. The read path re-checks
// fragment access on every open: a retracted/redacted statement, a version
// whose cited fragments were purged, and a version whose source scope left the
// workspace all answer the same closed denial and reveal no reason. The caller
// supplies the access context: the runtime open is a service-to-service read
// with a service principal that is not a workspace member.
func (store *Store) OpenDocument(ctx context.Context, access database.AccessContext, request OpenDocumentRequest) (OpenDocumentOutcome, error) {
	if err := store.validateOpen(request); err != nil {
		return OpenDocumentOutcome{}, err
	}
	outcome := OpenDocumentOutcome{}
	readErr := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		return transaction.QueryRow(transactionContext, `
			SELECT version, amendment_class, manifest_hash
			FROM app.open_answer_document($1, $2, $3)
		`, request.OrganizationID, request.WorkspaceID, request.AnswerDocumentID).
			Scan(&outcome.Version, &outcome.AmendmentClass, &outcome.ManifestHash)
	})
	if readErr != nil {
		if database.IsNotFound(readErr) {
			return OpenDocumentOutcome{}, &Error{code: CodeDenied}
		}
		return OpenDocumentOutcome{}, normalizeError(readErr)
	}
	return outcome, nil
}

func (store *Store) validateAmend(request AmendDocumentRequest) error {
	for _, value := range []string{request.OrganizationID, request.WorkspaceID, request.AnswerDocumentID,
		request.ActorPrincipalID, request.RequestID, request.AuditEventID} {
		if !validID(value) {
			return &Error{code: CodeRequestInvalid}
		}
	}
	if request.Version < 1 || !manifestHashPattern.MatchString(request.ManifestHash) || len(request.Citations) == 0 {
		return &Error{code: CodeRequestInvalid}
	}
	for _, citation := range request.Citations {
		if citation.Number < 1 || !validID(citation.EvidenceFragmentID) {
			return &Error{code: CodeRequestInvalid}
		}
	}
	if request.Version == 1 {
		if request.PreviousVersionHash != nil || request.AmendmentClass != nil || request.AmendmentReason != nil {
			return &Error{code: CodeRequestInvalid}
		}
		return nil
	}
	if request.PreviousVersionHash == nil || !manifestHashPattern.MatchString(*request.PreviousVersionHash) {
		return &Error{code: CodeRequestInvalid}
	}
	if request.AmendmentClass == nil || !AmendmentClass(*request.AmendmentClass).valid() {
		return &Error{code: CodeRequestInvalid}
	}
	if request.AmendmentReason == nil || len(*request.AmendmentReason) < 1 || len(*request.AmendmentReason) > 2000 {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func (store *Store) validateOpen(request OpenDocumentRequest) error {
	for _, value := range []string{request.OrganizationID, request.WorkspaceID, request.AnswerDocumentID, request.RequestID} {
		if !validID(value) {
			return &Error{code: CodeRequestInvalid}
		}
	}
	return nil
}

func normalizeError(err error) error {
	if err == nil {
		return nil
	}
	var repositoryError *Error
	if errors.As(err, &repositoryError) {
		return err
	}
	switch database.SQLStateCode(err) {
	case "42501":
		return &Error{code: CodeNotOwner, cause: err}
	case "55000":
		return &Error{code: CodeDocumentImmutable, cause: err}
	case "23514":
		return &Error{code: CodeAmendmentRejected, cause: err}
	}
	return &Error{code: CodeUnavailable, cause: err}
}

func validID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func pointer(value string) *string { return &value }
