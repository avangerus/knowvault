package question

import (
	"context"
	"errors"
	"log/slog"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// admissionJournal is the narrow slice of *audit.Store the governed question
// run actually needs for its single admission event. Accepting the interface
// (rather than depending on the concrete *audit.Store) mirrors the accepted
// governedask/evidence-read admission seams and lets a protected-independent
// unit test substitute a recording or failing journal. Production passes the
// concrete *audit.Store, which already has exactly this method.
type admissionJournal interface {
	Append(ctx context.Context, access database.AccessContext, input audit.EventInput) (audit.Event, error)
}

// emitAdmission persists the one admission event that must be durable before a
// governed workspace question run reads or returns any data. It records the
// effective actor kind (HUMAN | SERVICE), the access decision
// (OutcomeSuccess = admitted), the workspace id and the run id, and carries no
// question, answer or source content. The admission names the governed
// workspace as its resource: the run row is not created until admission is
// durable, so the run id travels in metadata while the workspace is the access
// that is being admitted. A failure is returned so the caller can fail closed
// with no data.
func (service *Service) emitAdmission(ctx context.Context, access database.AccessContext, workspaceID, runID string) error {
	if service == nil || service.newID == nil || service.now == nil {
		return errors.New("question: admission requires the service")
	}
	journal := service.admission
	if journal == nil {
		journal = service.audit
	}
	if journal == nil {
		return errors.New("question: admission requires the audit journal")
	}
	eventID, err := service.newID("aud")
	if err != nil {
		return err
	}
	qrunID := runID
	principal := access.PrincipalID
	_, err = journal.Append(ctx, access, audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspaceID,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionQuestionRunAdmitted,
		ResourceType:          audit.ResourceWorkspace,
		ResourceID:            workspaceID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeSuccess,
		ReferencedEvidenceIDs: []string{},
		Metadata:              audit.Metadata{QuestionRunID: &qrunID},
		OccurredAt:            service.now().UTC(),
	})
	return err
}

// withAdmission persists the mandatory admission event and only then invokes
// run, which performs every governed workspace read and returns the completed
// result. It is the same single-admission contract Create implements directly:
// Create must admit before its own previous-turn and idempotency reads, which
// are not all reachable from one closure, so it calls emitAdmission itself. If
// the admission cannot be recorded the typed unavailable error is returned and
// run is never invoked, so no answer, citation or row can be read or disclosed.
// The existing question.created / completed / failed outcome events are
// appended, unchanged, by run.
func (service *Service) withAdmission(ctx context.Context, access database.AccessContext, workspaceID, runID string, run func() (Run, error)) (Run, error) {
	if err := service.emitAdmission(ctx, access, workspaceID, runID); err != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	return run()
}

// emitRowsetAdmission persists the one admission event that must be durable
// before StructuredRowset's governed citation basis-panel read fetches any
// structured cell, snapshot row or source-version content. It reuses the
// registered evidence-read admission action and records the effective actor
// kind (HUMAN | SERVICE), the access decision (OutcomeSuccess = admitted), the
// governed workspace and the cited evidence fragment the rowset belongs to; it
// carries no cell, row, source or answer content. A failure is returned so the
// caller can fail closed with no rowset and no row.
func (service *Service) emitRowsetAdmission(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) error {
	if service == nil || service.newID == nil || service.now == nil {
		return errors.New("question: admission requires the service")
	}
	journal := service.admission
	if journal == nil {
		journal = service.audit
	}
	if journal == nil {
		return errors.New("question: admission requires the audit journal")
	}
	eventID, err := service.newID("aud")
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	_, err = journal.Append(ctx, access, audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspaceID,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionEvidenceReadAdmitted,
		ResourceType:          audit.ResourceCitation,
		ResourceID:            fragmentID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeSuccess,
		ReferencedEvidenceIDs: []string{fragmentID},
		OccurredAt:            service.now().UTC(),
	})
	return err
}

// rowsetReadFailureCode is the closed, content-free error code carried by the
// failure outcome matching a StructuredRowset admission; it names no fragment,
// tenant or infrastructure cause.
const rowsetReadFailureCode = "EVIDENCE_READ_FAILED"

// recordRowsetReadFailure appends the content-free failure outcome that matches
// the admission event StructuredRowset persisted before its governed read. It
// runs only on the error path, so the journal never holds an admission without
// its outcome for a failed rowset access. The append is best-effort: the
// governed read already failed and its error is returned unchanged.
func (service *Service) recordRowsetReadFailure(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string, cause error) {
	if service == nil || service.newID == nil || service.now == nil {
		return
	}
	journal := service.admission
	if journal == nil {
		journal = service.audit
	}
	if journal == nil {
		return
	}
	eventID, err := service.newID("aud")
	if err != nil {
		return
	}
	code := rowsetReadFailureCode
	principal := access.PrincipalID
	// The governed read already failed; persist the matching outcome on a short
	// detached window so a cancelled request cannot leave the admission alone.
	cleanupCtx, cancel := questionFailureCleanupContext(ctx)
	defer cancel()
	if _, appendErr := journal.Append(cleanupCtx, access, audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspaceID,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionEvidenceReadFailed,
		ResourceType:          audit.ResourceCitation,
		ResourceID:            fragmentID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeFailed,
		ErrorCode:             &code,
		ReferencedEvidenceIDs: []string{fragmentID},
		OccurredAt:            service.now().UTC(),
	}); appendErr != nil {
		slog.Warn("question rowset read failure outcome persistence failed", "cause_code", CodeOf(cause), "error_code", CodeOf(appendErr))
	}
}
