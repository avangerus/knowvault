package question

import (
	"context"
	"errors"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// FeedbackVerdict is the closed R1.S10.s1.T4 answer-correctness mark.
type FeedbackVerdict string

const (
	FeedbackCorrect   FeedbackVerdict = "CORRECT"
	FeedbackIncorrect FeedbackVerdict = "INCORRECT"

	feedbackCommentMaxRunes = 4096
)

func validFeedbackVerdict(verdict FeedbackVerdict) bool {
	return verdict == FeedbackCorrect || verdict == FeedbackIncorrect
}

// Feedback is one member's current mark on one terminal, answered Question
// Run. Comment is populated only where the caller explicitly asked for the
// decrypted text (the report and a self-read); a submission acknowledgement
// never carries it back.
type Feedback struct {
	QuestionRunID string
	Verdict       FeedbackVerdict
	HasComment    bool
	Comment       string
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// FeedbackReportEntry is one row of the workspace error-review report: the
// question and answer the mark refers to, the mark itself, and its author.
type FeedbackReportEntry struct {
	QuestionRunID     string
	Question          string
	Answer            string
	Verdict           FeedbackVerdict
	Comment           string
	AuthorPrincipalID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// feedbackAuthorize gates a read of the encrypted comment: the caller must be
// either the feedback's own author or a current OWNER/MANAGER of the
// workspace it belongs to. It runs inside the caller's transaction and uses
// only trusted, server-resolved identity — never a client-supplied role.
func feedbackAuthorize(ctx context.Context, tx database.Transaction, _ database.AccessContext, feedbackRowID string) error {
	var allowed bool
	if err := tx.QueryRow(ctx, `
		SELECT (
			feedback.created_by = app.current_principal_id()
			OR EXISTS (
				SELECT 1 FROM public.workspace_member manager
				WHERE manager.organization_id = feedback.organization_id
				  AND manager.workspace_id = feedback.workspace_id
				  AND manager.principal_id = app.current_principal_id()
				  AND manager.removed_at IS NULL
				  AND manager.role IN ('OWNER', 'MANAGER')
			)
		)
		FROM public.question_feedback feedback
		WHERE feedback.organization_id = app.current_organization_id() AND feedback.id = $1
	`, feedbackRowID).Scan(&allowed); err != nil || !allowed {
		return errors.New("question feedback comment is not readable")
	}
	return nil
}

// SubmitFeedback records or changes the caller's current mark on one Question
// Run. A CORRECT verdict discards any previously stored comment; an
// INCORRECT verdict requires a non-empty comment and (re)encrypts it under a
// fresh artifact bound, in place, to the same feedback row. Access mirrors
// the answer's own visibility: only a member who can currently read the
// run's content (workspace.read_content, which excludes AUDITOR) may mark it.
func (service *Service) SubmitFeedback(ctx context.Context, access database.AccessContext, workspaceID, runID string, verdict FeedbackVerdict, comment string) (Feedback, error) {
	if service == nil || service.db == nil || service.audit == nil || service.artifacts == nil || service.codec == nil ||
		access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(runID) || !validFeedbackVerdict(verdict) {
		return Feedback{}, &Error{code: CodeInvalid}
	}
	trimmedComment := strings.TrimSpace(comment)
	if verdict == FeedbackIncorrect && trimmedComment == "" {
		return Feedback{}, &Error{code: CodeInvalid}
	}
	if len([]rune(trimmedComment)) > feedbackCommentMaxRunes {
		return Feedback{}, &Error{code: CodeInvalid}
	}

	var result Feedback
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var (
			organizationStatus, workspaceStatus, principalStatus, role string
			principalRevision                                          int64
		)
		if err := tx.QueryRow(txCtx, `
			SELECT organization.status, workspace.status, principal.status, principal.session_revision, COALESCE(member.role, '')
			FROM public.organization
			JOIN public.workspace
			  ON workspace.organization_id = organization.id AND workspace.id = $2
			JOIN public.principal ON principal.organization_id = organization.id AND principal.id = $3
			LEFT JOIN public.workspace_member member
			  ON member.organization_id = workspace.organization_id AND member.workspace_id = workspace.id
			 AND member.principal_id = principal.id AND member.removed_at IS NULL
			WHERE organization.id = $1
		`, access.OrganizationID, workspaceID, access.PrincipalID).Scan(
			&organizationStatus, &workspaceStatus, &principalStatus, &principalRevision, &role,
		); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeDenied}
			}
			return err
		}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceReadContent,
			Subject: policy.Subject{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
				Status: policy.PrincipalStatus(principalStatus), SessionRevision: principalRevision},
			Workspace:  policy.Workspace{OrganizationID: access.OrganizationID, ID: workspaceID, Status: policy.WorkspaceStatus(workspaceStatus)},
			Membership: policy.Membership{Present: role != "", Role: policy.WorkspaceRole(role)},
		})
		if organizationStatus != "ACTIVE" || !decision.Allowed {
			return &Error{code: CodeDenied}
		}

		var runReadable bool
		if err := tx.QueryRow(txCtx, `
			SELECT app.question_run_readable(id, workspace_id)
			FROM public.question_run
			WHERE organization_id = $1 AND id = $2 AND workspace_id = $3
			  AND result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE')
		`, access.OrganizationID, runID, workspaceID).Scan(&runReadable); err != nil || !runReadable {
			if err != nil && !database.IsNotFound(err) {
				return err
			}
			return &Error{code: CodeNotFound}
		}

		newRowID, mintErr := service.newID("qfb")
		if mintErr != nil {
			return mintErr
		}
		var (
			feedbackRowID        string
			createdAt, updatedAt time.Time
		)
		if err := tx.QueryRow(txCtx, `
			INSERT INTO public.question_feedback (
				organization_id, id, question_run_id, workspace_id, created_by, verdict
			) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (organization_id, question_run_id, created_by)
			DO UPDATE SET verdict = EXCLUDED.verdict, updated_at = transaction_timestamp()
			RETURNING id, created_at, updated_at
		`, access.OrganizationID, newRowID, runID, workspaceID, access.PrincipalID, string(verdict)).Scan(
			&feedbackRowID, &createdAt, &updatedAt,
		); err != nil {
			return err
		}

		hasComment := verdict == FeedbackIncorrect
		if !hasComment {
			if _, err := tx.Exec(txCtx, `
				UPDATE public.question_feedback SET comment_artifact_id = NULL
				WHERE organization_id = $1 AND id = $2
			`, access.OrganizationID, feedbackRowID); err != nil {
				return err
			}
		} else {
			owner, ownerErr := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionFeedbackComment, access.OrganizationID, feedbackRowID)
			if ownerErr != nil {
				return ownerErr
			}
			envelope, sealErr := service.codec.Seal(owner, []byte(trimmedComment))
			if sealErr != nil {
				return sealErr
			}
			artifactID, artifactErr := service.newID("art")
			if artifactErr != nil {
				return artifactErr
			}
			if err := service.artifacts.Store(txCtx, tx, access, artifactcrypto.QuestionFeedbackComment, feedbackRowID, artifactID, envelope); err != nil {
				return err
			}
		}

		eventID, eventIDErr := service.newID("aud")
		if eventIDErr != nil {
			return eventIDErr
		}
		verdictValue := string(verdict)
		qrunID := runID
		if _, err := service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
			ActorPrincipalID: &access.PrincipalID, Action: audit.ActionQuestionFeedbackSubmitted,
			ResourceType: audit.ResourceQuestionFeedback, ResourceID: feedbackRowID, RequestID: access.RequestID,
			Outcome: audit.OutcomeSuccess, ReferencedEvidenceIDs: []string{},
			Metadata:   audit.Metadata{QuestionRunID: &qrunID, FeedbackVerdict: &verdictValue, FeedbackHasComment: &hasComment},
			OccurredAt: service.now().UTC(),
		}); err != nil {
			return err
		}

		result = Feedback{QuestionRunID: runID, Verdict: verdict, HasComment: hasComment,
			CreatedBy: access.PrincipalID, CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}
		return nil
	})
	if err != nil {
		if code := CodeOf(err); code == CodeDenied || code == CodeNotFound || code == CodeInvalid {
			return Feedback{}, err
		}
		return Feedback{}, &Error{code: CodeUnavailable, cause: err}
	}
	return result, nil
}

// OwnFeedback returns the caller's own current mark on one Question Run, if
// any, so the interface can show its state after a page reload. The comment
// is decrypted and returned only here and in FeedbackReport.
func (service *Service) OwnFeedback(ctx context.Context, access database.AccessContext, workspaceID, runID string) (Feedback, bool, error) {
	if service == nil || service.db == nil || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(runID) {
		return Feedback{}, false, &Error{code: CodeInvalid}
	}
	var (
		result Feedback
		found  bool
	)
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var (
			feedbackRowID, verdictValue string
			hasComment                  bool
			createdAt, updatedAt        time.Time
		)
		scanErr := tx.QueryRow(txCtx, `
			SELECT id, verdict, comment_artifact_id IS NOT NULL, created_at, updated_at
			FROM public.question_feedback
			WHERE organization_id = $1 AND question_run_id = $2 AND workspace_id = $3 AND created_by = $4
		`, access.OrganizationID, runID, workspaceID, access.PrincipalID).Scan(
			&feedbackRowID, &verdictValue, &hasComment, &createdAt, &updatedAt,
		)
		if database.IsNotFound(scanErr) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		result = Feedback{QuestionRunID: runID, Verdict: FeedbackVerdict(verdictValue), HasComment: hasComment,
			CreatedBy: access.PrincipalID, CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}
		return nil
	})
	if err != nil {
		return Feedback{}, false, &Error{code: CodeUnavailable, cause: err}
	}
	return result, found, nil
}

// FeedbackReport returns every member's current feedback in one workspace,
// with the question, the answer and the decrypted comment, for the workspace
// OWNER/MANAGER error-review surface. Any other role is denied, indistinctly
// from an unknown workspace.
func (service *Service) FeedbackReport(ctx context.Context, access database.AccessContext, workspaceID string) ([]FeedbackReportEntry, error) {
	if service == nil || service.db == nil || service.artifacts == nil || service.codec == nil ||
		access.Validate() != nil || !validOpaque(workspaceID) {
		return nil, &Error{code: CodeInvalid}
	}
	var entries []FeedbackReportEntry
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var (
			organizationStatus, workspaceStatus, principalStatus, role string
			principalRevision                                          int64
		)
		if err := tx.QueryRow(txCtx, `
			SELECT organization.status, workspace.status, principal.status, principal.session_revision, COALESCE(member.role, '')
			FROM public.organization
			JOIN public.workspace
			  ON workspace.organization_id = organization.id AND workspace.id = $2
			JOIN public.principal ON principal.organization_id = organization.id AND principal.id = $3
			LEFT JOIN public.workspace_member member
			  ON member.organization_id = workspace.organization_id AND member.workspace_id = workspace.id
			 AND member.principal_id = principal.id AND member.removed_at IS NULL
			WHERE organization.id = $1
		`, access.OrganizationID, workspaceID, access.PrincipalID).Scan(
			&organizationStatus, &workspaceStatus, &principalStatus, &principalRevision, &role,
		); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeDenied}
			}
			return err
		}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceManage,
			Subject: policy.Subject{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
				Status: policy.PrincipalStatus(principalStatus), SessionRevision: principalRevision},
			Workspace:  policy.Workspace{OrganizationID: access.OrganizationID, ID: workspaceID, Status: policy.WorkspaceStatus(workspaceStatus)},
			Membership: policy.Membership{Present: role != "", Role: policy.WorkspaceRole(role)},
		})
		if organizationStatus != "ACTIVE" || !decision.Allowed {
			return &Error{code: CodeDenied}
		}

		rows, queryErr := tx.Query(txCtx, `
			SELECT id, question_run_id, created_by, verdict, comment_artifact_id IS NOT NULL, created_at, updated_at
			FROM public.question_feedback
			WHERE organization_id = $1 AND workspace_id = $2
			ORDER BY created_at DESC
		`, access.OrganizationID, workspaceID)
		if queryErr != nil {
			return queryErr
		}
		type row struct {
			feedbackRowID, runID, authorID, verdict string
			hasComment                              bool
			createdAt, updatedAt                    time.Time
		}
		var collected []row
		for rows.Next() {
			var current row
			if scanErr := rows.Scan(&current.feedbackRowID, &current.runID, &current.authorID, &current.verdict,
				&current.hasComment, &current.createdAt, &current.updatedAt); scanErr != nil {
				rows.Close()
				return scanErr
			}
			collected = append(collected, current)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		rows.Close()

		entries = make([]FeedbackReportEntry, 0, len(collected))
		for _, current := range collected {
			questionPlain, questionErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.QuestionText, current.runID)
			if questionErr != nil {
				if isDroppableRunError(questionErr) {
					continue
				}
				return questionErr
			}
			answerPlain, answerErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.AnswerMarkdown, current.runID)
			if answerErr != nil {
				if isDroppableRunError(answerErr) {
					continue
				}
				return answerErr
			}
			var commentPlain []byte
			if current.hasComment {
				if err := feedbackAuthorize(txCtx, tx, access, current.feedbackRowID); err != nil {
					continue
				}
				plain, commentErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.QuestionFeedbackComment, current.feedbackRowID)
				if commentErr != nil {
					if isDroppableRunError(commentErr) {
						continue
					}
					return commentErr
				}
				commentPlain = plain
			}
			entries = append(entries, FeedbackReportEntry{
				QuestionRunID: current.runID, Question: string(questionPlain), Answer: string(answerPlain),
				Verdict: FeedbackVerdict(current.verdict), Comment: string(commentPlain),
				AuthorPrincipalID: current.authorID, CreatedAt: current.createdAt.UTC(), UpdatedAt: current.updatedAt.UTC(),
			})
		}
		return nil
	})
	if err != nil {
		if code := CodeOf(err); code == CodeDenied || code == CodeInvalid {
			return nil, err
		}
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	return entries, nil
}
