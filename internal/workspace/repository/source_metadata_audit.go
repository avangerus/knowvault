package repository

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

const (
	sourceStatusListRead          = "SOURCE_STATUS_LIST"
	sourceConfirmationContextRead = "SOURCE_CONFIRMATION_CONTEXT"
	sourceMetadataDenied          = "SOURCE_METADATA_READ_DENIED"
	sourceMetadataFailed          = "SOURCE_METADATA_READ_FAILED"
	sourceMetadataCleanupTimeout  = 5 * time.Second
)

// ListSources and ConfirmationContext are the common source metadata boundary
// for MCP, REST, tool-loop and operator callers. The private reads retain their
// existing authorization checks, including a recheck after durable admission.
func (store *Store) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]SourceStatus, error) {
	var result []SourceStatus
	err := store.sourceMetadataRead(ctx, access, workspaceID, sourceStatusListRead, func() error {
		var err error
		result, err = store.listSources(ctx, access, workspaceID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (store *Store) ConfirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (ConfirmationContext, error) {
	var result ConfirmationContext
	err := store.sourceMetadataRead(ctx, access, workspaceID, sourceConfirmationContextRead, func() error {
		var err error
		result, err = store.confirmationContext(ctx, access, workspaceID)
		return err
	})
	if err != nil {
		return ConfirmationContext{}, err
	}
	return result, nil
}

func (store *Store) sourceMetadataRead(ctx context.Context, access database.AccessContext, workspaceID, kind string, read func() error) error {
	if store == nil || store.database == nil || store.audit == nil || store.now == nil || store.newID == nil || ctx == nil ||
		access.Validate() != nil || !validID(workspaceID) || read == nil {
		return &Error{code: CodeRequestInvalid}
	}
	allowed := false
	var eventWorkspace *string
	err := store.database.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		// Only authorization facts are read before admission. The source status
		// and confirmation projections remain in the private read below.
		subject, organization, found, err := currentActor(txCtx, tx, access, false)
		if err != nil {
			return err
		}
		if !found {
			// An unknown actor cannot be referenced by an audit principal FK.
			return nil
		}
		var status string
		var role *string
		err = tx.QueryRow(txCtx, `
			SELECT workspace.status, member.role
			FROM public.workspace AS workspace
			LEFT JOIN public.workspace_member AS member
			  ON member.organization_id = workspace.organization_id AND member.workspace_id = workspace.id
			 AND member.principal_id = $3 AND member.removed_at IS NULL
			WHERE workspace.organization_id = $1 AND workspace.id = $2
		`, access.OrganizationID, workspaceID, access.PrincipalID).Scan(&status, &role)
		if err != nil && !database.IsNotFound(err) {
			return err
		}
		if err == nil {
			eventWorkspace = &workspaceID
			membership := policy.Membership{}
			if role != nil {
				membership = policy.Membership{Present: true, Role: policy.WorkspaceRole(*role)}
			}
			decision := policy.EvaluateWorkspace(policy.Request{
				Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
				Workspace:  policy.Workspace{OrganizationID: access.OrganizationID, ID: workspaceID, Status: policy.WorkspaceStatus(status)},
				Membership: membership,
			})
			allowed = organization.Status == policy.OrganizationActive && decision.Allowed
		}
		outcome, code := audit.OutcomeSuccess, ""
		if !allowed {
			outcome, code = audit.OutcomeDenied, sourceMetadataDenied
		}
		input, err := store.sourceMetadataEvent(access, workspaceID, eventWorkspace, kind, audit.ActionSourceMetadataReadAdmitted, outcome, code)
		if err != nil {
			return err
		}
		if _, err = store.audit.AppendInTransaction(txCtx, access, tx, input); err != nil {
			return err
		}
		if !allowed {
			input, err = store.sourceMetadataEvent(access, workspaceID, eventWorkspace, kind, audit.ActionSourceMetadataReadFailed, outcome, code)
			if err != nil {
				return err
			}
			_, err = store.audit.AppendInTransaction(txCtx, access, tx, input)
			return err
		}
		return nil
	})
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if !allowed {
		return &Error{code: CodeNotFound}
	}
	readErr := read()
	if readErr == nil && ctx.Err() != nil {
		readErr = &Error{code: CodePersistence, cause: ctx.Err()}
	}
	action, outcome, code := audit.ActionSourceMetadataReadCompleted, audit.OutcomeSuccess, ""
	if readErr != nil {
		action, outcome, code = audit.ActionSourceMetadataReadFailed, audit.OutcomeFailed, sourceMetadataFailed
		if CodeOf(readErr) == CodeDenied || CodeOf(readErr) == CodeNotFound {
			outcome, code = audit.OutcomeDenied, sourceMetadataDenied
		}
	}
	terminalCtx := ctx
	if readErr != nil {
		var cancel context.CancelFunc
		terminalCtx, cancel = sourceMetadataFailureContext(ctx)
		defer cancel()
	}
	if err := store.appendSourceMetadataEvent(terminalCtx, access, workspaceID, eventWorkspace, kind, action, outcome, code); err != nil {
		// The read result is withheld even when only its completion receipt
		// failed. Attempt a content-free failure outcome for the admission.
		if readErr == nil {
			cleanupCtx, cancel := sourceMetadataFailureContext(ctx)
			defer cancel()
			_ = store.appendSourceMetadataEvent(cleanupCtx, access, workspaceID, eventWorkspace, kind, audit.ActionSourceMetadataReadFailed, audit.OutcomeFailed, sourceMetadataFailed)
		}
		return &Error{code: CodePersistence, cause: err}
	}
	return readErr
}

func sourceMetadataFailureContext(parent context.Context) (context.Context, context.CancelFunc) {
	// Match governed question failure persistence: preserve request values,
	// ignore request cancellation, but never wait indefinitely for the journal.
	return context.WithTimeout(context.WithoutCancel(parent), sourceMetadataCleanupTimeout)
}

func (store *Store) sourceMetadataEvent(access database.AccessContext, workspaceID string, eventWorkspace *string, kind string, action audit.Action, outcome audit.Outcome, code string) (audit.EventInput, error) {
	eventID, err := store.newID("aud_")
	if err != nil {
		return audit.EventInput{}, err
	}
	principalID := access.PrincipalID
	input := audit.EventInput{EventID: eventID, WorkspaceID: eventWorkspace, ActorType: audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principalID, Action: action, ResourceType: audit.ResourceWorkspace, ResourceID: workspaceID,
		RequestID: access.RequestID, Outcome: outcome, Metadata: audit.Metadata{ReasonCodes: []string{kind}}, OccurredAt: store.now().UTC()}
	if code != "" {
		input.ErrorCode = &code
	}
	return input, nil
}

func (store *Store) appendSourceMetadataEvent(ctx context.Context, access database.AccessContext, workspaceID string, eventWorkspace *string, kind string, action audit.Action, outcome audit.Outcome, code string) error {
	input, err := store.sourceMetadataEvent(access, workspaceID, eventWorkspace, kind, action, outcome, code)
	if err != nil {
		return err
	}
	_, err = store.audit.Append(ctx, access, input)
	return err
}
