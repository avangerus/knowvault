package repository

// source_query_credential.go is S3 card 2b's organization-OWNER control over
// the SQL query credential of one PostgreSQL source connection (ADR-0097).
//
// It owns exactly two operations:
//
//   - SourceQueryCredentialTarget: the owner-gated read of the connection's
//     registered relation scope and immutable database identity, which the
//     composition-time credential check needs before it opens the candidate
//     connection. The gate is the organization OWNER source-registration rule
//     every other source-management command uses; an unknown, foreign or
//     non-member connection and a policy denial stay one content-free
//     CodeNotFound, so this read is not an existence oracle.
//   - SetSourceQueryCredential: the owner-gated write of the opaque 'cred'
//     reference or its removal. It calls only the migration 000117
//     SECURITY DEFINER function, which re-checks the OWNER inside the database
//     boundary, and appends one content-free audit event in the same
//     transaction. The reference itself is opaque: no DSN, password or secret
//     value is ever accepted or stored here.
//
// The card's pre-acceptance checks (the reference resolves in the mounted
// credentials, a read-only connection reaches the same database identity and
// the role cannot read a column excluded from the registered tables) happen in
// composition before SetSourceQueryCredential is called. A failed check
// returns its closed code and changes nothing.

import (
	"context"
	"errors"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// The migration 000117 setter raises a closed SQLSTATE for its two fail-closed
// branches. A raised exception aborts the caller's transaction, so the write
// must return a sentinel that stops the transaction and is mapped afterwards
// rather than continuing with an already-aborted session.
var (
	errSourceQueryCredentialNotFound = errors.New("source query credential connection not found")
	errSourceQueryCredentialDenied   = errors.New("source query credential control denied")
)

// SourceQueryCredentialTarget returns the registered relation scope of one
// enabled PostgreSQL source of the caller's workspace, but only to the current
// organization OWNER. It authorizes the organization operation
// source.register, which ADR-0074 s1.9 reserves to the OWNER, and then reuses
// the same relation-scope read the tool boundary performs.
func (store *Store) SourceQueryCredentialTarget(ctx context.Context, access database.AccessContext, workspaceID, sourceID string) (SourceQuerySource, error) {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) || !validID(sourceID) {
		return SourceQuerySource{}, &Error{code: CodeRequestInvalid}
	}
	var result SourceQuerySource
	denied, notFound := false, false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, _, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, workspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		if !policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: currentMembership(snapshot, access.PrincipalID),
		}).Allowed {
			denied = true
			return nil
		}
		if !policy.EvaluateOrganization(policy.OrganizationRequest{
			Operation: policy.OperationSourceRegister, Subject: subject,
			Organization: policy.Organization{ID: access.OrganizationID, Status: policy.OrganizationStatus(organization.Status)},
		}).Allowed {
			denied = true
			return nil
		}
		var readErr error
		result, notFound, readErr = readSourceQueryRelations(transactionContext, transaction, access.OrganizationID, workspaceID, sourceID)
		return readErr
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return SourceQuerySource{}, err
		}
		return SourceQuerySource{}, &Error{code: CodePersistence, cause: err}
	}
	if denied || notFound {
		return SourceQuerySource{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

// SetSourceQueryCredential sets, when credentialReference is non-empty, or
// clears, when it is empty, the connection's opaque query credential
// reference. It is the only writer of the migration 000117 table. A denial,
// unknown or foreign connection is the same content-free CodeNotFound the read
// above returns; an infrastructure failure rolls the whole transaction back so
// no unaudited change ever lands.
func (store *Store) SetSourceQueryCredential(ctx context.Context, access database.AccessContext, workspaceID, sourceID, credentialReference string) error {
	if store == nil || store.database == nil || store.audit == nil || access.Validate() != nil ||
		!validID(workspaceID) || !validID(sourceID) ||
		(credentialReference != "" && !validAuthorityCredentialReference(credentialReference)) {
		return &Error{code: CodeRequestInvalid}
	}
	denied, notFound := false, false
	err := store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, _, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, workspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		if !policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: currentMembership(snapshot, access.PrincipalID),
		}).Allowed {
			denied = true
			return nil
		}
		if !policy.EvaluateOrganization(policy.OrganizationRequest{
			Operation: policy.OperationSourceRegister, Subject: subject,
			Organization: policy.Organization{ID: access.OrganizationID, Status: policy.OrganizationStatus(organization.Status)},
		}).Allowed {
			denied = true
			return nil
		}
		var writeErr error
		if credentialReference == "" {
			_, writeErr = transaction.Exec(transactionContext,
				`SELECT app.source_query_credential_clear($1)`, sourceID)
		} else {
			_, writeErr = transaction.Exec(transactionContext,
				`SELECT app.source_query_credential_set($1, $2)`, sourceID, credentialReference)
		}
		if writeErr != nil {
			switch database.SQLStateCode(writeErr) {
			case "42501":
				return errSourceQueryCredentialDenied
			case "P0002":
				return errSourceQueryCredentialNotFound
			default:
				return writeErr
			}
		}
		eventID, idErr := store.generatedID("aud_")
		if idErr != nil {
			return idErr
		}
		actorID := access.PrincipalID
		connectionID := sourceID
		action := audit.ActionSourceQueryCredentialSet
		if credentialReference == "" {
			action = audit.ActionSourceQueryCredentialCleared
		}
		_, auditErr := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
			ActorPrincipalID: &actorID, Action: action,
			ResourceType: audit.ResourceSourceConnection, ResourceID: connectionID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess,
			Metadata:   audit.Metadata{SourceConnectionID: &connectionID},
			OccurredAt: store.now().UTC(),
		})
		return auditErr
	})
	if err != nil {
		if errors.Is(err, errSourceQueryCredentialNotFound) || errors.Is(err, errSourceQueryCredentialDenied) {
			return &Error{code: CodeNotFound}
		}
		if CodeOf(err) == CodePersistence {
			return err
		}
		return &Error{code: CodePersistence, cause: err}
	}
	if denied || notFound {
		return &Error{code: CodeNotFound}
	}
	return nil
}
