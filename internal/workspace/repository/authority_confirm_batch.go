package repository

// Batch managed-source confirmation (card S3.4b). A database connection can
// carry hundreds of registered tables; confirming them one authority command at
// a time is unusable at that scale, so this file adds one bounded request that
// confirms many tables at once while keeping every per-table guarantee of the
// single WORKSPACE_MANAGED_CONFIRM command.
//
// The batch is deliberately NOT a new ADR-0053 operation. It is a composite of
// the existing one: every table that is present in this workspace's visible
// bindings is confirmed through the unchanged ConfirmManagedSource path, so it
// gets exactly the same decision phase, canonical confirmation document,
// authority row, content-free audit event and receipt as an individual confirm.
// A table that is not a binding of this workspace (another workspace's table,
// or a table of another organization) is never named to the authority runtime
// at all: it resolves to the same content-free WORKSPACE_AUTHORITY_NOT_FOUND the
// individual route returns for an absent binding, and it discloses nothing.
//
// Replay safety is inherited from the individual receipts: the batch derives
// one deterministic child idempotency key per table from the batch's own
// Idempotency-Key and that table's scope, so repeating the same batch replays
// each table's stored terminal outcome and creates no second confirmation. A
// refusal of one table never blocks another: the loop records the refusal's
// closed code and continues. Only an infrastructure (persistence) failure
// aborts the whole request.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// MaxBatchConfirmTables is the hard bound on one batch confirmation request.
// A larger request is refused as a whole before any table is examined.
const MaxBatchConfirmTables = 1000

// batchConfirmChildKeyDomain separates a derived child key from any raw key a
// client could send, so a batch key can never collide with an individual
// confirmation key by accident.
const batchConfirmChildKeyDomain = "knowvault-managed-confirm-batch-v1"

// BatchConfirmTable is one named table of a batch confirmation: the exact
// enabled WORKSPACE_MANAGED binding tuple a single ConfirmRequest would carry.
type BatchConfirmTable struct {
	WorkspaceSourceID   string
	SourceScopeID       string
	SourceScopeRevision int64
	ScopeConfigHash     string
}

// BatchConfirmRequest is the closed batch confirmation request. Every field
// except Tables is shared by every table and mirrors the exact ConfirmRequest
// fields the individual command validates.
type BatchConfirmRequest struct {
	IdempotencyKey             string
	OrganizationID             string
	WorkspaceID                string
	WorkspaceRevision          int64
	WorkspaceConfigurationHash string

	ConfirmationActorGrantID       string
	ConfirmationActorGrantRevision int64
	ConfirmationActorGrantHash     string

	WarningVersion         string
	WarningContractHash    string
	AcknowledgementCode    string
	ExpectedPolicyRevision string

	Tables []BatchConfirmTable
}

// BatchConfirmOutcome is the per-table result. On success Confirmed is true and
// the created confirmation identity is present; on a business refusal Confirmed
// is false and ReasonCode is the closed repository code, never content.
type BatchConfirmOutcome struct {
	SourceScopeID    string
	Confirmed        bool
	ReasonCode       string
	ConfirmationID   string
	ConfirmationHash string
}

// BatchConfirmResult is the ordered per-table outcome of one batch request.
type BatchConfirmResult struct {
	Outcomes       []BatchConfirmOutcome
	ConfirmedCount int
	RefusedCount   int
}

// ConfirmManagedSourcesBatch confirms every named table through the individual
// authority command and reports one outcome per table.
func (store *Store) ConfirmManagedSourcesBatch(ctx context.Context, access database.AccessContext, request BatchConfirmRequest) (BatchConfirmResult, error) {
	if store == nil || store.database == nil || access.Validate() != nil || ctx == nil {
		return BatchConfirmResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	// The trusted tenant fence is exact: a mismatched organization is the same
	// content-free NOT_FOUND the single command returns.
	if request.OrganizationID != access.OrganizationID {
		return BatchConfirmResult{}, &Error{code: CodeAuthorityNotFound}
	}
	if !validID(request.WorkspaceID) || !authoritySafeRevision(request.WorkspaceRevision) ||
		!authorityHash(request.WorkspaceConfigurationHash) ||
		!authorityRequestID(request.ConfirmationActorGrantID) ||
		!authoritySafeRevision(request.ConfirmationActorGrantRevision) ||
		!authorityHash(request.ConfirmationActorGrantHash) ||
		request.WarningVersion != authorityWarningVersion || !authorityHash(request.WarningContractHash) ||
		request.AcknowledgementCode != authorityAcknowledgementCode ||
		!authorityPolicyRevisionID(request.ExpectedPolicyRevision) ||
		len(request.Tables) < 1 || len(request.Tables) > MaxBatchConfirmTables {
		return BatchConfirmResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	if _, err := idempotencyKeyHash(request.IdempotencyKey); err != nil {
		return BatchConfirmResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	for _, table := range request.Tables {
		if !authorityBindingID(table.WorkspaceSourceID) || !authorityRequestID(table.SourceScopeID) ||
			!authoritySafeRevision(table.SourceScopeRevision) || !authorityHash(table.ScopeConfigHash) {
			return BatchConfirmResult{}, &Error{code: CodeAuthorityRequestInvalid}
		}
	}

	visible, err := store.batchConfirmVisibleScopes(ctx, access, request.WorkspaceID)
	if err != nil {
		return BatchConfirmResult{}, err
	}

	result := BatchConfirmResult{Outcomes: make([]BatchConfirmOutcome, 0, len(request.Tables))}
	for _, table := range request.Tables {
		outcome := BatchConfirmOutcome{SourceScopeID: table.SourceScopeID}
		if _, present := visible[table.SourceScopeID]; !present {
			// A table of another workspace or organization is not a binding
			// here: the same content-free not-found, and no authority round
			// trip that could disclose anything about it.
			outcome.ReasonCode = string(CodeAuthorityNotFound)
			result.RefusedCount++
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		confirmed, confirmErr := store.ConfirmManagedSource(ctx, access, ConfirmRequest{
			IdempotencyKey:                 batchConfirmChildKey(request.IdempotencyKey, table.SourceScopeID),
			OrganizationID:                 request.OrganizationID,
			WorkspaceID:                    request.WorkspaceID,
			WorkspaceRevision:              request.WorkspaceRevision,
			WorkspaceConfigurationHash:     request.WorkspaceConfigurationHash,
			WorkspaceSourceID:              table.WorkspaceSourceID,
			SourceScopeID:                  table.SourceScopeID,
			SourceScopeRevision:            table.SourceScopeRevision,
			ScopeConfigHash:                table.ScopeConfigHash,
			AccessMode:                     authorityAccessModeManaged,
			ConfirmationActorGrantID:       request.ConfirmationActorGrantID,
			ConfirmationActorGrantRevision: request.ConfirmationActorGrantRevision,
			ConfirmationActorGrantHash:     request.ConfirmationActorGrantHash,
			WarningVersion:                 authorityWarningVersion,
			WarningContractHash:            request.WarningContractHash,
			AcknowledgementCode:            authorityAcknowledgementCode,
			ExpectedPolicyRevision:         request.ExpectedPolicyRevision,
		})
		if confirmErr == nil {
			outcome.Confirmed = true
			outcome.ConfirmationID = confirmed.ResultID
			outcome.ConfirmationHash = confirmed.ResultHash
			result.ConfirmedCount++
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		code := CodeOf(confirmErr)
		if code == CodeAuthorityPersistence || code == CodePersistence || code == CodeAuthorityRequestInvalid {
			// An infrastructure failure (or a shape error our own validation
			// should already have caught) is not a per-table business refusal:
			// it aborts the whole request rather than being reported as one.
			return BatchConfirmResult{}, confirmErr
		}
		if code == "" {
			return BatchConfirmResult{}, &Error{code: CodeAuthorityPersistence, cause: confirmErr}
		}
		outcome.ReasonCode = string(code)
		result.RefusedCount++
		result.Outcomes = append(result.Outcomes, outcome)
	}
	return result, nil
}

// batchConfirmVisibleScopes returns the set of source scope ids bound to the
// workspace's current revision that the caller may see, using the exact same
// visibility gate (active actor, ACTIVE organization, workspace metadata
// policy) ListSources uses. An invisible, absent or foreign workspace is the
// one content-free CodeNotFound; no binding of another workspace is ever read.
func (store *Store) batchConfirmVisibleScopes(ctx context.Context, access database.AccessContext, workspaceID string) (map[string]struct{}, error) {
	visible := map[string]struct{}{}
	denied := false
	notFound := false
	err := store.database.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		subject, organization, found, actorErr := currentActor(txCtx, tx, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, _, _, exists, loadErr := loadCurrentSnapshot(txCtx, tx, access.OrganizationID, workspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		membership := currentMembership(snapshot, access.PrincipalID)
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: membership,
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		rows, queryErr := tx.Query(txCtx, `
			SELECT source_scope_id FROM app.workspace_source_status_v3($1)
		`, workspaceID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var scopeID string
			if scanErr := rows.Scan(&scopeID); scanErr != nil {
				return scanErr
			}
			visible[scopeID] = struct{}{}
		}
		return rows.Err()
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return nil, err
		}
		return nil, &Error{code: CodeAuthorityPersistence, cause: err}
	}
	if denied || notFound {
		return nil, &Error{code: CodeAuthorityNotFound}
	}
	return visible, nil
}

// batchConfirmChildKey derives the deterministic per-table receipt key of one
// batch confirmation. It is a valid Idempotency-Key (base64url of 32 bytes) by
// construction, and it depends only on the batch key and the scope id, so the
// same request always re-addresses the same individual receipts.
func batchConfirmChildKey(batchKey, scopeID string) string {
	digest := sha256.Sum256([]byte(batchConfirmChildKeyDomain + "\x00" + batchKey + "\x00" + scopeID))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
