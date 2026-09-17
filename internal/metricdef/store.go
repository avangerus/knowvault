package metricdef

// R2 Outcome 1 persistence boundary (POSITION.md section 3 "Semantics").
//
// Store is the durable implementation of the transport's read catalog
// (List/GetVersion) and owner-only authoring capability (CreateDraft/Approve).
// It re-checks the caller's workspace access through the existing
// workspace.Snapshot authority on every read and every write, so it can never
// return or mutate another workspace's definition even when a definition id
// collides across tenants.
//
// The pure lifecycle rules stay in definition.go: this file only rehydrates a
// Series from the current rows, lets Series decide the transition (DRAFT edit
// in place, APPROVED -> version+1, RETIRED refused) and persists the exact
// delta. The database triggers in 000094 are the second, independent guard:
// an APPROVED version can never be updated in place and a version number can
// never move backwards.
//
// Failures are content-free. A caller without workspace access receives the
// same sentinel the transport maps to a non-enumerating 404
// (ErrAccessDenied mirrors workspaceapi.ErrMetricDefinitionDenied); an
// unknown definition or version is ErrDefinitionNotFound; owner and lifecycle
// refusals keep metricdef's typed codes. The mirroring is by the canonical
// message so this package keeps its one-way dependency and never imports the
// transport that consumes it.

import (
	"context"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
)

// WorkspaceAuthority is the existing workspace/membership snapshot authority.
// Store invents no second access-control path: a successful Get already proves
// a readable member, and its owner principal is the sole approver.
type WorkspaceAuthority interface {
	Get(ctx context.Context, access database.AccessContext, workspaceID string) (workspace.Snapshot, error)
}

// ApprovalAudit is the in-transaction audit boundary for approvals. It is
// called exactly once per successful approval, inside Store's own write
// transaction, so the approval event and the APPROVED state commit or roll
// back together. A nil boundary makes every approval fail closed with
// CodeAuditUnavailable. The composition root supplies the R1 audit-backed
// implementation; this package never fabricates an audit record itself.
type ApprovalAudit interface {
	RecordApproval(ctx context.Context, access database.AccessContext,
		transaction database.Transaction, event ApprovalEvent) error
}

// mirroredError is a content-free sentinel whose Is matches an equivalent
// sentinel in another package by its canonical message. It exists only because
// the transport imports this package (not the other way around); matching by
// the fixed code string keeps the dependency one-way while preserving the
// transport's existing errors.Is mapping.
type mirroredError struct{ message string }

func (e *mirroredError) Error() string { return e.message }

func (e *mirroredError) Is(target error) bool {
	return target != nil && target.Error() == e.message
}

// ErrAccessDenied is returned when the caller's access context may not read or
// write the named workspace. Its canonical message is identical to
// workspaceapi.ErrMetricDefinitionDenied, so the transport's errors.Is mapping
// turns it into the same non-enumerating 404 as any other denial.
var ErrAccessDenied = &mirroredError{message: "METRICDEFINITION_ACCESS_DENIED"}

// ErrDefinitionNotFound is returned for a definition id or version the
// workspace does not hold. Its canonical message is identical to
// workspaceapi.ErrMetricDefinitionNotFound.
var ErrDefinitionNotFound = &mirroredError{message: "METRICDEFINITION_NOT_FOUND"}

// Store is safe for concurrent use once constructed.
type Store struct {
	database   *database.Store
	workspaces WorkspaceAuthority
	audit      ApprovalAudit
	now        func() time.Time
}

// New binds the definition catalog to the reviewed database, the existing
// workspace authority and the owner-approval audit boundary. A nil auditor is
// accepted so a deployment without the audit capability still fails approvals
// closed (CodeAuditUnavailable) instead of silently approving.
func New(databaseStore *database.Store, workspaces WorkspaceAuthority, approvalAudit ApprovalAudit) (*Store, error) {
	if databaseStore == nil || workspaces == nil {
		return nil, newError(CodeInvalidDefinition)
	}
	return &Store{database: databaseStore, workspaces: workspaces, audit: approvalAudit, now: time.Now}, nil
}

// authorize re-checks the caller's workspace access through the existing
// snapshot authority. A read needs a readable membership (Get success is that
// proof); a write additionally needs the caller to be the current workspace
// owner and the workspace to be active.
func (store *Store) authorize(ctx context.Context, access database.AccessContext,
	workspaceID string, requireOwner bool) (workspace.Snapshot, error) {
	if store == nil || store.database == nil || store.workspaces == nil || ctx == nil ||
		access.Validate() != nil || !validID(workspaceID) {
		return workspace.Snapshot{}, newError(CodeInvalidDefinition)
	}
	snapshot, err := store.workspaces.Get(ctx, access, workspaceID)
	if err != nil || snapshot.ID != workspaceID || snapshot.OrganizationID != access.OrganizationID {
		return workspace.Snapshot{}, ErrAccessDenied
	}
	if !requireOwner {
		return snapshot, nil
	}
	if snapshot.Status != workspace.StatusActive || snapshot.OwnerPrincipalID != access.PrincipalID ||
		!isOwnerMember(snapshot, access.PrincipalID) {
		return workspace.Snapshot{}, newError(CodeNotWorkspaceOwner)
	}
	return snapshot, nil
}

func isOwnerMember(snapshot workspace.Snapshot, principalID string) bool {
	for _, member := range snapshot.Members {
		if member.PrincipalID == principalID && member.Role == workspace.RoleOwner {
			return true
		}
	}
	return false
}

// List returns every issued version of every definition in workspaceID.
func (store *Store) List(ctx context.Context, access database.AccessContext,
	workspaceID string) ([]Definition, error) {
	snapshot, err := store.authorize(ctx, access, workspaceID, false)
	if err != nil {
		return nil, err
	}
	definitions := []Definition{}
	err = store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT definition_id, version, status, name, source_connection_id,
			       projection_version, entity_key, grain, allowed_filters, unit,
			       owner_principal_id
			FROM public.metric_definition_version
			WHERE organization_id = $1 AND workspace_id = $2
			ORDER BY definition_id, version
		`, access.OrganizationID, workspaceID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			definition, scanErr := scanDefinition(rows, workspaceID)
			if scanErr != nil {
				return scanErr
			}
			// The workspace owner is the approver authority, resolved from the
			// live workspace snapshot rather than the stored row, so an
			// ownership transfer cannot leave a stale approver behind.
			definition.ownerPrincipalID = snapshot.OwnerPrincipalID
			definitions = append(definitions, definition)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return definitions, nil
}

// GetVersion returns exactly one version of metricID in workspaceID.
func (store *Store) GetVersion(ctx context.Context, access database.AccessContext,
	workspaceID, metricID string, version int64) (Definition, error) {
	snapshot, err := store.authorize(ctx, access, workspaceID, false)
	if err != nil {
		return Definition{}, err
	}
	if !validID(metricID) || version < 1 {
		return Definition{}, ErrDefinitionNotFound
	}
	definition := Definition{}
	found := false
	err = store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		row := transaction.QueryRow(transactionContext, `
			SELECT definition_id, version, status, name, source_connection_id,
			       projection_version, entity_key, grain, allowed_filters, unit,
			       owner_principal_id
			FROM public.metric_definition_version
			WHERE organization_id = $1 AND workspace_id = $2
			  AND definition_id = $3 AND version = $4
		`, access.OrganizationID, workspaceID, metricID, version)
		loaded, scanErr := scanDefinition(row, workspaceID)
		if database.IsNotFound(scanErr) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		loaded.ownerPrincipalID = snapshot.OwnerPrincipalID
		definition = loaded
		found = true
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	if !found {
		return Definition{}, ErrDefinitionNotFound
	}
	return definition, nil
}

// CreateDraft creates version 1 of definitionID when the workspace holds no
// such definition, or lets Series decide the next transition when it does:
// a DRAFT edit keeps the same version, an APPROVED version yields a new DRAFT
// at highest+1, and a RETIRED version is refused with CodeRetiredImmutable.
func (store *Store) CreateDraft(ctx context.Context, access database.AccessContext,
	workspaceID, definitionID string, spec Spec) (Definition, error) {
	snapshot, err := store.authorize(ctx, access, workspaceID, true)
	if err != nil {
		return Definition{}, err
	}
	if !validID(definitionID) {
		return Definition{}, newError(CodeInvalidDefinition)
	}
	if _, err := normalizeSpec(spec); err != nil {
		return Definition{}, err
	}
	result := Definition{}
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		series, found, loadErr := loadSeries(transactionContext, transaction, access.OrganizationID, workspaceID, definitionID, snapshot.OwnerPrincipalID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			created, createErr := NewSeries(definitionID, workspaceID, snapshot.OwnerPrincipalID, spec)
			if createErr != nil {
				return createErr
			}
			if insertErr := insertDefinition(transactionContext, transaction, access, workspaceID, definitionID, snapshot.OwnerPrincipalID); insertErr != nil {
				return insertErr
			}
			if insertErr := insertVersion(transactionContext, transaction, access, created.Current()); insertErr != nil {
				return insertErr
			}
			result = created.Current()
			return nil
		}
		next, supersedeErr := series.Supersede(spec)
		if supersedeErr != nil {
			return supersedeErr
		}
		if next.Highest() == series.Highest() {
			if updateErr := updateDraftVersion(transactionContext, transaction, access, next.Current()); updateErr != nil {
				return updateErr
			}
		} else {
			if insertErr := insertVersion(transactionContext, transaction, access, next.Current()); insertErr != nil {
				return insertErr
			}
			if bumpErr := bumpCurrentVersion(transactionContext, transaction, access, workspaceID, definitionID, series.Highest(), next.Highest()); bumpErr != nil {
				return bumpErr
			}
		}
		result = next.Current()
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return result, nil
}

// Approve flips the current DRAFT version to APPROVED through the workspace
// owner's audited approval boundary. Exactly one approval event is recorded,
// inside the same transaction as the state change; any refusal leaves the
// stored history untouched.
func (store *Store) Approve(ctx context.Context, access database.AccessContext,
	workspaceID, definitionID string) (Definition, error) {
	snapshot, err := store.authorize(ctx, access, workspaceID, true)
	if err != nil {
		return Definition{}, err
	}
	if !validID(definitionID) {
		return Definition{}, ErrDefinitionNotFound
	}
	result := Definition{}
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		series, found, loadErr := loadSeries(transactionContext, transaction, access.OrganizationID, workspaceID, definitionID, snapshot.OwnerPrincipalID)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return ErrDefinitionNotFound
		}
		var auditor ApprovalAuditor
		if store.audit != nil {
			auditor = transactionAuditor{ctx: transactionContext, access: access, transaction: transaction, journal: store.audit}
		}
		approved, approveErr := series.Approve(access.PrincipalID, auditor, store.now().UTC())
		if approveErr != nil {
			return approveErr
		}
		if markErr := markApproved(transactionContext, transaction, access, approved.Current()); markErr != nil {
			return markErr
		}
		result = approved.Current()
		return nil
	})
	if err != nil {
		return Definition{}, err
	}
	return result, nil
}

// transactionAuditor adapts the in-transaction audit boundary to the pure
// Series approval contract. Series calls it exactly once.
type transactionAuditor struct {
	ctx         context.Context
	access      database.AccessContext
	transaction database.Transaction
	journal     ApprovalAudit
}

func (auditor transactionAuditor) RecordApproval(event ApprovalEvent) error {
	return auditor.journal.RecordApproval(auditor.ctx, auditor.access, auditor.transaction, event)
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows, so one scan helper
// serves the exact-version read and the history load without importing the
// driver directly.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanDefinition(row rowScanner, workspaceID string) (Definition, error) {
	var id, status, name, connectionID, entityKey, grain, unit, owner string
	var version, projectionVersion int64
	var filters []string
	if err := row.Scan(&id, &version, &status, &name, &connectionID, &projectionVersion,
		&entityKey, &grain, &filters, &unit, &owner); err != nil {
		return Definition{}, err
	}
	if !validID(id) || !validID(owner) || !Status(status).valid() {
		return Definition{}, errors.New("METRICDEFINITION_PERSISTENCE_INVALID")
	}
	normalized, err := normalizeSpec(Spec{
		Name: name, Source: SourceConnection{ConnectionID: connectionID, ProjectionVersion: projectionVersion},
		EntityKey: entityKey, Grain: PeriodGrain(grain), Unit: unit, AllowedFilters: filters,
	})
	if err != nil {
		return Definition{}, errors.New("METRICDEFINITION_PERSISTENCE_INVALID")
	}
	return Definition{
		id: id, workspaceID: workspaceID, ownerPrincipalID: owner, version: version,
		name: normalized.name, source: normalized.source, entityKey: normalized.entityKey,
		grain: normalized.grain, allowedFilters: normalized.filters, unit: normalized.unit,
		status: Status(status),
	}, nil
}

// loadSeries rehydrates the whole version history of one definition id from
// the durable rows, locking the definition pointer so concurrent writers
// serialize. It is the only place that reconstructs a Series from persistence;
// everything else flows through Series' own transition methods.
func loadSeries(ctx context.Context, transaction database.Transaction,
	organizationID, workspaceID, definitionID, currentOwner string) (Series, bool, error) {
	var owner string
	err := transaction.QueryRow(ctx, `
		SELECT owner_principal_id
		FROM public.metric_definition
		WHERE organization_id = $1 AND workspace_id = $2 AND id = $3
		FOR UPDATE
	`, organizationID, workspaceID, definitionID).Scan(&owner)
	if database.IsNotFound(err) {
		return Series{}, false, nil
	}
	if err != nil {
		return Series{}, false, err
	}
	rows, err := transaction.Query(ctx, `
		SELECT definition_id, version, status, name, source_connection_id,
		       projection_version, entity_key, grain, allowed_filters, unit,
		       owner_principal_id
		FROM public.metric_definition_version
		WHERE organization_id = $1 AND workspace_id = $2 AND definition_id = $3
		ORDER BY version
	`, organizationID, workspaceID, definitionID)
	if err != nil {
		return Series{}, false, err
	}
	defer rows.Close()
	series := Series{
		id: definitionID, workspaceID: workspaceID, ownerPrincipalID: owner,
		versions: map[int64]Definition{}, highest: 0,
	}
	for rows.Next() {
		definition, scanErr := scanDefinition(rows, workspaceID)
		if scanErr != nil {
			return Series{}, false, scanErr
		}
		series.versions[definition.version] = definition
		if definition.version > series.highest {
			series.highest = definition.version
		}
	}
	if err := rows.Err(); err != nil {
		return Series{}, false, err
	}
	if series.highest == 0 {
		return Series{}, false, errors.New("METRICDEFINITION_PERSISTENCE_INVALID")
	}
	// The approver authority is always the current workspace owner.
	series.ownerPrincipalID = currentOwner
	return series, true, nil
}

func insertDefinition(ctx context.Context, transaction database.Transaction, access database.AccessContext,
	workspaceID, definitionID, ownerPrincipalID string) error {
	_, err := transaction.Exec(ctx, `
		INSERT INTO public.metric_definition (
			organization_id, workspace_id, id, owner_principal_id, current_version, created_by
		) VALUES ($1, $2, $3, $4, 1, $5)
	`, access.OrganizationID, workspaceID, definitionID, ownerPrincipalID, access.PrincipalID)
	return err
}

func insertVersion(ctx context.Context, transaction database.Transaction, access database.AccessContext,
	definition Definition) error {
	_, err := transaction.Exec(ctx, `
		INSERT INTO public.metric_definition_version (
			organization_id, workspace_id, definition_id, version, status, name,
			source_connection_id, projection_version, entity_key, grain,
			allowed_filters, unit, owner_principal_id, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`, access.OrganizationID, definition.workspaceID, definition.id, definition.version,
		string(definition.status), definition.name, definition.source.ConnectionID,
		definition.source.ProjectionVersion, definition.entityKey, string(definition.grain),
		definition.allowedFilters.Values(), definition.unit, definition.ownerPrincipalID,
		access.PrincipalID)
	return err
}

// updateDraftVersion edits a DRAFT in place. The WHERE clause restricts the
// update to a DRAFT row, so an APPROVED version can never be rewritten here
// even if a future caller skipped Series; the database guard is the second
// line of defence.
func updateDraftVersion(ctx context.Context, transaction database.Transaction, access database.AccessContext,
	definition Definition) error {
	tag, err := transaction.Exec(ctx, `
		UPDATE public.metric_definition_version
		SET name = $6, source_connection_id = $7, projection_version = $8,
		    entity_key = $9, grain = $10, allowed_filters = $11, unit = $12
		WHERE organization_id = $1 AND workspace_id = $2 AND definition_id = $3
		  AND version = $4 AND status = 'DRAFT'
	`, access.OrganizationID, definition.workspaceID, definition.id, definition.version,
		definition.name, definition.source.ConnectionID, definition.source.ProjectionVersion,
		definition.entityKey, string(definition.grain), definition.allowedFilters.Values(), definition.unit)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return newError(CodeNotApprovable)
	}
	return nil
}

func bumpCurrentVersion(ctx context.Context, transaction database.Transaction, access database.AccessContext,
	workspaceID, definitionID string, expected, next int64) error {
	tag, err := transaction.Exec(ctx, `
		UPDATE public.metric_definition
		SET current_version = $5
		WHERE organization_id = $1 AND workspace_id = $2 AND id = $3 AND current_version = $4
	`, access.OrganizationID, workspaceID, definitionID, expected, next)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return newError(CodeVersionNotMonotonic)
	}
	return nil
}

func markApproved(ctx context.Context, transaction database.Transaction, access database.AccessContext,
	definition Definition) error {
	tag, err := transaction.Exec(ctx, `
		UPDATE public.metric_definition_version
		SET status = 'APPROVED', approved_by = $5, approved_at = $6
		WHERE organization_id = $1 AND workspace_id = $2 AND definition_id = $3
		  AND version = $4 AND status = 'DRAFT'
	`, access.OrganizationID, definition.workspaceID, definition.id, definition.version,
		access.PrincipalID, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return newError(CodeNotApprovable)
	}
	return nil
}
