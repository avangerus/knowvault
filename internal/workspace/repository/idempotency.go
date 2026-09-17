package repository

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"

	"golang.org/x/text/unicode/norm"
)

const (
	commandSchemaVersion       = "workspace-command-v1"
	sourceCommandSchemaVersion = "workspace-command-v2"
)

type commandOperation string

type receiptStatus string

const (
	operationCreate            commandOperation = "WORKSPACE_CREATE"
	operationUpdate            commandOperation = "WORKSPACE_UPDATE"
	operationArchive           commandOperation = "WORKSPACE_ARCHIVE"
	operationMemberAdd         commandOperation = "WORKSPACE_MEMBER_ADD"
	operationMemberRoleChange  commandOperation = "WORKSPACE_MEMBER_ROLE_CHANGE"
	operationMemberRemove      commandOperation = "WORKSPACE_MEMBER_REMOVE"
	operationOwnershipTransfer commandOperation = "WORKSPACE_OWNERSHIP_TRANSFER"
	operationSourceAdd         commandOperation = "WORKSPACE_SOURCE_ADD"
	operationSourceRemove      commandOperation = "WORKSPACE_SOURCE_REMOVE"
)

const (
	receiptPending            receiptStatus = "PENDING"
	receiptSuccess            receiptStatus = "SUCCESS"
	receiptDenied             receiptStatus = "DENIED"
	receiptNotFound           receiptStatus = "NOT_FOUND"
	receiptPreconditionFailed receiptStatus = "PRECONDITION_FAILED"
)

type commandReservation struct {
	created  bool
	status   receiptStatus
	snapshot workspace.Snapshot
}

// commandIntent is the immutable, operation-specific receipt identity. It is
// deliberately separate from the canonical request hash: its fields bind the
// receipt to the exact audit resource and membership target that the command
// may affect.
type commandIntent struct {
	Operation         commandOperation
	WorkspaceID       string
	TargetPrincipalID string
	TargetRole        workspace.Role
	ResourceType      audit.ResourceType
	ResourceID        string
	Source            *sourceCommandIntent
}

// sourceCommandIntent is the closed gate-v2 receipt projection. Every field
// is immutable after reservation and binds one workspace base revision to one
// exact source-scope revision. ADD requires that revision to remain DRAFT;
// REMOVE uses the same exact tuple to revoke an enabled binding. It is
// configuration provenance only.
type sourceCommandIntent struct {
	ExpectedWorkspaceRevision int64
	ExpectedConfigurationHash string
	WorkspaceSourceID         string
	SourceScopeID             string
	SourceScopeRevision       int64
	ScopeConfigHash           string
	AccessMode                SourceAccessMode
}

type commandEnvelope struct {
	SchemaVersion string           `json:"schema_version"`
	Operation     commandOperation `json:"operation"`
	Request       any              `json:"request"`
}

type createCommandPayload struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	RetentionPolicyID string `json:"retention_policy_id"`
}

type updateCommandPayload struct {
	WorkspaceID               string `json:"workspace_id"`
	ExpectedConfigurationHash string `json:"expected_configuration_hash"`
	Name                      string `json:"name"`
	Description               string `json:"description"`
	RetentionPolicyID         string `json:"retention_policy_id"`
}

type archiveCommandPayload struct {
	WorkspaceID               string `json:"workspace_id"`
	ExpectedConfigurationHash string `json:"expected_configuration_hash"`
}

type memberCommandPayload struct {
	WorkspaceID               string `json:"workspace_id"`
	ExpectedConfigurationHash string `json:"expected_configuration_hash"`
	PrincipalID               string `json:"principal_id"`
	Role                      string `json:"role,omitempty"`
}

type sourceCommandPayload struct {
	WorkspaceID               string `json:"workspace_id"`
	ExpectedWorkspaceRevision int64  `json:"expected_workspace_revision"`
	ExpectedConfigurationHash string `json:"expected_configuration_hash"`
	SourceScopeID             string `json:"source_scope_id"`
	SourceScopeRevision       int64  `json:"source_scope_revision"`
	ScopeConfigHash           string `json:"scope_config_hash"`
	AccessMode                string `json:"access_mode"`
	WorkspaceSourceID         string `json:"workspace_source_id,omitempty"`
}

func createCommandHash(request CreateRequest) (string, error) {
	return canonicalCommandHash(operationCreate, createCommandPayload{
		Name: norm.NFC.String(request.Name), Description: norm.NFC.String(request.Description),
		RetentionPolicyID: request.RetentionPolicyID,
	})
}

func updateCommandHash(request UpdateRequest) (string, error) {
	return canonicalCommandHash(operationUpdate, updateCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedConfigurationHash: request.ExpectedConfigurationHash,
		Name: norm.NFC.String(request.Name), Description: norm.NFC.String(request.Description), RetentionPolicyID: request.RetentionPolicyID,
	})
}

func archiveCommandHash(request ArchiveRequest) (string, error) {
	return canonicalCommandHash(operationArchive, archiveCommandPayload{WorkspaceID: request.WorkspaceID, ExpectedConfigurationHash: request.ExpectedConfigurationHash})
}

func addMemberCommandHash(request AddMemberRequest) (string, error) {
	return canonicalCommandHash(operationMemberAdd, memberCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedConfigurationHash: request.ExpectedConfigurationHash,
		PrincipalID: request.PrincipalID, Role: string(request.Role),
	})
}

func changeMemberRoleCommandHash(request ChangeMemberRoleRequest) (string, error) {
	return canonicalCommandHash(operationMemberRoleChange, memberCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedConfigurationHash: request.ExpectedConfigurationHash,
		PrincipalID: request.PrincipalID, Role: string(request.Role),
	})
}

func removeMemberCommandHash(request RemoveMemberRequest) (string, error) {
	return canonicalCommandHash(operationMemberRemove, memberCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedConfigurationHash: request.ExpectedConfigurationHash, PrincipalID: request.PrincipalID,
	})
}

func transferOwnershipCommandHash(request TransferOwnershipRequest) (string, error) {
	return canonicalCommandHash(operationOwnershipTransfer, memberCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedConfigurationHash: request.ExpectedConfigurationHash, PrincipalID: request.NewOwnerPrincipalID,
	})
}

func addSourceCommandHash(request AddSourceRequest) (string, error) {
	return canonicalCommandHashWithVersion(sourceCommandSchemaVersion, operationSourceAdd, sourceCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
		AccessMode: string(request.AccessMode),
	})
}

func removeSourceCommandHash(request RemoveSourceRequest) (string, error) {
	return canonicalCommandHashWithVersion(sourceCommandSchemaVersion, operationSourceRemove, sourceCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
		AccessMode: string(request.AccessMode), WorkspaceSourceID: request.WorkspaceSourceID,
	})
}

func canonicalCommandHash(operation commandOperation, payload any) (string, error) {
	return canonicalCommandHashWithVersion(commandSchemaVersion, operation, payload)
}

func canonicalCommandHashWithVersion(schemaVersion string, operation commandOperation, payload any) (string, error) {
	raw, err := json.Marshal(commandEnvelope{SchemaVersion: schemaVersion, Operation: operation, Request: payload})
	if err != nil {
		return "", err
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func idempotencyKeyHash(key string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != key {
		return "", &Error{code: CodeRequestInvalid}
	}
	digest := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// commandResourceID is deterministic within the actor-scoped idempotency
// namespace. Receipts persist audit resource IDs, so retries must derive the
// same server-generated workspace/member ID before the reservation lookup.
func commandResourceID(prefix, organizationID, actorPrincipalID, keyHash string, operation commandOperation) string {
	digest := sha256.Sum256([]byte("workspace-command-resource-v1\x00" + prefix + "\x00" + organizationID + "\x00" + actorPrincipalID + "\x00" + keyHash + "\x00" + string(operation)))
	return prefix + hex.EncodeToString(digest[:])
}

func nullableCommandIntentValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func matchesNullableCommandIntentValue(stored *string, expected string) bool {
	if expected == "" {
		return stored == nil
	}
	return stored != nil && *stored == expected
}

func (intent commandIntent) matches(storedGateVersion int16, storedOperation string, storedWorkspaceID, storedTargetPrincipalID, storedTargetRole, storedResourceType, storedResourceID *string, storedSource sourceCommandReceiptProjection) bool {
	if storedOperation != string(intent.Operation) ||
		!matchesNullableCommandIntentValue(storedWorkspaceID, intent.WorkspaceID) ||
		!matchesNullableCommandIntentValue(storedTargetPrincipalID, intent.TargetPrincipalID) ||
		!matchesNullableCommandIntentValue(storedTargetRole, string(intent.TargetRole)) ||
		!matchesNullableCommandIntentValue(storedResourceType, string(intent.ResourceType)) ||
		!matchesNullableCommandIntentValue(storedResourceID, intent.ResourceID) {
		return false
	}
	if intent.Source == nil {
		return storedGateVersion == 1 && storedSource.isNull()
	}
	return storedGateVersion == 2 && storedSource.matches(*intent.Source)
}

type sourceCommandReceiptProjection struct {
	ExpectedWorkspaceRevision *int64
	ExpectedConfigurationHash *string
	WorkspaceSourceID         *string
	SourceScopeID             *string
	SourceScopeRevision       *int64
	ScopeConfigHash           *string
	AccessMode                *string
}

func (projection sourceCommandReceiptProjection) isNull() bool {
	return projection.ExpectedWorkspaceRevision == nil && projection.ExpectedConfigurationHash == nil &&
		projection.WorkspaceSourceID == nil && projection.SourceScopeID == nil &&
		projection.SourceScopeRevision == nil && projection.ScopeConfigHash == nil && projection.AccessMode == nil
}

func (projection sourceCommandReceiptProjection) matches(expected sourceCommandIntent) bool {
	return projection.ExpectedWorkspaceRevision != nil && *projection.ExpectedWorkspaceRevision == expected.ExpectedWorkspaceRevision &&
		projection.ExpectedConfigurationHash != nil && *projection.ExpectedConfigurationHash == expected.ExpectedConfigurationHash &&
		projection.WorkspaceSourceID != nil && *projection.WorkspaceSourceID == expected.WorkspaceSourceID &&
		projection.SourceScopeID != nil && *projection.SourceScopeID == expected.SourceScopeID &&
		projection.SourceScopeRevision != nil && *projection.SourceScopeRevision == expected.SourceScopeRevision &&
		projection.ScopeConfigHash != nil && *projection.ScopeConfigHash == expected.ScopeConfigHash &&
		projection.AccessMode != nil && *projection.AccessMode == string(expected.AccessMode)
}

func commandGateVersion(intent commandIntent) int16 {
	if intent.Source != nil {
		return 2
	}
	return 1
}

func nullableSourceIntent(intent *sourceCommandIntent) (any, any, any, any, any, any, any) {
	if intent == nil {
		return nil, nil, nil, nil, nil, nil, nil
	}
	return intent.ExpectedWorkspaceRevision, intent.ExpectedConfigurationHash, intent.WorkspaceSourceID,
		intent.SourceScopeID, intent.SourceScopeRevision, intent.ScopeConfigHash, string(intent.AccessMode)
}

/*
The source fields below deliberately stay SQL NULL for every gate-v1
command. This is checked both here during replay and by the database shape
constraint, so adding a source command cannot weaken an older operation.
*/
func reserveCommand(ctx context.Context, transaction database.Transaction, organizationID, actorPrincipalID, keyHash string, intent commandIntent, requestHash string) (commandReservation, error) {
	expectedRevision, expectedHash, workspaceSourceID, sourceScopeID, sourceScopeRevision, scopeHash, accessMode := nullableSourceIntent(intent.Source)
	tag, err := transaction.Exec(ctx, `
		INSERT INTO public.workspace_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, gate_version, operation, canonical_request_hash,
			command_workspace_id, command_target_principal_id, command_target_role,
			command_resource_type, command_resource_id,
			source_expected_workspace_revision, source_expected_configuration_hash,
			command_workspace_source_id, command_source_scope_id, command_source_scope_revision,
			command_scope_config_hash, command_access_mode
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT (organization_id, actor_principal_id, idempotency_key_hash) DO NOTHING
	`, organizationID, actorPrincipalID, keyHash, commandGateVersion(intent), string(intent.Operation), requestHash,
		intent.WorkspaceID, nullableCommandIntentValue(intent.TargetPrincipalID), nullableCommandIntentValue(string(intent.TargetRole)),
		string(intent.ResourceType), intent.ResourceID, expectedRevision, expectedHash, workspaceSourceID, sourceScopeID,
		sourceScopeRevision, scopeHash, accessMode)
	if err != nil {
		return commandReservation{}, err
	}
	if tag.RowsAffected() == 1 {
		return commandReservation{created: true, status: receiptPending}, nil
	}

	var storedGateVersion int16
	var storedOperation, storedRequestHash string
	var storedWorkspaceID, storedTargetPrincipalID, storedTargetRole, storedResourceType, storedResourceID *string
	var storedSource sourceCommandReceiptProjection
	var status receiptStatus
	var resultWorkspaceID, resultConfigurationHash *string
	var resultRevision *int64
	err = transaction.QueryRow(ctx, `
		SELECT gate_version, operation, canonical_request_hash,
		       command_workspace_id, command_target_principal_id, command_target_role,
		       command_resource_type, command_resource_id,
		       source_expected_workspace_revision, source_expected_configuration_hash,
		       command_workspace_source_id, command_source_scope_id, command_source_scope_revision,
		       command_scope_config_hash, command_access_mode,
		       status, result_workspace_id, result_workspace_revision, result_configuration_hash
		FROM public.workspace_command_receipt
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		FOR UPDATE
	`, organizationID, actorPrincipalID, keyHash).Scan(
		&storedGateVersion, &storedOperation, &storedRequestHash,
		&storedWorkspaceID, &storedTargetPrincipalID, &storedTargetRole, &storedResourceType, &storedResourceID,
		&storedSource.ExpectedWorkspaceRevision, &storedSource.ExpectedConfigurationHash,
		&storedSource.WorkspaceSourceID, &storedSource.SourceScopeID, &storedSource.SourceScopeRevision,
		&storedSource.ScopeConfigHash, &storedSource.AccessMode,
		&status, &resultWorkspaceID, &resultRevision, &resultConfigurationHash,
	)
	if err != nil {
		return commandReservation{}, err
	}
	if storedRequestHash != requestHash || !intent.matches(storedGateVersion, storedOperation, storedWorkspaceID, storedTargetPrincipalID, storedTargetRole, storedResourceType, storedResourceID, storedSource) {
		return commandReservation{}, &Error{code: CodeIdempotencyConflict}
	}
	if status == receiptPending {
		return commandReservation{}, &Error{code: CodePersistence}
	}
	if status != receiptSuccess {
		return commandReservation{status: status}, nil
	}
	if resultWorkspaceID == nil || resultRevision == nil || resultConfigurationHash == nil {
		return commandReservation{}, &Error{code: CodePersistence}
	}

	var canonical []byte
	if err := transaction.QueryRow(ctx, `
		SELECT canonical_bytes
		FROM public.workspace_revision_snapshot
		WHERE organization_id = $1 AND workspace_id = $2 AND revision = $3 AND configuration_hash = $4
	`, organizationID, *resultWorkspaceID, *resultRevision, *resultConfigurationHash).Scan(&canonical); err != nil {
		if database.IsNotFound(err) {
			return commandReservation{}, &Error{code: CodeNotFound}
		}
		return commandReservation{}, err
	}
	snapshot, err := workspace.ParseCanonicalSnapshot(canonical)
	if err != nil || snapshot.OrganizationID != organizationID || snapshot.ID != *resultWorkspaceID || snapshot.Revision != *resultRevision {
		return commandReservation{}, &Error{code: CodePersistence, cause: err}
	}
	hash, err := workspace.ConfigurationHash(snapshot)
	if err != nil || hash != *resultConfigurationHash {
		return commandReservation{}, &Error{code: CodePersistence, cause: err}
	}
	if err := hydrateMemberDisplayNames(ctx, transaction, &snapshot); err != nil {
		return commandReservation{}, err
	}
	return commandReservation{status: status, snapshot: snapshot}, nil
}

func persistRevisionSnapshot(ctx context.Context, transaction database.Transaction, snapshot workspace.Snapshot, sources []revisionSourceProjection) (string, error) {
	canonical, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		return "", &Error{code: CodePersistence, cause: err}
	}
	hash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		return "", &Error{code: CodePersistence, cause: err}
	}
	carriedSources, valid := carrySourceProjection(sources, snapshot, hash)
	if !valid {
		return "", &Error{code: CodePersistence}
	}
	_, err = transaction.Exec(ctx, `
		INSERT INTO public.workspace_revision_snapshot (
			organization_id, workspace_id, revision, configuration_hash, canonical_bytes
		) VALUES ($1, $2, $3, $4, $5)
	`, snapshot.OrganizationID, snapshot.ID, snapshot.Revision, hash, canonical)
	if err != nil {
		return "", err
	}
	for _, source := range carriedSources {
		if _, err = transaction.Exec(ctx, `
			INSERT INTO public.workspace_revision_source (
				organization_id, workspace_id, workspace_revision,
				workspace_configuration_hash, workspace_source_id,
				source_scope_id, source_scope_revision, scope_config_hash,
				access_mode, enabled
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, snapshot.OrganizationID, snapshot.ID, snapshot.Revision, source.WorkspaceConfigurationHash,
			source.WorkspaceSourceID, source.SourceScopeID, source.SourceScopeRevision,
			source.ScopeConfigHash, source.AccessMode, source.Enabled); err != nil {
			return "", err
		}
	}
	return hash, nil
}

func completeCommand(ctx context.Context, transaction database.Transaction, organizationID, actorPrincipalID, keyHash string, status receiptStatus, snapshot *workspace.Snapshot, auditEventID string) error {
	var workspaceID any
	var revision any
	var configurationHash any
	if status == receiptSuccess {
		if snapshot == nil {
			return &Error{code: CodePersistence}
		}
		hash, err := workspace.ConfigurationHash(*snapshot)
		if err != nil {
			return &Error{code: CodePersistence, cause: err}
		}
		workspaceID, revision, configurationHash = snapshot.ID, snapshot.Revision, hash
	} else if status != receiptDenied && status != receiptNotFound && status != receiptPreconditionFailed {
		return &Error{code: CodePersistence}
	}
	tag, err := transaction.Exec(ctx, `
		UPDATE public.workspace_command_receipt
		SET status = $4, result_workspace_id = $5, result_workspace_revision = $6,
		    result_configuration_hash = $7, audit_event_id = $8, terminal_at = transaction_timestamp()
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3 AND status = 'PENDING'
	`, organizationID, actorPrincipalID, keyHash, string(status), workspaceID, revision, configurationHash, auditEventID)
	if err != nil || tag.RowsAffected() != 1 {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func replayError(status receiptStatus) error {
	switch status {
	case receiptDenied:
		return &Error{code: CodeDenied}
	case receiptNotFound:
		return &Error{code: CodeNotFound}
	case receiptPreconditionFailed:
		return &Error{code: CodeRevisionConflict}
	default:
		return &Error{code: CodePersistence}
	}
}
