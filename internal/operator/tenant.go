package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/text/unicode/norm"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/workspace"
)

const (
	tenantOrganizationStatus = "ACTIVE"
	tenantPrincipalType      = "USER"
	tenantPrincipalStatus    = "ACTIVE"
	tenantWorkspaceStatus    = workspace.StatusActive
	tenantRevision           = int64(1)
)

// TenantProvisionRequest is the complete input for the initial owner tenant.
//
// OrganizationName, Region, OwnerDisplayName, WorkspaceID and WorkspaceName
// are deliberately caller supplied: these are the non-null business values
// required by the Stage 1 schema and are not guessed from an identifier. The
// initial principal and both initial aggregates are always ACTIVE; an owner
// tenant cannot be provisioned with a disabled principal or a non-active
// workspace. WorkspaceDescription and RetentionPolicyID are optional schema
// values and default to their Stage 1 empty values.
//
// WorkspaceRegion is accepted as a compatibility spelling for callers that
// describe a workspace's deployment region. Stage 1 stores region on
// organization, so when supplied it must exactly agree with Region.
type TenantProvisionRequest struct {
	OrganizationID       string
	OrganizationName     string
	Region               string
	WorkspaceRegion      string
	OwnerPrincipalID     string
	OwnerDisplayName     string
	WorkspaceID          string
	WorkspaceName        string
	WorkspaceDescription string
	RetentionPolicyID    string
}

// TenantProvision creates the minimum active owner tenant in one transaction.
// It is intended for the admin connection after the versioned migrations have
// been applied; runtime application roles remain unable to create an owner
// tenant. The returned bool is true only when this invocation inserted the
// state. An exact repeat verifies every deterministic row and returns false.
// Any pre-existing expected row, cross-tenant identifier collision, or drift
// is an incompatible migration state. The operation never overwrites or
// deletes state to make a request fit.
func TenantProvision(ctx context.Context, pool *pgxpool.Pool, request TenantProvisionRequest) (created bool, err error) {
	if ctx == nil || pool == nil {
		return false, DependencyUnavailable("nil context or pool")
	}
	payload, err := prepareTenantProvision(request)
	if err != nil {
		return false, MigrationIncompatible("tenant provisioning input fails the shared schema shape")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, DependencyUnavailable("begin tenant provisioning transaction failed: " + err.Error())
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Organization IDs are the serialization point for the operation. This
	// closes the absent-row race on a clean install without relying on a
	// test-only seed helper; unique constraints still protect global IDs when
	// two different organizations race for the same owner/workspace ID.
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, payload.organizationID); err != nil {
		return false, classifyTenantDatabaseError("tenant provisioning lock failed", err)
	}

	state, err := inspectTenantProvision(ctx, tx, payload)
	if err != nil {
		return false, err
	}
	if state.complete() {
		if err := tx.Commit(ctx); err != nil {
			return false, classifyTenantDatabaseError("tenant provisioning repeat commit failed", err)
		}
		return false, nil
	}
	if state.anyPresent() {
		return false, MigrationIncompatible("tenant provisioning found an incomplete or conflicting owner state")
	}

	var occurredAt time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&occurredAt); err != nil {
		return false, classifyTenantDatabaseError("tenant provisioning timestamp lookup failed", err)
	}
	// This is the genesis event for a newly-created organization: Build takes
	// the current head sequence, not the event sequence. The audit trigger will
	// establish the zero head and require the resulting event sequence to be 1.
	event, err := buildTenantAuditEvent(payload, 0, "sha256:"+strings.Repeat("0", 64), occurredAt)
	if err != nil {
		return false, MigrationIncompatible("tenant provisioning audit payload is invalid")
	}

	if err := insertTenantRows(ctx, tx, payload, event); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, classifyTenantDatabaseError("tenant provisioning commit failed", err)
	}
	return true, nil
}

// ProvisionTenant is the descriptive alias used by non-CLI callers. Keep the
// operation itself named TenantProvision so the operator command wiring can
// use a concise, stable signature.
func ProvisionTenant(ctx context.Context, pool *pgxpool.Pool, request TenantProvisionRequest) (bool, error) {
	return TenantProvision(ctx, pool, request)
}

type tenantPayload struct {
	organizationID       string
	organizationName     string
	region               string
	ownerPrincipalID     string
	ownerDisplayName     string
	workspaceID          string
	workspaceName        string
	workspaceDescription string
	retentionPolicyID    string
	roleAssignmentID     string
	membershipID         string
	auditEventID         string
	requestID            string
	snapshot             workspace.Snapshot
	configurationHash    string
	canonicalBytes       []byte
}

func prepareTenantProvision(request TenantProvisionRequest) (tenantPayload, error) {
	if !utf8.ValidString(request.OrganizationID) || !utf8.ValidString(request.OrganizationName) ||
		!utf8.ValidString(request.Region) || !utf8.ValidString(request.WorkspaceRegion) ||
		!utf8.ValidString(request.OwnerPrincipalID) || !utf8.ValidString(request.OwnerDisplayName) ||
		!utf8.ValidString(request.WorkspaceID) || !utf8.ValidString(request.WorkspaceName) ||
		!utf8.ValidString(request.WorkspaceDescription) || !utf8.ValidString(request.RetentionPolicyID) {
		return tenantPayload{}, errors.New("tenant input is not valid UTF-8")
	}
	region := norm.NFC.String(request.Region)
	workspaceRegion := norm.NFC.String(request.WorkspaceRegion)
	if region == "" {
		region = workspaceRegion
	} else if workspaceRegion != "" && workspaceRegion != region {
		return tenantPayload{}, errors.New("organization and workspace regions disagree")
	}
	organizationName := norm.NFC.String(request.OrganizationName)
	ownerDisplayName := norm.NFC.String(request.OwnerDisplayName)

	// workspace.Normalize is the single source of truth for identifier shape,
	// text NFC normalization, revision bounds, status and owner membership.
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID:    request.OrganizationID,
		ID:                request.WorkspaceID,
		Revision:          tenantRevision,
		Name:              request.WorkspaceName,
		Description:       request.WorkspaceDescription,
		Status:            tenantWorkspaceStatus,
		OwnerPrincipalID:  request.OwnerPrincipalID,
		RetentionPolicyID: request.RetentionPolicyID,
		Members:           []workspace.Member{{PrincipalID: request.OwnerPrincipalID, Role: workspace.RoleOwner}},
		SourceBindings:    []workspace.SourceBinding{},
	})
	if err != nil || !validTenantName(organizationName) || !validTenantName(ownerDisplayName) || !validTenantRegion(region) {
		return tenantPayload{}, errors.New("tenant input fails schema shape")
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		return tenantPayload{}, err
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		return tenantPayload{}, err
	}

	return tenantPayload{
		organizationID:       snapshot.OrganizationID,
		organizationName:     organizationName,
		region:               region,
		ownerPrincipalID:     snapshot.OwnerPrincipalID,
		ownerDisplayName:     ownerDisplayName,
		workspaceID:          snapshot.ID,
		workspaceName:        snapshot.Name,
		workspaceDescription: snapshot.Description,
		retentionPolicyID:    snapshot.RetentionPolicyID,
		roleAssignmentID:     tenantDerivedID("ora_", snapshot.OrganizationID),
		membershipID:         tenantDerivedID("wsm_", snapshot.ID),
		auditEventID:         tenantDerivedID("aud_tenant_", snapshot.OrganizationID),
		requestID:            tenantDerivedID("req_tenant_", snapshot.OrganizationID),
		snapshot:             snapshot,
		configurationHash:    configurationHash,
		canonicalBytes:       canonicalBytes,
	}, nil
}

func validTenantName(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= 256 &&
		strings.TrimSpace(value) == value && !strings.ContainsFunc(value, hasTenantControl)
}

func validTenantRegion(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= 64 &&
		strings.TrimSpace(value) == value && !strings.ContainsFunc(value, hasTenantControl)
}

func hasTenantControl(value rune) bool {
	return value < 0x20 || (value >= 0x7f && value <= 0x9f)
}

func tenantDerivedID(prefix, value string) string {
	if len(prefix)+len(value) <= 128 {
		return prefix + value
	}
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}

type tenantProvisionState struct {
	organization tenantRowState
	principal    tenantRowState
	role         tenantRowState
	workspace    tenantRowState
	revision     tenantRowState
	snapshot     tenantRowState
	membership   tenantRowState
	audit        tenantRowState
	auditHead    tenantRowState
}

type tenantRowState struct {
	present bool
	exact   bool
}

func (state tenantProvisionState) complete() bool {
	return state.organization.present && state.organization.exact &&
		state.principal.present && state.principal.exact &&
		state.role.present && state.role.exact &&
		state.workspace.present && state.workspace.exact &&
		state.revision.present && state.revision.exact &&
		state.snapshot.present && state.snapshot.exact &&
		state.membership.present && state.membership.exact &&
		state.audit.present && state.audit.exact &&
		state.auditHead.present && state.auditHead.exact
}

func (state tenantProvisionState) anyPresent() bool {
	return state.organization.present || state.principal.present || state.role.present || state.workspace.present ||
		state.revision.present || state.snapshot.present || state.membership.present || state.audit.present || state.auditHead.present
}

func inspectTenantProvision(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantProvisionState, error) {
	var state tenantProvisionState
	var err error
	if state.organization, err = inspectTenantOrganization(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.principal, err = inspectTenantPrincipal(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.role, err = inspectTenantRole(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.workspace, err = inspectTenantWorkspace(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.revision, err = inspectTenantRevision(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.snapshot, err = inspectTenantSnapshot(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.membership, err = inspectTenantMembership(ctx, tx, payload); err != nil {
		return state, err
	}
	if state.audit, state.auditHead, err = inspectTenantAudit(ctx, tx, payload); err != nil {
		return state, err
	}
	return state, nil
}

func inspectTenantOrganization(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var name, status, region, owner string
	var policyRevision, roleRevision int64
	var encryptionReference *string
	err := tx.QueryRow(ctx, `
		SELECT name, status, region, policy_revision, role_revision, owner_principal_id, encryption_key_reference
		FROM public.organization WHERE id = $1 FOR UPDATE`, payload.organizationID).
		Scan(&name, &status, &region, &policyRevision, &roleRevision, &owner, &encryptionReference)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("organization state lookup failed", err)
	}
	exact := name == payload.organizationName && status == tenantOrganizationStatus && region == payload.region &&
		policyRevision == tenantRevision && roleRevision == tenantRevision && owner == payload.ownerPrincipalID && encryptionReference == nil
	return tenantRowState{present: true, exact: exact}, nil
}

func inspectTenantPrincipal(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var organizationID, principalType, displayName, status string
	var sessionRevision int64
	err := tx.QueryRow(ctx, `
		SELECT organization_id, type, display_name, status, session_revision
		FROM public.principal WHERE id = $1 FOR UPDATE`, payload.ownerPrincipalID).
		Scan(&organizationID, &principalType, &displayName, &status, &sessionRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("owner principal state lookup failed", err)
	}
	exact := organizationID == payload.organizationID && principalType == tenantPrincipalType && displayName == payload.ownerDisplayName &&
		status == tenantPrincipalStatus && sessionRevision == tenantRevision
	return tenantRowState{present: true, exact: exact}, nil
}

func inspectTenantRole(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var organizationID, principalID, role, assignedBy string
	var validFrom int64
	var validTo *int64
	var revokedBy *string
	var revokedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT organization_id, principal_id, role, valid_from_revision, valid_to_revision,
		       assigned_by, revoked_by, revoked_at
		FROM public.organization_role_assignment WHERE id = $1 FOR UPDATE`, payload.roleAssignmentID).
		Scan(&organizationID, &principalID, &role, &validFrom, &validTo, &assignedBy, &revokedBy, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("owner role state lookup failed", err)
	}
	exact := organizationID == payload.organizationID && principalID == payload.ownerPrincipalID && role == "OWNER" &&
		validFrom == tenantRevision && validTo == nil && assignedBy == payload.ownerPrincipalID && revokedBy == nil && revokedAt == nil
	return tenantRowState{present: true, exact: exact}, nil
}

func inspectTenantWorkspace(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var organizationID, name, description, status, owner string
	var revision int64
	var retentionPolicyID *string
	err := tx.QueryRow(ctx, `
		SELECT organization_id, name, description, status, owner_principal_id, current_revision, retention_policy_id
		FROM public.workspace WHERE id = $1 FOR UPDATE`, payload.workspaceID).
		Scan(&organizationID, &name, &description, &status, &owner, &revision, &retentionPolicyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("workspace state lookup failed", err)
	}
	exactRetention := (retentionPolicyID == nil && payload.retentionPolicyID == "") ||
		(retentionPolicyID != nil && payload.retentionPolicyID != "" && *retentionPolicyID == payload.retentionPolicyID)
	exact := organizationID == payload.organizationID && name == payload.workspaceName && description == payload.workspaceDescription &&
		status == string(tenantWorkspaceStatus) && owner == payload.ownerPrincipalID && revision == tenantRevision && exactRetention
	return tenantRowState{present: true, exact: exact}, nil
}

func inspectTenantRevision(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var hash, createdBy string
	err := tx.QueryRow(ctx, `
		SELECT configuration_hash, created_by
		FROM public.workspace_revision
		WHERE organization_id = $1 AND workspace_id = $2 AND revision = $3
		FOR UPDATE`, payload.organizationID, payload.workspaceID, tenantRevision).
		Scan(&hash, &createdBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("workspace revision state lookup failed", err)
	}
	return tenantRowState{present: true, exact: hash == payload.configurationHash && createdBy == payload.ownerPrincipalID}, nil
}

func inspectTenantSnapshot(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var hash string
	var canonical []byte
	err := tx.QueryRow(ctx, `
		SELECT configuration_hash, canonical_bytes
		FROM public.workspace_revision_snapshot
		WHERE organization_id = $1 AND workspace_id = $2 AND revision = $3
		FOR UPDATE`, payload.organizationID, payload.workspaceID, tenantRevision).
		Scan(&hash, &canonical)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("workspace snapshot state lookup failed", err)
	}
	return tenantRowState{present: true, exact: hash == payload.configurationHash && bytes.Equal(canonical, payload.canonicalBytes)}, nil
}

func inspectTenantMembership(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, error) {
	var organizationID, workspaceID, principalID, role, addedBy string
	var validFrom int64
	var validTo *int64
	var removedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT organization_id, workspace_id, principal_id, role, valid_from_revision,
		       valid_to_revision, added_by, removed_at
		FROM public.workspace_member WHERE id = $1 FOR UPDATE`, payload.membershipID).
		Scan(&organizationID, &workspaceID, &principalID, &role, &validFrom, &validTo, &addedBy, &removedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("owner membership state lookup failed", err)
	}
	exact := organizationID == payload.organizationID && workspaceID == payload.workspaceID && principalID == payload.ownerPrincipalID &&
		role == string(workspace.RoleOwner) && validFrom == tenantRevision && validTo == nil && addedBy == payload.ownerPrincipalID && removedAt == nil
	return tenantRowState{present: true, exact: exact}, nil
}

type persistedTenantAudit struct {
	present                bool
	exact                  bool
	organizationID         string
	schemaVersion          string
	sequence               int64
	workspaceID            *string
	actorType              string
	actorPrincipalID       *string
	onBehalfOfPrincipalID  *string
	action                 string
	resourceType           string
	resourceID             string
	requestID              string
	policyDecisionID       *string
	outcome                string
	errorCode              *string
	referencedEvidenceJSON []byte
	metadataJSON           []byte
	canonicalBytes         []byte
	previousEventHash      string
	eventHash              string
	occurredAt             time.Time
}

func inspectTenantAudit(ctx context.Context, tx pgx.Tx, payload tenantPayload) (tenantRowState, tenantRowState, error) {
	var event persistedTenantAudit
	err := tx.QueryRow(ctx, `
		SELECT organization_id, schema_version, sequence, workspace_id,
		       actor_type, actor_principal_id, on_behalf_of_principal_id,
		       action, resource_type, resource_id, request_id, policy_decision_id,
		       outcome, error_code, referenced_evidence_ids_json, metadata_json,
		       canonical_bytes, previous_event_hash, event_hash, occurred_at
		FROM public.audit_event WHERE id = $1 FOR UPDATE`, payload.auditEventID).
		Scan(&event.organizationID, &event.schemaVersion, &event.sequence, &event.workspaceID,
			&event.actorType, &event.actorPrincipalID, &event.onBehalfOfPrincipalID,
			&event.action, &event.resourceType, &event.resourceID, &event.requestID, &event.policyDecisionID,
			&event.outcome, &event.errorCode, &event.referencedEvidenceJSON, &event.metadataJSON,
			&event.canonicalBytes, &event.previousEventHash, &event.eventHash, &event.occurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		headState, headErr := tenantAuditHeadState(ctx, tx, payload, false)
		return tenantRowState{}, headState, headErr
	}
	if err != nil {
		return tenantRowState{}, tenantRowState{}, classifyTenantDatabaseError("tenant audit state lookup failed", err)
	}
	event.present = true
	var headSequence int64
	var headHash string
	headState, headErr := tenantAuditHeadState(ctx, tx, payload, true)
	if headErr != nil {
		return tenantRowState{}, tenantRowState{}, headErr
	}
	if headState.present {
		if err := tx.QueryRow(ctx, `
			SELECT last_sequence, last_event_hash FROM public.audit_chain_head WHERE organization_id = $1`, payload.organizationID).
			Scan(&headSequence, &headHash); err != nil {
			return tenantRowState{}, tenantRowState{}, classifyTenantDatabaseError("tenant audit head lookup failed", err)
		}
	}
	genesisPreviousHash := "sha256:" + strings.Repeat("0", 64)
	if !tenantAuditIsGenesis(event) {
		return tenantRowState{present: true, exact: false}, headState, nil
	}
	expected, buildErr := buildTenantAuditEvent(payload, 0, genesisPreviousHash, event.occurredAt)
	if buildErr != nil {
		return tenantRowState{present: true, exact: false}, headState, nil
	}
	exact := event.organizationID == payload.organizationID && event.schemaVersion == expected.SchemaVersion &&
		event.sequence == expected.Sequence && sameNullableString(event.workspaceID, expected.WorkspaceID) &&
		event.actorType == string(expected.ActorType) && sameNullableString(event.actorPrincipalID, expected.ActorPrincipalID) &&
		sameNullableString(event.onBehalfOfPrincipalID, expected.OnBehalfOfPrincipalID) && event.action == string(expected.Action) &&
		event.resourceType == string(expected.ResourceType) && event.resourceID == expected.ResourceID && event.requestID == expected.RequestID &&
		sameNullableString(event.policyDecisionID, expected.PolicyDecisionID) && event.outcome == string(expected.Outcome) &&
		sameNullableString(event.errorCode, expected.ErrorCode) && string(event.referencedEvidenceJSON) == "[]" &&
		string(event.metadataJSON) == "{}" && bytes.Equal(event.canonicalBytes, expected.CanonicalBytes) &&
		event.previousEventHash == expected.PreviousEventHash && event.eventHash == expected.EventHash && event.occurredAt.Equal(expected.OccurredAt) &&
		headState.present && headSequence >= event.sequence && validAuditHash(headHash)
	return tenantRowState{present: true, exact: exact}, headState, nil
}

func tenantAuditIsGenesis(event persistedTenantAudit) bool {
	return event.sequence == 1 && event.previousEventHash == "sha256:"+strings.Repeat("0", 64)
}

func tenantAuditHeadState(ctx context.Context, tx pgx.Tx, payload tenantPayload, eventPresent bool) (tenantRowState, error) {
	var sequence int64
	var hash string
	err := tx.QueryRow(ctx, `
		SELECT last_sequence, last_event_hash
		FROM public.audit_chain_head WHERE organization_id = $1 FOR UPDATE`, payload.organizationID).
		Scan(&sequence, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantRowState{}, nil
	}
	if err != nil {
		return tenantRowState{}, classifyTenantDatabaseError("tenant audit head state lookup failed", err)
	}
	// An absent audit event with a head is partial state. When the event exists,
	// the exact audit comparison performs the event-to-head consistency check.
	exact := eventPresent && sequence >= 1 && validAuditHash(hash)
	return tenantRowState{present: true, exact: exact}, nil
}

func validAuditHash(value string) bool {
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

func sameNullableString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func buildTenantAuditEvent(payload tenantPayload, headSequence int64, headHash string, occurredAt time.Time) (audit.Event, error) {
	workspaceID := payload.workspaceID
	actorID := payload.ownerPrincipalID
	return audit.Build(payload.organizationID, audit.EventInput{
		EventID: payload.auditEventID, WorkspaceID: &workspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: audit.ActionWorkspaceCreated, ResourceType: audit.ResourceWorkspace, ResourceID: payload.workspaceID,
		RequestID: payload.requestID, Outcome: audit.OutcomeSuccess, OccurredAt: occurredAt.UTC(),
	}, headSequence, headHash)
}

func insertTenantRows(ctx context.Context, tx pgx.Tx, payload tenantPayload, event audit.Event) error {
	statements := []struct {
		sql  string
		args []any
	}{
		{
			sql: `
				INSERT INTO public.organization (id, name, status, region, policy_revision, role_revision, owner_principal_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			args: []any{payload.organizationID, payload.organizationName, tenantOrganizationStatus, payload.region, tenantRevision, tenantRevision, payload.ownerPrincipalID},
		},
		{
			sql: `
				INSERT INTO public.principal (id, organization_id, type, display_name, status, session_revision)
				VALUES ($1, $2, $3, $4, $5, $6)`,
			args: []any{payload.ownerPrincipalID, payload.organizationID, tenantPrincipalType, payload.ownerDisplayName, tenantPrincipalStatus, tenantRevision},
		},
		{
			sql: `
				INSERT INTO public.organization_role_assignment
				(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
				VALUES ($1, $2, $3, 'OWNER', $4, $3)`,
			args: []any{payload.roleAssignmentID, payload.organizationID, payload.ownerPrincipalID, tenantRevision},
		},
		{
			sql: `
				INSERT INTO public.workspace
				(id, organization_id, name, description, status, owner_principal_id, current_revision, retention_policy_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''))`,
			args: []any{payload.workspaceID, payload.organizationID, payload.workspaceName, payload.workspaceDescription, string(tenantWorkspaceStatus), payload.ownerPrincipalID, tenantRevision, payload.retentionPolicyID},
		},
		{
			sql: `
				INSERT INTO public.workspace_revision
				(organization_id, workspace_id, revision, configuration_hash, created_by)
				VALUES ($1, $2, $3, $4, $5)`,
			args: []any{payload.organizationID, payload.workspaceID, tenantRevision, payload.configurationHash, payload.ownerPrincipalID},
		},
		{
			sql: `
				INSERT INTO public.workspace_revision_snapshot
				(organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
				VALUES ($1, $2, $3, $4, $5)`,
			args: []any{payload.organizationID, payload.workspaceID, tenantRevision, payload.configurationHash, payload.canonicalBytes},
		},
		{
			sql: `
				INSERT INTO public.workspace_member
				(id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
				VALUES ($1, $2, $3, $4, 'OWNER', $5, $4)`,
			args: []any{payload.membershipID, payload.organizationID, payload.workspaceID, payload.ownerPrincipalID, tenantRevision},
		},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			return classifyTenantDatabaseError("tenant provisioning row insert failed", err)
		}
	}

	evidenceJSON, err := json.Marshal(event.ReferencedEvidenceIDs)
	if err != nil {
		return MigrationIncompatible("tenant provisioning audit evidence encoding failed")
	}
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return MigrationIncompatible("tenant provisioning audit metadata encoding failed")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.audit_event (
			id, schema_version, organization_id, sequence, workspace_id,
			actor_type, actor_principal_id, on_behalf_of_principal_id,
			action, resource_type, resource_id, request_id, policy_decision_id,
			outcome, error_code, referenced_evidence_ids_json, metadata_json,
			canonical_bytes, previous_event_hash, event_hash, occurred_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			$14, $15, $16::jsonb, $17::jsonb, $18, $19, $20, $21
		)`,
		event.EventID, event.SchemaVersion, event.OrganizationID, event.Sequence, event.WorkspaceID,
		event.ActorType, event.ActorPrincipalID, event.OnBehalfOfPrincipalID, event.Action, event.ResourceType,
		event.ResourceID, event.RequestID, event.PolicyDecisionID, event.Outcome, event.ErrorCode,
		string(evidenceJSON), string(metadataJSON), event.CanonicalBytes, event.PreviousEventHash, event.EventHash, event.OccurredAt,
	); err != nil {
		return classifyTenantDatabaseError("tenant provisioning audit insert failed", err)
	}
	return nil
}

func classifyTenantDatabaseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if code := tenantSQLState(err); code == "42P01" || code == "42703" || code == "42883" {
		return MigrationIncompatible(operation + ": expected migration relation or column is absent")
	}
	if code := tenantSQLState(err); code == "23505" || code == "23503" || code == "23514" || code == "23502" || code == "55000" || code == "P0001" {
		return MigrationIncompatible(operation + ": database state conflicts with the owner tenant contract")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return DependencyUnavailable(operation + ": context ended")
	}
	return DependencyUnavailable(operation + ": " + err.Error())
}

func tenantSQLState(err error) string {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return pgError.Code
	}
	return ""
}
