//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// Phase A authority constants. The policy registry revision is the head the
// organization row points at by default (policy_revision DEFAULT 1); the
// warning-contract values are the registry head migration 000010 seeds.
const (
	policyRevisionID        = "policy-e2e-0001"
	confirmationWarningVer  = "workspace-managed-risk-v1"
	confirmationWarningHash = "sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d"
	confirmationAckCode     = "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
	authorityRequestID      = "req_e2e_authority"
)

// seedPolicyRegistry inserts revision 1 of the e2e policy registry row.
// The organization row's policy_revision defaults to 1, so the head join the
// authority commands perform resolves to exactly this row. The insert is
// guarded so a harness replay keeps one canonical row.
func seedPolicyRegistry(ctx context.Context, cfg config) error {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	sum := sha256.Sum256([]byte("knowvault-e2e-policy-v1"))
	policyHash := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (
			organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by
		)
		SELECT $1, 1, $2, $3,
			to_char(date_trunc('second', transaction_timestamp() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			$4
		WHERE NOT EXISTS (
			SELECT 1 FROM public.organization_policy_revision
			WHERE organization_id = $1 AND policy_revision_id = $2
		)`, cfg.organizationID, policyRevisionID, policyHash, ownerPrincipalID); err != nil {
		return fmt.Errorf("seed policy registry: %w", err)
	}
	return nil
}

// seedCapabilityProfile seeds the exact verified FOLDER connector profile the
// registration runtime passes to the register function; migrations do not seed
// it. The shape mirrors the registration integration fixture verbatim.
func seedCapabilityProfile(ctx context.Context, cfg config) error {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
			connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
			item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ('cap_e2e_folder', 'sha256:`+strings.Repeat("a", 64)+`', 'folder-build-e2e', 'FOLDER', '1.0.0',
			'sha256:`+strings.Repeat("b", 64)+`', true, true, true, false, true, true, true, true, true, true,
			'sha256:`+strings.Repeat("c", 64)+`', transaction_timestamp())
		ON CONFLICT (id) DO NOTHING`); err != nil {
		return fmt.Errorf("seed folder capability profile: %w", err)
	}
	return nil
}

// connectorAdminPrincipalID is the e2e CONNECTOR_ADMIN principal that
// verifies connection trust (ADR-0087 §2). It is deliberately distinct from
// ownerPrincipalID: the ADR requires the CONNECTOR_ADMIN who verifies a
// connector's trust and the workspace owner/manager who confirms that scope's
// WORKSPACE_MANAGED binding to be different principals.
const connectorAdminPrincipalID = "e2e-connector-admin"

// seedConnectorAdminPrincipal provisions the e2e CONNECTOR_ADMIN principal
// through admin SQL, exactly as seedPolicyRegistry/seedCapabilityProfile seed
// other fixture-level state no product surface yet grants (ADR-0087 does not
// add an organization-role-assignment product surface; the operator's
// tenant-provision command only ever assigns OWNER — internal/operator/tenant.go).
func seedConnectorAdminPrincipal(ctx context.Context, cfg config) error {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE') ON CONFLICT (id) DO NOTHING`,
		connectorAdminPrincipalID, cfg.organizationID); err != nil {
		return fmt.Errorf("seed connector-admin principal: %w", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_'||$1, $2, $1, 'CONNECTOR_ADMIN', 1, $3)
		ON CONFLICT (id) DO NOTHING`, connectorAdminPrincipalID, cfg.organizationID, ownerPrincipalID); err != nil {
		return fmt.Errorf("seed connector-admin role: %w", err)
	}
	return nil
}

// verifyConnectionTrust advances the seeded connection trust from DRAFT to
// VERIFIED through the product command (ADR-0087 §2,
// Store.VerifyConnectionTrust), driven by the CONNECTOR_ADMIN principal
// seedConnectorAdminPrincipal provisions — the same production repository
// method the REST sources/connections/{id}:verify-trust action and the
// knowvault_verify_connection_trust MCP tool call, not a direct UPDATE
// against source_connection_trust_projection or an authority relation.
func verifyConnectionTrust(ctx context.Context, cfg config, store *workspacerepository.Store, connectionID string) error {
	access := database.AccessContext{OrganizationID: cfg.organizationID, PrincipalID: connectorAdminPrincipalID, RequestID: authorityRequestID}
	_, err := store.VerifyConnectionTrust(ctx, access, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: idemKey("verify-trust"), ConnectionID: connectionID,
		AttestedConnectorIdentity: connectionID, AttestedBy: "e2e-harness",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("verify connection trust: %w", err)
	}
	return nil
}

// scopeConfigHash reads the immutable scope-config hash of the DRAFT revision
// the registration route created; the confirmation chain pins it.
func scopeConfigHash(ctx context.Context, cfg config, sourceScopeID string) (string, error) {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return "", fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	var hash string
	if err := admin.QueryRow(ctx, `SELECT scope_config_hash FROM public.source_scope_revision
		WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, cfg.organizationID, sourceScopeID).Scan(&hash); err != nil {
		return "", fmt.Errorf("read scope config hash: %w", err)
	}
	return hash, nil
}

// workspaceSourceID reads the stable binding ID AddSource created; the
// confirmation chain must name the exact persisted lineage, not a recomputed
// value.
func workspaceSourceID(ctx context.Context, cfg config, workspaceID, sourceScopeID string) (string, error) {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return "", fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	var id string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
		WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
		cfg.organizationID, workspaceID, sourceScopeID).Scan(&id); err != nil {
		return "", fmt.Errorf("read workspace source binding: %w", err)
	}
	return id, nil
}

// openProductStore opens the workspace repository over the product database
// role, using the application DSN the operator wrote for the product binaries.
// This is the same construction the integration tests prove against real
// PostgreSQL, so the confirmation chain runs through production command code
// paths, not raw SQL.
func openProductStore(ctx context.Context) (*workspacerepository.Store, func(), error) {
	rawURL, err := os.ReadFile("/e2e/run/db.url")
	if err != nil {
		return nil, nil, fmt.Errorf("read application dsn: %w", err)
	}
	storeConfig := database.DefaultConfig()
	storeConfig.URL = strings.TrimSpace(string(rawURL))
	if storeConfig.URL == "" {
		return nil, nil, fmt.Errorf("application dsn is empty")
	}
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("open application store: %w", err)
	}
	closeStore := func() { databaseStore.Close() }
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		closeStore()
		return nil, nil, fmt.Errorf("create audit store: %w", err)
	}
	store, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		closeStore()
		return nil, nil, fmt.Errorf("create workspace repository: %w", err)
	}
	return store, closeStore, nil
}

// addSourceAndConfirm drives the WORKSPACE_MANAGED confirmation chain through
// the production repository: bind the exact DRAFT scope revision, recompute
// the configuration hash from the returned snapshot, issue the actor grant
// and confirm the managed source against the policy and warning registry
// heads.
func addSourceAndConfirm(ctx context.Context, cfg config, store *workspacerepository.Store, workspaceID string,
	workspaceRevision int64, workspaceConfHash, sourceScopeID, scopeHash string) (workspacerepository.AuthorityResult, error) {
	access := database.AccessContext{
		OrganizationID: cfg.organizationID, PrincipalID: ownerPrincipalID, RequestID: authorityRequestID,
	}
	snapshot, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey:            idemKey("add-source"),
		WorkspaceID:               workspaceID,
		ExpectedWorkspaceRevision: workspaceRevision,
		ExpectedConfigurationHash: workspaceConfHash,
		SourceScopeID:             sourceScopeID,
		SourceScopeRevision:       1,
		ScopeConfigHash:           scopeHash,
		AccessMode:                workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		return workspacerepository.AuthorityResult{}, fmt.Errorf("add source: %w", err)
	}
	nextHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		return workspacerepository.AuthorityResult{}, fmt.Errorf("configuration hash after add: %w", err)
	}
	grant, err := store.IssueConfirmationGrant(ctx, access, workspacerepository.IssueGrantRequest{
		IdempotencyKey:                     idemKey("issue-grant"),
		OrganizationID:                     cfg.organizationID,
		WorkspaceID:                        workspaceID,
		ExpectedWorkspaceRevision:          snapshot.Revision,
		ExpectedWorkspaceConfigurationHash: nextHash,
		TargetPrincipalID:                  ownerPrincipalID,
		TTLSeconds:                         3600,
		ExpectedPolicyRevision:             policyRevisionID,
	})
	if err != nil {
		return workspacerepository.AuthorityResult{}, fmt.Errorf("issue confirmation grant: %w", err)
	}
	bindingID, err := workspaceSourceID(ctx, cfg, workspaceID, sourceScopeID)
	if err != nil {
		return workspacerepository.AuthorityResult{}, err
	}
	if _, err := store.ConfirmManagedSource(ctx, access, workspacerepository.ConfirmRequest{
		IdempotencyKey:                 idemKey("confirm-source"),
		OrganizationID:                 cfg.organizationID,
		WorkspaceID:                    workspaceID,
		WorkspaceRevision:              snapshot.Revision,
		WorkspaceConfigurationHash:     nextHash,
		WorkspaceSourceID:              bindingID,
		SourceScopeID:                  sourceScopeID,
		SourceScopeRevision:            1,
		ScopeConfigHash:                scopeHash,
		AccessMode:                     string(workspacerepository.SourceAccessWorkspaceManaged),
		ConfirmationActorGrantID:       grant.ResultID,
		ConfirmationActorGrantRevision: 1,
		ConfirmationActorGrantHash:     grant.ResultHash,
		WarningVersion:                 confirmationWarningVer,
		WarningContractHash:            confirmationWarningHash,
		AcknowledgementCode:            confirmationAckCode,
		ExpectedPolicyRevision:         policyRevisionID,
	}); err != nil {
		return workspacerepository.AuthorityResult{}, fmt.Errorf("confirm managed source: %w", err)
	}
	return grant, nil
}
