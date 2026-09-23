package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// admittedAuthorityFixture is the smallest fully admitted PostgreSQL source
// used by the identity/precondition negative tests. Every caller creates it
// after resetStage1Database, so a failed case cannot alter the next one.
type admittedAuthorityFixture struct {
	admin        *pgxpool.Pool
	store        *workspacerepository.Store
	access       database.AccessContext
	request      workspacerepository.PostgreSQLAuthorityRequest
	binding      authorityOpsFixture
	grant        workspacerepository.AuthorityResult
	confirmation workspacerepository.AuthorityResult
}

func newAdmittedAuthorityFixture(t *testing.T) admittedAuthorityFixture {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	request := isolationProjectionRequest("kv_pgq_admission", "admission_view", "admission-lineage",
		"Admission operations", "sha256:"+strings.Repeat("7", 64))
	request.CredentialReference = authorityCredentialSentinel
	request.MaxRows = 73
	request.MaxColumns = len(request.Columns)
	request.MaxFieldBytes = 512
	request.MaxRowBytes = 2048
	request.MaxTotalBytes = 8192
	request.StatementTimeoutMS = 2500
	registered, err := service.Register(ctx, regOwnerAccess("req_negative_register"), request)
	if err != nil {
		t.Fatalf("register negative-test projection: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin,
		registered.SourceScopeID, registered.ScopeConfigHash,
		agg2StableWorkspaceSourceID(regOrg, regWorkspace, registered.SourceScopeID))

	runtime := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, runtime, binding, "negative-admission-grant")
	confirmation, err := runtime.ConfirmManagedSource(ctx,
		authorityAccess(binding, regOwner, "req_negative_confirm"),
		confirmRuntimeRequest(binding, grant, "negative-admission-confirm"))
	if err != nil {
		t.Fatalf("confirm negative-test source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatalf("create negative-test worker queue: %v", err)
	}
	bootstrapScheduledScope(t, ctx, admin, workerStore, workerQueue, workerAccess(t, regOrg),
		registered.SourceScopeID, jobs.TypePostgreSQLQuerySync, request.ContractHash)

	store := newAuthorityRuntime(t, ctx)
	authorityRequest := workspacerepository.PostgreSQLAuthorityRequest{
		WorkspaceID:         binding.workspaceID,
		WorkspaceSourceID:   binding.workspaceSourceID,
		SourceScopeID:       registered.SourceScopeID,
		SourceScopeRevision: request.ProjectionRevision,
		ScopeConfigHash:     registered.ScopeConfigHash,
		AccessMode:          "WORKSPACE_MANAGED",
	}
	positive, err := store.ResolvePostgreSQLAuthority(ctx,
		authorityAccess(binding, regOwner, "req_negative_positive_precondition"), authorityRequest)
	if err != nil {
		t.Fatalf("positive authority precondition resolve: %v", err)
	}
	if err := positive.Projection().Validate(); err != nil {
		t.Fatalf("positive authority projection invalid: %v", err)
	}
	if err := positive.Limits().Validate(); err != nil {
		t.Fatalf("positive authority limits invalid: %v", err)
	}
	return admittedAuthorityFixture{
		admin: admin, store: store,
		access:  authorityAccess(binding, regOwner, "req_negative_resolve"),
		request: authorityRequest, binding: binding,
		grant: grant, confirmation: confirmation,
	}
}

func assertAuthorityNotFound(t *testing.T, result workspacerepository.PostgreSQLAuthorityResult, err error) {
	t.Helper()
	assertAuthorityFailure(t, result, err, workspacerepository.CodeNotFound)
}

func assertAuthorityPersistence(t *testing.T, result workspacerepository.PostgreSQLAuthorityResult, err error) {
	t.Helper()
	assertAuthorityFailure(t, result, err, workspacerepository.CodePersistence)
}

func assertAuthorityFailure(t *testing.T, result workspacerepository.PostgreSQLAuthorityResult, err error, want workspacerepository.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("authority unexpectedly resolved: %s", formatAuthorityResult(t, result))
	}
	if got := workspacerepository.CodeOf(err); got != want {
		t.Fatalf("authority failure code = %q, want %q", got, want)
	}
	if err.Error() != string(want) {
		t.Fatalf("authority failure text = %q, want %q", err.Error(), want)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("authority failure exposed an underlying error: %v", errors.Unwrap(err))
	}
	assertZeroAuthorityResult(t, result)
	lower := strings.ToLower(err.Error())
	for _, forbidden := range []string{
		"permission", "postgresql_query_projection", "select ", "insert ", "update ", "delete ",
		"postgres://", "postgresql://", "dsn", "sql",
		strings.ToLower(authorityCredentialSentinel),
		strings.ToLower(authorityDSNSentinel), strings.ToLower(authoritySQLSentinel),
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("authority failure text leaked %q: %q", forbidden, err.Error())
		}
	}
}

func assertZeroAuthorityResult(t *testing.T, result workspacerepository.PostgreSQLAuthorityResult) {
	t.Helper()
	if result.WorkspaceID() != "" || result.WorkspaceRevision() != 0 ||
		result.WorkspaceConfigurationHash() != "" || result.WorkspaceSourceID() != "" ||
		result.SourceScopeID() != "" || result.SourceScopeRevision() != 0 ||
		result.ScopeConfigHash() != "" || result.AccessMode() != "" ||
		result.ConnectionRevision() != 0 {
		t.Fatalf("authority failure returned scalar accessors: %s", formatAuthorityResult(t, result))
	}
	if projection := result.Projection(); !reflect.DeepEqual(projection, postgresqlquery.Projection{}) {
		t.Fatalf("authority failure returned projection: %#v", projection)
	}
	if limits := result.Limits(); !reflect.DeepEqual(limits, postgresqlquery.Limits{}) {
		t.Fatalf("authority failure returned limits: %#v", limits)
	}
}

func TestPostgreSQLSourceAuthorityIdentityPreconditions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, admittedAuthorityFixture)
	}{
		{
			name: "foreign tenant",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				access := fixture.access
				access.OrganizationID = "org_foreign_authority"
				access.RequestID = "req_negative_foreign_tenant"
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "foreign workspace",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				request := fixture.request
				request.WorkspaceID = "ws_foreign_authority"
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), fixture.access, request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "unknown principal",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				access := fixture.access
				access.PrincipalID = "usr_unknown_authority"
				access.RequestID = "req_negative_unknown_principal"
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "principal without workspace membership",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				const principalID = "usr_authority_no_workspace"
				if _, err := fixture.admin.Exec(context.Background(), `
				INSERT INTO public.principal (id, organization_id, type, display_name, status)
				VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, principalID, regOrg); err != nil {
					t.Fatalf("seed non-member principal: %v", err)
				}
				access := fixture.access
				access.PrincipalID = principalID
				access.RequestID = "req_negative_no_workspace_membership"
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "stale scope revision",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				request := fixture.request
				request.SourceScopeRevision++
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), fixture.access, request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "stale valid scope hash",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				request := fixture.request
				request.ScopeConfigHash = "sha256:" + strings.Repeat("e", 64)
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), fixture.access, request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "source tuple mismatch",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				request := fixture.request
				request.WorkspaceSourceID = "binding_01ARZ3NDEKTSV4RRFFQ69G5FAE"
				result, err := fixture.store.ResolvePostgreSQLAuthority(context.Background(), fixture.access, request)
				assertAuthorityNotFound(t, result, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run(t, newAdmittedAuthorityFixture(t))
		})
	}
}

func TestPostgreSQLSourceAuthorityCurrentStatePreconditions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, admittedAuthorityFixture)
	}{
		{
			name: "activation syncing",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				tag, err := fixture.admin.Exec(ctx, `
					UPDATE public.source_scope_activation
					SET status = 'SYNCING', activated_at = NULL
					WHERE organization_id = $1
					  AND source_scope_id = $2
					  AND source_scope_revision = $3
					  AND revision = 1
					  AND status = 'READY'`,
					regOrg, fixture.request.SourceScopeID, fixture.request.SourceScopeRevision)
				if err != nil {
					t.Fatalf("activation READY->SYNCING blocker: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("activation READY->SYNCING affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "trust revoked",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				tag, err := fixture.admin.Exec(ctx, `
					UPDATE public.source_connection_trust_projection AS projection
					SET status = 'REVOKED'
					WHERE projection.organization_id = $1
					  AND projection.trust_record_id = (
						  SELECT connection_revision.trust_record_id
						  FROM public.source_scope_revision AS scope_revision
						  JOIN public.source_connection_revision AS connection_revision
							ON connection_revision.organization_id = scope_revision.organization_id
						   AND connection_revision.connection_id = scope_revision.connection_id
						   AND connection_revision.revision = scope_revision.connection_revision
						  WHERE scope_revision.organization_id = $1
							AND scope_revision.source_scope_id = $2
							AND scope_revision.revision = $3
					  )
					  AND projection.revision = 1
					  AND projection.status = 'VERIFIED'`,
					regOrg, fixture.request.SourceScopeID, fixture.request.SourceScopeRevision)
				if err != nil {
					t.Fatalf("trust VERIFIED->REVOKED blocker: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("trust VERIFIED->REVOKED affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "projection revoked",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				tag, err := fixture.admin.Exec(ctx, `
					UPDATE public.postgresql_query_projection
					SET status = 'REVOKED'
					WHERE organization_id = $1
					  AND source_scope_id = $2
					  AND source_scope_revision = $3
					  AND status = 'ACTIVE'`,
					regOrg, fixture.request.SourceScopeID, fixture.request.SourceScopeRevision)
				if err != nil {
					t.Fatalf("projection ACTIVE->REVOKED blocker: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("projection ACTIVE->REVOKED affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "unknown projection column",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				tag, err := fixture.admin.Exec(ctx, `
					UPDATE public.postgresql_query_projection
					SET columns_json = jsonb_set(columns_json, '{0,unknown}', 'true'::jsonb, true)
					WHERE organization_id = $1
					  AND source_scope_id = $2
					  AND source_scope_revision = $3
					  AND status = 'ACTIVE'`,
					regOrg, fixture.request.SourceScopeID, fixture.request.SourceScopeRevision)
				if err != nil {
					t.Fatalf("unknown projection column mutation blocker: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("unknown projection column mutation affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityPersistence(t, result, err)
			},
		},
		{
			name: "inconsistent valid database limits",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				tag, err := fixture.admin.Exec(ctx, `
					UPDATE public.postgresql_query_projection
					SET max_field_bytes = 4096, max_row_bytes = 1024
					WHERE organization_id = $1
					  AND source_scope_id = $2
					  AND source_scope_revision = $3
					  AND status = 'ACTIVE'`,
					regOrg, fixture.request.SourceScopeID, fixture.request.SourceScopeRevision)
				if err != nil {
					t.Fatalf("inconsistent limits mutation blocker: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("inconsistent limits mutation affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityPersistence(t, result, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run(t, newAdmittedAuthorityFixture(t))
		})
	}
}

func TestPostgreSQLSourceAuthorityRevocationAndPolicyPreconditions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, admittedAuthorityFixture)
	}{
		{
			name: "managed confirmation revoked",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				confirmationID, confirmationHash := loadLiveManagedConfirmation(t, ctx, fixture.admin, fixture.binding)
				if confirmationID != fixture.confirmation.ResultID || confirmationHash != fixture.confirmation.ResultHash {
					t.Fatalf("live confirmation identity = %s/%s, want issued result %s/%s",
						confirmationID, confirmationHash, fixture.confirmation.ResultID, fixture.confirmation.ResultHash)
				}
				if _, err := fixture.store.RevokeManagedConfirmation(ctx,
					authorityAccess(fixture.binding, regOwner, "req_negative_revoke_confirmation"),
					workspacerepository.RevokeConfirmationRequest{
						IdempotencyKey:         authorityIdempotencyKey("negative-revoke-confirmation"),
						OrganizationID:         regOrg,
						WorkspaceID:            fixture.binding.workspaceID,
						ConfirmationID:         confirmationID,
						ConfirmationHash:       confirmationHash,
						ExpectedPolicyRevision: fixture.binding.policyID,
					}); err != nil {
					t.Fatalf("revoke managed confirmation: %v", err)
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "confirmation grant revoked",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				if _, err := fixture.store.RevokeConfirmationGrant(ctx,
					authorityAccess(fixture.binding, regOwner, "req_negative_revoke_grant"),
					workspacerepository.RevokeGrantRequest{
						IdempotencyKey:         authorityIdempotencyKey("negative-revoke-grant"),
						OrganizationID:         regOrg,
						WorkspaceID:            fixture.binding.workspaceID,
						GrantID:                fixture.grant.ResultID,
						GrantRevision:          1,
						GrantHash:              fixture.grant.ResultHash,
						ExpectedPolicyRevision: fixture.binding.policyID,
					}); err != nil {
					t.Fatalf("revoke confirmation grant: %v", err)
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "organization policy drift",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				clock := fetchAuthorityClock(t, ctx, fixture.admin)
				insertPolicyRegistryRow(t, ctx, fixture.admin, regOrg, 2,
					"policy-registration-01ARZ3NDEKTSV4RRFFQ69G5FAW",
					authoritySha256('q'), regOwner, clock.now)
				tag, err := fixture.admin.Exec(ctx,
					`UPDATE public.organization SET policy_revision = 2 WHERE id = $1 AND policy_revision = 1`, regOrg)
				if err != nil {
					t.Fatalf("advance organization policy revision: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("advance organization policy revision affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "warning contract drift",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				dropWarningImmutabilityGuard(t, ctx, fixture.admin)
				tag, err := fixture.admin.Exec(ctx, warningAdvanceSQL, warningAdvanceBytes)
				if err != nil {
					t.Fatalf("advance warning contract: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("advance warning contract affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run(t, newAdmittedAuthorityFixture(t))
		})
	}
}

func TestPostgreSQLSourceAuthorityLifecyclePreconditions(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, admittedAuthorityFixture)
	}{
		{
			name: "organization suspended",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				tag, err := fixture.admin.Exec(ctx, `
					UPDATE public.organization
					SET status = 'SUSPENDED'
					WHERE id = $1 AND status = 'ACTIVE'`, fixture.binding.organizationID)
				if err != nil {
					t.Fatalf("suspend organization blocker: %v", err)
				}
				if tag.RowsAffected() != 1 {
					t.Fatalf("suspend organization affected %d rows, want 1", tag.RowsAffected())
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "workspace archived",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				archived, err := fixture.store.Archive(ctx,
					authorityAccess(fixture.binding, regOwner, "req_negative_archive"),
					workspacerepository.ArchiveRequest{
						IdempotencyKey:            workspaceIdempotencyKey("negative-archive"),
						WorkspaceID:               fixture.binding.workspaceID,
						ExpectedConfigurationHash: fixture.binding.workspaceConfHash,
					})
				if err != nil {
					t.Fatalf("archive workspace: %v", err)
				}
				if archived.Status != workspace.StatusArchived || archived.Revision != fixture.binding.workspaceRevision+1 {
					t.Fatalf("archive result = status %q revision %d, want ARCHIVED revision %d",
						archived.Status, archived.Revision, fixture.binding.workspaceRevision+1)
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "source removed",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				removed, err := fixture.store.RemoveSource(ctx,
					authorityAccess(fixture.binding, regOwner, "req_negative_remove_source"),
					workspacerepository.RemoveSourceRequest{
						IdempotencyKey:            workspaceIdempotencyKey("negative-remove-source"),
						WorkspaceID:               fixture.binding.workspaceID,
						ExpectedWorkspaceRevision: fixture.binding.workspaceRevision,
						ExpectedConfigurationHash: fixture.binding.workspaceConfHash,
						WorkspaceSourceID:         fixture.binding.workspaceSourceID,
						SourceScopeID:             fixture.binding.sourceScopeID,
						SourceScopeRevision:       fixture.binding.sourceScopeRevision,
						ScopeConfigHash:           fixture.binding.scopeConfigHash,
						AccessMode:                workspacerepository.SourceAccessWorkspaceManaged,
					})
				if err != nil {
					t.Fatalf("remove source: %v", err)
				}
				if removed.Revision != fixture.binding.workspaceRevision+1 {
					t.Fatalf("remove source revision = %d, want %d", removed.Revision, fixture.binding.workspaceRevision+1)
				}
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
		{
			name: "auditor cannot resolve authority",
			run: func(t *testing.T, fixture admittedAuthorityFixture) {
				ctx := context.Background()
				changed, err := fixture.store.ChangeMemberRole(ctx,
					authorityAccess(fixture.binding, regOwner, "req_negative_change_viewer_auditor"),
					workspacerepository.ChangeMemberRoleRequest{
						IdempotencyKey:            workspaceIdempotencyKey("negative-change-viewer-auditor"),
						WorkspaceID:               fixture.binding.workspaceID,
						ExpectedConfigurationHash: fixture.binding.workspaceConfHash,
						PrincipalID:               regViewer,
						Role:                      workspace.RoleAuditor,
					})
				if err != nil {
					t.Fatalf("change viewer role to auditor: %v", err)
				}
				if changed.Revision != fixture.binding.workspaceRevision+1 {
					t.Fatalf("auditor role change revision = %d, want %d", changed.Revision, fixture.binding.workspaceRevision+1)
				}
				foundAuditor := false
				for _, member := range changed.Members {
					if member.PrincipalID == regViewer && member.Role == workspace.RoleAuditor {
						foundAuditor = true
						break
					}
				}
				if !foundAuditor {
					t.Fatalf("changed snapshot has no AUDITOR membership for %s", regViewer)
				}

				updated := fixture.binding
				updated.workspaceRevision = changed.Revision
				updated.workspaceConfHash = mustWorkspaceHash(t, changed)
				grant := issueRuntimeGrant(t, ctx, fixture.store, updated, "negative-auditor-grant")
				if _, err := fixture.store.ConfirmManagedSource(ctx,
					authorityAccess(updated, regOwner, "req_negative_auditor_confirm"),
					confirmRuntimeRequest(updated, grant, "negative-auditor-confirm")); err != nil {
					t.Fatalf("confirm exact source at auditor revision: %v", err)
				}

				auditorAccess := authorityAccess(updated, regViewer, "req_negative_auditor_resolve")
				result, err := fixture.store.ResolvePostgreSQLAuthority(ctx, auditorAccess, fixture.request)
				assertAuthorityNotFound(t, result, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.run(t, newAdmittedAuthorityFixture(t))
		})
	}
}
