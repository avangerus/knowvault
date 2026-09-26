package postgres_test

// S3 card 2c database-side acceptance proof for the source query-credential
// separation and the stored least-privilege verification. It reuses S3 card
// 2b's production registration fixture (real PostgreSQL, migration 000118
// included) and drives workspacerepository.Store:
//
//   - the database itself refuses a query credential equal to the ingestion
//     credential, in addition to the composition pre-check;
//   - a recorded least-privilege proof is bound to the exact connection and
//     credential revision and becomes stale the moment the credential changes;
//   - the scope read is bound to the caller's organization, so another
//     organization's access can never resolve this connection's reference.

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const ownerControlCredentialRef3 = "cred_01ARZ3NDEKTSV4RRFFQ69G5FAX"

func TestSourceQueryCredentialSeparationEnforcedByDatabase(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_separation_owner")

	// ownerControlCredentialRef is the connection's own ingestion credential;
	// the migration 000118 trigger refuses it even though the composition
	// pre-check was bypassed here.
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef); err == nil {
		t.Fatal("the database accepted the ingestion credential as the query credential")
	}
	query, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || query.QueryCredentialReference != "" {
		t.Fatalf("a rejected credential changed the reference: %q err=%v", query.QueryCredentialReference, err)
	}

	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef2); err != nil {
		t.Fatalf("a distinct query credential was refused: %v", err)
	}
}

func TestSourceQueryVerificationBindsToTheCredentialRevision(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_verification_owner")
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef2); err != nil {
		t.Fatalf("set query credential: %v", err)
	}

	target, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil {
		t.Fatalf("read scope: %v", err)
	}
	if target.RoleProven() {
		t.Fatal("a fresh connection was already marked least-privilege proven")
	}
	if target.ScopeHash() == "" || target.ConnectionRevision < 1 || target.QueryCredentialRevision < 1 {
		t.Fatalf("scope identity = %+v", target)
	}

	roleDigest := "sha256:" + strings.Repeat("d", 64)
	if err := repository.RecordSourceQueryVerification(ctx, owner, regWorkspace, connectionID,
		target.ConnectionRevision, target.QueryCredentialRevision, target.ScopeHash(), roleDigest); err != nil {
		t.Fatalf("record verification: %v", err)
	}
	proven, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || !proven.RoleProven() {
		t.Fatalf("recorded verification did not satisfy the pair: %v", err)
	}

	// A new credential bumps the credential revision, so the old proof is stale
	// and the next call must re-prove the role.
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef3); err != nil {
		t.Fatalf("change query credential: %v", err)
	}
	stale, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil {
		t.Fatalf("read scope after credential change: %v", err)
	}
	if stale.QueryCredentialRevision == target.QueryCredentialRevision {
		t.Fatalf("the credential revision did not change: %d", stale.QueryCredentialRevision)
	}
	if stale.RoleProven() {
		t.Fatal("a proof survived the credential change")
	}
}

func TestSourceQueryScopeIsBoundToTheOrganization(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_binding_owner")
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef2); err != nil {
		t.Fatalf("set query credential: %v", err)
	}

	foreign := database.AccessContext{
		OrganizationID: "org_01ARZ3NDEKTSV4RRFFQ69G5FAV", PrincipalID: regOwner, RequestID: "req_binding_foreign",
	}
	if _, err := repository.SourceQuery(ctx, foreign, regWorkspace, connectionID); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("foreign organization read = %v, want CodeNotFound", err)
	}
}

// TestGovernedQueryPurposeIsAudited proves card S3.2c's purpose record lands in
// the real audit journal with migration 000118's metadata whitelist, and that
// the not-configured and credential-resolution refusals the executor emits are
// accepted by the governed-query projection.
func TestGovernedQueryPurposeIsAudited(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_purpose_owner")
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	for name, errorCode := range map[string]string{
		"not configured":      "SOURCE_SQL_NOT_CONFIGURED",
		"credential rejected": "DATABASE_REJECTED",
	} {
		t.Run(name, func(t *testing.T) {
			eventID, idErr := ids.New("gqat")
			if idErr != nil {
				t.Fatal(idErr)
			}
			workspace := regWorkspace
			principal := regOwner
			sqlHash := "sha256:" + strings.Repeat("a", 64)
			revision := int64(1)
			connection := connectionID
			outcome := audit.GovernedQueryOutcomeRejectedStatic
			purpose := "count contracts"
			code := errorCode
			if _, err := auditStore.Append(ctx, owner, audit.EventInput{
				EventID: eventID, WorkspaceID: &workspace, ActorType: audit.ActorHuman,
				ActorPrincipalID: &principal, Action: audit.ActionGovernedQueryAttempted,
				ResourceType: audit.ResourceGovernedQueryAttempt, ResourceID: sqlHash,
				RequestID: owner.RequestID, Outcome: audit.OutcomeFailed, ErrorCode: &code,
				Metadata: audit.Metadata{
					GovernedQueryConnectionID: &connection, GovernedQueryExposedSchemaRevision: &revision,
					GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcome, GovernedQueryPurpose: &purpose,
				},
				OccurredAt: time.Now().UTC(),
			}); err != nil {
				t.Fatalf("audit %s refusal: %v", name, err)
			}
		})
	}
}
