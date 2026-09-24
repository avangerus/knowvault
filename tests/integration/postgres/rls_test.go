package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	testDatabaseName = "knowvault_test"
	appRole          = "knowvault_app"
	appPassword      = "knowvault_test_password"
	workerRole       = "knowvault_worker"
	workerPassword   = "knowvault_test_password"
	purgerRole       = "knowvault_purger"
)

func TestRLSFailsClosedAcrossOrganizations(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")

	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	var count int
	if err := app.QueryRow(ctx, "SELECT count(*) FROM public.workspace").Scan(&count); err != nil {
		t.Fatalf("unscoped query failed instead of returning no rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("query without app.organization_id returned %d workspace rows", count)
	}

	for organizationID, expectedWorkspace := range map[string]string{
		"org_alpha": "ws_alpha",
		"org_beta":  "ws_beta",
	} {
		organizationID, expectedWorkspace := organizationID, expectedWorkspace
		t.Run(organizationID, func(t *testing.T) {
			tx, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContext(t, ctx, tx, organizationID)

			var workspaceID string
			if err := tx.QueryRow(ctx, "SELECT id FROM public.workspace ORDER BY id").Scan(&workspaceID); err != nil {
				t.Fatalf("scoped workspace lookup failed: %v", err)
			}
			if workspaceID != expectedWorkspace {
				t.Fatalf("organization %s saw workspace %q, want %q", organizationID, workspaceID, expectedWorkspace)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}

	// A role without BYPASSRLS cannot turn policies off. PostgreSQL may accept
	// SET LOCAL, but the following query must then fail rather than disclose rows.
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	if _, err := tx.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
		t.Fatalf("runtime role could not request a fail-closed RLS check: %v", err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.workspace").Scan(&count); err == nil {
		t.Fatal("runtime role bypassed row security after SET LOCAL row_security = off")
	}

	var forced bool
	if err := admin.QueryRow(ctx, `
		SELECT c.relforcerowsecurity
		FROM pg_class AS c
		JOIN pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = 'workspace'
	`).Scan(&forced); err != nil {
		t.Fatal(err)
	}
	if !forced {
		t.Fatal("workspace RLS is not forced for table owners")
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	store, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Read(ctx, database.AccessContext{
		OrganizationID: "org_alpha",
		PrincipalID:    "usr_alice",
		RequestID:      "req_alpha",
	}, func(ctx context.Context, transaction database.Transaction) error {
		var workspaceID string
		if err := transaction.QueryRow(ctx, "SELECT id FROM public.workspace").Scan(&workspaceID); err != nil {
			return err
		}
		if workspaceID != "ws_alpha" {
			return fmt.Errorf("database store returned foreign workspace %q", workspaceID)
		}
		return nil
	}); err != nil {
		t.Fatalf("database store did not install an authorized local context: %v", err)
	}
}

// TestTenantOwnedTablesRequireOrganizationColumn is the database-side TEN-001
// proof. Every table carrying forced tenant RLS must carry the tenant key that
// its policy can bind; the organization root is the sole intentional exception.
// This queries PostgreSQL's effective catalog rather than repeating migration
// text, so a future tenant table or a dropped column is caught after migration.
func TestTenantOwnedTablesRequireOrganizationColumn(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	rows, err := admin.Query(ctx, `
		SELECT c.relname
		FROM pg_class AS c
		JOIN pg_namespace AS n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relkind = 'r'
		  AND c.relrowsecurity
		  AND c.relname <> 'organization'
		  AND NOT EXISTS (
			SELECT 1
			FROM pg_attribute AS a
			WHERE a.attrelid = c.oid
			  AND a.attnum > 0
			  AND NOT a.attisdropped
			  AND a.attname = 'organization_id'
		  )
		ORDER BY c.relname`)
	if err != nil {
		t.Fatalf("inspect tenant table columns: %v", err)
	}
	defer rows.Close()
	var missing []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			t.Fatal(err)
		}
		missing = append(missing, tableName)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("forced-RLS tenant tables without organization_id: %s", strings.Join(missing, ", "))
	}
}

// TestOrganizationAdminWithoutWorkspaceData proves IDN-002 at the repository
// surface. Organization management authority is deliberately not a workspace
// membership, so the administrator receives the same non-enumerating result as
// any other non-member and cannot list or read workspace data.
func TestOrganizationAdminWithoutWorkspaceData(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_org_admin', 'org_alpha', 'USER', 'Organization admin', 'ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (
			id, organization_id, principal_id, role, valid_from_revision, assigned_by
		) VALUES ('ora_org_admin', 'org_alpha', 'usr_org_admin', 'ADMIN', 1, 'usr_alice')`); err != nil {
		t.Fatal(err)
	}
	decision := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceViewMetadata,
		Subject: policy.Subject{
			OrganizationID: "org_alpha", PrincipalID: "usr_org_admin", Status: policy.PrincipalActive,
			SessionRevision: 1, OrganizationRoles: []policy.OrganizationRole{policy.OrganizationAdmin},
		},
		Workspace:  policy.Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: policy.WorkspaceActive},
		Membership: policy.Membership{},
	})
	if decision.Allowed || len(decision.ReasonCodes) != 1 || decision.ReasonCodes[0] != policy.ReasonWorkspaceMembershipAbsent {
		t.Fatalf("workspace policy allowed an organization admin without membership: %+v", decision)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_org_admin", RequestID: "req_org_admin_no_workspace"}
	if _, err := workspaceStore.Get(ctx, access, "ws_alpha"); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("organization admin workspace read code=%q err=%v, want non-enumerating not-found", workspacerepository.CodeOf(err), err)
	}
	listed, err := workspaceStore.List(ctx, access)
	if err != nil {
		t.Fatalf("organization admin workspace list: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("organization admin listed %d workspace records without membership", len(listed))
	}
}

// TestWorkspaceListDegradesOnAStaleConfigurationHash proves the 12.09 acc2
// guard against a real PostgreSQL store: when one member workspace's live
// metadata no longer matches its immutable revision hash, the whole list still
// succeeds, only that workspace carries the typed degraded marker, every other
// membership is returned normally, and the condition is journalled with ids and
// the closed reason code only.
func TestWorkspaceListDegradesOnAStaleConfigurationHash(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedSecondWorkspaceSameOwner(t, ctx, admin, "org_alpha", "usr_alice", "ws_beta")
	// Advance the live metadata without moving the revision pointer: the live
	// snapshot then hashes to something other than revision one's stored hash.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace SET name = 'Diverged'
		WHERE organization_id = 'org_alpha' AND id = 'ws_beta'`); err != nil {
		t.Fatalf("diverge live workspace metadata: %v", err)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_degraded_workspace_list"}
	listed, err := workspaceStore.List(ctx, access)
	if err != nil {
		t.Fatalf("list aborted on one stale configuration hash: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("listed %d workspaces, want 2", len(listed))
	}
	byID := make(map[string]workspacerepository.Summary, len(listed))
	for _, summary := range listed {
		byID[summary.ID] = summary
	}
	healthy, ok := byID["ws_alpha"]
	if !ok {
		t.Fatal("healthy workspace ws_alpha missing from the list")
	}
	if healthy.Degraded || healthy.DegradedReason != "" {
		t.Fatalf("healthy workspace marked degraded: %+v", healthy)
	}
	if healthy.Name != "ws_alpha" || healthy.Status != workspace.StatusActive || healthy.Revision != 1 || healthy.Role != workspace.RoleOwner {
		t.Fatalf("healthy workspace projection changed: %+v", healthy)
	}
	stale, ok := byID["ws_beta"]
	if !ok {
		t.Fatal("stale workspace ws_beta missing from the list")
	}
	if !stale.Degraded || stale.DegradedReason != workspacerepository.SummaryDegradedReasonConfigurationHashStale {
		t.Fatalf("stale workspace marker=%v reason=%q, want degraded with the typed reason", stale.Degraded, stale.DegradedReason)
	}

	var journalled int
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND action = 'policy.decision'
		  AND outcome = 'FAILED'
		  AND error_code = $1
		  AND resource_id = 'ws_beta'`,
		workspacerepository.SummaryDegradedReasonConfigurationHashStale,
	).Scan(&journalled); err != nil {
		t.Fatalf("read degraded journal entry: %v", err)
	}
	if journalled != 1 {
		t.Fatalf("degraded condition journalled %d times, want exactly one content-free event", journalled)
	}
}

func TestRuntimeRoleCannotDeleteTenantRows(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	if _, err := tx.Exec(ctx, "DELETE FROM public.workspace WHERE id = $1", "ws_alpha"); err == nil {
		t.Fatal("runtime role unexpectedly has DELETE privilege")
	}
}

func TestOwnerConstraintsRequireExactlyTheDeclaredActiveOwner(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.organization (id, name, status, region, owner_principal_id)
		VALUES ('org_broken', 'Broken', 'ACTIVE', 'ru', 'usr_owner')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_owner', 'org_broken', 'USER', 'Owner', 'ACTIVE')
	`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("active organization committed without exactly one active OWNER assignment")
	}
}

func TestAuditAppendIsTenantScopedAppendOnlyAndRetriesAChainRace(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}

	start := make(chan struct{})
	errorsByEvent := make(chan error, 2)
	var workers sync.WaitGroup
	for _, requestID := range []string{"req_audit_01", "req_audit_02"} {
		requestID := requestID
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			actor := "usr_alice"
			workspaceID := "ws_alpha"
			_, appendErr := auditStore.Append(ctx, database.AccessContext{
				OrganizationID: "org_alpha", PrincipalID: actor, RequestID: requestID,
			}, audit.EventInput{
				EventID: requestID + "_event", WorkspaceID: ptr(workspaceID), ActorType: audit.ActorHuman,
				ActorPrincipalID: ptr(actor), Action: audit.ActionWorkspaceUpdated, ResourceType: audit.ResourceWorkspace,
				ResourceID: "ws_alpha", RequestID: requestID, Outcome: audit.OutcomeSuccess, OccurredAt: time.Now().UTC(),
			})
			errorsByEvent <- appendErr
		}()
	}
	close(start)
	workers.Wait()
	close(errorsByEvent)
	for appendErr := range errorsByEvent {
		if appendErr != nil {
			t.Fatalf("concurrent audit append failed: %v", appendErr)
		}
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	var sequenceCount, minimumSequence, maximumSequence int64
	if err := tx.QueryRow(ctx, `SELECT count(*), min(sequence), max(sequence) FROM public.audit_event`).Scan(&sequenceCount, &minimumSequence, &maximumSequence); err != nil {
		t.Fatal(err)
	}
	if sequenceCount != 2 || minimumSequence != 1 || maximumSequence != 2 {
		t.Fatalf("audit chain did not serialize appends: count=%d min=%d max=%d", sequenceCount, minimumSequence, maximumSequence)
	}
	for _, privilege := range []string{"UPDATE", "DELETE"} {
		var granted bool
		if err := admin.QueryRow(ctx, `SELECT has_table_privilege('knowvault_app', 'public.audit_event', $1)`, privilege).Scan(&granted); err != nil {
			t.Fatalf("inspect audit_event %s privilege: %v", privilege, err)
		}
		if granted {
			t.Fatalf("runtime role unexpectedly has %s privilege on audit_event", privilege)
		}
	}
	assertAuditMutationDenied(t, app, "org_alpha", "UPDATE public.audit_event SET action = 'audit.viewed' WHERE sequence = 1")
	assertAuditMutationDenied(t, app, "org_alpha", "DELETE FROM public.audit_event WHERE sequence = 1")
	assertAuditMutationDenied(t, app, "org_alpha", "UPDATE public.audit_chain_head SET last_sequence = 0")

	betaTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = betaTransaction.Rollback(ctx) }()
	setAccessContext(t, ctx, betaTransaction, "org_beta")
	var betaCount int
	if err := betaTransaction.QueryRow(ctx, "SELECT count(*) FROM public.audit_event").Scan(&betaCount); err != nil {
		t.Fatal(err)
	}
	if betaCount != 0 {
		t.Fatalf("organization beta saw %d organization alpha audit events", betaCount)
	}

	for _, tableName := range []string{"audit_event", "audit_chain_head"} {
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tableName).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s RLS is not forced", tableName)
		}
	}
}

func TestAuditAppendInTransactionCommitsAndRollsBackWithTheBusinessMutation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}

	actor := "usr_alice"
	commitAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: actor, RequestID: "req_atomic_commit"}
	if err := databaseStore.Write(ctx, commitAccess, func(transactionContext context.Context, transaction database.Transaction) error {
		if _, execErr := transaction.Exec(transactionContext, "UPDATE public.organization SET name = 'Committed organization' WHERE id = $1", commitAccess.OrganizationID); execErr != nil {
			return execErr
		}
		_, appendErr := auditStore.AppendInTransaction(transactionContext, commitAccess, transaction, audit.EventInput{
			EventID: "aud_atomic_commit", ActorType: audit.ActorHuman,
			ActorPrincipalID: ptr(actor), Action: audit.ActionPolicyDecision, ResourceType: audit.ResourcePolicy,
			ResourceID: "policy_atomic_commit", RequestID: commitAccess.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: time.Now().UTC(),
		})
		return appendErr
	}); err != nil {
		t.Fatalf("commit business mutation and audit event: %v", err)
	}

	rollbackAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: actor, RequestID: "req_atomic_rollback"}
	rollbackSentinel := errors.New("force transaction rollback")
	err = databaseStore.Write(ctx, rollbackAccess, func(transactionContext context.Context, transaction database.Transaction) error {
		if _, execErr := transaction.Exec(transactionContext, "UPDATE public.organization SET name = 'Must not commit' WHERE id = $1", rollbackAccess.OrganizationID); execErr != nil {
			return execErr
		}
		if _, appendErr := auditStore.AppendInTransaction(transactionContext, rollbackAccess, transaction, audit.EventInput{
			EventID: "aud_atomic_rollback", ActorType: audit.ActorHuman,
			ActorPrincipalID: ptr(actor), Action: audit.ActionPolicyDecision, ResourceType: audit.ResourcePolicy,
			ResourceID: "policy_atomic_rollback", RequestID: rollbackAccess.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: time.Now().UTC(),
		}); appendErr != nil {
			return appendErr
		}
		return rollbackSentinel
	})
	if !errors.Is(err, rollbackSentinel) {
		t.Fatalf("expected caller rollback error, got %v", err)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	var organizationName string
	if err := tx.QueryRow(ctx, "SELECT name FROM public.organization WHERE id = $1", commitAccess.OrganizationID).Scan(&organizationName); err != nil {
		t.Fatal(err)
	}
	if organizationName != "Committed organization" {
		t.Fatalf("rollback leaked business mutation: %q", organizationName)
	}
	var eventCount int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.audit_event").Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("rollback leaked audit event: count=%d", eventCount)
	}
}

func TestIdentityRepositoryCreatesAuditedOneTimeSessionAndFailsClosedOnProviderChange(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	identityStore, err := identityrepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create identity repository: %v", err)
	}
	providerConfiguration, err := identityStore.LoadProviderConfiguration(ctx, identity.OrganizationID("org_alpha"), identity.ProviderID("idp_alpha"), "req_repo_provider_001")
	if err != nil || providerConfiguration.Revision != 1 || providerConfiguration.ClientSecretReference != "secret_idp_alpha" || len(providerConfiguration.SigningAlgorithms) != 1 || providerConfiguration.SigningAlgorithms[0] != "RS256" {
		t.Fatalf("load provider configuration=%#v err=%v", providerConfiguration, err)
	}

	state := mustKeyedDigest(t, "a")
	browserBinding := mustKeyedDigest(t, "b")
	nonce := mustKeyedDigest(t, "c")
	pkceVerifier := mustKeyedDigest(t, "d")
	externalSubject := mustKeyedDigest(t, "e")
	sessionToken := mustKeyedDigest(t, "f")
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	attempt, err := identityStore.BeginLogin(ctx, identityrepository.BeginLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_001", RequestID: "req_repo_begin_001", StateDigest: state,
		BrowserBindingDigest: browserBinding, NonceDigest: nonce, PKCEVerifierDigest: pkceVerifier, ExpiresAt: expiresAt,
	})
	if err != nil || attempt.ProviderRevision != 1 {
		t.Fatalf("begin login result=%#v err=%v", attempt, err)
	}
	pendingConfiguration, err := identityStore.LoadPendingLoginConfiguration(ctx, identityrepository.PendingLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_001", RequestID: "req_repo_pending_001", StateDigest: state, BrowserBindingDigest: browserBinding,
		NonceDigest: nonce, PKCEVerifierDigest: pkceVerifier,
	})
	if err != nil || pendingConfiguration.Revision != providerConfiguration.Revision || pendingConfiguration.ClientSecretReference != providerConfiguration.ClientSecretReference {
		t.Fatalf("load pending configuration=%#v err=%v", pendingConfiguration, err)
	}
	pendingRequest := identityrepository.PendingLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_001", RequestID: "req_repo_pending_wrong", StateDigest: state, BrowserBindingDigest: browserBinding, NonceDigest: nonce, PKCEVerifierDigest: pkceVerifier,
	}
	for name, mutate := range map[string]func(*identityrepository.PendingLoginRequest){
		"state": func(value *identityrepository.PendingLoginRequest) { value.StateDigest = mustKeyedDigest(t, "1") },
		"binding": func(value *identityrepository.PendingLoginRequest) {
			value.BrowserBindingDigest = mustKeyedDigest(t, "2")
		},
		"nonce": func(value *identityrepository.PendingLoginRequest) { value.NonceDigest = mustKeyedDigest(t, "3") },
		"pkce": func(value *identityrepository.PendingLoginRequest) {
			value.PKCEVerifierDigest = mustKeyedDigest(t, "4")
		},
		"revision": func(value *identityrepository.PendingLoginRequest) { value.ProviderRevision++ },
		"provider": func(value *identityrepository.PendingLoginRequest) {
			value.ProviderID = identity.ProviderID("idp_other")
		},
	} {
		name, mutate := name, mutate
		t.Run("pending "+name, func(t *testing.T) {
			wrong := pendingRequest
			mutate(&wrong)
			if _, err := identityStore.LoadPendingLoginConfiguration(ctx, wrong); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
				t.Fatalf("wrong %s pending request did not deny: %v", name, err)
			}
		})
	}

	seedExternalIdentity(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "eid_repo_001", externalSubject.Value())
	completeRequest := identityrepository.CompleteLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_001", RequestID: "req_repo_complete_wrong", AuditEventID: "aud_repo_login_wrong",
		StateDigest: state, BrowserBindingDigest: browserBinding, NonceDigest: nonce, PKCEVerifierDigest: pkceVerifier, ExternalSubjectDigest: externalSubject,
		SessionID: "sess_repo_wrong", SessionTokenDigest: sessionToken, SessionExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	for name, mutate := range map[string]func(*identityrepository.CompleteLoginRequest){
		"state": func(value *identityrepository.CompleteLoginRequest) { value.StateDigest = mustKeyedDigest(t, "1") },
		"binding": func(value *identityrepository.CompleteLoginRequest) {
			value.BrowserBindingDigest = mustKeyedDigest(t, "2")
		},
		"nonce": func(value *identityrepository.CompleteLoginRequest) { value.NonceDigest = mustKeyedDigest(t, "3") },
		"pkce": func(value *identityrepository.CompleteLoginRequest) {
			value.PKCEVerifierDigest = mustKeyedDigest(t, "4")
		},
		"revision": func(value *identityrepository.CompleteLoginRequest) { value.ProviderRevision++ },
		"provider": func(value *identityrepository.CompleteLoginRequest) {
			value.ProviderID = identity.ProviderID("idp_other")
		},
	} {
		name, mutate := name, mutate
		t.Run("complete "+name, func(t *testing.T) {
			wrong := completeRequest
			mutate(&wrong)
			if _, err := identityStore.CompleteLogin(ctx, wrong); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
				t.Fatalf("wrong %s completion did not deny: %v", name, err)
			}
		})
	}
	var sessionsBeforeValid int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.identity_session WHERE organization_id = 'org_alpha'").Scan(&sessionsBeforeValid); err != nil || sessionsBeforeValid != 0 {
		t.Fatalf("rejected completions created a session: count=%d err=%v", sessionsBeforeValid, err)
	}
	issued, err := identityStore.CompleteLogin(ctx, identityrepository.CompleteLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_001", RequestID: "req_repo_complete_001", AuditEventID: "aud_repo_login_001",
		StateDigest: state, BrowserBindingDigest: browserBinding, NonceDigest: nonce, PKCEVerifierDigest: pkceVerifier, ExternalSubjectDigest: externalSubject,
		SessionID: "sess_repo_001", SessionTokenDigest: sessionToken, SessionExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil || issued.PrincipalID != identity.PrincipalID("usr_alice") {
		t.Fatalf("complete login result=%#v err=%v", issued, err)
	}

	resolved, err := identityStore.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), RequestID: "req_repo_resolve_001", SessionTokenDigest: sessionToken,
	})
	if err != nil || resolved.Access.PrincipalID != "usr_alice" || resolved.Claims.ProviderRevision() != 1 {
		t.Fatalf("resolve issued session=%#v err=%v", resolved, err)
	}
	if _, err := identityStore.CompleteLogin(ctx, identityrepository.CompleteLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_001", RequestID: "req_repo_complete_replay", AuditEventID: "aud_repo_login_replay",
		StateDigest: state, BrowserBindingDigest: browserBinding, NonceDigest: nonce, PKCEVerifierDigest: pkceVerifier, ExternalSubjectDigest: externalSubject,
		SessionID: "sess_repo_replay", SessionTokenDigest: mustKeyedDigest(t, "5"), SessionExpiresAt: time.Now().UTC().Add(time.Hour),
	}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("completed login replay did not deny: %v", err)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	var attemptStatus string
	if err := tx.QueryRow(ctx, "SELECT status FROM public.oidc_login_attempt WHERE id = 'login_repo_001'").Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "CONSUMED" {
		t.Fatalf("completed login status=%q", attemptStatus)
	}
	var auditCount int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.audit_event WHERE action = 'identity.login'").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("identity login audit count=%d", auditCount)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	missingState := mustKeyedDigest(t, "1")
	missingBrowserBinding := mustKeyedDigest(t, "2")
	if _, err := identityStore.BeginLogin(ctx, identityrepository.BeginLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_missing", RequestID: "req_repo_begin_missing", StateDigest: missingState,
		BrowserBindingDigest: missingBrowserBinding, NonceDigest: mustKeyedDigest(t, "3"), PKCEVerifierDigest: mustKeyedDigest(t, "4"), ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("begin login for missing mapping: %v", err)
	}
	if _, err := identityStore.CompleteLogin(ctx, identityrepository.CompleteLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: providerConfiguration.Revision,
		LoginAttemptID: "login_repo_missing", RequestID: "req_repo_complete_missing", AuditEventID: "aud_repo_login_missing",
		StateDigest: missingState, BrowserBindingDigest: missingBrowserBinding, NonceDigest: mustKeyedDigest(t, "3"), PKCEVerifierDigest: mustKeyedDigest(t, "4"), ExternalSubjectDigest: mustKeyedDigest(t, "5"),
		SessionID: "sess_repo_missing", SessionTokenDigest: mustKeyedDigest(t, "6"), SessionExpiresAt: time.Now().UTC().Add(time.Hour),
	}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("missing external mapping did not deny safely: %v", err)
	}

	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	if err := tx.QueryRow(ctx, "SELECT status FROM public.oidc_login_attempt WHERE id = 'login_repo_missing'").Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "FAILED" {
		t.Fatalf("missing-mapping login status=%q", attemptStatus)
	}
	var failedAuditCount, sessionCount int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.audit_event WHERE action = 'identity.login_failed'").Scan(&failedAuditCount); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.identity_session").Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if failedAuditCount != 1 || sessionCount != 1 {
		t.Fatalf("missing mapping issued session or omitted audit: failed_audits=%d sessions=%d", failedAuditCount, sessionCount)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	staleState := mustKeyedDigest(t, "9")
	staleBinding := mustKeyedDigest(t, "8")
	staleNonce := mustKeyedDigest(t, "7")
	stalePKCE := mustKeyedDigest(t, "6")
	if _, err := identityStore.BeginLogin(ctx, identityrepository.BeginLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: 1,
		LoginAttemptID: "login_repo_stale", RequestID: "req_repo_begin_stale", StateDigest: staleState, BrowserBindingDigest: staleBinding,
		NonceDigest: staleNonce, PKCEVerifierDigest: stalePKCE, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("begin stale login: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.oidc_provider_revision (
			organization_id, provider_id, revision, client_id, client_secret_reference,
			redirect_uri, allowed_id_token_algorithms_json, configuration_hash, created_by
		) VALUES ('org_alpha', 'idp_alpha', 2, 'client_idp_alpha_v2', 'secret_idp_alpha_v2',
			'https://workspace.example/auth/callback', '["RS256"]'::jsonb, $1, 'usr_alice')
	`, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		UPDATE public.oidc_provider SET current_revision = 2
		WHERE organization_id = 'org_alpha' AND id = 'idp_alpha'
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.LoadPendingLoginConfiguration(ctx, identityrepository.PendingLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: 1,
		LoginAttemptID: "login_repo_stale", RequestID: "req_repo_pending_stale", StateDigest: staleState, BrowserBindingDigest: staleBinding,
		NonceDigest: staleNonce, PKCEVerifierDigest: stalePKCE,
	}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("provider current revision change did not deny pending load: %v", err)
	}
	if _, err := identityStore.CompleteLogin(ctx, identityrepository.CompleteLoginRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), ProviderID: identity.ProviderID("idp_alpha"), ProviderRevision: 1,
		LoginAttemptID: "login_repo_stale", RequestID: "req_repo_complete_stale", AuditEventID: "aud_repo_login_stale",
		StateDigest: staleState, BrowserBindingDigest: staleBinding, NonceDigest: staleNonce, PKCEVerifierDigest: stalePKCE,
		ExternalSubjectDigest: externalSubject, SessionID: "sess_repo_stale", SessionTokenDigest: mustKeyedDigest(t, "5"), SessionExpiresAt: time.Now().UTC().Add(time.Hour),
	}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("provider current revision change did not deny completion: %v", err)
	}
	var sessionsAfterProviderChange int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.identity_session WHERE organization_id = 'org_alpha'").Scan(&sessionsAfterProviderChange); err != nil || sessionsAfterProviderChange != 1 {
		t.Fatalf("provider revision denial created a session: count=%d err=%v", sessionsAfterProviderChange, err)
	}

	if _, err := admin.Exec(ctx, `
		UPDATE public.oidc_provider
		SET status = 'DISABLED', disabled_at = transaction_timestamp()
		WHERE organization_id = 'org_alpha' AND id = 'idp_alpha'
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := identityStore.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: identity.OrganizationID("org_alpha"), RequestID: "req_repo_resolve_disabled", SessionTokenDigest: sessionToken,
	}); identity.CodeOf(err) != identity.CodeProviderInactive {
		t.Fatalf("disabled provider did not fail closed: %v", err)
	}
}

func TestWorkspaceRepositoryCreatesHashVerifiedTenantScopedWorkspace(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_create_001"}
	createRequest := workspacerepository.CreateRequest{IdempotencyKey: workspaceIdempotencyKey("create-alpha"), Name: "Cafe\u0301 launch", Description: "\u0422\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f Alpha", RetentionPolicyID: "ret_default"}
	created, err := workspaceStore.Create(ctx, access, createRequest)
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if created.Revision != 1 || created.Name != "Café launch" || created.Status != workspace.StatusActive || created.OwnerPrincipalID != "usr_alice" || len(created.Members) != 1 || created.Members[0].Role != workspace.RoleOwner {
		t.Fatalf("created snapshot = %#v", created)
	}
	replayAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_create_replay_001"}
	if replayed, replayErr := workspaceStore.Create(ctx, replayAccess, createRequest); replayErr != nil || !reflect.DeepEqual(replayed, created) {
		t.Fatalf("create replay=%#v err=%v", replayed, replayErr)
	}
	changedCreate := createRequest
	changedCreate.Name = "\u0414\u0440\u0443\u0433\u043e\u0439 workspace"
	if _, conflictErr := workspaceStore.Create(ctx, replayAccess, changedCreate); workspacerepository.CodeOf(conflictErr) != workspacerepository.CodeIdempotencyConflict {
		t.Fatalf("changed create idempotency code=%q err=%v", workspacerepository.CodeOf(conflictErr), conflictErr)
	}

	readAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_get_001"}
	loaded, err := workspaceStore.Get(ctx, readAccess, created.ID)
	if err != nil || !reflect.DeepEqual(loaded, created) {
		t.Fatalf("get created workspace=%#v err=%v", loaded, err)
	}

	betaAccess := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_bob", RequestID: "req_workspace_cross_tenant_001"}
	if _, err := workspaceStore.Get(ctx, betaAccess, created.ID); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("cross-tenant get code=%q err=%v, want no disclosure", workspacerepository.CodeOf(err), err)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	var revision int64
	var storedHash string
	if err := tx.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash
		FROM public.workspace AS workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id
		 AND revision.revision = workspace.current_revision
		WHERE workspace.id = $1
	`, created.ID).Scan(&revision, &storedHash); err != nil {
		t.Fatal(err)
	}
	expectedHash, err := workspace.ConfigurationHash(created)
	if err != nil || revision != 1 || storedHash != expectedHash {
		t.Fatalf("stored revision/hash=%d/%q expected=%q err=%v", revision, storedHash, expectedHash, err)
	}
	var auditCount int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.audit_event WHERE action = 'workspace.created' AND resource_id = $1", created.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("workspace create audit count=%d", auditCount)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_carol', 'org_alpha', 'USER', 'Carol', 'ACTIVE')
	`); err != nil {
		t.Fatal(err)
	}
	memberAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_member_001"}
	withCarol, err := workspaceStore.AddMember(ctx, memberAccess, workspacerepository.AddMemberRequest{IdempotencyKey: workspaceIdempotencyKey("add-carol"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, created), PrincipalID: "usr_carol", Role: workspace.RoleViewer})
	if err != nil || withCarol.Revision != 2 || len(withCarol.Members) != 2 || withCarol.Members[1].PrincipalID != "usr_carol" || withCarol.Members[1].Role != workspace.RoleViewer {
		t.Fatalf("add workspace member=%#v err=%v", withCarol, err)
	}
	carolAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_workspace_member_get_001"}
	if loadedByCarol, getErr := workspaceStore.Get(ctx, carolAccess, created.ID); getErr != nil || !reflect.DeepEqual(loadedByCarol, withCarol) {
		t.Fatalf("viewer get workspace=%#v err=%v", loadedByCarol, getErr)
	}
	roleAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_role_001"}
	withCarolManager, err := workspaceStore.ChangeMemberRole(ctx, roleAccess, workspacerepository.ChangeMemberRoleRequest{IdempotencyKey: workspaceIdempotencyKey("promote-carol"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, withCarol), PrincipalID: "usr_carol", Role: workspace.RoleManager})
	if err != nil || withCarolManager.Revision != 3 || withCarolManager.Members[1].Role != workspace.RoleManager {
		t.Fatalf("change workspace member role=%#v err=%v", withCarolManager, err)
	}
	deniedTransferAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_workspace_transfer_denied_001"}
	if _, transferErr := workspaceStore.TransferOwnership(ctx, deniedTransferAccess, workspacerepository.TransferOwnershipRequest{IdempotencyKey: workspaceIdempotencyKey("denied-transfer"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, withCarolManager), NewOwnerPrincipalID: "usr_alice"}); workspacerepository.CodeOf(transferErr) != workspacerepository.CodeDenied {
		t.Fatalf("manager ownership transfer code=%q err=%v", workspacerepository.CodeOf(transferErr), transferErr)
	}
	transferAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_transfer_001"}
	transferRequest := workspacerepository.TransferOwnershipRequest{IdempotencyKey: workspaceIdempotencyKey("transfer-carol"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, withCarolManager), NewOwnerPrincipalID: "usr_carol"}
	transferred, err := workspaceStore.TransferOwnership(ctx, transferAccess, transferRequest)
	if err != nil || transferred.Revision != 4 || transferred.OwnerPrincipalID != "usr_carol" || transferred.Members[0].Role != workspace.RoleManager || transferred.Members[1].Role != workspace.RoleOwner {
		t.Fatalf("transfer workspace ownership=%#v err=%v", transferred, err)
	}
	updateAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_workspace_update_001"}
	updateRequest := workspacerepository.UpdateRequest{IdempotencyKey: workspaceIdempotencyKey("update-alpha"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, transferred), Name: "Alpha revised", Description: "\u041d\u043e\u0432\u0430\u044f \u0441\u0432\u043e\u0434\u043a\u0430", RetentionPolicyID: "ret_default"}
	updated, err := workspaceStore.Update(ctx, updateAccess, updateRequest)
	if err != nil || updated.Revision != 5 || updated.Name != "Alpha revised" {
		t.Fatalf("update workspace=%#v err=%v", updated, err)
	}
	if replayed, replayErr := workspaceStore.TransferOwnership(ctx, transferAccess, transferRequest); replayErr != nil || !reflect.DeepEqual(replayed, transferred) {
		t.Fatalf("old ownership transfer replay=%#v err=%v", replayed, replayErr)
	}
	if _, staleErr := workspaceStore.Update(ctx, updateAccess, workspacerepository.UpdateRequest{IdempotencyKey: workspaceIdempotencyKey("stale-update"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, transferred), Name: "Stale overwrite", Description: "\u041d\u0435 \u0434\u043e\u043b\u0436\u043d\u043e \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c\u0441\u044f", RetentionPolicyID: "ret_default"}); workspacerepository.CodeOf(staleErr) != workspacerepository.CodeRevisionConflict {
		t.Fatalf("stale workspace update code=%q err=%v", workspacerepository.CodeOf(staleErr), staleErr)
	}
	removeAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_workspace_remove_001"}
	withoutAlice, err := workspaceStore.RemoveMember(ctx, removeAccess, workspacerepository.RemoveMemberRequest{IdempotencyKey: workspaceIdempotencyKey("remove-alice"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, updated), PrincipalID: "usr_alice"})
	if err != nil || withoutAlice.Revision != 6 || len(withoutAlice.Members) != 1 || withoutAlice.Members[0].PrincipalID != "usr_carol" || withoutAlice.Members[0].Role != workspace.RoleOwner {
		t.Fatalf("remove workspace member=%#v err=%v", withoutAlice, err)
	}
	if _, getErr := workspaceStore.Get(ctx, updateAccess, created.ID); workspacerepository.CodeOf(getErr) != workspacerepository.CodeNotFound {
		t.Fatalf("removed member get code=%q err=%v", workspacerepository.CodeOf(getErr), getErr)
	}
	if _, replayErr := workspaceStore.Update(ctx, updateAccess, updateRequest); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeNotFound {
		t.Fatalf("removed member replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}
	archiveAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_workspace_archive_001"}
	archived, err := workspaceStore.Archive(ctx, archiveAccess, workspacerepository.ArchiveRequest{IdempotencyKey: workspaceIdempotencyKey("archive-alpha"), WorkspaceID: created.ID, ExpectedConfigurationHash: mustWorkspaceHash(t, withoutAlice)})
	if err != nil || archived.Revision != 7 || archived.Status != workspace.StatusArchived {
		t.Fatalf("archive workspace=%#v err=%v", archived, err)
	}
	if loadedByCarol, getErr := workspaceStore.Get(ctx, carolAccess, created.ID); getErr != nil || !reflect.DeepEqual(loadedByCarol, archived) {
		t.Fatalf("viewer get archived workspace=%#v err=%v", loadedByCarol, getErr)
	}
	deniedAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_workspace_create_denied_001"}
	if _, err := workspaceStore.Create(ctx, deniedAccess, workspacerepository.CreateRequest{IdempotencyKey: workspaceIdempotencyKey("denied-create"), Name: "\u041d\u0435 \u0434\u043e\u043b\u0436\u043d\u043e \u043f\u043e\u044f\u0432\u0438\u0442\u044c\u0441\u044f"}); workspacerepository.CodeOf(err) != workspacerepository.CodeDenied {
		t.Fatalf("non-admin workspace create code=%q err=%v", workspacerepository.CodeOf(err), err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContext(t, ctx, tx, "org_alpha")
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE action = 'workspace.created' AND outcome = 'DENIED' AND actor_principal_id = 'usr_carol'
	`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("denied workspace create audit count=%d", auditCount)
	}
	var currentRevision int64
	var currentOwner string
	if err := tx.QueryRow(ctx, `
		SELECT current_revision, owner_principal_id
		FROM public.workspace
		WHERE id = $1
	`, created.ID).Scan(&currentRevision, &currentOwner); err != nil {
		t.Fatal(err)
	}
	if currentRevision != 7 || currentOwner != "usr_carol" {
		t.Fatalf("current workspace revision/owner=%d/%q", currentRevision, currentOwner)
	}
	var validMembershipHistory int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM public.workspace_member
		WHERE workspace_id = $1
		  AND (
			(principal_id = 'usr_alice' AND role = 'OWNER' AND valid_from_revision = 1 AND valid_to_revision = 4)
			OR (principal_id = 'usr_carol' AND role = 'VIEWER' AND valid_from_revision = 2 AND valid_to_revision = 3)
			OR (principal_id = 'usr_carol' AND role = 'MANAGER' AND valid_from_revision = 3 AND valid_to_revision = 4)
			OR (principal_id = 'usr_alice' AND role = 'MANAGER' AND valid_from_revision = 4 AND valid_to_revision = 6)
			OR (principal_id = 'usr_carol' AND role = 'OWNER' AND valid_from_revision = 4 AND valid_to_revision IS NULL AND removed_at IS NULL)
		  )
	`, created.ID).Scan(&validMembershipHistory); err != nil {
		t.Fatal(err)
	}
	if validMembershipHistory != 5 {
		t.Fatalf("valid membership history rows=%d, want 5", validMembershipHistory)
	}
	var activeOwners int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM public.workspace_member
		WHERE workspace_id = $1 AND role = 'OWNER' AND removed_at IS NULL
	`, created.ID).Scan(&activeOwners); err != nil {
		t.Fatal(err)
	}
	if activeOwners != 1 {
		t.Fatalf("active workspace owners=%d, want 1", activeOwners)
	}
	var deniedTransfers int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE workspace_id = $1 AND action = 'workspace.role_changed' AND outcome = 'DENIED'
	`, created.ID).Scan(&deniedTransfers); err != nil {
		t.Fatal(err)
	}
	if deniedTransfers != 1 {
		t.Fatalf("denied ownership transfer audit count=%d", deniedTransfers)
	}
	var revisionConflicts int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE workspace_id = $1 AND action = 'workspace.updated' AND outcome = 'FAILED'
		  AND error_code = 'WORKSPACE_REVISION_CONFLICT'
	`, created.ID).Scan(&revisionConflicts); err != nil {
		t.Fatal(err)
	}
	if revisionConflicts != 1 {
		t.Fatalf("workspace revision conflict audit count=%d", revisionConflicts)
	}
	var receiptCount, snapshotCount, pendingCount int
	if err := admin.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status = 'PENDING') FROM public.workspace_command_receipt WHERE organization_id = 'org_alpha'`).Scan(&receiptCount, &pendingCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_snapshot WHERE workspace_id = $1`, created.ID).Scan(&snapshotCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 10 || pendingCount != 0 || snapshotCount != 7 {
		t.Fatalf("command receipts/pending/snapshots=%d/%d/%d, want 10/0/7", receiptCount, pendingCount, snapshotCount)
	}
}

func TestWorkspaceCommandConcurrentCreateCommitsExactlyOnce(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	request := workspacerepository.CreateRequest{
		IdempotencyKey: workspaceIdempotencyKey("concurrent-create"),
		Name:           "Concurrent workspace", Description: "\u041e\u0434\u0438\u043d \u0440\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 \u0434\u043b\u044f \u0432\u0441\u0435\u0445 \u043f\u043e\u0432\u0442\u043e\u0440\u043e\u0432",
	}
	type commandResult struct {
		snapshot workspace.Snapshot
		err      error
	}
	const callers = 8
	start := make(chan struct{})
	results := make(chan commandResult, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			snapshot, createErr := workspaceStore.Create(ctx, database.AccessContext{
				OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: fmt.Sprintf("req_concurrent_create_%02d", index),
			}, request)
			results <- commandResult{snapshot: snapshot, err: createErr}
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	var expected workspace.Snapshot
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent create: %v", result.err)
		}
		if expected.ID == "" {
			expected = result.snapshot
			continue
		}
		if !reflect.DeepEqual(result.snapshot, expected) {
			t.Fatalf("concurrent replay snapshot=%#v, want %#v", result.snapshot, expected)
		}
	}
	if expected.ID == "" {
		t.Fatal("concurrent create returned no result")
	}

	var workspaces, revisions, snapshots, receipts, pending, events int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace WHERE organization_id = 'org_alpha' AND name = 'Concurrent workspace'`).Scan(&workspaces); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision WHERE organization_id = 'org_alpha' AND workspace_id = $1`, expected.ID).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_snapshot WHERE organization_id = 'org_alpha' AND workspace_id = $1`, expected.ID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status = 'PENDING') FROM public.workspace_command_receipt WHERE organization_id = 'org_alpha' AND operation = 'WORKSPACE_CREATE'`).Scan(&receipts, &pending); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id = 'org_alpha' AND action = 'workspace.created' AND resource_id = $1`, expected.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if workspaces != 1 || revisions != 1 || snapshots != 1 || receipts != 1 || pending != 0 || events != 1 {
		t.Fatalf("concurrent create counts workspace/revision/snapshot/receipt/pending/audit=%d/%d/%d/%d/%d/%d", workspaces, revisions, snapshots, receipts, pending, events)
	}
}

func TestWorkspaceManagerCanRemoveSelfAndReplayIsCurrentAccessGated(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_bob', 'org_alpha', 'USER', 'Bob', 'ACTIVE')
	`); err != nil {
		t.Fatal(err)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	aliceAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_self_remove_add"}
	initial, err := workspaceStore.Get(ctx, aliceAccess, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	withManager, err := workspaceStore.AddMember(ctx, aliceAccess, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("self-remove-add-manager"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial), PrincipalID: "usr_bob", Role: workspace.RoleManager,
	})
	if err != nil {
		t.Fatal(err)
	}

	bobAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_self_remove"}
	removeRequest := workspacerepository.RemoveMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("manager-self-remove"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, withManager), PrincipalID: "usr_bob",
	}
	removed, err := workspaceStore.RemoveMember(ctx, bobAccess, removeRequest)
	if err != nil || removed.Revision != 3 || len(removed.Members) != 1 || removed.Members[0].PrincipalID != "usr_alice" {
		t.Fatalf("manager self-remove snapshot=%#v err=%v", removed, err)
	}
	if _, getErr := workspaceStore.Get(ctx, bobAccess, "ws_alpha"); workspacerepository.CodeOf(getErr) != workspacerepository.CodeNotFound {
		t.Fatalf("self-removed manager get code=%q err=%v", workspacerepository.CodeOf(getErr), getErr)
	}
	if _, replayErr := workspaceStore.RemoveMember(ctx, bobAccess, removeRequest); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeNotFound {
		t.Fatalf("self-removed manager replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}
	if current, getErr := workspaceStore.Get(ctx, aliceAccess, "ws_alpha"); getErr != nil || !reflect.DeepEqual(current, removed) {
		t.Fatalf("owner current snapshot=%#v err=%v", current, getErr)
	}

	var receipts, successfulReceipts, audits int
	if err := admin.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status = 'SUCCESS')
		FROM public.workspace_command_receipt
		WHERE organization_id = 'org_alpha' AND actor_principal_id = 'usr_bob' AND operation = 'WORKSPACE_MEMBER_REMOVE'
	`).Scan(&receipts, &successfulReceipts); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha' AND actor_principal_id = 'usr_bob'
		  AND action = 'workspace.member_removed' AND outcome = 'SUCCESS'
	`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 || successfulReceipts != 1 || audits != 1 {
		t.Fatalf("self-remove receipt/successful-receipt/audit=%d/%d/%d, want 1/1/1", receipts, successfulReceipts, audits)
	}
}

func TestWorkspaceInactiveTargetDenialIsTerminalAndExactReplaySafe(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_inactive', 'org_alpha', 'USER', 'Inactive', 'DEPROVISIONED')
	`); err != nil {
		t.Fatal(err)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	aliceAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_inactive_target"}
	initial, err := workspaceStore.Get(ctx, aliceAccess, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	request := workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("inactive-target-denial"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial), PrincipalID: "usr_inactive", Role: workspace.RoleViewer,
	}
	if _, addErr := workspaceStore.AddMember(ctx, aliceAccess, request); workspacerepository.CodeOf(addErr) != workspacerepository.CodeDenied {
		t.Fatalf("inactive target initial denial code=%q err=%v", workspacerepository.CodeOf(addErr), addErr)
	}
	if _, replayErr := workspaceStore.AddMember(ctx, aliceAccess, request); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeDenied {
		t.Fatalf("inactive target exact replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}

	var revision, inactiveMemberships, receipts, deniedReceipts, audits int
	if err := admin.QueryRow(ctx, `
		SELECT current_revision FROM public.workspace
		WHERE organization_id = 'org_alpha' AND id = 'ws_alpha'
	`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_member
		WHERE organization_id = 'org_alpha' AND workspace_id = 'ws_alpha' AND principal_id = 'usr_inactive'
	`).Scan(&inactiveMemberships); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status = 'DENIED')
		FROM public.workspace_command_receipt
		WHERE organization_id = 'org_alpha' AND actor_principal_id = 'usr_alice' AND operation = 'WORKSPACE_MEMBER_ADD'
	`).Scan(&receipts, &deniedReceipts); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha' AND actor_principal_id = 'usr_alice'
		  AND action = 'workspace.member_added' AND outcome = 'DENIED'
	`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || inactiveMemberships != 0 || receipts != 1 || deniedReceipts != 1 || audits != 1 {
		t.Fatalf("inactive target revision/membership/receipt/denied-receipt/audit=%d/%d/%d/%d/%d, want 1/0/1/1/1", revision, inactiveMemberships, receipts, deniedReceipts, audits)
	}
}

func TestWorkspaceCommandReceiptRLSAndImmutabilityFailClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_bob', 'org_alpha', 'USER', 'Bob', 'ACTIVE')
	`); err != nil {
		t.Fatal(err)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	created, err := workspaceStore.Create(ctx, database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_receipt_rls_create"}, workspacerepository.CreateRequest{
		IdempotencyKey: workspaceIdempotencyKey("receipt-rls"), Name: "Receipt RLS",
	})
	if err != nil {
		t.Fatal(err)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	bobTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, bobTransaction, "org_alpha", "usr_bob")
	var visible int
	if err := bobTransaction.QueryRow(ctx, `SELECT count(*) FROM public.workspace_command_receipt`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("bob sees %d alice receipts", visible)
	}
	if err := bobTransaction.QueryRow(ctx, `SELECT count(*) FROM public.workspace_revision_snapshot`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("bob sees %d workspace revision snapshots without membership", visible)
	}
	if tag, err := bobTransaction.Exec(ctx, `UPDATE public.workspace_command_receipt SET status = 'DENIED', terminal_at = transaction_timestamp()`); err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("bob receipt update tag=%v err=%v", tag, err)
	}
	if err := bobTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	bypassTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, bypassTransaction, "org_alpha", "usr_bob")
	if _, err := bypassTransaction.Exec(ctx, `SET LOCAL row_security = off`); err != nil {
		t.Fatal(err)
	}
	if err := bypassTransaction.QueryRow(ctx, `SELECT count(*) FROM public.workspace_command_receipt`).Scan(&visible); err == nil {
		t.Fatal("row_security=off exposed workspace command receipts")
	}
	_ = bypassTransaction.Rollback(ctx)

	aliceTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, aliceTransaction, "org_alpha", "usr_alice")
	if _, err := aliceTransaction.Exec(ctx, `UPDATE public.workspace_command_receipt SET status = 'DENIED', terminal_at = transaction_timestamp()`); err == nil {
		t.Fatal("terminal receipt update unexpectedly succeeded")
	}
	_ = aliceTransaction.Rollback(ctx)

	aliceTransaction, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, aliceTransaction, "org_alpha", "usr_alice")
	if _, err := aliceTransaction.Exec(ctx, `UPDATE public.workspace_revision_snapshot SET canonical_bytes = '\x7b7d' WHERE workspace_id = $1`, created.ID); err == nil {
		t.Fatal("revision snapshot update unexpectedly succeeded")
	}
	_ = aliceTransaction.Rollback(ctx)

	aliceTransaction, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, aliceTransaction, "org_alpha", "usr_alice")
	if _, err := aliceTransaction.Exec(ctx, `DELETE FROM public.workspace_command_receipt`); err == nil {
		t.Fatal("receipt delete unexpectedly succeeded")
	}
	_ = aliceTransaction.Rollback(ctx)

	pendingHash := "sha256:" + strings.Repeat("d", 64)
	aliceTransaction, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, aliceTransaction, "org_alpha", "usr_alice")
	if _, err := aliceTransaction.Exec(ctx, `
		INSERT INTO public.workspace_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, operation, canonical_request_hash,
			command_workspace_id, command_resource_type, command_resource_id,
			command_target_principal_id, command_target_role
		) VALUES ('org_alpha', 'usr_alice', $1, 'WORKSPACE_ARCHIVE', $2,
			'ws_alpha', 'WORKSPACE', 'ws_alpha', NULL, NULL)
	`, pendingHash, "sha256:"+strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if err := aliceTransaction.Commit(ctx); err == nil {
		t.Fatal("PENDING receipt committed")
	}
	var pendingRows int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_command_receipt WHERE idempotency_key_hash = $1`, pendingHash).Scan(&pendingRows); err != nil {
		t.Fatal(err)
	}
	if pendingRows != 0 {
		t.Fatalf("rolled-back PENDING receipt rows=%d", pendingRows)
	}
}

// TestWorkspaceCommandDatabaseGateRejectsRawStateBypasses is intentionally a
// destructive integration test. The runtime role is allowed to write the
// Stage 1 control-plane tables, so the idempotency migration itself must prove
// that every mutable workspace aggregate edge is tied to one fresh receipt,
// immutable revision snapshot and matching audit event. Application helpers
// are not used for the attacks below.
func TestWorkspaceCommandDatabaseGateRejectsRawStateBypasses(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	for _, principal := range []string{"usr_bob", "usr_carol"} {
		if _, err := admin.Exec(ctx, `
			INSERT INTO public.principal (id, organization_id, type, display_name, status)
			VALUES ($1, 'org_alpha', 'USER', $1, 'ACTIVE')
		`, principal); err != nil {
			t.Fatal(err)
		}
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	aliceAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_gate_create"}
	created, err := workspaceStore.Create(ctx, aliceAccess, workspacerepository.CreateRequest{
		IdempotencyKey: workspaceIdempotencyKey("db-gate-create"), Name: "Gate workspace",
	})
	if err != nil {
		t.Fatal(err)
	}
	withBob, err := workspaceStore.AddMember(ctx, aliceAccess, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("db-gate-add-bob"), WorkspaceID: created.ID,
		ExpectedConfigurationHash: mustWorkspaceHash(t, created), PrincipalID: "usr_bob", Role: workspace.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if withBob.Revision != created.Revision+1 {
		t.Fatalf("setup member revision=%d, want %d", withBob.Revision, created.Revision+1)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	assertApplicationWriteRejected(t, app, "org_alpha", "usr_alice", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_revision (
				organization_id, workspace_id, revision, configuration_hash, created_by
			) VALUES ('org_alpha', $1, 3, $2, 'usr_alice')
		`, created.ID, "sha256:"+strings.Repeat("a", 64)); err != nil {
			return err
		}
		_, execErr := tx.Exec(ctx, `
			UPDATE public.workspace
			SET name = 'raw-write-must-not-commit', current_revision = 3, updated_at = transaction_timestamp()
			WHERE organization_id = 'org_alpha' AND id = $1
		`, created.ID)
		return execErr
	})
	assertApplicationWriteRejected(t, app, "org_alpha", "usr_alice", func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO public.workspace_revision (
				organization_id, workspace_id, revision, configuration_hash, created_by
			) VALUES ('org_alpha', $1, 3, $2, 'usr_alice')
		`, created.ID, "sha256:"+strings.Repeat("f", 64))
		return execErr
	})
	assertApplicationWriteRejected(t, app, "org_alpha", "usr_alice", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_revision (
				organization_id, workspace_id, revision, configuration_hash, created_by
			) VALUES ('org_alpha', $1, 3, $2, 'usr_alice')
		`, created.ID, "sha256:"+strings.Repeat("c", 64)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE public.workspace
			SET current_revision = 3, updated_at = transaction_timestamp()
			WHERE organization_id = 'org_alpha' AND id = $1
		`, created.ID); err != nil {
			return err
		}
		_, execErr := tx.Exec(ctx, `
			UPDATE public.workspace_member
			SET valid_to_revision = 3, removed_at = transaction_timestamp()
			WHERE organization_id = 'org_alpha' AND workspace_id = $1 AND principal_id = 'usr_bob' AND removed_at IS NULL
		`, created.ID)
		return execErr
	})
	assertApplicationWriteRejected(t, app, "org_alpha", "usr_alice", func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO public.workspace_member (
				id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
			) VALUES ('wsm_raw_carol', 'org_alpha', $1, 'usr_carol', 'VIEWER', 2, 'usr_alice')
		`, created.ID)
		return execErr
	})

	if err := admin.QueryRow(ctx, `
		SELECT current_revision FROM public.workspace
		WHERE organization_id = 'org_alpha' AND id = $1
	`, created.ID).Scan(&withBob.Revision); err != nil {
		t.Fatal(err)
	}
	if withBob.Revision != 2 {
		t.Fatalf("raw attacks changed workspace revision=%d", withBob.Revision)
	}
	var carolMemberships int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_member
		WHERE organization_id = 'org_alpha' AND workspace_id = $1 AND principal_id IN ('usr_bob', 'usr_carol') AND removed_at IS NULL
	`, created.ID).Scan(&carolMemberships); err != nil {
		t.Fatal(err)
	}
	if carolMemberships != 1 {
		t.Fatalf("raw member attacks changed active member count=%d, want 1", carolMemberships)
	}

	bobAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_gate_wrong_actor"}
	deniedCode := string(workspacerepository.CodeDenied)
	wrongActorAudit := appendWorkspaceGateAudit(t, ctx, auditStore, bobAccess, "aud_gate_wrong_actor", audit.ActionWorkspaceCreated, audit.OutcomeDenied, &deniedCode, created.ID)
	assertForgedDeniedReceiptRejected(t, app, "org_alpha", "usr_alice", created.ID, created.ID, "a", wrongActorAudit)

	wrongActionAudit := appendWorkspaceGateAudit(t, ctx, auditStore, aliceAccess, "aud_gate_wrong_action", audit.ActionWorkspaceUpdated, audit.OutcomeDenied, &deniedCode, created.ID)
	assertForgedDeniedReceiptRejected(t, app, "org_alpha", "usr_alice", created.ID, created.ID, "b", wrongActionAudit)

	wrongOutcomeAudit := appendWorkspaceGateAudit(t, ctx, auditStore, aliceAccess, "aud_gate_wrong_outcome", audit.ActionWorkspaceCreated, audit.OutcomeSuccess, nil, created.ID)
	assertForgedDeniedReceiptRejected(t, app, "org_alpha", "usr_alice", created.ID, created.ID, "c", wrongOutcomeAudit)

	deniedCreate := workspacerepository.CreateRequest{IdempotencyKey: workspaceIdempotencyKey("db-gate-bob-denied"), Name: "Bob cannot create"}
	if _, deniedErr := workspaceStore.Create(ctx, bobAccess, deniedCreate); workspacerepository.CodeOf(deniedErr) != workspacerepository.CodeDenied {
		t.Fatalf("setup denied create code=%q err=%v", workspacerepository.CodeOf(deniedErr), deniedErr)
	}
	var deniedWorkspaceID, deniedResourceID, deniedAuditID string
	if err := admin.QueryRow(ctx, `
		SELECT command_workspace_id, command_resource_id, audit_event_id
		FROM public.workspace_command_receipt
		WHERE organization_id = 'org_alpha' AND actor_principal_id = 'usr_bob'
		  AND operation = 'WORKSPACE_CREATE' AND status = 'DENIED'
	`).Scan(&deniedWorkspaceID, &deniedResourceID, &deniedAuditID); err != nil {
		t.Fatal(err)
	}
	assertForgedDeniedReceiptRejected(t, app, "org_alpha", "usr_bob", deniedWorkspaceID, deniedResourceID, "d", deniedAuditID)
	var auditUses int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_command_receipt
		WHERE organization_id = 'org_alpha' AND audit_event_id = $1
	`, deniedAuditID).Scan(&auditUses); err != nil {
		t.Fatal(err)
	}
	if auditUses != 1 {
		t.Fatalf("audit event reused by %d receipts", auditUses)
	}
}

func appendWorkspaceGateAudit(t *testing.T, ctx context.Context, store *audit.Store, access database.AccessContext, eventID string, action audit.Action, outcome audit.Outcome, errorCode *string, workspaceID string) string {
	t.Helper()
	actorID := access.PrincipalID
	event, err := store.Append(ctx, access, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: action, ResourceType: audit.ResourceWorkspace, ResourceID: workspaceID,
		RequestID: access.RequestID, Outcome: outcome, ErrorCode: errorCode, OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("append gate attack audit %s: %v", eventID, err)
	}
	return event.EventID
}

// assertForgedDeniedReceiptRejected proves three distinct attacks: a receipt
// cannot point to an audit event with a wrong actor/action/outcome, and an
// audit event cannot be reused by a second terminal receipt. DENIED needs no
// result snapshot, so the assertion cannot accidentally pass only because of
// the separate one-success-per-revision constraint.
func assertForgedDeniedReceiptRejected(t *testing.T, app *pgxpool.Pool, organizationID, principalID, commandWorkspaceID, commandResourceID, keyCharacter, auditEventID string) {
	t.Helper()
	keyHash := "sha256:" + strings.Repeat(keyCharacter, 64)
	requestHash := "sha256:" + strings.Repeat("f", 64)
	if keyCharacter == "a" {
		requestHash = "sha256:" + strings.Repeat("e", 64)
	}
	assertApplicationWriteRejected(t, app, organizationID, principalID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO public.workspace_command_receipt (
				organization_id, actor_principal_id, idempotency_key_hash, operation, canonical_request_hash,
				command_workspace_id, command_target_principal_id, command_target_role,
				command_resource_type, command_resource_id
			) VALUES ($1, $2, $3, 'WORKSPACE_CREATE', $4, $5, NULL, NULL, 'WORKSPACE', $6)
		`, organizationID, principalID, keyHash, requestHash, commandWorkspaceID, commandResourceID); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `
			UPDATE public.workspace_command_receipt
			SET status = 'DENIED', audit_event_id = $4, terminal_at = transaction_timestamp()
			WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		`, organizationID, principalID, keyHash, auditEventID)
		return err
	})
}

// assertApplicationWriteRejected accepts a rejection at the statement or at
// deferred-constraint commit boundary. Both are correct fail-closed outcomes
// for a raw runtime-role bypass attempt.
func assertApplicationWriteRejected(t *testing.T, app *pgxpool.Pool, organizationID, principalID string, work func(pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	if err := work(tx); err != nil {
		return
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("raw workspace command bypass committed")
	}
}

func mustWorkspaceHash(t *testing.T, snapshot workspace.Snapshot) string {
	t.Helper()
	hash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("workspace configuration hash: %v", err)
	}
	return hash
}

func workspaceIdempotencyKey(label string) string {
	digest := sha256.Sum256([]byte("workspace-test:" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestIdentitySessionsAreTenantBoundOneTimeAndRevocable(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	seedOIDCProvider(t, ctx, admin, "org_beta", "usr_bob", "idp_beta", "https://id.beta.example")

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	createConsumedIdentitySession(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a")
	var unscopedSessionCount int
	if err := app.QueryRow(ctx, "SELECT count(*) FROM public.identity_session").Scan(&unscopedSessionCount); err != nil {
		t.Fatal(err)
	}
	if unscopedSessionCount != 0 {
		t.Fatalf("unscoped identity session query returned %d rows", unscopedSessionCount)
	}

	alphaTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = alphaTransaction.Rollback(ctx) }()
	setAccessContext(t, ctx, alphaTransaction, "org_alpha")
	var sessionCount int
	if err := alphaTransaction.QueryRow(ctx, "SELECT count(*) FROM public.identity_session").Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 1 {
		t.Fatalf("alpha session count = %d, want 1", sessionCount)
	}
	if err := alphaTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertIdentityMutationDenied(t, app, "org_alpha", `
		INSERT INTO public.identity_session (
			id, organization_id, principal_id, provider_id, external_identity_id, login_attempt_id,
			session_token_digest, principal_session_revision, provider_revision, expires_at
		) VALUES (
			'sess_replay', 'org_alpha', 'usr_alice', 'idp_alpha', 'eid_alpha', 'login_alpha',
			'hmac-sha256:k1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 1, 1,
			transaction_timestamp() + interval '1 hour'
		)
	`)

	betaTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = betaTransaction.Rollback(ctx) }()
	setAccessContext(t, ctx, betaTransaction, "org_beta")
	if err := betaTransaction.QueryRow(ctx, "SELECT count(*) FROM public.identity_session").Scan(&sessionCount); err != nil {
		t.Fatal(err)
	}
	if sessionCount != 0 {
		t.Fatalf("beta saw %d alpha identity sessions", sessionCount)
	}
	if err := betaTransaction.QueryRow(ctx, `
		UPDATE public.identity_session
		SET revoked_at = transaction_timestamp(), revocation_code = 'TEST_REVOKE'
		WHERE id = 'sess_alpha'
		RETURNING id
	`).Scan(new(string)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("beta could target alpha identity session: %v", err)
	}
	if err := betaTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	deprovisionTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = deprovisionTransaction.Rollback(ctx) }()
	setAccessContext(t, ctx, deprovisionTransaction, "org_alpha")
	if _, err := deprovisionTransaction.Exec(ctx, `
		UPDATE public.principal
		SET status = 'DEPROVISIONED', session_revision = session_revision + 1
		WHERE id = 'usr_alice'
	`); err != nil {
		t.Fatalf("deprovision principal: %v", err)
	}
	var revokedAt *time.Time
	if err := deprovisionTransaction.QueryRow(ctx, "SELECT revoked_at FROM public.identity_session WHERE id = 'sess_alpha'").Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == nil {
		t.Fatal("principal deprovision did not revoke active identity session")
	}
	if err := deprovisionTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	assertIdentityMutationDenied(t, app, "org_alpha", `
		UPDATE public.principal
		SET status = 'ACTIVE', session_revision = session_revision + 1
		WHERE id = 'usr_alice'
	`)
	assertIdentityMutationDenied(t, app, "org_alpha", `
		UPDATE public.identity_session
		SET revoked_at = NULL, revocation_code = NULL
		WHERE id = 'sess_alpha'
	`)

	for _, tableName := range []string{
		"oidc_provider", "oidc_provider_revision", "external_identity", "oidc_login_attempt", "identity_session",
	} {
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tableName).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s RLS is not forced", tableName)
		}
	}
}

func TestOIDCLoginAttemptTransitionsAndDigestOnlyStorage(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.oidc_login_attempt (
			id, organization_id, provider_id, provider_revision, state_digest,
			browser_binding_digest, nonce_digest, pkce_verifier_digest, expires_at
		) VALUES (
			'login_transition', 'org_alpha', 'idp_alpha', 1, $1, $2, $3, $4,
			transaction_timestamp() + interval '5 minutes'
		)
	`, testIdentityDigest("a"), testIdentityDigest("b"), testIdentityDigest("c"), testIdentityDigest("d")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertIdentityMutationDenied(t, app, "org_alpha", `
		UPDATE public.oidc_login_attempt
		SET status = 'CONSUMED', claimed_at = transaction_timestamp(), completed_at = transaction_timestamp()
		WHERE id = 'login_transition'
	`)

	for _, forbiddenColumn := range []string{
		"access_token", "refresh_token", "id_token", "authorization_code", "external_subject", "email", "claims_json", "pkce_verifier", "nonce",
	} {
		var count int
		if err := admin.QueryRow(ctx, `
			SELECT count(*)
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name IN ('external_identity', 'oidc_login_attempt', 'identity_session')
			  AND column_name = $1
		`, forbiddenColumn).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("identity schema persists forbidden plaintext field %q", forbiddenColumn)
		}
	}
}

// migrationSequence is the exact ordered migration history. It is the only
// inventory of migrations the integration suite knows about: a rebuild is
// always a replay of these files against an empty schema, never a dump.
var migrationSequence = []string{
	"000000_stage0.sql",
	"000001_stage1_tenancy.sql",
	"000002_stage1_audit.sql",
	"000003_stage1_identity.sql",
	"000004_stage1_workspace_command_idempotency.sql",
	"000005_stage2_encrypted_artifact_outbox.sql",
	"000006_stage2_source_connection_draft.sql",
	"000007_stage2_source_scope_draft.sql",
	"000008_stage2_workspace_source_snapshot.sql",
	"000009_stage2_workspace_source_command_gate.sql",
	"000010_stage2_workspace_managed_confirmation_authority.sql",
	"000011_stage2_workspace_managed_authority_command.sql",
	"000012_stage2_encrypted_artifact_containment.sql",
	"000013_stage2_durable_ingestion_jobs.sql",
	"000014_stage2_catalog_extraction_evidence.sql",
	"000015_stage2_source_version_purge.sql",
	"000016_stage2_source_scope_revision_cutover.sql",
	"000017_stage2_keyed_evidence_anchor.sql",
	"000018_stage2_source_registration.sql",
	"000019_stage2_secret_rotation.sql",
	"000020_stage2_keyed_text_digest.sql",
	"000021_stage2_evidence_fragment_reproject_null_fence.sql",
	"000022_stage2_answer_document_amendment.sql",
	"000023_stage2_ocr_extraction_identity.sql",
	"000024_stage3_extractive_question_run.sql",
	"000025_stage3_postgresql_query_source.sql",
	"000026_stage2_workspace_source_status_binding_id.sql",
	"000027_stage3_search_retrieval_persistence.sql",
	"000028_stage3_retrieval_authorization_snapshot.sql",
	"000029_stage3_search_outbox_applier.sql",
	"000030_stage3_search_retention_cleanup.sql",
	"000031_stage3_generic_question_planner.sql",
	"000032_stage3_knowledge_graph.sql",
	"000033_stage3_knowledge_graph_visibility_retention.sql",
	"000034_stage3_knowledge_graph_purge.sql",
	"000035_stage3_knowledge_graph_purger_delete.sql",
	"000036_stage3_knowledge_graph_projection_targets.sql",
	"000037_stage3_analytic_tool_run.sql",
	"000038_stage3_question_signals.sql",
	"000039_stage3_knowledge_graph_relation_projection.sql",
	"000040_stage3_question_access_provenance.sql",
	"000041_stage3_source_observation_types.sql",
	"000042_stage3_remote_source_registration.sql",
	"000043_stage3_lexical_search_chunks.sql",
	"000044_stage3_question_citation_binding.sql",
	"000045_stage3_question_corpus_freshness.sql",
	"000046_stage3_search_optional_embedding_outbox.sql",
	"000047_stage3_knowledge_graph_idempotent_projection.sql",
	"000048_stage3_conversation_workspace_lifecycle.sql",
	"000049_stage3_question_conversation_binding.sql",
	"000050_stage3_conversation_command_receipt.sql",
	"000051_stage3_source_jobs_observability.sql",
	"000052_stage3_knowledge_graph_relation_endpoint_visibility.sql",
	"000053_stage3_question_conversation_retention_gate.sql",
	"000054_stage3_conversation_physical_purge.sql",
	"000055_stage3_conversation_purge_queue.sql",
	"000056_stage3_source_version_purge_queue.sql",
	"000057_stage2_source_connection_trust_verify.sql",
	"000058_stage2_registration_replay_lifecycle_gate.sql",
	"000059_stage2_source_connection_trust_verify_attestation.sql",
	"000060_stage3_generative_gateway_attempt.sql",
	"000061_stage3_postgresql_query_autosync.sql",
	"000062_stage3_source_status_schedule.sql",
	"000066_stage2_service_principal_credential.sql",
	"000067_stage2_service_principal_workspace_scope.sql",
	"000068_stage3_governed_query_exposed_schema.sql",
	"000069_stage3_governed_query_promotion_and_audit.sql",
	"000070_stage2_enqueue_job_id_idempotent.sql",
	"000071_stage3_worker_reads_activation_confirmation.sql",
	"000072_stage3_search_profile_revisions.sql",
	"000073_stage3_structured_snapshot_cells.sql",
	"000074_stage3_governed_query_attempt.sql",
	"000075_stage2_one_live_sync_job_per_scope.sql",
	"000076_stage2_source_scope_activation_confirmed_per_scope.sql",
	"000077_stage2_evidence_fragment_readable_per_scope.sql",
	"000078_stage3_governed_query_workspace_binding.sql",
	"000079_stage2_service_principal_credential_atomic_issue.sql",
	"000080_stage3_conversation_continuation_revision_tolerant.sql",
	"000081_stage3_structured_snapshot_period_role.sql",
	"000082_stage3_structured_snapshot_status_role.sql",
	"000083_stage3_structured_source_scope_names.sql",
	"000086_stage2_source_uploaded_document.sql",
	"000088_stage1_identity_session_sliding_renewal.sql",
	"000089_stage3_source_periodic_sync.sql",
	"000090_stage4_source_discovery.sql",
	"000091_stage4_source_connection_bootstrap.sql",
	"000092_stage4_source_discovery_owner_read.sql",
	"000093_stage4_source_discovery_registration.sql",
	"000094_stage3_metric_definitions.sql",
	"000095_stage3_source_object_skip.sql",
	"000096_stage3_source_object_skip_identity.sql",
	"000097_stage3_tool_loop_question.sql",
	"000098_stage3_source_object_skip_resolution.sql",
	"000099_stage2_workspace_source_confirmation_status.sql",
	"000100_stage2_durable_ingestion_lease_clock.sql",
	"000101_stage3_evidence_source_version_lookup.sql",
	"000102_stage3_source_scope_object_lookup.sql",
	"000103_stage2_evidence_fragment_exact_read.sql",
	"000104_stage2_evidence_exact_layout_metadata.sql",
	"000105_stage3_context_observed_extraction.sql",
	"000106_stage2_source_version_reobservation.sql",
	"000107_stage2_source_observed_presence.sql",
	"000108_stage3_source_freshness_completeness.sql",
	"000109_stage3_metric_definition_dataset_binding.sql",
	"000110_stage3_postgresql_query_table_source.sql",
	"000111_stage4_source_discovery_relation_limit.sql",
	"000112_stage4_workspace_model_context.sql",
	"000113_stage4_workspace_context_proposals.sql",
	"000114_stage4_source_connection_drafts.sql",
	"000115_stage4_postgresql_query_relation_catalog.sql",
	"000116_stage4_source_query_credential.sql",
}

// migrationHistoricalConfirmationAuthority is the last migration of the inert
// ADR-0052 authority foundation, before ADR-0053's receipt boundary opens any
// write path. Tests that pin that historical contract stop here on purpose;
// see resetAuthorityHistoricalDatabase.
const migrationHistoricalConfirmationAuthority = "000010_stage2_workspace_managed_confirmation_authority.sql"

// resetStage1Database rebuilds the database at the current head of the
// migration history.
func resetStage1Database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return resetDatabaseThrough(t, migrationSequence[len(migrationSequence)-1])
}

// resetAuthorityHistoricalDatabase rebuilds the database exactly as migration
// 000010 left it.
//
// The ADR-0052 checkpoint shipped the four confirmation-authority relations as
// inert persistence, and its test suite pins that boundary: SELECT-only
// privileges, no INSERT path, no receipt. Migration 000011 is chartered by
// ADR-0053 to replace precisely that inert boundary with a receipt-gated one,
// so those assertions are false at head by design, not by regression.
//
// Rather than delete the 000010 suite or rewrite its assertions into the new
// contract — either of which would silently drop the proof that the inert step
// was ever correct — the suite keeps testing the schema state it was written
// against. This also proves a deployment stopped mid-upgrade at 000010 is
// safe. The head-of-history contract is proved separately by the 000011 suite.
func resetAuthorityHistoricalDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return resetDatabaseThrough(t, migrationHistoricalConfirmationAuthority)
}

// resetPreCatalogDatabase rebuilds the database exactly as migration 000013 left
// it, before ADR-0058's S1d checkpoint (000014) opens the scope-activation and
// connection-trust transitions and makes the catalog relations writable.
//
// The source control-plane suites written against 000006/000007 pinned a
// DRAFT-only, fully immutable projection contract. 000014 is chartered to open
// exactly those transitions, so those assertions are false at head by design,
// not by regression — the same situation ADR-0053/000011 created for the inert
// authority suite. Rather than rewrite the historical proofs into the new
// contract (which would silently drop the evidence that the pre-S1d control
// plane was correct, and that a deployment stopped mid-upgrade at 000013 is
// safe), those suites keep testing the schema state they were written against.
// The head-of-history contract is proved separately by the S1d catalog/Evidence
// suite (catalog_evidence*_test.go).
func resetPreCatalogDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return resetDatabaseThrough(t, "000013_stage2_durable_ingestion_jobs.sql")
}

func readMigrationFile(t *testing.T, name string) (string, error) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "db", "migrations", name))
	return string(raw), err
}

func resetDatabaseThrough(t *testing.T, lastMigration string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	adminURL := testDatabaseURL(t)
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	t.Cleanup(admin.Close)

	for _, statement := range []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"DROP SCHEMA IF EXISTS app CASCADE",
		"DROP SCHEMA IF EXISTS operator CASCADE",
		"DROP ROLE IF EXISTS knowvault_app",
		"DROP ROLE IF EXISTS knowvault_worker",
		"DROP ROLE IF EXISTS knowvault_purger",
		"CREATE SCHEMA public AUTHORIZATION CURRENT_USER",
		"CREATE ROLE knowvault_app LOGIN PASSWORD 'knowvault_test_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
		"CREATE ROLE knowvault_worker LOGIN PASSWORD 'knowvault_test_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
		"CREATE ROLE knowvault_purger LOGIN PASSWORD 'knowvault_test_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("reset stage 1 database with %q: %v", statement, err)
		}
	}

	applied := false
	for _, migrationName := range migrationSequence {
		migration, err := os.ReadFile(filepath.Join(repositoryRoot(t), "db", "migrations", migrationName))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", migrationName, err)
		}
		if migrationName == lastMigration {
			applied = true
			break
		}
	}
	if !applied {
		t.Fatalf("migration %s is not part of the known migration sequence", lastMigration)
	}
	return admin
}

func ptr(value string) *string { return &value }

func assertAuditMutationDenied(t *testing.T, app *pgxpool.Pool, organizationID, statement string) {
	t.Helper()
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, organizationID)
	if _, err := tx.Exec(ctx, statement); err == nil {
		t.Fatalf("runtime role unexpectedly permitted %q", statement)
	}
}

func assertIdentityMutationDenied(t *testing.T, app *pgxpool.Pool, organizationID, statement string) {
	t.Helper()
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, organizationID)
	if _, err := tx.Exec(ctx, statement); err == nil {
		t.Fatalf("runtime role unexpectedly permitted identity mutation %q", statement)
	}
}

func seedOIDCProvider(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, providerID, issuerURL string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.oidc_provider (id, organization_id, issuer_url, status, current_revision, created_by)
		VALUES ($1, $2, $3, 'ACTIVE', 1, $4)
	`, providerID, organizationID, issuerURL, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.oidc_provider_revision (
			organization_id, provider_id, revision, client_id, client_secret_reference,
			redirect_uri, allowed_id_token_algorithms_json, configuration_hash, created_by
		) VALUES ($1, $2, 1, $3, $4, $5, '["RS256"]'::jsonb, $6, $7)
	`, organizationID, providerID, "client_"+providerID, "secret_"+providerID, "https://workspace.example/auth/callback", "sha256:"+strings.Repeat("b", 64), ownerID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func createConsumedIdentitySession(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, providerID, externalIdentityID, loginAttemptID, sessionID, digestCharacter string) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, organizationID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.external_identity (
			id, organization_id, principal_id, provider_id, external_subject_digest,
			digest_key_version, attributes_hash, status
		) VALUES ($1, $2, $3, $4, $5, 1, $6, 'ACTIVE')
	`, externalIdentityID, organizationID, principalID, providerID, testIdentityDigest("c"), "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.oidc_login_attempt (
			id, organization_id, provider_id, provider_revision, state_digest,
			browser_binding_digest, nonce_digest, pkce_verifier_digest, expires_at
		) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, transaction_timestamp() + interval '5 minutes')
	`, loginAttemptID, organizationID, providerID, testIdentityDigest("d"), testIdentityDigest("e"), testIdentityDigest("f"), testIdentityDigest("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.oidc_login_attempt
		SET status = 'CLAIMED', claimed_at = transaction_timestamp()
		WHERE id = $1
	`, loginAttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.identity_session (
			id, organization_id, principal_id, provider_id, external_identity_id, login_attempt_id,
			session_token_digest, principal_session_revision, provider_revision, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, 1, transaction_timestamp() + interval '1 hour')
	`, sessionID, organizationID, principalID, providerID, externalIdentityID, loginAttemptID, testIdentityDigest(digestCharacter)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.oidc_login_attempt
		SET status = 'CONSUMED', completed_at = transaction_timestamp()
		WHERE id = $1
	`, loginAttemptID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func testIdentityDigest(character string) string {
	return "hmac-sha256:k1:" + strings.Repeat(character, 64)
}

func mustKeyedDigest(t *testing.T, character string) identity.KeyedDigest {
	t.Helper()
	digest, err := identity.NewKeyedDigest(testIdentityDigest(character))
	if err != nil {
		t.Fatalf("NewKeyedDigest() error = %v", err)
	}
	return digest
}

func seedExternalIdentity(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, principalID, providerID, externalIdentityID, externalSubjectDigest string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.external_identity (
			id, organization_id, principal_id, provider_id, external_subject_digest,
			digest_key_version, attributes_hash, status
		) VALUES ($1, $2, $3, $4, $5, 1, $6, 'ACTIVE')
	`, externalIdentityID, organizationID, principalID, providerID, externalSubjectDigest, "sha256:"+strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
}

func seedOrganization(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: workspaceID, Status: workspace.StatusActive,
		OwnerPrincipalID: ownerID, Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatalf("seed workspace snapshot: %v", err)
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("seed workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("seed workspace canonical snapshot: %v", err)
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{
			sql:  "INSERT INTO public.organization (id, name, status, region, owner_principal_id) VALUES ($1, $2, 'ACTIVE', 'ru', $3)",
			args: []any{organizationID, organizationID, ownerID},
		},
		{
			sql:  "INSERT INTO public.principal (id, organization_id, type, display_name, status) VALUES ($1, $2, 'USER', $1, 'ACTIVE')",
			args: []any{ownerID, organizationID},
		},
		{
			sql: "INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by) VALUES ($1, $2, $3, 'OWNER', 1, $3)",
			args: []any{
				"ora_" + organizationID, organizationID, ownerID,
			},
		},
		{
			sql:  "INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id) VALUES ($1, $2, $1, 'ACTIVE', $3)",
			args: []any{workspaceID, organizationID, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, canonicalBytes},
		},
		{
			sql: "INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ($1, $2, $3, $4, 'OWNER', 1, $4)",
			args: []any{
				"wsm_" + workspaceID, organizationID, workspaceID, ownerID,
			},
		},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", organizationID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit %s: %v", organizationID, err)
	}
}

func openApplicationPool(t *testing.T, ctx context.Context, adminURL string) *pgxpool.Pool {
	t.Helper()
	app, err := pgxpool.New(ctx, applicationURL(t, adminURL))
	if err != nil {
		t.Fatalf("open runtime role: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

func applicationURL(t *testing.T, adminURL string) string {
	t.Helper()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(appRole, appPassword)
	return parsed.String()
}

func openWorkerPool(t *testing.T, ctx context.Context, adminURL string) *pgxpool.Pool {
	t.Helper()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(workerRole, workerPassword)
	worker, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatalf("open worker role: %v", err)
	}
	t.Cleanup(worker.Close)
	return worker
}

func setAccessContext(t *testing.T, ctx context.Context, tx pgx.Tx, organizationID string) {
	setAccessContextForPrincipal(t, ctx, tx, organizationID, "usr_test")
}

func setAccessContextForPrincipal(t *testing.T, ctx context.Context, tx pgx.Tx, organizationID, principalID string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `
		SELECT set_config('app.organization_id', $1, true),
		       set_config('app.principal_id', $2, true),
		       set_config('app.request_id', 'req_test', true)
	`, organizationID, principalID); err != nil {
		t.Fatalf("set transaction access context: %v", err)
	}
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KNOWVAULT_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Fatalf("KNOWVAULT_TEST_POSTGRES_URL is required; start the pinned PostgreSQL integration service before running acceptance tests")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || strings.TrimPrefix(parsed.Path, "/") != testDatabaseName {
		t.Fatalf("integration test only accepts a dedicated %s database", testDatabaseName)
	}
	return dsn
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("REPO_ROOT"); root != "" {
		return root
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(fmt.Errorf("resolve repository root: %w", err))
	}
	return root
}
