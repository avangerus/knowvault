package postgres_test

// S3 card 4's mode-switch proof: a table first registered as an ordinary
// indexed source is re-registered "only for SQL queries (not indexed)" — the
// same repeat-discovery flow an administrator uses to change the excluded
// columns today — and the superseded indexed registration's fragments leave
// search and readback.
//
// The indexed registration publishes a real row through the production
// publication path and is found by knowvault_search; after the query-only
// registration the same search returns nothing, the old scope's objects are
// non-queryable and its workspace membership is terminally REMOVED, while the
// new query-only scope itself has no fragments.

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/search"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

func TestPostgreSQLQueryOnlyModeSwitchRemovesFragments(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the query-only mode-switch proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())

	const schema = "kv_s34_mode_switch"
	if _, err := external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_s34_mode_switch" CASCADE;
		CREATE SCHEMA "kv_s34_mode_switch";
		CREATE TABLE "kv_s34_mode_switch"."accounts" (
			account_id uuid PRIMARY KEY,
			display_name text NOT NULL
		);
		INSERT INTO "kv_s34_mode_switch"."accounts" (account_id, display_name)
		VALUES ('550e8400-e29b-41d4-a716-4466554400b1', 'Northwind Trading Co');
	`); err != nil {
		t.Fatalf("seed external base table: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_s34_mode_switch" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_ms_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Mode switch database", DatabaseIdentity: "mode-switch-demo", LineageID: "mode-switch-primary",
			CredentialReference: testCredentialRef,
		})
	if err != nil {
		t.Fatalf("bootstrap mode-switch connection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, bootstrap.ConnectionID)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	tableColumns := []postgresqlquery.DiscoveredColumn{
		{Ordinal: 1, Name: "account_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64, PrimaryKey: true},
		{Ordinal: 2, Name: "display_name", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1024},
	}
	fullProjection := postgresqlquery.Projection{
		ConnectionID: bootstrap.ConnectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("e", 64),
		LineageID: "projection-lineage:" + strings.Repeat("f", 64), Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("1", 64), SchemaName: schema, RelationName: "accounts",
		RelationKind: "TABLE", EmptySnapshotPolicy: "AUTHORITATIVE",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
		},
	}
	snapshot := postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16387, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("9", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: bootstrap.ConnectionID, DatabaseOID: 16387, DatabaseName: "source_db",
			RelationOID: 42001, SchemaName: schema, RelationName: "accounts", RelationKind: "TABLE",
			ApproxRowCount: 1, Columns: tableColumns,
			Status: postgresqlquery.DiscoveryPrepared, Projection: &fullProjection,
		}},
	}
	connector := &sourceDiscoveryConnector{snapshot: snapshot}
	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Two independent discoveries of the same relation: one indexed
	// registration, then the mode switch to query-only.
	selectedViews := make([]sourcediscovery.SelectedView, 0, 2)
	for index, key := range []string{"indexed", "query-only"} {
		requested, err := service.RequestDiscovery(ctx, regOwnerAccess("req_ms_discover_"+key), registration.DiscoveryRequest{
			ConnectionID: bootstrap.ConnectionID, IdempotencyKey: "mode-switch-discovery-" + key,
			Limits: postgresqlquery.DiscoveryLimits{
				MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
				StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
			},
		})
		if err != nil {
			t.Fatalf("enqueue discovery %d: %v", index, err)
		}
		claimed, found, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
		if err != nil || !found || claimed.ID != requested.RequestID {
			t.Fatalf("claim discovery %d: found=%v err=%v", index, found, err)
		}
		generatedIDs := map[string]string{"sdr": mustID(t, "sdr"), "artifact": mustID(t, "artifact")}
		handler, err := sourcediscovery.NewHandler(workerStore, workerQueue, mustRepo(t), codec, connector,
			regWorkerID, 60, func(prefix string) (string, error) { return generatedIDs[prefix], nil })
		if err != nil {
			t.Fatal(err)
		}
		if err := handler.Handle(ctx, database.AccessContext{
			OrganizationID: regOrg, PrincipalID: "usr_worker", RequestID: claimed.ID,
		}, claimed); err != nil {
			t.Fatalf("handle discovery %d: %v", index, err)
		}
		read, err := reader.Get(ctx, regOwnerAccess("req_ms_read_"+key), requested.RequestID)
		if err != nil || len(read.Views) != 1 {
			t.Fatalf("read discovery %d: views=%d err=%v", index, len(read.Views), err)
		}
		selected, err := reader.Select(ctx, regOwnerAccess("req_ms_select_"+key), requested.RequestID, read.Views[0].Selector)
		if err != nil {
			t.Fatalf("select discovery %d: %v", index, err)
		}
		selectedViews = append(selectedViews, selected)
	}

	indexedSelected := selectedViews[0]
	indexed, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_ms_register_indexed"), indexedSelected, nil, "")
	if err != nil {
		t.Fatalf("register indexed table: %v (code=%s)", err, registration.CodeOf(err))
	}
	workspaceBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, indexed.SourceScopeID, indexed.ScopeConfigHash, mustID(t, "binding"))
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, workspaceBinding, "ms-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(workspaceBinding, workspaceBinding.ownerID, "req_ms_confirm"),
		confirmRuntimeRequest(workspaceBinding, grant, "ms-confirm")); err != nil {
		t.Fatalf("confirm indexed workspace source: %v", err)
	}

	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	profile := s3EmbeddingProfile(t)
	embeddingClient, err := embedding.New(profile, s3TrustRoots(), nil, &http.Client{Transport: s3EmbeddingTransport{t: t}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-registration-v1", OrganizationID: regOrg,
		Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(),
		VectorProfileHash: profile.ProfileHash, VectorDimension: s3Dimension,
		HTTPClient: &http.Client{Transport: index, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	workerAccessContext := workerAccess(t, regOrg)
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, tx database.Transaction) error {
		if err := searchRepository.EnsureMountedLexicalProfile(txCtx, tx, workerAccessContext, 1, 1); err != nil {
			return err
		}
		revision, err := searchRepository.StageRevision(txCtx, tx, workerAccessContext, profile.ID, profile.ProfileHash, 1, 1)
		if err != nil {
			return err
		}
		return searchRepository.ActivateRevision(txCtx, tx, workerAccessContext, revision.ActivationRevision, time.Now().UTC())
	}); err != nil {
		t.Fatalf("activate mode-switch search profile: %v", err)
	}
	ingestionHandler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New).
		WithSearchRepository(searchRepository)

	// Publish the indexed registration exactly like the worker: begin the
	// sync, activate the projection, read the real external table and publish.
	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatal(err)
	}
	syncJobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_ms_sync_enqueue"), jobs.Spec{
		JobID: syncJobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": indexed.SourceScopeID},
		IdempotencyKey: "ms-sync", Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue indexed sync: %v", err)
	}
	syncClaimed, ok, err := workerQueue.Claim(ctx, workerAccessContext, regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim indexed sync: %v ok=%v", err, ok)
	}
	publishRunID := mustID(t, "syncrun")
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`,
			indexed.SourceScopeID, int64(1), syncClaimed.ID, regWorkerID, syncClaimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`,
			indexed.SourceScopeID, int64(1), indexedSelected.Projection.ContractHash); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`,
			regOrg, publishRunID, indexed.SourceScopeID, syncClaimed.ID)
		return err
	}); err != nil {
		t.Fatalf("begin indexed sync publication: %v", err)
	}
	externalSnapshot, err := postgresqlquery.ReadProjection(ctx, external, indexedSelected.Projection, postgresqlquery.DefaultLimits())
	if err != nil {
		t.Fatalf("read indexed external table: %v", err)
	}
	if _, err := ingestionHandler.PublishPostgreSQLSnapshot(ctx, workerAccessContext, ingestion.PostgreSQLSnapshotRequest{
		ScopeID: indexed.SourceScopeID, ScopeRevision: 1, SyncRunID: publishRunID,
		Projection: indexedSelected.Projection, Snapshot: externalSnapshot, Claimed: syncClaimed,
	}); err != nil {
		t.Fatalf("publish indexed snapshot: %v (code=%s)", err, ingestion.CodeOf(err))
	}
	if err := workerQueue.Complete(ctx, workerAccessContext, syncClaimed.ID, regWorkerID, syncClaimed.LeaseEpoch); err != nil {
		t.Fatalf("complete indexed sync: %v", err)
	}
	applier, err := search.NewApplierWithEmbedding(workerStore, searchRepository, codec, searchClient, embeddingClient)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := applier.Drain(ctx, workerAccessContext, 10); err != nil || applied != 1 {
		t.Fatalf("indexed search applier drained %d events: %v", applied, err)
	}

	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := retrieval.NewExecutorWithGraph(searchClient, viewer, appStore, knowledgegraph.NewRepository())
	if err != nil {
		t.Fatal(err)
	}
	searchAccess := regOwnerAccess("req_ms_search_indexed")
	before, err := executor.SearchWorkspace(ctx, searchAccess, workspaceBinding.workspaceID, "Northwind", retrieval.WorkspaceSearchOptions{
		Mode: retrieval.SearchModeLexical, Limit: 10,
	})
	if err != nil {
		t.Fatalf("indexed SearchWorkspace: %v", err)
	}
	if before.Partial || len(before.Hits) != 1 {
		t.Fatalf("indexed search page=%#v, want exactly one hit before the mode switch", before)
	}

	// The mode switch: the same relation is re-registered query-only.
	queryOnlySelected := selectedViews[1]
	queryOnly, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_ms_register_query_only"), queryOnlySelected, nil, postgresqlquery.ProjectionModeQueryOnly)
	if err != nil {
		t.Fatalf("register query-only table: %v (code=%s)", err, registration.CodeOf(err))
	}
	if queryOnly.SourceScopeID == indexed.SourceScopeID {
		t.Fatal("the mode switch reused the indexed scope instead of minting a new query-only lineage")
	}

	t.Run("the superseded indexed fragments leave search", func(t *testing.T) {
		after, err := executor.SearchWorkspace(ctx, regAccessAt("req_ms_search_query_only", searchAccess), workspaceBinding.workspaceID, "Northwind", retrieval.WorkspaceSearchOptions{
			Mode: retrieval.SearchModeLexical, Limit: 10,
		})
		if err != nil {
			t.Fatalf("query-only SearchWorkspace: %v", err)
		}
		if len(after.Hits) != 0 {
			t.Fatalf("search still returned %d superseded hit(s): %#v", len(after.Hits), after.Hits)
		}
		var queryableObjects, activeMemberships int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM public.source_object
			WHERE organization_id=$1 AND connection_id=$2 AND queryable`, regOrg, bootstrap.ConnectionID).Scan(&queryableObjects); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM public.source_object_scope
			WHERE organization_id=$1 AND source_scope_id=$2 AND membership_state='ACTIVE'`, regOrg, indexed.SourceScopeID).Scan(&activeMemberships); err != nil {
			t.Fatal(err)
		}
		if queryableObjects != 0 || activeMemberships != 0 {
			t.Fatalf("superseded registration still queryable objects=%d active memberships=%d", queryableObjects, activeMemberships)
		}
		var queryOnlyStored bool
		if err := admin.QueryRow(ctx, `SELECT query_only FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`,
			regOrg, queryOnly.SourceScopeID).Scan(&queryOnlyStored); err != nil {
			t.Fatal(err)
		}
		if !queryOnlyStored {
			t.Fatal("the new scope is not stored as query-only")
		}
		var newScopeMemberships int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope WHERE organization_id=$1 AND source_scope_id=$2`,
			regOrg, queryOnly.SourceScopeID).Scan(&newScopeMemberships); err != nil {
			t.Fatal(err)
		}
		if newScopeMemberships != 0 {
			t.Fatalf("the query-only scope published %d memberships, want zero", newScopeMemberships)
		}
	})
}

// regAccessAt clones an access context with a fresh request id so repeated
// reads are separately audited in the tests.
func regAccessAt(requestID string, base database.AccessContext) database.AccessContext {
	base.RequestID = requestID
	return base
}
