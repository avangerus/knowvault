package postgres_test

// ADR-0097 / S1 acceptance proof: a base table (not a DBA-reviewed view) with
// a declared primary key is discovered, registered through the browser's
// discovery-derived surface with one excluded column, synced from a real
// external PostgreSQL table, found by knowvault_search and returned by
// knowvault_read -- and the excluded column never appears in any published
// fragment, index document or search/read result.
//
// The "external" business table and KnowVault's own catalog share the one
// pinned PostgreSQL instance named by KNOWVAULT_TEST_POSTGRES_URL: the table
// lives in its own schema, untouched by resetStage1Database's public/app/
// operator reset. Discovery itself is driven through a connector test double
// fed a hand-built CatalogSnapshot (the same seam TestSourceDiscoveryWorker-
// PersistsEncryptedCatalogResult uses): the SQL that turns a live primary key
// into IDENTITY and everything else into EVIDENCE is proved separately, with
// a real server, by TestDiscoveryCatalogAgainstRealPostgreSQL and its base-
// table siblings in internal/source/postgresqlquery. This test's own job is
// the S1 product path: discovery -> excluded-column registration -> real
// external read -> publish -> search -> read.
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

const tableExclusionPhone = "+1-555-0100-9999"

func TestPostgreSQLTableSourceExcludedColumnNeverPublished(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the base-table exclusion proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())

	const schema = "kv_pgq_table_excl"
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_table_excl" CASCADE;
		CREATE SCHEMA "kv_pgq_table_excl";
		CREATE TABLE "kv_pgq_table_excl"."accounts" (
			account_id uuid PRIMARY KEY,
			display_name text NOT NULL,
			phone text NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("seed external base table: %v", err)
	}
	const accountID = "550e8400-e29b-41d4-a716-446655440090"
	if _, err := external.Exec(ctx,
		`INSERT INTO "kv_pgq_table_excl"."accounts" (account_id, display_name, phone) VALUES ($1,$2,$3)`,
		accountID, "Northwind Trading Co", tableExclusionPhone); err != nil {
		t.Fatalf("seed external row: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_table_excl" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_tbl_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Accounts database", DatabaseIdentity: "accounts-demo", LineageID: "accounts-primary",
			CredentialReference: testCredentialRef,
		})
	if err != nil {
		t.Fatalf("bootstrap table connection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, bootstrap.ConnectionID)

	requested, err := service.RequestDiscovery(ctx, regOwnerAccess("req_tbl_discover"), registration.DiscoveryRequest{
		ConnectionID: bootstrap.ConnectionID, IdempotencyKey: "table-exclusion-discovery",
		Limits: postgresqlquery.DiscoveryLimits{
			MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
			StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("enqueue table discovery: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimedDiscovery, found, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !found {
		t.Fatalf("claim table discovery: found=%v err=%v", found, err)
	}
	if claimedDiscovery.ID != requested.RequestID {
		t.Fatalf("claimed job=%q, want discovery request=%q", claimedDiscovery.ID, requested.RequestID)
	}

	// The declared table shape mirrors the real external table exactly:
	// account_id is the primary key, display_name and phone are ordinary
	// columns. Discovery turns the key into IDENTITY and both others into
	// EVIDENCE; excluding phone at registration is what this test proves.
	tableColumns := []postgresqlquery.DiscoveredColumn{
		{Ordinal: 1, Name: "account_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64, PrimaryKey: true},
		{Ordinal: 2, Name: "display_name", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1024},
		{Ordinal: 3, Name: "phone", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 256},
	}
	fullTableProjection := postgresqlquery.Projection{
		ConnectionID: bootstrap.ConnectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("e", 64),
		LineageID: "projection-lineage:" + strings.Repeat("f", 64), Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("1", 64), SchemaName: schema, RelationName: "accounts",
		RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
			{Ordinal: 3, Name: "phone", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256},
		},
	}
	connector := &sourceDiscoveryConnector{snapshot: postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16385, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("9", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: bootstrap.ConnectionID, DatabaseOID: 16385, DatabaseName: "source_db",
			RelationOID: 40001, SchemaName: schema, RelationName: "accounts", RelationKind: "TABLE",
			ApproxRowCount: 1, Columns: tableColumns,
			Status: postgresqlquery.DiscoveryPrepared, Projection: &fullTableProjection,
		}},
	}}
	generatedIDs := map[string]string{"sdr": mustID(t, "sdr"), "artifact": mustID(t, "artifact")}
	discoveryHandler, err := sourcediscovery.NewHandler(workerStore, workerQueue, mustRepo(t), codec, connector,
		regWorkerID, 60, func(prefix string) (string, error) { return generatedIDs[prefix], nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := discoveryHandler.Handle(ctx, database.AccessContext{
		OrganizationID: regOrg, PrincipalID: "usr_worker", RequestID: claimedDiscovery.ID,
	}, claimedDiscovery); err != nil {
		t.Fatalf("handle table discovery: %v (code=%s)", err, sourcediscovery.CodeOf(err))
	}

	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(ctx, regOwnerAccess("req_tbl_read_discovery"), requested.RequestID)
	if err != nil {
		t.Fatalf("read table discovery: %v", err)
	}
	if read.RequestStatus != "SUCCEEDED" || read.PreparedViewCount != 1 || len(read.Views) != 1 {
		t.Fatalf("table discovery result = %#v", read)
	}
	view := read.Views[0]
	if view.RelationKind != "TABLE" || view.Status != postgresqlquery.DiscoveryPrepared {
		t.Fatalf("discovered table view = %#v", view)
	}
	var phoneOrdinal int
	for _, column := range view.Columns {
		switch column.Name {
		case "phone":
			phoneOrdinal = column.Ordinal
		case "account_id":
			if !column.PrimaryKey {
				t.Fatalf("account_id not reported as primary key: %#v", column)
			}
		}
	}
	if phoneOrdinal == 0 {
		t.Fatalf("phone column not found in discovery result: %#v", view.Columns)
	}

	selected, err := reader.Select(ctx, regOwnerAccess("req_tbl_select"), requested.RequestID, view.Selector)
	if err != nil {
		t.Fatalf("select table view: %v", err)
	}

	registered, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_tbl_register"), selected, []int{phoneOrdinal})
	if err != nil {
		t.Fatalf("register table with excluded column: %v (code=%s)", err, registration.CodeOf(err))
	}
	// NarrowProjection is a pure function of its inputs, so recomputing it
	// here reproduces exactly the projection RegisterDiscoveredView narrowed
	// and persisted -- used below to drive the real external read the same
	// way the worker would. ScopeConfigHash (asserted in seedRegistration-
	// WorkspaceBinding below) seals the whole scope config envelope, not the
	// bare projection contract hash, so the two are not expected to match.
	narrowedProjection, err := postgresqlquery.NarrowProjection(selected.Projection, map[int]bool{phoneOrdinal: true})
	if err != nil {
		t.Fatalf("recompute narrowed projection: %v", err)
	}
	for _, column := range narrowedProjection.Columns {
		if column.Name == "phone" {
			t.Fatalf("narrowed projection still carries the excluded column: %#v", narrowedProjection.Columns)
		}
	}

	workspaceBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, mustID(t, "binding"))
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, workspaceBinding, "tbl-excl-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(workspaceBinding, workspaceBinding.ownerID, "req_tbl_confirm"), confirmRuntimeRequest(workspaceBinding, grant, "tbl-excl-confirm")); err != nil {
		t.Fatalf("confirm table workspace source: %v", err)
	}

	// Search must be activated before publication so the ingestion handler's
	// outbox events have a live profile to apply against.
	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatalf("table search repository: %v", err)
	}
	profile := s3EmbeddingProfile(t)
	embeddingClient, err := embedding.New(profile, s3TrustRoots(), nil, &http.Client{Transport: s3EmbeddingTransport{t: t}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("table embedding client: %v", err)
	}
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-registration-v1", OrganizationID: regOrg,
		Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(),
		VectorProfileHash: profile.ProfileHash, VectorDimension: s3Dimension,
		HTTPClient: &http.Client{Transport: index, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("table search client: %v", err)
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
		t.Fatalf("activate table search profile: %v", err)
	}

	ingestionHandler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New).
		WithSearchRepository(searchRepository)

	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatal(err)
	}
	syncJobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_tbl_sync_enqueue"), jobs.Spec{
		JobID: syncJobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "tbl-excl-sync", Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue table sync: %v", err)
	}
	syncClaimed, ok, err := workerQueue.Claim(ctx, workerAccessContext, regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim table sync: %v ok=%v", err, ok)
	}
	if syncClaimed.ID != syncJobID {
		t.Fatalf("claimed sync job=%q, want=%q", syncClaimed.ID, syncJobID)
	}
	publishRunID := mustID(t, "syncrun")
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`,
			registered.SourceScopeID, int64(1), syncClaimed.ID, regWorkerID, syncClaimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`,
			registered.SourceScopeID, int64(1), narrowedProjection.ContractHash); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`,
			regOrg, publishRunID, registered.SourceScopeID, syncClaimed.ID)
		return err
	}); err != nil {
		t.Fatalf("begin table sync publication: %v", err)
	}

	// The generated SELECT itself must omit the excluded column: this is the
	// SQL boundary, not merely a post-hoc filter.
	snapshot, err := postgresqlquery.ReadProjection(ctx, external, narrowedProjection, postgresqlquery.DefaultLimits())
	if err != nil {
		t.Fatalf("read narrowed external table: %v", err)
	}
	if snapshot.RowCount != 1 {
		t.Fatalf("narrowed table row count=%d, want 1", snapshot.RowCount)
	}
	for _, row := range snapshot.Rows {
		if len(row.Values) != 2 {
			t.Fatalf("narrowed row carries %d values, want 2 (identity+evidence only, no phone): %#v", len(row.Values), row.Values)
		}
		for _, value := range row.Values {
			if text, ok := value.Value.(string); ok && strings.Contains(text, tableExclusionPhone) {
				t.Fatalf("excluded phone value present in the narrowed read snapshot: %#v", row.Values)
			}
		}
	}

	publishResult, err := ingestionHandler.PublishPostgreSQLSnapshot(ctx, workerAccessContext, ingestion.PostgreSQLSnapshotRequest{
		ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: publishRunID,
		Projection: narrowedProjection, Snapshot: snapshot, Claimed: syncClaimed,
	})
	if err != nil {
		t.Fatalf("publish narrowed table snapshot: %v (code=%s)", err, ingestion.CodeOf(err))
	}
	if publishResult.ObjectsSeen != 1 || publishResult.ObjectsIngested != 1 || publishResult.VersionsCreated != 1 || publishResult.EvidencePublished != 1 {
		t.Fatalf("publish counters=%#v, want exactly 1 row and 1 evidence fragment (display_name only, phone excluded)", publishResult)
	}
	if err := workerQueue.Complete(ctx, workerAccessContext, syncClaimed.ID, regWorkerID, syncClaimed.LeaseEpoch); err != nil {
		t.Fatalf("complete table sync: %v", err)
	}

	applier, err := search.NewApplierWithEmbedding(workerStore, searchRepository, codec, searchClient, embeddingClient)
	if err != nil {
		t.Fatalf("table search applier: %v", err)
	}
	applied, err := applier.Drain(ctx, workerAccessContext, 10)
	if err != nil || applied != 1 {
		t.Fatalf("table search applier drained %d events: %v", applied, err)
	}

	index.mutex.Lock()
	for _, document := range index.documents {
		for field, value := range document {
			if text, ok := value.(string); ok && strings.Contains(text, tableExclusionPhone) {
				t.Fatalf("excluded phone value leaked into search index field %q: %q", field, text)
			}
			if values, ok := value.([]any); ok {
				for _, item := range values {
					if text, ok := item.(string); ok && strings.Contains(text, tableExclusionPhone) {
						t.Fatalf("excluded phone value leaked into search index field %q: %q", field, text)
					}
				}
			}
		}
	}
	index.mutex.Unlock()

	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatalf("table evidence viewer: %v", err)
	}
	access := regOwnerAccess("req_tbl_search")
	executor, err := retrieval.NewExecutorWithGraph(searchClient, viewer, appStore, knowledgegraph.NewRepository())
	if err != nil {
		t.Fatalf("table search executor: %v", err)
	}
	page, err := executor.SearchWorkspace(ctx, access, workspaceBinding.workspaceID, "Northwind", retrieval.WorkspaceSearchOptions{
		Mode: retrieval.SearchModeLexical, Limit: 10,
	})
	if err != nil {
		t.Fatalf("table SearchWorkspace: %v", err)
	}
	if page.Partial || len(page.Hits) != 1 {
		t.Fatalf("table SearchWorkspace page=%#v, want exactly one hit", page)
	}
	hit := page.Hits[0]
	text := string(hit.Fragment.Text)
	if !strings.Contains(text, "display_name") || !strings.Contains(text, "Northwind Trading Co") {
		t.Fatalf("table search hit text=%q, want the display_name cell", text)
	}
	if strings.Contains(text, tableExclusionPhone) || strings.Contains(text, "phone") {
		t.Fatalf("table search hit exposed the excluded phone column: %q", text)
	}
	if !strings.HasPrefix(hit.Fragment.SourcePath, "postgresql-query/"+narrowedProjection.LineageID+"/") {
		t.Fatalf("table search hit source path=%q, want the narrowed lineage prefix", hit.Fragment.SourcePath)
	}

	readback, err := viewer.Read(ctx, access, workspaceBinding.workspaceID, hit.Fragment.FragmentID)
	if err != nil {
		t.Fatalf("read table search address %q: %v", hit.Fragment.FragmentID, err)
	}
	if string(readback.Text) != text || readback.SourcePath != hit.Fragment.SourcePath || readback.SourceObjectID != hit.Fragment.SourceObjectID {
		t.Fatalf("table readback=%#v, want search hit=%#v", readback, hit.Fragment)
	}
	if strings.Contains(string(readback.Text), tableExclusionPhone) {
		t.Fatalf("excluded phone value leaked into evidence read: %q", readback.Text)
	}
}
