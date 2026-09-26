package postgres_test

// S3 card 4's database-side acceptance proof for the query-only ("only for SQL
// queries, not indexed") registration mode. One base table is discovered and
// registered through the production discovery -> registration path in
// QUERY_ONLY mode with one column excluded, bound to the workspace with the
// ordinary confirmation flow, and then:
//
//   - knowvault_source_schema lists it with query_only = true and without the
//     excluded column;
//   - the knowvault_source_sql relation scope contains exactly the projected
//     columns, so the excluded column cannot be named;
//   - the sync worker completes the activation without opening the external
//     relation (the connector probe is never called) and publishes no
//     Evidence fragment and no search document.
//
// The same acceptance proof for a real partitioned parent table (registered as
// one relation, queried by a least-privilege role, partition child never
// listed) lives in internal/source/postgresqlquery's
// query_only_integration_test.go against the real server.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// queryOnlyConnectorProbe is the live external connector double. A query-only
// sync must never call it: any call fails the test through the returned error
// and is recorded so the assertion can name it.
type queryOnlyConnectorProbe struct {
	calls int
}

func (probe *queryOnlyConnectorProbe) ReadProjection(context.Context, string, string,
	postgresqlquery.Projection, postgresqlquery.Limits) (postgresqlquery.Snapshot, error) {
	probe.calls++
	return postgresqlquery.Snapshot{}, errors.New("a query-only sync must not read the external relation")
}

func TestPostgreSQLQueryOnlyRegistrationPublishesNothing(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_qo_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Trips database", DatabaseIdentity: "trips-demo", LineageID: "trips-primary",
			CredentialReference: testCredentialRef,
		})
	if err != nil {
		t.Fatalf("bootstrap query-only connection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, bootstrap.ConnectionID)

	requested, err := service.RequestDiscovery(ctx, regOwnerAccess("req_qo_discover"), registration.DiscoveryRequest{
		ConnectionID: bootstrap.ConnectionID, IdempotencyKey: "query-only-discovery",
		Limits: postgresqlquery.DiscoveryLimits{
			MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
			StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("enqueue query-only discovery: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimedDiscovery, found, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !found {
		t.Fatalf("claim query-only discovery: found=%v err=%v", found, err)
	}
	if claimedDiscovery.ID != requested.RequestID {
		t.Fatalf("claimed job=%q, want discovery request=%q", claimedDiscovery.ID, requested.RequestID)
	}

	const schemaName = "kv_s34_query_only"
	tableColumns := []postgresqlquery.DiscoveredColumn{
		{Ordinal: 1, Name: "trip_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64, PrimaryKey: true},
		{Ordinal: 2, Name: "carrier", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1024},
		{Ordinal: 3, Name: "driver_phone", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 256},
	}
	fullProjection := postgresqlquery.Projection{
		ConnectionID: bootstrap.ConnectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("e", 64),
		LineageID: "projection-lineage:" + strings.Repeat("f", 64), Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("1", 64), SchemaName: schemaName, RelationName: "trips",
		RelationKind: "PARTITIONED_TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "trip_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "carrier", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024},
			{Ordinal: 3, Name: "driver_phone", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256},
		},
	}
	connector := &sourceDiscoveryConnector{snapshot: postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16386, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("9", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: bootstrap.ConnectionID, DatabaseOID: 16386, DatabaseName: "source_db",
			RelationOID: 41001, SchemaName: schemaName, RelationName: "trips", RelationKind: "PARTITIONED_TABLE",
			ApproxRowCount: 25_000_000, Columns: tableColumns,
			Status: postgresqlquery.DiscoveryPrepared, Projection: &fullProjection,
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
		t.Fatalf("handle query-only discovery: %v (code=%s)", err, sourcediscovery.CodeOf(err))
	}

	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(ctx, regOwnerAccess("req_qo_read_discovery"), requested.RequestID)
	if err != nil {
		t.Fatalf("read query-only discovery: %v", err)
	}
	if len(read.Views) != 1 {
		t.Fatalf("query-only discovery views = %d, want 1", len(read.Views))
	}
	view := read.Views[0]
	var phoneOrdinal int
	for _, column := range view.Columns {
		if column.Name == "driver_phone" {
			phoneOrdinal = column.Ordinal
		}
	}
	if phoneOrdinal == 0 {
		t.Fatalf("driver_phone column not discovered: %#v", view.Columns)
	}
	selected, err := reader.Select(ctx, regOwnerAccess("req_qo_select"), requested.RequestID, view.Selector)
	if err != nil {
		t.Fatalf("select query-only view: %v", err)
	}

	registered, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_qo_register"), selected, []int{phoneOrdinal}, postgresqlquery.ProjectionModeQueryOnly)
	if err != nil {
		t.Fatalf("register query-only table: %v (code=%s)", err, registration.CodeOf(err))
	}

	// The mode is part of the persisted immutable contract: query_only is set
	// and the mode-only lineage differs from the discovered indexed one.
	expectedProjection, err := postgresqlquery.WithQueryOnly(
		mustNarrow(t, selected.Projection, phoneOrdinal), true)
	if err != nil {
		t.Fatalf("derive expected query-only projection: %v", err)
	}
	var storedQueryOnly bool
	var storedLineage, storedContract string
	if err := admin.QueryRow(ctx, `
		SELECT query_only, lineage_id, contract_hash
		FROM public.postgresql_query_projection
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`,
		regOrg, registered.SourceScopeID).Scan(&storedQueryOnly, &storedLineage, &storedContract); err != nil {
		t.Fatalf("read stored query-only projection: %v", err)
	}
	if !storedQueryOnly || storedLineage != expectedProjection.LineageID || storedContract != expectedProjection.ContractHash {
		t.Fatalf("stored projection query_only=%v lineage=%q contract=%q, want query-only %q/%q",
			storedQueryOnly, storedLineage, storedContract, expectedProjection.LineageID, expectedProjection.ContractHash)
	}
	if storedLineage == selected.Projection.LineageID {
		t.Fatal("the query-only registration reused the indexed lineage")
	}
	if _, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_qo_replay"), selected, []int{phoneOrdinal}, "NOT_A_MODE"); registration.CodeOf(err) != registration.CodeRequestInvalid {
		t.Fatalf("an unknown mode code=%s, want %s", registration.CodeOf(err), registration.CodeRequestInvalid)
	}

	workspaceBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, mustID(t, "binding"))

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	access := regOwnerAccess("req_qo_schema_tool")

	t.Run("the schema tool lists the relation as query-only without the excluded column", func(t *testing.T) {
		result, err := repository.SourceSchema(ctx, access, regWorkspace, bootstrap.ConnectionID, "", 0, 50)
		if err != nil {
			t.Fatalf("SourceSchema: %v", err)
		}
		if len(result.Tables) != 1 {
			t.Fatalf("tables=%#v, want one", result.Tables)
		}
		table := result.Tables[0]
		if !table.QueryOnly {
			t.Fatalf("table query_only=false, want true: %#v", table)
		}
		if table.Schema != schemaName || table.Name != "trips" || table.Kind != "PARTITIONED_TABLE" || table.RowEstimate != 25_000_000 {
			t.Fatalf("table=%#v", table)
		}
		for _, column := range table.Columns {
			if column.Name == "driver_phone" {
				t.Fatalf("the excluded column was listed: %#v", table.Columns)
			}
		}
	})

	t.Run("the SQL scope carries the projected columns and not the excluded one", func(t *testing.T) {
		target, err := repository.SourceQuery(ctx, access, regWorkspace, bootstrap.ConnectionID)
		if err != nil {
			t.Fatalf("SourceQuery: %v", err)
		}
		if len(target.Relations) != 1 {
			t.Fatalf("relations=%#v, want one", target.Relations)
		}
		relation := target.Relations[0]
		if !relation.QueryOnly || relation.Schema != schemaName || relation.Table != "trips" {
			t.Fatalf("relation=%#v, want the query-only relation", relation)
		}
		columns := map[string]bool{}
		for _, column := range relation.Columns {
			columns[column] = true
		}
		if !columns["trip_id"] || !columns["carrier"] {
			t.Fatalf("projected columns missing from the SQL scope: %#v", relation.Columns)
		}
		if columns["driver_phone"] {
			t.Fatalf("the excluded column is nameable by SQL: %#v", relation.Columns)
		}
	})

	// The ordinary confirmation flow applies unchanged to a query-only table.
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, workspaceBinding, "qo-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(workspaceBinding, workspaceBinding.ownerID, "req_qo_confirm"),
		confirmRuntimeRequest(workspaceBinding, grant, "qo-confirm")); err != nil {
		t.Fatalf("confirm query-only workspace source: %v", err)
	}

	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatal(err)
	}
	syncJobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_qo_sync_enqueue"), jobs.Spec{
		JobID: syncJobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "qo-sync", Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue query-only sync: %v", err)
	}
	workerAccessContext := workerAccess(t, regOrg)
	syncClaimed, ok, err := workerQueue.Claim(ctx, workerAccessContext, regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim query-only sync: %v ok=%v", err, ok)
	}
	if syncClaimed.ID != syncJobID {
		t.Fatalf("claimed sync job=%q, want=%q", syncClaimed.ID, syncJobID)
	}
	probe := &queryOnlyConnectorProbe{}
	ingestionHandler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New).
		WithPostgreSQLQueryConnector(probe)
	if err := ingestionHandler.HandlePostgreSQLQuery(ctx, workerAccessContext, syncClaimed); err != nil {
		t.Fatalf("query-only sync: %v (code=%s)", err, ingestion.CodeOf(err))
	}
	if probe.calls != 0 {
		t.Fatalf("the sync worker read the external relation %d time(s); a query-only sync must never copy rows", probe.calls)
	}

	t.Run("the query-only sync published no fragments and advanced activation", func(t *testing.T) {
		var objects, fragments int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1 AND connection_id=$2`,
			regOrg, bootstrap.ConnectionID).Scan(&objects); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope WHERE organization_id=$1 AND source_scope_id=$2`,
			regOrg, registered.SourceScopeID).Scan(&fragments); err != nil {
			t.Fatal(err)
		}
		if objects != 0 || fragments != 0 {
			t.Fatalf("query-only sync published objects=%d memberships=%d, want zero", objects, fragments)
		}
		var status string
		var seen int64
		var complete bool
		if err := admin.QueryRow(ctx, `SELECT status, objects_seen, coverage_complete FROM public.sync_run WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`,
			regOrg, registered.SourceScopeID).Scan(&status, &seen, &complete); err != nil {
			t.Fatal(err)
		}
		if status != "SUCCEEDED" || seen != 0 || !complete {
			t.Fatalf("query-only sync_run status=%q seen=%d complete=%v, want SUCCEEDED/0/true", status, seen, complete)
		}
		var activation string
		if err := admin.QueryRow(ctx, `SELECT status FROM public.source_scope_activation WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`,
			regOrg, registered.SourceScopeID).Scan(&activation); err != nil {
			t.Fatal(err)
		}
		if activation != "READY" {
			t.Fatalf("query-only activation status=%q, want READY", activation)
		}
	})
}

func mustNarrow(t *testing.T, projection postgresqlquery.Projection, excludedOrdinal int) postgresqlquery.Projection {
	t.Helper()
	narrowed, err := postgresqlquery.NarrowProjection(projection, map[int]bool{excludedOrdinal: true})
	if err != nil {
		t.Fatalf("narrow projection: %v", err)
	}
	return narrowed
}
