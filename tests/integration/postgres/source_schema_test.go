package postgres_test

// S3 card 1 (ADR-0097) database-side acceptance proof for
// knowvault_source_schema: one base table is discovered and registered through
// the production discovery->registration path with one column excluded, bound
// to the workspace, and then read back through the real
// workspacerepository.Store.SourceSchema/ListSourceSchemas boundary against
// real PostgreSQL (KNOWVAULT_TEST_POSTGRES_URL, migration 000115 included).
//
// It proves the stored projection and its persisted discovery catalog answer
// the tool with no external database call: the native type names, the primary
// key, the pg_class row estimate, the relation/column comments, and -- the
// security invariant -- that the excluded column is simply absent. It also
// proves a source that is not enabled in the caller's workspace is the same
// content-free not-found the other source metadata reads return, and that the
// database itself refuses a catalog row naming a column outside the
// projection.

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestPostgreSQLSourceSchemaAnswersFromStoredProjection(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_schema_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Schema database", DatabaseIdentity: "schema-demo", LineageID: "schema-primary",
			CredentialReference: testCredentialRef,
		})
	if err != nil {
		t.Fatalf("bootstrap schema connection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, bootstrap.ConnectionID)

	requested, err := service.RequestDiscovery(ctx, regOwnerAccess("req_schema_discover"), registration.DiscoveryRequest{
		ConnectionID: bootstrap.ConnectionID, IdempotencyKey: "schema-discovery",
		Limits: postgresqlquery.DiscoveryLimits{
			MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
			StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("enqueue schema discovery: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimed, found, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !found {
		t.Fatalf("claim schema discovery: found=%v err=%v", found, err)
	}
	if claimed.ID != requested.RequestID {
		t.Fatalf("claimed job=%q, want discovery request=%q", claimed.ID, requested.RequestID)
	}

	const schemaName = "kv_source_schema"
	const rowEstimate = 17030
	tableColumns := []postgresqlquery.DiscoveredColumn{
		{Ordinal: 1, Name: "account_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64, PrimaryKey: true, Comment: "surrogate key"},
		{Ordinal: 2, Name: "display_name", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Nullable: true, MaxBytes: 1024, Comment: "customer name"},
		{Ordinal: 3, Name: "phone", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 256, Comment: "never published"},
	}
	fullProjection := postgresqlquery.Projection{
		ConnectionID: bootstrap.ConnectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("e", 64),
		LineageID: "projection-lineage:" + strings.Repeat("f", 64), Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("1", 64), SchemaName: schemaName, RelationName: "accounts",
		RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
			{Ordinal: 3, Name: "phone", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256},
		},
	}
	connector := &sourceDiscoveryConnector{snapshot: postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16385, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("9", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: bootstrap.ConnectionID, DatabaseOID: 16385, DatabaseName: "source_db",
			RelationOID: 40002, SchemaName: schemaName, RelationName: "accounts", RelationKind: "TABLE",
			Comment: "registered customer accounts", ApproxRowCount: rowEstimate, Columns: tableColumns,
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
		OrganizationID: regOrg, PrincipalID: "usr_worker", RequestID: claimed.ID,
	}, claimed); err != nil {
		t.Fatalf("handle schema discovery: %v (code=%s)", err, sourcediscovery.CodeOf(err))
	}

	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(ctx, regOwnerAccess("req_schema_read_discovery"), requested.RequestID)
	if err != nil {
		t.Fatalf("read schema discovery: %v", err)
	}
	if len(read.Views) != 1 {
		t.Fatalf("schema discovery views = %d, want 1", len(read.Views))
	}
	view := read.Views[0]
	phoneOrdinal := 0
	for _, column := range view.Columns {
		if column.Name == "phone" {
			phoneOrdinal = column.Ordinal
			if column.Comment != "never published" {
				t.Fatalf("discovery lost the phone comment: %#v", column)
			}
		}
	}
	if phoneOrdinal == 0 {
		t.Fatalf("phone column not discovered: %#v", view.Columns)
	}
	selected, err := reader.Select(ctx, regOwnerAccess("req_schema_select"), requested.RequestID, view.Selector)
	if err != nil {
		t.Fatalf("select schema view: %v", err)
	}
	registered, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_schema_register"), selected, []int{phoneOrdinal}, "")
	if err != nil {
		t.Fatalf("register schema table with excluded column: %v (code=%s)", err, registration.CodeOf(err))
	}
	seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, mustID(t, "binding"))

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	access := regOwnerAccess("req_schema_tool")

	t.Run("source list groups the workspace's PostgreSQL tables by connection", func(t *testing.T) {
		sources, err := repository.ListSourceSchemas(ctx, access, regWorkspace)
		if err != nil {
			t.Fatalf("ListSourceSchemas: %v", err)
		}
		if len(sources) != 1 || sources[0].ID != bootstrap.ConnectionID ||
			sources[0].Name != "Schema database" || sources[0].TableCount != 1 {
			t.Fatalf("source list = %#v", sources)
		}
	})

	t.Run("the stored projection and catalog answer without the excluded column", func(t *testing.T) {
		result, err := repository.SourceSchema(ctx, access, regWorkspace, bootstrap.ConnectionID, "", 0, 50)
		if err != nil {
			t.Fatalf("SourceSchema: %v", err)
		}
		if result.SourceID != bootstrap.ConnectionID || !strings.HasPrefix(result.DatabaseIdentity, "pgdb:") {
			t.Fatalf("source identity = %q/%q", result.SourceID, result.DatabaseIdentity)
		}
		if result.HasMore || len(result.Tables) != 1 {
			t.Fatalf("tables = %#v, want one page of one", result.Tables)
		}
		table := result.Tables[0]
		if table.Schema != schemaName || table.Name != "accounts" || table.Kind != "TABLE" ||
			table.RowEstimate != rowEstimate || table.Note != "registered customer accounts" {
			t.Fatalf("table = %#v", table)
		}
		if len(table.Columns) != 2 {
			t.Fatalf("columns = %#v, want exactly the two projected columns", table.Columns)
		}
		byName := make(map[string]workspacerepository.SourceSchemaColumn, len(table.Columns))
		for _, column := range table.Columns {
			byName[column.Name] = column
		}
		if _, leaked := byName["phone"]; leaked {
			t.Fatalf("the excluded column was returned: %#v", table.Columns)
		}
		key, ok := byName["account_id"]
		if !ok || key.Type != "uuid" || !key.PrimaryKey || key.Nullable || key.Note != "surrogate key" {
			t.Fatalf("account_id = %#v", byName["account_id"])
		}
		if name, ok := byName["display_name"]; !ok || name.Type != "text" || name.PrimaryKey || !name.Nullable || name.Note != "customer name" {
			t.Fatalf("display_name = %#v", byName["display_name"])
		}
	})

	t.Run("the database refuses a catalog row that names an excluded column", func(t *testing.T) {
		tainted := `[{"name":"account_id","type_name":"uuid","comment":"","primary_key":true},` +
			`{"name":"display_name","type_name":"text","comment":"","primary_key":false},` +
			`{"name":"phone","type_name":"text","comment":"","primary_key":false}]`
		err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
			_, execErr := tx.Exec(txCtx, `SELECT app.postgresql_query_relation_catalog_record($1,$2,$3,$4,$5,$6::jsonb)`,
				registered.SourceScopeID, int64(1), bootstrap.ConnectionID, "registered customer accounts", int64(rowEstimate), tainted)
			return execErr
		})
		if err == nil {
			t.Fatalf("the catalog recorder accepted a column outside the projection")
		}
	})

	t.Run("a table selector narrows to that relation and a foreign source is not found", func(t *testing.T) {
		filtered, err := repository.SourceSchema(ctx, access, regWorkspace, bootstrap.ConnectionID, schemaName+".accounts", 0, 50)
		if err != nil || len(filtered.Tables) != 1 {
			t.Fatalf("filtered SourceSchema = %#v err=%v", filtered, err)
		}
		if _, err := repository.SourceSchema(ctx, access, regWorkspace, "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", "", 0, 50); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
			t.Fatalf("foreign source err = %v, want CodeNotFound", err)
		}
		other, err := repository.SourceSchema(ctx, access, "ws_other_01ARZ3NDEKTSV4RRFFQ69G5FAV", bootstrap.ConnectionID, "", 0, 50)
		if workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound || other.SourceID != "" {
			t.Fatalf("foreign workspace = %#v err=%v, want content-free CodeNotFound", other, err)
		}
	})
}
