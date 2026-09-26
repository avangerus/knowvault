package postgres_test

// Database-side proof that a PostgreSQL connection whose tables were
// registered one by one is one queryable source. The production registration
// path registers every discovered table as its own scope, so a customer
// database with several registered tables (GM: contract, container_group,
// client) is several scopes on one connection. Knowledge tool
// knowvault_source_sql and the owner's query-credential control address the
// connection, and before this proof such a connection was the content-free
// not-found: no table of it could be queried and no credential could be set.
//
// The test registers two tables of one connection through the production
// bootstrap -> discovery -> registration path, binds both to the workspace and
// drives workspacerepository.Store against real PostgreSQL:
//
//   - the source carries both tables under one exposed-schema revision that
//     activation does not change;
//   - it is READY only when both scopes are READY; and
//   - the owner's credential control sees both tables and can set the
//     credential, which the Sources card then reports as sql_available.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// multiScopeTable is one table of the multi-scope source database.
type multiScopeTable struct {
	oid     uint32
	name    string
	columns []string
}

// seedMultiScopeSource registers every table of one connection as its own
// scope through the production path and binds each scope to the registration
// workspace. It returns the repository, the connection id and the scope ids in
// table order.
func seedMultiScopeSource(t *testing.T, ctx context.Context, admin *pgxpool.Pool, tables []multiScopeTable) (*workspacerepository.Store, string, []string) {
	t.Helper()
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_multi_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Multi-table database", DatabaseIdentity: "multi-demo", LineageID: "multi-primary",
			CredentialReference: ownerControlCredentialRef,
		})
	if err != nil {
		t.Fatalf("bootstrap: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, bootstrap.ConnectionID)

	requested, err := service.RequestDiscovery(ctx, regOwnerAccess("req_multi_discover"), registration.DiscoveryRequest{
		ConnectionID: bootstrap.ConnectionID, IdempotencyKey: "multi-discovery",
		Limits: postgresqlquery.DiscoveryLimits{
			MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
			StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("enqueue discovery: %v", err)
	}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimed, found, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !found || claimed.ID != requested.RequestID {
		t.Fatalf("claim discovery: found=%v err=%v", found, err)
	}

	const schemaName = "kv_source_multi"
	snapshot := postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16386, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("8", 64),
	}
	for index, table := range tables {
		projection := postgresqlquery.Projection{
			ConnectionID: bootstrap.ConnectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("d", 64),
			LineageID: "projection-lineage:" + table.name, Revision: 1,
			ContractHash: "sha256:" + strings.Repeat(string(rune('1'+index)), 64), SchemaName: schemaName,
			RelationName: table.name, RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		}
		view := postgresqlquery.ViewDiscovery{
			ConnectionID: bootstrap.ConnectionID, DatabaseOID: 16386, DatabaseName: "source_db",
			RelationOID: table.oid, SchemaName: schemaName, RelationName: table.name, RelationKind: "TABLE",
			ApproxRowCount: 10, Status: postgresqlquery.DiscoveryPrepared,
		}
		for ordinal, name := range table.columns {
			role := postgresqlquery.RoleEvidence
			if ordinal == 0 {
				role = postgresqlquery.RoleIdentity
			}
			projection.Columns = append(projection.Columns, postgresqlquery.Column{
				Ordinal: ordinal + 1, Name: name, TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
				Roles: []postgresqlquery.Role{role}, Nullable: ordinal > 0, MaxBytes: 1024,
			})
			view.Columns = append(view.Columns, postgresqlquery.DiscoveredColumn{
				Ordinal: ordinal + 1, Name: name, TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25",
				LogicalType: postgresqlquery.TypeText, Nullable: ordinal > 0, MaxBytes: 1024, PrimaryKey: ordinal == 0,
			})
		}
		view.Projection = &projection
		snapshot.Views = append(snapshot.Views, view)
	}
	connector := &sourceDiscoveryConnector{snapshot: snapshot}
	discoveryHandler, err := sourcediscovery.NewHandler(workerStore, workerQueue, mustRepo(t), codec, connector,
		regWorkerID, 60, func(prefix string) (string, error) { return mustID(t, prefix), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := discoveryHandler.Handle(ctx, database.AccessContext{
		OrganizationID: regOrg, PrincipalID: "usr_worker", RequestID: claimed.ID,
	}, claimed); err != nil {
		t.Fatalf("handle discovery: %v (code=%s)", err, sourcediscovery.CodeOf(err))
	}
	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(ctx, regOwnerAccess("req_multi_read_discovery"), requested.RequestID)
	if err != nil || len(read.Views) != len(tables) {
		t.Fatalf("read discovery = %#v err=%v", read, err)
	}
	scopes := make([]string, 0, len(tables))
	for _, table := range tables {
		var selector string
		for _, view := range read.Views {
			if view.RelationName == table.name {
				selector = view.Selector
			}
		}
		if selector == "" {
			t.Fatalf("discovery did not list table %s: %#v", table.name, read.Views)
		}
		selected, err := reader.Select(ctx, regOwnerAccess("req_multi_select_"+table.name), requested.RequestID, selector)
		if err != nil {
			t.Fatalf("select %s: %v", table.name, err)
		}
		registered, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_multi_register_"+table.name), selected, nil, "")
		if err != nil {
			t.Fatalf("register %s: %v (code=%s)", table.name, err, registration.CodeOf(err))
		}
		seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, mustID(t, "binding"))
		scopes = append(scopes, registered.SourceScopeID)
	}

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	return repository, bootstrap.ConnectionID, scopes
}

// advanceMultiScopeActivation moves one scope's current activation DRAFT ->
// SYNCING -> READY, the transition the production sync performs.
func advanceMultiScopeActivation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, scopeID string) {
	t.Helper()
	for _, status := range []string{"SYNCING", "READY"} {
		if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
			SET status = $3, changed_at = transaction_timestamp(),
			    activated_at = CASE WHEN $3 = 'READY' THEN transaction_timestamp() ELSE activated_at END
			WHERE organization_id = $1 AND source_scope_id = $2`, regOrg, scopeID, status); err != nil {
			t.Fatalf("advance %s to %s: %v", scopeID, status, err)
		}
	}
}

func multiScopeTables(source workspacerepository.SourceQuerySource) []string {
	names := make([]string, 0, len(source.Relations))
	for _, relation := range source.Relations {
		names = append(names, relation.Table)
	}
	return names
}

func TestSourceQueryTablesRegisteredOneByOneAreOneSource(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID, scopes := seedMultiScopeSource(t, ctx, admin, []multiScopeTable{
		{oid: 40101, name: "contract", columns: []string{"contract_id", "number", "kind"}},
		{oid: 40102, name: "stand", columns: []string{"stand_id", "address"}},
	})
	owner := regOwnerAccess("req_multi_owner")

	pending, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil {
		t.Fatalf("two scopes on one connection = %v, want one source", err)
	}
	if got := strings.Join(multiScopeTables(pending), ","); got != "contract,stand" {
		t.Fatalf("source tables = %s, want contract,stand", got)
	}
	if pending.ScopeRevision < 1 {
		t.Fatalf("exposed-schema revision = %d, want a positive revision", pending.ScopeRevision)
	}
	if pending.ActivationStatus == "READY" {
		t.Fatalf("a source with no READY scope reports READY: %+v", pending)
	}

	advanceMultiScopeActivation(t, ctx, admin, scopes[0])
	half, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil {
		t.Fatalf("read with one READY scope: %v", err)
	}
	if half.ActivationStatus == "READY" {
		t.Fatal("the source is READY while its second table is still pending")
	}

	advanceMultiScopeActivation(t, ctx, admin, scopes[1])
	ready, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || ready.ActivationStatus != "READY" || !ready.TrustVerified || len(ready.Relations) != 2 ||
		ready.ScopeRevision != pending.ScopeRevision {
		t.Fatalf("both scopes READY = %+v err=%v, want a READY trusted source of 2 tables", ready, err)
	}

	target, err := repository.SourceQueryCredentialTarget(ctx, owner, regWorkspace, connectionID)
	if err != nil || strings.Join(multiScopeTables(target), ",") != "contract,stand" {
		t.Fatalf("owner credential target = %+v err=%v, want both tables", target, err)
	}
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef2); err != nil {
		t.Fatalf("owner set credential on a multi-table source: %v", err)
	}
	statuses, err := repository.ListSources(ctx, owner, regWorkspace)
	if err != nil || !sqlAvailableFor(statuses, connectionID) {
		t.Fatalf("sql_available after set = %#v err=%v", statuses, err)
	}
	withCredential, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || withCredential.QueryCredentialReference != ownerControlCredentialRef2 {
		t.Fatalf("source after set = %+v err=%v", withCredential, err)
	}
}
