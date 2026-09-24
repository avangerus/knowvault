package postgres_test

// S3 card 2b database-side acceptance proof for the organization-OWNER control
// over a PostgreSQL source connection's SQL query credential. It registers one
// real POSTGRESQL_QUERY source through the production discovery->registration
// path, binds it to a workspace with an OWNER and a MEMBER, and then drives
// workspacerepository.Store against real PostgreSQL (KNOWVAULT_TEST_POSTGRES_URL,
// migration 000117 included):
//
//   - the OWNER's target read and set/clear succeed and are visible to
//     SourceQuery (an empty reference is SOURCE_SQL_NOT_CONFIGURED) and to the
//     Sources card's sql_available projection;
//   - a non-owner workspace member gets the same content-free CodeNotFound as
//     an unknown or foreign source, for both the read and the write;
//   - the change is audited content-free; and
//   - an unknown or foreign connection is CodeNotFound and changes nothing.

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

const (
	ownerControlCredentialRef  = "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	ownerControlCredentialRef2 = "cred_01ARZ3NDEKTSV4RRFFQ69G5FAW"
)

// seedOwnerControlledSource runs the production bootstrap -> discovery ->
// registration path for one PostgreSQL source and binds it to the registration
// workspace, whose OWNER is regOwner and whose MEMBER is regViewer.
func seedOwnerControlledSource(t *testing.T, ctx context.Context, admin *pgxpool.Pool) (*workspacerepository.Store, string) {
	t.Helper()
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_cred_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Credential database", DatabaseIdentity: "credential-demo", LineageID: "credential-primary",
			CredentialReference: ownerControlCredentialRef,
		})
	if err != nil {
		t.Fatalf("bootstrap: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, bootstrap.ConnectionID)

	requested, err := service.RequestDiscovery(ctx, regOwnerAccess("req_cred_discover"), registration.DiscoveryRequest{
		ConnectionID: bootstrap.ConnectionID, IdempotencyKey: "credential-discovery",
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

	const schemaName = "kv_source_credential"
	projection := postgresqlquery.Projection{
		ConnectionID: bootstrap.ConnectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("c", 64),
		LineageID: "projection-lineage:credential", Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("1", 64), SchemaName: schemaName, RelationName: "accounts",
		RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "account_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "display_name", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
	connector := &sourceDiscoveryConnector{snapshot: postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16385, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("9", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: bootstrap.ConnectionID, DatabaseOID: 16385, DatabaseName: "source_db",
			RelationOID: 40002, SchemaName: schemaName, RelationName: "accounts", RelationKind: "TABLE",
			ApproxRowCount: 10, Status: postgresqlquery.DiscoveryPrepared, Projection: &projection,
			Columns: []postgresqlquery.DiscoveredColumn{
				{Ordinal: 1, Name: "account_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64, PrimaryKey: true},
				{Ordinal: 2, Name: "display_name", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Nullable: true, MaxBytes: 1024},
			},
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
		t.Fatalf("handle discovery: %v (code=%s)", err, sourcediscovery.CodeOf(err))
	}
	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	read, err := reader.Get(ctx, regOwnerAccess("req_cred_read_discovery"), requested.RequestID)
	if err != nil || len(read.Views) != 1 {
		t.Fatalf("read discovery = %#v err=%v", read, err)
	}
	selected, err := reader.Select(ctx, regOwnerAccess("req_cred_select"), requested.RequestID, read.Views[0].Selector)
	if err != nil {
		t.Fatalf("select view: %v", err)
	}
	registered, err := service.RegisterDiscoveredView(ctx, regOwnerAccess("req_cred_register"), selected, nil)
	if err != nil {
		t.Fatalf("register view: %v (code=%s)", err, registration.CodeOf(err))
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
	return repository, bootstrap.ConnectionID
}

func TestSourceQueryCredentialOwnerControl(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	repository, connectionID := seedOwnerControlledSource(t, ctx, admin)
	owner := regOwnerAccess("req_cred_owner")
	viewer := database.AccessContext{OrganizationID: regOrg, PrincipalID: regViewer, RequestID: "req_cred_viewer"}

	target, err := repository.SourceQueryCredentialTarget(ctx, owner, regWorkspace, connectionID)
	if err != nil || target.SourceID != connectionID || len(target.Relations) != 1 ||
		target.Relations[0].Table != "accounts" || len(target.Relations[0].Columns) != 2 {
		t.Fatalf("owner target read = %#v err=%v", target, err)
	}

	if _, err := repository.SourceQueryCredentialTarget(ctx, viewer, regWorkspace, connectionID); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("non-owner read = %v, want CodeNotFound", err)
	}
	if err := repository.SetSourceQueryCredential(ctx, viewer, regWorkspace, connectionID, ownerControlCredentialRef2); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("non-owner write = %v, want CodeNotFound", err)
	}
	query, err := repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || query.QueryCredentialReference != "" {
		t.Fatalf("a denied write changed the reference: %q err=%v", query.QueryCredentialReference, err)
	}

	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ownerControlCredentialRef2); err != nil {
		t.Fatalf("owner set: %v", err)
	}
	query, err = repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || query.QueryCredentialReference != ownerControlCredentialRef2 {
		t.Fatalf("after set reference = %q err=%v", query.QueryCredentialReference, err)
	}
	statuses, err := repository.ListSources(ctx, owner, regWorkspace)
	if err != nil || !sqlAvailableFor(statuses, connectionID) {
		t.Fatalf("sql_available after set = %#v err=%v", statuses, err)
	}

	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, connectionID, ""); err != nil {
		t.Fatalf("owner clear: %v", err)
	}
	query, err = repository.SourceQuery(ctx, owner, regWorkspace, connectionID)
	if err != nil || query.QueryCredentialReference != "" {
		t.Fatalf("after clear reference = %q err=%v", query.QueryCredentialReference, err)
	}
	statuses, err = repository.ListSources(ctx, owner, regWorkspace)
	if err != nil || sqlAvailableFor(statuses, connectionID) {
		t.Fatalf("sql_available after clear = %#v err=%v", statuses, err)
	}

	if _, err := repository.SourceQueryCredentialTarget(ctx, owner, "ws_foreign_01ARZ3NDEKTSV4RRFFQ69G5FAV", connectionID); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("foreign workspace = %v, want CodeNotFound", err)
	}
	if err := repository.SetSourceQueryCredential(ctx, owner, regWorkspace, "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", ownerControlCredentialRef2); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("foreign connection = %v, want CodeNotFound", err)
	}

	var audited int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id = $1 AND action IN ('source.query_credential_set', 'source.query_credential_cleared') AND resource_id = $2`,
		regOrg, connectionID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 2 {
		t.Fatalf("credential audit events = %d, want 2 (set and clear)", audited)
	}
	var metadata, resourceType, outcome, action string
	if err := admin.QueryRow(ctx, `SELECT metadata_json::text, resource_type, outcome, action FROM public.audit_event
		WHERE organization_id = $1 AND action IN ('source.query_credential_set', 'source.query_credential_cleared') AND resource_id = $2
		ORDER BY sequence LIMIT 1`, regOrg, connectionID).Scan(&metadata, &resourceType, &outcome, &action); err != nil {
		t.Fatal(err)
	}
	if resourceType != "SOURCE_CONNECTION" || outcome != "SUCCESS" || action != "source.query_credential_set" ||
		!strings.Contains(metadata, `"source_connection_id"`) {
		t.Fatalf("audit event = %s / %s / %s / %s", action, resourceType, outcome, metadata)
	}
	if strings.Contains(metadata, ownerControlCredentialRef2) || strings.Contains(metadata, "enabled") {
		t.Fatalf("audit event leaked reserved or secret content: %s", metadata)
	}
}

func sqlAvailableFor(statuses []workspacerepository.SourceStatus, connectionID string) bool {
	for _, status := range statuses {
		if status.ConnectionID == connectionID {
			return status.SQLAvailable
		}
	}
	return false
}
