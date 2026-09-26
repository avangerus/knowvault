package postgres_test

// Card S3.4b: real-PostgreSQL proof of batch discovery registration. One
// register-batch request resolves its selectors against one live encrypted
// discovery result and passes each prepared relation through the unchanged
// single-table registration, returning one outcome per selector. A relation the
// discovery worker could not prepare (here one with no primary key) reports its
// closed interpretation reason and never blocks the others.

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// batchDiscoveryColumns is the three-column business-object contract every
// prepared view of the batch fixture carries.
func batchDiscoveryColumns() []postgresqlquery.DiscoveredColumn {
	return []postgresqlquery.DiscoveredColumn{
		{Ordinal: 1, Name: "entity_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64},
		{Ordinal: 2, Name: "amount", TypeOID: 1700, TypeName: "numeric", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Precision: 12, Scale: 3, MaxBytes: 64},
		{Ordinal: 3, Name: "region", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 256},
	}
}

func batchDiscoveryProjection(connectionID, schema, relation, lineage, contractHash string) postgresqlquery.Projection {
	return postgresqlquery.Projection{
		ConnectionID: connectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("b", 64),
		LineageID: lineage, Revision: 1, ContractHash: contractHash,
		SchemaName: schema, RelationName: relation, RelationKind: "VIEW", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "entity_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "amount", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "region", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256},
		},
	}
}

// TestRegisterDiscoveredViewBatchRegistersEachPreparedTable proves the fourth
// card result: one server request registers three tables, and a table the
// discovery worker could not prepare carries its reason without blocking them.
func TestRegisterDiscoveredViewBatchRegistersEachPreparedTable(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "ws_sdr_batch")
	fixture := seedSourceDiscoveryConnection(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "alpha")

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatal(err)
	}
	codec := s1dCodec(t, fixture.organizationID)
	registrationService, err := registration.New(appStore, auditStore, codec, appQueue, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	ownerAccess := database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_batch_registration",
	}
	requested, err := registrationService.RequestDiscovery(ctx, ownerAccess, registration.DiscoveryRequest{
		ConnectionID: fixture.connectionID, IdempotencyKey: "discovery-batch-registration",
		Limits: postgresqlquery.DiscoveryLimits{
			MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
			StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("enqueue discovery: %v", err)
	}
	requestID := requested.RequestID

	workerStore := openStore(t, ctx, "knowvault_worker", "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimed, found, err := workerQueue.Claim(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_worker", RequestID: "worker.poll",
	}, "worker_sdr_batch", 60)
	if err != nil || !found {
		t.Fatalf("claim discovery: found=%v err=%v", found, err)
	}

	prepared := func(relation, lineage, contract string, relationOID uint32) postgresqlquery.ViewDiscovery {
		return postgresqlquery.ViewDiscovery{
			ConnectionID: fixture.connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
			RelationOID: relationOID, SchemaName: "demo_ops", RelationName: relation, RelationKind: "VIEW",
			Columns: batchDiscoveryColumns(), Status: postgresqlquery.DiscoveryPrepared,
			Projection: func() *postgresqlquery.Projection {
				projection := batchDiscoveryProjection(fixture.connectionID, "demo_ops", relation, lineage, contract)
				return &projection
			}(),
		}
	}
	connector := &sourceDiscoveryConnector{snapshot: postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{
			prepared("orders_v", "projection-lineage:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("1", 64), 24575),
			prepared("invoices_v", "projection-lineage:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("2", 64), 24576),
			prepared("trips_v", "projection-lineage:"+strings.Repeat("3", 64), "sha256:"+strings.Repeat("3", 64), 24577),
			{
				ConnectionID: fixture.connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
				RelationOID: 24578, SchemaName: "demo_ops", RelationName: "no_key_table", RelationKind: "TABLE",
				Columns:        batchDiscoveryColumns(),
				Status:         postgresqlquery.DiscoveryNeedsInterpretation,
				Interpretation: postgresqlquery.InterpretationNoPrimaryKey,
			},
		},
	}}
	generatedIDs := map[string]string{
		"sdr":      "sdr_01ARZ3NDEKTSV4RRFFQ69G5FAD",
		"artifact": "artifact_01ARZ3NDEKTSV4RRFFQ69G5FAE",
	}
	repository, err := ingestion.BuildRepository()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := sourcediscovery.NewHandler(workerStore, workerQueue, repository, codec, connector,
		"worker_sdr_batch", 60, func(prefix string) (string, error) { return generatedIDs[prefix], nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_worker", RequestID: claimed.ID,
	}, claimed); err != nil {
		t.Fatalf("handle discovery: %v (code=%s)", err, sourcediscovery.CodeOf(err))
	}

	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := reader.Get(ctx, ownerAccess, requestID)
	if err != nil {
		t.Fatalf("read discovery projection: %v", err)
	}
	if len(projection.Views) != 4 {
		t.Fatalf("views = %d, want 4", len(projection.Views))
	}
	unprepared := projection.Views[3]
	items := []registration.BatchRegisterItem{
		{ViewID: projection.Views[0].Selector},
		{ViewID: projection.Views[1].Selector, Mode: postgresqlquery.ProjectionModeQueryOnly},
		{ViewID: projection.Views[2].Selector},
		{ViewID: unprepared.Selector},
	}

	result, err := registration.RegisterDiscoveredViewBatch(ctx, registrationService, reader, ownerAccess, requestID, items)
	if err != nil {
		t.Fatalf("register batch: %v", err)
	}
	if result.RegisteredCount != 3 || result.RefusedCount != 1 || len(result.Outcomes) != 4 {
		t.Fatalf("batch registration result = %#v", result)
	}
	for index := 0; index < 3; index++ {
		outcome := result.Outcomes[index]
		if !outcome.Registered || !outcome.Result.Created || outcome.Result.SourceScopeID == "" {
			t.Fatalf("prepared view %d outcome = %#v", index, outcome)
		}
	}
	if refused := result.Outcomes[3]; refused.Registered || refused.ReasonCode != string(postgresqlquery.InterpretationNoPrimaryKey) {
		t.Fatalf("unprepared view outcome = %#v, want NO_PRIMARY_KEY", refused)
	}
	if result.Outcomes[1].Result.ScopeConfigHash == result.Outcomes[0].Result.ScopeConfigHash {
		t.Fatalf("query-only registration reused the indexed contract hash")
	}

	var scopeCount, projectionCount, queryOnlyCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM public.source_scope WHERE organization_id=$1 AND connection_id=$2),
		(SELECT count(*) FROM public.postgresql_query_projection AS projection
			JOIN public.source_scope AS scope ON scope.organization_id=projection.organization_id AND scope.id=projection.source_scope_id
			WHERE projection.organization_id=$1 AND scope.connection_id=$2),
		(SELECT count(*) FROM public.postgresql_query_projection AS projection
			JOIN public.source_scope AS scope ON scope.organization_id=projection.organization_id AND scope.id=projection.source_scope_id
			WHERE projection.organization_id=$1 AND scope.connection_id=$2 AND projection.query_only)`,
		fixture.organizationID, fixture.connectionID).Scan(&scopeCount, &projectionCount, &queryOnlyCount); err != nil {
		t.Fatalf("count batch registration rows: %v", err)
	}
	if scopeCount != 3 || projectionCount != 3 || queryOnlyCount != 1 {
		t.Fatalf("batch registration rows = scopes:%d projections:%d query-only:%d, want 3/3/1",
			scopeCount, projectionCount, queryOnlyCount)
	}
}
