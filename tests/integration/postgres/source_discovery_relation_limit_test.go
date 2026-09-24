package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// bulkRelationSchema holds the real base tables TestSourceDiscoveryWorkerPersistsManyRealRelationsThroughDurablePath
// creates directly on the shared integration-test PostgreSQL server (the same
// server tests/integration/postgres already uses for the control-plane
// database, reused here as the simulated customer "source" database exactly
// as internal/source/postgresqlquery's own real-server discovery tests do).
const bulkRelationSchema = "kv_bulk_discovery_durable"

// realCatalogConnector is a CatalogConnector that reads real PostgreSQL
// catalog rows (pg_class/pg_attribute/pg_index) for bulkRelationSchema's
// tables instead of returning a canned snapshot. It exists only to prove the
// DISCOVERY_LIMIT_EXCEEDED fix at the durable worker/storage layer against a
// real multi-hundred-relation catalog; it is not the production LiveConnector
// (which requires a TLS-verified external server) and lives only in this
// test file.
type realCatalogConnector struct {
	pool         *pgxpool.Pool
	connectionID string
	schemaName   string
}

func (connector *realCatalogConnector) DiscoverCatalog(ctx context.Context, _ postgresqlquery.DiscoveryRequest) (postgresqlquery.CatalogSnapshot, error) {
	var rawDatabaseOID int64
	var databaseName string
	if err := connector.pool.QueryRow(ctx, `
		SELECT d.oid::bigint, d.datname FROM pg_catalog.pg_database AS d WHERE d.datname = current_database()`,
	).Scan(&rawDatabaseOID, &databaseName); err != nil {
		return postgresqlquery.CatalogSnapshot{}, err
	}
	databaseOID := uint32(rawDatabaseOID)

	rows, err := connector.pool.Query(ctx, `
		SELECT c.oid::bigint, c.relname, a.attnum, a.attname,
			EXISTS (
				SELECT 1 FROM pg_catalog.pg_index AS i
				WHERE i.indrelid = a.attrelid AND i.indisprimary AND a.attnum = ANY(i.indkey)
			) AS is_primary_key
		FROM pg_catalog.pg_class AS c
		JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
		JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
		WHERE n.nspname = $1 AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY c.relname, a.attnum`, connector.schemaName)
	if err != nil {
		return postgresqlquery.CatalogSnapshot{}, err
	}
	defer rows.Close()

	var views []postgresqlquery.ViewDiscovery
	var currentName string
	var currentOID uint32
	var columns []postgresqlquery.DiscoveredColumn
	var projectionColumns []postgresqlquery.Column
	flush := func() {
		if currentName == "" {
			return
		}
		views = append(views, connector.buildView(databaseOID, databaseName, currentOID, currentName, columns, projectionColumns))
	}
	for rows.Next() {
		var rawOID int64
		var relationName, columnName string
		var ordinal int
		var isPrimaryKey bool
		if err := rows.Scan(&rawOID, &relationName, &ordinal, &columnName, &isPrimaryKey); err != nil {
			return postgresqlquery.CatalogSnapshot{}, err
		}
		if relationName != currentName {
			flush()
			currentName, currentOID, columns, projectionColumns = relationName, uint32(rawOID), nil, nil
		}
		typeOID, typeName, typeFingerprint, logicalType, maxBytes := uint32(2950), "uuid", "oid:2950", postgresqlquery.TypeUUID, 64
		role := postgresqlquery.RoleIdentity
		if columnName == "label" {
			typeOID, typeName, typeFingerprint, logicalType, maxBytes = 25, "text", "oid:25", postgresqlquery.TypeText, 1<<20
			role = postgresqlquery.RoleEvidence
		}
		columns = append(columns, postgresqlquery.DiscoveredColumn{
			Ordinal: ordinal, Name: columnName, TypeOID: typeOID, TypeName: typeName,
			TypeFingerprint: typeFingerprint, LogicalType: logicalType, MaxBytes: maxBytes, PrimaryKey: isPrimaryKey,
		})
		projectionColumns = append(projectionColumns, postgresqlquery.Column{
			Ordinal: ordinal, Name: columnName, TypeFingerprint: typeFingerprint, LogicalType: logicalType,
			Roles: []postgresqlquery.Role{role}, MaxBytes: maxBytes,
		})
	}
	if err := rows.Err(); err != nil {
		return postgresqlquery.CatalogSnapshot{}, err
	}
	flush()

	return postgresqlquery.CatalogSnapshot{
		DatabaseOID: databaseOID, DatabaseName: databaseName, Views: views,
		PrivilegeDigest: "sha256:" + strings.Repeat("7", 64),
	}, nil
}

func (connector *realCatalogConnector) buildView(databaseOID uint32, databaseName string, relationOID uint32,
	relationName string, columns []postgresqlquery.DiscoveredColumn, projectionColumns []postgresqlquery.Column) postgresqlquery.ViewDiscovery {
	sum := sha256.Sum256([]byte(connector.schemaName + "." + relationName))
	hash := hex.EncodeToString(sum[:])
	projection := postgresqlquery.Projection{
		ConnectionID: connector.connectionID, DatabaseIdentity: "pgdb:" + hash,
		LineageID: "projection-lineage:" + hash, Revision: 1, ContractHash: "sha256:" + hash,
		SchemaName: connector.schemaName, RelationName: relationName, RelationKind: "TABLE",
		Columns: projectionColumns, EmptySnapshotPolicy: "HELD",
	}
	return postgresqlquery.ViewDiscovery{
		ConnectionID: connector.connectionID, DatabaseOID: databaseOID, DatabaseName: databaseName,
		RelationOID: relationOID, SchemaName: connector.schemaName, RelationName: relationName, RelationKind: "TABLE",
		Columns: columns, Status: postgresqlquery.DiscoveryPrepared, Projection: &projection,
	}
}

// TestSourceDiscoveryWorkerPersistsManyRealRelationsThroughDurablePath is the
// mandatory real-PostgreSQL S1 fix proof for DISCOVERY_LIMIT_EXCEEDED: it
// creates 300 real base tables with declared primary keys directly against
// the integration-test PostgreSQL server, then drives them through the exact
// production durable path -- registration.RequestDiscovery (with the
// server's own empty/default limits, DefaultDiscoveryLimits, now MaxViews
// 1024), the SOURCE_DISCOVERY queue job, discovery.Handler.Handle (the
// worker.go ValidateDurable/buildMetadata bound and migration 000111's
// widened SQL CHECK constraints on source_discovery_request.max_views and
// source_discovery_result's three view counters), the encrypted metadata
// artifact, and Reader.Get (the widened Metadata.validate bound). GM's real
// catalog is 645 tables/views; 300 real relations here already exceeds the
// old 64-relation ceiling by 4.7x and proves the durable path no longer fails
// closed with DISCOVERY_LIMIT_EXCEEDED under the new 1024-relation ceiling.
func TestSourceDiscoveryWorkerPersistsManyRealRelationsThroughDurablePath(t *testing.T) {
	ctx := context.Background()
	const relationCount = 300
	admin := resetDatabaseThrough(t, "000111_stage4_source_discovery_relation_limit.sql")
	seedOrganization(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "ws_sdr_bulk")
	fixture := seedSourceDiscoveryConnection(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "alpha")

	var seed strings.Builder
	seed.WriteString(`DROP SCHEMA IF EXISTS "` + bulkRelationSchema + `" CASCADE;`)
	seed.WriteString(`CREATE SCHEMA "` + bulkRelationSchema + `";`)
	for index := 0; index < relationCount; index++ {
		seed.WriteString(`CREATE TABLE "` + bulkRelationSchema + `"."t` + strconv.Itoa(index) + `" (` +
			`id uuid PRIMARY KEY, label text NOT NULL);`)
	}
	if _, err := admin.Exec(ctx, seed.String()); err != nil {
		t.Fatalf("seed %d real relations: %v", relationCount, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS "`+bulkRelationSchema+`" CASCADE`)
	})

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

	requested, err := registrationService.RequestDiscovery(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_bulk_enqueue",
	}, registration.DiscoveryRequest{
		ConnectionID: fixture.connectionID, IdempotencyKey: "discovery-worker-bulk-lifecycle",
	})
	if err != nil {
		t.Fatalf("enqueue bulk source discovery: %v", err)
	}
	requestID := requested.RequestID

	workerStore := openStore(t, ctx, "knowvault_worker", "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimed, found, err := workerQueue.Claim(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_worker", RequestID: "worker.bulk.poll",
	}, "worker_sdr_bulk_runtime", 60)
	if err != nil || !found {
		t.Fatalf("claim bulk source discovery: found=%v err=%v", found, err)
	}

	repository, err := ingestion.BuildRepository()
	if err != nil {
		t.Fatal(err)
	}
	connector := &realCatalogConnector{pool: admin, connectionID: fixture.connectionID, schemaName: bulkRelationSchema}
	handler, err := sourcediscovery.NewHandler(workerStore, workerQueue, repository, codec, connector,
		"worker_sdr_bulk_runtime", 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	workerJobAccess := database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_worker", RequestID: claimed.ID,
	}
	if err := handler.Handle(ctx, workerJobAccess, claimed); err != nil {
		cause := errors.Unwrap(err)
		t.Fatalf("handle bulk source discovery: code=%s err=%v cause=%v", sourcediscovery.CodeOf(err), err, cause)
	}

	appPool := openApplicationPool(t, ctx, testDatabaseURL(t))
	status := sourceDiscoveryStatusValue(t, ctx, appPool, fixture.organizationID, fixture.ownerID, requestID)
	if status.requestStatus != "SUCCEEDED" || status.resultStatus != "SUCCEEDED" ||
		status.viewCount != relationCount || status.preparedViewCount != relationCount ||
		status.needsViewCount != 0 || status.failureCode != nil {
		t.Fatalf("bulk source discovery status = %#v", status)
	}

	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := reader.Get(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_bulk_read",
	}, requestID)
	if err != nil {
		t.Fatalf("read OWNER bulk discovery projection: %v cause=%v", err, errors.Unwrap(err))
	}
	if len(projection.Views) != relationCount {
		t.Fatalf("OWNER bulk discovery projection returned %d views, want %d", len(projection.Views), relationCount)
	}
	seenNames := make(map[string]bool, relationCount)
	for _, view := range projection.Views {
		if view.Status != postgresqlquery.DiscoveryPrepared || len(view.Columns) != 2 {
			t.Fatalf("bulk discovery view = %#v, want a 2-column PREPARED table", view)
		}
		seenNames[view.RelationName] = true
	}
	for index := 0; index < relationCount; index++ {
		if !seenNames["t"+strconv.Itoa(index)] {
			t.Fatalf("bulk discovery projection is missing relation t%d", index)
		}
	}
}
