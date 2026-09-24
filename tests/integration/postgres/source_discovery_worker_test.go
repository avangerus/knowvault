package postgres_test

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

type sourceDiscoveryConnector struct {
	snapshot postgresqlquery.CatalogSnapshot
	requests []postgresqlquery.DiscoveryRequest
}

func TestPostgreSQLConnectionBootstrapCreatesNoScope(t *testing.T) {
	ctx := context.Background()
	admin := resetDatabaseThrough(t, "000091_stage4_source_connection_bootstrap.sql")
	seedS1dOrg(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner)
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, discoveryMember, discoveryAlphaOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment
			(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_sdr_member', $1, $2, 'MEMBER', 1, $3)`,
		discoveryAlphaOrg, discoveryMember, discoveryAlphaOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (
			id, profile_hash, connector_build_id, connector_type, connector_version,
			connector_artifact_hash, stable_object_ids, native_versions,
			incremental_cursor, webhooks, item_level_acl, acl_refresh,
			historical_versions, deep_links, deletion_events, local_extraction,
			contract_suite_hash, verified_at
		) VALUES ('cap_sdr_bootstrap', $1, 'pg-sdr-bootstrap', 'POSTGRESQL_QUERY', '1.0.0',
			$2, true, true, true, false, true, true, true, true, true, true, $3,
			transaction_timestamp())`, "sha256:"+strings.Repeat("a", 64),
		"sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := jobs.New(appStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := registration.New(appStore, auditStore, s1dCodec(t, discoveryAlphaOrg), queue, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	request := registration.PostgreSQLConnectionBootstrapRequest{
		Name: "Fleet database", DatabaseIdentity: "fleet-demo", LineageID: "fleet-primary",
		CredentialReference: testCredentialRef,
	}
	ownerAccess := database.AccessContext{
		OrganizationID: discoveryAlphaOrg, PrincipalID: discoveryAlphaOwner, RequestID: "req_sdr_bootstrap",
	}
	result, err := service.BootstrapPostgreSQLConnection(ctx, ownerAccess, request)
	if err != nil {
		t.Fatalf("bootstrap PostgreSQL connection: %v", err)
	}
	if !result.Created || result.ConnectionRevision != 1 || result.CredentialReference != testCredentialRef ||
		!strings.HasPrefix(result.ConnectionID, "conn_") || !strings.HasPrefix(result.TrustProfileHash, "sha256:") {
		t.Fatalf("bootstrap result = %#v", result)
	}
	replay, err := service.BootstrapPostgreSQLConnection(ctx, ownerAccess, request)
	if err != nil || replay != (registration.PostgreSQLConnectionBootstrapResult{
		ConnectionID: result.ConnectionID, ConnectionRevision: 1, CredentialReference: testCredentialRef,
		TrustProfileHash: result.TrustProfileHash, Created: false,
	}) {
		t.Fatalf("bootstrap replay = %#v err=%v", replay, err)
	}
	if _, err := service.BootstrapPostgreSQLConnection(ctx, database.AccessContext{
		OrganizationID: discoveryAlphaOrg, PrincipalID: discoveryMember, RequestID: "req_sdr_member",
	}, request); registration.CodeOf(err) != registration.CodeDenied {
		t.Fatalf("member bootstrap code=%s err=%v", registration.CodeOf(err), err)
	}

	var discoveredCount, scopeCount, activationCount, jobCount, artifactCount, auditCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM public.source_discovered_scope WHERE organization_id=$1 AND connection_id=$2),
		(SELECT count(*) FROM public.source_scope WHERE organization_id=$1 AND connection_id=$2),
		(SELECT count(*) FROM public.source_scope_activation WHERE organization_id=$1),
		(SELECT count(*) FROM public.job WHERE organization_id=$1)`,
		discoveryAlphaOrg, result.ConnectionID).Scan(&discoveredCount, &scopeCount, &activationCount, &jobCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='source_connection_revision'
		  AND owner_column='trust_profile_artifact_id' AND resource_type='SOURCE_TRUST_CONFIG'`,
		discoveryAlphaOrg).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action='source.registration_created'
		  AND resource_type='SOURCE_CONNECTION' AND resource_id=$2`,
		discoveryAlphaOrg, result.ConnectionID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if discoveredCount != 0 || scopeCount != 0 || activationCount != 0 || jobCount != 0 || artifactCount != 1 || auditCount != 1 {
		t.Fatalf("bootstrap rows = discovered:%d scopes:%d activations:%d jobs:%d trust-artifacts:%d audits:%d",
			discoveredCount, scopeCount, activationCount, jobCount, artifactCount, auditCount)
	}
	var appBootstrap, workerBootstrap, publicBootstrap, workerTarget, appTarget, publicTarget bool
	if err := admin.QueryRow(ctx, `SELECT
		has_function_privilege('knowvault_app', 'app.source_postgresql_connection_bootstrap_begin(text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,bigint,bigint,bigint)', 'EXECUTE'),
		has_function_privilege('knowvault_worker', 'app.source_postgresql_connection_bootstrap_begin(text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,bigint,bigint,bigint)', 'EXECUTE'),
		has_function_privilege('public', 'app.source_postgresql_connection_bootstrap_begin(text,text,text,text,text,text,text,text,text,text,text,text,timestamptz,bigint,bigint,bigint)', 'EXECUTE'),
		has_function_privilege('knowvault_worker', 'app.source_discovery_worker_target(text,text,text,bigint)', 'EXECUTE'),
		has_function_privilege('knowvault_app', 'app.source_discovery_worker_target(text,text,text,bigint)', 'EXECUTE'),
		has_function_privilege('public', 'app.source_discovery_worker_target(text,text,text,bigint)', 'EXECUTE')`).Scan(
		&appBootstrap, &workerBootstrap, &publicBootstrap, &workerTarget, &appTarget, &publicTarget); err != nil {
		t.Fatal(err)
	}
	if !appBootstrap || workerBootstrap || publicBootstrap || !workerTarget || appTarget || publicTarget {
		t.Fatalf("bootstrap/target privileges = %v %v %v / %v %v %v",
			appBootstrap, workerBootstrap, publicBootstrap, workerTarget, appTarget, publicTarget)
	}
}

func (connector *sourceDiscoveryConnector) DiscoverCatalog(_ context.Context, request postgresqlquery.DiscoveryRequest) (postgresqlquery.CatalogSnapshot, error) {
	connector.requests = append(connector.requests, request)
	return connector.snapshot, nil
}

func TestSourceDiscoveryWorkerPersistsEncryptedCatalogResult(t *testing.T) {
	ctx := context.Background()
	admin := resetDatabaseThrough(t, "000114_stage4_postgresql_query_relation_catalog.sql")
	seedOrganization(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "ws_sdr_alpha")
	fixture := seedSourceDiscoveryConnection(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "alpha")

	appPool := openApplicationPool(t, ctx, testDatabaseURL(t))
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
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_enqueue",
	}, registration.DiscoveryRequest{
		ConnectionID: fixture.connectionID, IdempotencyKey: "discovery-worker-lifecycle",
		Limits: postgresqlquery.DiscoveryLimits{
			MaxViews: 16, MaxColumns: 32, MaxCommentBytes: 4096,
			StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("enqueue source discovery: %v", err)
	}
	requestID := requested.RequestID
	if requested.JobID != requestID || !requested.Created {
		t.Fatalf("enqueued discovery = %#v", requested)
	}

	workerStore := openStore(t, ctx, "knowvault_worker", "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	claimed, found, err := workerQueue.Claim(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_worker", RequestID: "worker.poll",
	}, "worker_sdr_runtime", 60)
	if err != nil || !found {
		t.Fatalf("claim source discovery: found=%v err=%v", found, err)
	}
	if claimed.ID != requestID || claimed.Type != sourcediscovery.JobType {
		t.Fatalf("claimed discovery = id:%q type:%q", claimed.ID, claimed.Type)
	}

	repository, err := ingestion.BuildRepository()
	if err != nil {
		t.Fatal(err)
	}
	preparedColumns := []postgresqlquery.DiscoveredColumn{
		{Ordinal: 1, Name: "entity_id", TypeOID: 2950, TypeName: "uuid", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, MaxBytes: 64},
		{Ordinal: 2, Name: "entity_version", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1 << 20},
		{Ordinal: 3, Name: "last_updated_at", TypeOID: 1184, TypeName: "timestamptz", TypeFingerprint: "oid:1184", LogicalType: postgresqlquery.TypeTimestamptz, MaxBytes: 64},
		{Ordinal: 4, Name: "payload", TypeOID: 3802, TypeName: "jsonb", TypeFingerprint: "oid:3802", LogicalType: postgresqlquery.TypeJSONB, MaxBytes: 1 << 20},
		{Ordinal: 5, Name: "payload_format", TypeOID: 25, TypeName: "text", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, MaxBytes: 1 << 20},
	}
	preparedProjection := postgresqlquery.Projection{
		ConnectionID: fixture.connectionID, DatabaseIdentity: "pgdb:" + strings.Repeat("b", 64),
		LineageID: "projection-lineage:" + strings.Repeat("c", 64), Revision: 1,
		ContractHash: "sha256:" + strings.Repeat("d", 64), SchemaName: "demo_ops",
		RelationName: "business_objects_v", RelationKind: "VIEW", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "entity_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "entity_version", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint}, MaxBytes: 1 << 20},
			{Ordinal: 3, Name: "last_updated_at", TypeFingerprint: "oid:1184", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint, postgresqlquery.RoleEvidence}, MaxBytes: 64},
			{Ordinal: 4, Name: "payload", TypeFingerprint: "oid:3802", LogicalType: postgresqlquery.TypeJSONB, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1 << 20},
			{Ordinal: 5, Name: "payload_format", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1 << 20},
		},
	}
	connector := &sourceDiscoveryConnector{snapshot: postgresqlquery.CatalogSnapshot{
		DatabaseOID: 16384, DatabaseName: "source_db", PrivilegeDigest: "sha256:" + strings.Repeat("a", 64),
		Views: []postgresqlquery.ViewDiscovery{{
			ConnectionID: fixture.connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
			RelationOID: 24575, SchemaName: "demo_ops", RelationName: "business_objects_v", RelationKind: "VIEW",
			Columns: preparedColumns, Status: postgresqlquery.DiscoveryPrepared, Projection: &preparedProjection,
		}, {
			ConnectionID: fixture.connectionID, DatabaseOID: 16384, DatabaseName: "source_db",
			RelationOID: 24576, SchemaName: "demo_ops", RelationName: "fleet_trips_v", RelationKind: "VIEW",
			Columns: []postgresqlquery.DiscoveredColumn{{
				Ordinal: 1, Name: "payload", TypeOID: 3802, TypeName: "jsonb", TypeFingerprint: "oid:3802",
				LogicalType: postgresqlquery.TypeJSON,
			}},
			Status:         postgresqlquery.DiscoveryNeedsInterpretation,
			Interpretation: postgresqlquery.InterpretationUnrecognizedFormat,
		}},
	}}
	generatedIDs := map[string]string{
		"sdr":      "sdr_01ARZ3NDEKTSV4RRFFQ69G5FAD",
		"artifact": "artifact_01ARZ3NDEKTSV4RRFFQ69G5FAE",
	}
	handler, err := sourcediscovery.NewHandler(workerStore, workerQueue, repository, codec, connector,
		"worker_sdr_runtime", 60, func(prefix string) (string, error) { return generatedIDs[prefix], nil })
	if err != nil {
		t.Fatal(err)
	}
	workerJobAccess := database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_worker", RequestID: claimed.ID,
	}
	if err := handler.Handle(ctx, workerJobAccess, claimed); err != nil {
		cause := errors.Unwrap(err)
		t.Fatalf("handle source discovery: code=%s err=%v cause=%v root=%v", sourcediscovery.CodeOf(err), err, cause, errors.Unwrap(cause))
	}
	if len(connector.requests) != 2 || connector.requests[0].CredentialReference != testCredentialRef ||
		connector.requests[0].ConnectionID != fixture.connectionID || connector.requests[0].SchemaName != "" ||
		connector.requests[0].RelationName != "" {
		t.Fatalf("catalog probes = %#v", connector.requests)
	}

	status := sourceDiscoveryStatusValue(t, ctx, appPool, fixture.organizationID, fixture.ownerID, requestID)
	if status.requestStatus != "SUCCEEDED" || status.resultID != generatedIDs["sdr"] ||
		status.resultStatus != "NEEDS_INTERPRETATION" || status.viewCount != 2 ||
		status.preparedViewCount != 1 || status.needsViewCount != 1 || status.failureCode != nil {
		t.Fatalf("source discovery status = %#v", status)
	}
	var jobStatus string
	if err := admin.QueryRow(ctx, `SELECT status FROM public.job WHERE organization_id=$1 AND id=$2`,
		fixture.organizationID, requestID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "SUCCEEDED" {
		t.Fatalf("source discovery job status = %q", jobStatus)
	}

	metadata := readSourceDiscoveryMetadata(t, ctx, workerStore, codec, workerJobAccess, status.resultID)
	if metadata.ConnectionID != fixture.connectionID || metadata.DatabaseOID != 16384 || metadata.DatabaseName != "source_db" ||
		len(metadata.Views) != 2 || metadata.Views[1].SchemaName != "demo_ops" || metadata.Views[1].RelationName != "fleet_trips_v" ||
		!metadata.Validate(16) {
		t.Fatalf("decrypted source discovery metadata = %#v", metadata)
	}
	var plaintextMatches int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND id=$2 AND position(convert_to('fleet_trips_v', 'UTF8') in ciphertext) > 0`,
		fixture.organizationID, generatedIDs["artifact"]).Scan(&plaintextMatches); err != nil {
		t.Fatal(err)
	}
	if plaintextMatches != 0 {
		t.Fatal("source relation name was stored as plaintext in the encrypted artifact")
	}
	reader, err := sourcediscovery.NewReader(appStore, codec, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := reader.Get(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_read",
	}, requestID)
	if err != nil {
		t.Fatalf("read OWNER discovery projection: %v cause=%v root=%v", err, errors.Unwrap(err), errors.Unwrap(errors.Unwrap(err)))
	}
	if projection.ResultID != status.resultID || len(projection.Views) != 2 ||
		!strings.HasPrefix(projection.Views[0].Selector, "sdv_") ||
		projection.Views[0].SchemaName != "demo_ops" || len(projection.Views[0].Columns) != 5 ||
		projection.Views[0].Columns[0].TypeName != "uuid" {
		t.Fatalf("OWNER discovery projection = %#v", projection)
	}
	otherKey := append([]byte(nil), s1dDigestKey...)
	otherKey[0] ^= 0xff
	otherReader, err := sourcediscovery.NewReader(appStore, codec, otherKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	otherProjection, err := otherReader.Get(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_other_key",
	}, requestID)
	if err != nil || otherProjection.Views[0].Selector == projection.Views[0].Selector {
		t.Fatalf("view selector is not keyed: first=%q second=%q err=%v",
			projection.Views[0].Selector, otherProjection.Views[0].Selector, err)
	}
	if _, err := reader.Select(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_unprepared",
	}, requestID, projection.Views[1].Selector); sourcediscovery.CodeOf(err) != sourcediscovery.CodeInvalid {
		t.Fatalf("unprepared view selection code=%s err=%v", sourcediscovery.CodeOf(err), err)
	}
	selected, err := reader.Select(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_select",
	}, requestID, projection.Views[0].Selector)
	if err != nil || selected.Projection.RelationName != "business_objects_v" || selected.ConnectionRevision != 1 {
		t.Fatalf("select prepared discovery view = %#v err=%v", selected, err)
	}
	registered, err := registrationService.RegisterDiscoveredView(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_register",
	}, selected, nil)
	if err != nil || !registered.Created || registered.SourceScopeID == "" || registered.ConnectionID != fixture.connectionID {
		t.Fatalf("register discovered view = %#v err=%v cause=%v root=%v", registered, err,
			errors.Unwrap(err), errors.Unwrap(errors.Unwrap(err)))
	}
	replay, err := registrationService.RegisterDiscoveredView(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sdr_register_replay",
	}, selected, nil)
	if err != nil || replay.Created || replay.SourceScopeID != registered.SourceScopeID || replay.ScopeConfigHash != registered.ScopeConfigHash {
		t.Fatalf("replay discovered view registration = %#v err=%v", replay, err)
	}
	var scopeCount, selectionCount, projectionCount int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM public.source_scope WHERE organization_id=$1 AND connection_id=$2),
		(SELECT count(*) FROM public.source_discovery_registration WHERE organization_id=$1 AND request_id=$3),
		(SELECT count(*) FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$4)`,
		fixture.organizationID, fixture.connectionID, requestID, registered.SourceScopeID).Scan(
		&scopeCount, &selectionCount, &projectionCount); err != nil {
		t.Fatal(err)
	}
	if scopeCount != 1 || selectionCount != 1 || projectionCount != 1 {
		t.Fatalf("selected registration rows = scopes:%d selections:%d projections:%d", scopeCount, selectionCount, projectionCount)
	}
	var appInsert, workerExecute, publicExecute, appExecute, appReadV2, workerReadV2 bool
	if err := admin.QueryRow(ctx, `SELECT
		has_table_privilege('knowvault_app', 'public.source_discovery_registration', 'INSERT'),
		has_function_privilege('knowvault_worker', 'app.source_discovery_view_registration_begin(text,text,text,text,bigint,text,text,bigint,text,text,text,text,text,text,text,text,integer,integer,bigint,bigint,bigint,text)', 'EXECUTE'),
		has_function_privilege('public', 'app.source_discovery_view_registration_begin(text,text,text,text,bigint,text,text,bigint,text,text,text,text,text,text,text,text,integer,integer,bigint,bigint,bigint,text)', 'EXECUTE'),
		has_function_privilege('knowvault_app', 'app.source_discovery_view_registration_begin(text,text,text,text,bigint,text,text,bigint,text,text,text,text,text,text,text,text,integer,integer,bigint,bigint,bigint,text)', 'EXECUTE'),
		has_function_privilege('knowvault_app', 'app.source_discovery_result_read_for_owner_v2(text)', 'EXECUTE'),
		has_function_privilege('knowvault_worker', 'app.source_discovery_result_read_for_owner_v2(text)', 'EXECUTE')`).Scan(
		&appInsert, &workerExecute, &publicExecute, &appExecute, &appReadV2, &workerReadV2); err != nil {
		t.Fatal(err)
	}
	if appInsert || workerExecute || publicExecute || !appExecute || !appReadV2 || workerReadV2 {
		t.Fatalf("selection registration privileges = app-insert:%v worker-exec:%v public-exec:%v app-exec:%v app-read:%v worker-read:%v",
			appInsert, workerExecute, publicExecute, appExecute, appReadV2, workerReadV2)
	}
	if _, err := reader.Get(ctx, database.AccessContext{
		OrganizationID: fixture.organizationID, PrincipalID: "usr_not_owner", RequestID: "req_sdr_hidden",
	}, requestID); sourcediscovery.CodeOf(err) != sourcediscovery.CodeNotFound {
		t.Fatalf("hidden discovery projection code=%s err=%v", sourcediscovery.CodeOf(err), err)
	}
}

func readSourceDiscoveryMetadata(t *testing.T, ctx context.Context, store *database.Store, codec *artifactcrypto.Codec,
	access database.AccessContext, resultID string) sourcediscovery.Metadata {
	t.Helper()
	var envelope artifactcrypto.Envelope
	if err := store.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceDiscoveryResultMetadata, access.OrganizationID, resultID)
		if err != nil {
			return err
		}
		var storedResultID, artifactID, wrappedDEKHash, kekReference, aadHash, plaintextHash string
		var ciphertext, nonce, wrappedDEK []byte
		var sizeBytes int
		var kekVersion int64
		if err := tx.QueryRow(ctx, `SELECT result_id, artifact_id, ciphertext, size_bytes, nonce,
			wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
			FROM app.source_discovery_result_read_metadata($1)`, resultID).Scan(
			&storedResultID, &artifactID, &ciphertext, &sizeBytes, &nonce, &wrappedDEK,
			&wrappedDEKHash, &kekReference, &kekVersion, &aadHash, &plaintextHash); err != nil {
			return err
		}
		if storedResultID != resultID || artifactID == "" {
			t.Fatalf("stored discovery envelope = result:%q artifact:%q", storedResultID, artifactID)
		}
		envelope = artifactcrypto.NewEnvelopeFromStorage(owner, artifactcrypto.CipherAES256GCM, ciphertext, sizeBytes,
			nonce, wrappedDEK, wrappedDEKHash, kekReference, kekVersion, aadHash, plaintextHash)
		return nil
	}); err != nil {
		t.Fatalf("read source discovery metadata: %v", err)
	}
	plaintext, err := codec.Open(artifactcrypto.OwnerIdentity{}, envelope)
	if err == nil {
		t.Fatal("discovery metadata opened with an unrelated owner")
	}
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceDiscoveryResultMetadata, access.OrganizationID, resultID)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = codec.Open(owner, envelope)
	if err != nil {
		t.Fatalf("decrypt source discovery metadata: %v", err)
	}
	defer func() {
		for index := range plaintext {
			plaintext[index] = 0
		}
	}()
	var metadata sourcediscovery.Metadata
	if err := jsonv2.Unmarshal(jsontext.Value(plaintext), &metadata, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		t.Fatalf("decode source discovery metadata: %v", err)
	}
	return metadata
}
