package postgres_test

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
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// TestPostgreSQLQueryGroupedSearchRowsThroughS3Index exercises the complete
// structured-row path with a real external PostgreSQL projection and the same
// in-process index transport used by the S3 controls.  Each row has sixteen
// evidence cells, but publication must create one indexed retrieval card per
// row.  Search then returns the two matching service_name cells, not one hit
// per timestamp or per other cell in those cards.  All candidate fragment
// rights are checked before the page and each selected address is read again
// through the live viewer.
func TestPostgreSQLQueryGroupedSearchRowsThroughS3Index(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the grouped PGQ search proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())

	const schema = "kv_pgq_grouped_search"
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_grouped_search" CASCADE;
		CREATE SCHEMA "kv_pgq_grouped_search";
		CREATE TABLE "kv_pgq_grouped_search"."service_rows" (
			service_id uuid NOT NULL,
			observed_at timestamptz NOT NULL,
			service_name text NOT NULL,
			region text NOT NULL,
			priority text NOT NULL,
			owner_name text NOT NULL,
			status text NOT NULL,
			category text NOT NULL,
			queue_name text NOT NULL,
			channel text NOT NULL,
			team text NOT NULL,
			site text NOT NULL,
			language text NOT NULL,
			sla text NOT NULL,
			ticket text NOT NULL,
			notes text NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("seed external grouped PGQ table: %v", err)
	}
	alphaObserved := time.Date(2026, 9, 14, 9, 34, 56, 789000000, time.UTC)
	betaObserved := time.Date(2026, 9, 14, 10, 34, 56, 789000000, time.UTC)
	_, err = external.Exec(ctx, `
		INSERT INTO "kv_pgq_grouped_search"."service_rows"
			(service_id, observed_at, service_name, region, priority, owner_name, status,
			 category, queue_name, channel, team, site, language, sla, ticket, notes)
		VALUES
			($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16),
			($17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)
	`,
		"550e8400-e29b-41d4-a716-446655440070", alphaObserved, "service-alpha", "north", "P1", "alice", "open",
		"payments", "priority", "email", "platform", "dc-a", "ru", "4h", "INC-070", "alpha service record",
		"550e8400-e29b-41d4-a716-446655440071", betaObserved, "service-beta", "south", "P2", "boris", "closed",
		"identity", "standard", "api", "core", "dc-b", "en", "8h", "INC-071", "beta service record",
	)
	if err != nil {
		t.Fatalf("seed external grouped PGQ rows: %v", err)
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_grouped_search"."service_view" AS
			SELECT service_id, observed_at, service_name, region, priority, owner_name, status,
			       category, queue_name, channel, team, site, language, sla, ticket, notes
		      FROM "kv_pgq_grouped_search"."service_rows"
	`); err != nil {
		t.Fatalf("create external grouped PGQ view: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_grouped_search" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := s3GroupedPostgreSQLProjectionRequest(schema)
	registered, err := service.Register(ctx, regOwnerAccess("req_s3_grouped_register"), request)
	if err != nil {
		t.Fatalf("register grouped PGQ source: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	workspaceBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FC1")
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, workspaceBinding, "s3-grouped-search-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(workspaceBinding, workspaceBinding.ownerID, "req_s3_grouped_confirm"), confirmRuntimeRequest(workspaceBinding, grant, "s3-grouped-search-confirm")); err != nil {
		t.Fatalf("confirm grouped PGQ workspace source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue := mustQueue(t, workerStore)
	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatalf("grouped search repository: %v", err)
	}
	profile := s3EmbeddingProfile(t)
	embeddingClient, err := embedding.New(profile, s3TrustRoots(), nil, &http.Client{Transport: s3EmbeddingTransport{t: t}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("grouped embedding client: %v", err)
	}
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-registration-v1", OrganizationID: regOrg,
		Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(),
		VectorProfileHash: profile.ProfileHash, VectorDimension: s3Dimension,
		HTTPClient: &http.Client{Transport: index, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("grouped search client: %v", err)
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
		t.Fatalf("activate grouped search profile: %v", err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New).
		WithSearchRepository(searchRepository)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, registered, request, "s3-grouped-search")

	applier, err := search.NewApplierWithEmbedding(workerStore, searchRepository, codec, searchClient, embeddingClient)
	if err != nil {
		t.Fatalf("grouped search applier: %v", err)
	}
	applied, err := applier.Drain(ctx, workerAccessContext, 10)
	if err != nil || applied != 2 {
		t.Fatalf("grouped search applier drained %d events: %v", applied, err)
	}
	fragmentIDs := s3GroupedIndexFragmentIDs(t, index)
	if len(fragmentIDs) != 32 {
		t.Fatalf("grouped index fragment cardinality=%d, want 32 (2 rows x 16 cells)", len(fragmentIDs))
	}

	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatalf("grouped search viewer: %v", err)
	}
	access := regOwnerAccess("req_s3_grouped_search")
	scopes, err := viewer.AuthorizedScopeIDs(ctx, access, workspaceBinding.workspaceID)
	if err != nil || len(scopes) != 1 || scopes[0] != registered.SourceScopeID {
		t.Fatalf("authorized grouped scopes=%v err=%v, want %q", scopes, err, registered.SourceScopeID)
	}
	authorized, err := viewer.AuthorizeFragments(ctx, access, workspaceBinding.workspaceID, fragmentIDs)
	if err != nil {
		t.Fatalf("authorize grouped indexed fragments: %v", err)
	}
	if len(authorized) != len(fragmentIDs) {
		t.Fatalf("authorized grouped fragments=%d, want %d", len(authorized), len(fragmentIDs))
	}
	for _, fragment := range authorized {
		if fragment.SourcePath == "" || !strings.HasPrefix(fragment.SourcePath, "postgresql-query/"+request.LineageID+"/") {
			t.Fatalf("authorized grouped fragment missing source path: %#v", fragment)
		}
	}

	executor, err := retrieval.NewExecutorWithGraph(searchClient, viewer, appStore, knowledgegraph.NewRepository())
	if err != nil {
		t.Fatalf("grouped search executor: %v", err)
	}
	page, err := executor.SearchWorkspace(ctx, access, workspaceBinding.workspaceID, "service", retrieval.WorkspaceSearchOptions{
		Mode: retrieval.SearchModeLexical, Limit: 10,
	})
	if err != nil {
		t.Fatalf("grouped SearchWorkspace: %v", err)
	}
	if page.Partial {
		t.Fatal("grouped SearchWorkspace returned a partial page")
	}
	if len(page.Hits) != 2 {
		t.Fatalf("grouped SearchWorkspace hits=%d, want two row groups", len(page.Hits))
	}
	seenObjects := make(map[string]struct{}, len(page.Hits))
	seenServices := make(map[string]struct{}, len(page.Hits))
	for _, hit := range page.Hits {
		text := string(hit.Fragment.Text)
		if hit.Fragment.ObjectType != "POSTGRESQL_QUERY_ROW" || hit.Fragment.Ordinal != 3 {
			t.Fatalf("grouped hit provenance=%#v, want PostgreSQL row service_name cell ordinal 3", hit.Fragment)
		}
		if !strings.Contains(text, "service_name = service-") || strings.Contains(text, "observed_at =") {
			t.Fatalf("grouped hit selected wrong cell text=%q", text)
		}
		if !strings.HasPrefix(hit.Fragment.SourcePath, "postgresql-query/"+request.LineageID+"/") || len(hit.Fragment.Anchor) == 0 {
			t.Fatalf("grouped hit address/provenance=%#v", hit.Fragment)
		}
		readback, err := viewer.Read(ctx, access, workspaceBinding.workspaceID, hit.Fragment.FragmentID)
		if err != nil {
			t.Fatalf("read grouped search address %q: %v", hit.Fragment.FragmentID, err)
		}
		if string(readback.Text) != text || string(readback.Anchor) != string(hit.Fragment.Anchor) ||
			readback.SourcePath != hit.Fragment.SourcePath || readback.SourceObjectID != hit.Fragment.SourceObjectID {
			t.Fatalf("grouped readback=%#v, want search hit=%#v", readback, hit.Fragment)
		}
		seenObjects[hit.Fragment.SourceObjectID] = struct{}{}
		seenServices[text] = struct{}{}
	}
	if len(seenObjects) != 2 || len(seenServices) != 2 {
		t.Fatalf("grouped result identities objects=%d services=%d, want two distinct rows", len(seenObjects), len(seenServices))
	}
}

func s3GroupedPostgreSQLProjectionRequest(schema string) registration.RegisterRequest {
	textColumn := func(ordinal int, name string, roles ...postgresqlquery.Role) postgresqlquery.Column {
		return postgresqlquery.Column{Ordinal: ordinal, Name: name, TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: roles, MaxBytes: 256}
	}
	return registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: "S3 grouped service rows", Kind: "business-object",
		DatabaseIdentity: "cluster-s3-grouped", LineageID: "s3-grouped-lineage", ProjectionRevision: 1,
		ContractHash: "sha256:" + strings.Repeat("7", 64), SchemaName: schema, RelationName: "service_view", RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "service_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity, postgresqlquery.RoleEvidence}, MaxBytes: 64},
			{Ordinal: 2, Name: "observed_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint, postgresqlquery.RoleEvidence}, Precision: 3, MaxBytes: 64},
			textColumn(3, "service_name", postgresqlquery.RoleTitle, postgresqlquery.RoleEvidence),
			textColumn(4, "region", postgresqlquery.RoleEvidence),
			textColumn(5, "priority", postgresqlquery.RoleEvidence),
			textColumn(6, "owner_name", postgresqlquery.RoleEvidence),
			textColumn(7, "status", postgresqlquery.RoleStatus, postgresqlquery.RoleEvidence),
			textColumn(8, "category", postgresqlquery.RoleEvidence),
			textColumn(9, "queue_name", postgresqlquery.RoleEvidence),
			textColumn(10, "channel", postgresqlquery.RoleEvidence),
			textColumn(11, "team", postgresqlquery.RoleEvidence),
			textColumn(12, "site", postgresqlquery.RoleEvidence),
			textColumn(13, "language", postgresqlquery.RoleEvidence),
			textColumn(14, "sla", postgresqlquery.RoleEvidence),
			textColumn(15, "ticket", postgresqlquery.RoleEvidence),
			textColumn(16, "notes", postgresqlquery.RoleEvidence),
		},
	}
}

func s3GroupedIndexFragmentIDs(t *testing.T, index *s3IndexTransport) []string {
	t.Helper()
	index.mutex.Lock()
	documents := make([]map[string]any, 0, len(index.documents))
	for _, document := range index.documents {
		documents = append(documents, document)
	}
	index.mutex.Unlock()
	if len(documents) != 2 {
		t.Fatalf("grouped index documents=%d, want 2", len(documents))
	}
	all := make([]string, 0, 32)
	seen := make(map[string]struct{}, 32)
	for _, document := range documents {
		ids := s3GroupedStringArray(t, document, "evidence_fragment_ids")
		textHashes := s3GroupedStringArray(t, document, "evidence_text_hashes")
		anchorHashes := s3GroupedStringArray(t, document, "evidence_anchor_hashes")
		if len(ids) != 16 || len(textHashes) != len(ids) || len(anchorHashes) != len(ids) {
			t.Fatalf("grouped index evidence arrays ids=%d text_hashes=%d anchor_hashes=%d, want 16 aligned", len(ids), len(textHashes), len(anchorHashes))
		}
		for _, id := range ids {
			if _, duplicate := seen[id]; duplicate {
				t.Fatalf("grouped index repeated fragment id %q", id)
			}
			seen[id] = struct{}{}
			all = append(all, id)
		}
	}
	return all
}

func s3GroupedStringArray(t *testing.T, document map[string]any, field string) []string {
	t.Helper()
	raw, ok := document[field].([]any)
	if !ok {
		t.Fatalf("grouped index field %q type=%T, want []any", field, document[field])
	}
	values := make([]string, len(raw))
	for index, value := range raw {
		text, ok := value.(string)
		if !ok || text == "" {
			t.Fatalf("grouped index field %q[%d]=%#v, want non-empty string", field, index, value)
		}
		values[index] = text
	}
	return values
}
