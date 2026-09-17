package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// TestKnowledgeGraphEvidenceWorkspaceIsolationAndRevocation exercises the
// graph on the real catalog, not a fixture-only unit seam.  The worker appends
// two entities, an edge and a semantic synonym; the application can read them
// only while the workspace source membership is active.  Revoking that source
// immediately removes every graph row from the app projection.
func TestKnowledgeGraphEvidenceWorkspaceIsolationAndRevocation(t *testing.T) {
	ctx, admin, _, extractionID, _ := s1ePurgeSetup(t)
	objectID, versionID, _ := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("graph fixture has no Evidence")
	}
	var workspaceRevision int64
	if err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace).Scan(&workspaceRevision); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	provenance := knowledgegraph.SourceProvenance{
		WorkspaceID: s1dWorkspace, WorkspaceRevision: workspaceRevision,
		SourceScopeID: s1dScopeID, SourceScopeRevision: 1,
		SourceObjectID: objectID, SourceVersionID: versionID,
		EvidenceFragmentID: fragments[0].id, ObservedAt: now, FreshnessAt: now,
	}
	entityA := knowledgegraph.Entity{
		OrganizationID: s1dOrg, ID: mustID(t, "entity"), EntityType: "PROCESS",
		CanonicalKeyHash: graphTestHash("a"), DisplayNameHash: graphTestHash("b"),
		AttributesJSON: []byte(`{"kind":"process"}`), SourceProvenance: provenance,
	}
	entityB := knowledgegraph.Entity{
		OrganizationID: s1dOrg, ID: mustID(t, "entity"), EntityType: "CODE_SYMBOL",
		CanonicalKeyHash: graphTestHash("c"), DisplayNameHash: graphTestHash("d"),
		AttributesJSON: []byte(`{"kind":"symbol"}`), SourceProvenance: provenance,
	}
	entityC := knowledgegraph.Entity{
		OrganizationID: s1dOrg, ID: mustID(t, "entity"), EntityType: "PROCESS",
		CanonicalKeyHash: graphTestHash("e"), DisplayNameHash: graphTestHash("0"),
		AttributesJSON: []byte(`{"kind":"second-process"}`), SourceProvenance: provenance,
	}
	relation := knowledgegraph.Relation{
		OrganizationID: s1dOrg, ID: mustID(t, "relation"), SubjectEntityID: entityA.ID,
		Predicate: "process.implemented_by", ObjectEntityID: entityB.ID, Confidence: 0.9,
		AttributesJSON: []byte(`{"source":"code"}`), SourceProvenance: provenance,
	}
	termHash, err := knowledgegraph.SemanticTermHash("Kafka")
	if err != nil {
		t.Fatal(err)
	}
	contextHash, err := knowledgegraph.SemanticTermHash("operations")
	if err != nil {
		t.Fatal(err)
	}
	term := knowledgegraph.SemanticTerm{
		OrganizationID: s1dOrg, ID: mustID(t, "term"), CanonicalEntityID: entityA.ID,
		TermKind: "SYNONYM", Language: "ru", TermHash: termHash,
		ContextHash: graphTestHash("f"), Confidence: 0.8,
		AttributesJSON: []byte(`{"context":"kafka"}`), SourceProvenance: provenance,
	}
	ambiguousTerm := knowledgegraph.SemanticTerm{
		OrganizationID: s1dOrg, ID: mustID(t, "term"), CanonicalEntityID: entityC.ID,
		TermKind: "ABBREVIATION", Language: "en", TermHash: termHash,
		Confidence: 0.7, AttributesJSON: []byte(`{"definition":"second kafka meaning"}`), SourceProvenance: provenance,
	}
	contextTermA := knowledgegraph.SemanticTerm{
		OrganizationID: s1dOrg, ID: mustID(t, "term"), CanonicalEntityID: entityA.ID,
		TermKind: "CONTEXT", Language: "en", TermHash: contextHash,
		Confidence: 0.4, AttributesJSON: []byte(`{"context":"operations"}`), SourceProvenance: provenance,
	}
	contextTermB := knowledgegraph.SemanticTerm{
		OrganizationID: s1dOrg, ID: mustID(t, "term"), CanonicalEntityID: entityB.ID,
		TermKind: "CONTEXT", Language: "en", TermHash: contextHash,
		Confidence: 0.3, AttributesJSON: []byte(`{"context":"operations"}`), SourceProvenance: provenance,
	}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	graphRepository := knowledgegraph.NewRepository()
	workerAccessContext := workerAccess(t, s1dOrg)
	if err := workerStore.Write(ctx, workerAccessContext, func(txContext context.Context, transaction database.Transaction) error {
		if err := graphRepository.CreateEntity(txContext, transaction, workerAccessContext, entityA); err != nil {
			return err
		}
		if err := graphRepository.CreateEntity(txContext, transaction, workerAccessContext, entityB); err != nil {
			return err
		}
		if err := graphRepository.CreateEntity(txContext, transaction, workerAccessContext, entityC); err != nil {
			return err
		}
		if err := graphRepository.CreateRelation(txContext, transaction, workerAccessContext, relation); err != nil {
			return err
		}
		if err := graphRepository.CreateSemanticTerm(txContext, transaction, workerAccessContext, term); err != nil {
			return err
		}
		if err := graphRepository.CreateSemanticTerm(txContext, transaction, workerAccessContext, ambiguousTerm); err != nil {
			return err
		}
		if err := graphRepository.CreateSemanticTerm(txContext, transaction, workerAccessContext, contextTermA); err != nil {
			return err
		}
		return graphRepository.CreateSemanticTerm(txContext, transaction, workerAccessContext, contextTermB)
	}); err != nil {
		t.Fatalf("append graph rows through worker repository: %v cause=%v (code=%s)", err, errors.Unwrap(err), knowledgegraph.CodeOf(err))
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	readCount := func(principal string) int64 {
		t.Helper()
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, principal)
		var count int64
		if err := tx.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM public.canonical_entity)
			     + (SELECT count(*) FROM public.entity_relation)
			     + (SELECT count(*) FROM public.semantic_term)`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if got := readCount(s1dOwner); got != 8 {
		t.Fatalf("workspace member saw graph rows=%d, want 8", got)
	}
	if got := readCount("usr_not_a_member"); got != 0 {
		t.Fatalf("non-member saw graph rows=%d, want 0", got)
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	var termMatches []knowledgegraph.EntityMatch
	var detailedResolution knowledgegraph.TermResolution
	var contextResolution knowledgegraph.TermResolution
	var relationMatches []knowledgegraph.RelationMatch
	appAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_graph_query"}
	if err := appStore.Read(ctx, appAccess, func(queryCtx context.Context, tx database.Transaction) error {
		var err error
		termMatches, err = graphRepository.ResolveTerms(queryCtx, tx, appAccess,
			knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"kafka"}, Limit: 8})
		if err != nil {
			return err
		}
		detailedResolution, err = graphRepository.ResolveTermsDetailed(queryCtx, tx, appAccess,
			knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"kafka"}, Limit: 1})
		if err != nil {
			return err
		}
		contextResolution, err = graphRepository.ResolveTermsDetailed(queryCtx, tx, appAccess,
			knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"operations"}, Limit: 8})
		if err != nil {
			return err
		}
		relationMatches, err = graphRepository.TraverseRelations(queryCtx, tx, appAccess,
			s1dWorkspace, []string{entityA.ID}, 8)
		return err
	}); err != nil {
		t.Fatalf("resolve semantic term and relation through app RLS: %v", err)
	}
	if len(termMatches) != 2 {
		t.Fatalf("semantic resolution=%+v", termMatches)
	}
	for _, match := range termMatches {
		if match.SourceObjectID != objectID || match.SourceVersionID != versionID ||
			match.ExtractionID != extractionID || match.EvidenceFragmentID != fragments[0].id {
			t.Fatalf("semantic evidence lineage=%+v", match)
		}
	}
	if len(detailedResolution.Matches) != 1 || len(detailedResolution.AmbiguousTermHashes) != 1 ||
		detailedResolution.AmbiguousTermHashes[0] != termHash || len(detailedResolution.TruncatedTermHashes) != 1 ||
		detailedResolution.TruncatedTermHashes[0] != termHash || !detailedResolution.Incomplete() {
		t.Fatalf("limit-truncated explicit ambiguity=%+v", detailedResolution)
	}
	if len(contextResolution.Matches) != 2 || len(contextResolution.AmbiguousTermHashes) != 0 ||
		len(contextResolution.TruncatedTermHashes) != 0 || contextResolution.Incomplete() {
		t.Fatalf("context overlap became ontology ambiguity=%+v", contextResolution)
	}
	deniedAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: "usr_not_a_member", RequestID: "req_graph_denied"}
	if err := appStore.Read(ctx, deniedAccess, func(queryCtx context.Context, tx database.Transaction) error {
		resolution, err := graphRepository.ResolveTermsDetailed(queryCtx, tx, deniedAccess,
			knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"kafka"}, Limit: 1})
		if err != nil {
			return err
		}
		if len(resolution.Matches) != 0 || resolution.Incomplete() {
			t.Fatalf("non-member semantic resolution=%+v", resolution)
		}
		return nil
	}); err != nil {
		t.Fatalf("non-member semantic resolution: %v", err)
	}
	if len(relationMatches) != 1 || relationMatches[0].ObjectEntityID != entityB.ID || relationMatches[0].EvidenceFragmentID != fragments[0].id {
		t.Fatalf("relation traversal=%+v", relationMatches)
	}
	// Retention is part of the graph authorization boundary, not a background
	// cleanup detail.  Turning either the source version or its extraction
	// non-queryable must immediately hide all derived rows.
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention
		SET queryable=false WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
		t.Fatalf("revoke source-version retention: %v", err)
	}
	if got := readCount(s1dOwner); got != 0 {
		t.Fatalf("non-queryable source version still exposed graph rows=%d", got)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention
		SET queryable=true WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
		t.Fatalf("restore source-version retention: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_extraction_retention
		SET queryable=false WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, extractionID); err != nil {
		t.Fatalf("revoke extraction retention: %v", err)
	}
	if got := readCount(s1dOwner); got != 0 {
		t.Fatalf("non-queryable extraction still exposed graph rows=%d", got)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_extraction_retention
		SET queryable=true WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, extractionID); err != nil {
		t.Fatalf("restore extraction retention: %v", err)
	}

	if _, err := admin.Exec(ctx, `UPDATE public.canonical_entity SET canonical_key_hash=$1 WHERE organization_id=$2 AND id=$3`, graphTestHash("0"), s1dOrg, entityA.ID); err == nil {
		t.Fatal("canonical entity identity accepted an UPDATE")
	} else {
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "55000" {
			t.Fatalf("canonical entity UPDATE rejected for wrong reason: %v", err)
		}
	}

	if _, err := admin.Exec(ctx, `UPDATE public.source_object_scope SET membership_state='REMOVED', removed_at=now()
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3 AND source_scope_revision=1`, s1dOrg, objectID, s1dScopeID); err != nil {
		t.Fatalf("revoke source membership: %v", err)
	}
	if got := readCount(s1dOwner); got != 0 {
		t.Fatalf("revoked source still exposed graph rows=%d", got)
	}
	if err := appStore.Read(ctx, appAccess, func(queryCtx context.Context, tx database.Transaction) error {
		matches, err := graphRepository.ResolveTerms(queryCtx, tx, appAccess,
			knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"kafka"}, Limit: 8})
		if err != nil {
			return err
		}
		if len(matches) != 0 {
			t.Fatalf("revoked source semantic matches=%+v", matches)
		}
		return nil
	}); err != nil {
		t.Fatalf("resolve revoked graph rows: %v", err)
	}
}

// TestKnowledgeGraphPhysicalPurgePropagation proves the second half of the
// lifecycle boundary: after the real purger commits PURGED, graph rows are
// removed in the same transaction, not merely hidden by RLS.
func TestKnowledgeGraphPhysicalPurgePropagation(t *testing.T) {
	ctx, admin, versionID, extractionID, purger := s1ePurgeSetup(t)
	var objectID, fragmentID string
	if err := admin.QueryRow(ctx, `SELECT source_object_id FROM public.source_version
		WHERE organization_id=$1 AND id=$2`, s1dOrg, versionID).Scan(&objectID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT id FROM public.evidence_fragment
		WHERE organization_id=$1 AND extraction_id=$2 ORDER BY ordinal LIMIT 1`, s1dOrg, extractionID).Scan(&fragmentID); err != nil {
		t.Fatal(err)
	}
	var workspaceRevision int64
	if err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace
		WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace).Scan(&workspaceRevision); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	entity := knowledgegraph.Entity{
		OrganizationID: s1dOrg, ID: mustID(t, "entity"), EntityType: "CONTROL",
		CanonicalKeyHash: graphTestHash("1"), DisplayNameHash: graphTestHash("2"),
		AttributesJSON: []byte(`{"kind":"purge-test"}`), SourceProvenance: knowledgegraph.SourceProvenance{
			WorkspaceID: s1dWorkspace, WorkspaceRevision: workspaceRevision,
			SourceScopeID: s1dScopeID, SourceScopeRevision: 1,
			SourceObjectID: objectID, SourceVersionID: versionID,
			EvidenceFragmentID: fragmentID, ObservedAt: now, FreshnessAt: now,
		},
	}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerAccessContext := workerAccess(t, s1dOrg)
	if err := workerStore.Write(ctx, workerAccessContext, func(txContext context.Context, transaction database.Transaction) error {
		return knowledgegraph.NewRepository().CreateEntity(txContext, transaction, workerAccessContext, entity)
	}); err != nil {
		t.Fatalf("append purge graph row: %v", err)
	}
	var before int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.canonical_entity
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 1 {
		t.Fatalf("graph rows before purge=%d, want 1", before)
	}
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "GRAPH_PURGE_TEST"); err != nil {
		t.Fatalf("begin purge: %v", err)
	}
	if _, err := purger.Cleanup(ctx, purgerAccess(), versionID); err != nil {
		t.Fatalf("cleanup purge: %v", err)
	}
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "GRAPH_PURGE_TEST"); err != nil {
		t.Fatalf("complete purge: %v", err)
	}
	var after int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.canonical_entity
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Fatalf("graph rows after PURGED=%d, want 0", after)
	}
}

func graphTestHash(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
