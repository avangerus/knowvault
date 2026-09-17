package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestKnowledgeGraphProjectionFromLiveIngestion proves that canonical graph
// rows are produced by the real source pipeline, not by a fixture-only INSERT.
// The same worker transaction that publishes Evidence creates a workspace-
// scoped entity and semantic catalog term, and the app resolver can read it
// only through the current RLS/retention chain.
func TestKnowledgeGraphProjectionFromLiveIngestion(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "kafka.txt"), []byte("Kafka is a message bus used by operations.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New).WithKnowledgeGraph(knowledgegraph.NewRepository())
	graphAccess := workerAccess(t, s1dOrg)
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, graphAccess, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "graph-live-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := queue.Claim(ctx, graphAccess, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim graph-live: %v ok=%v", err, ok)
	}
	if err := handler.Handle(ctx, graphAccess, claimed); err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("graph-live failure: %T: %v", cause, cause)
		}
		t.Fatal(fmt.Sprintf("handle graph-live: %v", err))
	}

	objectID, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	var entityCount, termCount, canonicalTerms, contextTerms int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.canonical_entity WHERE organization_id=$1 AND source_object_id=$2 AND source_version_id=$3`, s1dOrg, objectID, versionID).Scan(&entityCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.semantic_term WHERE organization_id=$1 AND source_object_id=$2 AND source_version_id=$3`, s1dOrg, objectID, versionID).Scan(&termCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE term_kind='CANONICAL'), count(*) FILTER (WHERE term_kind='CONTEXT') FROM public.semantic_term WHERE organization_id=$1 AND source_object_id=$2 AND source_version_id=$3`, s1dOrg, objectID, versionID).Scan(&canonicalTerms, &contextTerms); err != nil {
		t.Fatal(err)
	}
	if entityCount != 1 || termCount < 1 || canonicalTerms < 1 || contextTerms < 1 {
		t.Fatalf("live ingestion graph projection entity=%d terms=%d canonical=%d context=%d, want one entity with canonical and context terms", entityCount, termCount, canonicalTerms, contextTerms)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	_ = viewer
	graph := knowledgegraph.NewRepository()
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_graph_ingestion"}
	var matches []knowledgegraph.EntityMatch
	if err := appStore.Read(ctx, access, func(queryCtx context.Context, tx database.Transaction) error {
		var err error
		matches, err = graph.ResolveTerms(queryCtx, tx, access,
			knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"Kafka"}, Limit: 8})
		return err
	}); err != nil {
		t.Fatalf("resolve live-ingested semantic term: %v", err)
	}
	if len(matches) != 1 || matches[0].SourceVersionID != versionID || matches[0].EvidenceFragmentID == "" {
		t.Fatalf("live semantic resolution=%+v", matches)
	}
	var graphExtraction string
	if err := admin.QueryRow(ctx, `
		SELECT fragment.extraction_id
		  FROM public.canonical_entity entity
		  JOIN public.evidence_fragment fragment
		    ON fragment.organization_id=entity.organization_id
		   AND fragment.id=entity.evidence_fragment_id
		 WHERE entity.organization_id=$1 AND entity.source_version_id=$2`, s1dOrg, versionID).Scan(&graphExtraction); err != nil {
		t.Fatal(err)
	}
	if graphExtraction != extractionID {
		t.Fatalf("graph extraction=%s, active extraction=%s", graphExtraction, extractionID)
	}
}

// TestKnowledgeGraphSharedExplicitTermRelationLive proves that the graph
// projector creates a real cross-source edge only for an explicit canonical
// term assertion. Ordinary context-token overlap is not enough to create a
// relation, so this exercises the conservative ontology boundary end to end.
func TestKnowledgeGraphSharedExplicitTermRelationLive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte("Kafka means bus in operations.\n")
	if err := os.WriteFile(filepath.Join(fileDir, "contract.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "mail.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New).WithKnowledgeGraph(knowledgegraph.NewRepository())
	graphAccess := workerAccess(t, s1dOrg)
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, graphAccess, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "graph-shared-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := queue.Claim(ctx, graphAccess, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim graph-shared: %v ok=%v", err, ok)
	}
	if err := handler.Handle(ctx, graphAccess, claimed); err != nil {
		t.Fatalf("handle graph-shared: %v", err)
	}
	var relationCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.entity_relation WHERE organization_id=$1 AND predicate='context.mentions'`, s1dOrg).Scan(&relationCount); err != nil {
		t.Fatal(err)
	}
	if relationCount != 1 {
		t.Fatalf("shared explicit term relation count=%d, want 1", relationCount)
	}
	var workerCanExecute, appCanExecute, publicCanExecute bool
	if err := admin.QueryRow(ctx, `
		SELECT has_function_privilege('knowvault_worker', $1, 'EXECUTE'),
		       has_function_privilege('knowvault_app', $1, 'EXECUTE'),
		       has_function_privilege('public', $1, 'EXECUTE')`,
		"app.knowledge_graph_shared_term_targets(text,text,text)").Scan(
		&workerCanExecute, &appCanExecute, &publicCanExecute); err != nil {
		t.Fatal(err)
	}
	if !workerCanExecute || appCanExecute || publicCanExecute {
		t.Fatalf("shared-term target function privileges worker=%v app=%v public=%v",
			workerCanExecute, appCanExecute, publicCanExecute)
	}
	var subjectID, objectID, evidenceID string
	var relationSourceObjectID, relationSourceVersionID string
	var subjectSourceObjectID, subjectSourceVersionID, subjectEvidenceID string
	var objectSourceObjectID, objectSourceVersionID, objectEvidenceID string
	if err := admin.QueryRow(ctx, `
		SELECT relation.subject_entity_id, relation.object_entity_id, relation.evidence_fragment_id,
		       relation.source_object_id, relation.source_version_id,
		       subject_entity.source_object_id, subject_entity.source_version_id, subject_entity.evidence_fragment_id,
		       object_entity.source_object_id, object_entity.source_version_id, object_entity.evidence_fragment_id
		  FROM public.entity_relation relation
		  JOIN public.canonical_entity subject_entity
		    ON subject_entity.organization_id=relation.organization_id
		   AND subject_entity.id=relation.subject_entity_id
		  JOIN public.canonical_entity object_entity
		    ON object_entity.organization_id=relation.organization_id
		   AND object_entity.id=relation.object_entity_id
		 WHERE relation.organization_id=$1 AND relation.predicate='context.mentions'`, s1dOrg).Scan(
		&subjectID, &objectID, &evidenceID, &relationSourceObjectID, &relationSourceVersionID,
		&subjectSourceObjectID, &subjectSourceVersionID, &subjectEvidenceID,
		&objectSourceObjectID, &objectSourceVersionID, &objectEvidenceID); err != nil {
		t.Fatal(err)
	}
	if subjectID == objectID || evidenceID == "" || subjectSourceObjectID == "" || objectSourceObjectID == "" ||
		subjectSourceObjectID == objectSourceObjectID || subjectSourceVersionID == objectSourceVersionID ||
		subjectEvidenceID == "" || objectEvidenceID == "" || relationSourceObjectID == "" || relationSourceVersionID == "" {
		t.Fatalf("invalid shared relation subject=%q object=%q relation provenance=(%q,%q) subject provenance=(%q,%q,%q) object provenance=(%q,%q,%q)",
			subjectID, objectID, relationSourceObjectID, relationSourceVersionID,
			subjectSourceObjectID, subjectSourceVersionID, subjectEvidenceID,
			objectSourceObjectID, objectSourceVersionID, objectEvidenceID)
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	graph := knowledgegraph.NewRepository()
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_graph_shared"}
	traverse := func(readAccess database.AccessContext) []knowledgegraph.RelationMatch {
		t.Helper()
		var relations []knowledgegraph.RelationMatch
		if err := appStore.Read(ctx, readAccess, func(queryCtx context.Context, tx database.Transaction) error {
			var err error
			relations, err = graph.TraverseRelations(queryCtx, tx, readAccess, s1dWorkspace, []string{subjectID}, 8)
			return err
		}); err != nil {
			t.Fatalf("traverse shared relation through app RLS: %v", err)
		}
		return relations
	}
	relations := traverse(access)
	if len(relations) != 1 || relations[0].Predicate != "context.mentions" || relations[0].ObjectEntityID != objectID || relations[0].EvidenceFragmentID != evidenceID ||
		relations[0].SubjectSourceObjectID != subjectSourceObjectID || relations[0].SubjectSourceVersionID != subjectSourceVersionID ||
		relations[0].SubjectEvidenceFragmentID != subjectEvidenceID || relations[0].ObjectSourceObjectID != objectSourceObjectID ||
		relations[0].ObjectSourceVersionID != objectSourceVersionID || relations[0].ObjectEvidenceFragmentID != objectEvidenceID {
		t.Fatalf("shared relation projection or endpoint lineage=%+v", relations)
	}
	if denied := traverse(database.AccessContext{OrganizationID: s1dOrg, PrincipalID: "usr_not_a_member", RequestID: "req_graph_shared_denied"}); len(denied) != 0 {
		t.Fatalf("non-member saw shared relation=%+v", denied)
	}

	retentionObjectID, retentionVersionID := subjectSourceObjectID, subjectSourceVersionID
	if retentionObjectID == relationSourceObjectID {
		retentionObjectID, retentionVersionID = objectSourceObjectID, objectSourceVersionID
	}
	if retentionObjectID == relationSourceObjectID {
		t.Fatalf("relation provenance unexpectedly covers both endpoint source objects: relation=%q subject=%q object=%q", relationSourceObjectID, subjectSourceObjectID, objectSourceObjectID)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=false WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, retentionVersionID); err != nil {
		t.Fatalf("hide endpoint version retention: %v", err)
	}
	if hidden := traverse(access); len(hidden) != 0 {
		t.Fatalf("endpoint retention still exposed relation=%+v", hidden)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=true WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, retentionVersionID); err != nil {
		t.Fatalf("restore endpoint version retention: %v", err)
	}
	if restored := traverse(access); len(restored) != 1 {
		t.Fatalf("relation did not return after retention restore=%+v", restored)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_object_scope SET membership_state='REMOVED', removed_at=now()
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3 AND source_scope_revision=1`, s1dOrg, retentionObjectID, s1dScopeID); err != nil {
		t.Fatalf("revoke endpoint source membership: %v", err)
	}
	if hidden := traverse(access); len(hidden) != 0 {
		t.Fatalf("revoked endpoint membership still exposed relation=%+v", hidden)
	}
}
