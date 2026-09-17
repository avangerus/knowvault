package postgres_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestAllVersionsSearchFindsReadableSupersededEvidence proves the positive
// all_versions contract, not merely that old candidates do not fail the page.
// The original word occurs only in an immutable, retained historical version.
func TestAllVersionsSearchFindsReadableSupersededEvidence(t *testing.T) {
	const oldText = "historicalneedle original retained document\n"
	const newText = "currentneedle revised document\n"
	f := newExactEvidenceFixture(t, oldText)
	_, oldVersion, oldExtraction := s1dActiveEvidence(t, f.ctx, f.admin)
	oldFragment := s1dFragments(t, f.ctx, f.admin, oldExtraction)[0].id
	writeS1dFile(t, f.target, newText)
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "all-versions-new-current")
	historical, err := f.viewer.ReadObjectExactVersion(f.ctx, f.access, s1dWorkspace, oldFragment, oldVersion)
	if err != nil || string(historical.Text) != oldText {
		t.Fatalf("retained exact read: text=%q err=%v", historical.Text, err)
	}
	// No active index profile is attached: lexical fallback is the production
	// all_versions branch. The empty client is never used for external calls.
	executor, err := retrieval.NewExecutor(&search.Client{}, f.viewer)
	if err != nil {
		t.Fatal(err)
	}
	query := func(text string, all bool) retrieval.WorkspaceSearchPage {
		t.Helper()
		page, err := executor.SearchWorkspace(f.ctx, f.access, s1dWorkspace, text,
			retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: all, Limit: 20})
		if err != nil {
			t.Fatalf("search all_versions=%v: %v", all, err)
		}
		return page
	}
	if page := query("historicalneedle", false); len(page.Hits) != 0 {
		t.Fatalf("default search exposed %d historical hits", len(page.Hits))
	}
	if page := query("currentneedle", false); len(page.Hits) != 1 {
		t.Fatalf("current control: hits=%d want=1", len(page.Hits))
	}
	lexical, err := f.viewer.SearchFragments(f.ctx, f.access, s1dWorkspace, "historicalneedle", true, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	page := query("historicalneedle", true)
	t.Logf("exact_history_bytes=%d raw_all_versions_hits=%d workspace_all_versions_hits=%d current_control_hits=1 default_history_hits=0",
		len(historical.Text), len(lexical.Hits), len(page.Hits))
	if len(page.Hits) != 1 || page.Hits[0].Fragment.SourceVersionID != oldVersion || page.Hits[0].Fragment.FragmentID != oldFragment {
		t.Fatal("all_versions omitted a retained historical version readable by the same actor and workspace")
	}
	if page.Hits[0].VersionState != search.VersionStateSuperseded {
		t.Fatalf("historical hit mislabeled %s", page.Hits[0].VersionState)
	}
	if len(lexical.Hits) != 1 || lexical.Hits[0].Fragment.IsCurrentVersion ||
		string(page.Hits[0].Fragment.Text) != string(historical.Fragment.Text) ||
		page.Hits[0].Fragment.SourcePath == "" || page.Hits[0].Fragment.SourcePath != historical.Fragment.SourcePath {
		t.Fatal("historical search lost exact text, source path or live version provenance")
	}
	if page := query("document", false); len(page.Hits) != 1 || page.Hits[0].VersionState != search.VersionStateCurrent {
		t.Fatalf("default common-term search must contain only current evidence: %+v", page.Hits)
	}
	all := query("document", true)
	if len(all.Hits) != 2 || all.Hits[0].Fragment.SourceVersionID == all.Hits[1].Fragment.SourceVersionID {
		t.Fatalf("all_versions common-term search omitted or merged versions: %+v", all.Hits)
	}
	states := map[string]int{}
	for _, hit := range all.Hits {
		states[hit.VersionState]++
	}
	if states[search.VersionStateCurrent] != 1 || states[search.VersionStateSuperseded] != 1 {
		t.Fatalf("all_versions currency: %v", states)
	}
	first, err := executor.SearchWorkspace(f.ctx, f.access, s1dWorkspace, "document",
		retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: true, Limit: 1})
	if err != nil || len(first.Hits) != 1 || !first.HasMore || first.NextOffset != 1 {
		t.Fatalf("first history page: %+v %v", first, err)
	}
	second, err := executor.SearchWorkspace(f.ctx, f.access, s1dWorkspace, "document",
		retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: true, Limit: 1, Offset: first.NextOffset})
	if err != nil || len(second.Hits) != 1 || second.HasMore || first.Hits[0].Fragment.SourceVersionID == second.Hits[0].Fragment.SourceVersionID {
		t.Fatalf("history pagination repeated or lost a version: %+v %v", second, err)
	}
}

type allVersionsFixture struct {
	*exactEvidenceFixture
	executor      *retrieval.Executor
	old           evidence.FragmentVersionRef
	oldExtraction string
}

func newAllVersionsFixture(t *testing.T) allVersionsFixture {
	t.Helper()
	f := newExactEvidenceFixture(t, "historicalneedle original retained document\n")
	_, oldVersion, oldExtraction := s1dActiveEvidence(t, f.ctx, f.admin)
	oldFragment := s1dFragments(t, f.ctx, f.admin, oldExtraction)[0].id
	writeS1dFile(t, f.target, "currentneedle revised document\n")
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "all-versions-current")
	executor, err := retrieval.NewExecutor(&search.Client{}, f.viewer)
	if err != nil {
		t.Fatal(err)
	}
	result := allVersionsFixture{f, executor, evidence.FragmentVersionRef{FragmentID: oldFragment, SourceVersionID: oldVersion}, oldExtraction}
	page, err := executor.SearchWorkspace(f.ctx, f.access, s1dWorkspace, "historicalneedle",
		retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: true, Limit: 20})
	if err != nil || len(page.Hits) != 1 {
		t.Fatalf("history precondition hits=%d err=%v", len(page.Hits), err)
	}
	return result
}

func (f allVersionsFixture) assertHistoryDenied(t *testing.T, access database.AccessContext, workspaceID string) {
	t.Helper()
	// Reuse the pre-revocation references deliberately: cached candidate IDs
	// cannot authorize new bytes after any live authority or retention change.
	fragments, _ := f.viewer.AuthorizeFragmentVersions(f.ctx, access, workspaceID, []evidence.FragmentVersionRef{f.old})
	if len(fragments) != 0 {
		t.Fatal("final tuple authorization retained denied historical evidence")
	}
	page, _ := f.executor.SearchWorkspace(f.ctx, access, workspaceID, "historicalneedle",
		retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: true, Limit: 20})
	if len(page.Hits) != 0 || len(page.TermHits) != 0 {
		t.Fatal("denied history search returned content")
	}
	assertExactReadDenied(t, f.exactEvidenceFixture, access, workspaceID, f.old.FragmentID, f.old.SourceVersionID, "history search parity")
}

func (f allVersionsFixture) revokeSource(t *testing.T) {
	t.Helper()
	store := newAuthorityRuntime(t, f.ctx)
	owner := authorityAccess(f.authority, f.authority.ownerID, "req_history_remove_source")
	snapshot, err := store.Get(f.ctx, owner, s1dWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.RemoveSource(f.ctx, owner, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: authorityIdempotencyKey("history-remove-source"), WorkspaceID: s1dWorkspace,
		ExpectedWorkspaceRevision: snapshot.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, snapshot),
		WorkspaceSourceID: f.authority.workspaceSourceID, SourceScopeID: f.authority.sourceScopeID,
		SourceScopeRevision: f.authority.sourceScopeRevision, ScopeConfigHash: f.authority.scopeConfigHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllVersionsSearchLiveAuthorityAndRetention(t *testing.T) {
	cases := []struct {
		name  string
		close func(*testing.T, allVersionsFixture)
	}{
		{"workspace_source_removed", func(t *testing.T, f allVersionsFixture) { f.revokeSource(t) }},
		{"workspace_member_removed", func(t *testing.T, f allVersionsFixture) {
			store := newAuthorityRuntime(t, f.ctx)
			owner := authorityAccess(f.authority, f.authority.ownerID, "req_history_remove_member")
			snapshot, err := store.Get(f.ctx, owner, s1dWorkspace)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.RemoveMember(f.ctx, owner, workspacerepository.RemoveMemberRequest{
				IdempotencyKey: authorityIdempotencyKey("history-remove-member"), WorkspaceID: s1dWorkspace,
				ExpectedConfigurationHash: mustWorkspaceHash(t, snapshot), PrincipalID: s1dViewer,
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"confirmation_revoked", func(t *testing.T, f allVersionsFixture) {
			var id, hash string
			if err := f.admin.QueryRow(f.ctx, `SELECT confirmation_id, confirmation_hash
				FROM public.workspace_managed_grant_confirmation WHERE organization_id=$1 AND workspace_source_id=$2`,
				s1dOrg, f.authority.workspaceSourceID).Scan(&id, &hash); err != nil {
				t.Fatal(err)
			}
			_, err := newAuthorityRuntime(t, f.ctx).RevokeManagedConfirmation(f.ctx,
				authorityAccess(f.authority, f.authority.ownerID, "req_history_confirmation"), workspacerepository.RevokeConfirmationRequest{
					IdempotencyKey: authorityIdempotencyKey("history-confirmation"), OrganizationID: s1dOrg,
					WorkspaceID: s1dWorkspace, ConfirmationID: id, ConfirmationHash: hash, ExpectedPolicyRevision: f.authority.policyID,
				})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"actor_grant_revoked", func(t *testing.T, f allVersionsFixture) {
			var id, hash string
			var revision int64
			if err := f.admin.QueryRow(f.ctx, `SELECT g.grant_id, g.revision, g.grant_hash
				FROM public.workspace_source_confirmation_actor_grant g
				JOIN public.workspace_managed_grant_confirmation c ON c.organization_id=g.organization_id
				 AND c.confirmation_actor_grant_id=g.grant_id AND c.confirmation_actor_grant_revision=g.revision
				WHERE c.organization_id=$1 AND c.workspace_source_id=$2`, s1dOrg, f.authority.workspaceSourceID).
				Scan(&id, &revision, &hash); err != nil {
				t.Fatal(err)
			}
			_, err := newAuthorityRuntime(t, f.ctx).RevokeConfirmationGrant(f.ctx,
				authorityAccess(f.authority, f.authority.ownerID, "req_history_grant"), workspacerepository.RevokeGrantRequest{
					IdempotencyKey: authorityIdempotencyKey("history-grant"), OrganizationID: s1dOrg,
					WorkspaceID: s1dWorkspace, GrantID: id, GrantRevision: revision, GrantHash: hash, ExpectedPolicyRevision: f.authority.policyID,
				})
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"version_not_queryable", func(t *testing.T, f allVersionsFixture) {
			if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_version_retention SET queryable=false
				WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, f.old.SourceVersionID); err != nil {
				t.Fatal(err)
			}
		}},
		{"extraction_not_queryable", func(t *testing.T, f allVersionsFixture) {
			if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_extraction_retention SET queryable=false
				WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, f.oldExtraction); err != nil {
				t.Fatal(err)
			}
		}},
		{"object_not_queryable", func(t *testing.T, f allVersionsFixture) {
			if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_object SET queryable=false WHERE organization_id=$1`, s1dOrg); err != nil {
				t.Fatal(err)
			}
		}},
		{"source_observed_missing", func(t *testing.T, f allVersionsFixture) {
			// A completely empty snapshot is deliberately HELD, not evidence
			// of absence. Keep a real sibling throughout reconciliation.
			writeS1dFile(t, filepath.Join(filepath.Dir(f.target), "sentinel.txt"), "stable sentinel\n")
			runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "history-with-sentinel")
			if err := os.Remove(f.target); err != nil {
				t.Fatal(err)
			}
			runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "history-source-absent")
			var state string
			if err := f.admin.QueryRow(f.ctx, `SELECT o.lifecycle_state FROM public.source_object o
				JOIN public.source_version v ON v.organization_id=o.organization_id AND v.source_object_id=o.id
				WHERE v.organization_id=$1 AND v.id=$2`, s1dOrg, f.old.SourceVersionID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != "MISSING" {
				t.Fatalf("absence fixture state=%s, want MISSING", state)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAllVersionsFixture(t)
			tc.close(t, f)
			f.assertHistoryDenied(t, f.access, s1dWorkspace)
		})
	}
}

func TestAllVersionsSearchExactTupleAndTenantBoundaries(t *testing.T) {
	f := newAllVersionsFixture(t)
	_, currentVersion, _ := s1dActiveEvidence(t, f.ctx, f.admin)
	wrong := evidence.FragmentVersionRef{FragmentID: f.old.FragmentID, SourceVersionID: currentVersion}
	for _, refs := range [][]evidence.FragmentVersionRef{{wrong}, {f.old, wrong}} {
		got, _ := f.viewer.AuthorizeFragmentVersions(f.ctx, f.access, s1dWorkspace, refs)
		if len(got) != 0 {
			t.Fatal("mismatched or conflicting version tuple returned bytes")
		}
	}
	got, err := f.viewer.AuthorizeFragmentVersions(f.ctx, f.access, s1dWorkspace, []evidence.FragmentVersionRef{f.old, f.old})
	if err != nil || len(got) != 1 || got[0].SourceVersionID != f.old.SourceVersionID {
		t.Fatalf("duplicate exact tuple: %d %v", len(got), err)
	}
	outsider := f.access
	outsider.PrincipalID = "usr_history_outsider"
	f.assertHistoryDenied(t, outsider, s1dWorkspace)
	foreign := f.access
	foreign.OrganizationID, foreign.PrincipalID = "org_history_foreign", "usr_history_foreign"
	f.assertHistoryDenied(t, foreign, s1dWorkspace)
	f.assertHistoryDenied(t, f.access, "ws_history_unbound")
}

func TestAllVersionsSearchServiceRevocation(t *testing.T) {
	f := newAllVersionsFixture(t)
	db, journal, store := newServiceAccessCodeStores(t, f.ctx)
	codes, err := serviceprincipal.New(db, journal, store)
	if err != nil {
		t.Fatal(err)
	}
	owner := authorityAccess(f.authority, f.authority.ownerID, "req_history_service")
	issued, err := codes.Issue(f.ctx, owner, serviceprincipal.IssueRequest{Name: "history-agent", WorkspaceIDs: []string{s1dWorkspace},
		TTLSeconds: 3600, IdempotencyKey: workspaceIdempotencyKey("history-service")})
	if err != nil {
		t.Fatal(err)
	}
	access, err := codes.Authenticate(f.ctx, s1dOrg, issued.Code, "req_history_service_search")
	if err != nil || access.EffectiveActorKind() != database.ActorKindService {
		t.Fatalf("SERVICE authentication: %v", err)
	}
	page, err := f.executor.SearchWorkspace(f.ctx, access, s1dWorkspace, "historicalneedle",
		retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: true, Limit: 20})
	if err != nil || len(page.Hits) != 1 || page.Hits[0].VersionState != search.VersionStateSuperseded {
		t.Fatalf("SERVICE history: hits=%d %v", len(page.Hits), err)
	}
	if err := codes.Revoke(f.ctx, owner, issued.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := codes.Authenticate(f.ctx, s1dOrg, issued.Code, "req_history_revoked"); serviceprincipal.CodeOf(err) != serviceprincipal.CodeDenied {
		t.Fatalf("revoked credential authentication: %v", err)
	}
	// Even an AccessContext captured before revocation must no longer read.
	f.assertHistoryDenied(t, access, s1dWorkspace)
}

func TestAllVersionsSearchHistoricalPurgeKeepsCurrent(t *testing.T) {
	f := newAllVersionsFixture(t)
	purger, err := purge.NewPurger(openStore(t, f.ctx, purgerRole, "knowvault_purger"), time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(f.ctx, purgerAccess(), f.old.SourceVersionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatal(err)
	}
	f.assertHistoryDenied(t, f.access, s1dWorkspace)
	if _, err := purger.Cleanup(f.ctx, purgerAccess(), f.old.SourceVersionID); err != nil {
		t.Fatal(err)
	}
	if err := purger.CompletePurge(f.ctx, purgerAccess(), f.old.SourceVersionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatal(err)
	}
	f.assertHistoryDenied(t, f.access, s1dWorkspace)
	for _, all := range []bool{false, true} {
		page, err := f.executor.SearchWorkspace(f.ctx, f.access, s1dWorkspace, "currentneedle",
			retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeLexical, AllVersions: all, Limit: 20})
		if err != nil || len(page.Hits) != 1 || page.Hits[0].VersionState != search.VersionStateCurrent {
			t.Fatalf("purge disturbed current search all=%v hits=%d %v", all, len(page.Hits), err)
		}
	}
}

// The scoped channel is a deterministic scheduling point between lexical
// candidate reading and final authorization. It emits no text and calls no
// external service. Revocation is the real workspace authority operation.
type allVersionsRevokeVector struct{ revoke func() }

func (v *allVersionsRevokeVector) ProfileHash() string { return "sha256:" + strings.Repeat("a", 64) }
func (v *allVersionsRevokeVector) RetrieveVector(context.Context, database.AccessContext, string, string, string) (retrieval.ChannelResult, error) {
	panic("unscoped vector must not run")
}
func (v *allVersionsRevokeVector) RetrieveScopedVector(context.Context, database.AccessContext, string, string, string, []string, string) (retrieval.ChannelResult, error) {
	v.revoke()
	return retrieval.ChannelResult{Channel: retrieval.ChannelVector, CoverageComplete: true}, nil
}

func TestAllVersionsSearchRevocationBetweenChannelsAndFinalAuthorization(t *testing.T) {
	f := newAllVersionsFixture(t)
	called := false
	vector := &allVersionsRevokeVector{revoke: func() { called = true; f.revokeSource(t) }}
	repository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	worker := workerAccess(t, s1dOrg)
	if err := openStore(t, f.ctx, workerRole, "knowvault_worker").Write(f.ctx, worker, func(ctx context.Context, tx database.Transaction) error {
		return repository.EnsureMountedProfile(ctx, tx, worker, "history-race-profile", vector.ProfileHash(), 1, 1)
	}); err != nil {
		t.Fatal(err)
	}
	executor, err := retrieval.NewExecutorWithGraphAndVector(&search.Client{}, f.viewer,
		openStore(t, f.ctx, appRole, "knowvault_app"), knowledgegraph.NewRepository(), vector)
	if err != nil {
		t.Fatal(err)
	}
	page, err := executor.SearchWorkspace(f.ctx, f.access, s1dWorkspace, "historicalneedle",
		retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeHybrid, AllVersions: true, Limit: 20})
	if !called {
		t.Fatalf("revocation scheduling point did not run: %v", err)
	}
	if err != nil {
		t.Fatalf("final authorization should filter the revoked candidate: %v", err)
	}
	if len(page.Hits) != 0 || len(page.TermHits) != 0 {
		t.Fatal("already-read historical bytes survived live source revocation")
	}
}

func TestAllVersionsSearchRESTMCPHistoryParity(t *testing.T) {
	f := newAllVersionsFixture(t)
	authenticator, err := httpauth.New(kvA01TenantResolver{organizationID: s1dOrg},
		kvA01SessionResolver{organizationID: s1dOrg, principalID: s1dViewer, claims: kvA01Claims(t, s1dOrg, s1dViewer)})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := workspaceapi.NewWithQuestionsAndConversations(authenticator, newAuthorityRuntime(t, f.ctx), kvA01SourceService{},
		kvA03RelationViewer{Viewer: f.viewer}, kvA03QuestionService{}, kvA03ConversationService{})
	if err != nil {
		t.Fatal(err)
	}
	handler.EnableHybridSearch(f.executor, nil)
	token, csrf := kvA03Session(t)
	call := func(mcp, all bool) map[string]any {
		t.Helper()
		allText := "false"
		if all {
			allText = "true"
		}
		request := httptest.NewRequest(http.MethodGet, kvA01Origin+"/api/v1/workspaces/"+s1dWorkspace+"/tools/search?query=historicalneedle&all_versions="+allText+"&limit=20", nil)
		if mcp {
			request = httptest.NewRequest(http.MethodPost, kvA01Origin+"/api/v1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":"history-parity","method":"tools/call","params":{"name":"knowvault_search","arguments":{"workspace_id":"`+s1dWorkspace+`","query":"historicalneedle","all_versions":`+allText+`,"limit":20}}}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", kvA01Origin)
			request.Header.Set(httpauth.CSRFHeader, csrf)
		}
		request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("search transport mcp=%v status=%d %s", mcp, response.Code, response.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if mcp {
			result, ok := body["result"].(map[string]any)
			if !ok {
				t.Fatalf("MCP error: %s", response.Body.String())
			}
			body, ok = result["structuredContent"].(map[string]any)
			if !ok {
				t.Fatalf("MCP omitted structured page: %s", response.Body.String())
			}
		}
		return body
	}
	for _, all := range []bool{false, true} {
		rest, mcp := call(false, all), call(true, all)
		if !reflect.DeepEqual(rest["results"], mcp["results"]) {
			t.Fatalf("REST/MCP historical results differ: REST=%v MCP=%v", rest["results"], mcp["results"])
		}
		hits, _ := rest["results"].([]any)
		if !all {
			if len(hits) != 0 {
				t.Fatal("transport default exposed history")
			}
			continue
		}
		if len(hits) != 1 {
			t.Fatalf("transport historical hits=%d", len(hits))
		}
		hit := hits[0].(map[string]any)
		address, _ := hit["canonical_address"].(string)
		if hit["version_state"] != search.VersionStateSuperseded || !strings.Contains(address, f.old.SourceVersionID) || !strings.Contains(address, f.old.FragmentID) || hit["excerpt"] == "" {
			t.Fatalf("transport lost historical provenance/address: %v", hit)
		}
	}
	f.revokeSource(t)
	for _, mcp := range []bool{false, true} {
		body := call(mcp, true)
		if hits, _ := body["results"].([]any); len(hits) != 0 {
			t.Fatal("transport retained history after source removal")
		}
	}
}
