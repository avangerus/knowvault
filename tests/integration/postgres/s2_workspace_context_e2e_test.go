package postgres_test

// S2 end-to-end acceptance: the owner's scenario for ADR-0098's workspace
// model context, wired exactly as composition/runtime.go wires it (card A's
// workspacecontext.Store as the shared Reader, card E's proposer.Store as
// the RunObserver/ProposalService, a local VersionMinter mirroring
// composition's own atomic adapter) against a real PostgreSQL and a
// scripted model over HTTP -- no mock database, no fake tool loop.
//
// It proves, in one flow:
//  1. PUT context with term МНО (Save) -> a tool-loop run whose question
//     contains МНО sees the rendered WORKSPACE_CONTEXT_JSON block (the
//     scripted model asserts this on every request) and its persisted
//     ToolLoopRecord.WorkspaceContext.Terms records the match.
//  2. A run whose question uses the unknown abbreviation КП while the
//     model's own knowvault_search tool call carries МНО in its arguments
//     creates a PROPOSED SYNONYM proposal candidate="КП", target=МНО's term
//     (S2-MODEL-CONTEXT-DESIGN.md "Proposer" SYNONYM signal), through the
//     real ObserveRun wiring question.Service.observeWorkspaceContextRun
//     installs (tool_loop.go), not a direct call into the proposer package.
//  3. Accepting that proposal (proposer.Store.Accept, through the same
//     VersionMinter atomicity contract composition uses) makes КП a synonym
//     of МНО in the next context version.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	"knowvault.local/verified-workspace/internal/workspacecontext/proposer"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// s2e2eVersionMinter mirrors composition/runtime.go's proposalVersionMinter
// exactly (minus its audit append, which is proved separately by the audit
// package and workspace_context_proposal_test.go): it is the same
// atomicity contract proposer/seams.go's VersionMinter documents, over the
// same card A Store.AcceptProposalVersion, so this test proves the real
// wiring shape composition uses, not a simplified stand-in.
type s2e2eVersionMinter struct {
	database *database.Store
	context  *workspacecontext.Store
}

func (minter *s2e2eVersionMinter) MintAcceptedVersion(
	ctx context.Context, access workspacecontext.Access, workspaceID, ifMatchHash string,
	document workspacecontext.Document, proposalID string,
	decideProposal func(ctx context.Context, tx database.Transaction, mintedVersion int64) error,
) (workspacecontext.Version, error) {
	dbAccess := database.AccessContext{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID}
	knownProjections, err := minter.context.KnownProjections(ctx, dbAccess, workspaceID)
	if err != nil {
		return workspacecontext.Version{}, err
	}
	var minted workspacecontext.Version
	err = minter.database.Write(ctx, dbAccess, func(ctx context.Context, tx database.Transaction) error {
		version, acceptErr := minter.context.AcceptProposalVersion(ctx, tx, dbAccess, workspaceID, document, knownProjections, ifMatchHash, proposalID)
		if acceptErr != nil {
			return acceptErr
		}
		if err := decideProposal(ctx, tx, version.Number); err != nil {
			return err
		}
		minted = version
		return nil
	})
	if err != nil {
		return workspacecontext.Version{}, err
	}
	return minted, nil
}

// s2e2eSearchRuntime is the minimal real workspacetools.Runtime this
// scenario needs: one knowledge tool (knowvault_search) the scripted model
// can call, with no evidence/source pipeline at all -- this test's subject
// is the workspace-context wiring, not retrieval, and a zero-hit search
// result is exactly what a real, empty-corpus workspace would return.
type s2e2eSearchRuntime struct{}

func (s2e2eSearchRuntime) Catalog(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
	return []workspacetools.Definition{{
		Name: "knowvault_search", Description: "search the workspace",
		Schema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
	}}, nil
}

func (s2e2eSearchRuntime) Invoke(context.Context, workspacetools.Scope, string, json.RawMessage) (workspacetools.Result, error) {
	return workspacetools.Result{Text: `{"hits":[]}`}, nil
}

func s2e2eIdempotencyKey(fill byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func TestS2WorkspaceContextEndToEndSynonymProposalAndAccept(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_s2e2e"
		ownerID        = "usr_s2e2e_owner"
		workspaceID    = "ws_s2e2e"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	// seedOrganization does not seed an organization_policy_revision row;
	// question.Service.start's admission read (service.go) inner-joins it
	// against organization.policy_revision (default 1), so a bare
	// seedOrganization leaves every questions.Create call QUESTION_DENIED
	// (the JOIN itself resolves no row). Mirror
	// catalog_evidence_seed_test.go's own fixture policy row.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ($1, 1, $2, $3, '2019-01-01T00:00:00Z', $4)
	`, organizationID, "policy-s2e2e-01ARZ3NDEKTSV4RRFFQ69G5FAV", "sha256:"+strings.Repeat("e", 64), ownerID); err != nil {
		t.Fatalf("seed organization policy revision: %v", err)
	}

	contextStore, workspaceStore, databaseStore := newModelContextTestStore(t, ctx)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	_ = workspaceStore

	owner := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_s2e2e_save"}

	// 1. PUT context with term МНО, no synonym yet.
	document := workspacecontext.Document{Glossary: []workspacecontext.Term{{Term: "МНО"}}}
	saved, err := contextStore.Save(ctx, owner, workspaceID, document, "sha256:empty", s2e2eIdempotencyKey(0x01))
	if err != nil {
		t.Fatalf("save initial context: %v", err)
	}
	if len(saved.Document.Glossary) != 1 || saved.Document.Glossary[0].Term != "МНО" {
		t.Fatalf("saved document = %#v", saved.Document)
	}
	mnoTermID := saved.Document.Glossary[0].ID
	if mnoTermID == "" {
		t.Fatal("server did not assign a term id")
	}

	// The real proposer, wired to the real store exactly like
	// composition.installWorkspaceContext wires it: card A's Store as
	// Reader, this test's VersionMinter for atomic accept, no
	// RunExcerptReader (examples are out of this scenario's scope).
	proposals := proposer.NewStore(databaseStore, contextStore, &s2e2eVersionMinter{database: databaseStore, context: contextStore}, nil)
	proposals.EnableAudit(auditStore)

	codec := s1dCodec(t, organizationID)
	viewer, err := evidence.NewViewer(databaseStore, codec)
	if err != nil {
		t.Fatalf("evidence viewer: %v", err)
	}
	questions, err := question.New(databaseStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatalf("question service: %v", err)
	}
	questions.EnableToolLoop(s2e2eSearchRuntime{})
	if err := questions.EnableWorkspaceContext(contextStore); err != nil {
		t.Fatalf("enable workspace context reader: %v", err)
	}
	if err := questions.EnableWorkspaceContextObserver(proposals); err != nil {
		t.Fatalf("enable workspace context observer: %v", err)
	}

	// scenario switches the scripted model's behavior between the two runs
	// below; systemMessagesSeen records every system message this test's
	// own assertion (every request must carry the rendered block) checked.
	scenario := "term-question"
	var systemMessagesSeen int
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Messages []modelgateway.Message        `json:"messages"`
			Tools    []modelgateway.ToolDefinition `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Errorf("bad model request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(input.Messages) == 0 || input.Messages[0].Role != "system" {
			t.Fatal("first message must be the system instructions")
		}
		system := input.Messages[0].Content
		if !strings.Contains(system, "WORKSPACE_CONTEXT_JSON") || !strings.Contains(system, "МНО") {
			t.Errorf("system message did not carry the rendered workspace context: %s", system)
		}
		systemMessagesSeen++

		message := map[string]any{"role": "assistant"}
		finish := "stop"
		last := input.Messages[len(input.Messages)-1]
		if scenario == "synonym-signal" && last.Role == "user" {
			args, _ := json.Marshal(map[string]any{"query": "МНО"})
			message["tool_calls"] = []any{map[string]any{
				"id": "search-1", "type": "function",
				"function": map[string]any{"name": "knowvault_search", "arguments": string(args)},
			}}
			finish = "tool_calls"
		} else {
			content, _ := json.Marshal(map[string]any{"no_data": true, "claims": []any{}})
			message["content"] = string(content)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   "s2-e2e-fixture",
			"choices": []any{map[string]any{"message": message, "finish_reason": finish}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		})
	}))
	defer model.Close()

	config := modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: model.URL, ModelID: "s2-e2e-fixture",
		MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{ID: "s2-e2e-loop", MaxTurns: 6, MaxToolCalls: 6, MaxInputBytes: 60000, MaxToolResultBytes: 16000, MaxOutputTokens: 2048, TimeoutSeconds: 60},
	}
	profiles, err := modelgateway.NewProfileRegistry("default", []modelgateway.ProfileConfig{{ID: "default", Label: "S2 e2e fixture", Config: config}})
	if err != nil {
		t.Fatalf("profile registry: %v", err)
	}
	defer profiles.Close()
	questions.EnableGeneration(profiles.Default(), nil)

	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_s2e2e_run1"}

	// --- Run 1: the question itself matches МНО. ---
	scenario = "term-question"
	run1, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: workspaceID, Question: "Что такое МНО?", IdempotencyKey: s2e2eIdempotencyKey(0x02),
	})
	if err != nil {
		t.Fatalf("create run1: %v", err)
	}
	if run1.ToolLoop == nil || run1.ToolLoop.WorkspaceContext == nil {
		t.Fatalf("run1 did not record a workspace_context trace: %#v", run1.ToolLoop)
	}
	trace := run1.ToolLoop.WorkspaceContext
	if trace.Version != saved.Number || trace.ContentHash != saved.ContentHash {
		t.Fatalf("run1 workspace_context pinned version = %d/%s, want %d/%s", trace.Version, trace.ContentHash, saved.Number, saved.ContentHash)
	}
	foundMNO := false
	for _, term := range trace.Terms {
		if term.TermID == mnoTermID && strings.EqualFold(term.Term, "МНО") {
			foundMNO = true
		}
	}
	if !foundMNO {
		t.Fatalf("run1 workspace_context.terms did not record МНО: %#v", trace.Terms)
	}

	// --- Run 2: the question uses the unknown abbreviation КП, while this
	// run's own knowvault_search tool call carries the known term МНО. ---
	scenario = "synonym-signal"
	access.RequestID = "req_s2e2e_run2"
	run2, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: workspaceID, Question: "Что означает КП по этому проекту?", IdempotencyKey: s2e2eIdempotencyKey(0x03),
	})
	if err != nil {
		t.Fatalf("create run2: %v", err)
	}
	if run2.ToolLoop == nil || len(run2.ToolLoop.Calls) == 0 {
		t.Fatalf("run2 did not record a knowvault_search call: %#v", run2.ToolLoop)
	}
	if systemMessagesSeen < 3 {
		t.Fatalf("expected at least 3 model requests (1 for run1, 2 for run2's search turn), got %d", systemMessagesSeen)
	}

	proposalAccess := workspacecontext.Access{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_s2e2e_proposals"}
	proposed, err := proposals.List(ctx, proposalAccess, workspaceID, workspacecontext.ProposalStatusProposed)
	if err != nil {
		t.Fatalf("list proposals: %v", err)
	}
	var synonymProposal *workspacecontext.Proposal
	for index := range proposed {
		if proposed[index].Kind == workspacecontext.ProposalKindSynonym &&
			strings.EqualFold(proposed[index].CandidateTerm, "КП") && proposed[index].TargetTermID == mnoTermID {
			synonymProposal = &proposed[index]
		}
	}
	if synonymProposal == nil {
		t.Fatalf("no SYNONYM proposal (КП -> МНО) among PROPOSED: %#v", proposed)
	}

	// --- Accept: КП becomes a synonym of МНО in the next version. ---
	accepted, err := proposals.Accept(ctx, proposalAccess, workspaceID, synonymProposal.ID, saved.ContentHash, workspacecontext.ProposalEdits{})
	if err != nil {
		t.Fatalf("accept proposal: %v", err)
	}
	if accepted.Number != saved.Number+1 {
		t.Fatalf("accepted version = %d, want %d", accepted.Number, saved.Number+1)
	}
	if len(accepted.Document.Glossary) != 1 {
		t.Fatalf("accepted glossary = %#v", accepted.Document.Glossary)
	}
	mno := accepted.Document.Glossary[0]
	if mno.ID != mnoTermID {
		t.Fatalf("accepted term id = %q, want %q (edit must not mint a second term)", mno.ID, mnoTermID)
	}
	hasKP := false
	for _, synonym := range mno.Synonyms {
		if strings.EqualFold(synonym, "КП") {
			hasKP = true
		}
	}
	if !hasKP {
		t.Fatalf("МНО.Synonyms after accept = %#v, want КП among them", mno.Synonyms)
	}

	// The proposal itself is now ACCEPTED, and current() reflects the new version.
	decided, err := proposals.Get(ctx, proposalAccess, workspaceID, synonymProposal.ID)
	if err != nil {
		t.Fatalf("get decided proposal: %v", err)
	}
	if decided.Status != workspacecontext.ProposalStatusAccepted {
		t.Fatalf("proposal status = %q, want ACCEPTED", decided.Status)
	}
	current, err := contextStore.Current(ctx, proposalAccess, workspaceID)
	if err != nil {
		t.Fatalf("read current context: %v", err)
	}
	if current.Number != accepted.Number || current.ContentHash != accepted.ContentHash {
		t.Fatalf("current context = %d/%s, want the just-accepted %d/%s", current.Number, current.ContentHash, accepted.Number, accepted.ContentHash)
	}
}
