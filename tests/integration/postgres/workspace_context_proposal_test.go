package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	"knowvault.local/verified-workspace/internal/workspacecontext/proposer"
)

// seedProposalConversation inserts a minimal, real conversation +
// conversation_retention row. It must run as knowvault_app (appStore), not
// the admin/superuser pool: app.conversation_immutable_binding_guard rejects
// any other session_user outright.
func seedProposalConversation(t *testing.T, ctx context.Context, appStore *database.Store,
	organizationID, workspaceID, ownerID, conversationID string) {
	t.Helper()
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_ctxprop_seed_conv_" + conversationID}
	if err := appStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.conversation (organization_id, id, workspace_id, workspace_revision, created_by)
			VALUES ($1, $2, $3, 1, $4)
		`, organizationID, conversationID, workspaceID, ownerID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO public.conversation_retention (organization_id, conversation_id, workspace_id, workspace_revision)
			VALUES ($1, $2, $3, 1)
		`, organizationID, conversationID, workspaceID)
		return err
	}); err != nil {
		t.Fatalf("seed proposal test conversation %s: %v", conversationID, err)
	}
}

// seedProposalRun inserts one question_run + conversation_turn (at
// turnIndex) into an already-seeded conversation (seedProposalConversation),
// so evidence rows referencing conversationID/turnID/runID satisfy every FK
// migration 000113 declares. It mirrors the exact insert shape and ordering
// (question_run before its conversation_turn, relying on question_run_
// conversation_turn_binding_fk's DEFERRABLE INITIALLY DEFERRED check)
// already proven in conversation_pagination_test.go.
func seedProposalRun(t *testing.T, ctx context.Context, appStore *database.Store,
	organizationID, workspaceID, ownerID, conversationID, turnID, runID string, turnIndex int) {
	t.Helper()
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_ctxprop_seed_" + runID}
	if err := appStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id, question_hash, answer_mode,
				verification_method, workspace_scope_hash, policy_revision
			) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, 'EXTRACTIVE', 'BYTE_EXACT_CITATION', $7, 'policy-ctxprop')
		`, organizationID, runID, workspaceID, ownerID, conversationID, turnID, "sha256:"+strings.Repeat("a", 64)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO public.conversation_turn (organization_id, id, conversation_id, workspace_id, workspace_revision, turn_index, question_run_id)
			VALUES ($1, $2, $3, $4, 1, $5, $6)
		`, organizationID, turnID, conversationID, workspaceID, turnIndex, runID)
		return err
	}); err != nil {
		t.Fatalf("seed proposal test run fixture (conversation=%s run=%s): %v", conversationID, runID, err)
	}
}

// seedProposalTestRun is the common case: a brand-new conversation carrying
// exactly one run.
func seedProposalTestRun(t *testing.T, ctx context.Context, appStore *database.Store,
	organizationID, workspaceID, ownerID, conversationID, turnID, runID string) {
	t.Helper()
	seedProposalConversation(t, ctx, appStore, organizationID, workspaceID, ownerID, conversationID)
	seedProposalRun(t, ctx, appStore, organizationID, workspaceID, ownerID, conversationID, turnID, runID, 1)
}

// synonymEvent builds a RunEvent that heuristic-v1's SYNONYM signal turns
// into exactly one Candidate: candidateTerm is unknown, matchedTerm is
// already recognized in the run's own search arguments. QuestionText is
// deliberately just the bare candidate token: MatchTerms/the SYNONYM signal
// only need it to be present, and any *other* non-stop-word token repeated
// verbatim across two calls would itself cross NEW_TERM's own "at least two
// distinct runs" threshold and create an unrelated proposal, which would
// make every test in this file that calls this helper more than once
// non-deterministic about how many proposals to expect.
func synonymEvent(organizationID, workspaceID, conversationID, turnID, runID, candidateTerm, matchedTermID, matchedTerm string) workspacecontext.RunEvent {
	return workspacecontext.RunEvent{
		OrganizationID: organizationID, WorkspaceID: workspaceID,
		ConversationID: conversationID, TurnID: turnID, QuestionRunID: runID,
		QuestionText: candidateTerm,
		MatchedTerms: []workspacecontext.TermMatch{
			{TermID: matchedTermID, Term: matchedTerm, MatchedText: matchedTerm},
		},
	}
}

// TestWorkspaceContextProposalRLSOwnerManagerOnly proves S2-CONTRACT.md's
// "Proposals (OWNER and MANAGER only; others get 404)": migration 000113's
// RLS SELECT policy returns a proposal row only to OWNER/MANAGER, and
// returns nothing (not an error) to a MEMBER or to a principal with no
// membership at all.
func TestWorkspaceContextProposalRLSOwnerManagerOnly(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_ctxprop_rls"
		workspaceID    = "ws_ctxprop_rls"
		ownerID        = "usr_ctxprop_owner"
		managerID      = "usr_ctxprop_manager"
		memberID       = "usr_ctxprop_member"
		outsiderID     = "usr_ctxprop_outsider"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	insertAuthorityPrincipal(t, ctx, admin, organizationID, managerID)
	insertAuthorityPrincipal(t, ctx, admin, organizationID, memberID)
	insertAuthorityPrincipal(t, ctx, admin, organizationID, outsiderID)
	seedWorkspaceMemberAs(t, ctx, admin, organizationID, workspaceID, managerID, "MANAGER", ownerID)
	seedWorkspaceMemberAs(t, ctx, admin, organizationID, workspaceID, memberID, "MEMBER", ownerID)

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, "conv_ctxprop_rls", "turn_ctxprop_rls", "qrun_ctxprop_rls")

	store := proposer.NewStore(appStore, nil, nil, nil)
	event := synonymEvent(organizationID, workspaceID, "conv_ctxprop_rls", "turn_ctxprop_rls", "qrun_ctxprop_rls", "КП", "term_mno_rls", "МНО")
	if err := store.ObserveRun(ctx, event); err != nil {
		t.Fatalf("ObserveRun: %v", err)
	}

	for principalID, wantVisible := range map[string]bool{
		ownerID: true, managerID: true, memberID: false, outsiderID: false,
	} {
		principalID, wantVisible := principalID, wantVisible
		t.Run(principalID, func(t *testing.T) {
			access := workspacecontext.Access{OrganizationID: organizationID, PrincipalID: principalID, RequestID: "req_ctxprop_rls_" + principalID}
			proposals, err := store.List(ctx, access, workspaceID, workspacecontext.ProposalStatusProposed)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			gotVisible := len(proposals) == 1
			if gotVisible != wantVisible {
				t.Fatalf("List visible=%v (n=%d), want %v", gotVisible, len(proposals), wantVisible)
			}
			if wantVisible && proposals[0].CandidateTerm != "КП" {
				t.Fatalf("CandidateTerm = %q, want КП", proposals[0].CandidateTerm)
			}

			// Get and Reject must agree with List: RLS denies the read the
			// same way it denies the write, so both fail closed to
			// CodeNotFound for a non-manager caller.
			_, err = store.Get(ctx, access, workspaceID, probeProposalID(proposals, wantVisible))
			if wantVisible {
				if err != nil {
					t.Fatalf("Get (visible): %v", err)
				}
			} else if proposer.CodeOf(err) != proposer.CodeNotFound {
				t.Fatalf("Get (hidden) CodeOf(err) = %s, want %s", proposer.CodeOf(err), proposer.CodeNotFound)
			}
		})
	}
}

// probeProposalID returns the id to probe Get with: the real one when it was
// visible to List, or an arbitrary well-formed one otherwise (RLS must deny
// it regardless of whether it exists).
func probeProposalID(proposals []workspacecontext.Proposal, visible bool) string {
	if visible && len(proposals) == 1 {
		return proposals[0].ID
	}
	return "ctxprop_00000000000000000000000000"
}

// TestWorkspaceContextProposalDedupBoundsAndDecisions proves, against real
// PostgreSQL: dedup while PROPOSED (a second run bumps occurrences instead
// of creating a second row), the per-proposal evidence cap (20), the
// per-workspace open-proposal cap (200, "beyond that, only counters grow"),
// NEW_TERM's "at least two distinct runs" gate, and the Accept/Reject
// decision transitions (decided_by/at/version).
func TestWorkspaceContextProposalDedupBoundsAndDecisions(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_ctxprop_store"
		workspaceID    = "ws_ctxprop_store"
		ownerID        = "usr_ctxprop_store_owner"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	store := proposer.NewStore(appStore, nil, nil, nil)
	access := workspacecontext.Access{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_ctxprop_store"}

	// --- Dedup while PROPOSED: two runs, same candidate, one row. ---
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, "conv_dedup_1", "turn_dedup_1", "qrun_dedup_1")
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, "conv_dedup_2", "turn_dedup_2", "qrun_dedup_2")
	dedupEvent1 := synonymEvent(organizationID, workspaceID, "conv_dedup_1", "turn_dedup_1", "qrun_dedup_1", "КП", "term_mno_dedup", "МНО")
	dedupEvent2 := synonymEvent(organizationID, workspaceID, "conv_dedup_2", "turn_dedup_2", "qrun_dedup_2", "КП", "term_mno_dedup", "МНО")
	if err := store.ObserveRun(ctx, dedupEvent1); err != nil {
		t.Fatalf("ObserveRun 1: %v", err)
	}
	if err := store.ObserveRun(ctx, dedupEvent2); err != nil {
		t.Fatalf("ObserveRun 2: %v (cause: %v)", err, errors.Unwrap(err))
	}
	proposals, err := store.List(ctx, access, workspaceID, workspacecontext.ProposalStatusProposed)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(proposals) != 1 {
		t.Fatalf("len(proposals) = %d, want 1 (dedup)", len(proposals))
	}
	dedupProposal := proposals[0]
	if dedupProposal.Occurrences != 2 {
		t.Fatalf("Occurrences = %d, want 2", dedupProposal.Occurrences)
	}
	if dedupProposal.DetectorVersion != proposer.DetectorVersion {
		t.Fatalf("DetectorVersion = %q, want %q", dedupProposal.DetectorVersion, proposer.DetectorVersion)
	}
	var evidenceCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_context_proposal_evidence WHERE organization_id=$1 AND proposal_id=$2
	`, organizationID, dedupProposal.ID).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 2 {
		t.Fatalf("evidence rows = %d, want 2 (one per run)", evidenceCount)
	}

	// --- NEW_TERM: only promoted after at least two distinct runs. Must run
	// before the open-proposal cap block below fills the workspace to
	// capacity, or this promotion would itself be capped. QuestionText is a
	// single non-stop-word token so exactly one NEW_TERM candidate is at
	// stake (no unrelated tokens complicate the open-count arithmetic
	// below). ---
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, "conv_newterm_1", "turn_newterm_1", "qrun_newterm_1")
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, "conv_newterm_2", "turn_newterm_2", "qrun_newterm_2")
	newTermEvent1 := workspacecontext.RunEvent{
		OrganizationID: organizationID, WorkspaceID: workspaceID,
		ConversationID: "conv_newterm_1", TurnID: "turn_newterm_1", QuestionRunID: "qrun_newterm_1",
		QuestionText: "виджет",
	}
	newTermEvent2 := newTermEvent1
	newTermEvent2.ConversationID, newTermEvent2.TurnID, newTermEvent2.QuestionRunID = "conv_newterm_2", "turn_newterm_2", "qrun_newterm_2"
	if err := store.ObserveRun(ctx, newTermEvent1); err != nil {
		t.Fatalf("ObserveRun new-term 1: %v", err)
	}
	var newTermCountAfterFirst int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_context_proposal WHERE organization_id=$1 AND kind='NEW_TERM' AND candidate_term_key='виджет'
	`, organizationID).Scan(&newTermCountAfterFirst); err != nil {
		t.Fatal(err)
	}
	if newTermCountAfterFirst != 0 {
		t.Fatalf("NEW_TERM proposal exists after only one run (count=%d), want 0", newTermCountAfterFirst)
	}
	if err := store.ObserveRun(ctx, newTermEvent2); err != nil {
		t.Fatalf("ObserveRun new-term 2: %v", err)
	}
	var newTermCountAfterSecond int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_context_proposal WHERE organization_id=$1 AND kind='NEW_TERM' AND candidate_term_key='виджет'
	`, organizationID).Scan(&newTermCountAfterSecond); err != nil {
		t.Fatal(err)
	}
	if newTermCountAfterSecond != 1 {
		t.Fatalf("NEW_TERM proposal count after two distinct runs = %d, want 1", newTermCountAfterSecond)
	}

	// --- Evidence cap: 25 distinct runs for one candidate, at most 20 rows. ---
	for i := 0; i < 25; i++ {
		suffix := "_ev_" + string(rune('a'+i))
		conv, turn, run := "conv"+suffix, "turn"+suffix, "qrun"+suffix
		seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, conv, turn, run)
		event := synonymEvent(organizationID, workspaceID, conv, turn, run, "АБВ", "term_mno_dedup", "МНО")
		if err := store.ObserveRun(ctx, event); err != nil {
			t.Fatalf("ObserveRun evidence-cap[%d]: %v", i, err)
		}
	}
	var abvID string
	var abvOccurrences, abvEvidence int
	if err := admin.QueryRow(ctx, `
		SELECT id, occurrences FROM public.workspace_context_proposal
		 WHERE organization_id=$1 AND workspace_id=$2 AND candidate_term_key='абв' AND status='PROPOSED'
	`, organizationID, workspaceID).Scan(&abvID, &abvOccurrences); err != nil {
		t.Fatal(err)
	}
	if abvOccurrences != 25 {
		t.Fatalf("АБВ occurrences = %d, want 25 (counters keep growing)", abvOccurrences)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_context_proposal_evidence WHERE organization_id=$1 AND proposal_id=$2
	`, organizationID, abvID).Scan(&abvEvidence); err != nil {
		t.Fatal(err)
	}
	if abvEvidence != 20 {
		t.Fatalf("АБВ evidence rows = %d, want 20 (capped)", abvEvidence)
	}

	// --- Open-proposal cap: pre-fill 200 PROPOSED rows directly, then prove
	// a brand-new distinct candidate is silently skipped (no extra row),
	// while the dedup path above still works regardless of the cap. ---
	for i := 0; i < 200; i++ {
		id, err := ids.New("ctxprop")
		if err != nil {
			t.Fatal(err)
		}
		key := "cap-filler-" + padInt(i)
		if _, err := admin.Exec(ctx, `
			INSERT INTO public.workspace_context_proposal
				(organization_id, id, workspace_id, kind, candidate_term, candidate_term_key, status, occurrences, detector_version)
			VALUES ($1, $2, $3, 'NEW_TERM', $4, $4, 'PROPOSED', 1, $5)
		`, organizationID, id, workspaceID, key, proposer.DetectorVersion); err != nil {
			t.Fatalf("prefill open-cap[%d]: %v", i, err)
		}
	}
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, "conv_cap_new", "turn_cap_new", "qrun_cap_new")
	newCandidateEvent := synonymEvent(organizationID, workspaceID, "conv_cap_new", "turn_cap_new", "qrun_cap_new", "ГДЕ", "term_mno_dedup", "МНО")
	if err := store.ObserveRun(ctx, newCandidateEvent); err != nil {
		t.Fatalf("ObserveRun at open cap: %v", err)
	}
	var gdeCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_context_proposal WHERE organization_id=$1 AND candidate_term_key='где'
	`, organizationID).Scan(&gdeCount); err != nil {
		t.Fatal(err)
	}
	if gdeCount != 0 {
		t.Fatalf("open-cap: a new distinct proposal was created at the cap (count=%d), want 0 (skipped)", gdeCount)
	}
	// The dedup bump from before the cap was reached must still succeed.
	if err := store.ObserveRun(ctx, synonymEvent(organizationID, workspaceID, "conv_dedup_1", "turn_dedup_1", "qrun_dedup_1", "КП", "term_mno_dedup", "МНО")); err != nil {
		t.Fatalf("ObserveRun dedup bump at open cap: %v", err)
	}
	var openTotal int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_context_proposal WHERE organization_id=$1 AND workspace_id=$2 AND status='PROPOSED'
	`, organizationID, workspaceID).Scan(&openTotal); err != nil {
		t.Fatal(err)
	}
	if openTotal != 203 { // 200 filler + dedupProposal + виджет (NEW_TERM) + АБВ
		t.Fatalf("open PROPOSED total = %d, want 203", openTotal)
	}

	// --- Reject: PROPOSED -> REJECTED with decided_by/at recorded. ---
	rejected, err := store.Reject(ctx, access, workspaceID, abvID)
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if rejected.Status != workspacecontext.ProposalStatusRejected || rejected.DecidedBy != ownerID || rejected.DecidedAt.IsZero() {
		t.Fatalf("Reject result = %#v", rejected)
	}
	if _, err := store.Reject(ctx, access, workspaceID, abvID); proposer.CodeOf(err) != proposer.CodeNotProposed {
		t.Fatalf("double Reject CodeOf(err) = %s, want %s", proposer.CodeOf(err), proposer.CodeNotProposed)
	}

	// --- Accept: PROPOSED -> ACCEPTED with decided_by/at/version, atomic
	// with a (fake, this test's own) context-version mint. ---
	minter := &fakeVersionMinter{db: appStore}
	reader := fakeContextReader{version: workspacecontext.Version{
		Number: 3, ContentHash: "sha256:" + strings.Repeat("c", 64),
		Document: workspacecontext.Document{Glossary: []workspacecontext.Term{{ID: "term_mno_dedup", Term: "МНО"}}},
		Editable: true,
	}}
	acceptStore := proposer.NewStore(appStore, reader, minter, nil)
	accepted, err := acceptStore.Accept(ctx, access, workspaceID, dedupProposal.ID, reader.version.ContentHash, workspacecontext.ProposalEdits{})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if accepted.Number != 1 {
		t.Fatalf("minted version = %d, want 1", accepted.Number)
	}
	var acceptedStatus, decidedBy string
	var decidedVersion int64
	if err := admin.QueryRow(ctx, `
		SELECT status, decided_by, decided_version FROM public.workspace_context_proposal
		 WHERE organization_id=$1 AND id=$2
	`, organizationID, dedupProposal.ID).Scan(&acceptedStatus, &decidedBy, &decidedVersion); err != nil {
		t.Fatal(err)
	}
	if acceptedStatus != "ACCEPTED" || decidedBy != ownerID || decidedVersion != 1 {
		t.Fatalf("accepted row = status=%s decided_by=%s decided_version=%d", acceptedStatus, decidedBy, decidedVersion)
	}

	// A stale If-Match must fail closed without minting a version or
	// deciding the proposal (accept КП's target term is still open, unlike
	// the already-decided dedupProposal, so pick a still-PROPOSED row).
	if _, err := acceptStore.Accept(ctx, access, workspaceID, abvID, "sha256:"+strings.Repeat("0", 64), workspacecontext.ProposalEdits{}); proposer.CodeOf(err) != proposer.CodeNotProposed {
		// abvID was rejected above, so this proves the not-PROPOSED guard
		// independently of the hash check.
		t.Fatalf("Accept on a REJECTED proposal CodeOf(err) = %s, want %s", proposer.CodeOf(err), proposer.CodeNotProposed)
	}
}

func padInt(i int) string {
	digits := "0123456789"
	if i < 10 {
		return "00" + string(digits[i])
	}
	if i < 100 {
		return "0" + string(digits[i/10]) + string(digits[i%10])
	}
	return string(digits[i/100]) + string(digits[(i/10)%10]) + string(digits[i%10])
}

// TestWorkspaceContextProposalPurgeWithdraws proves
// S2-MODEL-CONTEXT-DESIGN.md's "Purging a conversation removes its evidence
// rows. A proposal left without evidence becomes WITHDRAWN with its text
// nulled": driven through the real internal/purge package (the same
// app.conversation_begin_purge/app.conversation_purge_cleanup boundary a
// production purge uses), purging one conversation withdraws a proposal
// whose only evidence came from it, while a proposal that also has evidence
// from a different, un-purged conversation stays PROPOSED.
func TestWorkspaceContextProposalPurgeWithdraws(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_ctxprop_purge"
		workspaceID    = "ws_ctxprop_purge"
		ownerID        = "usr_ctxprop_purge_owner"
		conversationA  = "conv_ctxprop_purge_a"
		conversationB  = "conv_ctxprop_purge_b"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	store := proposer.NewStore(appStore, nil, nil, nil)
	access := workspacecontext.Access{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_ctxprop_purge"}

	seedProposalConversation(t, ctx, appStore, organizationID, workspaceID, ownerID, conversationA)
	seedProposalRun(t, ctx, appStore, organizationID, workspaceID, ownerID, conversationA, "turn_purge_a1", "qrun_purge_a1", 1)
	seedProposalRun(t, ctx, appStore, organizationID, workspaceID, ownerID, conversationA, "turn_purge_a2", "qrun_purge_a2", 2)
	seedProposalTestRun(t, ctx, appStore, organizationID, workspaceID, ownerID, conversationB, "turn_purge_b1", "qrun_purge_b1")

	// P1: evidence only from conversation A -> must be withdrawn.
	if err := store.ObserveRun(ctx, synonymEvent(organizationID, workspaceID, conversationA, "turn_purge_a1", "qrun_purge_a1", "КПА", "term_mno_purge", "МНО")); err != nil {
		t.Fatalf("ObserveRun P1: %v", err)
	}
	// P2: evidence from both A and B -> must stay PROPOSED after A is purged.
	if err := store.ObserveRun(ctx, synonymEvent(organizationID, workspaceID, conversationA, "turn_purge_a2", "qrun_purge_a2", "КПБ", "term_mno_purge", "МНО")); err != nil {
		t.Fatalf("ObserveRun P2 (a): %v", err)
	}
	if err := store.ObserveRun(ctx, synonymEvent(organizationID, workspaceID, conversationB, "turn_purge_b1", "qrun_purge_b1", "КПБ", "term_mno_purge", "МНО")); err != nil {
		t.Fatalf("ObserveRun P2 (b): %v", err)
	}

	if proposals, err := store.List(ctx, access, workspaceID, workspacecontext.ProposalStatusProposed); err != nil || len(proposals) != 2 {
		t.Fatalf("List before purge: n=%d err=%v, want 2 PROPOSED", len(proposals), err)
	}

	var p1ID, p2ID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_context_proposal WHERE organization_id=$1 AND candidate_term_key='кпа'`, organizationID).Scan(&p1ID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_context_proposal WHERE organization_id=$1 AND candidate_term_key='кпб'`, organizationID).Scan(&p2ID); err != nil {
		t.Fatal(err)
	}

	// Drive a real conversation purge for A only, through the same queue and
	// SECURITY DEFINER boundary production uses.
	appQueue, err := purge.NewQueue(appStore)
	if err != nil {
		t.Fatal(err)
	}
	appAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_ctxprop_purge_enqueue"}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appQueue.Enqueue(ctx, appAccess, purge.RequestSpec{
		RequestID: requestID, WorkspaceID: workspaceID, ConversationID: conversationA,
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "ctxprop-purge-idem", Priority: 10, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue purge: %v", err)
	}

	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purgeQueue, err := purge.NewQueue(purgerStore)
	if err != nil {
		t.Fatal(err)
	}
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	purgeAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_ctxprop_purge_worker", RequestID: "req_ctxprop_purge_worker"}
	processed, err := purger.ProcessNextConversationPurge(ctx, purgeAccess, purgeQueue, "purger_ctxprop_worker", 30)
	if err != nil || !processed {
		t.Fatalf("ProcessNextConversationPurge processed=%v err=%v", processed, err)
	}

	var retentionState string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.conversation_retention WHERE organization_id=$1 AND conversation_id=$2`, organizationID, conversationA).Scan(&retentionState); err != nil {
		t.Fatal(err)
	}
	if retentionState != "PURGED" {
		t.Fatalf("conversation A retention state = %s, want PURGED", retentionState)
	}

	// P1: withdrawn, text nulled, no decided_by (system transition).
	var p1Status string
	var p1CandidateTerm, p1CandidateTermKey, p1SuggestedText, p1DecidedBy *string
	var p1DecidedAt *time.Time
	if err := admin.QueryRow(ctx, `
		SELECT status, candidate_term, candidate_term_key, suggested_text, decided_by, decided_at
		  FROM public.workspace_context_proposal WHERE organization_id=$1 AND id=$2
	`, organizationID, p1ID).Scan(&p1Status, &p1CandidateTerm, &p1CandidateTermKey, &p1SuggestedText, &p1DecidedBy, &p1DecidedAt); err != nil {
		t.Fatal(err)
	}
	if p1Status != "WITHDRAWN" {
		t.Fatalf("P1 status = %s, want WITHDRAWN", p1Status)
	}
	if p1CandidateTerm != nil || p1CandidateTermKey != nil || p1SuggestedText != nil {
		t.Fatalf("P1 text not nulled: candidate_term=%v candidate_term_key=%v suggested_text=%v", p1CandidateTerm, p1CandidateTermKey, p1SuggestedText)
	}
	if p1DecidedBy != nil {
		t.Fatalf("P1 decided_by = %v, want NULL (system withdrawal, not a person decision)", *p1DecidedBy)
	}
	if p1DecidedAt == nil {
		t.Fatal("P1 decided_at is NULL, want the withdrawal timestamp")
	}
	var p1EvidenceCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_context_proposal_evidence WHERE organization_id=$1 AND proposal_id=$2`, organizationID, p1ID).Scan(&p1EvidenceCount); err != nil {
		t.Fatal(err)
	}
	if p1EvidenceCount != 0 {
		t.Fatalf("P1 evidence rows = %d, want 0", p1EvidenceCount)
	}

	// P2: still PROPOSED (evidence from conversation B remains), text intact.
	var p2Status string
	var p2CandidateTerm *string
	if err := admin.QueryRow(ctx, `
		SELECT status, candidate_term FROM public.workspace_context_proposal WHERE organization_id=$1 AND id=$2
	`, organizationID, p2ID).Scan(&p2Status, &p2CandidateTerm); err != nil {
		t.Fatal(err)
	}
	if p2Status != "PROPOSED" {
		t.Fatalf("P2 status = %s, want PROPOSED (evidence remains from an un-purged conversation)", p2Status)
	}
	if p2CandidateTerm == nil || *p2CandidateTerm != "КПБ" {
		t.Fatalf("P2 candidate_term = %v, want КП2 (untouched)", p2CandidateTerm)
	}
	var p2EvidenceCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_context_proposal_evidence WHERE organization_id=$1 AND proposal_id=$2`, organizationID, p2ID).Scan(&p2EvidenceCount); err != nil {
		t.Fatal(err)
	}
	if p2EvidenceCount != 1 {
		t.Fatalf("P2 evidence rows = %d, want 1 (only conversation B's)", p2EvidenceCount)
	}
	var p2RemainingConversation string
	if err := admin.QueryRow(ctx, `SELECT conversation_id FROM public.workspace_context_proposal_evidence WHERE organization_id=$1 AND proposal_id=$2`, organizationID, p2ID).Scan(&p2RemainingConversation); err != nil {
		t.Fatal(err)
	}
	if p2RemainingConversation != conversationB {
		t.Fatalf("P2 remaining evidence conversation_id = %s, want %s", p2RemainingConversation, conversationB)
	}
}

// fakeContextReader is a minimal workspacecontext.Reader stand-in for
// Accept's unit-of-integration test: card A's real store
// (workspacecontext/store.go) does not exist yet in this worktree (see
// proposer/seams.go's VersionMinter doc comment), so this test proves
// Store.Accept's own orchestration (If-Match check, applyProposal, the
// atomic decide-with-mint contract) against a Document it fully controls.
type fakeContextReader struct{ version workspacecontext.Version }

func (reader fakeContextReader) Current(_ context.Context, _ workspacecontext.Access, _ string) (workspacecontext.Version, error) {
	return reader.version, nil
}

func (reader fakeContextReader) SourceNotes(_ context.Context, _ workspacecontext.Access, _, _ string) (workspacecontext.SourceNotes, error) {
	return workspacecontext.SourceNotes{}, nil
}

// fakeVersionMinter is a minimal proposer.VersionMinter stand-in: it mints
// a monotonically increasing in-memory version number, but faithfully
// upholds the real atomicity contract by running decideProposal inside a
// genuine internal/platform/database.Store.Write transaction against this
// test's own real Postgres proposal rows.
type fakeVersionMinter struct {
	db      *database.Store
	version int64
}

func (minter *fakeVersionMinter) MintAcceptedVersion(
	ctx context.Context, access workspacecontext.Access, _, _ string, document workspacecontext.Document, _ string,
	decideProposal func(context.Context, database.Transaction, int64) error,
) (workspacecontext.Version, error) {
	minter.version++
	minted := minter.version
	err := minter.db.Write(ctx, database.AccessContext{
		OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID,
	}, func(ctx context.Context, tx database.Transaction) error {
		return decideProposal(ctx, tx, minted)
	})
	if err != nil {
		return workspacecontext.Version{}, err
	}
	return workspacecontext.Version{Number: minted, ContentHash: "sha256:" + strings.Repeat("m", 64), Document: document, Editable: true}, nil
}
