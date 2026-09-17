package evidence

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

func TestIndexedSearchAdmissionUsesLiveMembershipAndDurableJournal(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		sink := &recordingSink{}
		viewer := &Viewer{db: &database.Store{}, audit: sink, authorizeWorkspaceFn: func(context.Context, database.AccessContext, string) (bool, error) { return allowed, nil }}
		err := viewer.AdmitSearch(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001")
		if (err == nil) != allowed || len(sink.appended) != 1 {
			t.Fatalf("allowed=%v error=%v events=%d", allowed, err, len(sink.appended))
		}
		event := sink.appended[0]
		if event.Action != audit.ActionEvidenceReadAdmitted {
			t.Fatal("missing admission")
		}
		if allowed && (len(event.Metadata.ReasonCodes) != 1 || event.Metadata.ReasonCodes[0] != "WORKSPACE_SEARCH_REQUEST") {
			t.Fatal("successful search lacks its content-free classification")
		}
		if _, err := audit.Build("org_0001", event, 0, ""); err != nil {
			t.Fatalf("search admission is outside the audit metadata contract: %v", err)
		}
		if !allowed && (event.Outcome != audit.OutcomeDenied || event.WorkspaceID != nil) {
			t.Fatal("denial revealed workspace existence")
		}
	}
	viewer := &Viewer{db: &database.Store{}, audit: failingSink{}, authorizeWorkspaceFn: func(context.Context, database.AccessContext, string) (bool, error) { return true, nil }}
	if err := viewer.AdmitSearch(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001"); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed journal admitted indexed search")
	}
}

func TestInventoryAdmissionDoesNotClaimToBeSearch(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{audit: sink}
	if err := viewer.emitWorkspaceEvent(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", audit.OutcomeSuccess, audit.ActionEvidenceReadAdmitted, ""); err != nil {
		t.Fatal(err)
	}
	if len(sink.appended) != 1 || len(sink.appended[0].Metadata.ReasonCodes) != 0 {
		t.Fatal("the unclassified inventory event was relabelled as search")
	}
}
