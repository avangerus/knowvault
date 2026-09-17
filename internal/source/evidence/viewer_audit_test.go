// Package evidence — audit emission contract for an authorized evidence read.
//
// These unit tests prove, with a fake audit sink, the curator audit fact for
// S1: after Viewer.Read authorizes and resolves a fragment it appends exactly
// one audit.ActionCitationOpened journal event naming the calling principal
// and the non-content provenance (fragment id, source_version_id,
// connection_id) of the fragment just disclosed — and it emits nothing for a
// read that is not authorized/resolved. Viewer.Read collapses every denial
// (unauthorized, cross-tenant, missing) to ErrNotFound before any emission, so
// the no-oracle, fail-closed 404 (ADR-0073) is unchanged: emitOpened is reached
// only on the success branch that actually returns a fragment.
package evidence

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// recordingSink is a fake audit writer that records every append it receives.
type recordingSink struct {
	appended []audit.EventInput
}

func (sink *recordingSink) Append(_ context.Context, _ database.AccessContext, input audit.EventInput) (audit.Event, error) {
	sink.appended = append(sink.appended, input)
	return audit.Event{}, nil
}

func authorizedReadFragment() Fragment {
	return Fragment{
		FragmentID:     "frag_evidence_card_0001",
		Text:           []byte("canonical text"),
		Anchor:         []byte("canonical anchor"),
		SourceVersionID: "src_ver_0001",
		ConnectionID:   "conn_0001",
		ExtractionID:   "extraction_0001",
	}
}

func TestEmitOpenedWritesExactlyOneCitationOpenedEvent(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{audit: sink}
	access := database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_viewer_0001",
		RequestID:      "req_evidence_0001",
	}
	fragment := authorizedReadFragment()

	if err := viewer.emitOpened(context.Background(), access, "ws_0001", fragment); err != nil {
		t.Fatalf("emitOpened returned an error: %v", err)
	}
	if len(sink.appended) != 1 {
		t.Fatalf("expected exactly one appended audit event, got %d", len(sink.appended))
	}

	got := sink.appended[0]
	if got.Action != audit.ActionCitationOpened {
		t.Errorf("action = %q, want citation.opened", got.Action)
	}
	if got.ActorType != audit.ActorHuman {
		t.Errorf("actor_type = %q, want HUMAN", got.ActorType)
	}
	if got.ActorPrincipalID == nil || *got.ActorPrincipalID != access.PrincipalID {
		t.Errorf("event does not name the calling principal %q", access.PrincipalID)
	}
	if got.WorkspaceID == nil || *got.WorkspaceID != "ws_0001" {
		t.Errorf("workspace_id = %v, want ws_0001", got.WorkspaceID)
	}
	// The non-content provenance the read resolved is carried: source_version_id
	// as the cited resource and the fragment id as the referenced evidence id.
	if got.ResourceID != fragment.SourceVersionID {
		t.Errorf("resource_id = %q, want source_version_id %q", got.ResourceID, fragment.SourceVersionID)
	}
	if len(got.ReferencedEvidenceIDs) != 1 || got.ReferencedEvidenceIDs[0] != fragment.FragmentID {
		t.Errorf("referenced_evidence_ids = %v, want [fragment_id %q]", got.ReferencedEvidenceIDs, fragment.FragmentID)
	}
	if got.Metadata.SourceConnectionID == nil || *got.Metadata.SourceConnectionID != fragment.ConnectionID {
		t.Errorf("metadata.source_connection_id = %v, want connection_id %q", got.Metadata.SourceConnectionID, fragment.ConnectionID)
	}
	if got.Outcome != audit.OutcomeSuccess {
		t.Errorf("outcome = %q, want SUCCESS", got.Outcome)
	}
	if got.ErrorCode != nil {
		t.Errorf("successful read must carry no error code")
	}
}

// A resolved fragment must be the only thing that produces an event. An
// un-returned / empty fragment — the shape Viewer.Read maps every denial to
// (returning ErrNotFound and never a Fragment) — must append nothing.
func TestEmitOpenedWritesNothingForUnresolvedRead(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{audit: sink}
	access := database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_viewer_0001",
		RequestID:      "req_evidence_0001",
	}

	// Denied reads never reach emitOpened; but even if handed a fragment that
	// carries no resolved identity (the denial sentinel), nothing is appended.
	empty := Fragment{}
	if err := viewer.emitOpened(context.Background(), access, "ws_0001", empty); err != nil {
		t.Fatalf("emitOpened returned an error: %v", err)
	}
	if len(sink.appended) != 0 {
		t.Fatalf("expected no audit event for an unresolved read, got %d", len(sink.appended))
	}
}

// A viewer with no audit sink (never constructed through the read path, or the
// fail-safe default) must not fail the read nor append anything.
func TestEmitOpenedIsNoopWithoutSink(t *testing.T) {
	viewer := &Viewer{} // audit sink is nil
	access := database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_viewer_0001",
		RequestID:      "req_evidence_0001",
	}
	if err := viewer.emitOpened(context.Background(), access, "ws_0001", authorizedReadFragment()); err != nil {
		t.Fatalf("emitOpened with nil sink returned an error: %v", err)
	}
}

// failingSink always fails the append, simulating a mandatory audit record
// that cannot be durably written (a full outage, a constraint violation, a
// contended retry budget exhausted -- Append's own documented failure
// modes).
type failingSink struct{}

var errInjectedAuditFailure = errors.New("injected: audit append failure")

func (failingSink) Append(context.Context, database.AccessContext, audit.EventInput) (audit.Event, error) {
	return audit.Event{}, errInjectedAuditFailure
}

// TestEmitOpenedPropagatesAppendFailure proves the FIX-1 #1 contract at the
// unit this package can test without a database: when the mandatory
// citation.opened record fails to persist, emitOpened returns that failure
// rather than swallowing it. Viewer.Read (which only a real-PostgreSQL
// fixture can exercise end to end) turns this same non-nil error into the
// identical ErrNotFound a denial gets, so an authorized fragment is never
// disclosed without its audit record landing.
func TestEmitOpenedPropagatesAppendFailure(t *testing.T) {
	viewer := &Viewer{audit: failingSink{}}
	access := database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_viewer_0001",
		RequestID:      "req_evidence_0001",
	}
	err := viewer.emitOpened(context.Background(), access, "ws_0001", authorizedReadFragment())
	if !errors.Is(err, errInjectedAuditFailure) {
		t.Fatalf("emitOpened with a failing sink = %v, want the injected append failure", err)
	}
}

// A denied inventory request must be journalled as a content-free denied
// admission event. The event carries no workspace so an unknown/foreign
// workspace never fails the audit_event workspace foreign key and the journal
// cannot become an existence oracle.
func TestListObjectsDenialJournalsNullWorkspace(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{}
	viewer.db = &database.Store{}
	viewer.audit = sink
	viewer.authorizeWorkspaceFn = func(context.Context, database.AccessContext, string) (bool, error) { return false, nil }
	page, err := viewer.ListObjects(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_unknown", false, 0, 10)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("denied ListObjects = %v, want ErrNotFound", err)
	}
	if len(page.Items) != 0 || page.HasMore || page.NextOffset != 0 {
		t.Fatalf("denial leaked a page: %#v", page)
	}
	if len(sink.appended) != 1 {
		t.Fatalf("denied inventory appended %d events, want one denied admission", len(sink.appended))
	}
	denial := sink.appended[0]
	if denial.Action != audit.ActionEvidenceReadAdmitted || denial.Outcome != audit.OutcomeDenied {
		t.Fatalf("denial event = %#v, want a denied admission", denial)
	}
	if denial.WorkspaceID != nil {
		t.Fatalf("denial workspace = %q, want NULL", *denial.WorkspaceID)
	}
	if denial.ErrorCode == nil || *denial.ErrorCode != auditInventoryDeniedCode {
		t.Fatalf("denial error code = %v, want %q", denial.ErrorCode, auditInventoryDeniedCode)
	}
	if denial.ResourceID != "ws_unknown" {
		t.Fatalf("denial resource = %q, want the requested workspace", denial.ResourceID)
	}
}

// A denial whose journal append fails must still return the content-free
// ErrNotFound, but the append failure is wrapped instead of being discarded so
// the missing denial record is observable.
func TestListObjectsDenialAppendFailureIsNotDiscarded(t *testing.T) {
	viewer := &Viewer{}
	viewer.db = &database.Store{}
	viewer.audit = failingSink{}
	viewer.authorizeWorkspaceFn = func(context.Context, database.AccessContext, string) (bool, error) { return false, nil }
	_, err := viewer.ListObjects(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_unknown", false, 0, 10)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListObjects with a failing denial append = %v, want ErrNotFound", err)
	}
	if !errors.Is(err, errInjectedAuditFailure) {
		t.Fatalf("ListObjects discarded the denial append failure: %v", err)
	}
}
