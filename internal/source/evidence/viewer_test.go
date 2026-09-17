// Outcome 2 (audit before data) contract for the authorized evidence read.
//
// These tests use the Viewer authorization/read seams plus a fake audit sink so
// the admission-before-data ordering and its fail-closed refusal are proven
// without a database. They are protected-independent: no real PostgreSQL and no
// protected file is touched.
package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// actionFailSink records every append but fails the named action, modelling a
// transient journal failure that hits only one event (for example the outcome)
// while the admission event still lands.
type actionFailSink struct {
	recordingSink
	failAction audit.Action
}

func (sink *actionFailSink) Append(ctx context.Context, access database.AccessContext, input audit.EventInput) (audit.Event, error) {
	if input.Action == sink.failAction {
		return audit.Event{}, errors.New("injected: audit append failure")
	}
	return sink.recordingSink.Append(ctx, access, input)
}

func evidenceAccess(kind database.ActorKind) database.AccessContext {
	return database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_viewer_0001",
		RequestID:      "req_evidence_0001",
		ActorKind:      kind,
	}
}

// A read whose authorization succeeds but whose admission append fails must
// return no data and no partial result, and must not fetch the fragment at all:
// the governed read runs only after admission is durable.
func TestReadAdmissionFailureReturnsNoDataBeforeAnyRead(t *testing.T) {
	readRan := false
	viewer := &Viewer{
		audit:       failingSink{},
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
		readFn: func(context.Context, database.AccessContext, string, string) (Fragment, error) {
			readRan = true
			return authorizedReadFragment(), nil
		},
	}

	fragment, err := viewer.Read(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read with a failed admission = %v, want ErrNotFound", err)
	}
	if readRan {
		t.Fatal("governed read ran after the admission append failed")
	}
	if fragment.FragmentID != "" || fragment.Text != nil || fragment.Anchor != nil {
		t.Fatalf("admission failure leaked a partial result: %#v", fragment)
	}
}

// A governed read that fails after admission leaves the admission event plus its
// matching failure outcome, and still returns no data.
func TestReadFailureAfterAdmissionLeavesAdmissionAndFailureOutcome(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
		readFn: func(context.Context, database.AccessContext, string, string) (Fragment, error) {
			return Fragment{}, errors.New("injected: governed read failure")
		},
	}

	fragment, err := viewer.Read(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read after a post-admission failure = %v, want ErrNotFound", err)
	}
	if fragment.FragmentID != "" || fragment.Text != nil {
		t.Fatalf("post-admission failure leaked a partial result: %#v", fragment)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + failure outcome", len(sink.appended))
	}
	if sink.appended[0].Action != audit.ActionEvidenceReadAdmitted || sink.appended[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("first event = %#v, want a successful admission", sink.appended[0])
	}
	failure := sink.appended[1]
	if failure.Action != audit.ActionEvidenceReadFailed || failure.Outcome != audit.OutcomeFailed || failure.ErrorCode == nil {
		t.Fatalf("second event = %#v, want a failure outcome with an error code", failure)
	}
}

// The success path appends the admission event first and keeps the existing
// citation.opened outcome event unchanged.
func TestReadSuccessAppendsAdmissionThenCitationOpened(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
		readFn: func(context.Context, database.AccessContext, string, string) (Fragment, error) {
			return authorizedReadFragment(), nil
		},
	}

	fragment, err := viewer.Read(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if err != nil {
		t.Fatalf("authorized Read = %v, want nil", err)
	}
	if string(fragment.Text) != "canonical text" {
		t.Fatalf("Read returned text %q, want the resolved fragment", fragment.Text)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + citation.opened", len(sink.appended))
	}
	if sink.appended[0].Action != audit.ActionEvidenceReadAdmitted {
		t.Fatalf("first event action = %q, want %q", sink.appended[0].Action, audit.ActionEvidenceReadAdmitted)
	}
	if sink.appended[1].Action != audit.ActionCitationOpened {
		t.Fatalf("second event action = %q, want %q", sink.appended[1].Action, audit.ActionCitationOpened)
	}
}

// If the success outcome cannot be persisted after admission, the matching
// failure outcome is recorded and the read still returns no data.
func TestReadOutcomeFailureAfterAdmissionLeavesMatchingFailureOutcome(t *testing.T) {
	sink := &actionFailSink{failAction: audit.ActionCitationOpened}
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
		readFn: func(context.Context, database.AccessContext, string, string) (Fragment, error) {
			return authorizedReadFragment(), nil
		},
	}

	fragment, err := viewer.Read(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read whose outcome append failed = %v, want ErrNotFound", err)
	}
	if fragment.FragmentID != "" || fragment.Text != nil {
		t.Fatalf("outcome-append failure leaked a partial result: %#v", fragment)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + failure outcome", len(sink.appended))
	}
	if sink.appended[0].Action != audit.ActionEvidenceReadAdmitted {
		t.Fatalf("first event action = %q, want the admission", sink.appended[0].Action)
	}
	if sink.appended[1].Action != audit.ActionEvidenceReadFailed || sink.appended[1].Outcome != audit.OutcomeFailed {
		t.Fatalf("second event = %#v, want the matching failure outcome", sink.appended[1])
	}
}

// Admission records the effective actor kind and the access decision, and names
// the fragment resource without content.
func TestReadAdmissionRecordsActorKindAndAccessDecision(t *testing.T) {
	for name, kind := range map[string]struct {
		kind database.ActorKind
		want audit.ActorType
	}{
		"human":   {database.ActorKindHuman, audit.ActorHuman},
		"service": {database.ActorKindService, audit.ActorService},
		"unset":   {"", audit.ActorHuman},
	} {
		t.Run(name, func(t *testing.T) {
			sink := &recordingSink{}
			viewer := &Viewer{
				audit:       sink,
				authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
				readFn: func(context.Context, database.AccessContext, string, string) (Fragment, error) {
					return authorizedReadFragment(), nil
				},
			}
			if _, err := viewer.Read(context.Background(), evidenceAccess(kind.kind), "ws_0001", "frag_0001"); err != nil {
				t.Fatalf("authorized Read = %v, want nil", err)
			}
			admission := sink.appended[0]
			if admission.ActorType != kind.want {
				t.Fatalf("admission actor_type = %q, want %q", admission.ActorType, kind.want)
			}
			if admission.ResourceType != audit.ResourceCitation || admission.ResourceID != "frag_0001" {
				t.Fatalf("admission resource = %q/%q, want CITATION/frag_0001", admission.ResourceType, admission.ResourceID)
			}
			if admission.Outcome != audit.OutcomeSuccess {
				t.Fatalf("admission access decision = %q, want SUCCESS", admission.Outcome)
			}
			if admission.WorkspaceID == nil || *admission.WorkspaceID != "ws_0001" {
				t.Fatalf("admission workspace = %v, want ws_0001", admission.WorkspaceID)
			}
		})
	}
}

// A denied read appends nothing and never runs the governed fetch: the
// no-oracle denial is unchanged.
func TestReadDenialAppendsNothingAndNeverReads(t *testing.T) {
	sink := &recordingSink{}
	readRan := false
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return false, nil },
		readFn: func(context.Context, database.AccessContext, string, string) (Fragment, error) {
			readRan = true
			return authorizedReadFragment(), nil
		},
	}
	if _, err := viewer.Read(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("denied Read = %v, want ErrNotFound", err)
	}
	if readRan {
		t.Fatal("governed read ran for a denied decision")
	}
	if len(sink.appended) != 0 {
		t.Fatalf("denied read appended %d events, want none", len(sink.appended))
	}
}

// ReadObject reuses the same admission-before-data ordering and the unchanged
// citation.opened outcome as Read, and returns the whole assembled original.
func TestReadObjectAppendsAdmissionThenCitationOpened(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
		readObjectFn: func(context.Context, database.AccessContext, string, string) (WholeObject, error) {
			fragment := authorizedReadFragment()
			return WholeObject{
				Fragment: fragment, Text: []byte("first\nsecond"),
				FragmentCount: 2, FirstOrdinal: 1, LastOrdinal: 2,
			}, nil
		},
	}

	object, err := viewer.ReadObject(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if err != nil {
		t.Fatalf("authorized ReadObject = %v, want nil", err)
	}
	if string(object.Text) != "first\nsecond" || object.FragmentCount != 2 {
		t.Fatalf("ReadObject result = %#v", object)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + citation.opened", len(sink.appended))
	}
	if sink.appended[0].Action != audit.ActionEvidenceReadAdmitted || sink.appended[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("first event = %#v, want a successful admission", sink.appended[0])
	}
	if sink.appended[1].Action != audit.ActionCitationOpened {
		t.Fatalf("second event = %#v, want citation.opened", sink.appended[1])
	}
}

// A denied whole-object read appends one content-free denied admission with its
// class, never runs the assembly and returns the single ErrNotFound with no
// partial text.
func TestReadObjectDenialJournalsClassAndNeverAssembles(t *testing.T) {
	sink := &recordingSink{}
	readRan := false
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return false, nil },
		readObjectFn: func(context.Context, database.AccessContext, string, string) (WholeObject, error) {
			readRan = true
			return WholeObject{Text: []byte("secret")}, nil
		},
	}

	object, err := viewer.ReadObject(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("denied ReadObject = %v, want ErrNotFound", err)
	}
	if readRan {
		t.Fatal("whole-object assembly ran for a denied decision")
	}
	if object.Fragment.FragmentID != "" || object.Text != nil {
		t.Fatalf("denial leaked a partial result: %#v", object)
	}
	if len(sink.appended) != 1 {
		t.Fatalf("denied whole-object read appended %d events, want one classed denial", len(sink.appended))
	}
	denial := sink.appended[0]
	if denial.Outcome != audit.OutcomeDenied || denial.ErrorCode == nil || *denial.ErrorCode != auditObjectDeniedCode {
		t.Fatalf("denial event = %#v, want a classed denial", denial)
	}
	if denial.WorkspaceID != nil {
		t.Fatalf("denial recorded a workspace: %#v", denial.WorkspaceID)
	}
}

// A whole-object assembly that fails after admission leaves the admission plus
// its matching failure outcome and returns no data.
func TestReadObjectFailureAfterAdmissionLeavesFailureOutcome(t *testing.T) {
	sink := &recordingSink{}
	viewer := &Viewer{
		audit:       sink,
		authorizeFn: func(context.Context, database.AccessContext, string, string) (bool, error) { return true, nil },
		readObjectFn: func(context.Context, database.AccessContext, string, string) (WholeObject, error) {
			return WholeObject{}, errors.New("injected: assembly failure")
		},
	}

	object, err := viewer.ReadObject(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "frag_0001")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReadObject after a post-admission failure = %v, want ErrNotFound", err)
	}
	if object.Fragment.FragmentID != "" || object.Text != nil {
		t.Fatalf("post-admission failure leaked a partial result: %#v", object)
	}
	if len(sink.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + failure outcome", len(sink.appended))
	}
	if sink.appended[0].Action != audit.ActionEvidenceReadAdmitted {
		t.Fatalf("first event = %#v, want the admission", sink.appended[0])
	}
	if sink.appended[1].Action != audit.ActionEvidenceReadFailed || sink.appended[1].Outcome != audit.OutcomeFailed || sink.appended[1].ErrorCode == nil {
		t.Fatalf("second event = %#v, want a classed failure outcome", sink.appended[1])
	}
}

// KV-A02c: the skip projection dedupes on the decrypted native identity within
// one source scope revision, not on the versioned digest. Two ledger rows for
// the same native object written under different digest_key_version values
// (a rotated digester key) must project as exactly one skip, keeping the newer
// reason code and moment.
func TestSelectSkipIdentitiesDedupesNativeIdentityAcrossKeyVersions(t *testing.T) {
	older := time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	ledger := []skipLedgerRow{
		{scopeID: "scope_a", scopeRevision: 1, digest: "digest_v1", keyVersion: 1, artifactID: "artifact_v1", reasonCode: "QUARANTINED_MALFORMED", observedAt: older, syncRunID: "run_1"},
		{scopeID: "scope_a", scopeRevision: 1, digest: "digest_v2", keyVersion: 2, artifactID: "artifact_v2", reasonCode: "FOLDER_OBJECT_OVERSIZED", observedAt: newer, syncRunID: "run_2"},
	}
	skips := selectSkipIdentities(ledger, func(skipLedgerRow) (string, bool) {
		return "native:skipped-a", true
	})
	if len(skips) != 1 {
		t.Fatalf("skips=%+v, want exactly one native identity", skips)
	}
	if skips[0].ExternalID != "native:skipped-a" {
		t.Fatalf("skip external_id=%q", skips[0].ExternalID)
	}
	if skips[0].ReasonCode != "FOLDER_OBJECT_OVERSIZED" {
		t.Fatalf("skip reason=%q, want the newest observation's code", skips[0].ReasonCode)
	}
	if !skips[0].ObservedAt.Equal(newer) {
		t.Fatalf("skip moment=%v, want %v", skips[0].ObservedAt, newer)
	}
}

// Two genuinely different native identities in the same scope revision still
// project as two skips, and the output order is the deterministic native id
// order rather than map iteration order.
func TestSelectSkipIdentitiesKeepsDistinctNativeIdentities(t *testing.T) {
	moment := time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)
	ledger := []skipLedgerRow{
		{scopeID: "scope_a", scopeRevision: 1, digest: "digest_b", keyVersion: 1, artifactID: "artifact_b", reasonCode: "GIT_BLOB_OVERSIZED", observedAt: moment, syncRunID: "run_1"},
		{scopeID: "scope_a", scopeRevision: 1, digest: "digest_a", keyVersion: 1, artifactID: "artifact_a", reasonCode: "GIT_INVALID_UTF8", observedAt: moment, syncRunID: "run_1"},
	}
	identities := map[string]string{"digest_a": "native:a", "digest_b": "native:b"}
	skips := selectSkipIdentities(ledger, func(row skipLedgerRow) (string, bool) {
		return identities[row.digest], true
	})
	if len(skips) != 2 {
		t.Fatalf("skips=%+v, want two distinct identities", skips)
	}
	if skips[0].ExternalID != "native:a" || skips[1].ExternalID != "native:b" {
		t.Fatalf("skip order=%v, want deterministic native id order", []string{skips[0].ExternalID, skips[1].ExternalID})
	}
}

// A row whose verifier declines (missing artifact or digest mismatch) is
// withheld fail closed and contributes no skip, while a verifiable row for the
// same scope revision still projects.
func TestSelectSkipIdentitiesWithholdsUnverifiableRows(t *testing.T) {
	moment := time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)
	ledger := []skipLedgerRow{
		{scopeID: "scope_a", scopeRevision: 1, digest: "digest_tampered", keyVersion: 1, artifactID: "artifact_tampered", reasonCode: "QUARANTINED_MALFORMED", observedAt: moment, syncRunID: "run_1"},
		{scopeID: "scope_a", scopeRevision: 1, digest: "digest_ok", keyVersion: 1, artifactID: "artifact_ok", reasonCode: "FOLDER_OBJECT_OVERSIZED", observedAt: moment, syncRunID: "run_1"},
	}
	skips := selectSkipIdentities(ledger, func(row skipLedgerRow) (string, bool) {
		if row.digest == "digest_tampered" {
			return "", false
		}
		return "native:skipped-a", true
	})
	if len(skips) != 1 || skips[0].ExternalID != "native:skipped-a" {
		t.Fatalf("skips=%+v, want only the verifiable skip", skips)
	}
}
