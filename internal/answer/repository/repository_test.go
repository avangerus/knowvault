package repository

import (
	"strings"
	"testing"
)

func testManifestHash(seed string) string {
	return "sha256:" + strings.Repeat(seed, 64)
}

func testAmendRequest() AmendDocumentRequest {
	return AmendDocumentRequest{
		OrganizationID: "org_alpha", WorkspaceID: "ws_alpha", AnswerDocumentID: "ansdoc_alpha",
		Version: 1, ManifestHash: testManifestHash("2"), ActorPrincipalID: "usr_alice",
		RequestID: "req_answer_001", AuditEventID: "audit_answer_001",
		Citations: []CitationRef{{Number: 1, EvidenceFragmentID: "frag_alpha"}},
	}
}

func stringPointer(value string) *string { return &value }

func TestValidateAmendAcceptsInitialVersion(t *testing.T) {
	store := &Store{}
	if err := store.validateAmend(testAmendRequest()); err != nil {
		t.Fatalf("initial version: err=%v", err)
	}
}

func TestValidateAmendAcceptsClosedAmendmentClasses(t *testing.T) {
	store := &Store{}
	for _, class := range []string{"SUPERSEDE", "RETRACT", "REDACT"} {
		request := testAmendRequest()
		request.Version = 2
		request.PreviousVersionHash = stringPointer(testManifestHash("2"))
		request.AmendmentClass = stringPointer(class)
		request.AmendmentReason = stringPointer("\u041f\u0440\u0438\u0447\u0438\u043d\u0430 \u043f\u0440\u0430\u0432\u043a\u0438.")
		if err := store.validateAmend(request); err != nil {
			t.Fatalf("class %s: err=%v", class, err)
		}
	}
}

func TestValidateAmendRejectsUnknownAmendmentClass(t *testing.T) {
	store := &Store{}
	request := testAmendRequest()
	request.Version = 2
	request.PreviousVersionHash = stringPointer(testManifestHash("2"))
	request.AmendmentClass = stringPointer("POLISH")
	request.AmendmentReason = stringPointer("\u041f\u043e\u043b\u0438\u0440\u043e\u0432\u043a\u0430 \u0431\u0435\u0437 \u0438\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u044f \u0441\u043c\u044b\u0441\u043b\u0430.")
	if err := store.validateAmend(request); CodeOf(err) != CodeRequestInvalid {
		t.Fatalf("unknown class: err=%v code=%q, want CodeRequestInvalid", err, CodeOf(err))
	}
}

func TestValidateAmendRejectsBrokenAmendmentShapes(t *testing.T) {
	store := &Store{}
	initial := testAmendRequest()
	cases := []struct {
		name  string
		apply func(*AmendDocumentRequest)
		want  ErrorCode
	}{
		{
			"initial version with amendment class",
			func(request *AmendDocumentRequest) { request.AmendmentClass = stringPointer("SUPERSEDE") },
			CodeRequestInvalid,
		},
		{
			"initial version with previous hash",
			func(request *AmendDocumentRequest) {
				request.PreviousVersionHash = stringPointer(testManifestHash("2"))
			},
			CodeRequestInvalid,
		},
		{
			"superseding version without previous hash",
			func(request *AmendDocumentRequest) {
				request.Version = 2
				request.AmendmentClass = stringPointer("SUPERSEDE")
				request.AmendmentReason = stringPointer("\u041f\u0440\u0438\u0447\u0438\u043d\u0430.")
			},
			CodeRequestInvalid,
		},
		{
			"superseding version without reason",
			func(request *AmendDocumentRequest) {
				request.Version = 2
				request.PreviousVersionHash = stringPointer(testManifestHash("2"))
				request.AmendmentClass = stringPointer("SUPERSEDE")
			},
			CodeRequestInvalid,
		},
		{
			"version without citations",
			func(request *AmendDocumentRequest) { request.Citations = nil },
			CodeRequestInvalid,
		},
		{
			"malformed manifest hash",
			func(request *AmendDocumentRequest) { request.ManifestHash = "sha256:xyz" },
			CodeRequestInvalid,
		},
	}
	for _, fixture := range cases {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			request := initial
			fixture.apply(&request)
			if err := store.validateAmend(request); CodeOf(err) != fixture.want {
				t.Fatalf("err=%v code=%q, want %q", err, CodeOf(err), fixture.want)
			}
		})
	}
}

func TestValidateOpenRejectsInvalidIdentifiers(t *testing.T) {
	store := &Store{}
	if err := store.validateOpen(OpenDocumentRequest{
		OrganizationID: "org_alpha", WorkspaceID: "ws_alpha", AnswerDocumentID: "", RequestID: "req_open_001",
	}); CodeOf(err) != CodeRequestInvalid {
		t.Fatalf("err=%v code=%q, want CodeRequestInvalid", err, CodeOf(err))
	}
}
