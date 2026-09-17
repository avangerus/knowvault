package observation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

type testAdapter struct {
	kind Kind
	page Page
}

func (adapter testAdapter) Kind() Kind { return adapter.kind }
func (adapter testAdapter) Observe(context.Context, Request) (Page, error) {
	return adapter.page, nil
}

func observationHash(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestRegistryValidatesOneSourceAgnosticDocumentObservation(t *testing.T) {
	content := []byte("Kafka is our event bus")
	adapter := testAdapter{
		kind: KindDocument,
		page: Page{OrganizationID: "org_demo", Kind: KindDocument, CoverageComplete: true, Objects: []Object{{
			Kind: KindDocument, ExternalID: "native:doc-1", VersionKey: "native:v1", ObjectType: "DOCUMENT",
			ContentHash: observationHash(content), ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
			Document: &DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: content},
		}}},
	}
	registry, err := NewRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	page, err := registry.Observe(context.Background(), KindDocument, Request{
		OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1,
		MaxObjects: 10, MaxBytes: 4096,
	})
	if err != nil || len(page.Objects) != 1 {
		t.Fatalf("observation rejected: page=%+v err=%v", page, err)
	}
	if _, err := registry.Observe(context.Background(), KindMail, Request{
		OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1,
		MaxObjects: 10, MaxBytes: 4096,
	}); CodeOf(err) != CodeAdapterMissing {
		t.Fatalf("missing real adapter code=%q, want %q", CodeOf(err), CodeAdapterMissing)
	}
}

func TestObservationRejectsFabricatedBytesAndAmbiguousPayloads(t *testing.T) {
	base := Object{
		Kind: KindGit, ExternalID: "native:commit-1", VersionKey: "native:v1", ObjectType: "GIT_COMMIT",
		ContentHash: observationHash([]byte("actual")), ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
		Document: &DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: []byte("actual")},
	}
	for name, mutate := range map[string]func(*Object){
		"hash mismatch": func(value *Object) { value.Document.Bytes = []byte("fabricated") },
		"two payloads": func(value *Object) {
			value.BusinessRow = &BusinessRowPayload{}
		},
		"missing evidence-like identity": func(value *Object) { value.ExternalID = "" },
		"untyped native version":         func(value *Object) { value.VersionKey = "commit:without-prefix" },
		"self parent relation":           func(value *Object) { value.ParentExternalID = value.ExternalID },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if CodeOf(value.Validate(KindGit)) != CodeInvalidRequest {
				t.Fatal("invalid observation passed validation")
			}
		})
	}
}

func TestRegistryRejectsDuplicateKindsAndInvalidBounds(t *testing.T) {
	adapter := testAdapter{kind: KindMail}
	if _, err := NewRegistry(adapter, adapter); CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("duplicate kind code=%q, want %q", CodeOf(err), CodeInvalidRequest)
	}
	if _, err := NewRegistry(testAdapter{kind: Kind("UNSUPPORTED")}); CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("unsupported kind code=%q, want %q", CodeOf(err), CodeInvalidRequest)
	}
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Observe(context.Background(), KindMail, Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, MaxObjects: 0, MaxBytes: 1}); CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("invalid bounds code=%q, want %q", CodeOf(err), CodeInvalidRequest)
	}
}

func TestObservationRejectsNonAdvancingAndContradictoryPagination(t *testing.T) {
	content := []byte("bounded")
	base := Page{OrganizationID: "org_demo", Kind: KindMail, Objects: []Object{{
		Kind: KindMail, ExternalID: "native:mail-1", VersionKey: "native:v1", ObjectType: "EMAIL",
		ContentHash: observationHash(content), ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
		Document: &DocumentPayload{MediaType: "message/rfc822", MediaFamily: "TEXT", Bytes: content},
	}}}
	for name, mutate := range map[string]func(*Page){
		"same cursor":                func(page *Page) { page.NextCursor = "cursor-1" },
		"complete with continuation": func(page *Page) { page.NextCursor = "cursor-2"; page.CoverageComplete = true },
	} {
		t.Run(name, func(t *testing.T) {
			page := base
			mutate(&page)
			request := Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, Cursor: "cursor-1", MaxObjects: 10, MaxBytes: 4096}
			if CodeOf(page.Validate(request)) != CodeInvalidRequest {
				t.Fatalf("pagination mutation passed validation: page=%+v", page)
			}
		})
	}
}

func TestObservationRejectsAggregateByteBudgetBeforeAddition(t *testing.T) {
	content := []byte("bounded")
	page := Page{OrganizationID: "org_demo", Kind: KindDocument, Objects: []Object{{
		Kind: KindDocument, ExternalID: "native:doc-1", VersionKey: "native:v1", ObjectType: "DOCUMENT",
		ContentHash: observationHash(content), ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
		Document: &DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: content},
	}}}
	request := Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, MaxObjects: 10, MaxBytes: int64(len(content) - 1)}
	if CodeOf(page.Validate(request)) != CodeInvalidRequest {
		t.Fatal("page exceeded aggregate byte budget but passed validation")
	}
}

func TestObservationAcceptsCanonicalSourcePathLongerThanOpaqueID(t *testing.T) {
	content := []byte("bounded")
	path := "documents/" + strings.Repeat("\u0434", 130) + ".doc"
	if len(path) <= 256 || len(path) > 4096 {
		t.Fatalf("test path length = %d, want 257..4096 bytes", len(path))
	}
	page := Page{
		OrganizationID: "org_demo", Kind: KindDocument, CoverageComplete: true,
		Objects: []Object{{
			Kind: KindDocument, ExternalID: path, VersionKey: "native:v1", ObjectType: "DOCUMENT",
			ContentHash: observationHash(content), ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
			Document: &DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: content},
		}},
		Quarantined: []Quarantine{{ExternalID: path, Code: "FOLDER_UNSUPPORTED_TYPE"}},
	}
	request := Request{OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1, MaxObjects: 10, MaxBytes: 4096}
	if err := page.Validate(request); err != nil {
		t.Fatalf("canonical source path rejected: %v", err)
	}
}

func TestObservationRejectsSourceIdentityOverCanonicalPathLimit(t *testing.T) {
	content := []byte("bounded")
	object := Object{
		Kind: KindDocument, ExternalID: strings.Repeat("a", 4097), VersionKey: "native:v1", ObjectType: "DOCUMENT",
		ContentHash: observationHash(content), ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
		Document: &DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: content},
	}
	if CodeOf(object.Validate(KindDocument)) != CodeInvalidRequest {
		t.Fatal("source identity over 4096 bytes passed validation")
	}
}

func TestObservationPreservesSourceNativeParentRelation(t *testing.T) {
	content := []byte("attachment")
	object := Object{Kind: KindMail, ExternalID: "imap:mail;part:2", VersionKey: "native:uidvalidity:1;uid:2;part:2",
		ObjectType: "EMAIL_ATTACHMENT", ParentExternalID: "imap:mail", PartPath: "2", ContentHash: observationHash(content),
		ObservedAt: time.Unix(1, 0).UTC(), PayloadKind: PayloadBytes,
		Document: &DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: content}}
	if err := object.Validate(KindMail); err != nil {
		t.Fatalf("valid parent relation rejected: %v", err)
	}
}
