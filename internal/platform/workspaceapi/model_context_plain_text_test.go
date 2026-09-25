package workspaceapi

// Card W-2 transport probe: the REST projection exposes the three plain-text
// fields. Instructions and glossary_text are the effective text, so a
// workspace whose rules/terms predate the card reads them as one block each
// (with no ids and no data-location blocks), while the structured records
// still travel unchanged for the model and for storage.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacecontext"
)

func TestModelContextGetProjectsEffectivePlainText(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{restResult: workspacecontext.VersionRecord{
		Version: workspacecontext.Version{
			Number: 2, ContentHash: "sha256:" + strings.Repeat("c", 64), Editable: true,
			Document: workspacecontext.Document{
				Rules: []workspacecontext.Rule{{ID: "rule_x", Text: "Always cite the source."}},
				Glossary: []workspacecontext.Term{{
					ID: "term_x", Term: "МНО", Synonyms: []string{"МНОшка"},
					Definition: "Monthly net orders.",
					DataLocations: []workspacecontext.DataLocation{{
						SourceConnectionID: "conn_1", Relation: "public.orders", Column: "status",
					}},
				}},
			},
		},
	}}
	harness.handler.EnableModelContext(fake)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextPath, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"instructions":"Always cite the source."`) {
		t.Fatalf("instructions text missing from %s", body)
	}
	for _, want := range []string{"МНО", "МНОшка", "Monthly net orders.", "public.orders.status"} {
		if !strings.Contains(body, want) {
			t.Fatalf("glossary_text missing %q in %s", want, body)
		}
	}
	// The structured records still travel, so nothing already entered stops
	// working, but the field text itself carries no term id.
	if !strings.Contains(body, `"id":"term_x"`) {
		t.Fatalf("structured glossary was dropped from %s", body)
	}
}

func TestModelContextSaveDecodesPlainTextFields(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{saveResult: workspacecontext.VersionRecord{
		Version: workspacecontext.Version{Number: 1, ContentHash: "sha256:" + strings.Repeat("d", 64), Editable: true},
	}}
	harness.handler.EnableModelContext(fake)

	body := `{"document":{"description":"d","instructions":"i","glossary_text":"g","rules":[],"glossary":[],"sources":[]}}`
	response := httptest.NewRecorder()
	request := harness.request(http.MethodPut, modelContextPath, body)
	setModelContextMutationHeaders(request, harness.idempotencyKey, modelContextEmptySentinel)
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.document.Instructions != "i" || fake.document.GlossaryText != "g" {
		t.Fatalf("fake saw document=%+v", fake.document)
	}
}
