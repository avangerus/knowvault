package workspaceapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

type neighborReadEvidence struct {
	fragment     evidence.Fragment
	neighbors    evidence.FragmentNeighbors
	neighborsErr error
	called       bool
}

func (service *neighborReadEvidence) Read(_ context.Context, _ database.AccessContext, _, _ string) (evidence.Fragment, error) {
	return service.fragment, nil
}

func (service *neighborReadEvidence) ReadNeighbors(_ context.Context, _ database.AccessContext, _ string, _ evidence.Fragment) (evidence.FragmentNeighbors, error) {
	service.called = true
	return service.neighbors, service.neighborsErr
}

func (service *neighborReadEvidence) ReadObject(_ context.Context, _ database.AccessContext, _, _ string) (evidence.WholeObject, error) {
	return evidence.WholeObject{
		Fragment:      service.fragment,
		Text:          service.fragment.Text,
		FragmentCount: 1,
		FirstOrdinal:  service.fragment.Ordinal,
		LastOrdinal:   service.fragment.Ordinal,
	}, nil
}

func TestReadNeighborProjectionKeepsOnlySameExtractionVersionAndDirection(t *testing.T) {
	current := testEvidenceFragment(t)
	current.ExtractionID = "extraction_current"
	current.SourceObjectID = "object_current"
	current.SourceVersionID = "version_current"
	current.Ordinal = 3
	previous := current
	previous.FragmentID = "fragment_previous"
	previous.Ordinal = 2
	previous.Text = []byte("previous secret")
	next := current
	next.FragmentID = "fragment_next"
	next.Ordinal = 4
	next.Text = []byte("next secret")

	harness := newTestHarness(t)
	projection := harness.handler.readNeighborsProjection(context.Background(), database.AccessContext{}, "ws_alpha", current)
	if projection != nil {
		t.Fatal("handler without optional capability returned neighbors")
	}

	service := &neighborReadEvidence{fragment: current, neighbors: evidence.FragmentNeighbors{Previous: &previous, Next: &next}}
	harness.handler.evidence = service
	projection = harness.handler.readNeighborsProjection(context.Background(), database.AccessContext{}, "ws_alpha", current)
	if projection == nil || projection.Previous == nil || projection.Next == nil {
		t.Fatalf("valid neighbors projection=%#v", projection)
	}
	if projection.Previous.FragmentID != previous.FragmentID || projection.Previous.Ordinal != previous.Ordinal || projection.Next.FragmentID != next.FragmentID || projection.Next.Ordinal != next.Ordinal {
		t.Fatalf("neighbor identity projection=%#v", projection)
	}
	if projection.Previous.Address == "" || projection.Next.Address == "" || strings.Contains(projection.Previous.Address, "previous secret") || strings.Contains(projection.Next.Address, "next secret") {
		t.Fatalf("neighbor address/text projection=%#v", projection)
	}

	wrong := next
	wrong.SourceVersionID = "version_other"
	service.neighbors = evidence.FragmentNeighbors{Previous: &wrong, Next: &wrong}
	projection = harness.handler.readNeighborsProjection(context.Background(), database.AccessContext{}, "ws_alpha", current)
	if projection == nil || projection.Previous != nil || projection.Next != nil {
		t.Fatalf("foreign neighbor was projected: %#v", projection)
	}
}

func TestMCPAndRESTDirectFullReadProjectNeighborsWithoutText(t *testing.T) {
	current := testEvidenceFragment(t)
	current.Text = []byte("current page")
	current.EvidenceTextHash = mcpEvidenceReadTextHash(current.Text)
	current.ExtractionID = "extraction_current"
	current.SourceObjectID = "object_current"
	current.SourceVersionID = "version_current"
	current.Ordinal = 3
	previous := current
	previous.FragmentID = "fragment_previous"
	previous.Ordinal = 2
	previous.Text = []byte("previous secret")
	next := current
	next.FragmentID = "fragment_next"
	next.Ordinal = 4
	next.Text = []byte("next secret")

	service := &neighborReadEvidence{fragment: current, neighbors: evidence.FragmentNeighbors{Previous: &previous, Next: &next}}
	harness := newTestHarness(t)
	harness.handler.evidence = service
	mcp := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+current.FragmentID+`","limit":4096}`)
	if mcp.Error != nil {
		t.Fatalf("MCP direct read refused: %#v", mcp.Error)
	}
	neighbors, ok := mcp.Result.Structured["neighbors"].(map[string]any)
	if !ok {
		t.Fatalf("MCP direct read missing neighbors: %#v", mcp.Result.Structured)
	}
	if neighbors["previous"].(map[string]any)["fragment_id"] != previous.FragmentID || neighbors["next"].(map[string]any)["fragment_id"] != next.FragmentID {
		t.Fatalf("MCP neighbors=%#v", neighbors)
	}
	content, _ := mcp.Result.Content[0]["text"].(string)
	if !strings.Contains(content, " neighbors=") || strings.Contains(content, "previous secret") || strings.Contains(content, "next secret") {
		t.Fatalf("MCP text channel neighbor metadata/content=%q", content)
	}

	restHarness := newTestHarness(t)
	restHarness.handler.evidence = service
	response, body := callRestRead(t, restHarness, http.MethodGet, "?fragment_id="+current.FragmentID+"&limit=4096", "")
	if response.Code != http.StatusOK {
		t.Fatalf("REST direct read status=%d body=%s", response.Code, response.Body.String())
	}
	restNeighbors, ok := body["neighbors"].(map[string]any)
	if !ok || restNeighbors["previous"].(map[string]any)["fragment_id"] != previous.FragmentID || restNeighbors["next"].(map[string]any)["fragment_id"] != next.FragmentID {
		t.Fatalf("REST neighbors=%#v body=%#v", restNeighbors, body)
	}
	encoded, _ := json.Marshal(body)
	if strings.Contains(string(encoded), "previous secret") || strings.Contains(string(encoded), "next secret") {
		t.Fatalf("REST neighbor text leaked: %s", encoded)
	}

	if !service.called {
		t.Fatal("full direct page did not invoke optional neighbor capability")
	}
	service.called = false
	partial := newTestHarness(t)
	partial.handler.evidence = service
	partialRead := mcpEvidenceRead(t, partial, `{"workspace_id":"ws_alpha","fragment_id":"`+current.FragmentID+`","limit":4}`)
	if partialRead.Error != nil {
		t.Fatalf("partial MCP read refused: %#v", partialRead.Error)
	}
	if _, present := partialRead.Result.Structured["neighbors"]; present {
		t.Fatalf("partial direct page exposed neighbors: %#v", partialRead.Result.Structured)
	}
	if service.called {
		t.Fatal("partial direct page invoked optional neighbor capability")
	}

	service.called = false
	finalPage := newTestHarness(t)
	finalPage.handler.evidence = service
	finalRead := mcpEvidenceRead(t, finalPage, `{"workspace_id":"ws_alpha","fragment_id":"`+current.FragmentID+`","offset":4,"limit":4096}`)
	if finalRead.Error != nil {
		t.Fatalf("offset>0 final page refused: %#v", finalRead.Error)
	}
	if _, present := finalRead.Result.Structured["neighbors"]; present {
		t.Fatalf("offset>0 final page exposed neighbors: %#v", finalRead.Result.Structured)
	}
	if service.called {
		t.Fatal("offset>0 final page invoked optional neighbor capability")
	}

	service.called = false
	whole := newTestHarness(t)
	whole.handler.evidence = service
	wholeRead := mcpEvidenceRead(t, whole, `{"workspace_id":"ws_alpha","fragment_id":"`+current.FragmentID+`","cursor":""}`)
	if wholeRead.Error != nil {
		t.Fatalf("whole-object cursor read refused: %#v", wholeRead.Error)
	}
	if _, present := wholeRead.Result.Structured["neighbors"]; present {
		t.Fatalf("whole-object cursor exposed neighbors: %#v", wholeRead.Result.Structured)
	}
	if service.called {
		t.Fatal("whole-object cursor invoked optional neighbor capability")
	}

	service.called = false
	restPartial := newTestHarness(t)
	restPartial.handler.evidence = service
	response, body = callRestRead(t, restPartial, http.MethodGet, "?fragment_id="+current.FragmentID+"&limit=4", "")
	if response.Code != http.StatusOK {
		t.Fatalf("partial REST read refused: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, present := body["neighbors"]; present {
		t.Fatalf("partial REST page exposed neighbors: %#v", body)
	}
	if service.called {
		t.Fatal("partial REST page invoked optional neighbor capability")
	}

	service.called = false
	restFinal := newTestHarness(t)
	restFinal.handler.evidence = service
	response, body = callRestRead(t, restFinal, http.MethodGet, "?fragment_id="+current.FragmentID+"&offset=4&limit=4096", "")
	if response.Code != http.StatusOK {
		t.Fatalf("offset>0 final REST read refused: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, present := body["neighbors"]; present {
		t.Fatalf("offset>0 final REST page exposed neighbors: %#v", body)
	}
	if service.called {
		t.Fatal("offset>0 final REST page invoked optional neighbor capability")
	}

	service.called = false
	restWhole := newTestHarness(t)
	restWhole.handler.evidence = service
	response, body = callRestRead(t, restWhole, http.MethodGet, "?fragment_id="+current.FragmentID+"&cursor=v1:0", "")
	if response.Code != http.StatusOK {
		t.Fatalf("whole-object REST read refused: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, present := body["neighbors"]; present {
		t.Fatalf("whole-object REST page exposed neighbors: %#v", body)
	}
	if service.called {
		t.Fatal("whole-object REST page invoked optional neighbor capability")
	}
}

func TestNeighborCapabilityErrorKeepsSuccessfulPrimaryReads(t *testing.T) {
	current := testEvidenceFragment(t)
	current.Text = []byte("primary page")
	current.EvidenceTextHash = mcpEvidenceReadTextHash(current.Text)
	current.ExtractionID = "extraction_current"
	current.SourceObjectID = "object_current"
	current.SourceVersionID = "version_current"
	current.Ordinal = 3

	service := &neighborReadEvidence{fragment: current, neighborsErr: errors.New("neighbors unavailable")}
	harness := newTestHarness(t)
	harness.handler.evidence = service
	mcp := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+current.FragmentID+`","limit":4096}`)
	if mcp.Error != nil {
		t.Fatalf("MCP primary read failed after optional capability error: %#v", mcp.Error)
	}
	if mcp.Result.Structured["text"] != string(current.Text) {
		t.Fatalf("MCP primary text=%#v want %q", mcp.Result.Structured["text"], current.Text)
	}
	if _, present := mcp.Result.Structured["neighbors"]; present {
		t.Fatalf("MCP exposed neighbors after capability error: %#v", mcp.Result.Structured)
	}
	if !service.called {
		t.Fatal("MCP did not attempt the optional neighbor capability")
	}

	service.called = false
	rest := newTestHarness(t)
	rest.handler.evidence = service
	response, body := callRestRead(t, rest, http.MethodGet, "?fragment_id="+current.FragmentID+"&limit=4096", "")
	if response.Code != http.StatusOK {
		t.Fatalf("REST primary read failed after optional capability error: status=%d body=%s", response.Code, response.Body.String())
	}
	if body["text"] != string(current.Text) {
		t.Fatalf("REST primary text=%#v want %q", body["text"], current.Text)
	}
	if _, present := body["neighbors"]; present {
		t.Fatalf("REST exposed neighbors after capability error: %#v", body)
	}
	if !service.called {
		t.Fatal("REST did not attempt the optional neighbor capability")
	}
}
