package workspaceapi

// R3a-1 KV-A04a focused tests: the code-source mirror age in the workspace
// object inventory. They prove that a GIT_FILE row returned by the MCP
// knowvault_list_objects tool and by its REST parity route
// (GET /api/v1/workspaces/{workspace_id}/tools/list-objects) carries a
// non-negative mirror_age_seconds and an RFC3339 mirrored_at when the code
// source has an already-persisted last successful mirror/sync moment, and that
// a document/evidence row keeps its prior projection with no mirror member, so
// a document is never mislabelled as a mirror.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

// codeMirrorInventoryItems builds one code-source row (GIT_FILE) with a
// persisted mirror moment and one document row with none.
func codeMirrorInventoryItems() ([]evidence.ObjectInventoryItem, time.Time) {
	moment := time.Date(2026, 9, 10, 8, 30, 0, 0, time.UTC)
	return []evidence.ObjectInventoryItem{
		{
			SourceObjectID: "object_code", ObjectType: mcpGrepCodeObjectType, ConnectionID: "conn_git",
			LifecycleState: "ACTIVE", SourceVersionID: "version_code", ExternalVersionKey: "native:commit:abc",
			ContentHash: strings.Repeat("ab", 32), ObservedAt: moment, VersionState: "CURRENT", Current: true,
			FragmentCount: 1, FirstFragmentID: "fragment_code", FirstOrdinal: 1, LastOrdinal: 1,
			MirrorAgeSeconds: 90, MirroredAt: &moment,
		},
		{
			SourceObjectID: "object_doc", ObjectType: "FILE", ConnectionID: "conn_docs",
			LifecycleState: "ACTIVE", SourceVersionID: "version_doc", ExternalVersionKey: "native:doc-a",
			ContentHash: strings.Repeat("cd", 32), ObservedAt: moment, VersionState: "CURRENT", Current: true,
			FragmentCount: 1, FirstFragmentID: "fragment_doc", FirstOrdinal: 1, LastOrdinal: 1,
		},
	}, moment
}

// TestMCPWorkspaceListCodeSourceCarriesMirrorAge proves the MCP tool and its
// REST parity route both expose the code-source mirror age, and that a document
// row carries no mirror member.
func TestMCPWorkspaceListCodeSourceCarriesMirrorAge(t *testing.T) {
	items, moment := codeMirrorInventoryItems()
	service := &fakeInventoryEvidence{items: items}
	harness := workspaceListHarness(t, service)

	envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha"}`)
	if envelope.Error != nil {
		t.Fatalf("inventory list refused: %#v", envelope.Error)
	}
	objects, ok := envelope.Result.Structured["objects"].([]any)
	if !ok || len(objects) != 2 {
		t.Fatalf("inventory objects=%#v", envelope.Result.Structured["objects"])
	}
	code, _ := objects[0].(map[string]any)
	if _, ok := code["address"]; !ok {
		t.Fatalf("code row lost its address: %#v", code)
	}
	if age, ok := code["mirror_age_seconds"].(float64); !ok || age != 90 {
		t.Fatalf("code row mirror_age_seconds=%#v", code["mirror_age_seconds"])
	}
	if code["mirrored_at"] != moment.Format(time.RFC3339) {
		t.Fatalf("code row mirrored_at=%#v want %q", code["mirrored_at"], moment.Format(time.RFC3339))
	}
	doc, _ := objects[1].(map[string]any)
	if _, ok := doc["mirror_age_seconds"]; ok {
		t.Fatalf("document row mislabelled with mirror_age_seconds: %#v", doc)
	}
	if _, ok := doc["mirrored_at"]; ok {
		t.Fatalf("document row mislabelled with mirrored_at: %#v", doc)
	}
	if doc["object_type"] != "FILE" || doc["source_object_id"] != "object_doc" {
		t.Fatalf("document row changed: %#v", doc)
	}

	// The REST parity route returns the identical projection.
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/tools/list-objects", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("REST list-objects status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("REST list-objects did not decode: %v: %s", err, response.Body.String())
	}
	if len(body.Objects) != 2 {
		t.Fatalf("REST objects=%#v", body.Objects)
	}
	if age, ok := body.Objects[0]["mirror_age_seconds"].(float64); !ok || age != 90 {
		t.Fatalf("REST code row mirror_age_seconds=%#v", body.Objects[0]["mirror_age_seconds"])
	}
	if body.Objects[0]["mirrored_at"] != moment.Format(time.RFC3339) {
		t.Fatalf("REST code row mirrored_at=%#v", body.Objects[0]["mirrored_at"])
	}
	if _, ok := body.Objects[1]["mirror_age_seconds"]; ok {
		t.Fatalf("REST document row mislabelled: %#v", body.Objects[1])
	}
	if _, ok := body.Objects[1]["mirrored_at"]; ok {
		t.Fatalf("REST document row mislabelled with mirrored_at: %#v", body.Objects[1])
	}
}

// TestMCPWorkspaceListMirrorAgeNeverNegative proves a missing or future mirror
// moment is reported as a non-negative age and never leaks a negative integer.
func TestMCPWorkspaceListMirrorAgeNeverNegative(t *testing.T) {
	item := evidence.ObjectInventoryItem{
		SourceObjectID: "object_code", ObjectType: mcpGrepCodeObjectType, ConnectionID: "conn_git",
		SourceVersionID: "version_code", ExternalVersionKey: "native:commit:abc",
		ContentHash: strings.Repeat("ab", 32), ObservedAt: time.Date(2026, 9, 10, 8, 30, 0, 0, time.UTC),
		VersionState: "CURRENT", Current: true, MirrorAgeSeconds: -5,
	}
	projection := mcpWorkspaceObjectProjection(item)
	if age, ok := projection["mirror_age_seconds"].(int64); !ok || age != 0 {
		t.Fatalf("negative mirror age not clamped: %#v", projection["mirror_age_seconds"])
	}
	if _, ok := projection["mirrored_at"]; ok {
		t.Fatalf("a row without a persisted moment carried mirrored_at: %#v", projection)
	}
}
