package workspaceapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

// Neither missing nor recorded immutable ingest metadata proves the current
// index's coverage. Exercise the public JSON encoding and both MCP channels,
// including REST parity, so null cannot silently become false or disappear.
func TestWorkspaceObjectInventoryEmbeddingStatusUnknown(t *testing.T) {
	for _, recordedIngestProfile := range []bool{false, true} {
		name := "no_ingest_profile"
		if recordedIngestProfile {
			name = "recorded_ingest_profile"
		}
		t.Run(name, func(t *testing.T) {
			item := testInventoryItems()[0]
			if recordedIngestProfile {
				item.EmbeddingProfileID = "profile_original"
				item.EmbeddingProfileHash = "sha256:" + strings.Repeat("ef", 32)
			}
			harness := workspaceListHarness(t, &fakeInventoryEvidence{
				items: []evidence.ObjectInventoryItem{item},
			})
			envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha"}`)
			if envelope.Error != nil {
				t.Fatalf("inventory list refused: %#v", envelope.Error)
			}
			objects, ok := envelope.Result.Structured["objects"].([]any)
			if !ok || len(objects) != 1 {
				t.Fatalf("inventory objects=%#v", envelope.Result.Structured["objects"])
			}
			object, ok := objects[0].(map[string]any)
			if !ok {
				t.Fatalf("inventory object=%#v", objects[0])
			}
			if embedded, present := object["embedded"]; !present || embedded != nil {
				t.Fatalf("embedded must be explicit null, got present=%t value=%#v", present, embedded)
			}
			if object["embedding_status"] != "UNKNOWN" {
				t.Fatalf("embedding_status=%#v", object["embedding_status"])
			}
			for _, key := range []string{"embedding_profile", "embedding_profile_hash"} {
				if value, present := object[key]; present {
					t.Fatalf("ingest metadata presented as indexed profile: %s=%#v", key, value)
				}
			}
			text := mcpContentTextBlock(t, envelope.Result.Content)
			if strings.Count(text, " embedded=unknown embedding_status=UNKNOWN") != 1 ||
				strings.Contains(text, "embedding_profile=") || strings.Contains(text, "embedding_profile_hash=") {
				t.Fatalf("text must report unknown without an indexed profile: %q", text)
			}
			mcpAssertAddressesInText(t, text, []any{object["address"]})
			if recordedIngestProfile && (strings.Contains(text, item.EmbeddingProfileID) ||
				strings.Contains(text, item.EmbeddingProfileHash)) {
				t.Fatalf("text disclosed the original profile as current: %q", text)
			}

			for _, method := range []string{http.MethodGet, http.MethodPost} {
				response := httptest.NewRecorder()
				harness.handler.ServeHTTP(response, harness.request(method, workspacesPath+"/ws_alpha/tools/list-objects", ""))
				if response.Code != http.StatusOK {
					t.Fatalf("REST %s status=%d body=%s", method, response.Code, response.Body.String())
				}
				var body struct {
					Objects []map[string]any `json:"objects"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("REST %s inventory: %v", method, err)
				}
				if len(body.Objects) != 1 || !reflect.DeepEqual(body.Objects[0], object) {
					t.Fatalf("REST %s projection differs from MCP: %#v", method, body.Objects)
				}
			}
		})
	}
}
