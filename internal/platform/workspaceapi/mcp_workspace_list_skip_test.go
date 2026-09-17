package workspaceapi

// R3a-1 KV-A02 focused test: the typed, content-free skip ledger of the
// workspace object inventory. It proves that both the MCP knowvault_list_objects
// tool and its REST parity route
// (GET /api/v1/workspaces/{workspace_id}/tools/list-objects) render every skip
// row with the object's stable external_id, the closed reason_code and the
// RFC3339 moment, and report skipped_count as the row count. The projection is a
// guard: dropping the typed reason_code must fail this probe (the declared RED
// weakening `r3a1-list-typed-skip-reason-dropped`), so a skip can never degrade
// to an untyped silence.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// skipInventoryEvidence is a minimal inventory capability fake returning one
// readable object row plus two typed skip rows, so both transports exercise the
// shared mcpWorkspaceSkipProjection through the same workspaceInventoryPage
// core.
type skipInventoryEvidence struct {
	*fakeEvidenceService
	items []evidence.ObjectInventoryItem
	skips []evidence.ObjectInventorySkip
}

func (service *skipInventoryEvidence) ListObjects(context.Context, database.AccessContext, string, bool, int64, int64) (evidence.ObjectInventoryPage, error) {
	return evidence.ObjectInventoryPage{Items: service.items, Skipped: service.skips}, nil
}

// skipLedgerHarness mounts a handler whose evidence service carries one object
// and two typed skips observed at a fixed moment.
func skipLedgerHarness(t *testing.T) (*testHarness, time.Time) {
	t.Helper()
	moment := time.Date(2026, 9, 11, 7, 15, 0, 0, time.UTC)
	harness := newTestHarness(t)
	service := &skipInventoryEvidence{
		fakeEvidenceService: harness.evidence,
		items:               testInventoryItems()[:1],
		skips: []evidence.ObjectInventorySkip{
			{ExternalID: "native:skipped-a", ReasonCode: "QUARANTINED_MALFORMED", ObservedAt: moment},
			{ExternalID: "native:skipped-b", ReasonCode: "EXTRACTION_UNSUPPORTED_VERSION", ObservedAt: moment},
		},
	}
	harness.handler.evidence = service
	return harness, moment
}

// TestMCPWorkspaceListSkipLedgerCarriesTypedReasonAndCount proves the MCP tool
// and its REST parity route both render the typed skip ledger: every skip row
// carries external_id, the closed reason_code and the moment, and skipped_count
// equals the row count.
func TestMCPWorkspaceListSkipLedgerCarriesTypedReasonAndCount(t *testing.T) {
	harness, moment := skipLedgerHarness(t)

	envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha"}`)
	if envelope.Error != nil {
		t.Fatalf("inventory list refused: %#v", envelope.Error)
	}
	assertSkipLedger(t, envelope.Result.Structured, moment)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/tools/list-objects", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("REST list-objects status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("REST list-objects did not decode: %v: %s", err, response.Body.String())
	}
	assertSkipLedger(t, body, moment)
}

// assertSkipLedger checks one transport's skip ledger against the two typed
// skips mounted by skipLedgerHarness.
func assertSkipLedger(t *testing.T, payload map[string]any, moment time.Time) {
	t.Helper()
	if count, ok := payload["skipped_count"].(float64); !ok || count != 2 {
		t.Fatalf("skipped_count=%#v want 2", payload["skipped_count"])
	}
	rows, ok := payload["skipped"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("skipped=%#v", payload["skipped"])
	}
	want := []struct{ id, reason string }{
		{"native:skipped-a", "QUARANTINED_MALFORMED"},
		{"native:skipped-b", "EXTRACTION_UNSUPPORTED_VERSION"},
	}
	for index, expected := range want {
		row, ok := rows[index].(map[string]any)
		if !ok {
			t.Fatalf("skipped[%d]=%#v", index, rows[index])
		}
		if row["external_id"] != expected.id {
			t.Fatalf("skipped[%d].external_id=%#v want %q", index, row["external_id"], expected.id)
		}
		if row["reason_code"] != expected.reason {
			t.Fatalf("skipped[%d].reason_code=%#v want %q", index, row["reason_code"], expected.reason)
		}
		if row["moment"] != moment.UTC().Format(time.RFC3339) {
			t.Fatalf("skipped[%d].moment=%#v want %q", index, row["moment"], moment.UTC().Format(time.RFC3339))
		}
	}
}
