package workspaceapi

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

type currentOnlyGrepEvidence struct {
	*fakeGrepInventoryEvidence
	historicalID string
}

func (service *currentOnlyGrepEvidence) ReadObject(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (evidence.WholeObject, error) {
	if fragmentID == service.historicalID {
		return evidence.WholeObject{}, evidence.ErrNotFound
	}
	return service.fakeGrepInventoryEvidence.ReadObject(ctx, access, workspaceID, fragmentID)
}

type exactInventoryGrepEvidence struct {
	*currentOnlyGrepEvidence
	exactCalls   int
	wrongVersion bool
}

func (service *exactInventoryGrepEvidence) ReadObjectExactVersion(_ context.Context, _ database.AccessContext, _, fragmentID, versionID string) (evidence.WholeObject, error) {
	service.exactCalls++
	object, ok := service.objects[fragmentID]
	if !ok || object.Fragment.SourceVersionID != versionID {
		return evidence.WholeObject{}, evidence.ErrNotFound
	}
	if service.wrongVersion {
		object.Fragment.SourceVersionID = "version_wrong"
	}
	return object, nil
}

func TestMCPGrepHistoricalInventoryUsesExactVersion(t *testing.T) {
	for _, mode := range []string{"all_versions", "ref", "address"} {
		t.Run(mode, func(t *testing.T) {
			base, ids := grepRefService(t)
			service := &exactInventoryGrepEvidence{currentOnlyGrepEvidence: &currentOnlyGrepEvidence{fakeGrepInventoryEvidence: base, historicalID: ids["a"]}}
			harness := grepInventoryHarness(t, base)
			harness.handler.evidence = service
			arguments := `{"workspace_id":"ws_alpha","pattern":"needle","all_versions":true}`
			if mode == "ref" {
				arguments = `{"workspace_id":"ws_alpha","pattern":"needle","ref":"aaaa"}`
			}
			if mode == "address" {
				canonical := mcpGrepCanonicalAddressKeyed(nil, base.objects[ids["a"]], "aaaa")
				arguments = `{"workspace_id":"ws_alpha","pattern":"needle","address":` + jsonString(t, canonical) + `}`
			}
			envelope := callMCPGrep(t, harness, arguments)
			if envelope.Error != nil || len(envelope.Result.Structured.Matches) == 0 || service.exactCalls == 0 {
				t.Fatalf("historical %s: error=%#v matches=%d exact reads=%d", mode, envelope.Error, len(envelope.Result.Structured.Matches), service.exactCalls)
			}
			found := false
			for _, hit := range envelope.Result.Structured.Matches {
				found = found || hit["excerpt"] == "package main\n\n// needle lives at ref A\n"
			}
			if !found {
				t.Fatalf("historical bytes absent: %#v", envelope.Result.Structured.Matches)
			}
		})
	}
}

func TestMCPGrepHistoricalInventoryRefusesUnavailableOrWrongVersion(t *testing.T) {
	base, ids := grepRefService(t)
	current := &currentOnlyGrepEvidence{fakeGrepInventoryEvidence: base, historicalID: ids["a"]}
	for _, objects := range []EvidenceWholeObject{current, &exactInventoryGrepEvidence{currentOnlyGrepEvidence: current, wrongVersion: true}} {
		source := inventoryGrepEvidence{inventory: base, objects: objects}
		page, err := source.GrepFragmentsAtRef(context.Background(), database.AccessContext{}, "ws_alpha", "needle", "aaaa", 0, 10)
		if !errors.Is(err, evidence.ErrNotFound) || len(page.Hits) != 0 {
			t.Fatalf("unavailable or wrong version disclosed data: page=%#v err=%v", page, err)
		}
	}
}
