package reranking

import (
	"encoding/json"
	"os"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestComposeProfileMatchesRecordedRuntimeIdentity(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/compose/reranking-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	runtimeRaw, err := os.ReadFile("../../deploy/compose/reranking-runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var runtime map[string]any
	if err := json.Unmarshal(runtimeRaw, &runtime); err != nil {
		t.Fatal(err)
	}
	identity, err := canon.CanonicalJSON(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ConfigurationHash != canon.Hash(identity) {
		t.Fatal("runtime identity differs from mounted profile")
	}
	if runtime["model_id"] != profile.ModelID || profile.MaxCandidates != 32 {
		t.Fatal("runtime model or candidate budget differs")
	}
}
