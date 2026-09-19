package governedquery

import "testing"

func validPreset() Preset {
	return Preset{
		ID: "check-contracts", Version: "v1", Name: "Check contracts",
		Description:     "Returns the current contract counters.",
		Phrases:         []string{"check contracts", "contract status please"},
		WorkspaceID:     "ws_alpha",
		SourceAttemptID: "gqat_reviewed", SQLHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExposedSchemaRevision: 3,
	}
}

func TestPresetValidationRejectsAmbiguousPhrasesAndInvalidAttemptBinding(t *testing.T) {
	first := validPreset()
	second := validPreset()
	second.ID = "other"
	second.Phrases = []string{"  CHECK   CONTRACTS "}
	if err := validatePresets([]Preset{first, second}); err == nil {
		t.Fatal("normalized phrase collision must be rejected")
	}
	invalid := validPreset()
	invalid.SQLHash = "sha256:not-a-hash"
	if err := validatePresets([]Preset{invalid}); err == nil {
		t.Fatal("a preset without a valid reviewed SQL hash must be rejected")
	}
}

func TestPresetLookupIsExactAndReceiptHashBindsStatement(t *testing.T) {
	preset := validPreset()
	config := Config{Presets: []Preset{preset}}
	matched, ok := config.PresetByPhrase("ws_alpha", "  CONTRACT   STATUS PLEASE ")
	if !ok || matched.ID != preset.ID {
		t.Fatalf("exact normalized phrase did not resolve: %+v %v", matched, ok)
	}
	if _, ok := config.PresetByPhrase("ws_alpha", "contract status please today"); ok {
		t.Fatal("a near phrase must not trigger a preset")
	}
	if _, ok := config.PresetByPhrase("ws_beta", "check contracts"); ok {
		t.Fatal("a preset must not be discoverable from another workspace")
	}
	changed := preset
	changed.SQLHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if preset.Hash() == changed.Hash() {
		t.Fatal("preset receipt hash must bind the reviewed SQL hash")
	}
	changed = preset
	changed.WorkspaceID = "ws_beta"
	if preset.Hash() == changed.Hash() {
		t.Fatal("preset receipt hash must bind the workspace")
	}
	changed = preset
	changed.Description = "Different public meaning."
	if preset.Hash() == changed.Hash() {
		t.Fatal("preset receipt hash must bind public catalogue metadata")
	}
	if summary := preset.Summary(); summary.PresetHash == "" || len(summary.Phrases) != 2 {
		t.Fatalf("incomplete preset summary: %+v", summary)
	}
}

func TestPresetIdentifiersAndPhrasesMayRepeatOnlyAcrossWorkspaces(t *testing.T) {
	first := validPreset()
	second := validPreset()
	second.WorkspaceID = "ws_beta"
	if err := validatePresets([]Preset{first, second}); err != nil {
		t.Fatalf("the same controlled vocabulary may be reused in another workspace: %v", err)
	}
	second.WorkspaceID = first.WorkspaceID
	if err := validatePresets([]Preset{first, second}); err == nil {
		t.Fatal("duplicate ids and phrases inside one workspace must be rejected")
	}
}

func TestPresetBindingRederivesStoredSQLHash(t *testing.T) {
	preset := validPreset()
	sqlText := "SELECT count(*) FROM reporting.contracts"
	preset.SQLHash = sha256Hex(sqlText)
	attempt := ExecutedAttempt{AttemptID: preset.SourceAttemptID, ExposedSchemaRevision: preset.ExposedSchemaRevision, SQLHash: preset.SQLHash, SQLText: sqlText}
	if !preset.Binds(attempt) {
		t.Fatal("exact reviewed attempt should bind")
	}
	attempt.SQLText = "SELECT secret FROM reporting.hidden"
	if preset.Binds(attempt) {
		t.Fatal("stored SQL text that does not match the reviewed hash must be refused")
	}
	attempt.SQLText = "DELETE FROM reporting.contracts"
	attempt.SQLHash = sha256Hex(attempt.SQLText)
	preset.SQLHash = attempt.SQLHash
	if preset.Binds(attempt) {
		t.Fatal("a mutating stored attempt must be refused even when its hash matches")
	}
}
