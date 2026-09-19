package governedquery

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	maxPresetCount       = 128
	maxPresetPhraseCount = 32
)

// Preset is one administrator-mounted, immutable reference to a live query
// that was already executed and reviewed. The mount contains no SQL text; no
// API, MCP client, model or workspace request can create or replace it.
type Preset struct {
	ID                    string
	Version               string
	Name                  string
	Description           string
	Phrases               []string
	WorkspaceID           string
	SourceAttemptID       string
	SQLHash               string
	ExposedSchemaRevision int64
}

// PresetSummary is the safe discovery projection. It deliberately omits the
// SQL text while retaining the versioned content hash needed for an execution
// receipt.
type PresetSummary struct {
	ID                    string   `json:"id"`
	Version               string   `json:"version"`
	Name                  string   `json:"name"`
	Description           string   `json:"description"`
	Phrases               []string `json:"phrases"`
	PresetHash            string   `json:"preset_hash"`
	SourceAttemptID       string   `json:"source_attempt_id"`
	SQLHash               string   `json:"sql_hash"`
	ExposedSchemaRevision int64    `json:"exposed_schema_revision"`
}

func (preset Preset) Summary() PresetSummary {
	return PresetSummary{
		ID: preset.ID, Version: preset.Version, Name: preset.Name,
		Description: preset.Description, Phrases: append([]string(nil), preset.Phrases...), PresetHash: preset.Hash(),
		SourceAttemptID: preset.SourceAttemptID, SQLHash: preset.SQLHash, ExposedSchemaRevision: preset.ExposedSchemaRevision,
	}
}

// Hash binds the public preset identity to the reviewed attempt, SQL hash and
// exposed-schema revision. It is content-free.
func (preset Preset) Hash() string {
	payload, _ := json.Marshal(struct {
		ID                    string   `json:"id"`
		Version               string   `json:"version"`
		Name                  string   `json:"name"`
		Description           string   `json:"description"`
		Phrases               []string `json:"phrases"`
		WorkspaceID           string   `json:"workspace_id"`
		SourceAttemptID       string   `json:"source_attempt_id"`
		SQLHash               string   `json:"sql_hash"`
		ExposedSchemaRevision int64    `json:"exposed_schema_revision"`
	}{preset.ID, preset.Version, preset.Name, preset.Description, preset.Phrases, preset.WorkspaceID, preset.SourceAttemptID, preset.SQLHash, preset.ExposedSchemaRevision})
	return sha256Hex(string(payload))
}

func validatePresets(presets []Preset) error {
	if len(presets) > maxPresetCount {
		return errors.New("too many governed query presets")
	}
	ids := make(map[string]struct{}, len(presets))
	phrases := make(map[string]struct{})
	for _, preset := range presets {
		if !validOpaque(preset.ID) || !validOpaque(preset.Version) ||
			!boundedText(preset.Name, 1, 200) || !boundedText(preset.Description, 1, 2000) ||
			len(preset.Phrases) == 0 || len(preset.Phrases) > maxPresetPhraseCount ||
			!validOpaque(preset.WorkspaceID) || !validOpaque(preset.SourceAttemptID) ||
			!validSQLHash(preset.SQLHash) || preset.ExposedSchemaRevision < 1 {
			return errors.New("invalid governed query preset")
		}
		idKey := preset.WorkspaceID + "\x00" + preset.ID
		if _, exists := ids[idKey]; exists {
			return errors.New("duplicate governed query preset id")
		}
		ids[idKey] = struct{}{}
		local := make(map[string]struct{}, len(preset.Phrases))
		for _, phrase := range preset.Phrases {
			normalized := normalizePresetPhrase(phrase)
			if normalized == "" || len([]byte(normalized)) > 256 {
				return errors.New("invalid governed query preset phrase")
			}
			if _, exists := local[normalized]; exists {
				return errors.New("duplicate governed query preset phrase")
			}
			local[normalized] = struct{}{}
			phraseKey := preset.WorkspaceID + "\x00" + normalized
			if _, exists := phrases[phraseKey]; exists {
				return errors.New("ambiguous governed query preset phrase")
			}
			phrases[phraseKey] = struct{}{}
		}
	}
	return nil
}

func validSQLHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func boundedText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len([]byte(value)) >= minimum && len([]byte(value)) <= maximum && strings.TrimSpace(value) == value
}

func normalizePresetPhrase(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func (config Config) HasPresets() bool { return len(config.Presets) > 0 }

func (config Config) PresetSummaries(workspaceID string) []PresetSummary {
	result := make([]PresetSummary, 0, len(config.Presets))
	for _, preset := range config.Presets {
		if preset.WorkspaceID == workspaceID {
			result = append(result, preset.Summary())
		}
	}
	return result
}

func (config Config) PresetByID(workspaceID, id string) (Preset, bool) {
	for _, preset := range config.Presets {
		if preset.WorkspaceID == workspaceID && preset.ID == id {
			return preset, true
		}
	}
	return Preset{}, false
}

// Binds verifies that the server-loaded attempt is exactly the reviewed one.
// Re-deriving the SQL hash matters even though the attempt table is immutable:
// the preset runner must not trust a stored hash column more than promotion
// does, and must refuse before executing if persistence was corrupted.
func (preset Preset) Binds(attempt ExecutedAttempt) bool {
	if attempt.AttemptID != preset.SourceAttemptID || attempt.ExposedSchemaRevision != preset.ExposedSchemaRevision ||
		!constantTimeEqual(attempt.SQLHash, preset.SQLHash) || !constantTimeEqual(sha256Hex(attempt.SQLText), preset.SQLHash) {
		return false
	}
	return staticPrecheck(attempt.SQLText) == nil
}

func (config Config) PresetByPhrase(workspaceID, phrase string) (Preset, bool) {
	normalized := normalizePresetPhrase(phrase)
	if normalized == "" {
		return Preset{}, false
	}
	for _, preset := range config.Presets {
		if preset.WorkspaceID != workspaceID {
			continue
		}
		for _, candidate := range preset.Phrases {
			if normalizePresetPhrase(candidate) == normalized {
				return preset, true
			}
		}
	}
	return Preset{}, false
}
