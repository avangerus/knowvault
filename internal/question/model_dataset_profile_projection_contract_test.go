package question

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// TestProjectModelDatasetProfileJSONAllowList pins the exact JSON key set of
// the model-facing dataset profile projection. It marshals the projected
// contract, decodes it back into generic maps, and asserts that every object
// exposes precisely the allow-listed keys: no more, no less.
func TestProjectModelDatasetProfileJSONAllowList(t *testing.T) {
	profile := newProjectionFixtureProfile(t)

	projected, err := projectModelDatasetProfile(profile)
	if err != nil {
		t.Fatalf("projectModelDatasetProfile returned error: %v", err)
	}

	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatalf("marshal projection: %v", err)
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal projection root: %v", err)
	}
	assertProjectionKeySet(t, "root", rootKeys(root), []string{
		"schema_version", "capability", "dataset_id", "profile_version", "profile_hash",
		"dataset_label", "dataset_description", "grain_description", "fields", "measures",
		"time", "declared_coverage_policy", "limits", "projection_digest",
	})

	fields, err := decodeProjectionArray(root, "fields")
	if err != nil {
		t.Fatalf("decode fields: %v", err)
	}
	if len(fields) == 0 {
		t.Fatal("projected fields are empty")
	}
	for _, field := range fields {
		assertProjectionKeySet(t, "field", rawKeys(field), []string{
			"token", "label", "description", "null_meaning", "aliases", "logical_type",
			"nullable", "filterable", "groupable", "sortable", "output_allowed",
			"allowed_operators",
		})
	}

	measures, err := decodeProjectionArray(root, "measures")
	if err != nil {
		t.Fatalf("decode measures: %v", err)
	}
	if len(measures) == 0 {
		t.Fatal("projected measures are empty")
	}
	for _, measure := range measures {
		assertProjectionKeySet(t, "measure", rawKeys(measure), []string{
			"id", "label", "description", "aliases", "reducer", "unit", "null_policy",
		})
	}

	timeRaw, ok := root["time"]
	if !ok {
		t.Fatal("projection root missing time")
	}
	timeObject, err := decodeProjectionObject(timeRaw)
	if err != nil {
		t.Fatalf("decode time: %v", err)
	}
	assertProjectionKeySet(t, "time", rawKeys(timeObject), []string{
		"kind", "field_token", "reporting_timezone", "calendar",
	})

	limitsRaw, ok := root["limits"]
	if !ok {
		t.Fatal("projection root missing limits")
	}
	limitsObject, err := decodeProjectionObject(limitsRaw)
	if err != nil {
		t.Fatalf("decode limits: %v", err)
	}
	assertProjectionKeySet(t, "limits", rawKeys(limitsObject), []string{
		"max_output_groups", "max_period_days",
	})
}

// TestProjectModelDatasetProfileIsDeterministicAndDetached proves that the
// projection is deterministic, owns all nested slices returned to its caller,
// and carries a digest that can be recomputed from the canonical JSON payload.
func TestProjectModelDatasetProfileIsDeterministicAndDetached(t *testing.T) {
	profile := newProjectionFixtureProfile(t)
	profileHash := profile.Hash()

	first, err := projectModelDatasetProfile(profile)
	if err != nil {
		t.Fatalf("first projectModelDatasetProfile returned error: %v", err)
	}
	second, err := projectModelDatasetProfile(profile)
	if err != nil {
		t.Fatalf("second projectModelDatasetProfile returned error: %v", err)
	}
	firstJSON, err := canon.CanonicalJSON(first)
	if err != nil {
		t.Fatalf("canonicalize first projection: %v", err)
	}
	secondJSON, err := canon.CanonicalJSON(second)
	if err != nil {
		t.Fatalf("canonicalize second projection: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("two projections are not byte-identical:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	if first.ProjectionDigest != second.ProjectionDigest {
		t.Fatalf("projection digests differ: first=%q second=%q", first.ProjectionDigest, second.ProjectionDigest)
	}

	if len(first.Fields) == 0 || len(first.Fields[0].Aliases) == 0 || len(first.Fields[0].AllowedOperators) == 0 {
		t.Fatal("fixture field does not expose nested slices to mutate")
	}
	if len(first.Measures) == 0 || len(first.Measures[0].Aliases) == 0 {
		t.Fatal("fixture measure does not expose aliases to mutate")
	}
	first.Fields[0].Aliases[0] = "mutated field alias"
	first.Fields[0].AllowedOperators[0] = "MUTATED_OPERATOR"
	first.Measures[0].Aliases[0] = "mutated measure alias"
	first.Fields[0].Aliases = append(first.Fields[0].Aliases, "mutated nested field alias")
	first.Fields[0].AllowedOperators = append(first.Fields[0].AllowedOperators, "MUTATED_NESTED_OPERATOR")
	first.Measures[0].Aliases = append(first.Measures[0].Aliases, "mutated nested measure alias")

	third, err := projectModelDatasetProfile(profile)
	if err != nil {
		t.Fatalf("reproject after returned-value mutation: %v", err)
	}
	thirdJSON, err := canon.CanonicalJSON(third)
	if err != nil {
		t.Fatalf("canonicalize reprojected profile: %v", err)
	}
	if !bytes.Equal(secondJSON, thirdJSON) {
		t.Fatalf("returned-value mutation changed a later projection:\nwant: %s\n got: %s", secondJSON, thirdJSON)
	}
	if third.ProjectionDigest != second.ProjectionDigest {
		t.Fatalf("returned-value mutation changed digest: before=%q after=%q", second.ProjectionDigest, third.ProjectionDigest)
	}
	if profile.Hash() != profileHash {
		t.Fatalf("returned-value mutation changed source profile hash: before=%q after=%q", profileHash, profile.Hash())
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(thirdJSON, &root); err != nil {
		t.Fatalf("decode canonical projection: %v", err)
	}
	digestRaw, ok := root["projection_digest"]
	if !ok {
		t.Fatal("canonical projection has no projection_digest")
	}
	var savedDigest string
	if err := json.Unmarshal(digestRaw, &savedDigest); err != nil {
		t.Fatalf("decode projection_digest: %v", err)
	}
	if savedDigest != third.ProjectionDigest {
		t.Fatalf("JSON projection_digest = %q, DTO digest = %q", savedDigest, third.ProjectionDigest)
	}
	delete(root, "projection_digest")
	withoutDigest, err := canon.CanonicalJSON(root)
	if err != nil {
		t.Fatalf("canonicalize projection without digest: %v", err)
	}
	if recomputed := canon.Hash(withoutDigest); recomputed != third.ProjectionDigest {
		t.Fatalf("recomputed projection digest = %q, want %q", recomputed, third.ProjectionDigest)
	}
}

// assertProjectionKeySet sorts both the actual and expected key slices and
// compares them for exact equality.
func assertProjectionKeySet(t *testing.T, scope string, actual, expected []string) {
	t.Helper()
	sortedActual := append([]string{}, actual...)
	sortedExpected := append([]string{}, expected...)
	sort.Strings(sortedActual)
	sort.Strings(sortedExpected)
	if len(sortedActual) != len(sortedExpected) {
		t.Fatalf("%s keys = %v, want %v", scope, sortedActual, sortedExpected)
	}
	for index := range sortedExpected {
		if sortedActual[index] != sortedExpected[index] {
			t.Fatalf("%s keys = %v, want %v", scope, sortedActual, sortedExpected)
		}
	}
}

func rootKeys(root map[string]json.RawMessage) []string {
	return rawKeys(root)
}

func rawKeys(object map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	return keys
}

func decodeProjectionArray(root map[string]json.RawMessage, key string) ([]map[string]json.RawMessage, error) {
	raw, ok := root[key]
	if !ok {
		return nil, &Error{code: CodeInvalid}
	}
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objects); err != nil {
		return nil, err
	}
	return objects, nil
}

func decodeProjectionObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	return object, nil
}
