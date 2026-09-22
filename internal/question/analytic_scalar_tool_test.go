package question

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

func TestAnalyticScalarToolDefinitionIsClosedAndListsMountedProfile(t *testing.T) {
	entry := scalarCapabilityFixtureEntry(t, "orders", 4, analytic.ProfileActive)
	catalog := scalarCapabilityFixtureCatalog(t, "catalog.scalar", 1, []analytic.CatalogEntryInput{entry})
	capability, err := newAnalyticScalarCapability(catalog, []analyticCandidate{scalarCapabilityFromEntry(entry)})
	if err != nil {
		t.Fatalf("construct capability: %v", err)
	}

	definition, err := analyticScalarToolDefinition(capability)
	if err != nil {
		t.Fatalf("build tool definition: %v", err)
	}
	if definition.Function.Name != analyticScalarToolName {
		t.Fatalf("tool name = %q, want %q", definition.Function.Name, analyticScalarToolName)
	}
	var schema map[string]any
	if err := json.Unmarshal(definition.Function.Parameters, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	assertClosedSchemaObjects(t, schema, "schema")
	required, ok := schema["required"].([]any)
	if !ok || len(required) != 10 {
		t.Fatalf("schema required = %#v, want the ten scalar fields", schema["required"])
	}
	for _, field := range []string{"schema_version", "operation", "dataset", "period", "filters", "sort", "limit", "measure", "dimensions", "output"} {
		if !containsJSONString(required, field) {
			t.Fatalf("schema required fields omit %q", field)
		}
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties = %#v", schema["properties"])
	}
	filters, ok := properties["filters"].(map[string]any)
	if !ok || filters["type"] != "array" || filters["minItems"] != float64(2) ||
		filters["maxItems"] != float64(2) || filters["uniqueItems"] != true || filters["const"] != nil {
		t.Fatalf("filter schema = %#v, want exactly the two profile-required non-time predicates", properties["filters"])
	}
	profile := capability.modelProfiles()[0]
	for _, want := range []string{profile.DatasetID, profile.ProfileHash, profile.DatasetLabel, profile.DatasetDescription,
		profile.Measures[0].ID, profile.Measures[0].Description, "filter order_total", "allowed_values=order-1,order-2"} {
		if !strings.Contains(definition.Function.Description, want) {
			t.Fatalf("tool description omits mounted profile detail %q: %s", want, definition.Function.Description)
		}
	}
	items, ok := filters["items"].(map[string]any)
	if !ok {
		t.Fatalf("filter items = %#v", filters["items"])
	}
	branches, ok := items["oneOf"].([]any)
	if !ok {
		t.Fatalf("filter branches = %#v", items["oneOf"])
	}
	foundAllowedValues := false
	for _, rawBranch := range branches {
		branch, _ := rawBranch.(map[string]any)
		branchProperties, _ := branch["properties"].(map[string]any)
		field, _ := branchProperties["field"].(map[string]any)
		if field["const"] != "order_id" {
			continue
		}
		values, _ := branchProperties["values"].(map[string]any)
		valueItems, _ := values["items"].(map[string]any)
		valueProperties, _ := valueItems["properties"].(map[string]any)
		value, _ := valueProperties["value"].(map[string]any)
		enum, _ := value["enum"].([]any)
		foundAllowedValues = len(enum) == 2 && enum[0] == "order-1" && enum[1] == "order-2"
	}
	if !foundAllowedValues {
		t.Fatalf("order_id filter schema omits sealed allowed values: %#v", filters)
	}
}

func TestAnalyticScalarFilterSchemaMergesDuplicateProfileAllowlists(t *testing.T) {
	profile := func(allowed ...string) modelDatasetProfile {
		return modelDatasetProfile{Fields: []modelDatasetProfileField{{
			Token: "code", LogicalType: "TEXT", Filterable: true,
			AllowedOperators: []string{"EQ"}, AllowedValues: append([]string(nil), allowed...),
		}}}
	}

	t.Run("disjoint enums are unioned", func(t *testing.T) {
		value := analyticScalarFilterValueSchema(t, analyticScalarFilterSchema([]modelDatasetProfile{
			profile("alpha", "beta"), profile("gamma"),
		}), "code")
		enum, ok := value["enum"].([]string)
		if !ok || !slices.Equal(enum, []string{"alpha", "beta", "gamma"}) {
			t.Fatalf("merged enum = %#v", value["enum"])
		}
	})

	t.Run("one unrestricted profile makes the schema unrestricted", func(t *testing.T) {
		value := analyticScalarFilterValueSchema(t, analyticScalarFilterSchema([]modelDatasetProfile{
			profile("alpha"), profile(),
		}), "code")
		if _, constrained := value["enum"]; constrained {
			t.Fatalf("unrestricted union retained enum: %#v", value)
		}
	})
}

func analyticScalarFilterValueSchema(t *testing.T, filters map[string]any, fieldToken string) map[string]any {
	t.Helper()
	items, ok := filters["items"].(map[string]any)
	if !ok {
		t.Fatalf("filter items = %#v", filters["items"])
	}
	branches, ok := items["oneOf"].([]any)
	if !ok {
		t.Fatalf("filter branches = %#v", items["oneOf"])
	}
	for _, rawBranch := range branches {
		branch, _ := rawBranch.(map[string]any)
		properties, _ := branch["properties"].(map[string]any)
		field, _ := properties["field"].(map[string]any)
		if field["const"] != fieldToken {
			continue
		}
		values, _ := properties["values"].(map[string]any)
		valueItems, _ := values["items"].(map[string]any)
		valueProperties, _ := valueItems["properties"].(map[string]any)
		value, ok := valueProperties["value"].(map[string]any)
		if !ok {
			t.Fatalf("value schema = %#v", valueProperties["value"])
		}
		return value
	}
	t.Fatalf("field %q is absent from schema %#v", fieldToken, filters)
	return nil
}

func TestAnalyticScalarPresentationIncludesAnswerProvenance(t *testing.T) {
	observation := analyticScalarObservationFixture(t)
	text, result, err := analyticScalarPresentation("How many assigned tasks?", observation)
	if err != nil {
		t.Fatalf("present valid observation: %v", err)
	}
	if text != "Total: 3888 tasks for September 10, 2026." {
		t.Fatalf("presentation = %q, want concise total", text)
	}
	if result == nil || result.Period == nil || result.ObservationWindow == nil {
		t.Fatalf("presentation omitted period or observation window: %#v", result)
	}
	if result.Period.From != "2026-09-10" || result.Period.To != "2026-09-10" {
		t.Fatalf("period = %#v, want the observed day", result.Period)
	}
	if result.Snapshot.RowCount != 407 {
		t.Fatalf("rows = %d, want 407", result.Snapshot.RowCount)
	}
	if result.ObservationWindow.Basis != "CLIENT_READ_CALL" ||
		result.ObservationWindow.StartedAt != "2026-09-10T00:00:01Z" ||
		result.ObservationWindow.CompletedAt != "2026-09-10T00:00:02Z" {
		t.Fatalf("observation window = %#v", result.ObservationWindow)
	}
	if result.ReceiptDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("receipt digest = %q", result.ReceiptDigest)
	}
}

func TestAnalyticScalarPresentationRefusesInvalidObservation(t *testing.T) {
	text, result, err := analyticScalarPresentation("How many?", analyticScalarObservation{})
	if err == nil || text != "" || result != nil || CodeOf(err) != CodeInvalid {
		t.Fatalf("invalid observation result = text %q result %#v err %v, want content-free invalid refusal", text, result, err)
	}
}

func assertClosedSchemaObjects(t *testing.T, value any, path string) {
	t.Helper()
	switch current := value.(type) {
	case map[string]any:
		if current["type"] == "object" && current["additionalProperties"] != false {
			t.Fatalf("%s is an open object: %#v", path, current)
		}
		for key, child := range current {
			assertClosedSchemaObjects(t, child, path+"."+key)
		}
	case []any:
		for index, child := range current {
			assertClosedSchemaObjects(t, child, path+"["+string(rune('0'+index))+"]")
		}
	}
}

func containsJSONString(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
