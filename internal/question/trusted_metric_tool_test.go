package question

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

type trustedMetricProbe struct {
	result    governedask.MetricComparisonResult
	calls     int
	access    database.AccessContext
	workspace string
	metric    string
	dateA     string
	dateB     string
}

func (probe *trustedMetricProbe) ComparisonCatalog(context.Context, database.AccessContext, string) ([]governedask.ComparisonSummary, error) {
	return trustedMetricCatalog(), nil
}

func (probe *trustedMetricProbe) CompareWorkspace(_ context.Context, access database.AccessContext, workspace, metric, dateA, dateB string) (governedask.MetricComparisonResult, error) {
	probe.calls++
	probe.access, probe.workspace, probe.metric, probe.dateA, probe.dateB = access, workspace, metric, dateA, dateB
	return probe.result, nil
}

func trustedMetricCatalog() []governedask.ComparisonSummary {
	return []governedask.ComparisonSummary{{MetricID: "work.assignments", Unit: "unknown", Description: "Assigned work indicator at the latest observed snapshot per date"}}
}

func trustedMetricFixture(t *testing.T) governedask.MetricComparisonResult {
	t.Helper()
	profile, err := metriccompare.NewProfile(metriccompare.ProfileSpec{
		ExposedSchemaRevision: 7, MetricID: "work.assignments", Unit: "unknown",
		Description: "Assigned work indicator", Schema: "reporting", View: "v_metric",
		SubjectColumn: "team_id", SnapshotColumn: "observed_at", MeasureColumn: "amount",
		Timezone: "Europe/Moscow", Filters: []metriccompare.FixedFilter{{Column: "range_kind", Value: "METER"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	row := func(values ...string) []*string {
		cells := make([]*string, len(values))
		for i, value := range values {
			copied := value
			cells[i] = &copied
		}
		return cells
	}
	columns := []string{"local_date", "snapshot_at", "contributing_rows", "distinct_subjects", "nonnull_count", "value"}
	rows := [][]*string{
		row("2026-09-10", "2026-09-10 00:00:00+03", "407", "407", "407", "3888"),
		row("2026-09-09", "2026-09-09 00:00:00+03", "457", "457", "457", "4140"),
	}
	comparison, err := metriccompare.ParseResult(metriccompare.TableResult{Columns: columns, RowCount: 2, Rows: rows}, "2026-09-10", "2026-09-09", profile)
	if err != nil {
		t.Fatal(err)
	}
	result := liveDataResultFixture()
	result.Columns, result.Rows, result.RowCount = columns, rows, 2
	canonical, err := canon.CanonicalJSON(struct {
		Format   string      `json:"format"`
		Columns  []string    `json:"columns"`
		RowCount int         `json:"row_count"`
		Rows     [][]*string `json:"rows"`
	}{liveDataResultFormat, columns, 2, rows})
	if err != nil {
		t.Fatal(err)
	}
	result.ResultDigest = canon.Hash(canonical)
	return governedask.MetricComparisonResult{Ask: result, Comparison: comparison}
}

func TestTrustedMetricDefinitionOnlyAdvertisesApprovedMetric(t *testing.T) {
	if _, ok := trustedMetricToolDefinition(nil); ok {
		t.Fatal("empty catalog advertised")
	}
	definition, ok := trustedMetricToolDefinition(trustedMetricCatalog())
	if !ok || definition.Function.Name != trustedMetricToolName {
		t.Fatalf("definition = %#v", definition)
	}
	var schema struct {
		AdditionalProperties bool     `json:"additionalProperties"`
		Required             []string `json:"required"`
		Properties           map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(definition.Function.Parameters, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties || !reflect.DeepEqual(schema.Required, []string{"metric_id", "date_a", "date_b"}) ||
		!reflect.DeepEqual(schema.Properties["metric_id"].Enum, []string{"work.assignments"}) {
		t.Fatalf("unexpected schema: %#v", schema)
	}
	if strings.Contains(definition.Function.Description, "reporting") || strings.Contains(definition.Function.Description, "SELECT") {
		t.Fatal("physical schema or SQL leaked in tool definition")
	}
}

func TestTrustedMetricToolRejectsUnknownArgumentsBeforeExecution(t *testing.T) {
	probe := &trustedMetricProbe{result: trustedMetricFixture(t)}
	for _, raw := range []string{
		`{"metric_id":"work.assignments","date_a":"2026-09-10","date_b":"2026-09-09","sql":"SELECT secret"}`,
		`{"metric_id":"other.metric","date_a":"2026-09-10","date_b":"2026-09-09"}`,
		`{"metric_id":"work.assignments","date_a":"2026-09-10","date_b":"2026-09-10"}`,
		`{"metric_id":"work.assignments","date_a":"2026-09-10","date_b":"2026-09-09","date_b":"2026-09-08"}`,
	} {
		result, retained, err := invokeTrustedMetricToolRetained(context.Background(), database.AccessContext{}, "ws_current", "qrun_current", probe, trustedMetricCatalog(), json.RawMessage(raw), 8192)
		if err != nil || !result.IsError || retained != nil {
			t.Fatalf("arguments %s accepted: %#v / %v", raw, result, err)
		}
	}
	if probe.calls != 0 {
		t.Fatalf("invalid calls reached governed comparison: %d", probe.calls)
	}
}

func TestTrustedMetricToolReturnsExactComparisonWithPrivateDependency(t *testing.T) {
	probe := &trustedMetricProbe{result: trustedMetricFixture(t)}
	access := database.AccessContext{OrganizationID: "org_current", PrincipalID: "usr_current", RequestID: "req_current"}
	result, retained, err := invokeTrustedMetricToolRetained(context.Background(), access, "ws_current", "qrun_current", probe, trustedMetricCatalog(),
		json.RawMessage(`{"metric_id":"work.assignments","date_a":"2026-09-10","date_b":"2026-09-09"}`), 8192)
	if err != nil || result.IsError || retained == nil {
		t.Fatalf("result = %#v, retained = %#v, err = %v", result, retained, err)
	}
	if probe.calls != 1 || probe.access != access || probe.workspace != "ws_current" || probe.metric != "work.assignments" || probe.dateA != "2026-09-10" || probe.dateB != "2026-09-09" {
		t.Fatalf("delegation scope = %#v", probe)
	}
	var output metricToolResult
	if err := json.Unmarshal(result.Structured, &output); err != nil {
		t.Fatal(err)
	}
	if output.First.Value != "3888" || output.Second.Value != "4140" || output.Delta != "-252" || output.PercentChange != "-6.09" ||
		output.Coverage != metriccompare.ObservedSnapshot || output.Unit != "unknown" || output.First.DistinctSubjects != 407 ||
		output.AttemptID != retained.projection.AttemptID || output.ReceiptDigest != retained.projection.ReceiptDigest {
		t.Fatalf("incorrect comparison output: %#v", output)
	}
	if strings.Contains(result.Text, "SELECT") || strings.Contains(result.Text, "private") || strings.Contains(result.Text, "connection_id") || strings.Contains(result.Text, "sql_hash") {
		t.Fatalf("private execution metadata leaked: %s", result.Text)
	}
	if !retained.dependency.validForRun("qrun_current") {
		t.Fatal("dependency was not retained")
	}
}

func TestTrustedMetricToolRejectsResultDigestTampering(t *testing.T) {
	bad := trustedMetricFixture(t)
	bad.Ask.ResultDigest = "sha256:" + strings.Repeat("0", 64)
	probe := &trustedMetricProbe{result: bad}
	result, retained, err := invokeTrustedMetricToolRetained(context.Background(), database.AccessContext{}, "ws_current", "qrun_current", probe, trustedMetricCatalog(),
		json.RawMessage(`{"metric_id":"work.assignments","date_a":"2026-09-10","date_b":"2026-09-09"}`), 8192)
	if err != nil || !result.IsError || retained != nil {
		t.Fatalf("tampered result accepted: %#v / %v", result, err)
	}
}
