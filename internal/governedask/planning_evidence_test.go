package governedask

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	"knowvault.local/verified-workspace/internal/tzrules"
)

func reportingEvidenceFixture(t *testing.T) (*Service, governedquery.ExposedSchema) {
	t.Helper()
	service := &Service{enabled: true}
	service.config.ConnectionID, service.config.DatabaseIdentity = "connection_alpha", "database_alpha"
	profile, err := metriccompare.NewProfile(metriccompare.ProfileSpec{
		ExposedSchemaRevision: 7, MetricID: "work.observed", Unit: "unknown",
		Schema: "reporting", View: "observations", SnapshotColumn: "observed_at",
		SubjectColumn: "subject_id", MeasureColumn: "amount", Timezone: "Europe/Moscow",
		Filters: []metriccompare.FixedFilter{{Column: "metric_code", Value: "work.observed"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnableMetricComparison("ws_alpha", profile); err != nil {
		t.Fatal(err)
	}
	schema := governedquery.ExposedSchema{Revision: 7, Objects: []governedquery.ExposedObject{{
		SchemaName: "reporting", TableName: "observations", Description: "Observed metrics",
		Columns: []governedquery.ExposedColumn{
			{Name: "observed_at", DataType: "timestamp with time zone", Description: "Snapshot"},
			{Name: "subject_id", DataType: "text", Description: "Subject"},
			{Name: "amount", DataType: "numeric", Description: "Measure"},
			{Name: "metric_code", DataType: "text", Description: "Metric code"},
		},
	}}}
	return service, schema
}

func TestPlanningEvidenceCarriesScopedMoscowCalendar(t *testing.T) {
	service, schema := reportingEvidenceFixture(t)
	evidence, err := service.planningEvidence("ws_alpha", schema)
	if err != nil || len(evidence) != 2 {
		t.Fatalf("planning evidence = %+v, %v", evidence, err)
	}
	var metadata struct {
		Relation string            `json:"relation"`
		Metric   string            `json:"metric_id"`
		Zone     string            `json:"reporting_timezone"`
		Filters  map[string]string `json:"required_equal_filters"`
		Coverage string            `json:"population_coverage"`
	}
	_, raw, found := strings.Cut(evidence[1].Text, "\n")
	if !found || json.Unmarshal([]byte(raw), &metadata) != nil || metadata.Relation != "reporting.observations" ||
		metadata.Metric != "work.observed" || metadata.Filters["metric_code"] != "work.observed" || metadata.Coverage != "UNKNOWN" {
		t.Fatalf("lost exact metric scope: %s", raw)
	}
	zone, err := tzrules.Load(metadata.Zone)
	if err != nil {
		t.Fatal(err)
	}
	start, err := time.ParseInLocation("2006-01-02", "2026-09-10", zone)
	if err != nil {
		t.Fatal(err)
	}
	if start.UTC().Format(time.RFC3339) != "2026-09-09T21:00:00Z" || start.AddDate(0, 0, 1).UTC().Format(time.RFC3339) != "2026-09-10T21:00:00Z" {
		t.Fatal("projected reporting day incorrectly uses UTC midnights")
	}
	if strings.Contains(evidence[0].Text, "Europe/Moscow") {
		t.Fatal("metric calendar became an unscoped table default")
	}
}

func TestPlanningEvidenceDoesNotBorrowForeignOrStaleCalendars(t *testing.T) {
	for _, example := range []string{"workspace", "connection", "database", "revision", "relation", "column"} {
		t.Run(example, func(t *testing.T) {
			service, schema := reportingEvidenceFixture(t)
			workspace := "ws_alpha"
			switch example {
			case "workspace":
				workspace = "ws_beta"
			case "connection":
				service.config.ConnectionID = "connection_beta"
			case "database":
				service.config.DatabaseIdentity = "database_beta"
			case "revision":
				schema.Revision++
			case "relation":
				schema.Objects[0].TableName = "other_observations"
			case "column":
				schema.Objects[0].Columns[0].Name = "other_time"
			}
			evidence, err := service.planningEvidence(workspace, schema)
			if err != nil || len(evidence) != 1 || strings.Contains(evidence[0].Text, "Europe/Moscow") {
				t.Fatalf("unconfirmed calendar escaped: %+v, %v", evidence, err)
			}
		})
	}
}

func TestPlanningInstructionsRefuseInventedCalendarAndZeroCompleteness(t *testing.T) {
	for _, instruction := range []string{"reporting timezone is absent", "return UNKNOWN", "do not COALESCE", "Population coverage is UNKNOWN"} {
		if !strings.Contains(askSystemInstructions, instruction) {
			t.Fatalf("missing planning constraint: %s", instruction)
		}
	}
}
