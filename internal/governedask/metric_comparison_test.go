package governedask

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

func comparisonTestProfile(t *testing.T, unit string) metriccompare.Profile {
	t.Helper()
	profile, err := metriccompare.NewProfile(metriccompare.ProfileSpec{
		ExposedSchemaRevision: 1,
		MetricID:              "observed.volume",
		Unit:                  unit,
		Schema:                "public",
		View:                  "observations",
		SubjectColumn:         "subject_id",
		SnapshotColumn:        "observed_at",
		MeasureColumn:         "amount",
		Timezone:              "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestComparisonProfileRequiresMountAndStaysWorkspaceScoped(t *testing.T) {
	profile := comparisonTestProfile(t, "unknown")
	service := &Service{}
	if err := service.EnableMetricComparison("ws_alpha", profile); CodeOf(err) != CodeRequestInvalid {
		t.Fatalf("registration without mount: %v", err)
	}
	service.enabled = true // A mounted capability; no query is executed here.
	service.config.ConnectionID = "connection_alpha"
	service.config.DatabaseIdentity = "database_alpha"
	if err := service.EnableMetricComparison("ws_alpha", profile); err != nil {
		t.Fatal(err)
	}
	if err := service.EnableMetricComparison("ws_alpha", profile); err != nil {
		t.Fatalf("idempotent registration: %v", err)
	}
	if got, ok := service.comparisonProfile("ws_alpha", "observed.volume"); !ok || got.Hash() != profile.Hash() {
		t.Fatal("registered profile missing or altered")
	}
	if _, ok := service.comparisonProfile("ws_beta", "observed.volume"); ok {
		t.Fatal("profile leaked into another workspace")
	}
	if _, ok := service.comparisonProfile("ws_alpha", "other.metric"); ok {
		t.Fatal("unregistered metric resolved")
	}
	service.config.DatabaseIdentity = "database_beta"
	if _, ok := service.comparisonProfile("ws_alpha", "observed.volume"); ok {
		t.Fatal("profile remained usable after the mounted database changed")
	}
}

func TestComparisonProfileCannotBeSilentlyReplaced(t *testing.T) {
	service := &Service{enabled: true}
	service.config.ConnectionID = "connection_alpha"
	service.config.DatabaseIdentity = "database_alpha"
	approved := comparisonTestProfile(t, "unknown")
	changed := comparisonTestProfile(t, "items")
	if err := service.EnableMetricComparison("ws_alpha", approved); err != nil {
		t.Fatal(err)
	}
	if err := service.EnableMetricComparison("ws_alpha", changed); CodeOf(err) != CodeRequestInvalid {
		t.Fatalf("replacement result: %v", err)
	}
	got, ok := service.comparisonProfile("ws_alpha", approved.MetricID())
	if !ok || got.Hash() != approved.Hash() {
		t.Fatal("rejected replacement changed the approved profile")
	}
}

func TestCompareWorkspaceFailsClosedBeforeAuthorizationWithoutMount(t *testing.T) {
	var service *Service
	got, err := service.CompareWorkspace(context.Background(), database.AccessContext{}, "ws_alpha", "observed.volume", "2026-09-10", "2026-09-09")
	if CodeOf(err) != CodeUnavailable || !reflect.DeepEqual(got, MetricComparisonResult{}) {
		t.Fatalf("unmounted comparison returned data or wrong error: %v", err)
	}
}

func TestComparisonDisclosureRefusesUnauditedOrIncompleteResults(t *testing.T) {
	checks := 0
	service := &Service{disclosureCheck: func(context.Context, database.AccessContext, string) error {
		checks++
		return nil
	}}
	profile := comparisonTestProfile(t, "unknown")
	partial := governedquery.QueryResult{
		Columns: []string{"local_date", "snapshot_at", "contributing_rows", "distinct_subjects", "nonnull_count", "value"},
		Rows: [][]*string{{comparisonCell("2026-09-10"), comparisonCell("2026-09-10T00:00:00Z"),
			comparisonCell("1"), comparisonCell("1"), comparisonCell("1"), comparisonCell("4")}},
		RowCount: 1,
	}
	journalFailure := errors.New("journal unavailable")
	for _, testCase := range []struct {
		name     string
		auditErr error
		wantCode ErrorCode
	}{
		{"audit failure", journalFailure, CodeUnavailable},
		{"incomplete comparison", nil, CodeExecutionFailed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := service.discloseComparison(context.Background(), governedAskAccess(database.ActorKindHuman),
				"ws_alpha", 1, "SELECT 1", governedquery.Attempt{}, partial, testCase.auditErr,
				profile, "2026-09-10", "2026-09-09")
			if CodeOf(err) != testCase.wantCode || !reflect.DeepEqual(got, MetricComparisonResult{}) || checks != 0 {
				t.Fatalf("data escaped the refusal gate: code=%s checks=%d", CodeOf(err), checks)
			}
		})
	}
}

func TestComparisonDisclosureReauthorizesBeforeRecording(t *testing.T) {
	checks := 0
	service := &Service{disclosureCheck: func(context.Context, database.AccessContext, string) error {
		checks++
		return &Error{code: CodeDenied}
	}}
	profile := comparisonTestProfile(t, "unknown")
	complete := governedquery.QueryResult{
		Columns: []string{"local_date", "snapshot_at", "contributing_rows", "distinct_subjects", "nonnull_count", "value"},
		Rows: [][]*string{
			{comparisonCell("2026-09-10"), comparisonCell("2026-09-10T00:00:00Z"), comparisonCell("1"), comparisonCell("1"), comparisonCell("1"), comparisonCell("8")},
			{comparisonCell("2026-09-09"), comparisonCell("2026-09-09T00:00:00Z"), comparisonCell("1"), comparisonCell("1"), comparisonCell("1"), comparisonCell("10")},
		},
		RowCount: 2,
	}
	got, err := service.discloseComparison(context.Background(), governedAskAccess(database.ActorKindHuman),
		"ws_alpha", 1, "SELECT 1", governedquery.Attempt{}, complete, nil,
		profile, "2026-09-10", "2026-09-09")
	if CodeOf(err) != CodeDenied || !reflect.DeepEqual(got, MetricComparisonResult{}) || checks != 1 {
		t.Fatalf("disclosure bypassed authorization: code=%s checks=%d", CodeOf(err), checks)
	}
}

func comparisonCell(value string) *string { return &value }
