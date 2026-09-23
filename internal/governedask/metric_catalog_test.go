package governedask

import (
	"context"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

func catalogProfile(t *testing.T, metricID, description string) metriccompare.Profile {
	t.Helper()
	profile, err := metriccompare.NewProfile(metriccompare.ProfileSpec{
		ExposedSchemaRevision: 1,
		MetricID:              metricID,
		Unit:                  "unknown",
		Description:           description,
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

func catalogTestService(t *testing.T) *Service {
	t.Helper()
	service := &Service{enabled: true}
	service.config.ConnectionID = "connection_alpha"
	service.config.DatabaseIdentity = "database_alpha"
	for _, item := range []struct{ workspace, metricID, description string }{
		{"ws_alpha", "zeta.metric", "Later observation"},
		{"ws_alpha", "alpha.metric", "Earlier observation"},
		{"ws_beta", "private.metric", "Other workspace"},
	} {
		if err := service.EnableMetricComparison(item.workspace, catalogProfile(t, item.metricID, item.description)); err != nil {
			t.Fatal(err)
		}
	}
	return service
}

func TestComparisonCatalogIsScopedSortedAndSafe(t *testing.T) {
	service := catalogTestService(t)
	access := governedAskAccess(database.ActorKindHuman)
	var checks []string
	got, err := service.comparisonCatalogWith(context.Background(), access, "ws_alpha",
		func(_ context.Context, _ database.AccessContext, workspaceID string, operation policy.Operation) error {
			if workspaceID != "ws_alpha" || operation != policy.OperationWorkspaceAsk {
				t.Fatalf("wrong authorization scope: %s %s", workspaceID, operation)
			}
			checks = append(checks, "authorize")
			return nil
		},
		func(_ context.Context, _ database.AccessContext, workspaceID string) (bool, error) {
			if workspaceID != "ws_alpha" {
				t.Fatalf("wrong live-query scope: %s", workspaceID)
			}
			checks = append(checks, "live")
			return true, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	want := []ComparisonSummary{
		{MetricID: "alpha.metric", Unit: "unknown", Description: "Earlier observation"},
		{MetricID: "zeta.metric", Unit: "unknown", Description: "Later observation"},
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(checks, []string{"authorize", "live"}) {
		t.Fatalf("catalog=%+v, checks=%v", got, checks)
	}
	other, err := service.comparisonCatalogWith(context.Background(), access, "ws_beta",
		func(context.Context, database.AccessContext, string, policy.Operation) error { return nil },
		func(context.Context, database.AccessContext, string) (bool, error) { return true, nil })
	if err != nil || len(other) != 1 || other[0].MetricID != "private.metric" {
		t.Fatalf("other workspace catalog=%+v err=%v", other, err)
	}
}

func TestComparisonCatalogDenialAndDisabledModeRevealNoSummaries(t *testing.T) {
	service := catalogTestService(t)
	access := governedAskAccess(database.ActorKindHuman)
	for _, testCase := range []struct {
		name      string
		authorize func(context.Context, database.AccessContext, string, policy.Operation) error
		live      func(context.Context, database.AccessContext, string) (bool, error)
		wantCode  ErrorCode
	}{
		{"denied", func(context.Context, database.AccessContext, string, policy.Operation) error {
			return &Error{code: CodeDenied}
		},
			func(context.Context, database.AccessContext, string) (bool, error) {
				t.Fatal("opt-in checked after denial")
				return false, nil
			}, CodeDenied},
		{"disabled", func(context.Context, database.AccessContext, string, policy.Operation) error { return nil },
			func(context.Context, database.AccessContext, string) (bool, error) { return false, nil }, CodeLiveQueriesOff},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := service.comparisonCatalogWith(context.Background(), access, "ws_alpha", testCase.authorize, testCase.live)
			if CodeOf(err) != testCase.wantCode || got != nil {
				t.Fatalf("denied catalog disclosed summaries: %+v err=%v", got, err)
			}
		})
	}
}
