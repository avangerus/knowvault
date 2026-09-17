package analytic

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
)

type fixedResultAdapter struct {
	result Result
	err    error
}

func (adapter fixedResultAdapter) Aggregate(context.Context, Request) (Result, error) {
	return adapter.result, adapter.err
}

type blockingAdapter struct{}

func (blockingAdapter) Aggregate(context.Context, Request) (Result, error) {
	time.Sleep(250 * time.Millisecond)
	return Result{Function: "SUM", Buckets: []Bucket{{Key: "__all__", Value: "1", Count: 1}}}, nil
}

func testCell(id, row, column, value string, numeric bool) Cell {
	return Cell{Evidence: Evidence{
		ID: id, SourceObjectID: "object_" + row, SourceVersionID: "version_" + row,
		ExtractionID: "extraction_" + row,
		ContentHash:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TextHash:     "hmac-sha256:k1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AnchorHash:   "hmac-sha256:k1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}, RowKey: row, Column: column, Value: value, Numeric: numeric}
}

func TestEvidenceAdapterAggregatesGroupsAndRanksGenericRows(t *testing.T) {
	adapter := NewEvidenceAdapter()
	result, err := adapter.Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", GroupBy: []string{"team"}, Metric: "kilograms", Order: "DESC", Limit: 1},
		Cells: []Cell{
			testCell("group-a-1", "row-a-1", "team", "Alpha", false),
			testCell("metric-a-1", "row-a-1", "kilograms", "12", true),
			testCell("group-a-2", "row-a-2", "team", "Alpha", false),
			testCell("metric-a-2", "row-a-2", "kilograms", "8", true),
			testCell("group-b-1", "row-b-1", "team", "Beta", false),
			testCell("metric-b-1", "row-b-1", "kilograms", "15", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Buckets) != 1 || result.Buckets[0].Key != "Alpha" || result.Buckets[0].Value != "20" || len(result.Buckets[0].Evidence) != 2 {
		t.Fatalf("result=%+v", result)
	}
}

func TestEvidenceAdapterAggregatesTwoDimensionsAndRanks(t *testing.T) {
	result, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", GroupBy: []string{"region", "channel"}, Metric: "amount", Order: "DESC", Limit: 2},
		Cells: []Cell{
			testCell("region-n-1", "row-1", "region", "North", false),
			testCell("channel-web-1", "row-1", "channel", "Web", false),
			testCell("amount-1", "row-1", "amount", "7", true),
			testCell("region-n-2", "row-2", "region", "North", false),
			testCell("channel-web-2", "row-2", "channel", "Web", false),
			testCell("amount-2", "row-2", "amount", "5", true),
			testCell("region-s-1", "row-3", "region", "South", false),
			testCell("channel-store-1", "row-3", "channel", "Store", false),
			testCell("amount-3", "row-3", "amount", "10", true),
			testCell("region-n-3", "row-4", "region", "North", false),
			testCell("channel-store-1b", "row-4", "channel", "Store", false),
			testCell("amount-4", "row-4", "amount", "2", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.GroupBy) != 2 || result.GroupBy[0] != "region" || result.GroupBy[1] != "channel" || len(result.Buckets) != 2 {
		t.Fatalf("multi-group result shape=%+v", result)
	}
	if result.Buckets[0].Key != "North / Web" || result.Buckets[0].Value != "12" || len(result.Buckets[0].GroupValues) != 2 || len(result.Buckets[0].GroupEvidence) != 2 {
		t.Fatalf("top multi-group bucket=%+v", result.Buckets[0])
	}
	if result.Buckets[1].Key != "South / Store" || result.Buckets[1].Value != "10" || len(result.Buckets[1].GroupEvidence) != 2 {
		t.Fatalf("second multi-group bucket=%+v", result.Buckets[1])
	}
}

func TestEvidenceAdapterAggregatesJSONPathDimensions(t *testing.T) {
	result, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", GroupBy: []string{"payload[/Region]", "payload[/Channel]"}, Metric: "payload[/Amount]", Order: "DESC", Limit: 2},
		Cells: []Cell{
			testCell("json-region-n", "json-row-1", "payload[/Region]", "North", false),
			testCell("json-channel-w", "json-row-1", "payload[/Channel]", "Web", false),
			testCell("json-amount-1", "json-row-1", "payload[/Amount]", "7", true),
			testCell("json-region-n2", "json-row-2", "payload[/Region]", "North", false),
			testCell("json-channel-w2", "json-row-2", "payload[/Channel]", "Web", false),
			testCell("json-amount-2", "json-row-2", "payload[/Amount]", "5", true),
			testCell("json-region-s", "json-row-3", "payload[/Region]", "South", false),
			testCell("json-channel-s", "json-row-3", "payload[/Channel]", "Store", false),
			testCell("json-amount-3", "json-row-3", "payload[/Amount]", "10", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Metric != "payload[/Amount]" || len(result.GroupBy) != 2 || result.Buckets[0].Key != "North / Web" || result.Buckets[0].Value != "12" || len(result.Buckets[0].GroupEvidence) != 2 {
		t.Fatalf("JSON-path aggregate result=%+v", result)
	}
}

func TestEvidenceAdapterRejectsUnresolvableMultiGroup(t *testing.T) {
	_, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", GroupBy: []string{"region", "channel"}, Metric: "amount"},
		Cells: []Cell{
			testCell("region-1", "row-1", "region", "North", false),
			testCell("amount-1", "row-1", "amount", "7", true),
		},
	})
	if CodeOf(err) != CodeIncomplete {
		t.Fatalf("unresolvable multi-group code=%s err=%v", CodeOf(err), err)
	}
}

func TestEvidenceAdapterAppliesGenericEqualityFilter(t *testing.T) {
	result, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Filters: []planner.Filter{{Name: "equals:status", Value: "active"}},
		Spec:    planner.AggregateSpec{Function: "SUM", Metric: "amount"},
		Cells: []Cell{
			testCell("status-a", "row-a", "status", "active", false),
			testCell("amount-a", "row-a", "amount", "4", true),
			testCell("status-b", "row-b", "status", "inactive", false),
			testCell("amount-b", "row-b", "amount", "100", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Buckets) != 1 || result.Buckets[0].Value != "4" || len(result.Buckets[0].Evidence) != 1 || result.Buckets[0].Evidence[0].ID != "amount-a" || len(result.Buckets[0].FilterEvidence) != 1 || result.Buckets[0].FilterEvidence[0].ID != "status-a" {
		t.Fatalf("filtered result=%+v", result)
	}
}

func TestEvidenceAdapterFailsClosedForAmbiguousMetricAndConflictingGroup(t *testing.T) {
	adapter := NewEvidenceAdapter()
	base := Request{WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Spec: planner.AggregateSpec{Function: "SUM"}}
	base.Cells = []Cell{testCell("metric-a", "row-a", "tonnes", "1", true), testCell("metric-b", "row-a", "distance", "2", true)}
	_, err := adapter.Aggregate(context.Background(), base)
	if CodeOf(err) != CodeIncomplete {
		t.Fatal("ambiguous metric was accepted")
	}
	conflict := base
	conflict.Spec = planner.AggregateSpec{Function: "SUM", GroupBy: []string{"team"}, Metric: "tonnes"}
	conflict.Cells = []Cell{testCell("group-a", "row-a", "team", "Alpha", false), testCell("group-b", "row-a", "team", "Beta", false), testCell("metric", "row-a", "tonnes", "1", true)}
	_, err = adapter.Aggregate(context.Background(), conflict)
	if CodeOf(err) != CodeConflict {
		t.Fatal("conflicting group values were accepted")
	}
}

func TestEvidenceAdapterCountsRowsWithoutNumericMetric(t *testing.T) {
	result, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "COUNT", GroupBy: []string{"crew"}, Order: "DESC"},
		Cells: []Cell{
			testCell("crew-a", "row-a", "crew", "Alpha", false),
			testCell("crew-b", "row-b", "crew", "Alpha", false),
			testCell("crew-c", "row-c", "crew", "Beta", false),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Buckets) != 2 || result.Buckets[0].Key != "Alpha" || result.Buckets[0].Value != "2" || len(result.Buckets[0].Evidence) != 2 {
		t.Fatalf("result=%+v", result)
	}
}

func TestEvidenceAdapterAverageKeepsFractionalPrecision(t *testing.T) {
	result, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "AVG", Metric: "value"},
		Cells: []Cell{
			testCell("value-a", "row-a", "value", "1", true),
			testCell("value-b", "row-b", "value", "2", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Buckets) != 1 || result.Buckets[0].Value != "1.5" {
		t.Fatalf("result=%+v", result)
	}
}

func TestEvidenceAdapterRejectsIncompleteEvidenceLineage(t *testing.T) {
	cell := testCell("metric", "row", "value", "1", true)
	cell.Evidence.SourceVersionID = ""
	_, err := NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", Metric: "value"}, Cells: []Cell{cell},
	})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("incomplete evidence lineage code=%s err=%v", CodeOf(err), err)
	}

	cell = testCell("metric", "row", "value", "1", true)
	cell.Evidence.TextHash = "sha256:not-a-digest"
	_, err = NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", Metric: "value"}, Cells: []Cell{cell},
	})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("malformed evidence digest code=%s err=%v", CodeOf(err), err)
	}

	cell = testCell("metric", "row", "value", "1", true)
	cell.Evidence.TextHash = "sha256:" + strings.Repeat("a", 64)
	_, err = NewEvidenceAdapter().Aggregate(context.Background(), Request{
		WorkspaceID: "ws_demo", PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Spec: planner.AggregateSpec{Function: "SUM", Metric: "value"}, Cells: []Cell{cell},
	})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("unkeyed evidence text hash was accepted: code=%s err=%v", CodeOf(err), err)
	}
}

func TestRegistryBindsExactPlannerOutputAndSealsEvidenceReceipt(t *testing.T) {
	plan, err := planner.New().Plan("\u041a\u0442\u043e \u0438\u0437 \u044d\u043a\u0438\u043f\u0430\u0436\u0435\u0439 \u0432\u044b\u0432\u0435\u0437 \u0431\u043e\u043b\u044c\u0448\u0435 \u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432?")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding(EvidenceReducerTool, toolBindingVersion, NewEvidenceAdapter(), DefaultLimits())
	if err != nil {
		t.Fatalf("binding: %v cause=%v", err, errors.Unwrap(err))
	}
	registry, err := NewRegistry(binding)
	if err != nil {
		t.Fatal(err)
	}
	result, receipt, err := registry.Invoke(context.Background(), Invocation{
		WorkspaceID: "ws_demo", ToolID: EvidenceReducerTool, Plan: plan,
		Cells: []Cell{
			testCell("metric-a", "row-a", "kilograms", "12", true),
			testCell("group-a", "row-a", "crew", "Alpha", false),
			testCell("metric-b", "row-b", "kilograms", "8", true),
			testCell("group-b", "row-b", "crew", "Beta", false),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Buckets) != 1 || receipt.Status != "SUCCEEDED" || receipt.ResultHash == "" || receipt.ReceiptHash == "" {
		t.Fatalf("result=%+v receipt=%+v", result, receipt)
	}
	if receipt.ToolID != EvidenceReducerTool || receipt.BindingHash == "" || receipt.PlanHash != plan.PlanHash || receipt.Rows != 2 || receipt.Cells != 4 {
		t.Fatalf("receipt=%+v", receipt)
	}
	if got := strings.Join(receipt.EvidenceIDs, ","); got != "group-a,metric-a" {
		t.Fatalf("evidence ids=%q", got)
	}
}

func TestRegistryRejectsUnknownToolPlanMutationAndBudgetOverflow(t *testing.T) {
	plan, err := planner.New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043f\u043e \u043e\u0442\u0434\u0435\u043b\u0430\u043c \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(mustBinding(EvidenceReducerTool, toolBindingVersion, NewEvidenceAdapter(), DefaultLimits()))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: "analytic.not-installed-v1", Plan: plan, Cells: []Cell{testCell("metric", "row", "value", "1", true)}})
	if CodeOf(err) != CodeToolNotFound {
		t.Fatalf("unknown tool code=%s err=%v", CodeOf(err), err)
	}
	plan.Aggregate.Function = "DELETE"
	_, _, err = registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: EvidenceReducerTool, Plan: plan, Cells: []Cell{testCell("metric", "row", "value", "1", true)}})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("mutated plan code=%s err=%v", CodeOf(err), err)
	}
	plan, err = planner.New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043f\u043e \u043e\u0442\u0434\u0435\u043b\u0430\u043c \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	tooMany := make([]Cell, 0, DefaultLimits().MaxCells+1)
	for index := 0; index <= DefaultLimits().MaxCells; index++ {
		tooMany = append(tooMany, testCell("metric-"+strings.Repeat("x", 1)+string(rune('a'+index%26))+"-"+string(rune('0'+index%10)), "row-"+string(rune('a'+index%26)), "value", "1", true))
	}
	_, _, err = registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: EvidenceReducerTool, Plan: plan, Cells: tooMany})
	if CodeOf(err) != CodeToolLimit {
		t.Fatalf("cell budget code=%s err=%v", CodeOf(err), err)
	}
}

func TestRegistryTimesOutAdapterThatIgnoresCancellation(t *testing.T) {
	limits := DefaultLimits()
	limits.Timeout = 5 * time.Millisecond
	binding, err := NewBinding("analytic.blocking-v1", "1", blockingAdapter{}, limits)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(binding)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: binding.ID, Plan: plan, Cells: []Cell{testCell("metric", "row", "value", "1", true)}})
	if CodeOf(err) != CodeToolTimeout || receipt.Status != "FAILED" || receipt.FailureCode != string(CodeToolTimeout) || receipt.ReceiptHash == "" {
		t.Fatalf("code=%s receipt=%+v err=%v", CodeOf(err), receipt, err)
	}
}

func TestRegistryRejectsAdapterEvidenceNotPresentInInvocation(t *testing.T) {
	plan, err := planner.New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	cell := testCell("metric", "row", "value", "1", true)
	forged := Result{Function: "SUM", Metric: "value", Buckets: []Bucket{{Key: "__all__", Value: "1", Count: 1, Evidence: []EvidenceRef{{ID: "forged", SourceObjectID: cell.Evidence.SourceObjectID, SourceVersionID: cell.Evidence.SourceVersionID, ExtractionID: cell.Evidence.ExtractionID, TextHash: cell.Evidence.TextHash, AnchorHash: cell.Evidence.AnchorHash, ContentHash: cell.Evidence.ContentHash}}}}}
	binding, err := NewBinding("analytic.forged-v1", "1", fixedResultAdapter{result: forged}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(binding)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: binding.ID, Plan: plan, Cells: []Cell{cell}})
	if CodeOf(err) != CodeToolResultError {
		t.Fatalf("forged evidence code=%s err=%v", CodeOf(err), err)
	}
}

func TestRegistryRejectsUnboundAggregateOutput(t *testing.T) {
	plan, err := planner.New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	cell := testCell("metric", "row", "value", "1", true)
	ref := evidenceRef(cell.Evidence)
	cases := []struct {
		name   string
		result Result
	}{
		{name: "missing value evidence", result: Result{Function: "SUM", Metric: "value", Buckets: []Bucket{{Key: "__all__", Value: "1", Count: 1}}}},
		{name: "unexpected group witness", result: Result{Function: "SUM", Metric: "value", Buckets: []Bucket{{Key: "__all__", Value: "1", Count: 1, Evidence: []EvidenceRef{ref}, GroupEvidence: []EvidenceRef{ref}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binding, bindErr := NewBinding("analytic.unbound-"+strings.ReplaceAll(tc.name, " ", "-")+"-v1", "1", fixedResultAdapter{result: tc.result}, DefaultLimits())
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			registry, registryErr := NewRegistry(binding)
			if registryErr != nil {
				t.Fatal(registryErr)
			}
			_, _, invokeErr := registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: binding.ID, Plan: plan, Cells: []Cell{cell}})
			if CodeOf(invokeErr) != CodeToolResultError {
				t.Fatalf("unbound result code=%s err=%v", CodeOf(invokeErr), invokeErr)
			}
		})
	}
}

func TestRegistryRejectsForgedMultiGroupWithoutDimensionWitnesses(t *testing.T) {
	plan, err := planner.New().Plan("aggregate entity orders metric_field=amount group_by=region,channel")
	if err != nil {
		t.Fatal(err)
	}
	metric := testCell("metric-row", "row", "amount", "7", true)
	ref := evidenceRef(metric.Evidence)
	forged := Result{
		Function: "SUM", Metric: "amount", GroupBy: []string{"region", "channel"},
		Buckets: []Bucket{{Key: "North / Web", Value: "7", Count: 1, Evidence: []EvidenceRef{ref}, GroupValues: []string{"North", "Web"}}},
	}
	binding, err := NewBinding("analytic.forged-multigroup-v1", "1", fixedResultAdapter{result: forged}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(binding)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: binding.ID, Plan: plan, Cells: []Cell{metric,
		testCell("region-row", "row", "region", "North", false), testCell("channel-row", "row", "channel", "Web", false)}})
	if CodeOf(err) != CodeToolResultError {
		t.Fatalf("forged multi-group result code=%s err=%v", CodeOf(err), err)
	}
}

func TestRegistryPropagatesAdapterFailureWithReceipt(t *testing.T) {
	plan, err := planner.New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := NewBinding("analytic.failure-v1", "1", fixedResultAdapter{err: &Error{code: CodeIncomplete}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(binding)
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := registry.Invoke(context.Background(), Invocation{WorkspaceID: "ws_demo", ToolID: binding.ID, Plan: plan, Cells: []Cell{testCell("metric", "row", "value", "1", true)}})
	if CodeOf(err) != CodeIncomplete || receipt.Status != "FAILED" || receipt.FailureCode != string(CodeIncomplete) || receipt.ReceiptHash == "" {
		t.Fatalf("code=%s receipt=%+v err=%v", CodeOf(err), receipt, err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("unexpected context cancellation")
	}
}
