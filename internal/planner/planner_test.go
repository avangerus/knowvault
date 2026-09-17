package planner

import (
	"strings"
	"sync"
	"testing"
)

func TestPlannerBuildsGenericAggregateGroupByAndRank(t *testing.T) {
	p := New()
	cases := []struct {
		name, question, group, metric string
	}{
		{"crew", "\u041a\u0442\u043e \u0438\u0437 \u044d\u043a\u0438\u043f\u0430\u0436\u0435\u0439 \u0432 \u044d\u0442\u043e\u043c \u043c\u0435\u0441\u044f\u0446\u0435 \u0432\u044b\u0432\u0435\u0437 \u0431\u043e\u043b\u044c\u0448\u0435 \u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432?", "\u044d\u043a\u0438\u043f\u0430\u0436\u0435\u0439", "\u044d\u043a\u0438\u043f\u0430\u0436\u0435\u0439"},
		{"departments", "\u041a\u0430\u043a\u0438\u0435 \u043e\u0442\u0434\u0435\u043b\u044b \u0432 \u044d\u0442\u043e\u043c \u043c\u0435\u0441\u044f\u0446\u0435 \u0432\u044b\u0432\u0435\u0437\u043b\u0438 \u0431\u043e\u043b\u044c\u0448\u0435 \u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432?", "\u043e\u0442\u0434\u0435\u043b\u044b", "\u043e\u0442\u0434\u0435\u043b\u044b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := p.Plan(tc.question)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Status != Ready || plan.Operation != Aggregate || plan.Aggregate == nil {
				t.Fatalf("unexpected plan: %+v", plan)
			}
			if len(plan.Aggregate.GroupBy) != 1 || plan.Aggregate.GroupBy[0] != tc.group {
				t.Fatalf("group_by=%v, want %q", plan.Aggregate.GroupBy, tc.group)
			}
			if plan.Aggregate.Order != "DESC" || plan.Aggregate.Limit != 1 {
				t.Fatalf("rank=%+v", plan.Aggregate)
			}
			if plan.PlanHash == "" || len(plan.CanonicalBytes) == 0 {
				t.Fatal("plan has no canonical provenance")
			}
			if err := plan.Validate(); err != nil {
				t.Fatalf("plan validation: %v", err)
			}
		})
	}
}

func TestPlannerParsesBoundedGenericTopN(t *testing.T) {
	p := New()
	for _, test := range []struct {
		question string
		limit    int
	}{
		{question: "\u0422\u043e\u043f 3 \u043a\u043e\u043c\u0430\u043d\u0434 \u043f\u043e \u0441\u0443\u043c\u043c\u0435 \u0437\u0430\u044f\u0432\u043e\u043a", limit: 3},
		{question: "top 5 teams by total requests", limit: 5},
	} {
		plan, err := p.Plan(test.question)
		if err != nil {
			t.Fatalf("%q: %v", test.question, err)
		}
		if plan.Status != Ready || plan.Operation != Aggregate || plan.Aggregate == nil || plan.Aggregate.Order != "DESC" || plan.Aggregate.Limit != test.limit {
			t.Fatalf("%q produced %+v", test.question, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid plan: %v", test.question, err)
		}
	}
	tooWide, err := p.Plan("top 129 teams by total requests")
	if err != nil {
		t.Fatal(err)
	}
	if tooWide.Aggregate == nil || tooWide.Aggregate.Limit != 1 {
		t.Fatalf("unbounded top-N escaped bounded default: %+v", tooWide.Aggregate)
	}
}

func TestPlannerExtractsMetricWithoutReusingGroupOrFillerTerms(t *testing.T) {
	p := New()
	cases := []struct {
		question string
		group    string
		metric   string
	}{
		{question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0443 \u043d\u0430\u0441 \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e?", metric: "\u043e\u0442\u0445\u043e\u0434\u043e\u0432"},
		{question: "\u041a\u0442\u043e \u0438\u0437 \u044d\u043a\u0438\u043f\u0430\u0436\u0435\u0439 \u0432 \u044d\u0442\u043e\u043c \u043c\u0435\u0441\u044f\u0446\u0435 \u0432\u044b\u0432\u0435\u0437 \u0431\u043e\u043b\u044c\u0448\u0435 \u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432?", group: "\u044d\u043a\u0438\u043f\u0430\u0436\u0435\u0439", metric: "\u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432"},
		{question: "\u0422\u043e\u043f 3 \u043a\u043e\u043c\u0430\u043d\u0434 \u043f\u043e \u0441\u0443\u043c\u043c\u0435 \u0437\u0430\u044f\u0432\u043e\u043a", group: "\u043a\u043e\u043c\u0430\u043d\u0434", metric: "\u0437\u0430\u044f\u0432\u043e\u043a"},
		{question: "top 5 teams by total requests", group: "teams", metric: "requests"},
		// No metric is named here. The adapter may resolve a sole numeric
		// column, but the planner must not pretend that the group is a metric.
		{question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043f\u043e \u043e\u0442\u0434\u0435\u043b\u0430\u043c \u0432\u0441\u0435\u0433\u043e?", group: "\u043e\u0442\u0434\u0435\u043b\u0430\u043c", metric: ""},
	}
	for _, tc := range cases {
		plan, err := p.Plan(tc.question)
		if err != nil {
			t.Fatalf("%q: %v", tc.question, err)
		}
		if plan.Status != Ready || plan.Operation != Aggregate || plan.Aggregate == nil {
			t.Fatalf("%q produced %+v", tc.question, plan)
		}
		if len(plan.Aggregate.GroupBy) > 0 && plan.Aggregate.GroupBy[0] != tc.group || len(plan.Aggregate.GroupBy) == 0 && tc.group != "" {
			t.Fatalf("%q group_by=%v, want %q", tc.question, plan.Aggregate.GroupBy, tc.group)
		}
		if plan.Aggregate.Metric != tc.metric {
			t.Fatalf("%q metric=%q, want %q", tc.question, plan.Aggregate.Metric, tc.metric)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid plan: %v", tc.question, err)
		}
	}
}

func TestPlannerParsesExplicitGenericAggregateClauses(t *testing.T) {
	plan, err := New().Plan("aggregate entity invoices metric_field=amount group_by=region top=3 order=asc \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 30 \u0434\u043d\u0435\u0439")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != Ready || plan.Operation != Aggregate || plan.Aggregate == nil {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Aggregate.Metric != "amount" || len(plan.Aggregate.GroupBy) != 1 || plan.Aggregate.GroupBy[0] != "region" {
		t.Fatalf("aggregate fields=%+v", plan.Aggregate)
	}
	if plan.Aggregate.Order != "ASC" || plan.Aggregate.Limit != 3 {
		t.Fatalf("aggregate rank=%+v", plan.Aggregate)
	}
	if len(plan.Filters) != 1 || plan.Filters[0] != (Filter{Name: "time_window", Value: "last_days:30"}) {
		t.Fatalf("filters=%+v", plan.Filters)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan validation: %v", err)
	}
}

func TestPlannerParsesExplicitMultiDimensionalAggregateClauses(t *testing.T) {
	plan, err := New().Plan("aggregate entity orders metric_field=amount group_by=region,channel top=3 order=desc \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 30 \u0434\u043d\u0435\u0439")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != Ready || plan.Operation != Aggregate || plan.Aggregate == nil {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Aggregate.Metric != "amount" || len(plan.Aggregate.GroupBy) != 2 || plan.Aggregate.GroupBy[0] != "region" || plan.Aggregate.GroupBy[1] != "channel" {
		t.Fatalf("aggregate fields=%+v", plan.Aggregate)
	}
	if plan.Aggregate.Order != "DESC" || plan.Aggregate.Limit != 3 {
		t.Fatalf("aggregate rank=%+v", plan.Aggregate)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan validation: %v", err)
	}

	natural, err := New().Plan("top 3 orders by region and channel total amount")
	if err != nil {
		t.Fatal(err)
	}
	if natural.Status != Ready || natural.Aggregate == nil || len(natural.Aggregate.GroupBy) != 2 || natural.Aggregate.GroupBy[0] != "region" || natural.Aggregate.GroupBy[1] != "channel" {
		t.Fatalf("natural multi-group plan=%+v", natural)
	}
}

func TestPlannerRejectsMalformedExplicitMultiGroup(t *testing.T) {
	for _, question := range []string{
		"aggregate entity orders metric_field=amount group_by=region,,channel",
		"aggregate entity orders metric_field=amount group_by=",
	} {
		plan, err := New().Plan(question)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || plan.Aggregate != nil {
			t.Fatalf("malformed group clause escaped fail-closed status: %+v", plan)
		}
		if len(plan.Reasons) != 1 || (plan.Reasons[0] != "invalid_aggregate_clause" && plan.Reasons[0] != "invalid_equality_filter") {
			t.Fatalf("malformed group reason=%v", plan.Reasons)
		}
	}
}

func TestPlannerParsesJSONPathAggregateFields(t *testing.T) {
	plan, err := New().Plan("aggregate entity records metric_field=payload[/metrics/amount] group_by=payload[/region],payload[/channel] top=2 order=desc")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != Ready || plan.Operation != Aggregate || plan.Aggregate == nil {
		t.Fatalf("unexpected JSON-path plan: %+v", plan)
	}
	if plan.Aggregate.Metric != "payload[/metrics/amount]" || len(plan.Aggregate.GroupBy) != 2 ||
		plan.Aggregate.GroupBy[0] != "payload[/region]" || plan.Aggregate.GroupBy[1] != "payload[/channel]" {
		t.Fatalf("JSON-path aggregate fields=%+v", plan.Aggregate)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("JSON-path plan validation: %v", err)
	}
}

func TestPlannerPreservesCaseSensitiveJSONPointerMembers(t *testing.T) {
	plan, err := New().Plan("aggregate entity records metric_field=payload[/Metrics/Amount] group_by=payload[/Region],payload[/Channel]")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != Ready || plan.Aggregate == nil || plan.Aggregate.Metric != "payload[/Metrics/Amount]" ||
		len(plan.Aggregate.GroupBy) != 2 || plan.Aggregate.GroupBy[0] != "payload[/Region]" || plan.Aggregate.GroupBy[1] != "payload[/Channel]" {
		t.Fatalf("case-sensitive JSON Pointer members were normalized: %+v", plan.Aggregate)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("case-sensitive JSON-path plan validation: %v", err)
	}
}

func TestPlannerRejectsMalformedJSONPathAggregateField(t *testing.T) {
	for _, question := range []string{
		"aggregate entity records metric_field=payload[metrics/amount] group_by=region,channel",
		"aggregate entity records metric_field=payload[/metrics/amount] group_by=payload[/region]payload[/channel]",
	} {
		plan, err := New().Plan(question)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || plan.Aggregate != nil {
			t.Fatalf("malformed JSON path escaped fail-closed status: %+v", plan)
		}
		if len(plan.Reasons) != 1 || plan.Reasons[0] != "invalid_aggregate_clause" {
			t.Fatalf("malformed JSON path reason=%v", plan.Reasons)
		}
	}
}

func TestPlannerNormalizesExplicitAndRelativeDateRanges(t *testing.T) {
	for _, tc := range []struct {
		question string
		name     string
		value    string
	}{
		{question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-08-01 \u043f\u043e 2026-08-15?", name: "time_range", value: "2026-08-01/2026-08-16"},
		{question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-8-2 \u043f\u043e 2026-8-15?", name: "time_range", value: "2026-08-02/2026-08-16"},
		{question: "How many requests for the last 7 days?", name: "time_window", value: "last_days:7"},
	} {
		plan, err := New().Plan(tc.question)
		if err != nil {
			t.Fatalf("%q: %v", tc.question, err)
		}
		if plan.Status != Ready || plan.Operation != Aggregate || len(plan.Filters) != 1 || plan.Filters[0].Name != tc.name || plan.Filters[0].Value != tc.value {
			t.Fatalf("%q filters=%+v plan=%+v", tc.question, plan.Filters, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid normalized plan: %v", tc.question, err)
		}
	}
}

func TestPlannerRejectsConflictingTemporalExpressions(t *testing.T) {
	for _, question := range []string{
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0437\u0430 \u044d\u0442\u043e\u0442 \u043c\u0435\u0441\u044f\u0446?",
		"How many requests today this week?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-08-01 \u043f\u043e 2026-08-02 \u0438 \u0441 2026-08-10 \u043f\u043e 2026-08-11?",
		"How many requests for the last 7 days and the last 30 days?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-08-01 \u043f\u043e 2026-08-02 \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 7 \u0434\u043d\u0435\u0439?",
	} {
		plan, err := New().Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || len(plan.Filters) != 0 || len(plan.Reasons) != 1 || plan.Reasons[0] != "invalid_time_period" {
			t.Fatalf("%q escaped conflicting-period boundary: %+v", question, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid unknown plan: %v", question, err)
		}
	}
}

func TestPlannerExtractsGenericEqualityFilters(t *testing.T) {
	plan, err := New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0433\u0434\u0435 status = active \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 30 \u0434\u043d\u0435\u0439?")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != Ready || plan.Operation != Aggregate || len(plan.Filters) != 2 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Filters[0] != (Filter{Name: "time_window", Value: "last_days:30"}) ||
		plan.Filters[1] != (Filter{Name: "equals:status", Value: "active"}) {
		t.Fatalf("filters=%+v", plan.Filters)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan validation: %v", err)
	}
}

func TestPlannerRejectsConflictingEqualityFilters(t *testing.T) {
	for _, question := range []string{
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0433\u0434\u0435 status = active \u0438 status = inactive?",
		"How many requests where status = ACTIVE and status = inactive?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0433\u0434\u0435 status = \"active\" \u0438 status = 'inactive'?",
	} {
		plan, err := New().Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || len(plan.Filters) != 0 || len(plan.Reasons) != 1 || plan.Reasons[0] != "conflicting_equality_filter" {
			t.Fatalf("%q escaped conflicting equality boundary: %+v", question, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid unknown plan: %v", question, err)
		}
	}
}

func TestPlannerKeepsIdenticalEqualityRepeatsDeterministic(t *testing.T) {
	plan, err := New().Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0433\u0434\u0435 status = active \u0438 status = ACTIVE?")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != Ready || plan.Operation != Aggregate || len(plan.Filters) != 2 || plan.Filters[0] != (Filter{Name: "equals:status", Value: "active"}) || plan.Filters[1] != (Filter{Name: "equals:status", Value: "active"}) {
		t.Fatalf("identical equality repeats changed plan semantics: %+v", plan)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan validation: %v", err)
	}
}

func TestPlannerRejectsMalformedEqualityFilters(t *testing.T) {
	for _, question := range []string{
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e amount \u0433\u0434\u0435 status =",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e amount \u0433\u0434\u0435 status = \"\"",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e amount \u0433\u0434\u0435 status = ?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e amount \u0433\u0434\u0435 status = \"active",
	} {
		plan, err := New().Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || len(plan.Filters) != 0 || len(plan.Reasons) != 1 || plan.Reasons[0] != "invalid_equality_filter" {
			t.Fatalf("%q escaped malformed equality boundary: %+v", question, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid unknown plan: %v", question, err)
		}
	}
}

func TestPlannerRejectsInvalidOrUnboundedDateRanges(t *testing.T) {
	for _, question := range []string{
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-08-20 \u043f\u043e 2026-08-01?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-02-30 \u043f\u043e 2026-03-01?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-08-00 \u043f\u043e 2026-08-15?",
		"How many requests for the last 367 days?",
		"How many requests for the last 1000 days?",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0437\u0430\u044f\u0432\u043e\u043a \u0441 2026-08-01?",
	} {
		plan, err := New().Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || len(plan.Reasons) != 1 || plan.Reasons[0] != "invalid_time_period" {
			t.Fatalf("%q escaped invalid-period boundary: %+v", question, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid unknown plan: %v", question, err)
		}
	}
}

func TestPlannerRejectsForgedOrUnknownFilters(t *testing.T) {
	for _, filter := range []Filter{
		{Name: "time_window", Value: "last_days:1000"},
		{Name: "time_range", Value: "2026-08-16/2026-08-01"},
		{Name: "time_period", Value: "forever"},
		{Name: "unknown", Value: "value"},
	} {
		if validFilter(filter) {
			t.Fatalf("invalid filter accepted: %+v", filter)
		}
	}
	for _, filter := range []Filter{
		{Name: "time_window", Value: "last_days:30"},
		{Name: "time_range", Value: "2026-08-01/2026-08-16"},
		{Name: "time_period", Value: "today"},
	} {
		if !validFilter(filter) {
			t.Fatalf("valid filter rejected: %+v", filter)
		}
	}
}

func TestPlannerUsesGenericOperationVocabulary(t *testing.T) {
	p := New()
	cases := []struct {
		question string
		want     Operation
	}{
		{"\u0427\u0442\u043e \u0443 \u043d\u0430\u0441 \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 \u0448\u0438\u043d\u0430 \u0438 \u0433\u0434\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f Kafka?", Explain},
		{"\u0415\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f \u043c\u0435\u0436\u0434\u0443 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u043e\u043c, \u043f\u0438\u0441\u044c\u043c\u0430\u043c\u0438 \u0438 \u0444\u0430\u043a\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u043c\u0438 \u0434\u0430\u043d\u043d\u044b\u043c\u0438?", Compare},
		{"\u041a\u0430\u043a\u0438\u0435 \u0431\u0438\u0437\u043d\u0435\u0441-\u043f\u0440\u043e\u0446\u0435\u0441\u0441\u044b \u0440\u0435\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u044b \u0432 \u043a\u043e\u0434\u0435, \u0430 \u043a\u0430\u043a\u0438\u0435 \u0442\u043e\u043b\u044c\u043a\u043e \u043e\u043f\u0438\u0441\u0430\u043d\u044b?", CodeTrace},
		{"\u041f\u0440\u043e\u0432\u0435\u0440\u044c, \u043a\u0430\u043a\u0438\u0435 compliance-\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u0438 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u044b \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u043c\u0438 \u0438 \u043a\u043e\u0434\u043e\u043c.", Audit},
	}
	for _, tc := range cases {
		plan, err := p.Plan(tc.question)
		if err != nil {
			t.Fatalf("%q: %v", tc.question, err)
		}
		if plan.Status != Ready || plan.Operation != tc.want {
			t.Fatalf("%q: operation=%s status=%s want=%s", tc.question, plan.Operation, plan.Status, tc.want)
		}
	}
}

func TestPlannerFailsClosedForUnknownAndAmbiguousRequests(t *testing.T) {
	p := New()
	unknown, err := p.Plan("???")
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Status != UnknownStatus || unknown.Operation != Unknown {
		t.Fatalf("unknown=%+v", unknown)
	}
	if err := unknown.Validate(); err != nil {
		t.Fatalf("unknown plan validation: %v", err)
	}
	ambiguous, err := p.Plan("\u041f\u0440\u043e\u0432\u0435\u0440\u044c \u0438 \u0441\u0440\u0430\u0432\u043d\u0438 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b \u0438 \u0434\u0430\u043d\u043d\u044b\u0435")
	if err != nil {
		t.Fatal(err)
	}
	if ambiguous.Status != ClarifyStatus || ambiguous.Operation != Clarify {
		t.Fatalf("ambiguous=%+v", ambiguous)
	}
	if err := ambiguous.Validate(); err != nil {
		t.Fatalf("clarification plan validation: %v", err)
	}
}

func TestPlannerRejectsExecutableOrMutatingRequestsWithoutRejectingExplain(t *testing.T) {
	p := New()
	for _, question := range []string{
		"SELECT * FROM customers",
		"\u0412\u044b\u043f\u043e\u043b\u043d\u0438 SQL \u0437\u0430\u043f\u0440\u043e\u0441 \u0438 \u0443\u0434\u0430\u043b\u0438 \u0437\u0430\u043f\u0438\u0441\u0438",
		"\u041e\u0442\u043f\u0440\u0430\u0432\u044c \u043f\u0438\u0441\u044c\u043c\u043e \u043a\u043b\u0438\u0435\u043d\u0442\u0443",
	} {
		plan, err := p.Plan(question)
		if err != nil {
			t.Fatalf("%q: %v", question, err)
		}
		if plan.Status != UnknownStatus || plan.Operation != Unknown || plan.Reasons[0] != "unsupported_read_only_boundary" {
			t.Fatalf("%q escaped read-only boundary: %+v", question, plan)
		}
		if err := plan.Validate(); err != nil {
			t.Fatalf("%q invalid unknown plan: %v", question, err)
		}
	}
	explain, err := p.Plan("\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 SQL \u0438 \u0433\u0434\u0435 \u043e\u043d \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f?")
	if err != nil {
		t.Fatal(err)
	}
	if explain.Status != Ready || explain.Operation != Explain {
		t.Fatalf("descriptive SQL question was rejected: %+v", explain)
	}
}

func TestPlannerCanonicalPlanIsDeterministic(t *testing.T) {
	p := New()
	left, err := p.Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043f\u043e \u043e\u0442\u0434\u0435\u043b\u0430\u043c \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	right, err := p.Plan("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043f\u043e \u043e\u0442\u0434\u0435\u043b\u0430\u043c \u0432\u0441\u0435\u0433\u043e?")
	if err != nil {
		t.Fatal(err)
	}
	if left.PlanHash != right.PlanHash || string(left.CanonicalBytes) != string(right.CanonicalBytes) {
		t.Fatalf("non-deterministic plan hashes %s/%s", left.PlanHash, right.PlanHash)
	}
}

func TestPlannerIsSafeForConcurrentRequests(t *testing.T) {
	p := New()
	questions := []string{
		"\u0427\u0442\u043e \u0443 \u043d\u0430\u0441 \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 \u0448\u0438\u043d\u0430 \u0438 \u0433\u0434\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f Kafka?",
		"\u041a\u0430\u043a\u0438\u0435 \u043a\u043e\u043c\u0430\u043d\u0434\u044b \u0437\u0430 \u043c\u0435\u0441\u044f\u0446 \u043e\u0431\u0440\u0430\u0431\u043e\u0442\u0430\u043b\u0438 \u0431\u043e\u043b\u044c\u0448\u0435 \u0437\u0430\u044f\u0432\u043e\u043a?",
		"\u041f\u0440\u043e\u0432\u0435\u0440\u044c \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0438\u0435 \u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044f \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u043c \u0438 \u043a\u043e\u0434\u0443",
		"SELECT * FROM forbidden_input",
	}
	want := make(map[string]string, len(questions))
	for _, question := range questions {
		plan, err := p.Plan(question)
		if err != nil {
			t.Fatal(err)
		}
		want[question] = plan.PlanHash
	}
	const workers = 16
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			for iteration := 0; iteration < 32; iteration++ {
				question := questions[(offset+iteration)%len(questions)]
				plan, err := p.Plan(question)
				if err != nil {
					errs <- err
					return
				}
				if plan.PlanHash != want[question] {
					errs <- &determinismError{question: question, got: plan.PlanHash, want: want[question]}
					return
				}
			}
		}(index)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestPlannerRejectsPlanMutationBeforeExecution(t *testing.T) {
	original, err := New().Plan("\u0422\u043e\u043f 3 \u043a\u043e\u043c\u0430\u043d\u0434 \u043f\u043e \u0441\u0443\u043c\u043c\u0435 \u0437\u0430\u044f\u0432\u043e\u043a")
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Plan){
		"operation": func(plan *Plan) { plan.Operation = Lookup },
		"status":    func(plan *Plan) { plan.Status = UnknownStatus },
		"reason":    func(plan *Plan) { plan.Reasons = []string{"forged"} },
		"limit":     func(plan *Plan) { plan.Aggregate.Limit = 128 },
		"canonical": func(plan *Plan) { plan.CanonicalBytes = append(plan.CanonicalBytes, 'x') },
		"hash":      func(plan *Plan) { plan.PlanHash = "sha256:" + strings.Repeat("f", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := original
			if original.Aggregate != nil {
				spec := *original.Aggregate
				mutated.Aggregate = &spec
			}
			mutated.SubjectTerms = append([]string(nil), original.SubjectTerms...)
			mutated.EntityHints = append([]string(nil), original.EntityHints...)
			mutated.Filters = append([]Filter(nil), original.Filters...)
			mutated.Reasons = append([]string(nil), original.Reasons...)
			mutate(&mutated)
			if err := mutated.Validate(); err == nil {
				t.Fatal("forged plan mutation passed validation")
			}
		})
	}
}

type determinismError struct {
	question string
	got      string
	want     string
}

func (err *determinismError) Error() string {
	return "planner hash changed concurrently for " + err.question + ": got=" + err.got + " want=" + err.want
}
