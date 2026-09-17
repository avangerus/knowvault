package planner

import "testing"

// TestPeriodFollowUpRecognizesBarePeriodContinuations proves the FIX-1 #4
// minimal topic-memory recognizer: "and yesterday?" and "for the week?" carry
// exactly one recognized time filter and nothing else meaningful, so they
// are period-only follow-ups.
func TestPeriodFollowUpRecognizesBarePeriodContinuations(t *testing.T) {
	cases := []struct {
		question   string
		wantName   string
		wantValue  string
		wantFollow bool
	}{
		{"\u0430 \u0432\u0447\u0435\u0440\u0430?", "time_period", "\u0432\u0447\u0435\u0440\u0430", true},
		{"\u0430 \u0437\u0430 \u043d\u0435\u0434\u0435\u043b\u044e?", "time_period", "\u043d\u0435\u0434\u0435\u043b\u044f", true},
		{"\u0430 \u0441\u0435\u0433\u043e\u0434\u043d\u044f?", "time_period", "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", true},
		{"\u0438 \u0437\u0430 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435 3 \u0434\u043d\u044f?", "time_window", "last_days:3", true},
		// A full new question that happens to contain a period word is not a
		// bare follow-up: "vehicle" carries real subject content.
		{"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0431\u044b\u043b\u043e \u0432\u0447\u0435\u0440\u0430?", "", "", false},
		// An equality predicate is a full new question, never a follow-up.
		{"\u0430 status = DONE?", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		filter, ok := PeriodFollowUp(tc.question)
		if ok != tc.wantFollow {
			t.Fatalf("PeriodFollowUp(%q) ok=%v want %v (filter=%+v)", tc.question, ok, tc.wantFollow, filter)
		}
		if !ok {
			continue
		}
		if filter.Name != tc.wantName || filter.Value != tc.wantValue {
			t.Fatalf("PeriodFollowUp(%q) = %+v, want {%s %s}", tc.question, filter, tc.wantName, tc.wantValue)
		}
	}
}

// TestSpliceFollowUpPeriodAppendsOntoAnUnperiodedBase proves the splice half:
// a base question with no period of its own gets the follow-up's period
// appended, and the combined text re-plans with that period recognized.
func TestSpliceFollowUpPeriodAppendsOntoAnUnperiodedBase(t *testing.T) {
	base := "\u041a\u0430\u043a\u0438\u0435 \u043e\u0431\u0440\u0430\u0449\u0435\u043d\u0438\u044f \u0433\u0440\u0430\u0436\u0434\u0430\u043d \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u044b?"
	filter, ok := PeriodFollowUp("\u0430 \u0432\u0447\u0435\u0440\u0430?")
	if !ok {
		t.Fatalf("expected \u0430 \u0432\u0447\u0435\u0440\u0430? to be recognized as a period follow-up")
	}
	combined, spliced := SpliceFollowUpPeriod(base, filter)
	if !spliced {
		t.Fatalf("expected splice to succeed onto an unperioded base")
	}
	plan, err := Default().Plan(combined)
	if err != nil {
		t.Fatalf("plan combined question %q: %v", combined, err)
	}
	found := false
	for _, planFilter := range plan.Filters {
		if planFilter.Name == "time_period" && planFilter.Value == "\u0432\u0447\u0435\u0440\u0430" {
			found = true
		}
	}
	if !found {
		t.Fatalf("combined question %q did not re-plan with the spliced period: filters=%+v", combined, plan.Filters)
	}
}

// TestSpliceFollowUpPeriodDeclinesWhenBaseAlreadyHasAPeriod proves the fail-
// safe half: a base question that already names its own period is never
// silently overwritten or duplicated -- splice declines rather than guess
// which period the caller now means.
func TestSpliceFollowUpPeriodDeclinesWhenBaseAlreadyHasAPeriod(t *testing.T) {
	base := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0431\u044b\u043b\u043e \u0432 \u0440\u0435\u0439\u0441\u0435 \u0432\u0447\u0435\u0440\u0430?"
	filter, ok := PeriodFollowUp("\u0430 \u0437\u0430 \u043d\u0435\u0434\u0435\u043b\u044e?")
	if !ok {
		t.Fatalf("expected \u0430 \u0437\u0430 \u043d\u0435\u0434\u0435\u043b\u044e? to be recognized as a period follow-up")
	}
	if _, spliced := SpliceFollowUpPeriod(base, filter); spliced {
		t.Fatalf("splice must decline when the base question already carries its own period")
	}
}

// TestAggregateFunctionFollowUpRecognizesBareOperationContinuations proves
// FIX-6 #1's second minimal topic-memory recognizer: "which ones?", "and how many?"
// and "list them" carry exactly one recognized reduction marker and nothing
// else meaningful.
func TestAggregateFunctionFollowUpRecognizesBareOperationContinuations(t *testing.T) {
	cases := []struct {
		question     string
		wantFunction string
		wantFollow   bool
	}{
		{"\u043a\u0430\u043a\u0438\u0435?", "LIST", true},
		{"\u0430 \u043a\u0430\u043a\u0438\u0435?", "LIST", true},
		{"\u043a\u0430\u043a\u0438\u0445?", "LIST", true},
		{"\u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438", "LIST", true},
		{"\u043f\u043e\u043a\u0430\u0436\u0438", "LIST", true},
		{"\u0430 \u0441\u043a\u043e\u043b\u044c\u043a\u043e?", "COUNT", true},
		{"\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e?", "COUNT", true},
		// A full new question that also names its own subject is not a bare
		// operation follow-up.
		{"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u043e\u0434\u0438\u0442\u0435\u043b\u0435\u0439 \u0441\u0435\u0433\u043e\u0434\u043d\u044f?", "", false},
		// A period-only follow-up carries its own recognized filter, so this
		// narrow detector declines and leaves it to PeriodFollowUp.
		{"\u0430 \u0432\u0447\u0435\u0440\u0430?", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		function, ok := AggregateFunctionFollowUp(tc.question)
		if ok != tc.wantFollow {
			t.Fatalf("AggregateFunctionFollowUp(%q) ok=%v want %v (function=%q)", tc.question, ok, tc.wantFollow, function)
		}
		if ok && function != tc.wantFunction {
			t.Fatalf("AggregateFunctionFollowUp(%q) = %q, want %q", tc.question, function, tc.wantFunction)
		}
	}
}

// TestSpliceFollowUpFunctionReplacesTheBaseQuestionsOwnReduction proves the
// splice half: a COUNT-shaped base question re-plans as LIST once "which ones" is
// spliced in, keeping the base's own period/subject intact -- the exact
// "how many vehicles are working today?" -> "which ones?" defect trace.
func TestSpliceFollowUpFunctionReplacesTheBaseQuestionsOwnReduction(t *testing.T) {
	base := "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?"
	combined, spliced := SpliceFollowUpFunction(base, "LIST")
	if !spliced {
		t.Fatalf("expected splice to succeed onto a COUNT-shaped base")
	}
	plan, err := Default().Plan(combined)
	if err != nil {
		t.Fatalf("plan combined question %q: %v", combined, err)
	}
	if plan.Operation != Aggregate || plan.Aggregate == nil || plan.Aggregate.Function != "LIST" {
		t.Fatalf("combined question %q did not re-plan as LIST: operation=%v aggregate=%+v", combined, plan.Operation, plan.Aggregate)
	}
	foundPeriod := false
	for _, filter := range plan.Filters {
		if filter.Name == "time_period" && filter.Value == "\u0441\u0435\u0433\u043e\u0434\u043d\u044f" {
			foundPeriod = true
		}
	}
	if !foundPeriod {
		t.Fatalf("combined question %q lost the base's own period: filters=%+v", combined, plan.Filters)
	}
}

// TestSpliceFollowUpFunctionDeclinesWithoutAnOwnReductionMarker proves the
// fail-safe half: a base question naming no recognized reduction marker has
// nothing this splice can safely replace.
func TestSpliceFollowUpFunctionDeclinesWithoutAnOwnReductionMarker(t *testing.T) {
	if _, spliced := SpliceFollowUpFunction("\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 SLA?", "LIST"); spliced {
		t.Fatalf("splice must decline when the base question names no reduction marker")
	}
}
