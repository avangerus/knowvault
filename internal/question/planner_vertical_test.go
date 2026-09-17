package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
)

func TestGenericPlannerVerticalSliceAggregatesAndRanksUnseenGroup(t *testing.T) {
	plannerInstance := planner.New()
	plan, err := plannerInstance.Plan("\u041a\u0430\u043a\u0438\u0435 \u043e\u0442\u0434\u0435\u043b\u044b \u0432 \u044d\u0442\u043e\u043c \u043c\u0435\u0441\u044f\u0446\u0435 \u0432\u044b\u0432\u0435\u0437\u043b\u0438 \u0431\u043e\u043b\u044c\u0448\u0435 \u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432?")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != planner.Aggregate || plan.Aggregate == nil || len(plan.Aggregate.GroupBy) != 1 || plan.Aggregate.Order != "DESC" {
		t.Fatalf("plan=%+v", plan)
	}
	candidates := []candidate{
		testPostgreSQLCandidate("department_a_1", "row_a_1", "department", "department = Alpha"),
		testPostgreSQLCandidate("date_a_1", "row_a_1", "collected_at", "collected_at = 2026-08-15"),
		testPostgreSQLCandidate("kilograms_a_1", "row_a_1", "kilograms", "kilograms = 12"),
		testPostgreSQLCandidate("department_a_2", "row_a_2", "department", "department = Alpha"),
		testPostgreSQLCandidate("date_a_2", "row_a_2", "collected_at", "collected_at = 2026-08-20"),
		testPostgreSQLCandidate("kilograms_a_2", "row_a_2", "kilograms", "kilograms = 8"),
		testPostgreSQLCandidate("department_b_1", "row_b_1", "department", "department = Beta"),
		testPostgreSQLCandidate("date_b_1", "row_b_1", "collected_at", "collected_at = 2026-08-22"),
		testPostgreSQLCandidate("kilograms_b_1", "row_b_1", "kilograms", "kilograms = 15"),
	}
	answer, citations := renderAnswerPlan("ws_demo", "\u041a\u0430\u043a\u0438\u0435 \u043e\u0442\u0434\u0435\u043b\u044b \u0432 \u044d\u0442\u043e\u043c \u043c\u0435\u0441\u044f\u0446\u0435 \u0432\u044b\u0432\u0435\u0437\u043b\u0438 \u0431\u043e\u043b\u044c\u0448\u0435 \u043a\u0438\u043b\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0432?", plan, candidates)
	if !strings.Contains(answer, "Alpha: 20") || strings.Contains(answer, "Beta: 15") {
		t.Fatalf("ranked answer=%q", answer)
	}
	if len(citations) != 3 {
		t.Fatalf("citations=%d want two numeric plus group evidence records", len(citations))
	}
}
