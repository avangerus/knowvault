package question

// Review remark Z1 (POKA_YOKE QRY-002 / SRCH-004). A PARTIAL corpus is a
// corpus this run did not see all of. Prose degrades honestly under that -- an
// excerpt is still a true excerpt -- but an aggregate does not: SUM/COUNT over
// the visible window is the exact answer to a different question, and it was
// published as COMPLETED with a precise number and no marking.
//
// These tests are the direct proof, over real structured cell Evidence the
// analytic adapter actually reduces, that the same candidates yield an exact
// total when the corpus is complete and are withheld when it is not.

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
)

func partialAggregateCandidates() []candidate {
	return []candidate{
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "row_a", "tonnes = 12.345"),
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAW", "row_b", "tonnes = 7.125"),
	}
}

func mustAggregatePlan(t *testing.T, question string) planner.Plan {
	t.Helper()
	planned, err := planner.Default().Plan(question)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Status != planner.Ready || planned.Operation != planner.Aggregate {
		t.Fatalf("fixture must plan a ready aggregate, got status=%v operation=%v", planned.Status, planned.Operation)
	}
	return planned
}

// The control: with the whole corpus visible, these candidates DO produce an
// exact total. Without this, the suppression test below could pass simply
// because the aggregate never resolves.
func TestCompleteCorpusPublishesTheExactAggregate(t *testing.T) {
	planned := mustAggregatePlan(t, "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?")
	selected := partialAggregateCandidates()
	if aggregateWithheldOnPartialCorpus(planned, false) {
		t.Fatal("a complete corpus must not withhold its aggregate")
	}
	answer, citations, _ := renderAnswerPlanAtWithReceipt("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", planned, selected, time.Unix(1, 0).UTC())
	if answer != "\u0418\u0442\u043e\u0433\u043e: 19.470" || len(citations) != 2 {
		t.Fatalf("expected the exact total with its citations, got answer=%q citations=%d", answer, len(citations))
	}
}

// The case itself: the identical plan and Evidence over a truncated corpus
// publishes no number at all. complete() turns the withheld selection into the
// ordinary insufficient-evidence terminal state, with corpus_status PARTIAL
// and the CORPUS_PARTIAL uncertainty carried beside it.
func TestPartialCorpusWithholdsTheExactAggregate(t *testing.T) {
	planned := mustAggregatePlan(t, "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?")
	if !aggregateWithheldOnPartialCorpus(planned, true) {
		t.Fatal("a PARTIAL corpus must withhold an exact aggregate")
	}
	// complete() clears the selection when the guard fires; rendering with
	// nothing selected is what it then does.
	answer, citations, _ := renderAnswerPlanAtWithReceipt("ws_demo", "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", planned, nil, time.Unix(1, 0).UTC())
	if answer != "" || len(citations) != 0 {
		t.Fatalf("a withheld aggregate must publish nothing, got answer=%q citations=%d", answer, len(citations))
	}
}

// The guard is about aggregates only. A PARTIAL corpus must keep answering
// every other operation: the retrieval budget makes any corpus larger than the
// candidate window permanently partial, so suppressing prose there would stop
// a workspace answering at all the moment a second source is connected.
func TestPartialCorpusStillAnswersNonAggregateOperations(t *testing.T) {
	planned, err := planner.Default().Plan("\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u0441\u0442\u0430\u0442\u0443\u0441 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Operation == planner.Aggregate {
		t.Fatalf("fixture question must not plan an aggregate, got %v", planned.Operation)
	}
	if aggregateWithheldOnPartialCorpus(planned, true) {
		t.Fatal("a PARTIAL corpus must not withhold a non-aggregate answer")
	}
}

// A plan that is not Ready (UNKNOWN, CLARIFICATION_REQUIRED) already completes
// as its own terminal state; the guard must not claim it.
func TestWithheldAggregateAppliesOnlyToReadyPlans(t *testing.T) {
	planned := mustAggregatePlan(t, "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?")
	planned.Status = planner.UnknownStatus
	if aggregateWithheldOnPartialCorpus(planned, true) {
		t.Fatal("only a ready aggregate plan is withheld by the partial-corpus guard")
	}
}
