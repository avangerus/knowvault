package question

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

func TestToolLoopAdvertisesBothGovernedToolsWhenConfigured(t *testing.T) {
	definitions, err := toolLoopGovernedDefinitions(trustedMetricCatalog(), &liveDataAskProbe{}, false, [2]string{})
	if err != nil || len(definitions) != 1 || definitions[0].Function.Name != liveDataToolName {
		t.Fatalf("single-date definitions = %#v, err %v; want live ask only", definitions, err)
	}
	definitions, err = toolLoopGovernedDefinitions(trustedMetricCatalog(), nil, false, [2]string{})
	if err != nil || len(definitions) != 0 {
		t.Fatalf("preset-only single-date definitions = %#v, err %v; want no governed tool", definitions, err)
	}
	if !strings.Contains(toolLoopInstructions, "Never invent a second date") ||
		!strings.Contains(toolLoopInstructions, "two distinct dates") {
		t.Fatal("tool routing guidance does not distinguish a requested comparison from a single-date read")
	}
}

func TestToolLoopDispatchesSingleDateAskWithComparisonCatalog(t *testing.T) {
	const question = "For code METER on 2026-09-10 in Europe/Moscow, use the latest snapshot of that local date; what are the GM and contributing rows?"
	ask := &liveDataAskProbe{result: liveDataResultFixture()}
	compare := &trustedMetricProbe{}
	service := &Service{liveDataAsk: ask, trustedMetricComparison: compare}
	run := Run{WorkspaceID: "ws_current", ID: "qrun_current"}
	access := database.AccessContext{OrganizationID: "org_current", PrincipalID: "usr_current", RequestID: "req_current"}
	state := &liveDataRunState{}
	result, evidence, err := service.invokeToolLoopGovernedData(context.Background(), access, run,
		liveDataToolName, trustedMetricCatalog(), false, [2]string{}, []string{"2026-09-10"}, json.RawMessage(`{"question":"`+question+`"}`), 8192, state)
	if err != nil || result.IsError || evidence != nil {
		t.Fatalf("one-date ask result = %#v, evidence = %#v, err = %v", result, evidence, err)
	}
	if ask.calls != 1 || ask.question != question || ask.access != access || ask.workspace != run.WorkspaceID || compare.calls != 0 ||
		!state.successfulCall || len(state.executions) != 1 {
		t.Fatalf("one-date ask was not dispatched and retained: ask=%#v compare=%#v state=%#v", ask, compare, state)
	}
	wrongDate, _, err := service.invokeToolLoopGovernedData(context.Background(), access, run,
		liveDataToolName, trustedMetricCatalog(), false, [2]string{}, []string{"2026-09-10"},
		json.RawMessage(`{"question":"What was the metric on 2026-01-10?"}`), 8192, &liveDataRunState{})
	if err != nil || !wrongDate.IsError || ask.calls != 1 {
		t.Fatalf("rewritten date reached database: result=%#v err=%v calls=%d", wrongDate, err, ask.calls)
	}
	presetOnly := &Service{trustedMetricComparison: compare}
	refusal, _, err := presetOnly.invokeToolLoopGovernedData(context.Background(), access, run,
		liveDataToolName, trustedMetricCatalog(), false, [2]string{}, nil, json.RawMessage(`{"question":"`+question+`"}`), 8192, &liveDataRunState{})
	if err != nil || !refusal.IsError || compare.calls != 0 {
		t.Fatalf("preset-only live ask = %#v, err %v, comparison calls %d; want refusal", refusal, err, compare.calls)
	}
	refusal, _, err = service.invokeToolLoopGovernedData(context.Background(), access, run,
		trustedMetricToolName, trustedMetricCatalog(), false, [2]string{}, nil,
		json.RawMessage(`{"metric_id":"gm.assigned_tasks_observed","date_a":"2026-01-10","date_b":"2026-01-11"}`), 8192, &liveDataRunState{})
	if err != nil || !refusal.IsError || compare.calls != 0 {
		t.Fatalf("unadvertised one-date comparison = %#v, err %v, calls %d; want refusal", refusal, err, compare.calls)
	}
}

func TestRecognizedComparisonRoutesOnlyExplicitTwoDateQuestions(t *testing.T) {
	comparisons := []string{
		"Compare the assigned work indicator on 2026-09-10 versus 2026-09-09 and explain the rule in the documents.",
		"\u0421\u0440\u0430\u0432\u043d\u0438 9 \u0438 10 \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f 2026 \u0433\u043e\u0434\u0430: \u043a\u0430\u043a\u0430\u044f \u0440\u0430\u0437\u043d\u0438\u0446\u0430?",
		"\u0410 \u043a\u0430\u043a\u043e\u0439 \u0438\u0437 \u044d\u0442\u0438\u0445 \u0434\u0432\u0443\u0445 \u0434\u043d\u0435\u0439 \u0432\u044b\u0448\u0435 \u0438 \u043d\u0430 \u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043f\u0440\u043e\u0446\u0435\u043d\u0442\u043e\u0432?",
	}
	for _, question := range comparisons {
		if !recognizedComparison(question) {
			t.Fatalf("comparison was not recognized: %q", question)
		}
		definitions, err := toolLoopGovernedDefinitions(trustedMetricCatalog(), &liveDataAskProbe{}, true, [2]string{"2026-09-09", "2026-09-10"})
		if err != nil || len(definitions) != 1 || definitions[0].Function.Name != trustedMetricToolName {
			t.Fatalf("comparison definitions = %#v, err = %v", definitions, err)
		}
		ask := &liveDataAskProbe{result: liveDataResultFixture()}
		service := &Service{liveDataAsk: ask, trustedMetricComparison: &trustedMetricProbe{}}
		refusal, _, err := service.invokeToolLoopGovernedData(context.Background(), database.AccessContext{}, Run{WorkspaceID: "ws_current", ID: "qrun_current"},
			liveDataToolName, trustedMetricCatalog(), true, [2]string{"2026-09-09", "2026-09-10"}, nil, json.RawMessage(`{"question":"bypass"}`), 8192, &liveDataRunState{})
		if err != nil || !refusal.IsError || !strings.Contains(refusal.Text, "TRUSTED_COMPARISON_REQUIRED") || ask.calls != 0 {
			t.Fatalf("generic comparison attempt = %#v, err = %v, calls = %d", refusal, err, ask.calls)
		}
	}
	for _, question := range []string{
		"What is the assigned work indicator on 2026-09-10?",
		"What company data is available now?",
		"Compare 2026-09-10 with 2026-09-10.",
	} {
		if recognizedComparison(question) {
			t.Fatalf("noncomparison was recognized: %q", question)
		}
		definitions, err := toolLoopGovernedDefinitions(trustedMetricCatalog(), &liveDataAskProbe{}, false, [2]string{})
		if err != nil || len(definitions) != 1 || definitions[0].Function.Name != liveDataToolName {
			t.Fatalf("noncomparison definitions = %#v, err = %v", definitions, err)
		}
	}
}

func TestComparisonDatePairBindsOnlyUserDates(t *testing.T) {
	sep := [2]string{"2026-09-09", "2026-09-10"}
	for _, question := range []string{
		"Compare 2026-09-10 with 2026-09-09.",
		"\u0421\u0440\u0430\u0432\u043d\u0438 9 \u0438 10 \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f 2026 \u0433\u043e\u0434\u0430.",
		"\u0421\u0440\u0430\u0432\u043d\u0438 10 \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f \u0438 9 \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f 2026 \u0433\u043e\u0434\u0430.",
		"Compare 09.09.2026 and 10.09.2026.",
	} {
		if got := comparisonDatePair(question, nil); got != sep {
			t.Fatalf("dates for %q = %v, want %v", question, got, sep)
		}
	}
	for _, question := range []string{
		"Compare 2026-09-10 and 10 \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f 2026.",
		"Compare 2026-09-10 with 2026-09-10.",
		"Compare 2026-02-30 with 2026-09-10.",
		"Compare 2026-09-09, 2026-09-10, and 2026-09-11.",
	} {
		if got := comparisonDatePair(question, nil); got != [2]string{} {
			t.Fatalf("ambiguous or single dates for %q = %v", question, got)
		}
	}
	if got := comparisonDatePair("\u0410 \u043a\u0430\u043a\u043e\u0439 \u0438\u0437 \u044d\u0442\u0438\u0445 \u0434\u0432\u0443\u0445 \u0434\u043d\u0435\u0439 \u0432\u044b\u0448\u0435?",
		[]toolLoopConversationTurn{{Question: "Compare 2026-09-10 with 2026-09-09."}}); got != sep {
		t.Fatalf("follow-up dates = %v, want %v", got, sep)
	}
	if got := comparisonDatePair("\u0410 \u043a\u0430\u043a\u043e\u0439 \u0438\u0437 \u044d\u0442\u0438\u0445 \u0434\u0432\u0443\u0445 \u0434\u043d\u0435\u0439 \u0432\u044b\u0448\u0435?",
		[]toolLoopConversationTurn{{Question: "What is the latest value?"}}); got != [2]string{} {
		t.Fatalf("unrelated history supplied dates: %v", got)
	}
	if !comparisonArgumentsMatch(json.RawMessage(`{"metric_id":"gm.assigned_tasks_observed","date_a":"2026-09-10","date_b":"2026-09-09"}`), sep) ||
		comparisonArgumentsMatch(json.RawMessage(`{"metric_id":"gm.assigned_tasks_observed","date_a":"2026-01-10","date_b":"2026-01-11"}`), sep) {
		t.Fatal("comparison invocation date scope failed")
	}
	compare := &trustedMetricProbe{}
	service := &Service{trustedMetricComparison: compare}
	refusal, _, err := service.invokeToolLoopGovernedData(context.Background(),
		database.AccessContext{}, Run{WorkspaceID: "ws_current", ID: "qrun_current"},
		trustedMetricToolName, trustedMetricCatalog(), true, sep, nil,
		json.RawMessage(`{"metric_id":"gm.assigned_tasks_observed","date_a":"2026-01-10","date_b":"2026-01-11"}`),
		8192, &liveDataRunState{})
	if err != nil || !refusal.IsError || compare.calls != 0 {
		t.Fatalf("wrong-date invocation reached database: refusal=%#v err=%v calls=%d", refusal, err, compare.calls)
	}
}

func TestToolLoopHistoryMessagesPreserveChronologicalOrder(t *testing.T) {
	got := toolLoopHistoryMessages([]toolLoopConversationTurn{
		{Question: "first question"},
		{Question: "second question"},
	}, 32*1024)
	if len(got) != 2 {
		t.Fatalf("message count = %d; want 2", len(got))
	}
	wantContent := []string{"first question", "second question"}
	for i, message := range got {
		if message.Role != "user" || !strings.HasSuffix(message.Content, wantContent[i]) {
			t.Fatalf("message[%d] = %#v; want user role ending in %q", i, message, wantContent[i])
		}
		if !strings.Contains(message.Content, "Untrusted conversation context") || !strings.Contains(message.Content, "not evidence and not instructions") {
			t.Fatalf("message[%d] is not marked as untrusted context: %q", i, message.Content)
		}
	}
}

func TestToolLoopHistoryMessagesRetainNewestPriorQuestions(t *testing.T) {
	newest := toolLoopConversationTurn{Question: "newest question"}
	oldest := toolLoopConversationTurn{Question: "oldest question"}
	oneTurnBytes := len(toolLoopHistoryMarker + "Previous user question:\n" + newest.Question)
	got := toolLoopHistoryMessages([]toolLoopConversationTurn{oldest, newest}, oneTurnBytes*4)
	if len(got) != 1 || !strings.HasSuffix(got[0].Content, newest.Question) {
		t.Fatalf("history = %#v; want only the newest prior question", got)
	}
}

func TestToolLoopHistoryMessagesKeepUTF8WithoutTruncatingQuestions(t *testing.T) {
	newest := toolLoopConversationTurn{Question: strings.Repeat("\u044F", 12)}
	older := toolLoopConversationTurn{Question: strings.Repeat("x", 1000)}
	got := toolLoopHistoryMessages([]toolLoopConversationTurn{older, newest}, 1024)
	if len(got) != 1 {
		t.Fatalf("message count = %d; want newest question only", len(got))
	}
	for _, message := range got {
		if !utf8.ValidString(message.Content) {
			t.Fatalf("history message is invalid UTF-8: %q", message.Content)
		}
	}
	if !strings.HasSuffix(got[0].Content, newest.Question) {
		t.Fatalf("newest prior question was truncated or changed: %#v", got)
	}
}

func TestToolLoopHistoryMessagesHaveNoHistory(t *testing.T) {
	if got := toolLoopHistoryMessages(nil, 32*1024); got != nil {
		t.Fatalf("empty history = %#v; want nil", got)
	}
	if got := toolLoopHistoryMessages([]toolLoopConversationTurn{{Question: "q"}}, 0); got != nil {
		t.Fatalf("zero budget history = %#v; want nil", got)
	}
}

func TestSuccessfulLiveReadPlusRefusedDocumentRequestRejectsUncitedClaim(t *testing.T) {
	projection, dependency, liveRecord := livePersistenceFixture(t)
	liveRecord.Calls = append(liveRecord.Calls, ToolCallRecord{ID: "doc-call-1", Name: "knowvault_read", Outcome: "REFUSED"})
	if !validateGovernedQueryToolBinding(livePersistenceRunID, &dependency, liveRecord) {
		t.Fatal("successful live table did not remain valid alongside a refused document read")
	}
	liveAnswer := livePersistenceAnswer(t, projection, dependency)
	if liveAnswer.Kind != "LIVE_TABLE" || len(liveAnswer.Keys) != 0 {
		t.Fatalf("server-owned live result was not kept separate from prose: %#v", liveAnswer)
	}

	call := modelgateway.ToolCall{}
	call.Function.Name = "knowvault_read"
	workspaceToolRequested := containsWorkspaceToolRequest([]modelgateway.ToolCall{call}, map[string]struct{}{"knowvault_read": {}})
	if !workspaceToolRequested {
		t.Fatal("document read request was not counted before its refused result")
	}
	liveOnly := toolLiveOnlyInterpretationAllowed(true, workspaceToolRequested, false)
	allClaimsBound := toolClaimHasSupport(false, 0, true, liveOnly)
	status := "COMPLETED"
	if !toolAnswerHasCompleteSupport(0, true, allClaimsBound) {
		status = "INSUFFICIENT_EVIDENCE"
	}
	if status != "INSUFFICIENT_EVIDENCE" || allClaimsBound {
		t.Fatalf("uncited invented document rule escaped after a refused read: status=%s all_claims_bound=%v", status, allClaimsBound)
	}
}

func TestPureLiveAndMixedDocumentClaimsUseSeparateSupport(t *testing.T) {
	projection, dependency, liveRecord := livePersistenceFixture(t)
	if !validateGovernedQueryToolBinding(livePersistenceRunID, &dependency, liveRecord) {
		t.Fatal("pure-live successful table did not validate")
	}
	liveAnswer := livePersistenceAnswer(t, projection, dependency)
	if liveAnswer.Kind != "LIVE_TABLE" || !toolLiveOnlyInterpretationAllowed(true, false, false) ||
		!toolClaimHasSupport(false, 0, true, true) || !toolAnswerHasCompleteSupport(0, true, true) {
		t.Fatal("citation-free interpretation without document tools was refused")
	}

	answerWithDocumentSelector := toolAnswer{Claims: []toolClaim{{Text: "Document rule", Citations: []toolCitation{{FragmentID: "fragment_1"}}}}}
	if toolLiveOnlyInterpretationAllowed(true, true, false) ||
		toolLiveOnlyInterpretationAllowed(true, false, toolAnswerHasCitationSelector(answerWithDocumentSelector)) {
		t.Fatal("live-only exception remained available in a mixed or cited answer")
	}
	if !toolClaimHasSupport(true, 1, true, false) || liveAnswer.Kind != "LIVE_TABLE" ||
		!toolAnswerHasCompleteSupport(1, true, true) {
		t.Fatal("cited document prose with a separate live receipt was refused")
	}
	if toolClaimHasSupport(true, 0, false, false) || toolAnswerHasCompleteSupport(1, true, false) {
		t.Fatal("invalid document references were rescued by the live table")
	}
	if toolLiveOnlyInterpretationAllowed(false, false, false) || toolClaimHasSupport(false, 0, true, false) {
		t.Fatal("citation-free claim without a live result was treated as supported")
	}
}

func TestToolLoopNoDataFallbackForRefusedMetricComparison(t *testing.T) {
	if got := toolLoopNoDataFallback(&ToolLoopRecord{Calls: []ToolCallRecord{{
		Name: trustedMetricToolName, Outcome: "REFUSED",
		Result: workspacetools.Result{Text: `{"error":"SNAPSHOT_UNAVAILABLE","date":"2026-09-10"}`},
	}}}, false); got != refusedMetricComparison {
		t.Fatalf("refused metric comparison fallback = %q; want %q", got, refusedMetricComparison)
	}
	if strings.Contains(refusedMetricComparison, "2026-09-10") || strings.Contains(refusedMetricComparison, "access") {
		t.Fatalf("fallback exposes refusal details: %q", refusedMetricComparison)
	}
	if got := toolLoopNoDataFallback(&ToolLoopRecord{Calls: []ToolCallRecord{{
		Name: trustedMetricToolName, Outcome: "REFUSED",
	}}}, true); got != noWorkspaceData {
		t.Fatalf("fallback with successful comparison = %q; want %q", got, noWorkspaceData)
	}
	if got := toolLoopNoDataFallback(&ToolLoopRecord{Calls: []ToolCallRecord{{
		Name: "knowvault_search", Outcome: "REFUSED",
	}}}, false); got != noWorkspaceData {
		t.Fatalf("fallback for another refused tool = %q; want %q", got, noWorkspaceData)
	}
}

func TestInitialToolLoopMessagesKeepHistoryOutOfPersistedTrace(t *testing.T) {
	const priorQuestion = "prior private question body"
	const priorAnswer = "prior private answer body"
	const priorScalar = "prior scalar result 742"
	outbound, persisted := initialToolLoopMessages("current question", []toolLoopConversationTurn{{
		Question: priorQuestion,
	}}, 32*1024)
	if len(outbound) != 3 || !strings.Contains(outbound[1].Content, priorQuestion) {
		t.Fatalf("outbound messages do not contain prior question context: %#v", outbound)
	}
	if len(persisted) != 2 || persisted[1].Content != "current question" {
		t.Fatalf("persisted initial messages = %#v; want only system and current question", persisted)
	}
	for _, message := range persisted {
		if strings.Contains(message.Content, priorQuestion) || strings.Contains(message.Content, priorAnswer) || strings.Contains(message.Content, priorScalar) {
			t.Fatalf("persisted initial trace contains previous-turn body: %#v", persisted)
		}
	}
	for _, message := range outbound {
		if strings.Contains(message.Content, priorAnswer) || strings.Contains(message.Content, priorScalar) {
			t.Fatalf("outbound context contains a prior answer/calculation: %#v", outbound)
		}
	}
}

func TestRecentToolLoopConversationTurnsRequireEarlierTerminalDisplayableRuns(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func (service *Service) recentToolLoopConversationTurns(")
	if start < 0 {
		t.Fatal("service.go does not declare recentToolLoopConversationTurns")
	}
	end := strings.Index(text[start:], "var errPreviousTurnUnreadable")
	if end < 0 {
		t.Fatal("cannot find the end of recentToolLoopConversationTurns")
	}
	sql := text[start : start+end]
	for _, required := range []string{
		"prior.turn_index < current_turn.turn_index",
		"current_turn.id = $4",
		"prior_run.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE')",
		"prior_run.question_text_artifact_id IS NOT NULL",
		"prior_run.answer_markdown_artifact_id IS NOT NULL OR NULLIF(prior_run.planner_clarification, '') IS NOT NULL",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("recent history SQL is missing %q", required)
		}
	}
	if strings.Contains(sql, "id <> $4") {
		t.Fatal("recent history must order against the current turn, not merely exclude its id")
	}
	for _, required := range []string{
		"runs, err := service.GetBatch(ctx, access, workspaceID, runIDs)",
		"return toolLoopConversationTurnsFromBatch(runIDs, runs), nil",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("recent history does not use the governed surviving-run map: missing %q", required)
		}
	}
	helperStart := strings.Index(text, "func toolLoopConversationTurnsFromBatch(")
	if helperStart < 0 {
		t.Fatal("service.go does not declare the surviving-run history projection")
	}
	helperEnd := strings.Index(text[helperStart:], "var errPreviousTurnUnreadable")
	if helperEnd < 0 {
		t.Fatal("cannot find the end of toolLoopConversationTurnsFromBatch")
	}
	helper := text[helperStart : helperStart+helperEnd]
	for _, required := range []string{"run, ok := runs[runIDs[i]]", "if !ok {\n\t\t\tcontinue", "toolLoopConversationTurn{Question: run.Question}"} {
		if !strings.Contains(helper, required) {
			t.Fatalf("surviving-run projection is missing %q", required)
		}
	}
}

func TestRevokedGovernedPriorQuestionIsOmittedFromNextModelPrompt(t *testing.T) {
	const revokedQuestion = "revoked governed prior question"
	const readableQuestion = "still readable prior question"
	// recentToolLoopConversationTurns receives this map from GetBatch. A
	// governed-denied prior run is removed from that map; exercise the exact
	// projection it uses and then the production prompt builder.
	runIDs := []string{"run_readable_prior", "run_revoked_governed_prior"}
	history := toolLoopConversationTurnsFromBatch(runIDs, map[string]Run{
		"run_readable_prior": {Question: readableQuestion},
	})
	if len(history) != 1 || history[0].Question != readableQuestion {
		t.Fatalf("history = %#v, want only the surviving prior run", history)
	}
	outbound, _ := initialToolLoopMessages("next model question", history, 32*1024)
	foundReadable, foundRevoked := false, false
	for _, message := range outbound {
		foundReadable = foundReadable || strings.Contains(message.Content, readableQuestion)
		foundRevoked = foundRevoked || strings.Contains(message.Content, revokedQuestion)
	}
	if !foundReadable || foundRevoked {
		t.Fatalf("next prompt readable=%v revoked=%v messages=%#v", foundReadable, foundRevoked, outbound)
	}
}

func TestToolAnswerAcceptsOnlyAnEntireJSONFence(t *testing.T) {
	const payload = `{"no_data":false,"claims":[{"text":"A source-backed fact.","citations":[{"fragment_id":"fragment_1"}]}]}`
	want, ok := parseToolAnswer(payload)
	if !ok {
		t.Fatal("valid bare answer rejected")
	}
	for _, wrapped := range []string{
		"```json\n" + payload + "\n```",
		"```\n" + payload + "\n```",
		" \r\n```json\r\n" + payload + "\r\n```\r\n ",
	} {
		got, ok := parseToolAnswer(wrapped)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("wrapper changed the answer: ok=%v got=%#v", ok, got)
		}
	}
	for _, invalid := range []string{
		"Here is an answer:\n```json\n" + payload + "\n```",
		"```json\n" + payload + "\n```\nAdditional claim.",
		"```json\n" + payload,
		"```javascript\n" + payload + "\n```",
		"```json\n" + payload + "\n```\n```json\n" + payload + "\n```",
		"```json\n{\"no_data\":true,\"no_data\":false}\n```",
		"```json\n{\"no_data\":true,\"unknown\":1}\n```",
		"```json\n{\"no_data\":true,}\n```",
		"```json\n{}\n```",
	} {
		if _, ok := parseToolAnswer(invalid); ok {
			t.Fatalf("invalid wrapped answer accepted: %q", invalid)
		}
	}
}

func TestToolAnswerDetailedClassifiesFormatFailures(t *testing.T) {
	const validAnswer = `{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"fragment_1"}]}]}`
	for _, tc := range []struct {
		name    string
		content string
		want    toolFormatInvalidCode
	}{
		{name: "Q3 quote only citation lacks selector", content: `{"no_data":false,"claims":[{"text":"Fact.","citations":[{"quote":"Source words."}]}]}`, want: toolFormatCitationSelectorInvalid},
		{name: "Q6 malformed JSON", content: `{"no_data":false,}`, want: toolFormatContentWrapperOrNonJSON},
		{name: "non JSON prose", content: "This is not JSON.", want: toolFormatContentWrapperOrNonJSON},
		{name: "invalid schema", content: `{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"fragment_1"}]}],"extra":true}`, want: toolFormatAnswerSchemaInvalid},
		{name: "invalid answer variant", content: `{"no_data":true,"claims":[{"text":"Fact.","citations":[{"fragment_id":"fragment_1"}]}]}`, want: toolFormatAnswerVariantInvalid},
		{name: "valid answer", content: validAnswer, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code := parseToolAnswerDetailed(tc.content)
			if code != tc.want {
				t.Fatalf("format code = %q; want %q", code, tc.want)
			}
		})
	}
}

func TestToolAnswerHasCitationSelector(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer toolAnswer
		want   bool
	}{
		{
			name:   "fragment id",
			answer: toolAnswer{Claims: []toolClaim{{Citations: []toolCitation{{FragmentID: "fragment_1"}}}}},
			want:   true,
		},
		{
			name:   "address",
			answer: toolAnswer{Claims: []toolClaim{{Citations: []toolCitation{{Address: "kv1:object/fragment"}}}}},
			want:   true,
		},
		{
			name:   "selector in later claim",
			answer: toolAnswer{Claims: []toolClaim{{Text: "Uncited text."}, {Citations: []toolCitation{{FragmentID: "fragment_2"}}}}},
			want:   true,
		},
		{
			name:   "citation without selector",
			answer: toolAnswer{Claims: []toolClaim{{Citations: []toolCitation{{Quote: "text"}}}}},
		},
		{
			name:   "no claims",
			answer: toolAnswer{NoData: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolAnswerHasCitationSelector(tc.answer); got != tc.want {
				t.Fatalf("toolAnswerHasCitationSelector() = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestContainsWorkspaceToolRequestUsesCatalogAndCountsRefusedBatch(t *testing.T) {
	makeCall := func(name string) modelgateway.ToolCall {
		var call modelgateway.ToolCall
		call.Function.Name = name
		return call
	}
	catalog := map[string]struct{}{
		"knowvault_search":     {},
		analyticScalarToolName: {},
		submitAnswerToolName:   {},
	}
	for _, tc := range []struct {
		name  string
		calls []modelgateway.ToolCall
		want  bool
	}{
		{
			name:  "recognized document call in refused batch",
			calls: []modelgateway.ToolCall{makeCall("knowvault_search"), makeCall("unrecognized_tool")},
			want:  true,
		},
		{
			name:  "only unrecognized calls",
			calls: []modelgateway.ToolCall{makeCall("unrecognized_tool")},
		},
		{
			name:  "analytic and submit calls are special",
			calls: []modelgateway.ToolCall{makeCall(analyticScalarToolName), makeCall(submitAnswerToolName)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsWorkspaceToolRequest(tc.calls, catalog); got != tc.want {
				t.Fatalf("containsWorkspaceToolRequest() = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestToolLoopFormatDiagnosticsAreBoundedAndContentFree(t *testing.T) {
	record := &ToolLoopRecord{StopReason: "FORMAT_INVALID"}
	appendToolFormatDiagnostic(record, 1, toolFormatChannelContent, toolFormatContentWrapperOrNonJSON)
	appendToolFormatDiagnostic(record, 2, toolFormatChannelSubmitAnswer, toolFormatSubmitNotSole)
	appendToolFormatDiagnostic(record, 3, toolFormatChannelContent, toolFormatAnswerSchemaInvalid)
	if len(record.FormatDiagnostics) != toolFormatDiagnosticLimit {
		t.Fatalf("diagnostic count = %d; want %d", len(record.FormatDiagnostics), toolFormatDiagnosticLimit)
	}
	want := []toolFormatDiagnostic{
		{Turn: 1, Channel: toolFormatChannelContent, Code: toolFormatContentWrapperOrNonJSON},
		{Turn: 2, Channel: toolFormatChannelSubmitAnswer, Code: toolFormatSubmitNotSole},
	}
	if !reflect.DeepEqual(record.FormatDiagnostics, want) {
		t.Fatalf("diagnostics = %#v; want %#v", record.FormatDiagnostics, want)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, forbidden := range []string{"model answer text", "source-fragment-id", "source-hash", "tool-argument"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("diagnostic serialization leaked %q: %s", forbidden, serialized)
		}
	}
	var decoded struct {
		FormatDiagnostics []map[string]json.RawMessage `json:"format_diagnostics"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.FormatDiagnostics) != 2 {
		t.Fatalf("serialized diagnostics = %#v", decoded.FormatDiagnostics)
	}
	var roundTrip ToolLoopRecord
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip.FormatDiagnostics, want) {
		t.Fatalf("round-tripped diagnostics = %#v; want %#v", roundTrip.FormatDiagnostics, want)
	}
	for _, diagnostic := range decoded.FormatDiagnostics {
		if len(diagnostic) != 3 {
			t.Fatalf("diagnostic contains fields beyond turn/channel/code: %#v", diagnostic)
		}
		for _, key := range []string{"turn", "channel", "code"} {
			if _, ok := diagnostic[key]; !ok {
				t.Fatalf("diagnostic missing %q: %#v", key, diagnostic)
			}
		}
	}
}

func TestToolAnswerDistinguishesClarificationFromUnsupportedClaims(t *testing.T) {
	for _, input := range []struct {
		name   string
		answer toolAnswer
		valid  bool
	}{
		{"clarification", toolAnswer{Clarification: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0447\u0435\u0433\u043e \u043d\u0443\u0436\u043d\u043e \u0443\u0437\u043d\u0430\u0442\u044c?"}, true},
		{"empty clarification", toolAnswer{Clarification: " "}, false},
		{"clarification mixed with facts", toolAnswer{Clarification: "\u041a\u0430\u043a\u043e\u0439 \u043f\u0435\u0440\u0438\u043e\u0434?", Claims: []toolClaim{{Text: "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b."}}}, false},
		{"clarification mixed with no data", toolAnswer{NoData: true, Clarification: "\u041a\u0430\u043a\u043e\u0439 \u043f\u0435\u0440\u0438\u043e\u0434?"}, false},
		{"no data", toolAnswer{NoData: true}, true},
		{"no data mixed with facts", toolAnswer{NoData: true, Claims: []toolClaim{{Text: "\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b."}}}, false},
		{"no answer", toolAnswer{}, false},
		{"address without copied quote", toolAnswer{Claims: []toolClaim{{Text: "\u0424\u0430\u043a\u0442 \u0438\u0437 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430.", Citations: []toolCitation{{Address: "kv1:observed-address"}}}}}, true},
		{"quote without address", toolAnswer{Claims: []toolClaim{{Text: "\u0424\u0430\u043a\u0442 \u0438\u0437 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430.", Citations: []toolCitation{{Quote: "\u0424\u0430\u043a\u0442"}}}}}, false},
		{"fragment reference", toolAnswer{Claims: []toolClaim{{Text: "\u0424\u0430\u043a\u0442.", Citations: []toolCitation{{FragmentID: "fragment_1"}}}}}, true},
		{"two reference selectors", toolAnswer{Claims: []toolClaim{{Text: "\u0424\u0430\u043a\u0442.", Citations: []toolCitation{{FragmentID: "fragment_1", Address: "kv1:observed-address"}}}}}, false},
	} {
		t.Run(input.name, func(t *testing.T) {
			if validToolAnswer(input.answer) != input.valid {
				t.Fatal("incorrect response-kind validation")
			}
		})
	}
}

func TestFragmentReferenceRequiresUniqueObservedAddress(t *testing.T) {
	makeAddress := func(end int) string {
		value, err := (address.Address{Source: "source_1", Object: "fragment_1", Version: "version_1", SpanKind: address.SpanKindText, CharEnd: end}).WithSpanHash([]byte("abcd"))
		if err != nil {
			t.Fatal(err)
		}
		return value.String()
	}
	first, second := makeAddress(4), makeAddress(2)
	for _, example := range []struct {
		name, fragment string
		observed       map[string]bool
		want           string
	}{
		{"observed", "fragment_1", map[string]bool{first: true}, first},
		{"unseen", "fragment_other", map[string]bool{first: true}, ""},
		{"absent", "fragment_1", nil, ""},
		{"not observed", "fragment_1", map[string]bool{first: false}, ""},
		{"malformed", "fragment_1", map[string]bool{first + "x": true}, ""},
		{"multiple spans", "fragment_1", map[string]bool{first: true, second: true}, ""},
	} {
		t.Run(example.name, func(t *testing.T) {
			actual, ok := observedFragmentAddress(example.fragment, example.observed)
			if actual != example.want || ok != (example.want != "") {
				t.Fatalf("got %q/%v; wanted %q", actual, ok, example.want)
			}
		})
	}
}
