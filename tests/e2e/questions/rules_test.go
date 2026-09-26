package questions

import (
	"strings"
	"testing"
)

func testSet(t *testing.T) *Set {
	t.Helper()
	set, err := LoadSet("questions.json")
	if err != nil {
		t.Fatalf("load question set: %v", err)
	}
	return set
}

func testQuestion(t *testing.T, set *Set, id string) Question {
	t.Helper()
	question, ok := set.Question(id)
	if !ok {
		t.Fatalf("question %s is not in the set", id)
	}
	return question
}

func passingObservation(set *Set, answer string) Observation {
	return Observation{
		QuestionID:      "Q1",
		QuestionText:    "что ты знаешь?",
		QuestionLang:    "ru",
		Answer:          answer,
		Status:          "COMPLETED",
		StopReason:      "ANSWER",
		GroundingStatus: "CONFIRMED_BY_FRAGMENT",
		StatusFieldName: "status",
	}
}

func ruleByID(verdicts []RuleVerdict, id string) (RuleVerdict, bool) {
	for _, verdict := range verdicts {
		if verdict.ID == id {
			return verdict, true
		}
	}
	return RuleVerdict{}, false
}

// TestOwnerFailedAnswerFails pins the owner's real failed answer to «что ты
// знаешь?»: the answer text carries the profile-limits sentence and the run
// stopped at its turn budget, so the hard rules must reject it.
func TestOwnerFailedAnswerFails(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q1")
	observation := passingObservation(set, "The answer could not be completed within the configured profile limits. Refine the question or try again.")
	observation.StopReason = "TURN_LIMIT"
	observation.Status = "INSUFFICIENT_EVIDENCE"
	observation.QuestionLang = "ru"

	verdicts := Evaluate(set, question, observation)
	if verdict, ok := ruleByID(verdicts, "no_profile_limits"); !ok || verdict.Passed {
		t.Fatalf("no_profile_limits = %#v, want FAIL", verdict)
	}
	if verdict, ok := ruleByID(verdicts, "verification_not_failed"); !ok || verdict.Passed {
		t.Fatalf("verification_not_failed = %#v, want FAIL", verdict)
	}
	if verdict, ok := ruleByID(verdicts, "language"); !ok || verdict.Passed {
		t.Fatalf("language = %#v, want FAIL for an English answer to a Russian question", verdict)
	}
	for _, verdict := range verdicts {
		if verdict.Passed {
			continue
		}
		return
	}
	t.Fatal("the owner's failed answer passed every rule")
}

// TestLabelEvidenceAndIDAnswerFails covers the label, evidence-number and
// internal-id rules on one canned answer.
func TestLabelEvidenceAndIDAnswerFails(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q1")
	answer := "Уточнение: вопрос непонятен. Evidence 1: quote verified. conn_6F8C ссылается на источник."
	observation := passingObservation(set, answer)

	verdicts := Evaluate(set, question, observation)
	for _, id := range []string{"no_label_prefix", "no_evidence_number", "no_verification_prose", "no_internal_markers"} {
		verdict, ok := ruleByID(verdicts, id)
		if !ok || verdict.Passed {
			t.Fatalf("%s = %#v, want FAIL", id, verdict)
		}
	}
}

// TestRenamedLabelStillFails proves the label rule is not keyed to one word:
// a different label followed by a colon is still a label line.
func TestRenamedLabelStillFails(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q1")
	observation := passingObservation(set, "Пояснение: в рабочей области есть два источника.")
	verdicts := Evaluate(set, question, observation)
	if verdict, ok := ruleByID(verdicts, "no_label_prefix"); !ok || verdict.Passed {
		t.Fatalf("no_label_prefix = %#v, want FAIL", verdict)
	}
}

// TestShortCorrectAnswerPasses proves the canned correct answer clears every
// hard rule and the Q1 checks.
func TestShortCorrectAnswerPasses(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q1")
	answer := "В рабочей области есть источники «Регламенты и договоры» и «Договоры», а также краткий глоссарий и регламент вывоза отходов."
	observation := passingObservation(set, answer)
	observation.ToolCalls = []ToolCall{{Name: "knowvault_sources", Arguments: `{"limit":10}`, MainArgument: "10"}}

	verdicts := Evaluate(set, question, observation)
	for _, verdict := range verdicts {
		if !verdict.Passed {
			t.Fatalf("rule %s failed on a short correct answer: %s", verdict.ID, verdict.Detail)
		}
	}
}

// TestDuplicateToolCallsFail: the same tool with the same arguments twice is a
// hard failure, and the same tool on the same source more than twice too.
func TestDuplicateToolCallsFail(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q4")
	observation := passingObservation(set, "Пять МНО на действующих договорах.")
	observation.QuestionID = "Q4"
	observation.ToolCalls = []ToolCall{
		{Name: "knowvault_source_sql", Arguments: `{"source_id":"conn_x","sql":"SELECT 1"}`, MainArgument: "conn_x"},
		{Name: "knowvault_source_sql", Arguments: `{"sql":"SELECT 1", "source_id":"conn_x"}`, MainArgument: "conn_x"},
		{Name: "knowvault_source_sql", Arguments: `{"source_id":"conn_x","sql":"SELECT 2"}`, MainArgument: "conn_x"},
	}
	verdicts := Evaluate(set, question, observation)
	if verdict, ok := ruleByID(verdicts, "no_duplicate_tool_calls"); !ok || verdict.Passed {
		t.Fatalf("no_duplicate_tool_calls = %#v, want FAIL", verdict)
	}
	if verdict, ok := ruleByID(verdicts, "same_tool_same_source_max_two"); !ok || verdict.Passed {
		t.Fatalf("same_tool_same_source_max_two = %#v, want FAIL", verdict)
	}
}

// TestStepsRule: the research-call count is judged against the question's own
// limit.
func TestStepsRule(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "H1")
	observation := passingObservation(set, "В рабочей области нет данных о погоде.")
	observation.QuestionID = "H1"
	observation.ToolCalls = []ToolCall{
		{Name: "knowvault_search", Arguments: `{"query":"погода"}`, MainArgument: "погода"},
		{Name: "knowvault_read", Arguments: `{"address":"kv1:x"}`, MainArgument: "kv1:x"},
	}
	verdicts := Evaluate(set, question, observation)
	if verdict, ok := ruleByID(verdicts, "steps_within_limit"); !ok || verdict.Passed {
		t.Fatalf("steps_within_limit = %#v, want FAIL", verdict)
	}
}

// TestAggregationHardVersusValue: a hard rule needs three of three runs, a
// value rule needs two of three.
func TestAggregationHardVersusValue(t *testing.T) {
	set := testSet(t)
	runs := []RunReport{
		{QuestionID: "Q3", Run: 1, Verdicts: []RuleVerdict{{ID: "hard_rule", Hard: true, Group: "hard", Passed: false}, {ID: "value_rule", Hard: false, Group: "value", Passed: true}}},
		{QuestionID: "Q3", Run: 2, Verdicts: []RuleVerdict{{ID: "hard_rule", Hard: true, Group: "hard", Passed: true}, {ID: "value_rule", Hard: false, Group: "value", Passed: true}}},
		{QuestionID: "Q3", Run: 3, Verdicts: []RuleVerdict{{ID: "hard_rule", Hard: true, Group: "hard", Passed: true}, {ID: "value_rule", Hard: false, Group: "value", Passed: false}}},
	}
	verdicts := Judge(set, runs)
	if len(verdicts) != 1 || verdicts[0].QuestionID != "Q3" {
		t.Fatalf("verdicts = %#v", verdicts)
	}
	if verdicts[0].Passed {
		t.Fatalf("question passed with a hard 2-of-3 rule: %#v", verdicts[0])
	}
	for _, rule := range verdicts[0].Rules {
		switch rule.ID {
		case "hard_rule":
			if rule.Required != 3 || rule.Passes != 2 || rule.Passed {
				t.Fatalf("hard aggregate = %#v, want 2 of 3 and FAIL", rule)
			}
		case "value_rule":
			if rule.Required != 2 || rule.Passes != 2 || !rule.Passed {
				t.Fatalf("value aggregate = %#v, want 2 of 2 and PASS", rule)
			}
		}
	}
}

// TestValueAndTimeChecks reads the question's own numeric and time
// expectations.
func TestValueAndTimeChecks(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q3")
	observation := passingObservation(set, "Действует 3 договора.")
	observation.QuestionID = "Q3"
	observation.Seconds = 12
	verdicts := Evaluate(set, question, observation)
	value, ok := ruleByID(verdicts, "q3_value")
	if !ok || !value.Passed {
		t.Fatalf("q3_value = %#v, want PASS on the seeded A", value)
	}
	time, ok := ruleByID(verdicts, "q3_time")
	if !ok || !time.Passed {
		t.Fatalf("q3_time = %#v, want PASS within 40 s", time)
	}

	wrong := passingObservation(set, "Действует 5 договоров.")
	wrong.QuestionID = "Q3"
	wrong.Seconds = 55
	wrongVerdicts := Evaluate(set, question, wrong)
	if verdict, ok := ruleByID(wrongVerdicts, "q3_value"); !ok || verdict.Passed {
		t.Fatalf("q3_value = %#v, want FAIL on the wrong number", verdict)
	}
	if verdict, ok := ruleByID(wrongVerdicts, "q3_time"); !ok || verdict.Passed {
		t.Fatalf("q3_time = %#v, want FAIL over the limit", verdict)
	}
}

// TestO1Shape: either the seeded number or exactly one question mark inside
// the short bound.
func TestO1Shape(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "O1")
	number := passingObservation(set, "На действующих договорах 5 МНО.")
	number.QuestionID = "O1"
	if verdict, ok := ruleByID(Evaluate(set, question, number), "o1_shape"); !ok || !verdict.Passed {
		t.Fatalf("o1_shape number form = %#v, want PASS", verdict)
	}
	shortQuestion := passingObservation(set, "Уточните: вас интересуют все МНО или только действующие?")
	shortQuestion.QuestionID = "O1"
	if verdict, ok := ruleByID(Evaluate(set, question, shortQuestion), "o1_shape"); !ok || !verdict.Passed {
		t.Fatalf("o1_shape one-question-mark form = %#v, want PASS", verdict)
	}
	long := passingObservation(set, "Уточните? "+strings.Repeat("Данные. ", 80))
	long.QuestionID = "O1"
	if verdict, ok := ruleByID(Evaluate(set, question, long), "o1_shape"); !ok || verdict.Passed {
		t.Fatalf("o1_shape long form = %#v, want FAIL", verdict)
	}
}

// h5Observation is one canned H5 run: a completed Russian answer with no tool
// calls, so the H5 checks see only the answer text.
func h5Observation(answer string) Observation {
	return Observation{
		QuestionID: "H5", QuestionText: "Сколько заявок в базе «Заявки»?", QuestionLang: "ru",
		Answer: answer, Status: "COMPLETED", StopReason: "ANSWER",
		GroundingStatus: "CONFIRMED_BY_FRAGMENT", StatusFieldName: "status",
	}
}

// TestH5CompliantAnswerPassesAndFailureModesFail pins result 1 of card E-2: a
// short answer that names the database and speaks of confirming its tables is
// green, and each rule-decidable failure mode makes H5 red: a SQL call, a third
// sentence, an answer that does not name the database, one silent about
// confirming its tables, and an empty result.
func TestH5CompliantAnswerPassesAndFailureModesFail(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "H5")

	compliant := h5Observation("База «Заявки» пока не читается, потому что её таблицы ещё не подтверждены. Подтвердите её таблицы, и база станет доступна для чтения.")
	for _, verdict := range Evaluate(set, question, compliant) {
		if !verdict.Passed {
			t.Fatalf("H5 rejected a compliant answer at rule %s: %s", verdict.ID, verdict.Detail)
		}
	}

	afterSQL := h5Observation(compliant.Answer)
	afterSQL.ToolCalls = []ToolCall{{
		Name: "knowvault_source_sql", Arguments: `{"source_id":"conn_x","sql":"SELECT count(*) FROM public.request"}`,
		MainArgument: "conn_x",
	}}
	if verdict, ok := ruleByID(Evaluate(set, question, afterSQL), "h5_no_sql"); !ok || verdict.Passed {
		t.Fatalf("h5_no_sql = %#v, want FAIL after a SQL call", verdict)
	}

	threeSentences := h5Observation("База «Заявки» пока не читается. Её таблицы ещё не подтверждены. Подтвердите таблицы, и база станет доступна.")
	if verdict, ok := ruleByID(Evaluate(set, question, threeSentences), "h5_sentences"); !ok || verdict.Passed {
		t.Fatalf("h5_sentences = %#v, want FAIL for three sentences", verdict)
	}

	// An answer that never names the database, however well it words the rest.
	unnamed := h5Observation("Данные пока нельзя загрузить, её таблицы ждут подтверждения. Подтвердите таблицы.")
	if verdict, ok := ruleByID(Evaluate(set, question, unnamed), "h5_database"); !ok || verdict.Passed {
		t.Fatalf("h5_database = %#v, want FAIL without the database name", verdict)
	}

	// An answer that names the database and the trouble but never speaks of
	// confirming its tables.
	silent := h5Observation("База «Заявки» пока не читается: к данным нет доступа.")
	if verdict, ok := ruleByID(Evaluate(set, question, silent), "h5_confirm_tables"); !ok || verdict.Passed {
		t.Fatalf("h5_confirm_tables = %#v, want FAIL when the answer is silent about confirming the tables", verdict)
	}

	// A zero count and an explicit no-records sentence both present an empty
	// result and are rejected by the rule that exists for exactly that.
	for _, answer := range []string{
		"База «Заявки» пока не читается, в ней 0 заявок. Подтвердите её таблицы.",
		"База «Заявки» пока не читается, записей нет. Подтвердите её таблицы.",
		"no records in the database",
	} {
		if verdict, ok := ruleByID(Evaluate(set, question, h5Observation(answer)), "h5_no_empty_result"); !ok || verdict.Passed {
			t.Fatalf("h5_no_empty_result = %#v, want FAIL for %q", verdict, answer)
		}
	}
}

// TestH5AcceptsAnyCorrectWording pins the revised result 1 of card E-2: the
// automatic checks decide only what a rule can decide, so a correct answer
// passes them however it words or orders the two statements — the database
// cannot be read yet, and confirming its tables makes it readable. The meaning
// itself is judged by acceptance against the question's value note, not by a
// rule, so a wording the check cannot enumerate is never red for wording alone.
func TestH5AcceptsAnyCorrectWording(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "H5")

	correct := []string{
		"База «Заявки» пока не читается, потому что её таблицы ещё не подтверждены. Подтвердите её таблицы, и база станет доступна для чтения.",
		"База «Заявки» недоступна для чтения. Чтобы её прочитать, подтвердите таблицы.",
		"Сейчас базу «Заявки» прочитать нельзя, её таблицы ждут подтверждения. Как только таблицы подтвердят, база станет доступна.",
		"Прочитать её пока нельзя. Нужно подтвердить таблицы базы «Заявки».",
		"База «Заявки» не открывается: таблицы не подтверждены. Подтверждение таблиц сделает её читаемой.",
		"Доступ к базе «Заявки» закрыт. Дождитесь подтверждения её таблиц.",
		"Чтение базы «Заявки» пока невозможно. Таблицы нужно подтвердить.",
		"Нет доступа к базе «Заявки»; чтобы читать её, подтвердите её таблицы.",
		"База «Заявки» ещё не готова к чтению: её таблицы не подтверждены. Как только таблицы подтвердят, она откроется.",
		// The wording RETURN-2 reported as wrongly red: the data cannot be
		// loaded yet because the tables await confirmation.
		"Данные базы «Заявки» пока нельзя загрузить, потому что её таблицы ждут подтверждения. Подтвердите таблицы, чтобы получить данные.",
		"Данные из базы «Заявки» не выгружаются, пока её таблицы не подтверждены. Подтвердите таблицы.",
		"База «Заявки» ждёт подтверждения таблиц. Её данные пока не загружены.",
	}
	for _, answer := range correct {
		for _, verdict := range Evaluate(set, question, h5Observation(answer)) {
			if !verdict.Passed {
				t.Fatalf("H5 rejected a correct answer %q at rule %s: %s", answer, verdict.ID, verdict.Detail)
			}
		}
	}
}

// TestH5CarriesTheValueNote pins result 1 of card E-2: what the answer must
// mean — the database cannot be read yet, and confirming its tables makes it
// readable — is the question's value note, which acceptance judges by reading
// the answers.
func TestH5CarriesTheValueNote(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "H5")
	if strings.TrimSpace(question.ValueNote) == "" {
		t.Fatal("H5 carries no value note")
	}
	note := strings.ToLower(question.ValueNote)
	for _, want := range []string{"cannot be read", "confirm", "table", "заявки"} {
		if !strings.Contains(note, want) {
			t.Fatalf("H5 value note does not state %q: %q", want, question.ValueNote)
		}
	}
}

// TestReportShowsH5DatabaseAwaitingConfirmation: the report states, per H5 run,
// what the harness read from the product just before asking.
func TestReportShowsH5DatabaseAwaitingConfirmation(t *testing.T) {
	markdown := RenderMarkdown(Report{Title: "h5 report", Runs: []RunReport{{
		QuestionID: "H5", QuestionText: "Сколько заявок в базе «Заявки»?", Run: 1,
		Answer: "…", DatabaseName: "Заявки", DatabaseAwaitingConfirmation: true,
	}}})
	if !strings.Contains(markdown, "«Заявки» — tables awaiting confirmation") {
		t.Fatalf("report does not show the H5 database awaiting confirmation:\n%s", markdown)
	}
}

// TestCitationDocument: the answer needs a citation whose stored fragment text
// mentions the contract number.
func TestCitationDocument(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q5")
	observation := passingObservation(set, "Договор 47 заключён с ООО «Северный Ветер» 12.03.2025; стоимость 1 250 000 рублей.")
	observation.QuestionID = "Q5"
	observation.Citations = []Citation{{Address: "kv1:x", Excerpt: "Договор № 47", Text: "Договор № 47.\n\nЗаказчик: ООО «Северный Ветер»."}}
	verdicts := Evaluate(set, question, observation)
	if verdict, ok := ruleByID(verdicts, "q5_document"); !ok || !verdict.Passed {
		t.Fatalf("q5_document = %#v, want PASS", verdict)
	}
	if verdict, ok := ruleByID(verdicts, "q5_values"); !ok || !verdict.Passed {
		t.Fatalf("q5_values = %#v, want PASS", verdict)
	}
}

// mcpQ7Observation is the canned Q7 (MCP) run the card's parity rule judges:
// a live-table count answer with the product's own record of the run and the
// peer (Q3) answer of the same run.
func mcpQ7Observation(answer, peerAnswer string) Observation {
	live := func() (string, string) { return "LIVE_TABLE", "sha256:" + strings.Repeat("a", 64) }
	ownKind, ownReceipt := live()
	peerKind, peerReceipt := live()
	return Observation{
		QuestionID: "Q7", QuestionText: "Сколько договоров действует?", QuestionLang: "ru",
		Answer: answer, Status: "COMPLETED", StopReason: "ANSWER", GroundingStatus: "CONFIRMED_BY_FRAGMENT",
		LiveResultKind: ownKind, LiveResultReceipt: ownReceipt, LiveResultSourceID: "conn_contract",
		ViaMCP: true, MCPRecorded: true, StatusFieldName: "status",
		Peer: &PeerObservation{
			QuestionID: "Q3", Answer: peerAnswer,
			LiveResultKind: peerKind, LiveResultReceipt: peerReceipt, LiveResultSourceID: "conn_contract",
		},
	}
}

// TestQ7NumberEqualsQ3InSameRun is card D-19 result 2: a stubbed MCP answer
// carrying Q3's number is green, an answer carrying a different number is red.
func TestQ7NumberEqualsQ3InSameRun(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q7")

	equal := mcpQ7Observation("По данным источника договоров действующих 3. [Результат 1]", "Действующих договоров 3. [Результат 1]")
	verdicts := Evaluate(set, question, equal)
	for _, verdict := range verdicts {
		if !verdict.Passed {
			t.Fatalf("equal-number MCP answer failed %s: %s", verdict.ID, verdict.Detail)
		}
	}

	different := mcpQ7Observation("По данным источника договоров действующих 5. [Результат 1]", "Действующих договоров 3. [Результат 1]")
	verdicts = Evaluate(set, question, different)
	number, ok := ruleByID(verdicts, "q7_number")
	if !ok || number.Passed {
		t.Fatalf("q7_number = %#v, want FAIL when the MCP number differs from Q3's in the same run", number)
	}
	if !strings.Contains(number.Detail, "Q7=5") || !strings.Contains(number.Detail, "Q3=3") {
		t.Fatalf("q7_number detail = %q, want both numbers", number.Detail)
	}
	for _, verdict := range verdicts {
		if verdict.ID == "q7_number" {
			continue
		}
		if !verdict.Passed && verdict.Hard {
			t.Fatalf("only q7_number should differ, hard rule %s failed: %s", verdict.ID, verdict.Detail)
		}
	}
}

// TestQ7SourceMustMatchQ3 is card D-19 result 1: the MCP answer must cite the
// same live source as Q3 in the same run.
func TestQ7SourceMustMatchQ3(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q7")

	other := mcpQ7Observation("Действующих договоров 3. [Результат 1]", "Действующих договоров 3. [Результат 1]")
	other.Peer.LiveResultSourceID = "conn_other"
	if verdict, ok := ruleByID(Evaluate(set, question, other), "q7_source"); !ok || verdict.Passed {
		t.Fatalf("q7_source = %#v, want FAIL when the live source differs from Q3's", verdict)
	}

	missing := mcpQ7Observation("Действующих договоров 3. [Результат 1]", "Действующих договоров 3. [Результат 1]")
	missing.LiveResultSourceID = ""
	if verdict, ok := ruleByID(Evaluate(set, question, missing), "q7_source"); !ok || verdict.Passed {
		t.Fatalf("q7_source = %#v, want FAIL with no live source", verdict)
	}
}

// TestQ7TransportMustBeRecorded: a run without the product's own MCP record is
// not a question asked through MCP, so the hard rule must reject it.
func TestQ7TransportMustBeRecorded(t *testing.T) {
	set := testSet(t)
	question := testQuestion(t, set, "Q7")
	observation := mcpQ7Observation("Действующих договоров 3. [Результат 1]", "Действующих договоров 3. [Результат 1]")
	observation.MCPRecorded = false
	if verdict, ok := ruleByID(Evaluate(set, question, observation), "q7_mcp"); !ok || verdict.Passed {
		t.Fatalf("q7_mcp = %#v, want FAIL without the product's MCP record", verdict)
	}
}

// TestSignificantNumberDropsCitationMarkers: the reference number inside
// "[Результат 1]" is not the answer's own number.
func TestSignificantNumberDropsCitationMarkers(t *testing.T) {
	for _, testCase := range []struct {
		answer string
		want   int
		ok     bool
	}{
		{"Действующих договоров 3. [Результат 1]", 3, true},
		{"[Результат 1] Действующих договоров 5.", 5, true},
		{"Данных нет. [1]", 0, false},
	} {
		got, ok := SignificantNumber(testCase.answer)
		if ok != testCase.ok || got != testCase.want {
			t.Fatalf("SignificantNumber(%q) = %d/%t, want %d/%t", testCase.answer, got, ok, testCase.want, testCase.ok)
		}
	}
}

// TestReportShowsMCPParity pins the cross-transport evidence the card's report
// needs: the question, the run, green/red, the number and the source.
func TestReportShowsMCPParity(t *testing.T) {
	number, peerNumber := 3, 3
	report := Report{
		Title: "mcp parity test",
		Runs: []RunReport{{
			QuestionID: "Q7", Run: 1, Via: "mcp", MCPRequestID: "req_mcp_1", MCPRecorded: true,
			Answer: "Действующих договоров 3. [Результат 1]", Number: &number,
			PeerQuestionID: "Q3", PeerNumber: &peerNumber,
			LiveResultSourceID: "conn_contract", PeerLiveResultSourceID: "conn_contract",
		}},
	}
	markdown := RenderMarkdown(report)
	for _, want := range []string{
		"## MCP parity (card D-19)",
		"| Q7 | 1 | 3 | Q3 | 3 | conn_contract | conn_contract | yes (`req_mcp_1`) |",
		"- Via: `mcp`; MCP request id `req_mcp_1`",
		"- Number: 3; peer Q3 number: 3;",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("report does not contain %q:\n%s", want, markdown)
		}
	}
}
