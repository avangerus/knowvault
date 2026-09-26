package question

// Card D-14 requirement 1: every answer the product composes itself --
// calculations, refusals, extractive answers, their explanations and labels --
// follows the language of the question. These tests drive each composing
// branch with a Russian question and with the same question in English, and
// assert the product's own text around data values, citations and statuses
// that must not change. Names of sources, fields and values taken from the
// data are allowed in either language; the product's service words are not.

import (
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
)

func assertAnswerPhrases(t *testing.T, answer string, want, forbid []string) {
	t.Helper()
	for _, phrase := range want {
		if !strings.Contains(answer, phrase) {
			t.Fatalf("answer %q is missing %q", answer, phrase)
		}
	}
	for _, phrase := range forbid {
		if strings.Contains(answer, phrase) {
			t.Fatalf("answer %q still carries foreign-language product text %q", answer, phrase)
		}
	}
}

// TestSnapshotAnswerFollowsQuestionLanguage covers the richest composed
// branch: one calculation with a period, an equality filter, a declared status
// condition and its row cards. The comparison is against the reducer's typed
// overdue fixture, so the value (1 distinct address), the status and the
// citation count stay exactly what they are today; only the product's own
// sentences and labels follow the question's language.
func TestSnapshotAnswerFollowsQuestionLanguage(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	citations := []Citation{{Number: 1}}
	for _, tc := range []struct {
		name         string
		question     string
		wantFunction string
		want         []string
		forbid       []string
	}{
		{
			name:         "russian question",
			question:     "Какие обращения граждан просрочены сегодня, status = OPEN?",
			wantFunction: "LIST",
			want: []string{
				"Ответ: ул. Ленина, д. 12 — всего 1.",
				"Расчёт выполнен детерминированно по полному текущему снимку структурного источника: строк в снимке — 13, подходящих под условие — 1.",
				"Период по колонке deadline_at: с 2026-09-08 по 2026-09-08 включительно, часовой пояс UTC.",
				"Отбор: status = open.",
				"Отбор: просрочено — колонка deadline_at раньше 2026-09-08.",
				"Статус учтён: закрытые статусы исключены.",
				"Карточки строк: [1]",
			},
			forbid: []string{
				"Answer:", "Calculated", "rows in snapshot", "matching the condition",
				"Period by column", "Selection:", "Status considered", "Status not considered", "Row cards",
			},
		},
		{
			name:         "english question",
			question:     "how many citizen requests are overdue today, status = OPEN?",
			wantFunction: "COUNT",
			want: []string{
				"Answer: 1.",
				"Calculated deterministically from the complete current structured-source snapshot: rows in snapshot — 13, matching the condition — 1.",
				"Period by column deadline_at: from 2026-09-08 through 2026-09-08 inclusive, tenant time zone UTC.",
				"Selection: status = open.",
				"Selection: overdue — column deadline_at before 2026-09-08.",
				"Status considered: closed statuses excluded.",
				"Row cards: [1]",
			},
			forbid: []string{
				"Ответ:", "всего", "Расчёт", "строк в снимке", "Период по колонке",
				"Отбор:", "Статус учтён", "Карточки строк",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := mustPlan(t, tc.question)
			if plan.Operation != planner.Aggregate || plan.Aggregate == nil {
				t.Fatalf("plan=%+v want an AGGREGATE plan", plan.Aggregate)
			}
			result, ok := reduceStructuredSnapshot(citizenRequestsOverdueSnapshot(now), plan, now, "UTC")
			if !ok {
				t.Fatalf("reducer declined the overdue reduction for %q", tc.question)
			}
			if result.function != tc.wantFunction {
				t.Fatalf("function=%s want %s", result.function, tc.wantFunction)
			}
			result.language = questionLanguage(tc.question)
			assertAnswerPhrases(t, renderSnapshotAnswer(result, citations), tc.want, tc.forbid)

			// The structured AnswerResult's own rule is product text too.
			rule := buildAnswerResult(result).Rule
			if result.language == questionLanguageRussian {
				if !strings.Contains(rule, "условие просрочки") || strings.Contains(rule, "overdue condition") {
					t.Fatalf("russian rule=%q", rule)
				}
			} else if !strings.Contains(rule, "overdue condition") || strings.Contains(rule, "условие просрочки") {
				t.Fatalf("english rule=%q", rule)
			}
		})
	}
}

// TestSnapshotAnswerNoMatchesFollowsQuestionLanguage covers the LIST branch
// whose match set is empty: the exact "(0)" fact is unchanged, and the whole
// refusal is written in the question's language.
func TestSnapshotAnswerNoMatchesFollowsQuestionLanguage(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	today := now.Format("2006-01-02")
	rows := []snapshotRow{{versionID: "ver_today", cells: []snapshotCell{
		{fragmentID: "frg_today_title", ordinal: 2, column: "vehicle", logicalType: "TEXT", title: true, value: "V-101"},
		{fragmentID: "frg_today_started", ordinal: 5, column: "started_at", logicalType: "TIMESTAMPTZ",
			value: today, calendarDate: snapshotDate(today)},
	}}}
	for _, tc := range []struct {
		name         string
		question     string
		planQuestion string
		want         []string
		forbid       []string
	}{
		{
			name:         "russian question",
			question:     "Какие машины были в рейсе вчера?",
			planQuestion: "Какие машины были в рейсе вчера?",
			want: []string{
				"Ответ: подходящих записей в снимке нет (0).",
				"строк в снимке — 1, подходящих под условие — 0.",
				"Период по колонке started_at: с 2026-09-07 по 2026-09-07 включительно, часовой пояс UTC.",
			},
			forbid: []string{"Answer:", "no matching records", "rows in snapshot", "Period by column"},
		},
		{
			name:         "english question",
			question:     "which vehicles were on a trip yesterday?",
			planQuestion: "Какие машины были в рейсе вчера?",
			want: []string{
				"Answer: no matching records in the snapshot (0).",
				"rows in snapshot — 1, matching the condition — 0.",
				"Period by column started_at: from 2026-09-07 through 2026-09-07 inclusive, tenant time zone UTC.",
			},
			forbid: []string{"Ответ:", "подходящих записей", "строк в снимке", "Период по колонке"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := mustPlan(t, tc.planQuestion)
			if plan.Operation != planner.Aggregate || plan.Aggregate == nil || plan.Aggregate.Function != "LIST" {
				t.Fatalf("plan=%+v want AGGREGATE/LIST", plan.Aggregate)
			}
			result, ok := reduceStructuredSnapshot(rows, plan, now, "UTC")
			if !ok {
				t.Fatalf("reducer declined the empty enumeration for %q", tc.question)
			}
			if len(result.values) != 0 {
				t.Fatalf("values=%v want none", result.values)
			}
			result.language = questionLanguage(tc.question)
			assertAnswerPhrases(t, renderSnapshotAnswer(result, nil), tc.want, tc.forbid)
		})
	}
}

// TestAmbiguousStructuredSourceRefusalFollowsQuestionLanguage covers the
// named clarifying refusal for a question more than one enabled structured
// source could resolve. Source names are workspace data and stay as written.
func TestAmbiguousStructuredSourceRefusalFollowsQuestionLanguage(t *testing.T) {
	names := []string{"Рейсы мусоровозов", "Обращения граждан"}
	russian := ambiguousStructuredSourceAnswer(questionLanguage("Сколько машин сегодня в рейсе?"), names)
	assertAnswerPhrases(t, russian, []string{
		"Вопрос не указывает однозначно на один из включённых структурных источников: «Рейсы мусоровозов», «Обращения граждан».",
		"Добавьте слово, характерное для одного источника",
	}, []string{"The question does not uniquely identify", "Add a term specific"})
	english := ambiguousStructuredSourceAnswer(questionLanguage("how many vehicles are on a trip today?"), names)
	assertAnswerPhrases(t, english, []string{
		"The question does not uniquely identify one of the enabled structured sources: «Рейсы мусоровозов», «Обращения граждан».",
		"Add a term specific to one source",
	}, []string{"Вопрос не указывает", "Добавьте слово"})
}

// TestInsufficientEvidenceAnswerFollowsQuestionLanguage covers the stable
// refusal for a run with no citation to stand on.
func TestInsufficientEvidenceAnswerFollowsQuestionLanguage(t *testing.T) {
	if got := insufficientEvidenceAnswer(questionLanguage("Сколько отходов вывезено сегодня?")); got != "Недостаточно доказательств в подключённых источниках." {
		t.Fatalf("russian refusal=%q", got)
	}
	if got := insufficientEvidenceAnswer(questionLanguage("how much waste was hauled today?")); got != "Insufficient evidence in the connected sources." {
		t.Fatalf("english refusal=%q", got)
	}
}

// TestAggregateCalculationFollowsQuestionLanguage covers the ungrouped
// analytic total: the value and the citation count are unchanged, only the
// label around them follows the question.
func TestAggregateCalculationFollowsQuestionLanguage(t *testing.T) {
	selected := []candidate{
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", "row_a", "tonnes = 12.345"),
		testAggregateCandidate("fragment_01ARZ3NDEKTSV4RRFFQ69G5FAW", "row_b", "tonnes = 7.125"),
	}
	for _, tc := range []struct {
		question string
		want     string
		forbid   string
	}{
		{"сколько отходов вывезено?", "Итого: 19.470", "Total:"},
		{"how much waste was hauled?", "Total: 19.470", "Итого:"},
	} {
		answer, citations := renderAnswer("ws_demo", tc.question, selected)
		if answer != tc.want || len(citations) != 2 {
			t.Fatalf("question=%q answer=%q citations=%d", tc.question, answer, len(citations))
		}
		if strings.Contains(answer, tc.forbid) {
			t.Fatalf("question=%q answer=%q carries %q", tc.question, answer, tc.forbid)
		}
	}
}

// TestExtractiveAnswerCarriesNoProductText proves the extractive foundation
// adds no service sentence of its own: the answer is the source's own sentence
// plus the citation marker, whatever language the question and the data are in.
func TestExtractiveAnswerCarriesNoProductText(t *testing.T) {
	for _, tc := range []struct {
		name     string
		question string
		text     string
		want     string
	}{
		{"russian question and data", "что вывезено сегодня", "Сегодня вывезено 42 тонны отходов.", "Сегодня вывезено 42 тонны отходов [1]"},
		{"english question and data", "what was hauled today", "Today 42 tonnes of waste were hauled.", "Today 42 tonnes of waste were hauled [1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			planned, err := planner.Default().Plan(tc.question)
			if err != nil {
				t.Fatal(err)
			}
			if planned.Status != planner.Ready || planned.Operation != planner.Lookup {
				t.Fatalf("plan=%+v want a ready LOOKUP plan", planned)
			}
			selected := []candidate{{
				ID: "fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV", SourceObjectID: "object_01ARZ3NDEKTSV4RRFFQ69G5FAV",
				SourceVersionID: "version_01ARZ3NDEKTSV4RRFFQ69G5FAV", ExtractionID: "extraction_01ARZ3NDEKTSV4RRFFQ69G5FAV",
				Text: []byte(tc.text), Anchor: []byte(`{"kind":"TEXT","line_start":1,"line_end":1}`),
				ContentHash: testContentHash, TextHash: testTextHash, AnchorHash: testAnchorHash,
			}}
			answer, citations, _ := renderAnswerPlanAtWithReceipt("ws_demo", tc.question, planned, selected, time.Unix(1, 0).UTC())
			if answer != tc.want || len(citations) != 1 {
				t.Fatalf("question=%q answer=%q citations=%d", tc.question, answer, len(citations))
			}
		})
	}
}
