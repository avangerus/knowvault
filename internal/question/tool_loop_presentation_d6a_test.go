package question

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// presentationVocabRecord is one run's own evidence for the technical names it
// saw: a glossary term whose location names a relation and a column, and the
// SQL statement the model wrote. No question-set data is involved.
func presentationVocabRecord() *ToolLoopRecord {
	return &ToolLoopRecord{
		WorkspaceContext: &ToolLoopWorkspaceContext{Terms: []ToolLoopWorkspaceContextTerm{{
			TermID: "term_mno", Term: "МНО",
			Locations: []ToolLoopWorkspaceContextLocation{{
				SourceConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
				Relation:           "public.container_group",
				Column:             "code",
			}},
		}}},
		Calls: []ToolCallRecord{{
			Name: sourceSQLToolName, Outcome: "SUCCEEDED",
			Arguments: json.RawMessage(`{"source_id":"conn_01H9ABCDEFGHJKMNPQRSTVWXYZ","sql":"SELECT count(*) AS active_contracts FROM public.contract WHERE status = 'active'"}`),
			Result:    workspacetools.Result{Structured: json.RawMessage(`{"row_count":1}`)},
		}, {
			Name: "knowvault_source_schema", Outcome: "SUCCEEDED",
			Result: workspacetools.Result{Structured: json.RawMessage(`{"tables":[{"name":"contract","columns":[{"name":"id"},{"name":"number"},{"name":"client_id"},{"name":"status"},{"name":"signed_on"},{"name":"amount"}]}]}`)},
		}},
	}
}

func TestToolLoopPresentationVocabularyComesFromTheRun(t *testing.T) {
	names := toolLoopTechnicalVocabulary(presentationVocabRecord())
	for _, want := range []string{"container_group", "code", "contract", "status", "id", "client_id", "signed_on", "amount"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("technical vocabulary misses %q: %v", want, names)
		}
	}
	// A quoted business value and SQL keywords are not technical names.
	for _, unwanted := range []string{"active", "select", "count", "public", "from", "where"} {
		if _, ok := names[unwanted]; ok {
			t.Fatalf("technical vocabulary wrongly contains %q", unwanted)
		}
	}
}

func TestToolLoopAnswerSelfLabelAndInternalMarkers(t *testing.T) {
	for _, text := range []string{
		"Ответ: в рабочей области пять МНО.",
		"Уточнение: данных недостаточно.",
		"Ограничение охвата: прочитан один документ.",
		"Answer: there are five container sites.",
		"Scope: only one document was read.",
	} {
		if label := toolLoopAnswerSelfLabel(text); label == "" {
			t.Fatalf("self-label not found in %q", text)
		}
	}
	for _, text := range []string{
		"В рабочей области есть договор № 47.",
		"Вывоз выполняется не позднее 24 часов с момента заполнения контейнера.",
	} {
		if label := toolLoopAnswerSelfLabel(text); label != "" {
			t.Fatalf("ordinary prose was mistaken for a self-label: %q in %q", label, text)
		}
	}
	for _, text := range []string{
		"Источник conn_01H9ABCDEFGHJKMNPQRSTVWXYZ содержит пять записей.",
		"Прочитан файл projects/alpha/waste-removal-regulation.txt.",
		"Прочитан файл waste-removal-regulation.txt и глоссарий glossary.txt.",
		"Наблюдение сделано 2026-09-25T06:43:05Z.",
		"Эта метка paraphrase не для пользователя.",
	} {
		if marker := toolLoopAnswerPartMarker(text); marker == "" {
			t.Fatalf("internal marker not found in %q", text)
		}
	}
	if marker := toolLoopAnswerPartMarker("В рабочей области пять мест накопления отходов."); marker != "" {
		t.Fatalf("clean answer matched internal marker %q", marker)
	}
	// A clarification that asks the user a question is not a self-label.
	if label := toolLoopAnswerSelfLabel("Сколько чего нужно узнать: массу отходов или число рейсов?"); label != "" {
		t.Fatalf("a clarifying question was mistaken for a self-label: %q", label)
	}
	if issue := toolLoopAnswerPresentationIssue("Сколько чего нужно узнать: массу отходов или число рейсов?", nil); issue != "" {
		t.Fatalf("a clarifying question was rejected with %q", issue)
	}
}

// TestToolLoopAnswerPresentationRejectsRawNames is card D-6a's unit proof that
// an answer carrying a self-label or a raw relation/column name is not
// presented as-is, while ordinary business prose is kept.
func TestToolLoopAnswerPresentationRejectsRawNames(t *testing.T) {
	record := presentationVocabRecord()
	pattern := toolLoopTechnicalNamePattern(toolLoopTechnicalVocabulary(record))
	for _, text := range []string{
		"Данные хранятся в поле code таблицы container_group.",
		"Пять записей лежат в таблице container_group.",
		"The count comes from the contract table.",
		"Its status field equals active.",
		"Ответ: в рабочей области пять МНО.",
	} {
		if issue := toolLoopAnswerPresentationIssue(text, pattern); issue == "" {
			t.Fatalf("presentation issue not found in %q", text)
		}
	}
	for _, text := range []string{
		"В рабочей области пять мест накопления отходов.",
		"Действующих договоров три.",
		"There are 3 active contracts.",
		"There are 42 registered contracts.",
		"Договор № 47 действует с 12.03.2025.",
		"Стоимость услуг 1 250 000 рублей в год.",
	} {
		if issue := toolLoopAnswerPresentationIssue(text, pattern); issue != "" {
			t.Fatalf("clean answer %q matched %q", text, issue)
		}
	}
	// A question about the data structure is not an exception: the raw relation
	// and column names are presentation there too, and the answer must use
	// business words. This is the acceptance remark of card D-6a.
	for _, text := range []string{
		"В базе про договоры есть таблица public.contract со столбцами id, number, client_id, status, signed_on и amount.",
		"В базе по договорам есть одна таблица contract с полями id, number, client_id, status, signed_on и amount.",
	} {
		if issue := toolLoopAnswerPresentationIssue(text, pattern); issue == "" {
			t.Fatalf("a schema answer was presented as-is: %q", text)
		}
	}
}

// TestToolLoopPresentAnswerKeepsTheGatheredAnswer is card D-6a's requirement 3
// at the unit level: the forced final turn's rejected answer still yields a
// shown answer with its content, not a stub.
func TestToolLoopPresentAnswerKeepsTheGatheredAnswer(t *testing.T) {
	record := presentationVocabRecord()
	answer := toolAnswer{Claims: []toolClaim{{
		Text:      "Ответ: в рабочей области пять МНО. Данные о них хранятся в поле code таблицы container_group. Файл projects/alpha/waste-removal-regulation.txt прочитан.",
		Citations: []toolCitation{{Address: "kv1:object#span"}},
	}}}
	presented, changed := toolLoopPresentAnswer(answer, toolLoopTechnicalVocabulary(record))
	if !changed {
		t.Fatal("a form-rejected answer was not cleaned")
	}
	if len(presented.Claims) != 1 {
		t.Fatalf("presented claims = %#v", presented.Claims)
	}
	text := presented.Claims[0].Text
	for _, forbidden := range []string{"Ответ:", "container_group", "code", "projects/alpha", "waste-removal-regulation"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("presented answer still carries %q: %q", forbidden, text)
		}
	}
	if !strings.Contains(text, "пять МНО") {
		t.Fatalf("presented answer lost the gathered content: %q", text)
	}
	if len(presented.Claims[0].Citations) != 1 || presented.Claims[0].Citations[0].Address != "kv1:object#span" {
		t.Fatalf("presented answer lost its citation binding: %#v", presented.Claims[0].Citations)
	}
}

// TestToolLoopPresentAnswerCleansSchemaQuestionNames is the acceptance remark
// of card D-6a at the unit level: a question about the data structure is not an
// exception, so a forced-final answer that names the relation and its columns
// is cleaned to business words instead of being shown as-is, and it is still an
// answer, not a stub.
func TestToolLoopPresentAnswerCleansSchemaQuestionNames(t *testing.T) {
	record := presentationVocabRecord()
	answer := toolAnswer{Claims: []toolClaim{{
		Text:      "Ответ: в базе по договорам есть таблица contract с полями id, number, client_id, status, signed_on и amount. Она хранит номер договора, его клиента, статус, дату подписания и сумму.",
		Citations: []toolCitation{{Address: "kv1:object#span"}},
	}}}
	presented, changed := toolLoopPresentAnswer(answer, toolLoopTechnicalVocabulary(record))
	if !changed {
		t.Fatal("a schema-question answer was presented as-is")
	}
	if len(presented.Claims) != 1 {
		t.Fatalf("presented claims = %#v", presented.Claims)
	}
	text := presented.Claims[0].Text
	rawName := regexp.MustCompile(`(?i)\b(?:contract|id|number|client_id|status|signed_on|amount)\b`)
	if match := rawName.FindString(text); match != "" {
		t.Fatalf("presented schema answer still carries the raw name %q: %q", match, text)
	}
	if label := toolLoopAnswerSelfLabel(text); label != "" {
		t.Fatalf("presented schema answer still carries the self-label %q: %q", label, text)
	}
	if !strings.Contains(text, "номер договора") || !strings.Contains(text, "дату подписания") || !strings.Contains(text, "сумму") {
		t.Fatalf("presented schema answer lost its business content: %q", text)
	}
	if len(presented.Claims[0].Citations) != 1 {
		t.Fatalf("presented schema answer lost its citation binding: %#v", presented.Claims[0].Citations)
	}
}

// TestToolLoopPresentedClaimsBindTheShownAnswer proves the read path rebuilds
// the displayed bytes from the presented claims, so the answer the user saw and
// the persisted evidence agree even after a form-rejected final answer was
// cleaned instead of dropped.
func TestToolLoopPresentedClaimsBindTheShownAnswer(t *testing.T) {
	claimText := "В рабочей области пять МНО."
	record := &ToolLoopRecord{
		ClaimEvidenceVersion: "v1",
		ClaimEvidence: []ToolClaimEvidence{{
			TextHash: canon.Hash([]byte(claimText)), CitationNumbers: []int64{1},
		}},
		PresentedClaims: []toolClaim{{Text: claimText, Citations: []toolCitation{{Address: "kv1:object#span"}}}},
	}
	raw := toolAnswer{Claims: []toolClaim{{
		Text:      "Ответ: в рабочей области пять МНО, см. code.",
		Citations: []toolCitation{{Address: "kv1:object#span"}},
	}}}
	if _, ok := finalToolAnswerFromRecord(record); !ok {
		t.Fatal("the presented claims did not parse")
	}
	parsed, _ := finalToolAnswerFromRecord(record)
	if len(parsed.Claims) != 1 || parsed.Claims[0].Text != claimText {
		t.Fatalf("final answer did not come from the presented claims: %#v", parsed)
	}
	markdown := claimText + " [1]"
	if !validateToolLoopClaimEvidence("qrun_current", markdown, record, nil, []Citation{{Number: 1}}) {
		t.Fatal("the displayed answer was not bound to the presented claims")
	}
	// The raw submission would not match: the cleaning is what made it
	// presentable, and the read path must not fall back to it.
	rawArguments, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var rawCall modelgateway.ToolCall
	rawCall.ID, rawCall.Type = "submit-raw", "function"
	rawCall.Function.Name = submitAnswerToolName
	rawCall.Function.Arguments = string(rawArguments)
	rawRecord := *record
	rawRecord.PresentedClaims = nil
	rawRecord.Messages = []modelgateway.Message{{Role: "assistant", ToolCalls: []modelgateway.ToolCall{rawCall}}}
	if validateToolLoopClaimEvidence("qrun_current", markdown, &rawRecord, nil, []Citation{{Number: 1}}) {
		t.Fatal("the raw submission was accepted after cleaning")
	}
}
