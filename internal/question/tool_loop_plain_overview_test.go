package question

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// Card D-16 result 2: the plain_overview route mounts only read-only knowledge
// tools. No tool that writes SQL or reads live data can be offered.
func TestPlainOverviewToolAllowlistExcludesDataTools(t *testing.T) {
	for _, name := range []string{
		"knowvault_search", "knowvault_read", "knowvault_evidence_read",
		"knowvault_list_objects", "knowvault_workspace_list", "knowvault_related",
		"knowvault_grep", "knowvault_sources", "knowvault_sources_list",
		"knowvault_workspace_context",
	} {
		if !plainOverviewToolAllowed(name) {
			t.Fatalf("knowledge tool %q is not mounted on the plain_overview route", name)
		}
	}
	for _, name := range []string{
		sourceSQLToolName, "knowvault_source_schema", liveDataToolName,
		trustedMetricToolName, analyticScalarToolName, submitAnswerToolName,
	} {
		if plainOverviewToolAllowed(name) {
			t.Fatalf("data tool %q is mounted on the plain_overview route", name)
		}
	}
}

// Card D-16 result 1: a plain_overview answer ends with a next question, so the
// server reads only the text after the last question mark.
func TestToolLoopAnswerHasNextQuestion(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{name: "question at the end", text: "Данные о договорах есть. Хотите узнать про договор № 47?", want: true},
		{name: "quoted closing", text: "Сведения о площадках есть. Показать адреса?", want: true},
		{name: "trailing period", text: "Сведения есть. Что именно показать?.", want: true},
		{name: "closing bracket", text: "Сведения есть (что уточнить?)", want: true},
		{name: "no question", text: "В рабочей области есть сведения о договорах.", want: false},
		{name: "question in the middle", text: "Что показать? Пока известны только договоры.", want: false},
		{name: "empty", text: "", want: false},
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			if got := toolLoopAnswerHasNextQuestion(example.text); got != example.want {
				t.Fatalf("toolLoopAnswerHasNextQuestion(%q) = %v, want %v", example.text, got, example.want)
			}
		})
	}
}

// Card D-16 result 1: the kind-specific instruction carries every rule the
// route needs: read the workspace first, say when nothing is held, name no
// technical location, and finish with a next question.
func TestPlainOverviewInstructionsCarryRouteRules(t *testing.T) {
	for _, want := range []string{
		"what this workspace's information holds about one subject",
		"When the workspace holds nothing about the subject, say plainly that there is nothing on it and describe no data",
		"name at least three things they really record about it",
		"never write or request SQL",
		"never names a table, relation, column, field, schema, connection or source identifier",
		"Always finish with at least one concrete question",
		"in the language of the user's question",
	} {
		if !strings.Contains(plainOverviewInstructions, want) {
			t.Fatalf("plainOverviewInstructions is missing %q", want)
		}
	}
	// The instruction is this route's own: it must not carry the full loop's
	// SQL or live-data rules.
	for _, forbidden := range []string{"knowvault_source_sql", "knowvault_ask_live_data", "knowvault_compare_metric"} {
		if strings.Contains(plainOverviewInstructions, forbidden) {
			t.Fatalf("plainOverviewInstructions carries a data-tool rule: %q", forbidden)
		}
	}
}

// Card D-16 / D-20: the server orientation names the sources by their human
// names, lists the features each database really records (as its registered
// column names, which the answer must translate into business words and never
// show), and repeats the two rules a model most easily misses. It never
// carries a connection identifier, status or count.
func TestToolLoopPlainOverviewTextNamesRecordedFeatures(t *testing.T) {
	text := toolLoopPlainOverviewText(questionLanguageRussian, []plainOverviewTopic{
		{Name: "Договоры", Attributes: []plainOverviewAttribute{
			{Name: "number", Type: "text"}, {Name: "client_id", Type: "int"},
			{Name: "signed_on", Type: "date"}, {Name: "amount", Type: "numeric"},
		}},
		{Name: "Клиенты"},
	}, "Краткое описание рабочей области.")
	for _, want := range []string{
		"«Договоры»", "«Клиенты»", "number (text)", "client_id (int)",
		"signed_on (date)", "amount (numeric)", "Краткое описание рабочей области.",
		"ничего нет", "конкретным вопросом",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plain overview orientation is missing %q: %q", want, text)
		}
	}
	for _, forbidden := range []string{"conn_", "READY", "source_id"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("plain overview orientation leaks %q: %q", forbidden, text)
		}
	}
}

// d20OrientationRuntime answers the orientation's two system reads with canned
// envelopes: a source list with one database source and one document source,
// and a stored source schema for the database source only.
type d20OrientationRuntime struct {
	calls []string
}

func (runtime *d20OrientationRuntime) Catalog(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
	return nil, workspacetools.ErrUnavailable
}

func (runtime *d20OrientationRuntime) Invoke(_ context.Context, _ workspacetools.Scope, name string, arguments json.RawMessage) (workspacetools.Result, error) {
	runtime.calls = append(runtime.calls, name)
	switch name {
	case "knowvault_sources":
		return workspacetools.Result{Structured: json.RawMessage(`{"sources":[
			{"connection_id":"conn_database_01H9ABCDEFGHJKMNPQRSTVWXYZ","connection_name":"Договоры","source_type":"POSTGRESQL_QUERY"},
			{"connection_id":"conn_documents_01H9ABCDEFGHJKMNPQRSTVWXYZ","connection_name":"Документы","source_type":"FOLDER"}]}`)}, nil
	case "knowvault_source_schema":
		var envelope struct {
			SourceID string `json:"source_id"`
		}
		if json.Unmarshal(arguments, &envelope) != nil || envelope.SourceID != "conn_database_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
			return workspacetools.Result{IsError: true}, nil
		}
		return workspacetools.Result{Structured: json.RawMessage(`{"source_id":"conn_database_01H9ABCDEFGHJKMNPQRSTVWXYZ","tables":[{"name":"contract","columns":[
			{"name":"number","type":"text"},{"name":"client_id","type":"int"},{"name":"status","type":"text"},
			{"name":"signed_on","type":"date"},{"name":"amount","type":"numeric"}]}]}`)}, nil
	}
	return workspacetools.Result{IsError: true}, nil
}

// Card D-20 result 1: the plain_overview orientation reads each database
// source's stored schema as a system call, so the answer can name what the
// database really records, and the read is recorded in the run trace so the
// answer's own presentation guard knows the columns it must not show.
func TestBuildPlainOverviewOrientationReadsRecordedFeatures(t *testing.T) {
	runtime := &d20OrientationRuntime{}
	service := &Service{tools: runtime}
	record := &ToolLoopRecord{}
	overview, err := service.buildPlainOverviewOrientation(context.Background(),
		workspacetools.Scope{WorkspaceID: "ws_0001"}, record, questionLanguageRussian, "Описание.")
	if err != nil || overview == nil {
		t.Fatalf("plain overview orientation: %v %#v", err, overview)
	}
	for _, want := range []string{"«Договоры»", "«Документы»", "number (text)", "client_id (int)", "signed_on (date)", "amount (numeric)"} {
		if !strings.Contains(overview.Text, want) {
			t.Fatalf("orientation is missing %q: %q", want, overview.Text)
		}
	}
	schemaReads := 0
	for _, call := range record.Calls {
		if call.Name == "knowvault_source_schema" && call.System {
			schemaReads++
		}
	}
	if schemaReads != 1 {
		t.Fatalf("orientation recorded %d system schema reads, want 1", schemaReads)
	}
	for _, name := range runtime.calls {
		if name == "knowvault_source_sql" || name == "knowvault_ask_live_data" {
			t.Fatalf("orientation reached a data tool %q", name)
		}
	}
	vocabulary := toolLoopTechnicalVocabulary(record)
	for _, column := range []string{"number", "client_id", "status", "signed_on", "amount"} {
		if _, ok := vocabulary[column]; !ok {
			t.Fatalf("orientation did not teach the answer's guard the column %q: %v", column, vocabulary)
		}
	}
}

// Card D-16: the plain_overview route uses its own system instruction, and the
// untouched wrapper still uses the full loop's instruction byte for byte.
func TestInitialToolLoopMessagesWithKindInstruction(t *testing.T) {
	outbound, persisted := initialToolLoopMessagesWith("вопрос", nil, 32*1024, "\nCONTEXT", plainOverviewInstructions)
	if len(outbound) != 2 || outbound[0].Content != plainOverviewInstructions+"\nCONTEXT" {
		t.Fatalf("plain_overview system message = %#v", outbound)
	}
	if len(persisted) != 2 || persisted[0].Content != plainOverviewInstructions+"\nCONTEXT" {
		t.Fatalf("persisted plain_overview system message = %#v", persisted)
	}
	generic, _ := initialToolLoopMessages("вопрос", nil, 32*1024, "")
	if len(generic) != 2 || generic[0].Content != toolLoopInstructions {
		t.Fatal("the generic route lost its own instruction")
	}
}
