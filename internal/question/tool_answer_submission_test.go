package question

import (
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

func TestSubmitAnswerDefinitionUsesPrivateV1ChatSchema(t *testing.T) {
	definition := submitAnswerToolDefinition()
	if definition.Type != "function" || definition.Function.Name != submitAnswerToolName {
		t.Fatalf("definition = %#v", definition)
	}
	if !strings.Contains(definition.Function.Description, submitAnswerSchemaV1) {
		t.Fatalf("definition description must identify schema %q", submitAnswerSchemaV1)
	}
	if !json.Valid(definition.Function.Parameters) {
		t.Fatal("submit_answer schema is not valid JSON")
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(definition.Function.Parameters, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Required) != 2 || schema.Required[0] != "no_data" || schema.Required[1] != "claims" {
		t.Fatalf("required fields = %#v", schema.Required)
	}
}

func TestParseSubmitAnswerArgumentsAcceptsBoundedResponseKinds(t *testing.T) {
	valid := []struct {
		name string
		json string
	}{
		{
			name: "claims",
			json: `{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"fabricated-fragment"}]}]}`,
		},
		{name: "no data", json: `{"no_data":true,"claims":[]}`},
		{name: "clarification", json: `{"no_data":false,"claims":[],"clarification":"Which project?"}`},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			answer, ok := parseSubmitAnswerArguments([]byte(tc.json))
			if !ok {
				t.Fatal("valid submit_answer arguments rejected")
			}
			if tc.name == "claims" && answer.Claims[0].Citations[0].FragmentID != "fabricated-fragment" {
				t.Fatal("parser must preserve a citation for later binding; it must not fabricate or rewrite it")
			}
		})
	}
}

func TestParseSubmitAnswerArgumentsRejectsMissingNullUnknownAndDuplicateFields(t *testing.T) {
	invalid := []string{
		`{"claims":[],"clarification":"Which project?"}`,
		`{"no_data":true}`,
		`{"no_data":true,"claims":[],"unknown":1}`,
		`{"no_data":true,"no_data":false,"claims":[]}`,
		`{"no_data":null,"claims":[]}`,
		`{"no_data":true,"claims":null}`,
		`{"no_data":false,"claims":[{"text":"Fact."}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":null}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[],"unknown":1}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"a","fragment_id":"b"}]}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"a","address":null}]}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"a","address":""}]}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"a","quote":null}]}]}`,
	}
	for _, payload := range invalid {
		if _, ok := parseSubmitAnswerArguments([]byte(payload)); ok {
			t.Fatalf("invalid submit_answer arguments accepted: %s", payload)
		}
	}
}

func TestParseSubmitAnswerArgumentsDetailedClassifiesFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want toolFormatInvalidCode
	}{
		{name: "malformed JSON", json: `{"no_data":false,}`, want: toolFormatAnswerSchemaInvalid},
		{name: "unknown field", json: `{"no_data":true,"claims":[],"extra":1}`, want: toolFormatAnswerSchemaInvalid},
		{name: "invalid variant", json: `{"no_data":true,"claims":[{"text":"Fact.","citations":[{"fragment_id":"fragment_1"}]}]}`, want: toolFormatAnswerVariantInvalid},
		{name: "quote without selector", json: `{"no_data":false,"claims":[{"text":"Fact.","citations":[{"quote":"Source words."}]}]}`, want: toolFormatCitationSelectorInvalid},
		{name: "both selectors", json: `{"no_data":false,"claims":[{"text":"Fact.","citations":[{"fragment_id":"fragment_1","address":"kv1:address"}]}]}`, want: toolFormatCitationSelectorInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, code := parseSubmitAnswerArgumentsDetailed([]byte(tc.json))
			if ok || code != tc.want {
				t.Fatalf("parse result = ok:%v code:%q; want ok:false code:%q", ok, code, tc.want)
			}
		})
	}
}

func TestSubmitAnswerCallsFormatCodeDistinguishesMixedCalls(t *testing.T) {
	submit := testSubmitAnswerCall(`{"no_data":true,"claims":[]}`)
	knowledge := testSubmitAnswerCall(`{"fragment_id":"fragment_1"}`)
	knowledge.Function.Name = "knowvault_read"
	if got := submitAnswerCallsFormatCode([]modelgateway.ToolCall{submit}); got != "" {
		t.Fatalf("sole submit_answer code = %q", got)
	}
	if got := submitAnswerCallsFormatCode([]modelgateway.ToolCall{submit, knowledge}); got != toolFormatSubmitNotSole {
		t.Fatalf("mixed call code = %q; want %q", got, toolFormatSubmitNotSole)
	}
	if got := submitAnswerCallsFormatCode([]modelgateway.ToolCall{knowledge}); got != "" {
		t.Fatalf("knowledge-only code = %q", got)
	}
}

func TestSubmitAnswerCallMustBeSoleFinalCall(t *testing.T) {
	submit := testSubmitAnswerCall(`{"no_data":true,"claims":[]}`)
	knowledge := testSubmitAnswerCall(`{"fragment_id":"fragment_1"}`)
	knowledge.Function.Name = "knowvault_read"
	if !containsSubmitAnswerCall([]modelgateway.ToolCall{submit}) || !isSoleSubmitAnswerCall([]modelgateway.ToolCall{submit}) {
		t.Fatal("a sole submit_answer call must be recognized as the final call")
	}
	if !containsSubmitAnswerCall([]modelgateway.ToolCall{submit, knowledge}) || isSoleSubmitAnswerCall([]modelgateway.ToolCall{submit, knowledge}) {
		t.Fatal("mixed submit_answer and knowledge calls must not be accepted")
	}
	if isSoleSubmitAnswerCall([]modelgateway.ToolCall{submit, submit}) {
		t.Fatal("multiple final calls must not be accepted as a sole submit_answer call")
	}
}

func TestSubmitAnswerProtocolErrorIsPublicToolResult(t *testing.T) {
	result := submitAnswerProtocolError("SUBMIT_ANSWER_MUST_BE_SOLE_CALL")
	if !result.IsError || !strings.Contains(result.Text, "SUBMIT_ANSWER_MUST_BE_SOLE_CALL") {
		t.Fatalf("protocol result = %#v", result)
	}
}

func TestFormatDiagnosticsPreserveContentSelectorCompatibility(t *testing.T) {
	// Content historically tolerates an empty/null unused selector. submit_answer
	// requires exactly one selector key. Diagnostics must preserve that difference.
	for _, unused := range []string{`""`, `null`} {
		raw := `{"no_data":false,"claims":[{"text":"fact","citations":[{"fragment_id":"fragment_1","address":` + unused + `}]}]}`
		if _, ok := parseToolAnswer(raw); !ok {
			t.Fatal("diagnostics tightened the content parser")
		}
		if _, ok := parseSubmitAnswerArguments(json.RawMessage(raw)); ok {
			t.Fatal("diagnostics weakened the submit parser")
		}
	}
}

func testSubmitAnswerCall(arguments string) modelgateway.ToolCall {
	call := modelgateway.ToolCall{ID: "call-1", Type: "function"}
	call.Function.Name = submitAnswerToolName
	call.Function.Arguments = arguments
	return call
}
