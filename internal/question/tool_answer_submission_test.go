package question

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

func TestSubmitAnswerDefinitionUsesPrivateV2ChatSchema(t *testing.T) {
	definition := submitAnswerToolDefinition()
	if definition.Type != "function" || definition.Function.Name != submitAnswerToolName {
		t.Fatalf("definition = %#v", definition)
	}
	if !strings.Contains(definition.Function.Description, submitAnswerSchemaV2) {
		t.Fatalf("definition description must identify schema %q", submitAnswerSchemaV2)
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

func TestSubmitAnswerLiveReadReferencesAreOptionalAndBounded(t *testing.T) {
	definition := submitAnswerToolDefinition()
	if !strings.Contains(string(definition.Function.Parameters), `"live_reads"`) || !strings.Contains(string(definition.Function.Parameters), `"maxItems":3`) {
		t.Fatal("submit_answer schema must expose at most three explicit live-read references")
	}
	legacy := `{"no_data":false,"claims":[{"text":"Document fact.","citations":[{"fragment_id":"fragment_1"}]}]}`
	if _, ok := parseSubmitAnswerArguments([]byte(legacy)); !ok {
		t.Fatal("legacy document-only claim without live_reads was rejected")
	}
	valid := `{"no_data":false,"claims":[{"text":"Mixed fact.","citations":[{"fragment_id":"fragment_1"}],"live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}`
	answer, ok := parseSubmitAnswerArguments([]byte(valid))
	if !ok || len(answer.Claims) != 1 || len(answer.Claims[0].LiveReads) != 1 || answer.Claims[0].LiveReads[0].ResultID != "gqat_test_1" {
		t.Fatalf("valid mixed claim was not preserved exactly: %#v, ok=%v", answer, ok)
	}
	invalid := []string{
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[],"live_reads":null}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[],"live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}]}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[],"live_reads":[{"result_id":"gqat_test_1","receipt_digest":"bad"}]}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[],"live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}`,
		`{"no_data":false,"claims":[{"text":"Fact.","citations":[],"live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"result_id":"gqat_test_2","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"result_id":"gqat_test_3","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"result_id":"gqat_test_4","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}`,
	}
	for _, raw := range invalid {
		if _, ok := parseSubmitAnswerArguments([]byte(raw)); ok {
			t.Fatalf("invalid live-read references accepted: %s", raw)
		}
	}
}

func TestSubmitAnswerAcceptsLiveOnlyClaimWithoutCitations(t *testing.T) {
	const payload = `{"no_data":false,"claims":[{"text":"Live observation.","live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}`
	answer, ok := parseSubmitAnswerArguments([]byte(payload))
	if !ok || len(answer.Claims) != 1 || len(answer.Claims[0].Citations) != 0 || len(answer.Claims[0].LiveReads) != 1 {
		t.Fatalf("live-only claim without citations was rejected or changed: %#v, ok=%v", answer, ok)
	}
	var schema any
	if err := json.Unmarshal(submitAnswerToolDefinition().Function.Parameters, &schema); err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := json.Unmarshal([]byte(payload), &instance); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedSubmitAnswerSchema(schema, instance); err != nil {
		t.Fatalf("published schema rejected live-only claim: %v", err)
	}
}

func TestSubmitAnswerAcceptsSupportedClaimWithoutRedundantFalseFlag(t *testing.T) {
	const payload = `{"claims":[{"text":"Observed value is 3888.","live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}`
	answer, ok := parseSubmitAnswerArguments([]byte(payload))
	if !ok || answer.NoData || len(answer.Claims) != 1 || len(answer.Claims[0].LiveReads) != 1 {
		t.Fatalf("supported claim without no_data=false was rejected or changed: %#v, ok=%v", answer, ok)
	}
	for _, invalid := range []string{`{"claims":[]}`, `{"claims":[],"clarification":"Which project?"}`, `{"claims":[{"text":"Unsupported."}]}`} {
		if _, ok := parseSubmitAnswerArguments([]byte(invalid)); ok {
			t.Fatalf("unsupported or empty variant accepted without no_data: %s", invalid)
		}
	}
}

func TestSubmitAnswerRejectsClaimsWithoutEvidence(t *testing.T) {
	for _, payload := range []string{
		`{"no_data":false,"claims":[{"text":"Unsupported."}]}`,
		`{"no_data":false,"claims":[{"text":"Unsupported.","citations":[]}]}`,
		`{"no_data":false,"claims":[{"text":"Unsupported.","live_reads":[]}]}`,
		`{"no_data":false,"claims":[{"text":"Unsupported.","citations":[],"live_reads":[]}]}`,
	} {
		if _, ok := parseSubmitAnswerArguments([]byte(payload)); ok {
			t.Fatalf("unsupported claim accepted: %s", payload)
		}
	}
}

func TestSubmitAnswerPublishedSchemaAcceptsMixedDocumentLivePayload(t *testing.T) {
	definition := submitAnswerToolDefinition()
	var schema any
	if err := json.Unmarshal(definition.Function.Parameters, &schema); err != nil {
		t.Fatalf("decode published submit_answer JSON Schema: %v", err)
	}
	payload := []byte(`{"no_data":false,"claims":[{"text":"The policy sets the limit and two current reads show exceptions.","citations":[{"fragment_id":"fragment_rule"}],"live_reads":[{"result_id":"gqat_test_1","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"result_id":"gqat_test_2","receipt_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}]}`)
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatalf("decode mixed payload: %v", err)
	}
	if err := validatePublishedSubmitAnswerSchema(schema, instance); err != nil {
		t.Fatalf("published submit_answer JSON Schema rejected a mixed document/live payload: %v", err)
	}
	unknownProperty := bytes.Replace(payload, []byte(`,"live_reads":`), []byte(`,"unknown_claim_field":true,"live_reads":`), 1)
	var invalid any
	if err := json.Unmarshal(unknownProperty, &invalid); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedSubmitAnswerSchema(schema, invalid); err == nil {
		t.Fatal("published closed claim schema accepted an unknown property")
	}

	if !strings.Contains(toolLoopInstructions, "setting result_id to that result's attempt_id") ||
		!strings.Contains(toolFinalizationInstructions, "result_id is copied from that output's attempt_id") ||
		!strings.Contains(liveDataToolDefinition().Function.Description, "attempt_id as live_reads.result_id") {
		t.Fatal("live tool instructions do not explain the attempt_id to result_id mapping")
	}
	if !strings.Contains(toolLoopInstructions, "Do not restate, alter, or recalculate that knowvault_analyze result") ||
		!strings.Contains(toolLoopInstructions, "For knowvault_ask_live_data, interpret its returned rows and cite its live read") {
		t.Fatal("tool-loop instructions conflate server-presented analytic values with model-interpreted live rows")
	}
}

// validatePublishedSubmitAnswerSchema evaluates the JSON Schema keywords used
// by the published submit_answer contract. It reads the actual schema from the
// tool definition, so a property placed outside claim.properties is rejected
// by the claim's additionalProperties:false rule.
func validatePublishedSubmitAnswerSchema(schema, instance any) error {
	object, ok := schema.(map[string]any)
	if !ok {
		return fmt.Errorf("schema must be an object")
	}
	for keyword := range object {
		switch keyword {
		case "type", "required", "properties", "additionalProperties", "items", "maxItems", "minLength", "maxLength", "pattern", "oneOf", "not", "description":
		default:
			return fmt.Errorf("test validator does not support schema keyword %q", keyword)
		}
	}
	if typeName, exists := object["type"].(string); exists {
		validType := false
		switch typeName {
		case "object":
			_, validType = instance.(map[string]any)
		case "array":
			_, validType = instance.([]any)
		case "string":
			_, validType = instance.(string)
		case "boolean":
			_, validType = instance.(bool)
		default:
			return fmt.Errorf("unsupported schema type %q", typeName)
		}
		if !validType {
			return fmt.Errorf("instance has wrong type; want %s", typeName)
		}
	}
	if required, exists := object["required"].([]any); exists {
		instanceObject, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("required applies to a non-object instance")
		}
		for _, rawName := range required {
			name, ok := rawName.(string)
			if !ok {
				return fmt.Errorf("required member name is not a string")
			}
			if _, exists := instanceObject[name]; !exists {
				return fmt.Errorf("required property %q is missing", name)
			}
		}
	}
	if properties, exists := object["properties"].(map[string]any); exists {
		instanceObject, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("properties applies to a non-object instance")
		}
		if additional, exists := object["additionalProperties"].(bool); exists && !additional {
			for name := range instanceObject {
				if _, declared := properties[name]; !declared {
					return fmt.Errorf("additional property %q is forbidden", name)
				}
			}
		}
		for name, childSchema := range properties {
			if child, exists := instanceObject[name]; exists {
				if err := validatePublishedSubmitAnswerSchema(childSchema, child); err != nil {
					return fmt.Errorf("property %q: %w", name, err)
				}
			}
		}
	}
	if itemsSchema, exists := object["items"]; exists {
		items, ok := instance.([]any)
		if !ok {
			return fmt.Errorf("items applies to a non-array instance")
		}
		for index, item := range items {
			if err := validatePublishedSubmitAnswerSchema(itemsSchema, item); err != nil {
				return fmt.Errorf("array item %d: %w", index, err)
			}
		}
	}
	if maximum, exists := object["maxItems"].(float64); exists {
		items, ok := instance.([]any)
		if !ok || float64(len(items)) > maximum {
			return fmt.Errorf("array exceeds maxItems %d", int(maximum))
		}
	}
	if text, ok := instance.(string); ok {
		length := utf8.RuneCountInString(text)
		if minimum, exists := object["minLength"].(float64); exists && float64(length) < minimum {
			return fmt.Errorf("string is shorter than minLength %d", int(minimum))
		}
		if maximum, exists := object["maxLength"].(float64); exists && float64(length) > maximum {
			return fmt.Errorf("string exceeds maxLength %d", int(maximum))
		}
		if pattern, exists := object["pattern"].(string); exists {
			compiled, err := regexp.Compile(pattern)
			if err != nil || !compiled.MatchString(text) {
				return fmt.Errorf("string does not match pattern %q", pattern)
			}
		}
	}
	if branches, exists := object["oneOf"].([]any); exists {
		validBranches := 0
		for _, branch := range branches {
			if validatePublishedSubmitAnswerSchema(branch, instance) == nil {
				validBranches++
			}
		}
		if validBranches != 1 {
			return fmt.Errorf("oneOf matched %d branches", validBranches)
		}
	}
	if prohibited, exists := object["not"]; exists && validatePublishedSubmitAnswerSchema(prohibited, instance) == nil {
		return fmt.Errorf("not schema matched")
	}
	return nil
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
