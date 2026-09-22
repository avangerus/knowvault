package question

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/modelgateway"
)

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
