package question

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

func testReadAddress(t *testing.T, version string, text string) string {
	t.Helper()
	base := address.Address{
		Source:    "demo-source",
		Object:    "demo-object",
		Version:   version,
		SpanKind:  address.SpanKindText,
		CharStart: 0,
		CharEnd:   len([]rune(text)),
	}
	value, err := base.WithSpanHash([]byte(text))
	if err != nil {
		t.Fatalf("address.WithSpanHash: %v", err)
	}
	return value.String()
}

func testReadCall(t *testing.T, id, canonicalAddress, text string) ToolCallRecord {
	t.Helper()
	length := int64(len([]byte(text)))
	structured, err := json.Marshal(map[string]any{
		"canonical_address": canonicalAddress,
		"text":              text,
		"offset":            0,
		"length":            length,
		"total_length":      length,
		"has_more":          false,
		"complete":          true,
	})
	if err != nil {
		t.Fatalf("json.Marshal(read result): %v", err)
	}
	return ToolCallRecord{
		ID:            id,
		Name:          "knowvault_read",
		Arguments:     json.RawMessage(`{"address":"` + canonicalAddress + `"}`),
		ArgumentsHash: "arguments-hash-" + id,
		Outcome:       "SUCCEEDED",
		Result: workspacetools.Result{
			Text:       text + "\ncanonical_address=" + canonicalAddress,
			Structured: structured,
		},
	}
}

func testToolMessage(call ToolCallRecord) (modelgateway.Message, modelgateway.Message) {
	var toolCall modelgateway.ToolCall
	toolCall.ID = call.ID
	toolCall.Type = "function"
	toolCall.Function.Name = call.Name
	toolCall.Function.Arguments = string(call.Arguments)
	return modelgateway.Message{
			Role:      "assistant",
			ToolCalls: []modelgateway.ToolCall{toolCall},
		}, modelgateway.Message{
			Role:       "tool",
			ToolCallID: call.ID,
			Content:    call.Result.Text,
		}
}

func testMessages(calls []ToolCallRecord) []modelgateway.Message {
	messages := make([]modelgateway.Message, 0, len(calls)*2)
	for _, call := range calls {
		assistant, tool := testToolMessage(call)
		messages = append(messages, assistant, tool)
	}
	return messages
}

func contextEncodedSize(t *testing.T, messages []modelgateway.Message, tools []modelgateway.ToolDefinition) int {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Messages []modelgateway.Message
		Tools    []modelgateway.ToolDefinition
	}{messages, tools})
	if err != nil {
		t.Fatalf("json.Marshal(context): %v", err)
	}
	return len(encoded)
}

func TestCollapseExactReadDuplicatesPreservesRecordAndPairing(t *testing.T) {
	text := strings.Repeat("\u041a\u0412-\u0421\u0435\u0440\u0432\u0438\u0441 \u0414\u0435\u043c\u043e: \u043f\u043b\u0430\u043d\u043e\u0432\u0430\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043e\u0431\u043e\u0440\u0443\u0434\u043e\u0432\u0430\u043d\u0438\u044f. ", 8)
	canonical := testReadAddress(t, "2026-08", text)
	calls := []ToolCallRecord{
		testReadCall(t, "read-1", canonical, text),
		testReadCall(t, "read-2", canonical, text),
		testReadCall(t, "read-3", canonical, text),
		testReadCall(t, "read-4", canonical, text),
	}
	working := testMessages(calls)
	recordCalls := append([]ToolCallRecord(nil), calls...)
	recordMessages := append([]modelgateway.Message(nil), working...)
	recordMessagesBefore := append([]modelgateway.Message(nil), recordMessages...)
	record := ToolLoopRecord{Calls: calls, Messages: recordMessages}
	packing := &toolContextPacking{Representatives: make(map[readPageKey]*contextRepresentative)}

	if !collapseExactReadDuplicates(working, record.Calls, packing) {
		t.Fatal("collapseExactReadDuplicates reported no change")
	}
	fullPages := 0
	reusedPages := 0
	for index, message := range working {
		if message.Role != "tool" {
			continue
		}
		if marker, ok := isContextReusedMarker(message.Content); ok {
			reusedPages++
			if marker.RepresentativeToolCallID != calls[0].ID {
				t.Fatalf("message %d representative = %q, want %q", index, marker.RepresentativeToolCallID, calls[0].ID)
			}
			if message.ToolCallID != calls[reusedPages].ID {
				t.Fatalf("message %d pairing id = %q, want %q", index, message.ToolCallID, calls[reusedPages].ID)
			}
			continue
		}
		if strings.Contains(message.Content, text) {
			fullPages++
		}
	}
	if fullPages != 1 || reusedPages != 3 {
		t.Fatalf("full pages = %d, reused pages = %d, want 1 and 3", fullPages, reusedPages)
	}
	for index := 0; index < len(working); index += 2 {
		if len(working[index].ToolCalls) != 1 || working[index].ToolCalls[0].ID != calls[index/2].ID {
			t.Fatalf("assistant/tool pairing changed at message %d: %#v", index, working[index])
		}
	}
	if !reflect.DeepEqual(record.Calls, recordCalls) {
		t.Fatal("ToolCallRecord values changed while packing transient messages")
	}
	if !reflect.DeepEqual(record.Messages, recordMessagesBefore) {
		t.Fatal("record.Messages changed while packing transient messages")
	}
}

func TestCollapseRejectsUnprovenReadPages(t *testing.T) {
	text := strings.Repeat("complete page ", 20)
	canonical := testReadAddress(t, "2026-08", text)
	cases := []struct {
		name  string
		setup func(ToolCallRecord, modelgateway.Message) (ToolCallRecord, modelgateway.Message)
	}{
		{
			name: "different version",
			setup: func(call ToolCallRecord, message modelgateway.Message) (ToolCallRecord, modelgateway.Message) {
				other := testReadAddress(t, "2026-09", text)
				call.Arguments = json.RawMessage(`{"address":"` + other + `"}`)
				var envelope map[string]any
				if err := json.Unmarshal(call.Result.Structured, &envelope); err != nil {
					t.Fatalf("json.Unmarshal(read result): %v", err)
				}
				envelope["canonical_address"] = other
				call.Result.Structured, _ = json.Marshal(envelope)
				message.Content = call.Result.Text
				return call, message
			},
		},
		{
			name: "partial page",
			setup: func(call ToolCallRecord, message modelgateway.Message) (ToolCallRecord, modelgateway.Message) {
				var envelope map[string]any
				if err := json.Unmarshal(call.Result.Structured, &envelope); err != nil {
					t.Fatalf("json.Unmarshal(read result): %v", err)
				}
				envelope["has_more"] = true
				call.Result.Structured, _ = json.Marshal(envelope)
				return call, message
			},
		},
		{
			name: "malformed structured result",
			setup: func(call ToolCallRecord, message modelgateway.Message) (ToolCallRecord, modelgateway.Message) {
				call.Result.Structured = json.RawMessage(`{"canonical_address":`)
				return call, message
			},
		},
		{
			name: "refused outcome",
			setup: func(call ToolCallRecord, message modelgateway.Message) (ToolCallRecord, modelgateway.Message) {
				call.Outcome = "REFUSED"
				return call, message
			},
		},
		{
			name: "model result budget",
			setup: func(call ToolCallRecord, message modelgateway.Message) (ToolCallRecord, modelgateway.Message) {
				call.Result.Text = `{"error":"MODEL_RESULT_BUDGET"}`
				message.Content = call.Result.Text
				return call, message
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := testReadCall(t, "read-1", canonical, text)
			second := testReadCall(t, "read-2", canonical, text)
			firstAssistant, firstTool := testToolMessage(first)
			secondAssistant, secondTool := testToolMessage(second)
			second, secondTool = tc.setup(second, secondTool)
			messages := []modelgateway.Message{firstAssistant, firstTool, secondAssistant, secondTool}
			before := append([]modelgateway.Message(nil), messages...)
			packing := &toolContextPacking{Representatives: make(map[readPageKey]*contextRepresentative)}
			if collapseExactReadDuplicates(messages, []ToolCallRecord{first, second}, packing) {
				t.Fatal("invalid or partial page was collapsed")
			}
			if !reflect.DeepEqual(messages, before) {
				t.Fatal("invalid or partial page changed transient content")
			}
		})
	}
}

func TestContextPackingBudgetFallbackNeverLeavesMarkerWithoutRepresentative(t *testing.T) {
	text := strings.Repeat("long page content ", 24)
	canonical := testReadAddress(t, "2026-08", text)
	calls := []ToolCallRecord{
		testReadCall(t, "read-1", canonical, text),
		testReadCall(t, "read-2", canonical, text),
	}
	working := testMessages(calls)
	packing := &toolContextPacking{Representatives: make(map[readPageKey]*contextRepresentative)}
	if !collapseExactReadDuplicates(working, calls, packing) {
		t.Fatal("duplicate page was not collapsed")
	}
	if _, ok := isContextReusedMarker(working[3].Content); !ok {
		t.Fatal("second page is not a reuse marker before fallback")
	}
	if fitToolContextWithPacking(working, nil, 1, packing) {
		t.Fatal("fit unexpectedly succeeded with a one-byte budget")
	}
	for index, message := range working {
		if isContextReusedContent(message.Content) {
			t.Fatalf("message %d retained a reuse marker after representative fallback", index)
		}
	}
}

func TestContextPackingDropsUnprotectedResultBeforeRepresentative(t *testing.T) {
	text := strings.Repeat("repeated complete page ", 20)
	distinctText := strings.Repeat("distinct complete page ", 20)
	canonical := testReadAddress(t, "2026-08", text)
	distinctCanonical := testReadAddress(t, "2026-09", distinctText)
	calls := []ToolCallRecord{
		testReadCall(t, "read-1", canonical, text),
		testReadCall(t, "read-2", canonical, text),
		testReadCall(t, "read-3", distinctCanonical, distinctText),
	}
	working := testMessages(calls)
	packing := &toolContextPacking{Representatives: make(map[readPageKey]*contextRepresentative)}
	if !collapseExactReadDuplicates(working, calls, packing) {
		t.Fatal("duplicate page was not collapsed")
	}
	packedSize := contextEncodedSize(t, working, nil)
	if !fitToolContextWithPacking(working, nil, packedSize+2047, packing) {
		t.Fatal("fit did not omit the available distinct result")
	}
	if !strings.Contains(working[1].Content, text) {
		t.Fatal("protected representative was omitted while a distinct result was available")
	}
	if _, ok := isContextReusedMarker(working[3].Content); !ok {
		t.Fatal("reuse marker lost while representative remained")
	}
	if !isContextOmitted(working[5].Content) {
		t.Fatal("distinct unprotected result was not compacted")
	}
}

func TestContextPackingMakesRepeatedPagesFitWithoutFixedPromptThreshold(t *testing.T) {
	text := strings.Repeat("same complete read ", 20)
	canonical := testReadAddress(t, "2026-08", text)
	calls := []ToolCallRecord{
		testReadCall(t, "read-1", canonical, text),
		testReadCall(t, "read-2", canonical, text),
		testReadCall(t, "read-3", canonical, text),
	}
	before := testMessages(calls)
	beforeSize := contextEncodedSize(t, before, nil)
	working := append([]modelgateway.Message(nil), before...)
	packing := &toolContextPacking{Representatives: make(map[readPageKey]*contextRepresentative)}
	if !collapseExactReadDuplicates(working, calls, packing) {
		t.Fatal("duplicate pages were not collapsed")
	}
	afterSize := contextEncodedSize(t, working, nil)
	if afterSize >= beforeSize {
		t.Fatalf("packed context size = %d, before size = %d; expected reduction", afterSize, beforeSize)
	}
	if !fitToolContextWithPacking(working, nil, afterSize+2048, packing) {
		t.Fatalf("packed context did not fit its measured budget %d", afterSize+2048)
	}
	if !strings.Contains(working[1].Content, text) {
		t.Fatal("representative page was not preserved in the fitting context")
	}
	if _, ok := isContextReusedMarker(working[3].Content); !ok {
		t.Fatal("reuse marker disappeared despite sufficient packed budget")
	}
	if !bytes.Contains([]byte(working[5].Content), []byte(`context_reused`)) {
		t.Fatal("third duplicate did not retain its reuse marker")
	}
}
