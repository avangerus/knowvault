package workspaceapi

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/question"
)

type countingStreamWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (writer *countingStreamWriter) Flush() {
	writer.flushes++
	writer.ResponseRecorder.Flush()
}

func TestQuestionEventStreamActionAndTerminalFrames(t *testing.T) {
	writer := &countingStreamWriter{ResponseRecorder: httptest.NewRecorder()}
	stream := newQuestionEventStream(writer)
	if got := writer.Header().Get("Content-Type"); got != questionStreamContentType {
		t.Fatalf("content type = %q", got)
	}
	if writer.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("stream response may be cached")
	}
	if err := stream.action(question.ActionEvent{Sequence: 1, Type: "action_started", Label: "document_search"}); err != nil {
		t.Fatal(err)
	}
	duration := int64(17)
	if err := stream.action(question.ActionEvent{Sequence: 2, Type: "action_finished", Label: "document_search", Outcome: "succeeded", DurationMS: &duration}); err != nil {
		t.Fatal(err)
	}
	run := question.Run{ID: "run_1", ResultStatus: "COMPLETED", Answer: "authorized answer"}
	if err := stream.result(run); err != nil {
		t.Fatal(err)
	}
	if writer.flushes != 3 {
		t.Fatalf("flush count = %d", writer.flushes)
	}
	lines := strings.Split(strings.TrimSpace(writer.Body.String()), "\n")
	if len(lines) != 3 || lines[0] != `{"type":"action","sequence":1,"phase":"action_started","label":"document_search"}` ||
		lines[1] != `{"type":"action","sequence":2,"phase":"action_finished","label":"document_search","outcome":"succeeded","duration_ms":17}` {
		t.Fatalf("unexpected action wire frames: %q", writer.Body.String())
	}
	var final map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[2]), &final); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sortedKeys(final), []string{"result", "type"}) || string(final["type"]) != `"result"` {
		t.Fatalf("unexpected terminal envelope: %s", lines[2])
	}
	var restored question.Run
	if err := json.Unmarshal(final["result"], &restored); err != nil || restored.ID != run.ID || restored.Answer != run.Answer || restored.ResultStatus != run.ResultStatus {
		t.Fatalf("terminal result differs from completed Create response: %+v, %v", restored, err)
	}
	if err := stream.action(question.ActionEvent{Sequence: 3, Type: "action_started", Label: "model"}); err == nil {
		t.Fatal("action accepted after terminal result")
	}
}

func TestQuestionEventStreamRejectsUntrustedEventFields(t *testing.T) {
	writer := &countingStreamWriter{ResponseRecorder: httptest.NewRecorder()}
	stream := newQuestionEventStream(writer)
	secret := "PRIVATE_SQL_AND_MODEL_TEXT"
	for _, event := range []question.ActionEvent{
		{Sequence: 1, Type: "action_started", Label: question.ActionLabel(secret)},
		{Sequence: 1, Type: question.ActionEventType(secret), Label: "model"},
		{Sequence: 1, Type: "action_finished", Label: "live_data", Outcome: question.ActionOutcome(secret)},
	} {
		if err := stream.action(event); err == nil {
			t.Fatalf("accepted untrusted event: %+v", event)
		}
	}
	if err := stream.failure("req_1"); err != nil {
		t.Fatal(err)
	}
	if got := writer.Body.String(); got != "{\"type\":\"error\",\"code\":\"QUESTION_FAILED\",\"request_id\":\"req_1\"}\n" || strings.Contains(got, secret) {
		t.Fatalf("unexpected error frame: %q", got)
	}
	if writer.flushes != 1 {
		t.Fatalf("flush count = %d", writer.flushes)
	}
}

func TestQuestionEventStreamConcurrentActionsRemainWholeFrames(t *testing.T) {
	writer := &countingStreamWriter{ResponseRecorder: httptest.NewRecorder()}
	stream := newQuestionEventStream(writer)
	var wait sync.WaitGroup
	for index := uint64(1); index <= 24; index++ {
		wait.Add(1)
		go func(sequence uint64) {
			defer wait.Done()
			if err := stream.action(question.ActionEvent{Sequence: sequence, Type: "action_started", Label: "model"}); err != nil {
				t.Errorf("action %d: %v", sequence, err)
			}
		}(index)
	}
	wait.Wait()
	if err := stream.failure("req_2"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(writer.Body.String()), "\n")
	if len(lines) != 25 || writer.flushes != 25 {
		t.Fatalf("lines=%d flushes=%d", len(lines), writer.flushes)
	}
	for _, line := range lines {
		var frame questionStreamFrame
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			t.Fatalf("partial frame %q: %v", line, err)
		}
	}
	if lines[24] != `{"type":"error","code":"QUESTION_FAILED","request_id":"req_2"}` {
		t.Fatalf("terminal frame is not last: %q", lines[24])
	}
}

func sortedKeys(value map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	if len(keys) == 2 && keys[0] > keys[1] {
		keys[0], keys[1] = keys[1], keys[0]
	}
	return keys
}
