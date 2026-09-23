package workspaceapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
)

type stagedQuestionService struct {
	*fakeQuestionService
	release   <-chan struct{}
	cancelled chan<- struct{}
}

func (service *stagedQuestionService) Create(ctx context.Context, access database.AccessContext, request question.CreateRequest) (question.Run, error) {
	question.ReportAction(ctx, question.ActionEvent{Type: "action_started", Label: "model"})
	select {
	case <-service.release:
		question.ReportAction(ctx, question.ActionEvent{Type: "action_finished", Label: "model", Outcome: "succeeded"})
		return service.fakeQuestionService.Create(ctx, access, request)
	case <-ctx.Done():
		if service.cancelled != nil {
			close(service.cancelled)
		}
		return question.Run{}, ctx.Err()
	}
}

type flushedResponse struct {
	*httptest.ResponseRecorder
	first   sync.Once
	flushed chan struct{}
}

func (writer *flushedResponse) Flush() {
	writer.ResponseRecorder.Flush()
	writer.first.Do(func() { close(writer.flushed) })
}

func streamQuestionRequest(harness *testHarness, body string) *http.Request {
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", body)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	request.Header.Set("Accept", questionStreamContentType)
	return request
}

func TestQuestionCreateStreamFlushesActionBeforeCompletedResult(t *testing.T) {
	harness := newTestHarness(t)
	release := make(chan struct{})
	harness.handler.questions = &stagedQuestionService{fakeQuestionService: harness.questions, release: release}
	writer := &flushedResponse{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		harness.handler.ServeHTTP(writer, streamQuestionRequest(harness, `{"question":"How many?"}`))
	}()
	select {
	case <-writer.flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("first action was not flushed before completion")
	}
	if got := writer.Body.String(); got != "{\"type\":\"action\",\"sequence\":1,\"phase\":\"action_started\",\"label\":\"model\"}\n" {
		t.Fatalf("first flush includes unfinished content: %q", got)
	}
	close(release)
	<-done
	if writer.Code != http.StatusOK || writer.Header().Get("Content-Type") != questionStreamContentType {
		t.Fatalf("status=%d content-type=%q", writer.Code, writer.Header().Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimSpace(writer.Body.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], `"phase":"action_finished"`) {
		t.Fatalf("unexpected stream: %q", writer.Body.String())
	}
	var frame map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lines[2]), &frame); err != nil {
		t.Fatal(err)
	}
	var streamed question.Run
	if err := json.Unmarshal(frame["result"], &streamed); err != nil || !reflect.DeepEqual(streamed, harness.questions.run) {
		t.Fatalf("completed result differs: %+v, %v", streamed, err)
	}
	jsonResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(jsonResponse, func() *http.Request {
		request := streamQuestionRequest(harness, `{"question":"How many?"}`)
		request.Header.Del("Accept")
		return request
	}())
	var ordinary question.Run
	if err := json.Unmarshal(jsonResponse.Body.Bytes(), &ordinary); err != nil || !reflect.DeepEqual(streamed, ordinary) {
		t.Fatalf("stream differs from ordinary response: %+v / %+v, %v", streamed, ordinary, err)
	}
}

func TestQuestionCreateStreamValidationAndDenialStayContentFree(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, streamQuestionRequest(harness, `{"question":"  "}`))
	if response.Code != http.StatusBadRequest || !strings.HasPrefix(response.Header().Get("Content-Type"), jsonContentType) || harness.questions.call != "" {
		t.Fatalf("validation response changed: status=%d type=%q body=%s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	harness.questions.err = errors.New("secret denial detail")
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, streamQuestionRequest(harness, `{"question":"private question"}`))
	if response.Code != http.StatusOK || strings.Count(response.Body.String(), "\n") != 1 || strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), `"action"`) {
		t.Fatalf("denial disclosed content: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"QUESTION_FAILED"`) {
		t.Fatalf("missing terminal failure: %s", response.Body.String())
	}
}

func TestQuestionCreateStreamIdempotentResultHasNoSyntheticAction(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, streamQuestionRequest(harness, `{"question":"How many?"}`))
	if strings.Count(response.Body.String(), "\n") != 1 || !strings.HasPrefix(response.Body.String(), `{"type":"result"`) {
		t.Fatalf("unexpected synthetic actions: %s", response.Body.String())
	}
}

type failingStreamWriter struct{ header http.Header }

func (writer *failingStreamWriter) Header() http.Header { return writer.header }
func (writer *failingStreamWriter) Write([]byte) (int, error) {
	return 0, errors.New("client disconnected")
}
func (writer *failingStreamWriter) WriteHeader(int) {}
func (writer *failingStreamWriter) Flush()          {}

func TestQuestionCreateStreamWriteFailureCancelsWork(t *testing.T) {
	harness := newTestHarness(t)
	cancelled := make(chan struct{})
	harness.handler.questions = &stagedQuestionService{fakeQuestionService: harness.questions, release: make(chan struct{}), cancelled: cancelled}
	harness.handler.ServeHTTP(&failingStreamWriter{header: make(http.Header)}, streamQuestionRequest(harness, `{"question":"How many?"}`))
	select {
	case <-cancelled:
	default:
		t.Fatal("stream write failure did not cancel question context")
	}
}

func TestQuestionStreamAcceptIsExplicit(t *testing.T) {
	for _, testCase := range []struct {
		accept string
		want   bool
	}{
		{"application/x-ndjson", true},
		{"application/json, application/x-ndjson;q=0.5", true},
		{"application/x-ndjson;q=0", false},
		{"application/x-ndjson;q=NaN", false},
		{"*/*", false},
		{"application/json", false},
	} {
		if got := acceptsQuestionEventStream(testCase.accept); got != testCase.want {
			t.Errorf("Accept %q: got %t want %t", testCase.accept, got, testCase.want)
		}
	}
}
