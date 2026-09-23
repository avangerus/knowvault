package workspaceapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/apphttp"
	"knowvault.local/verified-workspace/internal/question"
)

func TestQuestionStreamThroughSecurityHeadersArrivesBeforeTerminal(t *testing.T) {
	releaseTerminal := make(chan struct{})
	terminalStarted := make(chan struct{})
	writeErrors := make(chan error, 2)
	server := httptest.NewServer(apphttp.WithSecurityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// The middleware must still restore a removed security header when
		// committing the streamed response.
		writer.Header().Del("Content-Security-Policy")
		stream := newQuestionEventStream(writer)
		if err := stream.action(question.ActionEvent{Sequence: 1, Type: "action_started", Label: "document_search"}); err != nil {
			writeErrors <- err
			return
		}
		select {
		case <-releaseTerminal:
		case <-request.Context().Done():
			return
		}
		close(terminalStarted)
		writeErrors <- stream.result(question.Run{ID: "run_stream", ResultStatus: "COMPLETED"})
	})))
	defer server.Close()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseTerminal) }) }
	defer release()
	client := server.Client()
	client.Timeout = 2 * time.Second // a missing flush fails rather than hanging
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("stream headers were not flushed before completion: %v", err)
	}
	defer response.Body.Close()
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"} {
		if response.Header.Get(header) == "" {
			t.Fatalf("stream lost mandatory header %s", header)
		}
	}
	if response.Header.Get("X-Accel-Buffering") != "no" || response.Header.Get("Content-Type") != questionStreamContentType {
		t.Fatal("stream headers permit proxy buffering or lose NDJSON type")
	}
	decoder := json.NewDecoder(response.Body)
	var first questionStreamFrame
	if err := decoder.Decode(&first); err != nil || first.Type != "action" || first.Label != "document_search" {
		t.Fatalf("first event unavailable while terminal is blocked: %+v, %v", first, err)
	}
	select {
	case <-terminalStarted:
		t.Fatal("action became visible only after terminal execution started")
	default:
	}
	release()
	var terminal questionStreamFrame
	if err := decoder.Decode(&terminal); err != nil || terminal.Type != "result" || terminal.Result == nil || terminal.Result.ID != "run_stream" {
		t.Fatalf("terminal frame = %+v, %v", terminal, err)
	}
	if err := <-writeErrors; err != nil {
		t.Fatalf("stream write failed: %v", err)
	}
}
