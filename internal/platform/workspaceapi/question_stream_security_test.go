package workspaceapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// R2: Request/Detail must stay length-bounded and correctly paired with the
// phase that can actually know them (a request is known once a call starts,
// an outcome only once it finishes), even if a caller upstream of the
// transport ever computed them incorrectly.
func TestQuestionEventStreamRejectsUnboundedOrMispairedActionText(t *testing.T) {
	overlong := strings.Repeat("a", 181)
	cases := map[string]question.ActionEvent{
		"request on a finished frame": {Sequence: 1, Type: "action_finished", Label: "document_search", Outcome: "succeeded", Request: "leaked after the fact"},
		"detail on a started frame":   {Sequence: 1, Type: "action_started", Label: "document_search", Detail: "leaked before the call ran"},
		"request exceeds the bound":   {Sequence: 1, Type: "action_started", Label: "document_search", Request: overlong},
		"detail exceeds the bound":    {Sequence: 1, Type: "action_finished", Label: "document_search", Outcome: "succeeded", Detail: overlong},
	}
	for name, event := range cases {
		writer := &countingStreamWriter{ResponseRecorder: httptest.NewRecorder()}
		stream := newQuestionEventStream(writer)
		if err := stream.action(event); err == nil {
			t.Fatalf("%s: accepted an invalid action event: %+v", name, event)
		}
		if writer.Body.Len() != 0 {
			t.Fatalf("%s: an invalid frame was written before being rejected: %q", name, writer.Body.String())
		}
	}
}
