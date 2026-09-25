package failurelog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureLogs installs a JSON slog handler as the process default for one test
// and returns the buffer it writes to, so a test can assert on real structured
// server-log output instead of trusting a mock.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buffer := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buffer
}

func loggedLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := []map[string]any{}
	for _, raw := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("server log line is not JSON: %q: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestFiveHundredLeavesOneLineWithMethodRouteStatusAndCause(t *testing.T) {
	buffer := captureLogs(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		Set(writer, "workspace service: WORKSPACE_PERSISTENCE_FAILED")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":{"code":"SERVICE_UNAVAILABLE"}}`))
	})
	response := httptest.NewRecorder()

	WithFailureLog(next).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/api/v1/workspaces/ws_alpha?token=must-not-log", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("response status changed: %d", response.Code)
	}
	lines := loggedLines(t, buffer)
	if len(lines) != 1 {
		t.Fatalf("want exactly one failure line, got %d: %v", len(lines), lines)
	}
	line := lines[0]
	if line["msg"] != Message {
		t.Fatalf("msg=%v, want %q", line["msg"], Message)
	}
	if line["method"] != http.MethodGet {
		t.Fatalf("method=%v", line["method"])
	}
	if line["route"] != "/api/v1/workspaces/ws_alpha" {
		t.Fatalf("route=%v (the query string must never be logged)", line["route"])
	}
	if line["status"] != float64(http.StatusServiceUnavailable) {
		t.Fatalf("status=%v", line["status"])
	}
	if line["cause"] != "workspace service: WORKSPACE_PERSISTENCE_FAILED" {
		t.Fatalf("cause=%v", line["cause"])
	}
	if strings.Contains(buffer.String(), "must-not-log") {
		t.Fatalf("query value leaked into the log: %s", buffer.String())
	}
}

func TestResponsesBelowFiveHundredLeaveNoFailureLine(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusMovedPermanently, http.StatusNotFound, http.StatusTooManyRequests} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			buffer := captureLogs(t)
			next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				Set(writer, "must never be logged for a non-5xx")
				writer.WriteHeader(status)
			})
			WithFailureLog(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/anything", nil))
			if lines := loggedLines(t, buffer); len(lines) != 0 {
				t.Fatalf("status %d logged a failure line: %v", status, lines)
			}
		})
	}
}

func TestEachFiveHundredStatusLeavesExactlyOneLine(t *testing.T) {
	for _, status := range []int{
		http.StatusInternalServerError,
		http.StatusNotImplemented,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			buffer := captureLogs(t)
			next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				Set(writer, "storage component capability lost")
				writer.WriteHeader(status)
				_, _ = writer.Write([]byte("first"))
				_, _ = writer.Write([]byte("second"))
			})
			WithFailureLog(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", nil))
			lines := loggedLines(t, buffer)
			if len(lines) != 1 || lines[0]["status"] != float64(status) {
				t.Fatalf("status %d produced %v", status, lines)
			}
		})
	}
}

func TestCauseFallsBackInsteadOfLeavingTheLineUnnamed(t *testing.T) {
	buffer := captureLogs(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	})
	WithFailureLog(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/system/health", nil))
	lines := loggedLines(t, buffer)
	if len(lines) != 1 || lines[0]["cause"] != unclassifiedCause {
		t.Fatalf("lines=%v", lines)
	}
}

func TestFirstCauseWinsAndEmptyCauseIsIgnored(t *testing.T) {
	buffer := captureLogs(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		Set(writer, "")
		Set(writer, "first cause")
		Set(writer, "second cause")
		writer.WriteHeader(http.StatusBadGateway)
	})
	WithFailureLog(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	lines := loggedLines(t, buffer)
	if len(lines) != 1 || lines[0]["cause"] != "first cause" {
		t.Fatalf("lines=%v", lines)
	}
}

// TestFlushForwardingKeepsAStreamingFiveHundredIntact proves the recorder does
// not break http.ResponseController: the streaming question route flushes
// before its terminal write.
func TestFlushForwardingKeepsAStreamingFiveHundredIntact(t *testing.T) {
	buffer := captureLogs(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		Set(writer, "stream failed")
		writer.WriteHeader(http.StatusServiceUnavailable)
		if err := http.NewResponseController(writer).Flush(); err != nil {
			t.Errorf("flush through the failure recorder: %v", err)
		}
	})
	response := httptest.NewRecorder()
	WithFailureLog(next).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/stream", nil))
	if response.Code != http.StatusServiceUnavailable || response.Flushed != true {
		t.Fatalf("status=%d flushed=%v", response.Code, response.Flushed)
	}
	if lines := loggedLines(t, buffer); len(lines) != 1 {
		t.Fatalf("lines=%v", lines)
	}
}

// TestFlushBeforeWriteCommitsTwoHundredAndNoFailureLine proves the recorder
// tracks the status the client actually received: once a handler flushes, the
// response is 200 and a later ignored WriteHeader(5xx) must not invent a line.
func TestFlushBeforeWriteCommitsTwoHundredAndNoFailureLine(t *testing.T) {
	buffer := captureLogs(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(writer).Flush(); err != nil {
			t.Errorf("flush through the failure recorder: %v", err)
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	})
	response := httptest.NewRecorder()
	WithFailureLog(next).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/stream", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d, want the flushed 200", response.Code)
	}
	if lines := loggedLines(t, buffer); len(lines) != 0 {
		t.Fatalf("a 200 response produced a failure line: %v", lines)
	}
}

// TestFailureLineCarriesNoRequestSecret is the card's secret rule at the
// middleware itself: a password field, a session cookie and an authorization
// header value never reach the line, whatever the cause says.
func TestFailureLineCarriesNoRequestSecret(t *testing.T) {
	const (
		cookieSecret = "session-cookie-must-never-be-logged"
		bearerSecret = "bearer-must-never-be-logged"
		bodySecret   = "body-password-must-never-be-logged"
	)
	buffer := captureLogs(t)
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		Set(writer, "sign-in: AUTH_UNAVAILABLE")
		writer.WriteHeader(http.StatusServiceUnavailable)
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{"password":"`+bodySecret+`"}`))
	request.Header.Set("Cookie", "session="+cookieSecret)
	request.Header.Set("Authorization", "Bearer "+bearerSecret)
	WithFailureLog(next).ServeHTTP(httptest.NewRecorder(), request)
	captured := buffer.String()
	for _, secret := range []string{cookieSecret, bearerSecret, bodySecret} {
		if strings.Contains(captured, secret) {
			t.Fatalf("secret %q leaked into the server log: %s", secret, captured)
		}
	}
}
