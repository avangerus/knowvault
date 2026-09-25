// Package failurelog owns the single content-free server-log line for every
// 5xx response an HTTP boundary produces. Before it existed a storage or
// capability failure the composition had silently lost answered the operator
// with a bare 503 and left nothing in the log, so the cause could only be found
// by reproducing the request in a browser and reading code.
//
// The middleware captures the response status and the handler-supplied cause
// and emits exactly one structured line per 5xx. The cause is a short,
// server-owned phrase or typed code; a handler never passes a request body,
// header, session value, credential or error message, so the line can never
// carry tenant content.
package failurelog

import (
	"log/slog"
	"net/http"
)

const (
	// Message is the exact server-log message of the one line per 5xx. It is
	// stable so an operator alert or a log query can anchor on it.
	Message = "http request failed"

	component = "knowvault-server"

	// unclassifiedCause is the closed fallback for the (unreachable in
	// production) case of a 5xx that no handler annotated: the line still
	// names the request and status instead of staying silent.
	unclassifiedCause = "unclassified server failure"
)

// Recorder is implemented by the response writer the middleware installs. A
// handler that is about to answer 5xx records a short, content-free cause
// naming what failed.
type Recorder interface {
	SetFailureCause(cause string)
}

// Set records cause on the writer's failure recorder. It is a no-op for any
// other writer (httptest recorders, boundaries assembled without the
// middleware), so a handler stays correct in isolation. The first non-empty
// cause wins, so a handler that knows the typed cause sets it before a generic
// fallback.
func Set(writer http.ResponseWriter, cause string) {
	if writer == nil || cause == "" {
		return
	}
	if recorder, ok := writer.(Recorder); ok {
		recorder.SetFailureCause(cause)
	}
}

// WithFailureLog wraps next so exactly one structured line is emitted for
// every response whose status is 5xx. The line names the request method and
// route, the status and the cause. Responses below 500 are untouched.
func WithFailureLog(next http.Handler) http.Handler {
	if next == nil {
		return nil
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder := &failureRecorder{ResponseWriter: writer}
		next.ServeHTTP(recorder, request)
		if recorder.status < http.StatusInternalServerError {
			return
		}
		cause := recorder.cause
		if cause == "" {
			cause = unclassifiedCause
		}
		slog.Error(Message,
			"component", component,
			"method", requestMethod(request),
			"route", requestRoute(request),
			"status", recorder.status,
			"cause", cause,
		)
	})
}

func requestMethod(request *http.Request) string {
	if request == nil {
		return ""
	}
	return request.Method
}

// requestRoute is the decoded path only: never a query string, header or body.
func requestRoute(request *http.Request) string {
	if request == nil || request.URL == nil {
		return ""
	}
	return request.URL.Path
}

// failureRecorder records the first status the handler commits and the first
// content-free cause it annotates, while forwarding the response unchanged.
type failureRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	cause  string
}

func (recorder *failureRecorder) SetFailureCause(cause string) {
	if recorder.cause == "" && cause != "" {
		recorder.cause = cause
	}
}

func (recorder *failureRecorder) WriteHeader(status int) {
	if !recorder.wrote {
		recorder.status = status
		recorder.wrote = true
	}
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *failureRecorder) Write(body []byte) (int, error) {
	if !recorder.wrote {
		recorder.status = http.StatusOK
		recorder.wrote = true
	}
	return recorder.ResponseWriter.Write(body)
}

// Unwrap lets http.ResponseController reach the wrapped writer's capabilities
// (for example the streaming question route's flush).
func (recorder *failureRecorder) Unwrap() http.ResponseWriter {
	return recorder.ResponseWriter
}

// FlushError preserves streaming behaviour: a handler that flushes before
// writing still commits a real status on the wrapped writer.
func (recorder *failureRecorder) FlushError() error {
	return http.NewResponseController(recorder.ResponseWriter).Flush()
}
