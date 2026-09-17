// Mandatory response security headers (D7-8). Every response of the
// application boundary — auth, system, workspace API, UI and the dispatcher's
// own 404 — carries Content-Security-Policy, X-Frame-Options and
// Strict-Transport-Security. The middleware pre-sets the headers before the
// child runs and re-checks them at the first write, so a child that streams a
// body without an explicit status, or one that deletes a header, still cannot
// publish a response without the full set. A child-provided value (if ever
// stricter) is never overwritten.
package apphttp

import "net/http"

const (
	// contentSecurityPolicy is the minimal self-contained policy: the SPA may
	// load only same-origin scripts, styles, connections and forms; images may
	// additionally carry inline data; nothing else (objects, embedding,
	// base-URI rewriting) is permitted.
	contentSecurityPolicy   = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	strictTransportSecurity = "max-age=31536000; includeSubDomains"
	frameOptions            = "DENY"
)

// WithSecurityHeaders guarantees the D7-8 header set on every response the
// wrapped handler produces.
func WithSecurityHeaders(next http.Handler) http.Handler {
	if next == nil {
		return nil
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		applySecurityHeaders(writer.Header())
		guarded := &securityHeaderWriter{ResponseWriter: writer}
		next.ServeHTTP(guarded, request)
	})
}

func applySecurityHeaders(header http.Header) {
	if header.Get("Content-Security-Policy") == "" {
		header.Set("Content-Security-Policy", contentSecurityPolicy)
	}
	if header.Get("X-Frame-Options") == "" {
		header.Set("X-Frame-Options", frameOptions)
	}
	if header.Get("Strict-Transport-Security") == "" {
		header.Set("Strict-Transport-Security", strictTransportSecurity)
	}
}

// securityHeaderWriter re-applies the header set at the moment the response is
// committed, so a child that removed or never wrote headers still yields a
// complete set.
type securityHeaderWriter struct {
	http.ResponseWriter
	wrote bool
}

func (writer *securityHeaderWriter) WriteHeader(status int) {
	applySecurityHeaders(writer.Header())
	writer.wrote = true
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *securityHeaderWriter) Write(body []byte) (int, error) {
	if !writer.wrote {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}
