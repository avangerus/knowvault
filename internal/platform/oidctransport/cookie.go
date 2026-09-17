package oidctransport

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const maxCookieHeaderBytes = 4096

// BrowserTransport is the only reviewed HTTP projection of the sealed OIDC
// envelope. It owns the exact cookie profile, strict single-cookie parsing and
// deletion semantics; it does not own login sequencing.
type BrowserTransport struct {
	codec *Codec
	now   func() time.Time
}

// PreparedCookie is an opaque one-shot capability sealed before BeginLogin.
// Its only operation cannot fail and is called after the durable commit.
type PreparedCookie interface {
	WriteOnce(http.ResponseWriter)
}

type preparedCookie struct {
	state *preparedCookieState
}

type preparedCookieState struct {
	header string
	used   atomic.Bool
}

func (preparedCookie) String() string   { return "oidctransport.PreparedCookie{[REDACTED]}" }
func (preparedCookie) GoString() string { return "oidctransport.PreparedCookie{[REDACTED]}" }

func (BrowserTransport) String() string   { return "oidctransport.BrowserTransport{[REDACTED]}" }
func (BrowserTransport) GoString() string { return "oidctransport.BrowserTransport{[REDACTED]}" }

func NewBrowserTransport(codec *Codec) (*BrowserTransport, error) {
	if codec == nil || !codec.valid() {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	return &BrowserTransport{codec: codec, now: time.Now}, nil
}

// Prepare seals and validates the cookie before BeginLogin. It performs no
// HTTP write, so a crypto failure cannot leave a durable orphan attempt.
func (transport *BrowserTransport) Prepare(record Record) (PreparedCookie, error) {
	if transport == nil || transport.codec == nil || transport.now == nil {
		return nil, &Error{code: CodeSealFailed}
	}
	now := transport.now().UTC()
	expires := record.expiresAt.UTC().Truncate(time.Second)
	lifetime := expires.Sub(now)
	maxAge := int(lifetime / time.Second)
	if maxAge < 1 || lifetime > maxAttemptLifetime || time.Duration(maxAge)*time.Second > lifetime {
		return nil, &Error{code: CodeSealFailed}
	}
	envelope, err := transport.codec.Seal(record)
	if err != nil {
		return nil, &Error{code: CodeSealFailed}
	}
	if len(envelope) == 0 || len(envelope) > maxEnvelopeBytes {
		return nil, &Error{code: CodeSealFailed}
	}
	header := (&http.Cookie{
		Name: CookieName, Value: envelope, Path: "/", Expires: expires, MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}).String()
	if header == "" {
		return nil, &Error{code: CodeSealFailed}
	}
	return &preparedCookie{state: &preparedCookieState{header: header}}, nil
}

// WriteOnce is deliberately a no-error, no-clock, write-only step. Prepare has
// already completed every operation that may fail before BeginLogin commits.
// Copies share the same private one-shot state.
func (prepared *preparedCookie) WriteOnce(writer http.ResponseWriter) {
	if prepared == nil || prepared.state == nil || writer == nil || prepared.state.header == "" || !prepared.state.used.CompareAndSwap(false, true) {
		return
	}
	writer.Header().Add("Set-Cookie", prepared.state.header)
}

// OpenRequest accepts exactly one Cookie header and exactly one transport
// cookie within it. Other well-formed cookies are allowed.
func (transport *BrowserTransport) OpenRequest(request *http.Request) (Record, error) {
	if transport == nil || transport.codec == nil || request == nil {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	headers := exactHeaderValues(request.Header, "Cookie")
	if len(headers) != 1 || len(headers[0]) == 0 || len(headers[0]) > maxCookieHeaderBytes {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	cookies, err := http.ParseCookie(headers[0])
	if err != nil {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	value := ""
	count := 0
	for _, cookie := range cookies {
		if cookie.Quoted {
			return Record{}, &Error{code: CodeOpenRejected}
		}
		if cookie.Name == CookieName {
			count++
			value = cookie.Value
		}
	}
	if count != 1 || len(value) == 0 || len(value) > maxEnvelopeBytes {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	return transport.codec.Open(value)
}

// Clear invalidates the browser transport on every callback outcome.
func (transport *BrowserTransport) Clear(writer http.ResponseWriter) {
	if writer == nil {
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func exactHeaderValues(header http.Header, name string) []string {
	var values []string
	for key, items := range header {
		if strings.EqualFold(key, name) {
			values = append(values, items...)
		}
	}
	return values
}
