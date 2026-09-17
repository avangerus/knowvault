package oidctransport

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrowserTransportIssuesOpensAndClearsExactCookieProfile(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(bytes.Repeat([]byte{0x71}, nonceBytes*2)), now)
	transport, err := NewBrowserTransport(codec)
	if err != nil {
		t.Fatal(err)
	}
	transport.now = func() time.Time { return now }
	record := testRecord(t, now)
	response := httptest.NewRecorder()
	prepared, err := transport.Prepare(record)
	if err != nil {
		t.Fatal(err)
	}
	prepared.WriteOnce(response)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != CookieName || cookie.Value == "" || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode ||
		!cookie.Expires.Equal(record.ExpiresAt().Truncate(time.Second)) || cookie.MaxAge != int(record.ExpiresAt().Truncate(time.Second).Sub(now)/time.Second) {
		t.Fatalf("cookie=%#v", cookie)
	}
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback", nil)
	request.Header.Set("Cookie", "other=value; "+CookieName+"="+cookie.Value)
	opened, err := transport.OpenRequest(request)
	if err != nil || opened.AttemptID() != record.AttemptID() {
		t.Fatalf("opened=%#v err=%v", opened, err)
	}
	cleared := httptest.NewRecorder()
	transport.Clear(cleared)
	deleted := cleared.Result().Cookies()
	if len(deleted) != 1 || deleted[0].Name != CookieName || deleted[0].Value != "" || deleted[0].MaxAge != -1 || !deleted[0].Secure || !deleted[0].HttpOnly || deleted[0].SameSite != http.SameSiteLaxMode || deleted[0].Path != "/" || deleted[0].Domain != "" {
		t.Fatalf("deletion cookie=%#v", deleted)
	}
	for _, formatted := range []string{fmt.Sprint(transport), fmt.Sprintf("%#v", transport), fmt.Sprint(prepared), fmt.Sprintf("%#v", prepared)} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, cookie.Value) {
			t.Fatalf("transport formatting leaked envelope: %q", formatted)
		}
	}
}

func TestBrowserTransportRejectsDuplicateMissingMalformedAndOversizedCookies(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(bytes.Repeat([]byte{0x72}, nonceBytes*4)), now)
	transport, err := NewBrowserTransport(codec)
	if err != nil {
		t.Fatal(err)
	}
	transport.now = func() time.Time { return now }
	response := httptest.NewRecorder()
	prepared, err := transport.Prepare(testRecord(t, now))
	if err != nil {
		t.Fatal(err)
	}
	prepared.WriteOnce(response)
	value := response.Result().Cookies()[0].Value

	for name, configure := range map[string]func(*http.Request){
		"missing": func(*http.Request) {},
		"two headers": func(request *http.Request) {
			request.Header.Add("Cookie", CookieName+"="+value)
			request.Header.Add("Cookie", "other=value")
		},
		"duplicate target": func(request *http.Request) {
			request.Header.Set("Cookie", CookieName+"="+value+"; "+CookieName+"="+value)
		},
		"malformed sibling": func(request *http.Request) {
			request.Header.Set("Cookie", CookieName+"="+value+"; malformed")
		},
		"trailing empty pair": func(request *http.Request) {
			request.Header.Set("Cookie", CookieName+"="+value+";")
		},
		"quoted target": func(request *http.Request) {
			request.Header.Set("Cookie", CookieName+`="`+value+`"`)
		},
		"oversized header": func(request *http.Request) {
			request.Header.Set("Cookie", strings.Repeat("x", maxCookieHeaderBytes+1))
		},
		"tampered envelope": func(request *http.Request) {
			replacement := "A"
			if strings.HasSuffix(value, replacement) {
				replacement = "B"
			}
			request.Header.Set("Cookie", CookieName+"="+value[:len(value)-1]+replacement)
		},
	} {
		name, configure := name, configure
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback", nil)
			configure(request)
			if _, err := transport.OpenRequest(request); CodeOf(err) != CodeOpenRejected {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestBrowserTransportPreparesBeforeCommitAndIssuesCapabilityOnlyOnce(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(bytes.Repeat([]byte{0x73}, nonceBytes)), now)
	transport, err := NewBrowserTransport(codec)
	if err != nil {
		t.Fatal(err)
	}
	transport.now = func() time.Time { return now.Add(6 * time.Minute) }
	response := httptest.NewRecorder()
	if prepared, err := transport.Prepare(testRecord(t, now)); CodeOf(err) != CodeSealFailed || prepared != nil {
		t.Fatalf("invalid prepare succeeded: %#v err=%v", prepared, err)
	}
	transport.now = func() time.Time { return now }
	prepared, err := transport.Prepare(testRecord(t, now))
	if err != nil {
		t.Fatal(err)
	}
	transport.now = func() time.Time { panic("Issue must not consult the clock") }
	concrete := prepared.(*preparedCookie)
	preparedCopy := *concrete
	prepared.WriteOnce(response)
	preparedCopy.WriteOnce(response)
	(*preparedCookie)(nil).WriteOnce(response)
	if len(response.Header().Values("Set-Cookie")) != 1 {
		t.Fatalf("capability was not one-shot: %v", response.Header().Values("Set-Cookie"))
	}
	if _, err := NewBrowserTransport(nil); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("nil codec accepted: %v", err)
	}
}
