package systemapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
)

func TestHealthResponseMatchesContract(t *testing.T) {
	t.Parallel()

	recorder := performRequest(t, http.MethodGet, HealthPath)
	assertCommonHeaders(t, recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got, want := recorder.Body.String(), "{\"status\":\"UP\",\"component\":\"knowvault-server\"}\n"; got != want {
		t.Fatalf("health body = %q, want %q", got, want)
	}
}

func TestBuildInfoResponseMatchesContract(t *testing.T) {
	t.Parallel()

	h := New(buildinfo.Info{
		Version:      "1.2.3",
		Revision:     "abc123",
		BuiltAt:      "2026-07-14T12:00:00Z",
		GoVersion:    "go1.26.5",
		GoExperiment: "jsonv2",
	})
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, BuildInfoPath, nil))

	assertCommonHeaders(t, recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("build-info status = %d, want %d", recorder.Code, http.StatusOK)
	}
	want := "{\"version\":\"1.2.3\",\"revision\":\"abc123\",\"built_at\":\"2026-07-14T12:00:00Z\",\"go_version\":\"go1.26.5\",\"go_experiment\":\"jsonv2\"}\n"
	if got := recorder.Body.String(); got != want {
		t.Fatalf("build-info body = %q, want %q", got, want)
	}
}

func TestCapabilitiesResponseMatchesRuntimeSnapshot(t *testing.T) {
	t.Parallel()

	want := RuntimeCapabilities(false)
	h := New(buildinfo.Info{}, want)
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, CapabilitiesPath, nil))

	assertCommonHeaders(t, recorder)
	if recorder.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var got CapabilityReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("capabilities JSON: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
	if strings.Contains(recorder.Body.String(), "https://") || strings.Contains(recorder.Body.String(), "password") ||
		strings.Contains(recorder.Body.String(), "client_cert") || strings.Contains(recorder.Body.String(), "endpoint") {
		t.Fatalf("capabilities response contains deployment or tenant detail: %s", recorder.Body.String())
	}
}

func TestRuntimeCapabilitiesVectorStateIsTruthful(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		vectorReady bool
		wantStatus  CapabilityStatus
		wantReason  string
	}{
		{name: "missing profile remains partial", vectorReady: false, wantStatus: CapabilityPartial, wantReason: "EMBEDDING_PROFILE_UNAVAILABLE"},
		{name: "mounted profile is ready", vectorReady: true, wantStatus: CapabilityReady},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := RuntimeCapabilities(test.vectorReady)
			var vector Capability
			for _, capability := range report.Capabilities {
				if capability.ID == "vector_retrieval" {
					vector = capability
					break
				}
			}
			if vector.Status != test.wantStatus || vector.ReasonCode != test.wantReason {
				t.Fatalf("vector capability = %#v, want status=%s reason=%q", vector, test.wantStatus, test.wantReason)
			}
		})
	}
}

func TestInvalidCapabilityReportFallsBackClosed(t *testing.T) {
	t.Parallel()

	invalid := RuntimeCapabilities(true)
	invalid.ReleaseEligible = true
	h := New(buildinfo.Info{}, invalid)
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, CapabilitiesPath, nil))
	var got CapabilityReport
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("capabilities JSON: %v", err)
	}
	if got.ReleaseEligible {
		t.Fatal("invalid report enabled release eligibility")
	}
	if got.SchemaVersion != CapabilitiesSchemaVersion || !validCapabilityReport(got) {
		t.Fatalf("fallback report is invalid: %#v", got)
	}
}

func TestCapabilitiesEndpointRejectsNonGETAndEncodedAliases(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodOptions} {
		recorder := performRequest(t, method, CapabilitiesPath)
		assertCommonHeaders(t, recorder)
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s capabilities status = %d, want %d", method, recorder.Code, http.StatusMethodNotAllowed)
		}
		if got := recorder.Header().Get("Allow"); got != http.MethodGet {
			t.Fatalf("%s capabilities Allow = %q, want %q", method, got, http.MethodGet)
		}
	}
	for _, path := range []string{"/api/v1/system/%63apabilities", CapabilitiesPath + "/"} {
		recorder := performRequest(t, http.MethodGet, path)
		assertCommonHeaders(t, recorder)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("encoded capability path %q status = %d, want %d", path, recorder.Code, http.StatusNotFound)
		}
	}
}

func TestSystemEndpointsAreGETOnly(t *testing.T) {
	t.Parallel()

	for _, path := range []string{HealthPath, BuildInfoPath, CapabilitiesPath} {
		path := path
		for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodOptions} {
			method := method
			t.Run(method+" "+path, func(t *testing.T) {
				t.Parallel()

				recorder := performRequest(t, method, path)
				assertCommonHeaders(t, recorder)
				if recorder.Code != http.StatusMethodNotAllowed {
					t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
				}
				if got := recorder.Header().Get("Allow"); got != http.MethodGet {
					t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
				}
				if got, want := recorder.Body.String(), "{\"error_code\":\"METHOD_NOT_ALLOWED\"}\n"; got != want {
					t.Fatalf("body = %q, want %q", got, want)
				}
			})
		}
	}
}

func TestUnknownRouteHasNoDebugOrCORSSurface(t *testing.T) {
	t.Parallel()

	recorder := performRequest(t, http.MethodGet, "/api/v1/debug")
	assertCommonHeaders(t, recorder)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if got, want := recorder.Body.String(), "{\"error_code\":\"NOT_FOUND\"}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	for _, name := range []string{"Access-Control-Allow-Origin", "Server", "X-Powered-By"} {
		if value := recorder.Header().Get(name); value != "" {
			t.Fatalf("unexpected %s header: %q", name, value)
		}
	}
}

func TestEncodedPathAliasIsNotAnEndpoint(t *testing.T) {
	t.Parallel()

	recorder := performRequest(t, http.MethodGet, "/api/v1/system/%68ealth")
	assertCommonHeaders(t, recorder)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if got, want := recorder.Body.String(), "{\"error_code\":\"NOT_FOUND\"}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func performRequest(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()

	h := New(buildinfo.Info{})
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

func assertCommonHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()

	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Content-Type":           "application/json",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}
