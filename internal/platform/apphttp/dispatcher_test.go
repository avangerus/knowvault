package apphttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/systemapi"
)

func TestDispatcherRoutesOnlyExactSpecialisedPaths(t *testing.T) {
	for name, route := range map[string]struct {
		requestURL string
		want       string
	}{
		"login":                           {"https://workspace.example/auth/login", "auth"},
		"callback":                        {"https://workspace.example/auth/callback", "auth"},
		"logout":                          {"https://workspace.example/auth/logout", "auth"},
		"system health":                   {"https://workspace.example" + systemapi.HealthPath, "system"},
		"system build information":        {"https://workspace.example" + systemapi.BuildInfoPath, "system"},
		"system capabilities":             {"https://workspace.example" + systemapi.CapabilitiesPath, "system"},
		"workspace":                       {"https://workspace.example/api/v1/workspaces", "workspace"},
		"unknown api":                     {"https://workspace.example/api/v1/system/unknown", "workspace"},
		"root ui":                         {"https://workspace.example/", "ui"},
		"system trailing slash workspace": {"https://workspace.example" + systemapi.BuildInfoPath + "/", "workspace"},
		"encoded api delimiter workspace": {"https://workspace.example/api%2fv1%2fworkspaces", "workspace"},
		"bare api workspace":              {"https://workspace.example/api", "workspace"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := make([]string, 0, 1)
			dispatcher := testDispatcher(t, &calls)
			response := httptest.NewRecorder()
			dispatcher.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route.requestURL, nil))
			if len(calls) != 1 || calls[0] != route.want {
				t.Fatalf("calls=%v want=%q", calls, route.want)
			}
			if response.Code != http.StatusNoContent || response.Header().Get("Location") != "" {
				t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
		})
	}
}

func TestDispatcherReservesEntireAuthNamespaceFromTheSPA(t *testing.T) {
	for name, requestURL := range map[string]string{
		"bare auth":              "https://workspace.example/auth",
		"unknown auth":           "https://workspace.example/auth/forgot",
		"trailing auth login":    "https://workspace.example/auth/login/",
		"encoded auth alias":     "https://workspace.example/auth/%6cogin",
		"encoded auth delimiter": "https://workspace.example/auth%2flogin",
	} {
		t.Run(name, func(t *testing.T) {
			calls := make([]string, 0, 1)
			dispatcher := testDispatcher(t, &calls)
			response := httptest.NewRecorder()
			dispatcher.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestURL, nil))
			if len(calls) != 0 || response.Code != http.StatusNotFound || response.Body.String() != "not found\n" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("calls=%v status=%d body=%q headers=%v", calls, response.Code, response.Body.String(), response.Header())
			}
		})
	}
}

func TestDispatcherRejectsMissingAndTypedNilDependencies(t *testing.T) {
	handler := namedHandler{name: "valid"}
	for name, dependencies := range map[string][]http.Handler{
		"nil auth":      {nil, handler, handler, handler},
		"nil system":    {handler, nil, handler, handler},
		"nil workspace": {handler, handler, nil, handler},
		"nil ui":        {handler, handler, handler, nil},
		"typed nil":     {(*nilHandler)(nil), handler, handler, handler},
	} {
		t.Run(name, func(t *testing.T) {
			if dispatcher, err := New(dependencies[0], dependencies[1], dependencies[2], dependencies[3]); err == nil || dispatcher != nil {
				t.Fatalf("dispatcher=%#v err=%v", dispatcher, err)
			}
		})
	}
}

func TestDispatcherFormattingIsRedacted(t *testing.T) {
	var calls []string
	dispatcher := testDispatcher(t, &calls)
	for _, formatted := range []string{fmt.Sprint(dispatcher), fmt.Sprintf("%#v", dispatcher)} {
		if !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("dispatcher formatting=%q", formatted)
		}
	}
}

func testDispatcher(t *testing.T, calls *[]string) *Dispatcher {
	t.Helper()
	dispatcher, err := New(
		namedHandler{name: "auth", calls: calls}, namedHandler{name: "system", calls: calls}, namedHandler{name: "workspace", calls: calls}, namedHandler{name: "ui", calls: calls},
	)
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

type namedHandler struct {
	name  string
	calls *[]string
}

func (handler namedHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	*handler.calls = append(*handler.calls, handler.name)
	writer.WriteHeader(http.StatusNoContent)
}

type nilHandler struct{}

func (*nilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}
