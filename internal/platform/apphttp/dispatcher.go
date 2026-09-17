// Package apphttp selects one already-composed HTTP boundary without cleaning
// paths, inferring tenant identity, or falling back to the process-global mux.
package apphttp

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/systemapi"
)

const apiPrefix = "/api/"

// Dispatcher is the explicit root router for the small set of application
// boundaries.  Each child owns its own method and request validation.
type Dispatcher struct {
	auth      http.Handler
	system    http.Handler
	workspace http.Handler
	ui        http.Handler
}

func (Dispatcher) String() string   { return "apphttp.Dispatcher{[REDACTED]}" }
func (Dispatcher) GoString() string { return "apphttp.Dispatcher{[REDACTED]}" }

// New requires every boundary explicitly.  A nil dependency is a composition
// failure, never a reason to silently install DefaultServeMux or a fallback.
func New(auth, system, workspace, ui http.Handler) (*Dispatcher, error) {
	if unavailable(auth) || unavailable(system) || unavailable(workspace) || unavailable(ui) {
		return nil, errors.New("apphttp: dependencies are required")
	}
	return &Dispatcher{auth: auth, system: system, workspace: workspace, ui: ui}, nil
}

// ServeHTTP leaves escaped aliases unnormalised. The complete /auth and /api
// namespaces are reserved: only the three exact auth paths may reach OIDC,
// only exact system paths may reach systemapi, and all remaining API paths
// reach workspace so it can return its own exact API denial. Ambiguous auth
// aliases must never fall through to the SPA.
func (dispatcher *Dispatcher) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if dispatcher == nil || request == nil || request.URL == nil {
		return
	}
	if exactPath(request, "/auth/login") || exactPath(request, "/auth/callback") || exactPath(request, "/auth/logout") {
		dispatcher.auth.ServeHTTP(writer, request)
		return
	}
	if inNamespace(request, "/auth") {
		writeNotFound(writer)
		return
	}
	if exactPath(request, systemapi.HealthPath) || exactPath(request, systemapi.BuildInfoPath) || exactPath(request, systemapi.CapabilitiesPath) {
		dispatcher.system.ServeHTTP(writer, request)
		return
	}
	if inNamespace(request, strings.TrimSuffix(apiPrefix, "/")) {
		dispatcher.workspace.ServeHTTP(writer, request)
		return
	}
	dispatcher.ui.ServeHTTP(writer, request)
}

func exactPath(request *http.Request, value string) bool {
	return request != nil && request.URL != nil && request.URL.Path == value && request.URL.RawPath == "" && request.URL.Opaque == ""
}

func inNamespace(request *http.Request, namespace string) bool {
	return request != nil && request.URL != nil && (request.URL.Path == namespace || strings.HasPrefix(request.URL.Path, namespace+"/"))
}

func writeNotFound(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(writer, "not found\n")
}

func unavailable(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
