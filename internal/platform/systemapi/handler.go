// Package systemapi implements the content-free HTTP endpoints declared in api/openapi.yaml.
package systemapi

import (
	"encoding/json"
	"net/http"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/failurelog"
)

const (
	HealthPath       = "/api/v1/system/health"
	BuildInfoPath    = "/api/v1/system/build-info"
	CapabilitiesPath = "/api/v1/system/capabilities"

	CapabilitiesSchemaVersion = "system-capabilities-v1"
)

type handler struct {
	build        buildinfo.Info
	capabilities CapabilityReport
}

type healthResponse struct {
	Status    string `json:"status"`
	Component string `json:"component"`
}

type buildInfoResponse struct {
	Version      string `json:"version"`
	Revision     string `json:"revision"`
	BuiltAt      string `json:"built_at"`
	GoVersion    string `json:"go_version"`
	GoExperiment string `json:"go_experiment"`
}

type errorResponse struct {
	ErrorCode string `json:"error_code"`
}

// CapabilityStatus is a deployment capability state, not a claim that a
// tenant has configured a source. The endpoint is deliberately content-free.
type CapabilityStatus string

const (
	CapabilityReady       CapabilityStatus = "READY"
	CapabilityPartial     CapabilityStatus = "PARTIAL"
	CapabilityBlocked     CapabilityStatus = "BLOCKED"
	CapabilityUnavailable CapabilityStatus = "UNAVAILABLE"
)

// Capability is an immutable, content-free projection of one server-owned
// capability. ReasonCode is a stable operator vocabulary and never contains
// an endpoint, secret, tenant identifier, or dependency response body.
type Capability struct {
	ID         string           `json:"id"`
	Status     CapabilityStatus `json:"status"`
	ReasonCode string           `json:"reason_code,omitempty"`
}

// CapabilityReport is the only data returned by CapabilitiesPath. It is a
// startup snapshot: the production composition creates it from the actual
// mounted adapters, while deferred external qualifications remain explicit.
type CapabilityReport struct {
	SchemaVersion   string       `json:"schema_version"`
	Component       string       `json:"component"`
	ReleaseEligible bool         `json:"release_eligible"`
	Capabilities    []Capability `json:"capabilities"`
}

// RuntimeCapabilities builds the content-free report for a composed server.
// Every READY state below means the corresponding server-owned adapter was
// constructed successfully; it does not bypass source-level RBAC or tenant
// configuration. Vector retrieval is PARTIAL until a qualified embedding
// profile is actually mounted. Enterprise release is always closed here:
// external qualification and owner acceptance are not process-local facts.
func RuntimeCapabilities(vectorReady bool) CapabilityReport {
	vectorStatus := CapabilityPartial
	vectorReason := "EMBEDDING_PROFILE_UNAVAILABLE"
	if vectorReady {
		vectorStatus = CapabilityReady
		vectorReason = ""
	}
	return CapabilityReport{
		SchemaVersion:   CapabilitiesSchemaVersion,
		Component:       "knowvault-server",
		ReleaseEligible: false,
		Capabilities: []Capability{
			{ID: "workspace_rbac", Status: CapabilityReady},
			{ID: "rest_api", Status: CapabilityReady},
			{ID: "mcp_interface", Status: CapabilityReady},
			{ID: "lexical_retrieval", Status: CapabilityReady},
			{ID: "entity_relationship_retrieval", Status: CapabilityReady},
			{ID: "semantic_catalog", Status: CapabilityReady},
			{ID: "generic_planner", Status: CapabilityReady},
			{ID: "safe_sql_analytics", Status: CapabilityReady},
			{ID: "evidence_bound_answers", Status: CapabilityReady},
			{ID: "vector_retrieval", Status: vectorStatus, ReasonCode: vectorReason},
			{ID: "generative_model_gateway", Status: CapabilityBlocked, ReasonCode: "MODEL_PROFILE_UNAVAILABLE"},
			{ID: "office_pdf_ocr", Status: CapabilityBlocked, ReasonCode: "QUALIFICATION_REQUIRED"},
			{ID: "mail_ingestion", Status: CapabilityBlocked, ReasonCode: "TENANT_CREDENTIALS_UNAVAILABLE"},
			{ID: "git_code_ingestion", Status: CapabilityBlocked, ReasonCode: "TENANT_CREDENTIALS_UNAVAILABLE"},
			{ID: "oidc_runtime", Status: CapabilityReady},
			{ID: "enterprise_oidc", Status: CapabilityBlocked, ReasonCode: "CUSTOMER_IDP_ACCEPTANCE_REQUIRED"},
			{ID: "source_health", Status: CapabilityReady},
			{ID: "enterprise_release_gate", Status: CapabilityBlocked, ReasonCode: "EXTERNAL_QUALIFICATION_REQUIRED"},
		},
	}
}

func validCapabilityReport(report CapabilityReport) bool {
	if report.SchemaVersion != CapabilitiesSchemaVersion || report.Component != "knowvault-server" ||
		report.ReleaseEligible || len(report.Capabilities) == 0 || len(report.Capabilities) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(report.Capabilities))
	for _, capability := range report.Capabilities {
		if !validCapabilityID(capability.ID) || capability.Status == "" || capability.ReasonCode != "" && !validReasonCode(capability.ReasonCode) {
			return false
		}
		switch capability.Status {
		case CapabilityReady, CapabilityPartial, CapabilityBlocked, CapabilityUnavailable:
		default:
			return false
		}
		if _, exists := seen[capability.ID]; exists {
			return false
		}
		seen[capability.ID] = struct{}{}
	}
	return true
}

func validCapabilityID(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validReasonCode(value string) bool {
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func cloneCapabilityReport(report CapabilityReport) CapabilityReport {
	report.Capabilities = append([]Capability(nil), report.Capabilities...)
	return report
}

// New returns a handler with no business routes, middleware, CORS, or debug surface.
func New(build buildinfo.Info, reports ...CapabilityReport) http.Handler {
	report := RuntimeCapabilities(false)
	if len(reports) > 0 && validCapabilityReport(reports[0]) {
		report = cloneCapabilityReport(reports[0])
	}
	return handler{build: build, capabilities: report}
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setResponseHeaders(w)

	switch r.URL.EscapedPath() {
	case HealthPath:
		if !requireGET(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, healthResponse{
			Status:    "UP",
			Component: "knowvault-server",
		})
	case BuildInfoPath:
		if !requireGET(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, buildInfoResponse{
			Version:      h.build.Version,
			Revision:     h.build.Revision,
			BuiltAt:      h.build.BuiltAt,
			GoVersion:    h.build.GoVersion,
			GoExperiment: h.build.GoExperiment,
		})
	case CapabilitiesPath:
		if !requireGET(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, h.capabilities)
	default:
		writeJSON(w, http.StatusNotFound, errorResponse{ErrorCode: "NOT_FOUND"})
	}
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.Header().Set("Allow", http.MethodGet)
	writeJSON(w, http.StatusMethodNotAllowed, errorResponse{ErrorCode: "METHOD_NOT_ALLOWED"})
	return false
}

func setResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		failurelog.Set(w, "system endpoint: response encoding failed")
		body = []byte(`{"error_code":"RESPONSE_ENCODING_FAILED"}`)
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
