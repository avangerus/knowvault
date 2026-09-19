package modelgateway

// This file adds one additive, clearly-labelled capability: a plain
// OpenAI-compatible chat-completions adapter for the GEN-1 slice (ADR-0088).
//
// It is NOT the ADR-0080 production remote-peer path. It does not use mutual
// TLS, dedicated CA/client-identity mounts, egress-deny enforcement or a
// qualified/hashed model artifact, and it must never be presented as such. It
// exists only so the already-designed evidence-bounded ClaimPlan contract
// (GenerateRequest/ClaimPlan/ClaimPlan.Validate, unchanged in this file) has a
// real, testable implementation while a fully qualified generator/verifier
// pair per ADR-0080 remains outstanding. Composition wires it only behind an
// explicit administrator-provisioned mount (see mount_lab.go) that requires an
// explicit acknowledgement; it is never reachable from request data, and it
// carries no tool schema, credential or prior Question Run content.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// LabAdapterSchemaVersion tags the config shape so a mistaken production
	// mount (see mount_lab.go) fails closed instead of silently parsing.
	LabAdapterSchemaVersion = "model-gateway-lab-adapter-v1"

	labMinTimeout = time.Second
	labMaxTimeout = 240 * time.Second
	// labMaxOutputTokens is deliberately independent of the shared
	// gateway.MaxOutputTokens (the ADR-0080 production-path bound): this
	// interim adapter's endpoint (observed as deepseek-v4-flash) is a
	// reasoning model whose hidden chain-of-thought consumes the output
	// token budget before any answer content is emitted, so a real bounded
	// attempt against real multi-fragment Evidence needs materially more
	// headroom than the 2,048-token production cap to reliably reach
	// finish_reason "stop" instead of a mid-answer truncation ("length").
	// This is a GEN-2 lab-path bound only; it does not change or reuse the
	// ADR-0080 production constant.
	labMaxOutputTokens       = 32768
	labMaxModelIDBytes       = 256
	labMaxAPIKeyBytes        = 4096
	labMaxResponseBytes      = MaxResponseBytes
	labMaxAttemptsPerCall    = 2
	labMaxExternalWorkspaces = 8

	// RuntimeScopeLocalLab is the default: the adapter's endpoint is a
	// loopback/private-network address on the operator's own bounded lab
	// network, reachable from any workspace exactly as before GEN-2.
	RuntimeScopeLocalLab = "LOCAL_LAB"
	// RuntimeScopeExternalWorkspaceScoped means the endpoint is a public,
	// non-private destination (e.g. a third-party chat-completions API). This
	// is never the default: it is only reachable at all when the mounted
	// config explicitly lists the exact workspace IDs allowed to use it
	// (ExternalRuntimeWorkspaceIDs), and every other workspace on the same
	// deployment keeps GENERATIVE unsupported even though the process-wide
	// adapter is wired.
	RuntimeScopeExternalWorkspaceScoped = "EXTERNAL_WORKSPACE_SCOPED"
)

// ThinkingMode selects the provider's explicit reasoning mode for the lab
// adapter. The mounted GEN-2 configuration must set one of these values;
// only direct local generic-lab configurations may leave it empty.
type ThinkingMode string

const (
	ThinkingModeDisabled ThinkingMode = "disabled"
	ThinkingModeEnabled  ThinkingMode = "enabled"
)

func (mode ThinkingMode) valid() bool {
	return mode == ThinkingModeDisabled || mode == ThinkingModeEnabled
}

// StructuredOutputMode selects how the lab adapter asks the provider for a
// structured (machine-parseable) completion. It is a typed, closed set: the
// zero value is valid and maps to StructuredOutputJSONObject, exactly as
// omission in a mounted config does (D1/A1).
type StructuredOutputMode string

const (
	StructuredOutputJSONObject StructuredOutputMode = "json_object"
	StructuredOutputJSONSchema StructuredOutputMode = "json_schema"
)

// valid accepts only the empty/default value and the two explicit modes.
func (mode StructuredOutputMode) valid() bool {
	return mode == "" || mode == StructuredOutputJSONObject || mode == StructuredOutputJSONSchema
}

// effective maps the empty/default value to StructuredOutputJSONObject and
// otherwise returns the mode unchanged.
func (mode StructuredOutputMode) effective() StructuredOutputMode {
	if mode == "" {
		return StructuredOutputJSONObject
	}
	return mode
}

// LabAdapterConfig is the non-production, explicitly-acknowledged transport
// configuration for the interim GEN-1 adapter. It is deliberately distinct
// from Profile: it does not assert an artifact/tokenizer/runtime hash and must
// never be substituted for a qualified Profile in an ADR-0080 production path.
type LabAdapterConfig struct {
	SchemaVersion   string        `json:"schema_version"`
	Endpoint        string        `json:"endpoint"`
	ModelID         string        `json:"model_id"`
	APIKey          string        `json:"api_key,omitempty"`
	Timeout         time.Duration `json:"-"`
	MaxOutputTokens int           `json:"max_output_tokens"`
	// ThinkingMode is provider-specific request configuration. An empty value
	// is retained only for direct local generic-lab callers whose endpoint may
	// not implement DeepSeek's thinking control; the mounted deployment config
	// rejects omission and sets this explicitly.
	ThinkingMode ThinkingMode `json:"thinking_mode,omitempty"`
	// StructuredOutputMode is optional (D1/A1). Omission is valid and stays the
	// zero value, whose effective behavior is StructuredOutputJSONObject.
	StructuredOutputMode StructuredOutputMode `json:"structured_output_mode,omitempty"`
	// InsecureLabMode must be explicitly true. It exists so a mounted config
	// file cannot silently activate this non-mTLS path; the field name itself
	// documents, at the point of use, that this is not the ADR-0080 boundary.
	InsecureLabMode bool `json:"insecure_lab_mode"`
	// ExternalRuntimeWorkspaceIDs is empty by default (local-only policy). A
	// non-empty, explicit list is the only way Endpoint may resolve to a
	// public, non-private host, and it then bounds which exact workspaces may
	// reach it (GEN-2, workspace-scoped external runtime policy). It must stay
	// empty when Endpoint is a loopback/private address.
	ExternalRuntimeWorkspaceIDs []string `json:"external_runtime_workspace_ids,omitempty"`
	// TrustRoots is the explicit, mounted CA set the adapter's TLS client
	// trusts (GEN-2). It is never populated from JSON: mount_lab.go reads it
	// from its own dedicated PEM file inside the mount root (trust_bundle_file),
	// mirroring the "explicit mount, never the ambient system trust pool"
	// discipline every other TLS peer in this codebase already follows. A nil
	// value falls back to the Go runtime's default verification (acceptable
	// only for a local lab endpoint, which is already restricted to a
	// loopback/private literal IP and therefore not a public-PKI target).
	TrustRoots *x509.CertPool   `json:"-"`
	ToolLoop   *ToolLoopProfile `json:"tool_loop,omitempty"`
}

func (config LabAdapterConfig) Validate() error {
	if config.ToolLoop != nil {
		if err := config.ToolLoop.Validate(); err != nil || !config.ThinkingMode.valid() || config.ToolLoop.MaxOutputTokens > config.MaxOutputTokens || (config.ToolLoop.ThinkingMode != "" && config.ToolLoop.ThinkingMode != config.ThinkingMode) {
			return &Error{code: CodeProfile}
		}
	}
	if config.SchemaVersion != LabAdapterSchemaVersion || !config.InsecureLabMode {
		return &Error{code: CodeProfile}
	}
	if config.ThinkingMode != "" && !config.ThinkingMode.valid() {
		return &Error{code: CodeProfile}
	}
	if !config.StructuredOutputMode.valid() {
		return &Error{code: CodeProfile}
	}
	if config.ModelID == "" || len(config.ModelID) > labMaxModelIDBytes || !validOpaque(config.ModelID) {
		return &Error{code: CodeProfile}
	}
	if len(config.APIKey) > labMaxAPIKeyBytes {
		return &Error{code: CodeProfile}
	}
	if config.MaxOutputTokens < 1 || config.MaxOutputTokens > labMaxOutputTokens {
		return &Error{code: CodeProfile}
	}
	if config.Timeout != 0 && (config.Timeout < labMinTimeout || config.Timeout > labMaxTimeout) {
		return &Error{code: CodeProfile}
	}
	if len(config.ExternalRuntimeWorkspaceIDs) > labMaxExternalWorkspaces {
		return &Error{code: CodeProfile}
	}
	seen := make(map[string]struct{}, len(config.ExternalRuntimeWorkspaceIDs))
	for _, workspaceID := range config.ExternalRuntimeWorkspaceIDs {
		if !validOpaque(workspaceID) {
			return &Error{code: CodeProfile}
		}
		if _, duplicate := seen[workspaceID]; duplicate {
			return &Error{code: CodeProfile}
		}
		seen[workspaceID] = struct{}{}
	}
	external := len(config.ExternalRuntimeWorkspaceIDs) > 0
	if external && config.ThinkingMode == "" {
		return &Error{code: CodeProfile}
	}
	// An external (public) endpoint must carry its own explicit, mounted trust
	// root: this adapter never falls back to an ambient/system trust pool for
	// a public-PKI destination (GEN-2; the runtime image this ships in has no
	// system CA bundle at all, by design — see docs/adr/0088). A local
	// loopback/private endpoint is unaffected; Go's default verification
	// applies only there, and only within an operator's own bounded network.
	if external && config.TrustRoots == nil {
		return &Error{code: CodeProfile}
	}
	return validLabEndpoint(config.Endpoint, external)
}

// AllowsWorkspace reports whether workspaceID may use this adapter. A local
// (loopback/private) endpoint has no workspace restriction, exactly as before
// GEN-2. An external endpoint is usable only by a workspace explicitly listed
// in ExternalRuntimeWorkspaceIDs; every other workspace must be treated as if
// the capability were absent (CodeUnsupportedMode at the question authority),
// never as a silent downgrade to a different mode.
func (config LabAdapterConfig) AllowsWorkspace(workspaceID string) bool {
	if !validOpaque(workspaceID) {
		return false
	}
	if len(config.ExternalRuntimeWorkspaceIDs) == 0 {
		return true
	}
	for _, allowed := range config.ExternalRuntimeWorkspaceIDs {
		if allowed == workspaceID {
			return true
		}
	}
	return false
}

// RuntimeScope reports the content-free, typed classification of this
// adapter's endpoint for attempt provenance and audit (GEN-2).
func (config LabAdapterConfig) RuntimeScope() string {
	if len(config.ExternalRuntimeWorkspaceIDs) > 0 {
		return RuntimeScopeExternalWorkspaceScoped
	}
	return RuntimeScopeLocalLab
}

// validLabEndpoint accepts a loopback or RFC1918/RFC4193 private literal IP
// host by default: this path is for an administrator's own bounded lab/test
// network, never a public or arbitrary DNS-resolved destination. Only when
// allowExternal is true (the mounted config explicitly names the workspaces
// permitted to use it) may the host be a public DNS name or address, and even
// then only over https.
func validLabEndpoint(value string, allowExternal bool) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil ||
		parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
		strings.HasSuffix(parsed.Path, "/") || parsed.RawPath != "" ||
		!validEndpointPath(parsed.Path) {
		return &Error{code: CodeProfile}
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	private := ip != nil && (ip.IsLoopback() || ip.IsPrivate())
	if !private {
		if !allowExternal || parsed.Scheme != "https" || host == "" {
			return &Error{code: CodeProfile}
		}
	}
	port := parsed.Port()
	if port == "" {
		if allowExternal && !private {
			port = "443"
		} else {
			return &Error{code: CodeProfile}
		}
	} else {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port ||
			net.JoinHostPort(host, port) != parsed.Host {
			return &Error{code: CodeProfile}
		}
	}
	return nil
}

// validEndpointPath allows an empty path or a bounded, clean "/segment"* API
// base path (e.g. "/v1"), never a query, traversal or unusual character.
func validEndpointPath(path string) bool {
	if path == "" {
		return true
	}
	if len(path) > 128 || path[0] != '/' {
		return false
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, r := range segment {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// LabAdapter is the interim, non-mTLS OpenAI-compatible chat-completions
// client. See the package-level doc comment above for its exact scope limit.
type LabAdapter struct {
	config LabAdapterConfig
	http   *http.Client
}

func NewLabAdapter(config LabAdapterConfig) (*LabAdapter, error) {
	config.ExternalRuntimeWorkspaceIDs = append([]string(nil), config.ExternalRuntimeWorkspaceIDs...)
	if config.TrustRoots != nil {
		config.TrustRoots = config.TrustRoots.Clone()
	}
	if config.ToolLoop != nil {
		copied := config.ToolLoop.clone()
		config.ToolLoop = &copied
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxResponseHeaderBytes: 1 << 20}
	if config.TrustRoots != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: config.TrustRoots, MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &LabAdapter{config: config, http: client}, nil
}

// AllowsWorkspace reports whether workspaceID may issue a GENERATIVE request
// against this adapter's configured endpoint (GEN-2 workspace-scoped external
// runtime policy; see LabAdapterConfig.AllowsWorkspace).
func (adapter *LabAdapter) AllowsWorkspace(workspaceID string) bool {
	if adapter == nil {
		return false
	}
	return adapter.config.AllowsWorkspace(workspaceID)
}

// RuntimeScope reports the content-free, typed classification of this
// adapter's endpoint (GEN-2), for attempt provenance and audit.
func (adapter *LabAdapter) RuntimeScope() string {
	if adapter == nil {
		return RuntimeScopeLocalLab
	}
	return adapter.config.RuntimeScope()
}

// ProviderName reports the mounted adapter's model id (e.g.
// "deepseek-v4-flash"), the same value AttemptResult.ModelID already
// discloses per attempt (GenerateBounded). It carries no endpoint, key or
// other transport detail.
func (adapter *LabAdapter) ProviderName() string {
	if adapter == nil {
		return ""
	}
	return adapter.config.ModelID
}

func (adapter *LabAdapter) Close() error {
	if adapter == nil || adapter.http == nil {
		return nil
	}
	if transport, ok := adapter.http.Transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// AttemptResult is a content-free summary of one bounded call, suitable for
// MOD-007/MOD-008 persistence. It retains transport status and response stage
// without carrying question text, evidence text, prompt bytes or model output.
type AttemptResult struct {
	ModelID            string
	StatusCode         int
	ResponseStage      ResponseStage
	ResponseDiagnostic ResponseDiagnostic
	Succeeded          bool
	RequestBytes       int
	ResponseBytes      int
	FailureCode        ErrorCode
}

// ResponseDiagnostic is a closed, content-free rejection reason. Never assign
// provider strings, JSON decoder messages, arguments or response bytes to it.
type ResponseDiagnostic string

const (
	ResponseJSONInvalid          ResponseDiagnostic = "MODEL_RESPONSE_JSON_INVALID"
	ResponseModelMismatch        ResponseDiagnostic = "MODEL_RESPONSE_MODEL_MISMATCH"
	ResponseChoiceCountInvalid   ResponseDiagnostic = "MODEL_RESPONSE_CHOICE_COUNT_INVALID"
	ResponseRoleInvalid          ResponseDiagnostic = "MODEL_RESPONSE_ROLE_INVALID"
	ResponseFinishInvalid        ResponseDiagnostic = "MODEL_RESPONSE_FINISH_INVALID"
	ResponseProviderResource     ResponseDiagnostic = "MODEL_RESPONSE_PROVIDER_RESOURCE"
	ResponseProviderAborted      ResponseDiagnostic = "MODEL_RESPONSE_PROVIDER_ABORTED"
	ResponseProviderFiltered     ResponseDiagnostic = "MODEL_RESPONSE_PROVIDER_FILTERED"
	ResponseOutputLimit          ResponseDiagnostic = "MODEL_RESPONSE_OUTPUT_LIMIT"
	ResponseToolCountExceeded    ResponseDiagnostic = "MODEL_RESPONSE_TOOL_COUNT_EXCEEDED"
	ResponseToolIDInvalid        ResponseDiagnostic = "MODEL_RESPONSE_TOOL_ID_INVALID"
	ResponseToolIDDuplicate      ResponseDiagnostic = "MODEL_RESPONSE_TOOL_ID_DUPLICATE"
	ResponseToolTypeInvalid      ResponseDiagnostic = "MODEL_RESPONSE_TOOL_TYPE_INVALID"
	ResponseToolNameInvalid      ResponseDiagnostic = "MODEL_RESPONSE_TOOL_NAME_INVALID"
	ResponseArgumentsTooLarge    ResponseDiagnostic = "MODEL_RESPONSE_ARGUMENTS_TOO_LARGE"
	ResponseArgumentsJSONInvalid ResponseDiagnostic = "MODEL_RESPONSE_ARGUMENTS_JSON_INVALID"
)

// ReasonCode returns only a code minted by this package's fixed vocabulary.
// Unknown values cannot become content in the audit metadata.
func (diagnostic ResponseDiagnostic) ReasonCode() string {
	switch diagnostic {
	case ResponseJSONInvalid, ResponseModelMismatch, ResponseChoiceCountInvalid,
		ResponseRoleInvalid, ResponseFinishInvalid, ResponseProviderResource,
		ResponseProviderAborted, ResponseProviderFiltered, ResponseOutputLimit,
		ResponseToolCountExceeded, ResponseToolIDInvalid, ResponseToolIDDuplicate,
		ResponseToolTypeInvalid, ResponseToolNameInvalid, ResponseArgumentsTooLarge,
		ResponseArgumentsJSONInvalid:
		return string(diagnostic)
	default:
		return ""
	}
}

// ResponseStage is a content-free stage reached while validating a model
// response. It is suitable for attempt provenance and never contains model
// response data.
type ResponseStage string

const (
	ResponseStageWire  ResponseStage = "WIRE"
	ResponseStageJSON  ResponseStage = "JSON"
	ResponseStageClaim ResponseStage = "CLAIM"
)

func (stage ResponseStage) valid() bool {
	return stage == ResponseStageWire || stage == ResponseStageJSON || stage == ResponseStageClaim
}

// responseFormat builds the lab-only provider response_format for the exact
// StructuredOutputMode. It copies outputSchema into a private RawMessage (never
// sharing the caller's mutable bytes), and rejects malformed or non-object
// top-level schemas before any HTTP call. The default mode is json_object, so
// the omitempty field on completionResponseFormat stays absent.
func (mode StructuredOutputMode) responseFormat(outputSchema []byte) (*completionResponseFormat, error) {
	switch mode {
	case StructuredOutputJSONObject:
		return &completionResponseFormat{Type: string(StructuredOutputJSONObject)}, nil
	case StructuredOutputJSONSchema:
		schema := json.RawMessage(bytes.Clone(outputSchema))
		var object map[string]json.RawMessage
		if err := strictJSON(schema, &object); err != nil || object == nil {
			return nil, &Error{code: CodeInvalid, cause: err}
		}
		return &completionResponseFormat{Type: string(StructuredOutputJSONSchema), JSONSchema: &completionResponseJSONSchema{
			Name: "knowvault_claim_plan", Strict: true, Schema: schema,
		}}, nil
	default:
		return nil, &Error{code: CodeInvalid}
	}
}

// Generate performs at most one bounded HTTP attempt and returns both the
// content-free attempt summary (always) and the parsed, evidence-validated
// ClaimPlan (only when Succeeded). Question, systemInstructions, schema and
// evidence follow exactly the existing GenerateRequest/ClaimPlan contract;
// this function adds no tool, credential or endpoint-discovery surface.
func (adapter *LabAdapter) Generate(ctx context.Context, question, systemInstructions string, outputSchema []byte, evidence []Evidence, maxOutputTokens int) (ClaimPlan, AttemptResult, error) {
	result := AttemptResult{ModelID: "", FailureCode: CodeInvalid}
	if adapter == nil || adapter.http == nil || ctx == nil {
		return ClaimPlan{}, result, &Error{code: CodeInvalid}
	}
	result.ModelID = adapter.config.ModelID
	if !validPromptText(question, MaxQuestionBytes) || !validPromptText(systemInstructions, MaxInstructionBytes) ||
		len(outputSchema) == 0 || len(outputSchema) > MaxSchemaBytes || len(evidence) == 0 || len(evidence) > MaxEvidenceItems ||
		maxOutputTokens < 1 || maxOutputTokens > adapter.config.MaxOutputTokens {
		return ClaimPlan{}, result, &Error{code: CodeInvalid}
	}
	content := make([]map[string]string, 0, len(evidence))
	for _, item := range evidence {
		if err := item.Validate(); err != nil {
			return ClaimPlan{}, result, err
		}
		content = append(content, map[string]string{"evidence_id": item.ID, "text": item.Text, "text_hash": item.TextHash, "anchor_hash": item.AnchorHash})
	}
	responseFormat, err := adapter.config.StructuredOutputMode.effective().responseFormat(outputSchema)
	if err != nil {
		return ClaimPlan{}, result, err
	}
	payload := completionRequest{Model: adapter.config.ModelID, Messages: []completionMessage{
		{Role: "system", Content: systemInstructions},
		{Role: "user", Content: marshalContext(question, outputSchema, content)},
	}, Temperature: 0, MaxTokens: maxOutputTokens, Stream: false,
		ResponseFormat: responseFormat}
	if adapter.config.ThinkingMode != "" {
		payload.Thinking = &completionThinking{Type: string(adapter.config.ThinkingMode)}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ClaimPlan{}, result, &Error{code: CodeInvalid, cause: err}
	}
	result.RequestBytes = len(body)
	target := strings.TrimSuffix(adapter.config.Endpoint, "/") + "/chat/completions"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return ClaimPlan{}, result, &Error{code: CodeInvalid, cause: err}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if adapter.config.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+adapter.config.APIKey)
	}
	response, err := adapter.http.Do(request)
	if err != nil {
		result.FailureCode = CodeUnavailable
		return ClaimPlan{}, result, &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	result.StatusCode = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		result.FailureCode = CodeRejected
		return ClaimPlan{}, result, &Error{code: CodeRejected, status: response.StatusCode}
	}
	result.ResponseStage = ResponseStageWire
	raw, err := io.ReadAll(io.LimitReader(response.Body, labMaxResponseBytes+1))
	if err != nil || len(raw) > labMaxResponseBytes {
		result.FailureCode = CodeResponse
		return ClaimPlan{}, result, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	result.ResponseBytes = len(raw)
	var wire completionResponse
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Model != adapter.config.ModelID ||
		len(wire.Choices) != 1 || wire.Choices[0].Message.Content == "" || wire.Choices[0].FinishReason != "stop" {
		result.FailureCode = CodeResponse
		return ClaimPlan{}, result, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	result.ResponseStage = ResponseStageJSON
	var plan ClaimPlan
	if err := strictJSON([]byte(wire.Choices[0].Message.Content), &plan); err != nil {
		result.FailureCode = CodeResponse
		return ClaimPlan{}, result, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	result.ResponseStage = ResponseStageClaim
	if err := plan.Validate(evidence); err != nil {
		result.FailureCode = CodeResponse
		return ClaimPlan{}, result, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	result.Succeeded = true
	result.FailureCode = ""
	return plan, result, nil
}

// GenerateBounded runs Generate up to labMaxAttemptsPerCall times, matching
// ADR-0080 §2.2's "at most two recorded attempts" bound: a retry is allowed
// only for a typed transient transport failure (CodeUnavailable) before any
// accepted output. Every attempt (including a failed one) is reported through
// onAttempt for content-free persistence before the next attempt starts.
func (adapter *LabAdapter) GenerateBounded(ctx context.Context, question, systemInstructions string, outputSchema []byte, evidence []Evidence, maxOutputTokens int, onAttempt func(AttemptResult)) (ClaimPlan, error) {
	var lastErr error
	for attempt := 1; attempt <= labMaxAttemptsPerCall; attempt++ {
		plan, result, err := adapter.Generate(ctx, question, systemInstructions, outputSchema, evidence, maxOutputTokens)
		if onAttempt != nil {
			onAttempt(result)
		}
		if err == nil {
			return plan, nil
		}
		lastErr = err
		if !retryableAttemptCode(CodeOf(err)) {
			return ClaimPlan{}, err
		}
	}
	if lastErr == nil {
		lastErr = &Error{code: CodeUnavailable}
	}
	return ClaimPlan{}, lastErr
}

// retryableAttemptCode decides which failed attempt may consume the SECOND of
// the bounded attempts. Sampling is not deterministic: the same model, prompt
// and schema produce a structurally valid ClaimPlan on one call and a malformed
// one on the next, and CodeResponse is exactly that outcome — the response was
// received and then REJECTED by this package's own validation. Spending the
// budget on it is the whole reason the budget exists (ADR-0088: at most two
// attempts, then a terminal INSUFFICIENT_EVIDENCE); refusing to retry made one
// unlucky sample a terminal answer, which is what the acceptance stand saw as
// an intermittently unanswerable GENERATIVE question. Nothing is relaxed: each
// attempt is validated in full and persisted as its own audited row, and the
// cap stays at two. A rejected REQUEST, an exhausted budget, a profile/binding
// mismatch or an invalid request are deterministic — a second identical call
// would fail identically — so they stay terminal on the first attempt.
func retryableAttemptCode(code ErrorCode) bool {
	return code == CodeUnavailable || code == CodeResponse
}
