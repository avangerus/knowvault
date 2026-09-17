// Package modelgateway is the only boundary through which a qualified model
// runtime may be called.  It deliberately contains no model implementation:
// profiles are deployment-owned, immutable inputs and the package remains
// inert until an exact profile has passed the runtime qualification gates.
//
// The gateway accepts a server-owned binding and post-authorized Evidence
// context.  It never accepts SQL, credentials, an endpoint from a request, or
// a caller-selected fallback.  Model output is a claim plan, not final
// Markdown; every factual claim must name an Evidence ID from the request and
// the application remains responsible for deterministic rendering/signing.
package modelgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	SchemaVersion        = "model-gateway-v1"
	ProfileSchemaVersion = "model-profile-v1"
	ModelAnswerVersion   = "1.4"

	MaxQuestionBytes      = 32 << 10
	MaxInstructionBytes   = 32 << 10
	MaxSchemaBytes        = 64 << 10
	MaxEvidenceItems      = 256
	MaxEvidenceBytes      = 8 << 20
	MaxContextTokens      = 24_000
	MaxOutputTokens       = 2_048
	MaxResponseBytes      = 512 << 10
	MaxClaims             = 40
	MaxSections           = 8
	MaxEvidencePerClaim   = 12
	MaxSupportingClaims   = 12
	MaxQuestionRunIDBytes = 128
)

// Purpose identifies a separately qualified model profile. A profile is
// never reused across purposes, even if the underlying artifact is identical.
type Purpose string

const (
	PurposeEmbedding    Purpose = "EMBEDDING"
	PurposeReranking    Purpose = "RERANKING"
	PurposeGeneration   Purpose = "GENERATION"
	PurposeVerification Purpose = "VERIFICATION"
)

// ErrorCode is intentionally content-free.  Endpoint bodies, prompts,
// Evidence text and model output are retained only in trusted diagnostics by
// the caller and never become an API error string.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "MODEL_GATEWAY_REQUEST_INVALID"
	CodeUnavailable ErrorCode = "MODEL_GATEWAY_UNAVAILABLE"
	CodeRejected    ErrorCode = "MODEL_GATEWAY_REJECTED"
	CodeResponse    ErrorCode = "MODEL_GATEWAY_RESPONSE_INVALID"
	CodeProfile     ErrorCode = "MODEL_GATEWAY_PROFILE_UNREADY"
	CodeBinding     ErrorCode = "MODEL_GATEWAY_BINDING_MISMATCH"
	CodeBudget      ErrorCode = "MODEL_GATEWAY_BUDGET_EXCEEDED"
)

type Error struct {
	code   ErrorCode
	cause  error
	status int
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
func (e *Error) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// Profile is the immutable, deployment-owned identity of one model
// capability. ProfileHash is the SHA-256 of the canonical profile projection
// with ProfileHash itself excluded. Artifact and tokenizer hashes are required
// even when the runtime is remote; a self-reported model alias is not enough.
type Profile struct {
	SchemaVersion     string  `json:"schema_version"`
	ID                string  `json:"id"`
	Purpose           Purpose `json:"purpose"`
	ModelID           string  `json:"model_id"`
	ArtifactHash      string  `json:"artifact_hash"`
	TokenizerHash     string  `json:"tokenizer_hash"`
	RuntimeHash       string  `json:"runtime_hash"`
	ConfigurationHash string  `json:"configuration_hash"`
	Endpoint          string  `json:"endpoint"`
	ServerName        string  `json:"server_name"`
	ContextTokens     int     `json:"context_tokens"`
	MaxOutputTokens   int     `json:"max_output_tokens"`
	Revision          int64   `json:"revision"`
	ProfileHash       string  `json:"profile_hash"`
}

func (profile Profile) Validate() error {
	if profile.SchemaVersion != ProfileSchemaVersion || !validOpaque(profile.ID) ||
		!validOpaque(profile.ModelID) || !validPurpose(profile.Purpose) ||
		!validSHA256(profile.ArtifactHash) || !validSHA256(profile.TokenizerHash) ||
		!validSHA256(profile.RuntimeHash) || !validSHA256(profile.ConfigurationHash) ||
		!validSHA256(profile.ProfileHash) || profile.Revision < 1 || profile.Revision > maxInt64 ||
		profile.ContextTokens < 1 || profile.ContextTokens > 262144 ||
		profile.MaxOutputTokens < 1 || profile.MaxOutputTokens > MaxOutputTokens {
		return &Error{code: CodeProfile}
	}
	if profile.Endpoint == "" || profile.ServerName == "" || !validModelEndpoint(profile.Endpoint, profile.ServerName) {
		return &Error{code: CodeProfile}
	}
	raw, err := profileCanonical(profile)
	if err != nil || canon.Hash(raw) != profile.ProfileHash {
		return &Error{code: CodeProfile, cause: err}
	}
	return nil
}

func (profile Profile) CanonicalBytes() ([]byte, error) { return profileCanonical(profile) }

func profileCanonical(profile Profile) ([]byte, error) {
	return canon.CanonicalJSON(struct {
		SchemaVersion     string  `json:"schema_version"`
		ID                string  `json:"id"`
		Purpose           Purpose `json:"purpose"`
		ModelID           string  `json:"model_id"`
		ArtifactHash      string  `json:"artifact_hash"`
		TokenizerHash     string  `json:"tokenizer_hash"`
		RuntimeHash       string  `json:"runtime_hash"`
		ConfigurationHash string  `json:"configuration_hash"`
		Endpoint          string  `json:"endpoint"`
		ServerName        string  `json:"server_name"`
		ContextTokens     int     `json:"context_tokens"`
		MaxOutputTokens   int     `json:"max_output_tokens"`
		Revision          int64   `json:"revision"`
	}{profile.SchemaVersion, profile.ID, profile.Purpose, profile.ModelID,
		profile.ArtifactHash, profile.TokenizerHash, profile.RuntimeHash,
		profile.ConfigurationHash, profile.Endpoint, profile.ServerName,
		profile.ContextTokens, profile.MaxOutputTokens, profile.Revision})
}

// Binding prevents queueing or dispatching context under a different tenant,
// workspace, Question Run, retrieval snapshot or model purpose.
type Binding struct {
	OrganizationID        string  `json:"organization_id"`
	WorkspaceID           string  `json:"workspace_id"`
	QuestionRunID         string  `json:"question_run_id"`
	Purpose               Purpose `json:"purpose"`
	ProfileHash           string  `json:"profile_hash"`
	RetrievalSnapshotHash string  `json:"retrieval_snapshot_hash"`
	ContextPackHash       string  `json:"context_pack_hash"`
}

func (binding Binding) Validate(profile Profile) error {
	if !validOpaque(binding.OrganizationID) || !validOpaque(binding.WorkspaceID) ||
		!validOpaque(binding.QuestionRunID) || len(binding.QuestionRunID) > MaxQuestionRunIDBytes ||
		binding.Purpose != profile.Purpose || binding.ProfileHash != profile.ProfileHash ||
		!validSHA256(binding.ProfileHash) || !validSHA256(binding.RetrievalSnapshotHash) ||
		!validSHA256(binding.ContextPackHash) {
		return &Error{code: CodeBinding}
	}
	return nil
}

// Evidence is the only source content admitted to a model request. The
// caller must obtain it through the current PostgreSQL authorization gate.
// The gateway checks shape and lineage references but does not become an
// alternate Evidence authority.
type Evidence struct {
	ID              string `json:"evidence_id"`
	SourceObjectID  string `json:"source_object_id"`
	SourceVersionID string `json:"source_version_id"`
	ExtractionID    string `json:"extraction_id"`
	TextHash        string `json:"text_hash"`
	AnchorHash      string `json:"anchor_hash"`
	Text            string `json:"text"`
}

func (evidence Evidence) Validate() error {
	if !validEvidenceID(evidence.ID) || !validOpaque(evidence.SourceObjectID) ||
		!validOpaque(evidence.SourceVersionID) || !validOpaque(evidence.ExtractionID) ||
		!validDigest(evidence.TextHash) || !validDigest(evidence.AnchorHash) ||
		evidence.Text == "" || !utf8.ValidString(evidence.Text) || len([]byte(evidence.Text)) > maximumEvidenceItemBytes {
		return &Error{code: CodeInvalid}
	}
	return nil
}

// GenerateRequest is created only by a server-owned Question authority. The
// request contains no SQL, endpoint, credential or arbitrary tool field.
type GenerateRequest struct {
	SchemaVersion      string     `json:"schema_version"`
	Binding            Binding    `json:"binding"`
	Question           string     `json:"question"`
	SystemInstructions string     `json:"system_instructions"`
	OutputSchema       []byte     `json:"output_schema"`
	OutputSchemaHash   string     `json:"output_schema_hash"`
	ContextTokenCount  int        `json:"context_token_count"`
	MaxOutputTokens    int        `json:"max_output_tokens"`
	Evidence           []Evidence `json:"evidence"`
}

func (request GenerateRequest) Validate(profile Profile) error {
	if request.SchemaVersion != SchemaVersion {
		return &Error{code: CodeInvalid}
	}
	if err := request.Binding.Validate(profile); err != nil {
		return err
	}
	if !validPromptText(request.Question, MaxQuestionBytes) ||
		!validPromptText(request.SystemInstructions, MaxInstructionBytes) ||
		len(request.OutputSchema) == 0 || len(request.OutputSchema) > MaxSchemaBytes ||
		!validSHA256(request.OutputSchemaHash) || request.ContextTokenCount < 1 ||
		request.ContextTokenCount > MaxContextTokens || request.ContextTokenCount > profile.ContextTokens ||
		request.MaxOutputTokens < 1 || request.MaxOutputTokens > profile.MaxOutputTokens ||
		len(request.Evidence) == 0 || len(request.Evidence) > MaxEvidenceItems {
		return &Error{code: CodeInvalid}
	}
	canonicalSchema := bytes.Clone(request.OutputSchema)
	if err := canonicalizeJSON(canonicalSchema); err != nil || canon.Hash(canonicalSchema) != request.OutputSchemaHash {
		return &Error{code: CodeInvalid, cause: err}
	}
	totalBytes := 0
	seen := make(map[string]struct{}, len(request.Evidence))
	for _, evidence := range request.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[evidence.ID]; duplicate {
			return &Error{code: CodeInvalid}
		}
		seen[evidence.ID] = struct{}{}
		totalBytes += len([]byte(evidence.Text))
		if totalBytes > MaxEvidenceBytes {
			return &Error{code: CodeBudget}
		}
	}
	return nil
}

// ClaimPlan is the strict model-answer contract. It is intentionally
// transport-neutral and must be rendered by the deterministic answer owner.
type ClaimPlan struct {
	SchemaVersion string    `json:"schema_version"`
	Claims        []Claim   `json:"claims"`
	Sections      []Section `json:"sections"`
}

type Claim struct {
	ID                 string   `json:"claim_id"`
	Text               *string  `json:"text"`
	Kind               string   `json:"kind"`
	UnknownReason      *string  `json:"unknown_reason"`
	EvidenceIDs        []string `json:"evidence_ids"`
	SupportingClaimIDs []string `json:"supporting_claim_ids"`
}

type Section struct {
	ID              string   `json:"section_id"`
	Title           *string  `json:"title"`
	OrderedClaimIDs []string `json:"ordered_claim_ids"`
}

// UnmarshalJSON preserves the model-answer schema's required-vs-null
// distinction. The standard decoder maps both an omitted nullable member and
// an explicit null to nil, so the required-member check lives here.
func (claim *Claim) UnmarshalJSON(raw []byte) error {
	type wire Claim
	var value wire
	if err := decodeKnown(raw, &value, "claim_id", "text", "kind", "unknown_reason", "evidence_ids", "supporting_claim_ids"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range []string{"claim_id", "text", "kind", "unknown_reason", "evidence_ids", "supporting_claim_ids"} {
		if _, ok := fields[name]; !ok {
			return errors.New("claim required member missing")
		}
	}
	*claim = Claim(value)
	return nil
}

func (section *Section) UnmarshalJSON(raw []byte) error {
	type wire Section
	var value wire
	if err := decodeKnown(raw, &value, "section_id", "title", "ordered_claim_ids"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range []string{"section_id", "title", "ordered_claim_ids"} {
		if _, ok := fields[name]; !ok {
			return errors.New("section required member missing")
		}
	}
	*section = Section(value)
	return nil
}

func (plan *ClaimPlan) UnmarshalJSON(raw []byte) error {
	type wire ClaimPlan
	var value wire
	if err := decodeKnown(raw, &value, "schema_version", "claims", "sections"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range []string{"schema_version", "claims", "sections"} {
		if _, ok := fields[name]; !ok {
			return errors.New("claim plan required member missing")
		}
	}
	*plan = ClaimPlan(value)
	return nil
}

func decodeKnown(raw []byte, target any, _ ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func (plan ClaimPlan) Validate(allowedEvidence []Evidence) error {
	if plan.SchemaVersion != ModelAnswerVersion || len(plan.Claims) == 0 || len(plan.Claims) > MaxClaims ||
		len(plan.Sections) == 0 || len(plan.Sections) > MaxSections {
		return &Error{code: CodeResponse}
	}
	allowed := make(map[string]struct{}, len(allowedEvidence))
	for _, evidence := range allowedEvidence {
		if err := evidence.Validate(); err != nil {
			return &Error{code: CodeResponse}
		}
		allowed[evidence.ID] = struct{}{}
	}
	claims := make(map[string]struct{}, len(plan.Claims))
	for _, claim := range plan.Claims {
		if !validClaimID(claim.ID) || len(claim.EvidenceIDs) > MaxEvidencePerClaim || len(claim.SupportingClaimIDs) > MaxSupportingClaims {
			return &Error{code: CodeResponse}
		}
		if _, duplicate := claims[claim.ID]; duplicate {
			return &Error{code: CodeResponse}
		}
		claims[claim.ID] = struct{}{}
		if claim.Text != nil && (!validText(*claim.Text, 2000) || strings.TrimSpace(*claim.Text) != *claim.Text) {
			return &Error{code: CodeResponse}
		}
		if claim.UnknownReason != nil && !validUnknownReason(*claim.UnknownReason) {
			return &Error{code: CodeResponse}
		}
		if !validClaimShape(claim) || !uniqueStrings(claim.EvidenceIDs) || !uniqueStrings(claim.SupportingClaimIDs) {
			return &Error{code: CodeResponse}
		}
		for _, evidenceID := range claim.EvidenceIDs {
			if _, ok := allowed[evidenceID]; !ok {
				return &Error{code: CodeResponse}
			}
		}
	}
	for _, claim := range plan.Claims {
		for _, supporting := range claim.SupportingClaimIDs {
			if _, ok := claims[supporting]; !ok || supporting == claim.ID {
				return &Error{code: CodeResponse}
			}
		}
	}
	// Supporting claims form a directed acyclic graph. A cycle would make an
	// inference appear supported without a terminal, Evidence-backed FACT.
	state := make(map[string]uint8, len(plan.Claims))
	var visit func(string) bool
	visit = func(id string) bool {
		switch state[id] {
		case 1:
			return false
		case 2:
			return true
		}
		state[id] = 1
		for _, claim := range plan.Claims {
			if claim.ID != id {
				continue
			}
			for _, supporting := range claim.SupportingClaimIDs {
				if !visit(supporting) {
					return false
				}
			}
			break
		}
		state[id] = 2
		return true
	}
	for id := range claims {
		if !visit(id) {
			return &Error{code: CodeResponse}
		}
	}
	sections := make(map[string]struct{}, len(plan.Sections))
	seenClaimInSection := make(map[string]struct{}, len(plan.Claims))
	for _, section := range plan.Sections {
		if !validSectionID(section.ID) || len(section.OrderedClaimIDs) == 0 || len(section.OrderedClaimIDs) > MaxClaims || !uniqueStrings(section.OrderedClaimIDs) {
			return &Error{code: CodeResponse}
		}
		if _, duplicate := sections[section.ID]; duplicate {
			return &Error{code: CodeResponse}
		}
		sections[section.ID] = struct{}{}
		if section.Title != nil && (!validText(*section.Title, 512) || strings.TrimSpace(*section.Title) != *section.Title) {
			return &Error{code: CodeResponse}
		}
		for _, claimID := range section.OrderedClaimIDs {
			if _, ok := claims[claimID]; !ok {
				return &Error{code: CodeResponse}
			}
			seenClaimInSection[claimID] = struct{}{}
		}
	}
	if len(seenClaimInSection) != len(claims) {
		return &Error{code: CodeResponse}
	}
	return nil
}

// Client is an immutable, purpose-bound mTLS transport. It has no public
// method for changing endpoint/profile and does not follow redirects.
type Client struct {
	profile  Profile
	endpoint url.URL
	http     *http.Client
}

type Config struct {
	Profile           Profile
	TrustRoots        *x509.CertPool
	ClientCertificate *tls.Certificate
	Timeout           time.Duration
}

func New(config Config) (*Client, error) {
	if err := config.Profile.Validate(); err != nil || config.TrustRoots == nil || len(config.TrustRoots.Subjects()) == 0 || config.ClientCertificate == nil || len(config.ClientCertificate.Certificate) == 0 || config.ClientCertificate.PrivateKey == nil {
		return nil, &Error{code: CodeProfile}
	}
	parsed, err := url.Parse(config.Profile.Endpoint)
	if err != nil || !validModelEndpoint(config.Profile.Endpoint, config.Profile.ServerName) {
		return nil, &Error{code: CodeProfile}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	if timeout > 90*time.Second {
		return nil, &Error{code: CodeProfile}
	}
	tlsConfig := &tls.Config{RootCAs: config.TrustRoots, Certificates: []tls.Certificate{*config.ClientCertificate}, MinVersion: tls.VersionTLS12, ServerName: config.Profile.ServerName}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true, MaxResponseHeaderBytes: 1 << 20, ForceAttemptHTTP2: true}
	return &Client{profile: config.Profile, endpoint: *parsed, http: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (client *Client) Profile() Profile {
	if client == nil {
		return Profile{}
	}
	return client.profile
}

func (client *Client) Close() error {
	if client == nil || client.http == nil {
		return nil
	}
	if transport, ok := client.http.Transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// Generate performs exactly one bounded request. It rejects all transport
// responses except one strict JSON claim plan with the configured model ID.
func (client *Client) Generate(ctx context.Context, request GenerateRequest) (ClaimPlan, error) {
	if client == nil || client.http == nil || ctx == nil {
		return ClaimPlan{}, &Error{code: CodeInvalid}
	}
	if err := client.profile.Validate(); err != nil {
		return ClaimPlan{}, err
	}
	if client.profile.Purpose != PurposeGeneration && client.profile.Purpose != PurposeVerification {
		return ClaimPlan{}, &Error{code: CodeProfile}
	}
	if err := request.Validate(client.profile); err != nil {
		return ClaimPlan{}, err
	}
	content := make([]map[string]string, 0, len(request.Evidence))
	for _, evidence := range request.Evidence {
		content = append(content, map[string]string{"evidence_id": evidence.ID, "text": evidence.Text, "text_hash": evidence.TextHash, "anchor_hash": evidence.AnchorHash})
	}
	payload := completionRequest{Model: client.profile.ModelID, Messages: []completionMessage{{Role: "system", Content: request.SystemInstructions}, {Role: "user", Content: marshalContext(request.Question, request.OutputSchema, content)}}, Temperature: 0, MaxTokens: request.MaxOutputTokens, Stream: false}
	body, err := json.Marshal(payload)
	if err != nil {
		return ClaimPlan{}, &Error{code: CodeInvalid, cause: err}
	}
	httpRequest, err := client.newRequest(ctx, "/v1/chat/completions", body)
	if err != nil {
		return ClaimPlan{}, err
	}
	response, err := client.http.Do(httpRequest)
	if err != nil {
		return ClaimPlan{}, &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ClaimPlan{}, &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(raw) > MaxResponseBytes {
		return ClaimPlan{}, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	var wire completionResponse
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Model != client.profile.ModelID || len(wire.Choices) != 1 || wire.Choices[0].Message.Content == "" || wire.Choices[0].FinishReason != "stop" {
		return ClaimPlan{}, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	var plan ClaimPlan
	if err := strictJSON([]byte(wire.Choices[0].Message.Content), &plan); err != nil {
		return ClaimPlan{}, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	if err := plan.Validate(request.Evidence); err != nil {
		return ClaimPlan{}, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	return plan, nil
}

type completionRequest struct {
	Model       string              `json:"model"`
	Messages    []completionMessage `json:"messages"`
	Temperature float64             `json:"temperature"`
	MaxTokens   int                 `json:"max_tokens"`
	Stream      bool                `json:"stream"`
	// These provider controls are populated only by LabAdapter. Client keeps
	// both pointers nil, preserving the production request contract.
	Thinking       *completionThinking       `json:"thinking,omitempty"`
	ResponseFormat *completionResponseFormat `json:"response_format,omitempty"`
}

type completionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type completionThinking struct {
	Type string `json:"type"`
}

type completionResponseFormat struct {
	Type string `json:"type"`
}
type completionResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (client *Client) newRequest(ctx context.Context, path string, body []byte) (*http.Request, error) {
	if client == nil || ctx == nil || path != "/v1/chat/completions" {
		return nil, &Error{code: CodeInvalid}
	}
	target := client.endpoint
	target.Path = strings.TrimSuffix(target.Path, "/") + path
	target.RawQuery, target.Fragment, target.RawPath = "", "", ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

func marshalContext(question string, schema []byte, evidence []map[string]string) string {
	// JSON encoding makes source text data, not an instruction delimiter. The
	// server-owned system prompt tells the model to emit only ClaimPlan JSON.
	payload, _ := json.Marshal(struct {
		Question     string              `json:"question"`
		OutputSchema json.RawMessage     `json:"output_schema"`
		Evidence     []map[string]string `json:"evidence"`
	}{question, schema, evidence})
	return string(payload)
}

func validModelEndpoint(value, serverName string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Hostname() != serverName || net.ParseIP(parsed.Hostname()) != nil || !netcanon.ValidCanonicalHost(parsed.Hostname()) {
		return false
	}
	port := parsed.Port()
	if port == "" {
		return parsed.Host == parsed.Hostname()
	}
	parsedPort, err := strconv.Atoi(port)
	return err == nil && parsedPort > 0 && parsedPort <= 65535 && strconv.Itoa(parsedPort) == port && net.JoinHostPort(parsed.Hostname(), port) == parsed.Host
}

func strictJSON(raw []byte, target any) error {
	return jsonv2.Unmarshal(raw, target, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false))
}

func canonicalizeJSON(raw []byte) error {
	var value any
	if err := strictJSON(raw, &value); err != nil {
		return err
	}
	canonical, err := canon.CanonicalJSON(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return errors.New("schema is not canonical")
	}
	return nil
}

func validClaimShape(claim Claim) bool {
	switch claim.Kind {
	case "FACT":
		return claim.Text != nil && claim.UnknownReason == nil && len(claim.EvidenceIDs) > 0 && len(claim.SupportingClaimIDs) == 0
	case "INFERENCE":
		return claim.Text != nil && claim.UnknownReason == nil && len(claim.EvidenceIDs) == 0 && len(claim.SupportingClaimIDs) > 0
	case "UNKNOWN":
		return claim.Text == nil && claim.UnknownReason != nil && len(claim.EvidenceIDs) == 0 && len(claim.SupportingClaimIDs) == 0
	default:
		return false
	}
}

func validUnknownReason(value string) bool {
	return value == "NO_RELEVANT_EVIDENCE" || value == "INSUFFICIENT_SUPPORT" || value == "CONFLICTING_EVIDENCE"
}
func validPurpose(value Purpose) bool {
	return value == PurposeEmbedding || value == PurposeReranking || value == PurposeGeneration || value == PurposeVerification
}
func validText(value string, maximum int) bool {
	return value != "" && utf8.ValidString(value) && len([]byte(value)) <= maximum && !containsControl(value)
}

func validPromptText(value string, maximum int) bool {
	return value != "" && strings.TrimSpace(value) != "" && utf8.ValidString(value) && len([]byte(value)) <= maximum && !containsPromptControl(value)
}

func containsPromptControl(value string) bool {
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '\u200e' || r == '\u200f' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return true
		}
	}
	return false
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '\u200e' || r == '\u200f' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return true
		}
	}
	return false
}
func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

// validEvidenceID accepts any opaque workspace-scoped identifier, exactly
// like SourceObjectID/SourceVersionID/ExtractionID below. GEN-2: a real
// deployment's Evidence IDs are the exact evidence_fragment.id values minted
// by the extraction pipeline (observed on the acc stand as
// "fragment_<ULID>"), not a synthetic "ev_"-prefixed scheme; a fixed prefix
// requirement here made every real GENERATIVE attempt fail MODEL_REQUEST_INVALID
// before ever reaching the model. There is no single prefix guaranteed across
// every source/extraction type, so this validates shape only, as the other
// opaque identifiers in Evidence already do.
func validEvidenceID(value string) bool {
	return validOpaque(value)
}
func validClaimID(value string) bool   { return len(value) > 1 && value[0] == 'C' && digits(value[1:]) }
func validSectionID(value string) bool { return len(value) > 1 && value[0] == 'S' && digits(value[1:]) }
func digits(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func validOpaque(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}
func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func validDigest(value string) bool {
	if validSHA256(value) {
		return true
	}
	const prefix = "hmac-sha256:k"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	rest := value[len(prefix):]
	separator := strings.IndexByte(rest, ':')
	if separator < 1 || separator > 9 || separator+1+64 != len(rest) || rest[0] == '0' {
		return false
	}
	for _, r := range rest[:separator] {
		if r < '0' || r > '9' {
			return false
		}
	}
	for _, r := range rest[separator+1:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

const maxInt64 = int64(math.MaxInt64)
const maximumEvidenceItemBytes = 256 << 10

// Keep deterministic ordering available to callers building logs/evidence
// without exposing content. It also makes a future context-pack hash stable.
func EvidenceIDs(evidence []Evidence) []string {
	ids := make([]string, 0, len(evidence))
	for _, item := range evidence {
		ids = append(ids, item.ID)
	}
	sort.Strings(ids)
	return ids
}
