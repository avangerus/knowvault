// Package embedding is the server-owned boundary for a qualified embedding
// provider. It has no model implementation and cannot choose a fallback:
// callers bind an immutable profile, provide canonical text, and receive an
// exact-dimension vector whose output hash can be recorded with provenance.
// The package is deliberately inert until an exact artifact, tokenizer,
// runtime, license and benchmark profile is activated by deployment.
package embedding

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	SchemaVersion        = "embedding-gateway-v1"
	ProfileSchemaVersion = "embedding-profile-v1"

	DefaultMaxInputBytes = 32 << 10
	MaxInputBytes        = 128 << 10
	MaxResponseBytes     = 8 << 20
	MaxDimension         = 65536
	MaxRevision          = int64(9007199254740991)
	defaultTimeout       = 5 * time.Second
)

// ErrorCode is content-free. Provider response bodies, endpoint strings and
// input text are retained only as trusted diagnostics and never appear in the
// returned error string.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "EMBEDDING_REQUEST_INVALID"
	CodeUnavailable ErrorCode = "EMBEDDING_DEPENDENCY_UNAVAILABLE"
	CodeRejected    ErrorCode = "EMBEDDING_DEPENDENCY_REJECTED"
	CodeResponse    ErrorCode = "EMBEDDING_RESPONSE_INVALID"
	CodeProfile     ErrorCode = "EMBEDDING_PROFILE_UNREADY"
	CodeBinding     ErrorCode = "EMBEDDING_BINDING_MISMATCH"
	CodeBudget      ErrorCode = "EMBEDDING_BUDGET_EXCEEDED"
)

type Error struct {
	code   ErrorCode
	cause  error
	status int
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	return string(err.code)
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *Error) StatusCode() int {
	if err == nil {
		return 0
	}
	return err.status
}

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// Profile is the deployment-owned identity of an embedding model and its
// serving runtime. ProfileHash is the SHA-256 of the canonical projection
// with ProfileHash itself excluded. A provider alias alone is never enough to
// activate a vector space.
type Profile struct {
	SchemaVersion     string `json:"schema_version"`
	ID                string `json:"id"`
	ModelID           string `json:"model_id"`
	ArtifactHash      string `json:"artifact_hash"`
	TokenizerHash     string `json:"tokenizer_hash"`
	RuntimeHash       string `json:"runtime_hash"`
	ConfigurationHash string `json:"configuration_hash"`
	Endpoint          string `json:"endpoint"`
	ServerName        string `json:"server_name"`
	Dimension         int    `json:"dimension"`
	MaxInputBytes     int    `json:"max_input_bytes"`
	Revision          int64  `json:"revision"`
	ProfileHash       string `json:"profile_hash"`
}

func (profile Profile) Validate() error {
	if profile.SchemaVersion != ProfileSchemaVersion || !validOpaque(profile.ID) ||
		!validOpaque(profile.ModelID) || !validSHA256(profile.ArtifactHash) ||
		!validSHA256(profile.TokenizerHash) || !validSHA256(profile.RuntimeHash) ||
		!validSHA256(profile.ConfigurationHash) || !validSHA256(profile.ProfileHash) ||
		profile.Dimension < 1 || profile.Dimension > MaxDimension ||
		profile.MaxInputBytes < 1 || profile.MaxInputBytes > MaxInputBytes ||
		profile.Revision < 1 || profile.Revision > MaxRevision {
		return &Error{code: CodeProfile}
	}
	if profile.Endpoint == "" || profile.ServerName == "" || !validEndpoint(profile.Endpoint, profile.ServerName) {
		return &Error{code: CodeProfile}
	}
	raw, err := profileCanonical(profile)
	if err != nil || canon.Hash(raw) != profile.ProfileHash {
		return &Error{code: CodeProfile, cause: err}
	}
	return nil
}

func (profile Profile) CanonicalBytes() ([]byte, error) {
	return profileCanonical(profile)
}

func profileCanonical(profile Profile) ([]byte, error) {
	return canon.CanonicalJSON(struct {
		SchemaVersion     string `json:"schema_version"`
		ID                string `json:"id"`
		ModelID           string `json:"model_id"`
		ArtifactHash      string `json:"artifact_hash"`
		TokenizerHash     string `json:"tokenizer_hash"`
		RuntimeHash       string `json:"runtime_hash"`
		ConfigurationHash string `json:"configuration_hash"`
		Endpoint          string `json:"endpoint"`
		ServerName        string `json:"server_name"`
		Dimension         int    `json:"dimension"`
		MaxInputBytes     int    `json:"max_input_bytes"`
		Revision          int64  `json:"revision"`
	}{profile.SchemaVersion, profile.ID, profile.ModelID, profile.ArtifactHash,
		profile.TokenizerHash, profile.RuntimeHash, profile.ConfigurationHash,
		profile.Endpoint, profile.ServerName, profile.Dimension,
		profile.MaxInputBytes, profile.Revision})
}

// Binding prevents a vector from being requested under another tenant,
// workspace, operation or profile. Identifiers are server-owned context and
// are intentionally not sent to the model provider.
type Binding struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	OperationID    string `json:"operation_id"`
	ProfileHash    string `json:"profile_hash"`
}

func (binding Binding) Validate(profile Profile) error {
	if !validOpaque(binding.OrganizationID) || !validOpaque(binding.WorkspaceID) ||
		!validOpaque(binding.OperationID) || !validSHA256(binding.ProfileHash) ||
		binding.ProfileHash != profile.ProfileHash {
		return &Error{code: CodeBinding}
	}
	return nil
}

// Result is the only provider output admitted by this package. Values are
// copied out of the response and never silently normalized, padded or
// truncated. OutputHash covers profile, dimension and IEEE-754 float32 bits.
type Result struct {
	ProfileHash string
	Dimension   int
	InputHash   string
	OutputHash  string
	Vector      []float32
}

// Client owns one immutable qualified profile and one purpose-specific HTTPS
// transport. It is safe for concurrent use.
type Client struct {
	profile  Profile
	endpoint url.URL
	http     *http.Client
}

// New validates a deployment profile and constructs a hardened client. A
// custom HTTP client is accepted only for controlled composition tests; the
// production path builds a no-proxy TLS client with the supplied CA roots.
func New(profile Profile, trustRoots *x509.CertPool, clientCertificate *tls.Certificate, httpClient *http.Client) (*Client, error) {
	if err := profile.Validate(); err != nil || trustRoots == nil || len(trustRoots.Subjects()) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, &Error{code: CodeProfile}
	}
	endpoint, err := url.Parse(profile.Endpoint)
	if err != nil || !validEndpoint(profile.Endpoint, profile.ServerName) {
		return nil, &Error{code: CodeProfile, cause: err}
	}
	if httpClient == nil {
		tlsConfig := &tls.Config{RootCAs: trustRoots, ServerName: profile.ServerName, MinVersion: tls.VersionTLS12}
		if clientCertificate != nil {
			tlsConfig.Certificates = []tls.Certificate{*clientCertificate}
		}
		transport := &http.Transport{
			Proxy:                  nil,
			TLSClientConfig:        tlsConfig,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 1 << 20,
			ForceAttemptHTTP2:      true,
		}
		httpClient = &http.Client{Transport: transport, Timeout: defaultTimeout}
	} else if httpClient.Timeout <= 0 || httpClient.Timeout > 60*time.Second {
		return nil, &Error{code: CodeInvalid}
	}
	return &Client{profile: profile, endpoint: *endpoint, http: httpClient}, nil
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
	if closer, ok := client.http.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

// Embed canonicalizes and embeds exactly one input. A provider cannot return
// a result for another binding or model because those fields never come from
// the wire and are reattached from this immutable client profile.
func (client *Client) Embed(ctx context.Context, binding Binding, input string) (Result, error) {
	if client == nil || client.http == nil || ctx == nil {
		return Result{}, &Error{code: CodeInvalid}
	}
	if err := binding.Validate(client.profile); err != nil {
		return Result{}, err
	}
	canonical, err := canon.Canonicalize([]byte(input))
	if err != nil || len(canonical) == 0 || len(canonical) > client.profile.MaxInputBytes ||
		!utf8.Valid(canonical) || !bytes.Equal(canonical, []byte(input)) || !validPromptText(string(canonical)) {
		return Result{}, &Error{code: CodeInvalid, cause: err}
	}
	payload, err := json.Marshal(struct {
		Model          string `json:"model"`
		Input          string `json:"input"`
		EncodingFormat string `json:"encoding_format"`
	}{Model: client.profile.ModelID, Input: string(canonical), EncodingFormat: "float"})
	if err != nil {
		return Result{}, &Error{code: CodeInvalid, cause: err}
	}
	request, err := client.request(ctx, payload)
	if err != nil {
		return Result{}, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return Result{}, &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Result{}, &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(raw) > MaxResponseBytes {
		return Result{}, &Error{code: CodeBudget, cause: err, status: response.StatusCode}
	}
	var wire embeddingResponse
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return Result{}, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	if wire.Object != "list" || wire.Model != client.profile.ModelID || len(wire.Data) != 1 || wire.Data[0].Index != 0 ||
		wire.Data[0].Object != "embedding" || len(wire.Data[0].Embedding) != client.profile.Dimension ||
		!validVector(wire.Data[0].Embedding) {
		return Result{}, &Error{code: CodeResponse, status: response.StatusCode}
	}
	vector := append([]float32(nil), wire.Data[0].Embedding...)
	return Result{ProfileHash: client.profile.ProfileHash, Dimension: client.profile.Dimension,
		InputHash: canon.Hash(canonical), OutputHash: vectorHash(client.profile.ProfileHash, vector), Vector: vector}, nil
}

type embeddingResponse struct {
	Object string `json:"object"`
	Data   []struct {
		Object    string    `json:"object"`
		Embedding []float32 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Model string `json:"model"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		TotalTokens      int `json:"total_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (client *Client) request(ctx context.Context, payload []byte) (*http.Request, error) {
	if client == nil || ctx == nil {
		return nil, &Error{code: CodeInvalid}
	}
	target := client.endpoint
	target.Path = strings.TrimSuffix(target.Path, "/") + "/v1/embeddings"
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

func vectorHash(profileHash string, vector []float32) string {
	// The profile hash and dimension are part of the identity; the binary
	// representation avoids JSON's implementation-dependent float formatting.
	buffer := make([]byte, len(vector)*4)
	for index, value := range vector {
		binary.BigEndian.PutUint32(buffer[index*4:], math.Float32bits(value))
	}
	identity := append([]byte(profileHash+":"+strconv.Itoa(len(vector))+":"), buffer...)
	return canon.Hash(identity)
}

func validVector(vector []float32) bool {
	for _, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return false
		}
	}
	return true
}

func validPromptText(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\r' || character == '\t' {
			continue
		}
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) ||
			(character >= 0x202A && character <= 0x202E) ||
			(character >= 0x2066 && character <= 0x2069) {
			return false
		}
	}
	return true
}

func validEndpoint(raw, serverName string) bool {
	value, err := url.Parse(raw)
	if err != nil || value.Scheme != "https" || value.User != nil || value.Host == "" ||
		value.Path != "" || value.RawPath != "" || value.RawQuery != "" ||
		value.Fragment != "" || value.Opaque != "" || serverName == "" {
		return false
	}
	host := value.Hostname()
	if !netcanon.ValidCanonicalHost(host) || strings.HasSuffix(host, ".") || host != strings.ToLower(host) ||
		net.ParseIP(host) != nil || serverName != host {
		return false
	}
	port := value.Port()
	if port == "" {
		return value.Host == host
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535 && strconv.Itoa(portNumber) == port && net.JoinHostPort(host, port) == value.Host
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) ||
			(character >= 0x202A && character <= 0x202E) ||
			(character >= 0x2066 && character <= 0x2069) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
