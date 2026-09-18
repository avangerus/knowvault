// Package reranking admits bounded scores from a deployment-owned cross encoder.
// Provider text, credentials and diagnostics never appear in public errors.
package reranking

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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	ProfileSchemaVersion = "reranking-profile-v1"
	MaxCandidates        = 128
	MaxInputBytes        = 1 << 20
	MaxQueryBytes        = 32 << 10
	MaxTextBytes         = 8 << 10
	MaxResponseBytes     = 64 << 10
	MaxRevision          = int64(9007199254740991)
)

type ErrorCode string

const (
	CodeInvalid     ErrorCode = "RERANKING_REQUEST_INVALID"
	CodeUnavailable ErrorCode = "RERANKING_DEPENDENCY_UNAVAILABLE"
	CodeRejected    ErrorCode = "RERANKING_DEPENDENCY_REJECTED"
	CodeResponse    ErrorCode = "RERANKING_RESPONSE_INVALID"
	CodeProfile     ErrorCode = "RERANKING_PROFILE_UNREADY"
	CodeBudget      ErrorCode = "RERANKING_BUDGET_EXCEEDED"
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

// ProfileHash covers the canonical projection with only ProfileHash excluded.
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
	Revision          int64  `json:"revision"`
	MaxCandidates     int    `json:"max_candidates"`
	MaxInputBytes     int    `json:"max_input_bytes"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	ProfileHash       string `json:"profile_hash"`
}

func (profile Profile) CanonicalBytes() ([]byte, error) {
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
		Revision          int64  `json:"revision"`
		MaxCandidates     int    `json:"max_candidates"`
		MaxInputBytes     int    `json:"max_input_bytes"`
		TimeoutSeconds    int    `json:"timeout_seconds"`
	}{profile.SchemaVersion, profile.ID, profile.ModelID, profile.ArtifactHash,
		profile.TokenizerHash, profile.RuntimeHash, profile.ConfigurationHash,
		profile.Endpoint, profile.ServerName, profile.Revision, profile.MaxCandidates,
		profile.MaxInputBytes, profile.TimeoutSeconds})
}

func (profile Profile) Validate() error {
	if profile.SchemaVersion != ProfileSchemaVersion || !validOpaque(profile.ID) || !validOpaque(profile.ModelID) ||
		!validSHA256(profile.ArtifactHash) || !validSHA256(profile.TokenizerHash) || !validSHA256(profile.RuntimeHash) ||
		!validSHA256(profile.ConfigurationHash) || !validSHA256(profile.ProfileHash) ||
		profile.Revision < 1 || profile.Revision > MaxRevision || profile.MaxCandidates < 1 || profile.MaxCandidates > MaxCandidates ||
		profile.MaxInputBytes < 1 || profile.MaxInputBytes > MaxInputBytes || profile.TimeoutSeconds < 1 || profile.TimeoutSeconds > 120 ||
		!validEndpoint(profile.Endpoint, profile.ServerName) {
		return &Error{code: CodeProfile}
	}
	raw, err := profile.CanonicalBytes()
	if err != nil || canon.Hash(raw) != profile.ProfileHash {
		return &Error{code: CodeProfile}
	}
	return nil
}

type Client struct {
	profile  Profile
	http     *http.Client
	endpoint string
}

// A supplied HTTP client is a controlled composition-test seam. Production
// creates a private-address-only, no-proxy transport with explicit CA and mTLS.
func New(profile Profile, roots *x509.CertPool, certificate *tls.Certificate, supplied *http.Client) (*Client, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if roots == nil || len(roots.Subjects()) == 0 || certificate == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, &Error{code: CodeProfile}
	}
	var httpClient http.Client
	if supplied == nil {
		tlsConfig := &tls.Config{RootCAs: roots.Clone(), ServerName: profile.ServerName, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*certificate}}
		httpClient.Transport = &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: privateDialContext,
			DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, MaxIdleConns: 4, MaxIdleConnsPerHost: 4,
			IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: time.Duration(profile.TimeoutSeconds) * time.Second}
	} else {
		if supplied.Timeout <= 0 || supplied.Timeout > 120*time.Second || supplied.Transport == nil || supplied.Jar != nil {
			return nil, &Error{code: CodeInvalid}
		}
		httpClient = *supplied
	}
	httpClient.Timeout = time.Duration(profile.TimeoutSeconds) * time.Second
	if supplied != nil && supplied.Timeout < httpClient.Timeout {
		httpClient.Timeout = supplied.Timeout
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{profile: profile, http: &httpClient, endpoint: profile.Endpoint + "/rerank"}, nil
}

func (client *Client) Profile() Profile {
	if client == nil {
		return Profile{}
	}
	return client.profile
}
func (client *Client) RerankingIdentity() (string, string) {
	profile := client.Profile()
	return profile.ModelID, profile.ProfileHash
}
func (client *Client) Close() error {
	if client != nil && client.http != nil {
		client.http.CloseIdleConnections()
	}
	return nil
}

// Scores requires exactly one finite probability per input. TEI sorts the wire
// result by score; indices restore the original order without trusting position.
func (client *Client) Scores(ctx context.Context, query string, texts []string) ([]float64, error) {
	if client == nil || client.http == nil || ctx == nil || !validPromptText(query) || len(texts) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	if len(texts) > client.profile.MaxCandidates || len(query) > MaxQueryBytes {
		return nil, &Error{code: CodeBudget}
	}
	total := len(query)
	for _, text := range texts {
		if !validPromptText(text) {
			return nil, &Error{code: CodeInvalid}
		}
		if len(text) > MaxTextBytes {
			return nil, &Error{code: CodeBudget}
		}
		total += len(text)
		if total > client.profile.MaxInputBytes {
			return nil, &Error{code: CodeBudget}
		}
	}
	if total > client.profile.MaxInputBytes {
		return nil, &Error{code: CodeBudget}
	}
	payload, err := json.Marshal(struct {
		Query      string   `json:"query"`
		Texts      []string `json:"texts"`
		Truncate   bool     `json:"truncate"`
		ReturnText bool     `json:"return_text"`
	}{query, texts, true, false})
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	defer clearBytes(payload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	defer clearBytes(raw)
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	if len(raw) > MaxResponseBytes {
		return nil, &Error{code: CodeBudget}
	}
	var wire []struct {
		Index *int     `json:"index"`
		Score *float64 `json:"score"`
	}
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || len(wire) != len(texts) {
		return nil, &Error{code: CodeResponse}
	}
	scores := make([]float64, len(texts))
	seen := make([]bool, len(texts))
	for _, entry := range wire {
		if entry.Index == nil || entry.Score == nil || *entry.Index < 0 || *entry.Index >= len(texts) || seen[*entry.Index] || math.IsNaN(*entry.Score) || math.IsInf(*entry.Score, 0) || *entry.Score < 0 || *entry.Score > 1 {
			return nil, &Error{code: CodeResponse}
		}
		seen[*entry.Index] = true
		scores[*entry.Index] = *entry.Score
	}
	return scores, nil
}

func privateDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("reranking dial rejected")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("reranking resolution unavailable")
	}
	for _, address := range addresses {
		if address.Zone != "" || !(address.IP.IsPrivate() || address.IP.IsLoopback()) {
			return nil, errors.New("reranking address rejected")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("reranking dial unavailable")
}

func validEndpoint(raw, serverName string) bool {
	value, err := url.Parse(raw)
	if err != nil || value.Scheme != "https" || value.User != nil || value.Host == "" || value.Path != "" || value.RawPath != "" || value.RawQuery != "" || value.ForceQuery || value.Fragment != "" || value.Opaque != "" {
		return false
	}
	host := value.Hostname()
	if !netcanon.ValidCanonicalHost(host) || strings.HasSuffix(host, ".") || host != strings.ToLower(host) || serverName != host || net.ParseIP(host) != nil {
		return false
	}
	if strings.Contains(host, ".") && !strings.HasSuffix(host, ".local") && !strings.HasSuffix(host, ".internal") {
		return false
	}
	port := value.Port()
	if port == "" {
		return value.Host == host
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port && net.JoinHostPort(host, port) == value.Host
}

func validOpaque(value string) bool {
	return len(value) <= 256 && validPromptText(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\t")
}
func validPromptText(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r >= 0x7f && r <= 0x9f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return false
		}
	}
	return true
}
func validSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[7:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
