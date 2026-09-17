package embedding

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/canon"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func testRoots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("embed.example")})
	return roots
}

func testProfile() Profile {
	profile := Profile{
		SchemaVersion:     ProfileSchemaVersion,
		ID:                "mxbai-embed-large-v1",
		ModelID:           "mixedbread-ai/mxbai-embed-large-v1",
		ArtifactHash:      "sha256:" + strings.Repeat("a", 64),
		TokenizerHash:     "sha256:" + strings.Repeat("b", 64),
		RuntimeHash:       "sha256:" + strings.Repeat("c", 64),
		ConfigurationHash: "sha256:" + strings.Repeat("d", 64),
		Endpoint:          "https://embed.example",
		ServerName:        "embed.example",
		Dimension:         3,
		MaxInputBytes:     1024,
		Revision:          1,
	}
	raw, err := profile.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	profile.ProfileHash = canon.Hash(raw)
	return profile
}

func newTestClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := New(testProfile(), testRoots(), nil, &http.Client{Transport: transport, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func testBinding(profile Profile) Binding {
	return Binding{OrganizationID: "org-a", WorkspaceID: "workspace-a", OperationID: "question-run-a", ProfileHash: profile.ProfileHash}
}

func TestProfileCanonicalHashAndDrift(t *testing.T) {
	profile := testProfile()
	if err := profile.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	profile.ModelID = "other-model"
	if CodeOf(profile.Validate()) != CodeProfile {
		t.Fatal("profile identity drift passed validation")
	}
}

func TestNewRejectsUnsafeEndpointAndTimeout(t *testing.T) {
	base := testProfile()
	cases := map[string]func(*Profile){
		"http": func(profile *Profile) { profile.Endpoint = "http://embed.example" },
		"ip":   func(profile *Profile) { profile.Endpoint, profile.ServerName = "https://127.0.0.1", "127.0.0.1" },
		"path": func(profile *Profile) { profile.Endpoint = "https://embed.example/v1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile := base
			mutate(&profile)
			if _, err := New(profile, testRoots(), nil, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return testResponse(http.StatusOK, `{}`), nil
			}), Timeout: time.Second}); CodeOf(err) != CodeProfile {
				t.Fatalf("New() code = %q, want %q", CodeOf(err), CodeProfile)
			}
		})
	}
	if _, err := New(base, testRoots(), nil, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, `{}`), nil
	}), Timeout: 61 * time.Second}); CodeOf(err) != CodeInvalid {
		t.Fatalf("long timeout code = %q, want %q", CodeOf(err), CodeInvalid)
	}
}

func TestEmbedBuildsCanonicalProviderRequestAndHashesOutput(t *testing.T) {
	profile := testProfile()
	var request *http.Request
	var payload []byte
	client := newTestClient(t, roundTripFunc(func(got *http.Request) (*http.Response, error) {
		request = got
		payload, _ = io.ReadAll(got.Body)
		return testResponse(http.StatusOK, `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"mixedbread-ai/mxbai-embed-large-v1","usage":{"prompt_tokens":2,"total_tokens":2,"completion_tokens":0}}`), nil
	}))
	result, err := client.Embed(context.Background(), testBinding(profile), "Kafka\n\u0448\u0438\u043d\u0430")
	if err != nil {
		t.Fatalf("Embed() error = %v", err)
	}
	if result.ProfileHash != profile.ProfileHash || result.Dimension != 3 || len(result.Vector) != 3 || result.InputHash == "" || result.OutputHash == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if request == nil || request.Method != http.MethodPost || request.URL.String() != "https://embed.example/v1/embeddings" {
		t.Fatalf("unexpected request: %#v", request)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 3 || body["model"] != profile.ModelID || body["input"] != "Kafka\n\u0448\u0438\u043d\u0430" || body["encoding_format"] != "float" {
		t.Fatalf("provider request leaked or changed fields: %#v", body)
	}
	canonical, _ := canon.Canonicalize([]byte("Kafka\n\u0448\u0438\u043d\u0430"))
	if result.InputHash != canon.Hash(canonical) {
		t.Fatalf("input hash = %q, want canonical hash", result.InputHash)
	}
}

func TestEmbedRejectsBindingAndCanonicalizationDriftBeforeNetwork(t *testing.T) {
	profile := testProfile()
	called := false
	client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusOK, `{}`), nil
	}))
	cases := map[string]Binding{
		"profile": {OrganizationID: "org-a", WorkspaceID: "workspace-a", OperationID: "run", ProfileHash: "sha256:" + strings.Repeat("e", 64)},
		"empty":   {},
		"control": {OrganizationID: "org-a", WorkspaceID: "workspace-a", OperationID: "run\u202e", ProfileHash: profile.ProfileHash},
	}
	for name, binding := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := client.Embed(context.Background(), binding, "text"); CodeOf(err) != CodeBinding {
				t.Fatalf("binding code = %q, want %q", CodeOf(err), CodeBinding)
			}
		})
	}
	if _, err := client.Embed(context.Background(), testBinding(profile), "a\r\nb"); CodeOf(err) != CodeInvalid {
		t.Fatalf("noncanonical newline code = %q, want %q", CodeOf(err), CodeInvalid)
	}
	if called {
		t.Fatal("invalid embedding input reached provider")
	}
}

func TestEmbedRejectsUnknownDuplicateWrongModelAndWrongDimension(t *testing.T) {
	profile := testProfile()
	cases := map[string]string{
		"unknown":     `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"mixedbread-ai/mxbai-embed-large-v1","extra":1}`,
		"duplicate":   `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"mixedbread-ai/mxbai-embed-large-v1","model":"other"}`,
		"wrong model": `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"other"}`,
		"wrong dim":   `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0}],"model":"mixedbread-ai/mxbai-embed-large-v1"}`,
	}
	for name, responseBody := range cases {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return testResponse(http.StatusOK, responseBody), nil
			}))
			if _, err := client.Embed(context.Background(), testBinding(profile), "text"); CodeOf(err) != CodeResponse {
				t.Fatalf("response code = %q, want %q", CodeOf(err), CodeResponse)
			}
		})
	}
}

func TestEmbedRejectsNonFiniteVectorsAndProviderErrorsWithoutDisclosure(t *testing.T) {
	if validVector([]float32{0.1, float32(math.NaN()), 0.3}) || validVector([]float32{0.1, float32(math.Inf(1)), 0.3}) {
		t.Fatal("non-finite vector accepted")
	}
	profile := testProfile()
	client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusBadGateway, "secret=not-for-users"), nil
	}))
	_, err := client.Embed(context.Background(), testBinding(profile), "text")
	if CodeOf(err) != CodeRejected || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "embed.example") {
		t.Fatalf("unsafe provider error: %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("unexpected cancellation")
	}
}
