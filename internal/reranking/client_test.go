package reranking

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/canon"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func testProfile() Profile {
	p := Profile{SchemaVersion: ProfileSchemaVersion, ID: "bge-m3", ModelID: "BAAI/bge-reranker-v2-m3", ArtifactHash: "sha256:" + strings.Repeat("a", 64), TokenizerHash: "sha256:" + strings.Repeat("b", 64), RuntimeHash: "sha256:" + strings.Repeat("c", 64), ConfigurationHash: "sha256:" + strings.Repeat("d", 64), Endpoint: "https://knowvault-reranking:443", ServerName: "knowvault-reranking", Revision: 1, MaxCandidates: 32, MaxInputBytes: 512 << 10, TimeoutSeconds: 30}
	raw, err := p.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	p.ProfileHash = canon.Hash(raw)
	return p
}
func testRoots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("test")})
	return roots
}
func testCertificate() *tls.Certificate {
	return &tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: struct{}{}}
}
func newTestClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	c, err := New(testProfile(), testRoots(), testCertificate(), &http.Client{Transport: transport, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestScoresRestoresInputOrderAndBoundsProviderRequest(t *testing.T) {
	c := newTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://knowvault-reranking:443/rerank" || r.Method != "POST" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatalf("unsafe request: %v", r.URL)
		}
		var body struct {
			Query      string   `json:"query"`
			Texts      []string `json:"texts"`
			Truncate   bool     `json:"truncate"`
			ReturnText bool     `json:"return_text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Query != "where" || len(body.Texts) != 2 || !body.Truncate || body.ReturnText {
			t.Fatalf("wrong request: %+v", body)
		}
		return testResponse(200, `[{"index":1,"score":0.9},{"index":0,"score":0.2}]`), nil
	}))
	scores, err := c.Scores(context.Background(), "where", []string{"A", "B"})
	if err != nil || len(scores) != 2 || scores[0] != 0.2 || scores[1] != 0.9 {
		t.Fatalf("scores=%v err=%v", scores, err)
	}
	model, hash := c.RerankingIdentity()
	if model != testProfile().ModelID || hash != testProfile().ProfileHash {
		t.Fatal("identity drift")
	}
}

func TestScoresRejectsPartialDuplicateMalformedAndUnboundedOutput(t *testing.T) {
	cases := map[string]string{
		"partial":          `[{"index":0,"score":0.1}]`,
		"duplicate":        `[{"index":0,"score":0.1},{"index":0,"score":0.2}]`,
		"out of range":     `[{"index":0,"score":0.1},{"index":2,"score":0.2}]`,
		"negative index":   `[{"index":-1,"score":0.1},{"index":1,"score":0.2}]`,
		"missing score":    `[{"index":0},{"index":1,"score":0.2}]`,
		"missing index":    `[{"score":0.1},{"index":1,"score":0.2}]`,
		"duplicate member": `[{"index":0,"score":0.1,"score":0.3},{"index":1,"score":0.2}]`,
		"unknown member":   `[{"index":0,"score":0.1,"text":"secret"},{"index":1,"score":0.2}]`,
		"negative score":   `[{"index":0,"score":-0.1},{"index":1,"score":0.2}]`,
		"large score":      `[{"index":0,"score":1.1},{"index":1,"score":0.2}]`,
		"infinite":         `[{"index":0,"score":1e999},{"index":1,"score":0.2}]`,
		"null":             `null`, "trailing": `[{"index":0,"score":0.1},{"index":1,"score":0.2}] true`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(200, body), nil }))
			scores, err := c.Scores(context.Background(), "Q", []string{"A", "B"})
			if scores != nil || CodeOf(err) != CodeResponse {
				t.Fatalf("scores=%v err=%v", scores, err)
			}
		})
	}
}

func TestScoresRejectsBudgetsBeforeNetwork(t *testing.T) {
	c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("budget reached network"); return nil, nil }))
	cases := []struct {
		query string
		texts []string
		code  ErrorCode
	}{{"", []string{"A"}, CodeInvalid}, {"Q", nil, CodeInvalid}, {"Q", []string{"\x00"}, CodeInvalid}, {strings.Repeat("Q", MaxQueryBytes+1), []string{"A"}, CodeBudget}, {"Q", []string{strings.Repeat("A", MaxTextBytes+1)}, CodeBudget}, {"Q", make([]string, 33), CodeBudget}}
	for _, item := range cases {
		if _, err := c.Scores(context.Background(), item.query, item.texts); CodeOf(err) != item.code {
			t.Fatalf("got %v want %v", err, item.code)
		}
	}
	c.profile.MaxInputBytes = 3
	if _, err := c.Scores(context.Background(), "QQ", []string{"AA"}); CodeOf(err) != CodeBudget {
		t.Fatal(err)
	}
}

func TestScoresSanitizesFailuresAndHonorsCancellation(t *testing.T) {
	for _, status := range []int{302, 401, 500} {
		c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			r := testResponse(status, "SECRET INPUT CREDENTIAL")
			r.Header.Set("Location", "https://public.example")
			return r, nil
		}))
		_, err := c.Scores(context.Background(), "Q", []string{"A"})
		if CodeOf(err) != CodeRejected || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(err)
		}
	}
	c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("SECRET ENDPOINT") }))
	_, err := c.Scores(context.Background(), "Q", []string{"A"})
	if err.Error() != string(CodeUnavailable) {
		t.Fatal(err)
	}
	c = newTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err = c.Scores(ctx, "Q", []string{"A"})
	if CodeOf(err) != CodeUnavailable || time.Since(start) > time.Second {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = c.Scores(ctx, "Q", []string{"A"})
	if CodeOf(err) != CodeUnavailable {
		t.Fatal(err)
	}
}

func TestScoresRejectsOversizedResponse(t *testing.T) {
	c := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(200, strings.Repeat(" ", MaxResponseBytes+1)), nil
	}))
	if _, err := c.Scores(context.Background(), "Q", []string{"A"}); CodeOf(err) != CodeBudget {
		t.Fatal(err)
	}
}

func TestProfileRejectsDriftAndUnsafeEndpoints(t *testing.T) {
	p := testProfile()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.ModelID = "different"
	if CodeOf(p.Validate()) != CodeProfile {
		t.Fatal("drift accepted")
	}
	for _, endpoint := range []string{"http://knowvault-reranking", "https://cloud.example", "https://127.0.0.1", "https://knowvault-reranking/rerank", "https://knowvault-reranking?", "https://knowvault-reranking:0443"} {
		p := testProfile()
		p.Endpoint = endpoint
		raw, _ := p.CanonicalBytes()
		p.ProfileHash = canon.Hash(raw)
		if CodeOf(p.Validate()) != CodeProfile {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	if _, err := New(testProfile(), testRoots(), nil, nil); CodeOf(err) != CodeProfile {
		t.Fatal("missing mTLS accepted")
	}
	c, err := New(testProfile(), testRoots(), testCertificate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	transport := c.http.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || len(transport.TLSClientConfig.Certificates) != 1 || transport.DialContext == nil || c.http.CheckRedirect == nil {
		t.Fatal("unsafe production transport")
	}
}
