package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
)

var _ func(trustbundle.OIDCRoots) (*HardenedHTTPClient, error) = NewProductionHTTPClient

func TestHardenedHTTPClientAllowsOnlyHTTPSAndNeverFollowsRedirects(t *testing.T) {
	calls := 0
	delegate := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host == "redirect.example" {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://other.example/next"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
	})
	client, err := newHardenedHTTPClient(delegate)
	if err != nil {
		t.Fatal(err)
	}
	if !client.valid() || client.client.Timeout != hardenedHTTPTimeout || client.client.Jar != nil {
		t.Fatalf("client profile=%#v", client)
	}
	if _, err := client.client.Get("http://identity.example/.well-known/openid-configuration"); CodeOf(err) != CodeConfigurationInvalid || calls != 0 {
		t.Fatalf("HTTP reached delegate: calls=%d err=%v", calls, err)
	}
	response, err := client.client.Get("https://identity.example/.well-known/openid-configuration")
	if err != nil || response.StatusCode != http.StatusOK || calls != 1 {
		t.Fatalf("HTTPS result=%#v calls=%d err=%v", response, calls, err)
	}
	_ = response.Body.Close()
	response, err = client.client.Get("https://redirect.example/start")
	if err != nil || response.StatusCode != http.StatusFound || calls != 2 {
		t.Fatalf("redirect was followed: result=%#v calls=%d err=%v", response, calls, err)
	}
	_ = response.Body.Close()
	for _, formatted := range []string{fmt.Sprint(client), fmt.Sprintf("%#v", client), fmt.Sprintf("%#v", client.client.Transport)} {
		if !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("HTTP client formatting not redacted: %q", formatted)
		}
	}
}

func TestHardenedHTTPClientRejectsDeclaredOversizedBodyBeforeReadingAndClosesIt(t *testing.T) {
	body := &trackingReadCloser{reader: &fixedByteReader{remaining: maximumOIDCResponseBodyBytes + 1}}
	client, err := newHardenedHTTPClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body,
			ContentLength: maximumOIDCResponseBodyBytes + 1, Request: request}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.client.Get("https://identity.example/oversized")
	if response != nil || CodeOf(err) != CodeConfigurationInvalid || body.reads.Load() != 0 || body.closes.Load() != 1 {
		t.Fatalf("declared oversized response=%v err=%v reads=%d closes=%d", response, err, body.reads.Load(), body.closes.Load())
	}
}

func TestHardenedHTTPClientRejectsChunkedOverflowAtMaxPlusOneAndClosesOnce(t *testing.T) {
	body := &trackingReadCloser{reader: &fixedByteReader{remaining: maximumOIDCResponseBodyBytes + 1}}
	client, err := newHardenedHTTPClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, ContentLength: -1, Request: request}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.client.Get("https://identity.example/chunked")
	if err != nil {
		t.Fatal(err)
	}
	contents, readErr := io.ReadAll(response.Body)
	if len(contents) != int(maximumOIDCResponseBodyBytes) || CodeOf(readErr) != CodeConfigurationInvalid ||
		readErr.Error() != string(CodeConfigurationInvalid) || body.closes.Load() != 1 {
		t.Fatalf("chunked bytes=%d err=%v closes=%d", len(contents), readErr, body.closes.Load())
	}
	if closeErr := response.Body.Close(); closeErr != nil || body.closes.Load() != 1 {
		t.Fatalf("repeated close err=%v closes=%d", closeErr, body.closes.Load())
	}
}

func TestHardenedHTTPClientAcceptsExactBodyLimitAndDelegatesClose(t *testing.T) {
	body := &trackingReadCloser{reader: &fixedByteReader{remaining: maximumOIDCResponseBodyBytes}}
	client, err := newHardenedHTTPClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body,
			ContentLength: maximumOIDCResponseBodyBytes, Request: request}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.client.Get("https://identity.example/exact")
	if err != nil {
		t.Fatal(err)
	}
	contents, readErr := io.ReadAll(response.Body)
	if readErr != nil || len(contents) != int(maximumOIDCResponseBodyBytes) || body.closes.Load() != 0 {
		t.Fatalf("exact-limit bytes=%d err=%v closes=%d", len(contents), readErr, body.closes.Load())
	}
	if closeErr := response.Body.Close(); closeErr != nil || body.closes.Load() != 1 {
		t.Fatalf("close err=%v closes=%d", closeErr, body.closes.Load())
	}
}

func TestExchangeUsesTheSameHardenedHTTPClient(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.String() != "https://identity.example/token" || request.Method != http.MethodPost {
			t.Fatalf("unexpected token request: %s %s", request.Method, request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"access_token":"opaque","token_type":"Bearer"}`)), Request: request,
		}, nil
	})
	hardened, err := newHardenedHTTPClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	digestor, err := NewHMACDigestor(1, bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewSecureAttempt(digestor)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{
		configuration: ProviderConfiguration{IssuerURL: "https://identity.example", ClientID: "client_001", RedirectURL: "https://workspace.example/auth/callback", SigningAlgorithms: []string{"RS256"}},
		endpoint:      oauth2.Endpoint{AuthURL: "https://identity.example/authorize", TokenURL: "https://identity.example/token"},
		verifier:      &coreoidc.IDTokenVerifier{}, digestor: digestor, httpClient: hardened.client,
	}
	if _, err := client.ExchangeAndVerify(context.Background(), "authorization-code", "client-secret", attempt); CodeOf(err) != CodeTokenInvalid || calls != 1 {
		t.Fatalf("exchange did not use hardened transport: calls=%d err=%v", calls, err)
	}
}

func TestDiscoverExchangeAndJWKSUseInjectedHardenedClientNotDefaultClient(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digestor, err := NewHMACDigestor(1, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := NewSecureAttempt(digestor)
	if err != nil {
		t.Fatal(err)
	}
	_, nonce, _, _, ok := attempt.TransportMaterial()
	if !ok {
		t.Fatal("fresh attempt did not expose protocol material")
	}
	idToken := signedRS256Token(t, privateKey, "https://identity.example", "client_001", nonce)
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(unsignedIntegerBytes(privateKey.PublicKey.E)),
	}}})
	if err != nil {
		t.Fatal(err)
	}

	var calls []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls = append(calls, request.Method+" "+request.URL.String())
		switch request.URL.String() {
		case "https://identity.example/.well-known/openid-configuration":
			return jsonResponse(request, http.StatusOK, `{
				"issuer":"https://identity.example",
				"authorization_endpoint":"https://identity.example/authorize",
				"token_endpoint":"https://identity.example/token",
				"jwks_uri":"https://identity.example/keys",
				"response_types_supported":["code"],
				"subject_types_supported":["public"],
				"id_token_signing_alg_values_supported":["RS256"]
			}`), nil
		case "https://identity.example/token":
			if request.Method != http.MethodPost {
				t.Fatalf("token method=%s", request.Method)
			}
			return jsonResponse(request, http.StatusOK, `{"access_token":"opaque-access","token_type":"Bearer","id_token":"`+idToken+`","expires_in":300}`), nil
		case "https://identity.example/keys":
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(jwks)), Request: request}, nil
		default:
			return nil, fmt.Errorf("unexpected hardened request %s %s", request.Method, request.URL)
		}
	})
	hardened, err := newHardenedHTTPClient(transport)
	if err != nil {
		t.Fatal(err)
	}

	previousDefaultClient := http.DefaultClient
	defaultCalls := 0
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		defaultCalls++
		return nil, errors.New("default HTTP client must not be used")
	})}
	t.Cleanup(func() { http.DefaultClient = previousDefaultClient })

	client, err := Discover(context.Background(), hardened, ProviderConfiguration{
		IssuerURL: "https://identity.example", ClientID: "client_001", RedirectURL: "https://workspace.example/auth/callback", SigningAlgorithms: []string{"RS256"},
	}, digestor)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	subject, err := client.ExchangeAndVerify(context.Background(), "authorization-code", "client-secret", attempt)
	if err != nil {
		t.Fatalf("exchange/verification failed: %v", err)
	}
	if subject.Digest.Value() == "" || !subject.ExpiresAt.After(time.Now()) {
		t.Fatalf("verified subject=%#v", subject)
	}
	wantCalls := []string{
		"GET https://identity.example/.well-known/openid-configuration",
		"POST https://identity.example/token",
		"GET https://identity.example/keys",
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") || defaultCalls != 0 {
		t.Fatalf("hardened calls=%v default calls=%d", calls, defaultCalls)
	}
}

func TestHardenedHTTPClientRejectsUnsafeProductionTransport(t *testing.T) {
	unsafeTLS := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	oldTLS := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS11}}
	maxOldTLS := &http.Transport{TLSClientConfig: &tls.Config{MaxVersion: tls.VersionTLS11}}
	customTLS := &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("not called") }}
	for name, transport := range map[string]*http.Transport{"nil": nil, "insecure": unsafeTLS, "old minimum tls": oldTLS, "old maximum tls": maxOldTLS, "custom tls dial": customTLS} {
		if _, err := NewHardenedHTTPClient(transport); CodeOf(err) != CodeConfigurationInvalid {
			t.Fatalf("%s transport accepted: %v", name, err)
		}
	}
	if client, err := NewHardenedHTTPClient(&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}); err != nil || !client.valid() {
		t.Fatalf("reviewed production transport rejected: %#v err=%v", client, err)
	}
}

func TestProductionHTTPClientRejectsMissingTrustRoots(t *testing.T) {
	if _, err := NewProductionHTTPClient(trustbundle.OIDCRoots{}); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("zero typed trust roots accepted: %v", err)
	}
}

func TestProductionHTTPClientOwnsExactDirectTransportProfile(t *testing.T) {
	roots := testOIDCRoots(t, 1)
	client, err := NewProductionHTTPClient(roots)
	if err != nil {
		t.Fatal(err)
	}
	if !client.valid() || client.client.Timeout != hardenedHTTPTimeout || client.client.Jar != nil {
		t.Fatalf("production client profile=%#v", client)
	}
	wrapper, ok := client.client.Transport.(httpsOnlyRoundTripper)
	if !ok {
		t.Fatalf("production client transport type=%T", client.client.Transport)
	}
	bounded, ok := wrapper.delegate.(boundedResponseRoundTripper)
	if !ok {
		t.Fatalf("production bounded transport type=%T", wrapper.delegate)
	}
	transport, ok := bounded.delegate.(*http.Transport)
	if !ok {
		t.Fatalf("production delegate type=%T", wrapper.delegate)
	}
	if transport.Proxy != nil || transport.DialContext == nil || transport.DialTLS != nil || transport.DialTLSContext != nil || len(transport.TLSNextProto) != 0 {
		t.Fatal("production transport admits proxy, implicit dialing, or custom TLS dialing")
	}
	if !transport.ForceAttemptHTTP2 || !transport.DisableCompression || transport.DisableKeepAlives ||
		transport.MaxIdleConns != productionMaxIdleConnections || transport.MaxIdleConnsPerHost != productionMaxIdleConnectionsHost ||
		transport.MaxConnsPerHost != productionMaxConnectionsHost || transport.IdleConnTimeout != productionIdleConnectionTimeout ||
		transport.TLSHandshakeTimeout != productionTLSHandshakeTimeout || transport.ResponseHeaderTimeout != productionResponseHeaderTimeout ||
		transport.ExpectContinueTimeout != productionExpectContinueTimeout || transport.MaxResponseHeaderBytes != productionMaxResponseHeaderBytes {
		t.Fatal("production transport does not match the fixed bounded profile")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.MaxVersion != 0 ||
		transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "" {
		t.Fatal("production TLS profile is not pinned to cloned explicit roots and TLS 1.2+")
	}
	internalSubjects := len(transport.TLSClientConfig.RootCAs.Subjects())
	callerPool, err := roots.NewCertPool()
	if err != nil {
		t.Fatal(err)
	}
	callerPool.AddCert(testRootCertificate(t, 2))
	if len(callerPool.Subjects()) <= internalSubjects || len(transport.TLSClientConfig.RootCAs.Subjects()) != internalSubjects {
		t.Fatal("caller mutation changed production trust roots")
	}
}

func TestProductionHTTPClientCloseIdleConnectionsClosesItsPool(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	roots, serverCertificate := testServerTrust(t)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)

	client, err := NewProductionHTTPClient(roots)
	if err != nil {
		t.Fatal(err)
	}
	getAndClose := func() {
		response, requestErr := client.client.Get(server.URL)
		if requestErr != nil {
			t.Fatalf("production HTTPS request failed: %v", requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("response close failed: %v", closeErr)
		}
	}
	getAndClose()
	if connections.Load() != 1 {
		t.Fatalf("initial connection count=%d", connections.Load())
	}
	client.CloseIdleConnections()
	getAndClose()
	if connections.Load() < 2 {
		t.Fatalf("idle connection remained reusable after close: count=%d", connections.Load())
	}
}

func TestHardenedHTTPClientClosesOnlyItsInjectedIdleTransport(t *testing.T) {
	transport := &closingRoundTripper{}
	client, err := newHardenedHTTPClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	if transport.closed != 1 {
		t.Fatalf("close calls=%d", transport.closed)
	}
	var nilClient *HardenedHTTPClient
	nilClient.CloseIdleConnections()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type closingRoundTripper struct{ closed int }

func (*closingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("not called")
}

func (transport *closingRoundTripper) CloseIdleConnections() { transport.closed++ }

type trackingReadCloser struct {
	reader io.Reader
	reads  atomic.Int32
	closes atomic.Int32
}

func (body *trackingReadCloser) Read(destination []byte) (int, error) {
	body.reads.Add(1)
	return body.reader.Read(destination)
}

func (body *trackingReadCloser) Close() error {
	body.closes.Add(1)
	return nil
}

type fixedByteReader struct{ remaining int64 }

func (reader *fixedByteReader) Read(destination []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := len(destination)
	if int64(count) > reader.remaining {
		count = int(reader.remaining)
	}
	for index := 0; index < count; index++ {
		destination[index] = 'x'
	}
	reader.remaining -= int64(count)
	return count, nil
}

func jsonResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}
}

func signedRS256Token(t *testing.T, privateKey *rsa.PrivateKey, issuer, audience, nonce string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key","typ":"JWT"}`))
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "aud": audience, "sub": "subject_001", "nonce": nonce, "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func unsignedIntegerBytes(value int) []byte {
	return new(big.Int).SetInt64(int64(value)).Bytes()
}

func testRootCertificate(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("OIDC test root %d", serial)},
		NotBefore:             time.Unix(1_700_000_000, 0).UTC(),
		NotAfter:              time.Unix(2_000_000_000, 0).UTC(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testOIDCRoots(t *testing.T, serial int64) trustbundle.OIDCRoots {
	t.Helper()
	certificate := testRootCertificate(t, serial)
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	roots, err := trustbundle.NewOIDCRootsPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	for index := range raw {
		raw[index] ^= 0xff
	}
	for index := range certificate.Raw {
		certificate.Raw[index] ^= 0xff
	}
	return roots
}

func testServerTrust(t *testing.T) (trustbundle.OIDCRoots, tls.Certificate) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(500), Subject: pkix.Name{CommonName: "OIDC test CA"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rootsPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	roots, err := trustbundle.NewOIDCRootsPEM(rootsPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(501), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverPrivate}
	return roots, certificate
}
