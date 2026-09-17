//go:build linux

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// staticIDP is the in-process OIDC provider the e2e product server logs in
// against. It implements exactly the surface the production client consumes —
// discovery, S256 PKCE authorization, code exchange with a client secret, an
// RS256 id_token echoing the nonce — over the TLS chain pinned to the e2e CA.
// The issuer subject is the fixed owner subject whose keyed digest is seeded
// as the external identity. It is test infrastructure: it holds no product
// state and its tokens never leave the container.
type staticIDP struct {
	issuer      string
	clientID    string
	redirectURI string
	secret      string

	signingKey *rsa.PrivateKey
	keyID      string
	server     *http.Server

	mu      sync.Mutex
	pending map[string]pendingAuthorization // authorization code -> proof
}

type pendingAuthorization struct {
	challenge string
	nonce     string
}

// startIDP loads the OIDC client secret from the generated mount (the same
// reference the server resolves), generates a signing key, and serves
// :9443 over the e2e CA chain. It returns once the discovery endpoint
// answers.
func startIDP(ctx context.Context, cfg config) (*staticIDP, error) {
	secret, err := mountClientSecret()
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("idp signing key: %w", err)
	}
	kid := make([]byte, 16)
	if _, err := rand.Read(kid); err != nil {
		return nil, err
	}
	idp := &staticIDP{
		issuer:      cfg.issuer,
		clientID:    cfg.clientID,
		redirectURI: cfg.publicOrigin + "/auth/callback",
		secret:      secret,
		signingKey:  key,
		keyID:       base64.RawURLEncoding.EncodeToString(kid),
		pending:     make(map[string]pendingAuthorization),
	}
	server := &http.Server{
		Addr:              ":9443",
		Handler:           idp,
		ReadHeaderTimeout: 10 * time.Second,
	}
	idp.server = server
	go func() {
		_ = server.ListenAndServeTLS(filepath.Join(cfg.caDir, "localhost.crt"), filepath.Join(cfg.caDir, "localhost.key"))
	}()
	if err := waitHTTP(ctx, cfg, "https://localhost:9443/.well-known/openid-configuration", 20*time.Second); err != nil {
		return nil, fmt.Errorf("idp readiness: %w", err)
	}
	return idp, nil
}

// mountClientSecret reads the OIDC client secret for the pinned reference from
// the operator-generated mount manifest, the same file the product server
// resolves at preflight and login time.
func mountClientSecret() (string, error) {
	rawManifest, err := os.ReadFile("/run/knowvault/secrets/manifest.json")
	if err != nil {
		return "", fmt.Errorf("read mount manifest: %w", err)
	}
	var manifest struct {
		OIDCClientSecrets []struct {
			OrganizationID string `json:"organization_id"`
			ProviderID     string `json:"provider_id"`
			Reference      string `json:"reference"`
			Filename       string `json:"filename"`
		} `json:"oidc_client_secrets"`
	}
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return "", fmt.Errorf("parse mount manifest: %w", err)
	}
	for _, entry := range manifest.OIDCClientSecrets {
		if entry.Reference == clientSecretReference {
			secret, err := os.ReadFile(filepath.Join("/run/knowvault/secrets", entry.Filename))
			if err != nil {
				return "", fmt.Errorf("read client secret: %w", err)
			}
			if len(secret) == 0 {
				return "", fmt.Errorf("client secret file is empty")
			}
			return string(secret), nil
		}
	}
	return "", fmt.Errorf("mount manifest carries no %s client secret", clientSecretReference)
}

func (idp *staticIDP) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		idp.discovery(writer, request)
	case "/authorize":
		idp.authorize(writer, request)
	case "/token":
		idp.token(writer, request)
	case "/jwks":
		idp.jwks(writer, request)
	default:
		http.Error(writer, "not found", http.StatusNotFound)
	}
}

func (idp *staticIDP) discovery(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{
		"issuer":                                idp.issuer,
		"authorization_endpoint":                idp.issuer + "/authorize",
		"token_endpoint":                        idp.issuer + "/token",
		"jwks_uri":                              idp.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (idp *staticIDP) authorize(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := request.URL.Query()
	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	scope := query.Get("scope")
	state := query.Get("state")
	nonce := query.Get("nonce")
	challengeMethod := query.Get("code_challenge_method")
	challenge := query.Get("code_challenge")
	if responseType != "code" || clientID != idp.clientID || redirectURI != idp.redirectURI ||
		scope != "openid" || state == "" || nonce == "" || challengeMethod != "S256" || len(challenge) != 43 {
		http.Error(writer, "invalid authorization request", http.StatusBadRequest)
		return
	}
	rawCode := make([]byte, 24)
	if _, err := rand.Read(rawCode); err != nil {
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(rawCode)
	idp.mu.Lock()
	idp.pending[code] = pendingAuthorization{challenge: challenge, nonce: nonce}
	idp.mu.Unlock()
	target := redirectURI + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	http.Redirect(writer, request, target, http.StatusSeeOther)
}

func (idp *staticIDP) token(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	// The production client authenticates with HTTP Basic; accept it and, for
	// robustness, the equivalent form credentials as well.
	clientID, clientSecret, basic := request.BasicAuth()
	if clientID == "" && clientSecret == "" {
		clientID, clientSecret, basic = request.PostForm.Get("client_id"), request.PostForm.Get("client_secret"), true
	}
	if !basic || clientID != idp.clientID || subtle.ConstantTimeCompare([]byte(clientSecret), []byte(idp.secret)) != 1 {
		http.Error(writer, "invalid client", http.StatusUnauthorized)
		return
	}
	if request.PostForm.Get("grant_type") != "authorization_code" ||
		request.PostForm.Get("redirect_uri") != idp.redirectURI {
		http.Error(writer, "invalid grant", http.StatusBadRequest)
		return
	}
	code := request.PostForm.Get("code")
	verifier := request.PostForm.Get("code_verifier")
	idp.mu.Lock()
	pending, ok := idp.pending[code]
	delete(idp.pending, code) // one-time use regardless of the outcome
	idp.mu.Unlock()
	if !ok {
		http.Error(writer, "invalid code", http.StatusBadRequest)
		return
	}
	challengeDigest := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(challengeDigest[:])), []byte(pending.challenge)) != 1 {
		http.Error(writer, "invalid verifier", http.StatusBadRequest)
		return
	}
	idToken, err := idp.issueIDToken(pending.nonce)
	if err != nil {
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSONResponse(writer, http.StatusOK, map[string]any{
		"access_token": "e2e-access-token",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

// issueIDToken builds the minimal RS256 id_token the production verifier
// accepts: issuer, the fixed owner subject, the exact client audience, expiry
// and the nonce echoed from the authorization request. The signing is stdlib
// only; no external JWT dependency enters the harness.
func (idp *staticIDP) issueIDToken(nonce string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString(mustJSONBytes(map[string]any{
		"alg": "RS256", "kid": idp.keyID, "typ": "JWT",
	}))
	now := time.Now().Unix()
	claims := base64.RawURLEncoding.EncodeToString(mustJSONBytes(map[string]any{
		"iss": idp.issuer, "sub": ownerSubject, "aud": idp.clientID,
		"iat": now, "exp": now + 300, "nonce": nonce,
	}))
	unsigned := header + "." + claims
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, idp.signingKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (idp *staticIDP) jwks(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	publicKey := idp.signingKey.Public().(*rsa.PublicKey)
	writeJSONResponse(writer, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": idp.keyID,
			"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}},
	})
}

func mustJSONBytes(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err) // fixed literals only
	}
	return raw
}

func writeJSONResponse(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// waitHTTP polls one HTTPS GET until it answers or the deadline passes. It
// validates the chain against the process-wide certificate file the harness
// pinned at startup.
func waitHTTP(ctx context.Context, cfg config, target string, timeout time.Duration) error {
	caPEM, err := os.ReadFile(filepath.Join(cfg.caDir, "ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("ca pool: no certificates")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		response, err := client.Get(target)
		if err == nil {
			_ = response.Body.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("did not answer: %w", lastErr)
}

// readCertificatePEM is a small helper for the TLS front; kept here so all
// PEM handling of the e2e chain lives in one file.
func readCertificatePEM(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return block.Bytes, nil
}
