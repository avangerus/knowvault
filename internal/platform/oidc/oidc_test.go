package oidc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
)

func TestNewAttemptUsesDistinctCSPRNGValuesAndDomainSeparatedDigests(t *testing.T) {
	t.Parallel()

	digestor, err := NewHMACDigestor(7, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	entropy := bytes.NewReader(append(append(append(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32)...), bytes.Repeat([]byte{0x03}, 32)...), bytes.Repeat([]byte{0x04}, 32)...))
	attempt, err := newAttempt(entropy, digestor)
	if err != nil {
		t.Fatal(err)
	}
	if !validAttempt(attempt) || attempt.state == attempt.nonce || attempt.nonce == attempt.pkceVerifier || attempt.pkceVerifier == attempt.browserBinding {
		t.Fatalf("attempt material is invalid or reused: %#v", attempt)
	}
	if attempt.stateDigest.Value() == attempt.nonceDigest.Value() || strings.Contains(attempt.stateDigest.Value(), attempt.state) {
		t.Fatalf("attempt digest is not domain-separated or leaked raw material: %#v", attempt)
	}
	for _, formatted := range []string{fmt.Sprint(attempt), fmt.Sprintf("%#v", attempt), fmt.Sprintf("%+v", attempt)} {
		if strings.Contains(formatted, attempt.state) || strings.Contains(formatted, attempt.pkceVerifier) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("attempt formatting leaked raw material: %q", formatted)
		}
	}
	forged := attempt
	forged.pkceVerifier = forged.state
	if validAttempt(forged) {
		t.Fatal("attempt accepted state reused as PKCE verifier")
	}
	if _, _, _, _, ok := forged.TransportMaterial(); ok {
		t.Fatal("forged attempt released transport material")
	}
	if _, _, _, _, ok := (Attempt{}).TransportMaterial(); ok {
		t.Fatal("zero attempt released transport material")
	}
	restored, err := RestoreTransportAttempt(digestor, attempt.state, attempt.nonce, attempt.pkceVerifier, attempt.browserBinding)
	if err != nil || !validAttempt(restored) {
		t.Fatalf("authenticated transport material was not restored: %#v err=%v", restored, err)
	}
	if _, _, _, _, ok := restored.TransportMaterial(); ok {
		t.Fatal("restored callback attempt was accepted as a fresh seal input")
	}
}

func TestDigestorAndConfigurationFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := NewHMACDigestor(0, bytes.Repeat([]byte{0x42}, 32)); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("zero HMAC key version accepted: %v", err)
	}
	if _, err := NewHMACDigestor(1, make([]byte, 32)); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("all-zero HMAC key accepted: %v", err)
	}
	digestor, err := NewHMACDigestor(1, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := digestor.Digest("unknown-purpose", "value"); CodeOf(err) != CodeMaterialFailed {
		t.Fatalf("unknown digest purpose accepted: %v", err)
	}

	valid := ProviderConfiguration{
		IssuerURL: "https://identity.example", ClientID: "client_001", RedirectURL: "https://workspace.example/auth/callback",
		SigningAlgorithms: []string{"ES256", "RS256"},
	}
	if !validConfiguration(valid) {
		t.Fatal("valid provider configuration rejected")
	}
	for name, configuration := range map[string]ProviderConfiguration{
		"http issuer":          {IssuerURL: "http://identity.example", ClientID: "client_001", RedirectURL: valid.RedirectURL, SigningAlgorithms: []string{"RS256"}},
		"none algorithm":       {IssuerURL: valid.IssuerURL, ClientID: "client_001", RedirectURL: valid.RedirectURL, SigningAlgorithms: []string{"none"}},
		"unordered algorithms": {IssuerURL: valid.IssuerURL, ClientID: "client_001", RedirectURL: valid.RedirectURL, SigningAlgorithms: []string{"RS256", "ES256"}},
	} {
		if validConfiguration(configuration) {
			t.Fatalf("invalid provider configuration accepted: %s", name)
		}
	}
}

func TestSessionAndCSRFDigestsAreDomainSeparated(t *testing.T) {
	t.Parallel()

	digestor, err := NewHMACDigestor(3, bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	session, err := digestor.Digest("session_token", "same-opaque-browser-value")
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := digestor.Digest("csrf", "same-opaque-browser-value")
	if err != nil {
		t.Fatal(err)
	}
	if session.Value() == csrf.Value() || strings.Contains(session.Value(), "same-opaque-browser-value") || strings.Contains(csrf.Value(), "same-opaque-browser-value") {
		t.Fatalf("session and csrf digests are not domain-separated: %q / %q", session.Value(), csrf.Value())
	}
}

func TestHMACDigestorFormattingDoesNotExposeSecret(t *testing.T) {
	secret := []byte("super-secret-key-material-that-must-not-leak")
	digestor, err := NewHMACDigestor(1, secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := digestor.KeyMaterialFingerprint(), sha256.Sum256(secret); got != want {
		t.Fatalf("key material fingerprint mismatch: %x", got)
	}
	valueCopy := *digestor
	for _, formatted := range []string{
		fmt.Sprint(digestor), fmt.Sprintf("%#v", digestor), fmt.Sprintf("%+v", digestor),
		fmt.Sprint(valueCopy), fmt.Sprintf("%#v", valueCopy), fmt.Sprintf("%+v", valueCopy),
	} {
		if strings.Contains(formatted, string(secret)) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("digestor formatting leaked secret: %q", formatted)
		}
	}
}

func TestHMACDigestorCopiesShareCloseAndZeroizeRetainedSecret(t *testing.T) {
	var nilDigestor *HMACDigestor
	nilDigestor.Close()
	if _, err := nilDigestor.Digest("state", "opaque-value"); CodeOf(err) != CodeMaterialFailed {
		t.Fatalf("nil digestor did not fail closed: %v", err)
	}
	if fingerprint := nilDigestor.KeyMaterialFingerprint(); fingerprint != ([32]byte{}) {
		t.Fatalf("nil digestor exposed a key fingerprint: %x", fingerprint)
	}

	secret := bytes.Repeat([]byte{0x6b}, 32)
	digestor, err := NewHMACDigestor(9, secret)
	if err != nil {
		t.Fatal(err)
	}
	retainedSecret := digestor.state.secret
	valueCopy := *digestor
	valueCopy.Close()

	if _, err := digestor.Digest("state", "opaque-value"); CodeOf(err) != CodeMaterialFailed {
		t.Fatalf("closed original handle accepted digest after copied handle closed: %v", err)
	}
	if fingerprint := digestor.KeyMaterialFingerprint(); fingerprint != ([32]byte{}) {
		t.Fatalf("closed handle exposed a key fingerprint: %x", fingerprint)
	}
	for index, value := range retainedSecret {
		if value != 0 {
			t.Fatalf("retained secret was not zeroized at byte %d", index)
		}
	}
	if !digestor.state.closed || digestor.state.keyVersion != 0 || digestor.state.secret != nil {
		t.Fatal("closed digestor retained live lifecycle state")
	}
	digestor.Close()
	valueCopy.Close()
}

func TestHMACDigestorConcurrentCloseIsRaceSafe(t *testing.T) {
	digestor, err := NewHMACDigestor(4, bytes.Repeat([]byte{0x39}, 32))
	if err != nil {
		t.Fatal(err)
	}
	retainedSecret := digestor.state.secret
	valueCopy := *digestor
	start := make(chan struct{})
	errorsSeen := make(chan error, 128)
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			<-start
			if worker%4 == 0 {
				valueCopy.Close()
				return
			}
			for iteration := 0; iteration < 8; iteration++ {
				_, digestErr := digestor.Digest("nonce", "concurrent-value")
				if digestErr != nil && CodeOf(digestErr) != CodeMaterialFailed {
					errorsSeen <- digestErr
				}
				_ = valueCopy.KeyMaterialFingerprint()
			}
		}(worker)
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for digestErr := range errorsSeen {
		t.Fatalf("unexpected concurrent digest error: %v", digestErr)
	}
	digestor.Close()

	if _, err := valueCopy.Digest("nonce", "after-close"); CodeOf(err) != CodeMaterialFailed {
		t.Fatalf("copied handle accepted digest after close: %v", err)
	}
	if fingerprint := valueCopy.KeyMaterialFingerprint(); fingerprint != ([32]byte{}) {
		t.Fatalf("copied handle exposed fingerprint after close: %x", fingerprint)
	}
	for index, value := range retainedSecret {
		if value != 0 {
			t.Fatalf("concurrent close did not zero retained byte %d", index)
		}
	}
}

func TestValidateProviderConfigurationReturnsContentFreeError(t *testing.T) {
	valid := ProviderConfiguration{
		IssuerURL: "https://identity.example", ClientID: "client_001", RedirectURL: "https://workspace.example/auth/callback",
		SigningAlgorithms: []string{"ES256", "RS256"},
	}
	if err := ValidateProviderConfiguration(valid); err != nil {
		t.Fatalf("valid provider configuration rejected: %v", err)
	}

	sensitive := "sensitive-provider-configuration-value"
	invalid := valid
	invalid.IssuerURL = "http://" + sensitive + ".example"
	err := ValidateProviderConfiguration(invalid)
	if CodeOf(err) != CodeConfigurationInvalid || err.Error() != string(CodeConfigurationInvalid) {
		t.Fatalf("invalid configuration returned wrong error: %v", err)
	}
	for _, formatted := range []string{err.Error(), fmt.Sprint(err), fmt.Sprintf("%#v", err), fmt.Sprintf("%+v", err)} {
		if strings.Contains(formatted, sensitive) {
			t.Fatalf("configuration validation error leaked rejected content: %q", formatted)
		}
	}
}

func TestOIDCErrorAndClientFormattingDoNotExposeCausesOrDigestors(t *testing.T) {
	secret := []byte("another-super-secret-key-material")
	digestor, err := NewHMACDigestor(1, secret)
	if err != nil {
		t.Fatal(err)
	}
	errorValue := &Error{code: CodeExchangeFailed, cause: fmt.Errorf("provider response contains %s", secret)}
	client := Client{digestor: digestor}
	for _, formatted := range []string{fmt.Sprintf("%#v", errorValue), fmt.Sprint(client), fmt.Sprintf("%#v", client), fmt.Sprintf("%+v", client)} {
		if strings.Contains(formatted, string(secret)) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("OIDC formatting leaked secret: %q", formatted)
		}
	}
}

func TestAttemptDigestFailureIsMappedToContentFreeOIDCError(t *testing.T) {
	_, err := newAttempt(bytes.NewReader(make([]byte, rawBytes*4)), failingDigestor{})
	if CodeOf(err) != CodeMaterialFailed || err.Error() != string(CodeMaterialFailed) || strings.Contains(fmt.Sprintf("%#v", err), "provider secret") {
		t.Fatalf("error=%v formatted=%#v", err, err)
	}
}

func TestAuthorizationCodeValidationRejectsControlContent(t *testing.T) {
	t.Parallel()

	if !validAuthorizationCode("code-opaque_001") {
		t.Fatal("valid authorization code rejected")
	}
	for _, invalid := range []string{"", "code\nvalue", string(bytes.Repeat([]byte{'a'}, maxAuthorizationCodeLength+1))} {
		if validAuthorizationCode(invalid) {
			t.Fatalf("invalid authorization code accepted: %q", invalid)
		}
	}
}

type failingDigestor struct{}

func (failingDigestor) Digest(string, string) (identity.KeyedDigest, error) {
	return identity.KeyedDigest{}, errors.New("provider secret must stay hidden")
}

func (failingDigestor) KeyMaterialFingerprint() [32]byte {
	return sha256.Sum256([]byte("failing-digestor"))
}
