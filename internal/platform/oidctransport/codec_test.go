package oidctransport

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	platformoidc "knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

func TestSealOpenRoundTripUsesCanonicalEnvelopeAndRedactsFormatting(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(append(bytes.Repeat([]byte{0x11}, nonceBytes), bytes.Repeat([]byte{0x22}, nonceBytes)...)), now)
	record := testRecord(t, now)

	first, err := codec.Seal(record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Seal(record)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(first, ".")
	if len(parts) != 4 || parts[0] != envelopeVersion || parts[1] != "key_oidc_001" || len(first) > maxEnvelopeBytes || first == second {
		t.Fatalf("unexpected envelopes %q / %q", first, second)
	}
	opened, err := codec.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	if opened.OrganizationID() != record.OrganizationID() || opened.ProviderID() != record.ProviderID() || opened.ProviderRevision() != record.ProviderRevision() ||
		opened.AttemptID() != record.AttemptID() || opened.State() != record.State() || opened.Nonce() != record.Nonce() || opened.PKCEVerifier() != record.PKCEVerifier() ||
		opened.BrowserBinding() != record.BrowserBinding() || !opened.IssuedAt().Equal(record.IssuedAt()) || !opened.ExpiresAt().Equal(record.ExpiresAt()) {
		t.Fatalf("opened record mismatch: %#v", opened)
	}
	for _, formatted := range []string{fmt.Sprint(codec), fmt.Sprintf("%#v", codec), fmt.Sprint(record), fmt.Sprintf("%#v", record)} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, record.State()) || strings.Contains(formatted, record.PKCEVerifier()) {
			t.Fatalf("formatting leaked sealed material: %q", formatted)
		}
	}
}

func TestOpenFailsClosedForMalformedUnknownAndAADMismatch(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(bytes.Repeat([]byte{0x41}, nonceBytes*8)), now)
	envelope, err := codec.Seal(testRecord(t, now))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(envelope, ".")
	tampered := append([]string(nil), parts...)
	replacement := "A"
	if strings.HasSuffix(tampered[3], replacement) {
		replacement = "B"
	}
	tampered[3] = tampered[3][:len(tampered[3])-1] + replacement
	unknownKid := append([]string(nil), parts...)
	unknownKid[1] = "key_other_001"
	wrongOrigin := testCodec(t, "https://other.example", bytes.NewReader(bytes.Repeat([]byte{0x22}, nonceBytes)), now)
	wrongTenantSecurity, err := tenantsecurity.NewContext("org_other", "idp_primary", "https://workspace.example", "key_identity", testDigestor{"identity"}, "key_session", testDigestor{"session"})
	if err != nil {
		t.Fatal(err)
	}
	wrongTenant, err := newCodec(wrongTenantSecurity, "key_oidc_transport", "key_oidc_001", bytes.Repeat([]byte{0x7b}, keyBytes), bytes.NewReader(bytes.Repeat([]byte{0x23}, nonceBytes)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	wrongProviderSecurity, err := tenantsecurity.NewContext("org_alpha", "idp_other", "https://workspace.example", "key_identity", testDigestor{"identity"}, "key_session", testDigestor{"session"})
	if err != nil {
		t.Fatal(err)
	}
	wrongProvider, err := newCodec(wrongProviderSecurity, "key_oidc_transport", "key_oidc_001", bytes.Repeat([]byte{0x7b}, keyBytes), bytes.NewReader(bytes.Repeat([]byte{0x24}, nonceBytes)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	for name, value := range map[string]string{
		"empty":               "",
		"too long":            strings.Repeat("x", maxEnvelopeBytes+1),
		"bad version":         "v2." + strings.Join(parts[1:], "."),
		"unknown kid":         strings.Join(unknownKid, "."),
		"extra segment":       envelope + ".extra",
		"noncanonical base64": parts[0] + "." + parts[1] + "." + parts[2] + "=." + parts[3],
		"wrong nonce length":  parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte{1}) + "." + parts[3],
		"tampered cipher":     strings.Join(tampered, "."),
	} {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			if _, err := codec.Open(value); CodeOf(err) != CodeOpenRejected {
				t.Fatalf("error=%v code=%s", err, CodeOf(err))
			}
		})
	}
	if _, err := wrongOrigin.Open(envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("cross-origin replay accepted: %v", err)
	}
	if _, err := wrongTenant.Open(envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("cross-tenant replay accepted: %v", err)
	}
	if _, err := wrongProvider.Open(envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("cross-provider replay accepted: %v", err)
	}
}

func TestEnvelopeWorksAcrossInstancesAndRotationInvalidatesPendingLogin(t *testing.T) {
	now := testNow()
	key := bytes.Repeat([]byte{0x7b}, keyBytes)
	first := testCodecWithKey(t, key, bytes.NewReader(bytes.Repeat([]byte{0x51}, nonceBytes)), now)
	second := testCodecWithKey(t, key, bytes.NewReader(bytes.Repeat([]byte{0x52}, nonceBytes)), now)
	envelope, err := first.Seal(testRecord(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open(envelope); err != nil {
		t.Fatalf("second instance rejected shared KMS key: %v", err)
	}
	rotated := testCodecWithKey(t, bytes.Repeat([]byte{0x7c}, keyBytes), bytes.NewReader(bytes.Repeat([]byte{0x53}, nonceBytes)), now)
	if _, err := rotated.Open(envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("rotated key accepted pending login: %v", err)
	}
}

func TestOpenStrictlyRejectsPlaintextSchemaTenantAndExpiry(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(bytes.Repeat([]byte{0x33}, nonceBytes*12)), now)
	record := testRecord(t, now)
	valid, err := marshalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	tenantMismatch := strings.Replace(string(valid), `"organization_id":"org_alpha"`, `"organization_id":"org_other"`, 1)
	unknown := strings.TrimSuffix(string(valid), "}") + `,"unexpected":true}`
	duplicate := strings.TrimSuffix(string(valid), "}") + `,"schema":"oidc-transport-v1"}`
	invalidUTF8 := append([]byte(`{"schema":"oidc-transport-v1","organization_id":"`), 0xff)
	expired, err := newRecord("org_alpha", "idp_primary", 7, "attempt_alpha", rawValue("state"), rawValue("nonce"), rawValue("pkce"), rawValue("binding"), now.Add(-10*time.Minute), now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	expiredWire, err := marshalRecord(expired)
	if err != nil {
		t.Fatal(err)
	}
	expiresNow, err := newRecord("org_alpha", "idp_primary", 7, "attempt_alpha", rawValue("state"), rawValue("nonce"), rawValue("pkce"), rawValue("binding"), now.Add(-time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	expiresNowWire, err := marshalRecord(expiresNow)
	if err != nil {
		t.Fatal(err)
	}
	futureIssued, err := newRecord("org_alpha", "idp_primary", 7, "attempt_alpha", rawValue("state"), rawValue("nonce"), rawValue("pkce"), rawValue("binding"), now.Add(time.Second), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	futureIssuedWire, err := marshalRecord(futureIssued)
	if err != nil {
		t.Fatal(err)
	}

	for name, plaintext := range map[string][]byte{
		"unknown member":   []byte(unknown),
		"duplicate member": []byte(duplicate),
		"tenant mismatch":  []byte(tenantMismatch),
		"invalid utf8":     invalidUTF8,
		"expired":          expiredWire,
		"expires at now":   expiresNowWire,
		"issued in future": futureIssuedWire,
	} {
		name, plaintext := name, plaintext
		t.Run(name, func(t *testing.T) {
			envelope, err := codec.sealPlaintext(plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := codec.Open(envelope); CodeOf(err) != CodeOpenRejected {
				t.Fatalf("error=%v code=%s", err, CodeOf(err))
			}
		})
	}
}

func TestConfigurationRecordAndEntropyFailuresDoNotLeak(t *testing.T) {
	now := testNow()
	security := testSecurity(t, "https://workspace.example")
	for name, fixture := range map[string]struct {
		keyID string
		key   []byte
	}{
		"short key":      {"key_oidc_001", bytes.Repeat([]byte{0x11}, keyBytes-1)},
		"all-zero key":   {"key_oidc_001", make([]byte, keyBytes)},
		"invalid key id": {"key bad", bytes.Repeat([]byte{0x11}, keyBytes)},
		"delimiter kid":  {"key.with.dot", bytes.Repeat([]byte{0x11}, keyBytes)},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			if _, err := newCodec(security, "key_oidc_transport", fixture.keyID, fixture.key, bytes.NewReader(nil), func() time.Time { return now }); CodeOf(err) != CodeConfigurationInvalid {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if _, err := newRecord("org alpha", "idp_primary", 7, "attempt_alpha", rawValue("state"), rawValue("nonce"), rawValue("pkce"), rawValue("binding"), now, now.Add(time.Minute)); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("invalid record accepted: %v", err)
	}
	codec, err := newCodec(security, "key_oidc_transport", "key_oidc_001", bytes.Repeat([]byte{0x11}, keyBytes), failingReader{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if envelope, err := codec.Seal(testRecord(t, now)); CodeOf(err) != CodeSealFailed || envelope != "" {
		t.Fatalf("entropy result=%q err=%v", envelope, err)
	}
	if _, ok := any(&Error{code: CodeOpenRejected}).(interface{ Unwrap() error }); ok {
		t.Fatal("error must not expose a cause")
	}
}

func TestCanonicalPlaintextAADAndKidLimit(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", bytes.NewReader(bytes.Repeat([]byte{0x61}, nonceBytes*4)), now)
	record := testRecord(t, now)
	canonical, err := marshalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	canonicalValue := jsontext.Value(append([]byte(nil), canonical...))
	if err := canonicalValue.Canonicalize(); err != nil || !bytes.Equal(canonical, canonicalValue) {
		t.Fatalf("plaintext is not exact JCS: %q err=%v", canonical, err)
	}
	if !bytes.Contains(canonical, []byte(`"schema":"oidc-transport-v1"`)) || !bytes.Contains(canonical, []byte(`"login_attempt_id":"attempt_alpha"`)) || bytes.Contains(canonical, []byte(`"schema_version":`)) || bytes.Contains(canonical, []byte(`"attempt_id":`)) {
		t.Fatalf("plaintext contract drift: %s", canonical)
	}
	uncanonical, err := jsonv2.Marshal(wireRecord{
		Schema: plaintextSchema, OrganizationID: string(record.OrganizationID()), ProviderID: string(record.ProviderID()), ProviderRevision: record.ProviderRevision(),
		LoginAttemptID: record.AttemptID(), State: record.State(), Nonce: record.Nonce(), PKCEVerifier: record.PKCEVerifier(), BrowserBinding: record.BrowserBinding(),
		IssuedAt: record.IssuedAt().Format(time.RFC3339Nano), ExpiresAt: record.ExpiresAt().Format(time.RFC3339Nano),
	})
	if err != nil || bytes.Equal(uncanonical, canonical) {
		t.Fatalf("test fixture did not create a noncanonical JSON form: %q err=%v", uncanonical, err)
	}
	envelope, err := codec.sealPlaintext(uncanonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Open(envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("noncanonical plaintext accepted: %v", err)
	}

	aad := codec.aad()
	aadValue := jsontext.Value(append([]byte(nil), aad...))
	if err := aadValue.Canonicalize(); err != nil || !bytes.Equal(aad, aadValue) || !bytes.Contains(aad, []byte(`"schema":"oidc-cookie-aad-v1"`)) || !bytes.Contains(aad, []byte(`"cookie_name":"__Host-knowvault_oidc"`)) || !bytes.Contains(aad, []byte(`"kid":"key_oidc_001"`)) {
		t.Fatalf("AAD is not canonical/bound: %q err=%v", aad, err)
	}
	security := testSecurity(t, "https://workspace.example")
	if _, err := newCodec(security, "key_oidc_transport", strings.Repeat("k", 33), bytes.Repeat([]byte{0x01}, keyBytes), bytes.NewReader(nil), func() time.Time { return now }); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("oversized kid accepted: %v", err)
	}
	for _, reused := range []string{"key_identity", "key_session"} {
		if _, err := newCodec(security, reused, "key_oidc_001", bytes.Repeat([]byte{0x01}, keyBytes), bytes.NewReader(nil), func() time.Time { return now }); CodeOf(err) != CodeConfigurationInvalid {
			t.Fatalf("digest key reference reused for AEAD: %q err=%v", reused, err)
		}
	}
}

func TestRecordRequiresBoundedCanonicalOIDCValues(t *testing.T) {
	now := testNow()
	for name, mutate := range map[string]func(*recordInput){
		"short state":       func(value *recordInput) { value.state = "short" },
		"reused verifier":   func(value *recordInput) { value.pkce = value.state },
		"invalid attempt":   func(value *recordInput) { value.attemptID = "a b" },
		"zero revision":     func(value *recordInput) { value.revision = 0 },
		"too long lifetime": func(value *recordInput) { value.expiresAt = value.issuedAt.Add(maxAttemptLifetime + time.Nanosecond) },
		"inverted time":     func(value *recordInput) { value.expiresAt = value.issuedAt },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			input := validRecordInput(now)
			mutate(&input)
			if _, err := input.record(); CodeOf(err) != CodeConfigurationInvalid {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCodecCopiesShareCloseAndEraseRetainedKey(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", cryptorand.Reader, now)
	copyValue := *codec
	envelope, err := copyValue.Seal(testRecord(t, now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Open(envelope); err != nil {
		t.Fatalf("original handle could not open copy's envelope: %v", err)
	}
	for _, formatted := range []string{fmt.Sprint(copyValue), fmt.Sprintf("%#v", copyValue), fmt.Sprint(&copyValue), fmt.Sprintf("%#v", &copyValue)} {
		if formatted != "oidctransport.Codec{[REDACTED]}" {
			t.Fatalf("copy formatting was not redacted: %q", formatted)
		}
	}
	if err := copyValue.Close(); err != nil {
		t.Fatal(err)
	}
	if err := codec.Close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
	if !codec.state.closed || codec.state.key != ([keyBytes]byte{}) || codec.state.entropy != nil || codec.state.now != nil {
		t.Fatalf("closed shared state retained lifecycle material: %#v", codec)
	}
	if _, err := codec.Seal(testRecord(t, now)); CodeOf(err) != CodeSealFailed {
		t.Fatalf("closed original sealed: %v", err)
	}
	if _, err := copyValue.Open(envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("closed copy opened: %v", err)
	}
}

func TestCodecZeroAndNilHandlesFailClosed(t *testing.T) {
	now := testNow()
	record := testRecord(t, now)
	var zero Codec
	var nilCodec *Codec
	for name, codec := range map[string]*Codec{"zero": &zero, "nil": nilCodec} {
		if _, err := codec.Seal(record); CodeOf(err) != CodeSealFailed {
			t.Fatalf("%s codec sealed: %v", name, err)
		}
		if _, err := codec.Open("v1.key_oidc_001.x.y"); CodeOf(err) != CodeOpenRejected {
			t.Fatalf("%s codec opened: %v", name, err)
		}
		if err := codec.Close(); err != nil {
			t.Fatalf("%s codec close: %v", name, err)
		}
	}
	if _, err := NewBrowserTransport(&zero); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("zero codec accepted by browser boundary: %v", err)
	}
}

func TestCodecCloseWaitsForInflightSeal(t *testing.T) {
	now := testNow()
	entropy := &blockingReader{started: make(chan struct{}), release: make(chan struct{})}
	codec := testCodec(t, "https://workspace.example", entropy, now)
	sealDone := make(chan error, 1)
	go func() {
		_, err := codec.Seal(testRecord(t, now))
		sealDone <- err
	}()
	<-entropy.started

	closeEntered := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeEntered)
		closeDone <- codec.Close()
	}()
	<-closeEntered
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before in-flight Seal: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(entropy.release)
	if err := <-sealDone; err != nil {
		t.Fatalf("in-flight Seal failed during Close: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if codec.state.key != ([keyBytes]byte{}) {
		t.Fatal("Close did not erase the retained key")
	}
}

func TestCodecConcurrentCopiesAreRaceFree(t *testing.T) {
	now := testNow()
	codec := testCodec(t, "https://workspace.example", cryptorand.Reader, now)
	record := testRecord(t, now)
	envelope, err := codec.Seal(record)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 24
	start := make(chan struct{})
	errors := make(chan error, workers)
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(workers)
	done.Add(workers)
	for index := 0; index < workers; index++ {
		copyValue := *codec
		go func(worker int, handle Codec) {
			defer done.Done()
			ready.Done()
			<-start
			for iteration := 0; iteration < 25; iteration++ {
				if worker%2 == 0 {
					if _, err := handle.Open(envelope); err != nil {
						errors <- err
						return
					}
					continue
				}
				if _, err := handle.Seal(record); err != nil {
					errors <- err
					return
				}
			}
		}(index, copyValue)
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(errors)
	for err := range errors {
		t.Fatalf("concurrent copied handle failed: %v", err)
	}
	if err := codec.Close(); err != nil {
		t.Fatal(err)
	}
}

type recordInput struct {
	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	revision       int64
	attemptID      string
	state          string
	nonce          string
	pkce           string
	binding        string
	issuedAt       time.Time
	expiresAt      time.Time
}

func validRecordInput(now time.Time) recordInput {
	return recordInput{
		organizationID: "org_alpha", providerID: "idp_primary", revision: 7, attemptID: "attempt_alpha",
		state: rawValue("state"), nonce: rawValue("nonce"), pkce: rawValue("pkce"), binding: rawValue("binding"),
		issuedAt: now.Add(-time.Minute), expiresAt: now.Add(5 * time.Minute),
	}
}

func (input recordInput) record() (Record, error) {
	return newRecord(input.organizationID, input.providerID, input.revision, input.attemptID, input.state, input.nonce, input.pkce, input.binding, input.issuedAt, input.expiresAt)
}

func TestExportedRecordBoundaryAcceptsOnlySecureOIDCAttempt(t *testing.T) {
	now := testNow()
	attempt, err := platformoidc.NewSecureAttempt(testDigestor{"identity"})
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewRecord("org_alpha", "idp_primary", 7, "attempt_alpha", attempt, now, now.Add(5*time.Minute))
	if err != nil || !record.valid() {
		t.Fatalf("secure attempt rejected: %#v err=%v", record, err)
	}
	if _, err := NewRecord("org_alpha", "idp_primary", 7, "attempt_alpha", platformoidc.Attempt{}, now, now.Add(5*time.Minute)); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("zero/forged attempt accepted: %v", err)
	}
	if !record.MatchesState(record.State()) || record.MatchesState(rawValue("different")) {
		t.Fatal("record state comparison did not exact-match")
	}
	restored, err := record.RestoreAttempt(testDigestor{"identity"})
	if err != nil || restored.StateDigest().Value() != attempt.StateDigest().Value() || restored.NonceDigest().Value() != attempt.NonceDigest().Value() ||
		restored.PKCEVerifierDigest().Value() != attempt.PKCEVerifierDigest().Value() || restored.BrowserBindingDigest().Value() != attempt.BrowserBindingDigest().Value() {
		t.Fatalf("attempt restore mismatch: %#v err=%v", restored, err)
	}
	if _, _, _, _, ok := restored.TransportMaterial(); ok {
		t.Fatal("restored callback attempt was resealable")
	}
}

func testRecord(t *testing.T, now time.Time) Record {
	t.Helper()
	record, err := validRecordInput(now).record()
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testCodec(t *testing.T, origin string, entropy io.Reader, now time.Time) *Codec {
	t.Helper()
	codec, err := newCodec(testSecurity(t, origin), "key_oidc_transport", "key_oidc_001", bytes.Repeat([]byte{0x7b}, keyBytes), entropy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func testCodecWithKey(t *testing.T, key []byte, entropy io.Reader, now time.Time) *Codec {
	t.Helper()
	codec, err := newCodec(testSecurity(t, "https://workspace.example"), "key_oidc_transport", "key_oidc_001", key, entropy, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func testSecurity(t *testing.T, origin string) tenantsecurity.Context {
	t.Helper()
	security, err := tenantsecurity.NewContext("org_alpha", "idp_primary", origin, "key_identity", testDigestor{"identity"}, "key_session", testDigestor{"session"})
	if err != nil {
		t.Fatal(err)
	}
	return security
}

func testNow() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }

func rawValue(label string) string {
	digest := sha256.Sum256([]byte("oidc:" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type testDigestor struct{ name string }

func (digestor testDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	digest := sha256.Sum256([]byte(digestor.name + "\x00" + purpose + "\x00" + raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + fmt.Sprintf("%x", digest[:]))
}

func (digestor testDigestor) KeyMaterialFingerprint() [32]byte {
	return sha256.Sum256([]byte(digestor.name))
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("entropy failed") }

type blockingReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (reader *blockingReader) Read(buffer []byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.release
	for index := range buffer {
		buffer[index] = byte(index + 1)
	}
	return len(buffer), nil
}
