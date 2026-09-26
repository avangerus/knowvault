package artifactcrypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

const (
	testOrganization = "org_001"
	testResourceID   = "art_0000000000000000000000001"
	testKEKReference = "artifact_kek_ref"
	testKEKVersion   = int64(4)
)

func testProvider(t *testing.T) *MountedProvider {
	t.Helper()
	key := bytes.Repeat([]byte{0x44}, kekBytes)
	provider, err := NewMountedProvider(testOrganization, testKEKReference, testKEKVersion, key)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	return provider
}

func testCodec(t *testing.T) *Codec {
	t.Helper()
	codec, err := NewCodec(testProvider(t))
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	return codec
}

func ownerFor(t *testing.T, field OwnerField, resourceID string) OwnerIdentity {
	t.Helper()
	owner, err := NewOwnerIdentity(field, testOrganization, resourceID)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	return owner
}

func TestOwnerInventoryHasExactlyTwentyEightTypedSelectors(t *testing.T) {
	if len(ownerInventory) != 28 {
		t.Fatalf("owner inventory has %d rows, expected 28", len(ownerInventory))
	}
	if int(ownerFieldSentinel)-int(ownerFieldInvalid)-1 != 28 {
		t.Fatalf("typed selector range is not exactly 28")
	}
	if len(ownerByField) != 28 {
		t.Fatalf("owner registry built %d entries, expected 28", len(ownerByField))
	}
	seen := make(map[[4]string]bool, 28)
	for _, definition := range ownerInventory {
		tuple := [4]string{definition.ownerTable, definition.ownerColumn, definition.resourceType, definition.aadField}
		if seen[tuple] {
			t.Fatalf("duplicate owner tuple: %v", tuple)
		}
		seen[tuple] = true
	}
}

func TestNewOwnerIdentityFailsClosedOnUnknownSelectorAndMalformedIdentity(t *testing.T) {
	if _, err := NewOwnerIdentity(ownerFieldInvalid, testOrganization, testResourceID); CodeOf(err) != CodeUnknownOwner {
		t.Fatalf("zero selector err=%v", err)
	}
	if _, err := NewOwnerIdentity(ownerFieldSentinel, testOrganization, testResourceID); CodeOf(err) != CodeUnknownOwner {
		t.Fatalf("sentinel selector err=%v", err)
	}
	for name, mutate := range map[string]struct{ org, resource string }{
		"empty org":           {"", testResourceID},
		"empty resource":      {testOrganization, ""},
		"control in org":      {"org\x01", testResourceID},
		"whitespace resource": {testOrganization, " " + testResourceID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewOwnerIdentity(QuestionText, mutate.org, mutate.resource); CodeOf(err) != CodeInvalidOwner {
				t.Fatalf("expected invalid owner, err=%v", err)
			}
		})
	}
}

func TestSealOpenRoundTripAcrossEveryOwnerBranch(t *testing.T) {
	codec := testCodec(t)
	for _, definition := range ownerInventory {
		owner := ownerFor(t, definition.field, testResourceID)
		plaintext := []byte("payload for " + definition.resourceType + "/" + definition.aadField)
		envelope, err := codec.Seal(owner, plaintext)
		if err != nil {
			t.Fatalf("seal %v: %v", definition.field, err)
		}
		if envelope.Cipher() != CipherAES256GCM || envelope.SizeBytes() != len(plaintext) ||
			len(envelope.Ciphertext()) != len(plaintext)+gcmTagLen || len(envelope.Nonce()) != artifactNonceLen ||
			envelope.KEKReference() != testKEKReference || envelope.KEKVersion() != testKEKVersion ||
			envelope.OwnerTable() != definition.ownerTable || envelope.Field() != definition.aadField ||
			!strings.HasPrefix(envelope.AADHash(), "sha256:") || !strings.HasPrefix(envelope.PlaintextHash(), "sha256:") {
			t.Fatalf("envelope shape wrong for %v", definition.field)
		}
		recovered, err := codec.Open(owner, envelope)
		if err != nil || !bytes.Equal(recovered, plaintext) {
			t.Fatalf("open %v: err=%v equal=%v", definition.field, err, bytes.Equal(recovered, plaintext))
		}
	}
}

func TestOpenFailsClosedOnTamperedEnvelopeComponents(t *testing.T) {
	codec := testCodec(t)
	owner := ownerFor(t, QuestionText, testResourceID)
	plaintext := bytes.Repeat([]byte("q"), 4096)
	base, err := codec.Seal(owner, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Envelope){
		"ciphertext body": func(e *Envelope) { e.ciphertext[0] ^= 0x01 },
		"ciphertext tag":  func(e *Envelope) { e.ciphertext[len(e.ciphertext)-1] ^= 0x01 },
		"nonce":           func(e *Envelope) { e.nonce[0] ^= 0x01 },
		"wrapped dek":     func(e *Envelope) { e.wrappedDEK[len(e.wrappedDEK)-1] ^= 0x01 },
		"wrapped scheme":  func(e *Envelope) { e.wrappedDEK[1] = 0x02 },
		"kek version":     func(e *Envelope) { e.kekVersion++ },
		"kek reference":   func(e *Envelope) { e.kekReference = "other_ref" },
		"aad hash":        func(e *Envelope) { e.aadHash = hashDigest([]byte("wrong")) },
		"plaintext hash":  func(e *Envelope) { e.plaintextHash = hashDigest([]byte("wrong")) },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := cloneEnvelope(base)
			mutate(&tampered)
			if plain, err := codec.Open(owner, tampered); CodeOf(err) != CodeOpenRejected || plain != nil {
				t.Fatalf("tamper %q not rejected: err=%v", name, err)
			}
		})
	}
}

func TestOpenFailsClosedOnCrossOwnerSwap(t *testing.T) {
	codec := testCodec(t)
	source := ownerFor(t, QuestionText, testResourceID)
	plaintext := []byte("cross-owner secret payload")
	envelope, err := codec.Seal(source, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	for name, wrongOwner := range map[string]OwnerIdentity{
		"other column":   ownerFor(t, AnswerMarkdown, testResourceID),
		"other resource": ownerFor(t, QuestionText, "art_0000000000000000000000999"),
		"other tenant": func() OwnerIdentity {
			owner, ownerErr := NewOwnerIdentity(QuestionText, "org_other", testResourceID)
			if ownerErr != nil {
				t.Fatal(ownerErr)
			}
			return owner
		}(),
		"other resource type": ownerFor(t, ClaimText, testResourceID),
	} {
		t.Run(name, func(t *testing.T) {
			swapped := cloneEnvelope(envelope)
			// Simulate a ciphertext moved under a foreign owning row: the stored
			// owner columns are rewritten but the decrypt owner is recomputed
			// from the trusted mapping, which must still fail GCM authentication.
			swapped.organizationID = wrongOwner.organizationID
			swapped.ownerTable = wrongOwner.ownerTable
			swapped.ownerColumn = wrongOwner.ownerColumn
			swapped.resourceType = wrongOwner.resourceType
			swapped.resourceID = wrongOwner.resourceID
			swapped.field = wrongOwner.field
			swapped.aadHash = mustAADHash(t, wrongOwner)
			if plain, err := codec.Open(wrongOwner, swapped); CodeOf(err) != CodeOpenRejected || plain != nil {
				t.Fatalf("cross-owner %q not rejected: err=%v", name, err)
			}
		})
	}
}

func TestArtifactAADBindsResourceType(t *testing.T) {
	owner := ownerFor(t, QuestionText, testResourceID)
	got, err := artifactAAD(owner)
	if err != nil {
		t.Fatalf("artifact AAD: %v", err)
	}
	want := `{"field":"QUESTION_TEXT","organization_id":"org_001","owner_column":"question_text_artifact_id","owner_table":"question_run","resource_id":"art_0000000000000000000000001","resource_type":"QUESTION_RUN","schema_version":"encrypted-artifact-aad-v1"}`
	if string(got) != want {
		t.Fatalf("artifact AAD omitted or changed a resource tuple member:\n got %s\nwant %s", got, want)
	}
}

func TestUnwrapFailsClosedOnForeignSchemeAndUnknownKey(t *testing.T) {
	provider := testProvider(t)
	owner := ownerFor(t, QuestionText, testResourceID)
	dek := bytes.Repeat([]byte{0x55}, dekBytes)
	wrapped, err := provider.WrapDEK(dek, owner)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.KeyReference() != testKEKReference || wrapped.KeyVersion() != testKEKVersion {
		t.Fatal("wrap result did not carry the exact key reference/version atomically")
	}
	if _, err := provider.UnwrapDEK(wrapped, owner); err != nil {
		t.Fatalf("valid unwrap failed: %v", err)
	}
	foreignBytes := wrapped.Bytes()
	foreignBytes[1] = 0x02
	if _, err := provider.UnwrapDEK(NewWrappedDEK(testKEKReference, testKEKVersion, foreignBytes), owner); CodeOf(err) != CodeUnwrapRejected {
		t.Fatalf("foreign scheme not rejected: %v", err)
	}
	if _, err := provider.UnwrapDEK(NewWrappedDEK("wrong_ref", testKEKVersion, wrapped.Bytes()), owner); CodeOf(err) != CodeUnwrapRejected {
		t.Fatalf("unknown key reference not rejected: %v", err)
	}
	if _, err := provider.UnwrapDEK(NewWrappedDEK(testKEKReference, testKEKVersion+1, wrapped.Bytes()), owner); CodeOf(err) != CodeUnwrapRejected {
		t.Fatalf("unknown key version not rejected: %v", err)
	}
	otherOwner := ownerFor(t, AnswerMarkdown, testResourceID)
	if _, err := provider.UnwrapDEK(wrapped, otherOwner); CodeOf(err) != CodeUnwrapRejected {
		t.Fatalf("owner-bound wrap AAD not enforced: %v", err)
	}
}

func TestProviderAndCodecFailClosedOnTenantMiscomposition(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, kekBytes)
	provider, err := NewMountedProvider("org_alpha", testKEKReference, testKEKVersion, key)
	if err != nil {
		t.Fatal(err)
	}
	if provider.OrganizationID() != "org_alpha" {
		t.Fatal("provider not bound to its tenant")
	}
	codec, err := NewCodec(provider)
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := NewOwnerIdentity(QuestionText, "org_beta", testResourceID)
	if err != nil {
		t.Fatal(err)
	}
	// A codec bound to org_alpha cannot seal a formally valid org_beta owner.
	if _, err := codec.Seal(foreignOwner, []byte("foreign tenant payload")); CodeOf(err) != CodeSealFailed {
		t.Fatalf("cross-tenant seal not rejected: %v", err)
	}
	// Nor wrap directly.
	dek := bytes.Repeat([]byte{0x55}, dekBytes)
	if _, err := provider.WrapDEK(dek, foreignOwner); CodeOf(err) != CodeWrapFailed {
		t.Fatalf("cross-tenant wrap not rejected: %v", err)
	}
	// A DEK legitimately wrapped for org_alpha cannot be unwrapped for org_beta.
	localOwner, err := NewOwnerIdentity(QuestionText, "org_alpha", testResourceID)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := provider.WrapDEK(dek, localOwner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UnwrapDEK(wrapped, foreignOwner); CodeOf(err) != CodeUnwrapRejected {
		t.Fatalf("cross-tenant unwrap not rejected: %v", err)
	}
}

func TestClosedProviderAndCodecFailClosed(t *testing.T) {
	provider := testProvider(t)
	codec, err := NewCodec(provider)
	if err != nil {
		t.Fatal(err)
	}
	owner := ownerFor(t, QuestionText, testResourceID)
	envelope, err := codec.Seal(owner, []byte("still-open payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if provider.OrganizationID() != "" {
		t.Fatal("closed provider still exposes tenant metadata")
	}
	if _, err := codec.Seal(owner, []byte("after close")); CodeOf(err) != CodeSealFailed {
		t.Fatalf("seal after close: %v", err)
	}
	if _, err := codec.Open(owner, envelope); CodeOf(err) != CodeOpenRejected {
		t.Fatalf("open after close: %v", err)
	}
}

func TestSealRejectsOutOfRangePlaintextSizes(t *testing.T) {
	codec := testCodec(t)
	owner := ownerFor(t, QuestionText, testResourceID)
	if _, err := codec.Seal(owner, nil); CodeOf(err) != CodeSealFailed {
		t.Fatalf("empty plaintext: %v", err)
	}
	if _, err := codec.Seal(owner, make([]byte, maxPlaintextBytes+1)); CodeOf(err) != CodeSealFailed {
		t.Fatalf("oversized plaintext: %v", err)
	}
}

func TestFormattingIsRedacted(t *testing.T) {
	provider := testProvider(t)
	codec, err := NewCodec(provider)
	if err != nil {
		t.Fatal(err)
	}
	owner := ownerFor(t, QuestionText, testResourceID)
	secret := []byte("top secret plaintext body")
	envelope, err := codec.Seal(owner, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{
		fmt.Sprint(provider), fmt.Sprintf("%#v", provider), fmt.Sprint(*codec), fmt.Sprintf("%#v", codec),
		fmt.Sprint(envelope), fmt.Sprintf("%#v", envelope),
	} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, testKEKReference) || strings.Contains(formatted, string(secret)) {
			t.Fatalf("formatting leaked material: %q", formatted)
		}
	}
}

func TestFreshDEKAndNoncePerSeal(t *testing.T) {
	codec := testCodec(t)
	owner := ownerFor(t, QuestionText, testResourceID)
	plaintext := []byte("identical payload")
	first, err := codec.Seal(owner, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Seal(owner, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Nonce(), second.Nonce()) || bytes.Equal(first.Ciphertext(), second.Ciphertext()) || bytes.Equal(first.WrappedDEK(), second.WrappedDEK()) {
		t.Fatal("seal reused nonce, ciphertext or wrapped DEK across artifacts")
	}
}

func cloneEnvelope(source Envelope) Envelope {
	clone := source
	clone.ciphertext = append([]byte(nil), source.ciphertext...)
	clone.nonce = append([]byte(nil), source.nonce...)
	clone.wrappedDEK = append([]byte(nil), source.wrappedDEK...)
	return clone
}

func mustAADHash(t *testing.T, owner OwnerIdentity) string {
	t.Helper()
	aad, err := artifactAAD(owner)
	if err != nil {
		t.Fatal(err)
	}
	return hashDigest(aad)
}

var _ = rand.Reader
