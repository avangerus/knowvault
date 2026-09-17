package postgres_test

// ADR-0070 §1.5 recovery bundle proofs: the operator backup seals entries
// into one encrypted bundle whose DEK is wrapped by a separate recovery key;
// restore fails closed with typed errors on a missing, wrong or cross-tenant
// key and on a tampered bundle, and the restore drill demonstrates the NFR-B2
// window (≤2 h) into a clean environment after the mandatory negative checks
// (ADR-0069: restore readiness is gated on the negative checks).
//
// The tests live in the PostgreSQL integration harness so the acceptance
// invariants (CRY-003 negative tests) are registered against executable
// POSTGRES_INTEGRATION tests executed on the real database stack, exactly as
// the mutation corpus drives them.

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/recovery"
)

// recoveryOrg / recoveryKeyMaterial are the sealed-organization test pair.
const (
	recoveryOrg        = "org_recovery"
	recoveryOtherOrg   = "org_recovery_other"
	recoveryKeyVersion = "test"
)

func recoveryTestKey(t *testing.T, org string) *recovery.RecoveryKey {
	t.Helper()
	material := bytes.Repeat([]byte{0x5a}, 32)
	if org == recoveryOtherOrg {
		material = bytes.Repeat([]byte{0x6b}, 32)
	}
	key, err := recovery.NewRecoveryKey(org, material)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Clear)
	return key
}

func recoveryTestEntries(t *testing.T, names ...string) []recovery.Entry {
	t.Helper()
	var entries []recovery.Entry
	for index, name := range names {
		entry, err := recovery.NewEntry(name, []byte("recovery-payload-"+strings.Repeat(string(rune('a'+index)), 16)))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, *entry)
	}
	return entries
}

// sealedBundle is a small helper bundling the standard three-file dataset.
func sealedBundle(t *testing.T, key *recovery.RecoveryKey, entries []recovery.Entry) []byte {
	t.Helper()
	sealed, err := recovery.Backup(key.OrganizationID(), entries, key, time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// TestRecoveryRestoreWithoutKey is the drill-lite procedure: the mandatory
// negative checks first (missing key, wrong key, tampered bundle — each must
// fail closed with a typed error), then the successful restore of the very
// same bundle with the correct key. It is the registered negative test of
// acceptance.crypto.backup-restore-without-key (CRY-003).
func TestRecoveryRestoreWithoutKey(t *testing.T) {
	key := recoveryTestKey(t, recoveryOrg)
	entries := recoveryTestEntries(t, "encrypted_artifacts.json", "rotation_state.json", "secret_manifest.json")
	sealed := sealedBundle(t, key, entries)

	// Negative checks gate restore readiness (ADR-0069, ADR-0070 §1.5).
	if _, err := recovery.Restore(sealed, nil); recovery.CodeOf(err) != recovery.CodeInvalid {
		t.Fatalf("missing key: code=%s, want RECOVERY_INVALID", recovery.CodeOf(err))
	}
	wrongKey, err := recovery.NewRecoveryKey(recoveryOrg, bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrongKey.Clear)
	if _, err := recovery.Restore(sealed, wrongKey); recovery.CodeOf(err) != recovery.CodeFailed {
		t.Fatalf("wrong key: code=%s, want RECOVERY_FAILED", recovery.CodeOf(err))
	}
	tampered := tamperBundle(t, sealed)
	if _, err := recovery.Restore(tampered, key); recovery.CodeOf(err) != recovery.CodeFailed {
		t.Fatalf("tampered bundle: code=%s, want RECOVERY_FAILED", recovery.CodeOf(err))
	}

	// With the correct key the same bundle restores fully, entry for entry.
	restored, err := recovery.Restore(sealed, key)
	if err != nil {
		t.Fatalf("restore with correct key: %v", err)
	}
	if len(restored) != len(entries) {
		t.Fatalf("restored %d entries, want %d", len(restored), len(entries))
	}
	for index := range entries {
		if restored[index].Name() != entries[index].Name() || !bytes.Equal(restored[index].Data(), entries[index].Data()) {
			t.Fatalf("restored entry %d differs: %q", index, restored[index].Name())
		}
	}
}

// TestRecoveryRestoreWrongTenantKey is the registered negative test of
// acceptance.crypto.backup-restore-wrong-tenant-key (CRY-003): a bundle
// sealed for one organization is refused by another organization's key
// before any decryption attempt — never a partial restore (ENCRYPTION.md §4).
// The cross-tenant key carries the very same material as the sealing key, so
// the refusal is bound to the organization binding, not to the material.
func TestRecoveryRestoreWrongTenantKey(t *testing.T) {
	key := recoveryTestKey(t, recoveryOrg)
	sealed := sealedBundle(t, key, recoveryTestEntries(t, "encrypted_artifacts.json"))

	crossTenantSameMaterial, err := recovery.NewRecoveryKey(recoveryOtherOrg, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(crossTenantSameMaterial.Clear)
	if _, err := recovery.Restore(sealed, crossTenantSameMaterial); recovery.CodeOf(err) != recovery.CodeDenied {
		t.Fatalf("wrong tenant: code=%s, want RECOVERY_DENIED", recovery.CodeOf(err))
	}

	// The correct organization key restores the same bundle fully.
	restored, err := recovery.Restore(sealed, key)
	if err != nil {
		t.Fatalf("correct tenant key: %v", err)
	}
	if len(restored) != 1 {
		t.Fatalf("restored %d entries, want 1", len(restored))
	}
}

// TestRecoveryRoundTrip seals and restores a multi-entry dataset with binary
// payloads and proves byte-identical round trip through the bundle.
func TestRecoveryRoundTrip(t *testing.T) {
	key := recoveryTestKey(t, recoveryOrg)
	payloads := [][]byte{
		[]byte("secret manifest v7"),
		bytes.Repeat([]byte{0x00, 0x01, 0x02, 0xff}, 64),
		[]byte("\u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f \u0441 \u044e\u043d\u0438\u043a\u043e\u0434\u043e\u043c \u0438 \u043f\u0440\u043e\u0431\u0435\u043b\u0430\u043c\u0438"),
	}
	var entries []recovery.Entry
	for index, payload := range payloads {
		entry, err := recovery.NewEntry("entry-"+string(rune('a'+index))+".bin", payload)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, *entry)
	}
	sealed := sealedBundle(t, key, entries)

	restored, err := recovery.Restore(sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != len(entries) {
		t.Fatalf("restored %d entries, want %d", len(restored), len(entries))
	}
	for index := range entries {
		if restored[index].Name() != entries[index].Name() {
			t.Fatalf("entry %d name %q, want %q", index, restored[index].Name(), entries[index].Name())
		}
		if !bytes.Equal(restored[index].Data(), payloads[index]) {
			t.Fatalf("entry %d data differs", index)
		}
	}
}

// TestRecoveryEntryNameValidation proves the flat-name contract from outside
// the package: NewEntry refuses every non-flat name. The crafted-bundle half
// (a sealed payload carrying a non-flat name must fail closed with no partial
// result) cannot be constructed here — the bundle format is private and Backup
// is the only constructor — so it is proven in the package-internal test
// TestRestoreRejectsCraftedName (internal/recovery).
func TestRecoveryEntryNameValidation(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/../b", "/abs", "sub/dir", "a\\b", "name\x00x", " trailing", "trailing ", "l" + strings.Repeat("o", 200) + "ng"} {
		if _, err := recovery.NewEntry(name, []byte("x")); recovery.CodeOf(err) != recovery.CodeInvalid {
			t.Fatalf("name %q accepted by NewEntry", name)
		}
	}
}

// TestRecoveryBundleContentScan is the backup-content-scan enforcement
// (CRY-003): the bundle bytes never carry source binaries, signing private
// keys, recovery-key material or entry plaintext in readable form.
func TestRecoveryBundleContentScan(t *testing.T) {
	key := recoveryTestKey(t, recoveryOrg)
	material := bytes.Repeat([]byte{0x5a}, 32)
	signingMarker := []byte("-----BEGIN TEST PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCAmc3\n-----END TEST PRIVATE KEY-----\n")
	binaryMarker := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00")
	entry, err := recovery.NewEntry("payload.bin", append(append(append([]byte("plaintext-marker-"), signingMarker...), binaryMarker...), material...))
	if err != nil {
		t.Fatal(err)
	}
	sealed := sealedBundle(t, key, []recovery.Entry{*entry})

	for _, marker := range [][]byte{signingMarker, binaryMarker, material, []byte("plaintext-marker-")} {
		if bytes.Contains(sealed, marker) {
			t.Fatalf("bundle contains a forbidden marker in readable form")
		}
		encoded := base64.StdEncoding.EncodeToString(marker)
		if len(encoded) >= 16 && bytes.Contains(sealed, []byte(encoded)) {
			t.Fatalf("bundle contains a forbidden marker in base64 form")
		}
	}
}

// TestRecoveryDrillRestoreB2 is the mandatory restore drill (ADR-0070 §1.5):
// restore into a clean environment, the negative checks first, then the full
// restore under the measured NFR-B2 window (≤2 h), recording the measured
// time.
func TestRecoveryDrillRestoreB2(t *testing.T) {
	key := recoveryTestKey(t, recoveryOrg)
	var entries []recovery.Entry
	for index := 0; index < 64; index++ {
		entry, err := recovery.NewEntry("artifact-"+string(rune('a'+index%26))+string(rune('0'+index/10))+".bin",
			bytes.Repeat([]byte{byte(index), byte(index * 7)}, 1024))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, *entry)
	}
	sealed := sealedBundle(t, key, entries)

	// Negative checks gate restore readiness (ADR-0069).
	if _, err := recovery.Restore(sealed, nil); recovery.CodeOf(err) != recovery.CodeInvalid {
		t.Fatalf("drill negative missing key: code=%s", recovery.CodeOf(err))
	}
	wrongKey, err := recovery.NewRecoveryKey(recoveryOrg, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrongKey.Clear)
	if _, err := recovery.Restore(sealed, wrongKey); recovery.CodeOf(err) != recovery.CodeFailed {
		t.Fatalf("drill negative wrong key: code=%s", recovery.CodeOf(err))
	}
	if _, err := recovery.Restore(tamperBundle(t, sealed), key); recovery.CodeOf(err) != recovery.CodeFailed {
		t.Fatalf("drill negative tampered bundle: code=%s", recovery.CodeOf(err))
	}

	// Restore into a clean environment: a fresh, empty directory.
	cleanDir := t.TempDir()
	start := time.Now()
	restored, err := recovery.Restore(sealed, key)
	if err != nil {
		t.Fatalf("drill restore: %v", err)
	}
	for _, restoredEntry := range restored {
		target := filepath.Join(cleanDir, restoredEntry.Name())
		if err := os.WriteFile(target, restoredEntry.Data(), 0o600); err != nil {
			t.Fatalf("drill write %s: %v", restoredEntry.Name(), err)
		}
	}
	elapsed := time.Since(start)
	if len(restored) != len(entries) {
		t.Fatalf("drill restored %d entries, want %d", len(restored), len(entries))
	}
	for index := range entries {
		content, err := os.ReadFile(filepath.Join(cleanDir, entries[index].Name()))
		if err != nil || !bytes.Equal(content, entries[index].Data()) {
			t.Fatalf("drill verify entry %q failed: %v", entries[index].Name(), err)
		}
	}
	if elapsed > 2*time.Hour {
		t.Fatalf("drill restore took %v, over the NFR-B2 window (≤2 h)", elapsed)
	}
	// Record the measured time: the drill evidence line of the run.
	t.Logf("restore drill: %d entries into a clean environment in %v (NFR-B2 window ≤2 h)", len(restored), elapsed)
}

// tamperBundle flips one payload byte inside the bundle, preserving JSON
// validity so the tamper is caught by authentication, not by parsing.
func tamperBundle(t *testing.T, sealed []byte) []byte {
	t.Helper()
	mutated := make([]byte, len(sealed))
	copy(mutated, sealed)
	// Flip a byte near the end of the document: inside the base64 payload
	// region. A base64 digit flip stays parseable JSON and fails the GCM tag.
	last := len(mutated) - 1
	for mutated[last] == '"' || mutated[last] == '}' || mutated[last] == '\n' {
		last--
	}
	mutated[last] ^= 0x01
	if bytes.Equal(mutated, sealed) {
		t.Fatal("tamper did not change the bundle")
	}
	return mutated
}
