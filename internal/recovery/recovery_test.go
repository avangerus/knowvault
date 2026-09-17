package recovery

// ADR-0070 §1.5 package-internal proofs: a crafted bundle whose sealed payload
// carries a non-flat entry name fails closed without returning any entry, and
// Backup refuses a non-flat entry even when constructed in-package. The
// external acceptance tests (tests/integration/postgres) cannot craft such a
// bundle — the format is private and NewEntry is the only entry constructor —
// so the crafted-bundle invariant is proven here, inside the package.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func craftedBundleTestKey(t *testing.T) *RecoveryKey {
	t.Helper()
	key, err := NewRecoveryKey("org_crafted", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Clear)
	return key
}

// TestBackupRejectsNonFlatEntry proves Backup validates every entry name even
// when the entry bypasses NewEntry (an in-package struct literal): a non-flat
// name can never reach the sealed payload.
func TestBackupRejectsNonFlatEntry(t *testing.T) {
	key := craftedBundleTestKey(t)
	entries := []Entry{{name: "sub/dir", data: []byte("x")}}
	if _, err := Backup("org_crafted", entries, key, time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)); CodeOf(err) != CodeInvalid {
		t.Fatalf("backup with non-flat entry: code=%s, want RECOVERY_INVALID", CodeOf(err))
	}
}

// TestRestoreRejectsCraftedName proves restore validates every name inside the
// sealed payload before any entry is returned: a payload carrying "evil/name"
// — re-sealed under the very same DEK, so only the name is wrong — fails
// closed with no partial result (CodeFailed, zero entries).
func TestRestoreRejectsCraftedName(t *testing.T) {
	key := craftedBundleTestKey(t)
	entry, err := NewEntry("ok.txt", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Backup("org_crafted", []Entry{*entry}, key, time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	var container bundle
	if err := json.Unmarshal(sealed, &container); err != nil {
		t.Fatal(err)
	}
	aad, err := baseAAD(container.bundleBase)
	if err != nil {
		t.Fatal(err)
	}
	wrappedDEK, err := base64.StdEncoding.DecodeString(container.WrappedDEK)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := openLayer(wrappedDEK, key.material[:], aad)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(dek)

	craftedRecords := []entryRecord{{Name: "evil/name", Data: base64.StdEncoding.EncodeToString([]byte("x"))}}
	payloadJSON, err := json.Marshal(craftedRecords)
	if err != nil {
		t.Fatal(err)
	}
	sealedPayload, err := sealLayer(payloadJSON, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	container.Payload = base64.StdEncoding.EncodeToString(sealedPayload)
	crafted, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := Restore(crafted, key)
	if err == nil || len(restored) != 0 || CodeOf(err) != CodeFailed {
		t.Fatalf("crafted name bundle: entries=%d err=%v code=%s, want 0 entries RECOVERY_FAILED", len(restored), err, CodeOf(err))
	}
}
