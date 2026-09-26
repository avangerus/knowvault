package workspacecontext

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspace"
)

// TestMintMissingIDsAssignsOnlyEmptyIDs proves the store's own id-minting
// step (S2-CONTRACT.md "New items are sent with \"id\": \"\"; the server
// assigns ids") mints a fresh, correctly-prefixed, Validate-shaped id for
// every empty Rule/Term id and leaves an already-assigned id untouched.
func TestMintMissingIDsAssignsOnlyEmptyIDs(t *testing.T) {
	document := Document{
		Rules: []Rule{
			{ID: "", Text: "new rule"},
			{ID: "rule_01ARZ3NDEKTSV4RRFFQ69G5FAV", Text: "existing rule"},
		},
		Glossary: []Term{
			{ID: "", Term: "МНО"},
			{ID: "term_01ARZ3NDEKTSV4RRFFQ69G5FAV", Term: "existing term"},
		},
	}
	minted, err := mintMissingIDs(document)
	if err != nil {
		t.Fatalf("mintMissingIDs: %v", err)
	}
	if minted.Rules[0].ID == "" || !strings.HasPrefix(minted.Rules[0].ID, "rule_") {
		t.Fatalf("new rule did not receive a rule_ id: %q", minted.Rules[0].ID)
	}
	if !assignedIDPattern.MatchString(minted.Rules[0].ID) {
		t.Fatalf("minted rule id does not match the assigned-id shape: %q", minted.Rules[0].ID)
	}
	if minted.Rules[1].ID != "rule_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("existing rule id was rewritten: %q", minted.Rules[1].ID)
	}
	if minted.Glossary[0].ID == "" || !strings.HasPrefix(minted.Glossary[0].ID, "term_") {
		t.Fatalf("new term did not receive a term_ id: %q", minted.Glossary[0].ID)
	}
	if minted.Glossary[1].ID != "term_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("existing term id was rewritten: %q", minted.Glossary[1].ID)
	}
	// The original document is never mutated: mintMissingIDs returns a copy.
	if document.Rules[0].ID != "" || document.Glossary[0].ID != "" {
		t.Fatalf("mintMissingIDs mutated the caller's document in place")
	}
}

// TestMintMissingIDsIsDeterministicPerCallOnly proves two independent mints
// of the identical shape produce DIFFERENT ids (fresh ULIDs), which is why
// Save's idempotency request hash must be computed on the raw, pre-mint
// document rather than after minting.
func TestMintMissingIDsIsDeterministicPerCallOnly(t *testing.T) {
	document := Document{Rules: []Rule{{ID: "", Text: "rule"}}}
	first, err := mintMissingIDs(document)
	if err != nil {
		t.Fatalf("mintMissingIDs: %v", err)
	}
	second, err := mintMissingIDs(document)
	if err != nil {
		t.Fatalf("mintMissingIDs: %v", err)
	}
	if first.Rules[0].ID == second.Rules[0].ID {
		t.Fatalf("two independent mints produced the same id: %q", first.Rules[0].ID)
	}
}

// TestScopedHashIsStableAndOperationSeparated proves scopedHash is a pure,
// deterministic function of its inputs (so a Save/Restore retry with the
// identical raw request hashes identically) and that the same raw value
// hashes differently under different operation scopes (so a SAVE key can
// never collide with a RESTORE key).
func TestScopedHashIsStableAndOperationSeparated(t *testing.T) {
	first := scopedHash("SAVE", "sha256:abc")
	second := scopedHash("SAVE", "sha256:abc")
	if first != second {
		t.Fatalf("scopedHash is not deterministic: %q != %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("scopedHash does not match the sha256:<64 hex> shape: %q", first)
	}
	restoreScoped := scopedHash("RESTORE", "sha256:abc")
	if first == restoreScoped {
		t.Fatalf("SAVE and RESTORE scopes collided for the same raw value")
	}
}

func TestVersionTokenRendersDecimal(t *testing.T) {
	cases := map[int64]string{0: "0", 1: "1", 9: "9", 10: "10", 42: "42", 1000000: "1000000"}
	for input, want := range cases {
		if got := versionToken(input); got != want {
			t.Fatalf("versionToken(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestValidIfMatchAcceptsSentinelAndRealHashOnly(t *testing.T) {
	if !validIfMatch(emptyContextSentinel) {
		t.Fatalf("validIfMatch rejected the empty-context sentinel")
	}
	realHash, err := Hash(Document{})
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !validIfMatch(realHash) {
		t.Fatalf("validIfMatch rejected a real content hash: %q", realHash)
	}
	for _, bad := range []string{"", "sha256:", "not-a-hash", "sha256:" + strings.Repeat("g", 64)} {
		if validIfMatch(bad) {
			t.Fatalf("validIfMatch accepted an invalid value: %q", bad)
		}
	}
}

// TestCanonicalDocumentBytesAndHashRoundTripsThroughDecodeDocument proves the
// storage encoding used for workspace_model_context_version.document is
// exactly decodeDocument's inverse: what Save/Restore write is byte-for-byte
// what a later read reconstructs, and the stored hash matches Hash's own
// content hash for the identical (already-minted, already-normalized)
// document.
func TestCanonicalDocumentBytesAndHashRoundTripsThroughDecodeDocument(t *testing.T) {
	document := Document{
		Description: "d",
		Rules:       []Rule{{ID: "rule_01ARZ3NDEKTSV4RRFFQ69G5FAV", Text: "r"}},
		Glossary: []Term{{
			ID: "term_01ARZ3NDEKTSV4RRFFQ69G5FAV", Term: "МНО", Synonyms: []string{"mno"}, Definition: "def",
			DataLocations: []DataLocation{{SourceConnectionID: "conn", Relation: "public.t", Column: "c", Hint: "h"}},
		}},
		Sources: []Source{{
			SourceConnectionID: "conn", Description: "sd",
			Tables: []Table{{Relation: "public.t", Note: "n", Columns: []Column{{Name: "c", Note: "cn"}}}},
		}},
	}
	bytes, hash, err := canonicalDocumentBytesAndHash(document)
	if err != nil {
		t.Fatalf("canonicalDocumentBytesAndHash: %v", err)
	}
	wantHash, err := Hash(document)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash != wantHash {
		t.Fatalf("stored content hash %q does not match Hash(document) %q", hash, wantHash)
	}
	decoded, err := decodeDocument(bytes)
	if err != nil {
		t.Fatalf("decodeDocument: %v", err)
	}
	roundTripHash, err := Hash(decoded)
	if err != nil {
		t.Fatalf("Hash(decoded): %v", err)
	}
	if roundTripHash != hash {
		t.Fatalf("round-tripped document hashes to %q, want %q", roundTripHash, hash)
	}
	if decoded.Glossary[0].DataLocations[0].Relation != "public.t" || decoded.Sources[0].Tables[0].Columns[0].Name != "c" {
		t.Fatalf("round trip lost nested field content: %+v", decoded)
	}
}

func TestIsEditorRequiresOwnerOrManagerMembership(t *testing.T) {
	snapshot := workspace.Snapshot{Members: []workspace.Member{
		{PrincipalID: "owner", Role: workspace.RoleOwner},
		{PrincipalID: "manager", Role: workspace.RoleManager},
		{PrincipalID: "member", Role: workspace.RoleMember},
	}}
	for principalID, want := range map[string]bool{"owner": true, "manager": true, "member": false, "stranger": false} {
		if got := isEditor(snapshot, principalID); got != want {
			t.Fatalf("isEditor(%q) = %v, want %v", principalID, got, want)
		}
	}
}

func TestValidWorkspaceIDBounds(t *testing.T) {
	if validWorkspaceID("ab") {
		t.Fatalf("validWorkspaceID accepted a too-short id")
	}
	if !validWorkspaceID("abc") {
		t.Fatalf("validWorkspaceID rejected a minimal valid id")
	}
	if !validWorkspaceID(strings.Repeat("a", 128)) {
		t.Fatalf("validWorkspaceID rejected a 128-character id")
	}
	if validWorkspaceID(strings.Repeat("a", 129)) {
		t.Fatalf("validWorkspaceID accepted a 129-character id")
	}
}

func TestDecodeProjectionColumnNamesExtractsNamesOnly(t *testing.T) {
	names, err := decodeProjectionColumnNames([]byte(`[{"ordinal":1,"name":"id"},{"ordinal":2,"name":"amount"}]`))
	if err != nil {
		t.Fatalf("decodeProjectionColumnNames: %v", err)
	}
	if len(names) != 2 || names[0] != "id" || names[1] != "amount" {
		t.Fatalf("unexpected column names: %v", names)
	}
}
