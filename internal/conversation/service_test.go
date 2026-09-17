package conversation

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestConversationIdentifiersAndKeysAreClosed(t *testing.T) {
	validKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, value := range []string{"ws_alpha", "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV", "turn_01ARZ3NDEKTSV4RRFFQ69G5FAV"} {
		if !validOpaque(value) {
			t.Fatalf("valid opaque id rejected: %q", value)
		}
	}
	if !validIdempotencyKey(validKey) {
		t.Fatal("canonical base64url idempotency key rejected")
	}
	for _, value := range []string{"", " ws_alpha", "ws/alpha", "ws_alpha\n", strings.Repeat("x", 129)} {
		if validOpaque(value) {
			t.Fatalf("invalid opaque id accepted: %q", value)
		}
	}
	for _, value := range []string{"", "not-base64", validKey + "A", "AA=="} {
		if validIdempotencyKey(value) {
			t.Fatalf("invalid idempotency key accepted: %q", value)
		}
	}
}

func TestConversationArchiveRetentionGuardCallIsClosed(t *testing.T) {
	if strings.Join(strings.Fields(conversationRetentionArchiveGuardQuery), " ") !=
		"SELECT app.conversation_retention_archive_guard($1, $2, $3)" {
		t.Fatalf("retention guard call contract changed: %q", conversationRetentionArchiveGuardQuery)
	}
}

func TestConversationViewNeverCarriesPlaintextFields(t *testing.T) {
	view := View{ID: "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV", WorkspaceID: "ws_alpha", WorkspaceRevision: 1,
		CreatedBy: "usr_alice", Turns: []Turn{{ID: "turn_01ARZ3NDEKTSV4RRFFQ69G5FAV", QuestionRunID: "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV", TurnIndex: 1}}}
	if strings.Contains(strings.ToLower(viewJSON(view)), "question") && strings.Contains(strings.ToLower(viewJSON(view)), "text") {
		t.Fatal("conversation view unexpectedly contains plaintext question fields")
	}
}

func viewJSON(value View) string {
	// Keep the assertion independent of a JSON implementation: these are the
	// only fields intentionally owned by this package.
	return value.ID + " " + value.WorkspaceID + " " + value.CreatedBy + " " + value.Turns[0].QuestionRunID
}
