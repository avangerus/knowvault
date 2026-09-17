package modelgateway

import (
	"context"
	"testing"
)

func TestLocalHashEmbedFuncDiscriminatesSupportedFromUnsupportedClaims(t *testing.T) {
	embed := LocalHashEmbedFunc()
	evidence := "AIS (Automatic Identification System) \u2014 \u0441\u0438\u0441\u0442\u0435\u043c\u0430 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u043e\u0439 \u0438\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u0438, \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u043c\u0430\u044f \u0434\u043b\u044f \u043e\u0442\u0441\u043b\u0435\u0436\u0438\u0432\u0430\u043d\u0438\u044f \u0441\u0443\u0434\u043e\u0432."
	supported := "AIS \u0440\u0430\u0441\u0448\u0438\u0444\u0440\u043e\u0432\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u043a\u0430\u043a \u0441\u0438\u0441\u0442\u0435\u043c\u0430 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u043e\u0439 \u0438\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u0438."
	unsupported := "\u041e\u0442\u0432\u0435\u0442 \u043d\u0430 \u0432\u043e\u043f\u0440\u043e\u0441 \u043f\u0440\u043e \u043f\u043e\u0433\u043e\u0434\u0443 \u0432 \u041c\u043e\u0441\u043a\u0432\u0435."

	verifier, err := NewVerifier(embed, LocalHashVerifierThreshold)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ok, err := verifier.VerifyClaim(context.Background(), "ws1", "qrun1:claim1", supported, []string{evidence})
	if err != nil || !ok {
		t.Fatalf("expected a lexically supported claim to verify, ok=%v err=%v", ok, err)
	}
	ok, err = verifier.VerifyClaim(context.Background(), "ws1", "qrun1:claim2", unsupported, []string{evidence})
	if err != nil || ok {
		t.Fatalf("expected an unrelated claim to fail verification, ok=%v err=%v", ok, err)
	}
}

func TestLocalHashEmbedFuncIsDeterministic(t *testing.T) {
	embed := LocalHashEmbedFunc()
	first, err := embed(context.Background(), "ws", "op", "\u0442\u0435\u043a\u0441\u0442 \u0434\u043b\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0434\u0435\u0442\u0435\u0440\u043c\u0438\u043d\u0438\u0437\u043c\u0430")
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	second, err := embed(context.Background(), "other-ws", "other-op", "\u0442\u0435\u043a\u0441\u0442 \u0434\u043b\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u0434\u0435\u0442\u0435\u0440\u043c\u0438\u043d\u0438\u0437\u043c\u0430")
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("expected equal-length vectors, got %d and %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("expected identical vectors regardless of workspace/operation id, differ at index %d: %v vs %v", i, first[i], second[i])
		}
	}
}

func TestLocalHashEmbedShortTextIsDegenerate(t *testing.T) {
	vector := localHashEmbed("ab")
	for _, value := range vector {
		if value != 0 {
			t.Fatalf("expected an all-zero vector for text shorter than one trigram, got a nonzero entry")
		}
	}
}
