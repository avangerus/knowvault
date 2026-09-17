package modelgateway

// This file is the GEN-2 network-free fallback embedding source for Verifier
// (verifier.go), used only when composition has no internal/embedding mTLS
// channel mounted (e.g. the acc acceptance stand today, which has no
// embedding/reranker capability at all — see docs/adr/0088 GEN-2 addendum).
// Rather than making GENERATIVE permanently unavailable wherever the
// embedding mount is absent, this backs the same Verifier/cosine-similarity
// code path with a classic character-trigram feature-hashing vector: a real,
// deterministic, disclosed textual-similarity proxy computed only from the
// exact claim/evidence text already selected for this attempt, with no
// network call, no external model and no per-tenant binding to construct. It
// is explicitly weaker than a real embedding profile and is never described
// as the ADR-0080 §2.3 independently-qualified different-family verifier.

import (
	"context"
	"hash/fnv"
	"strings"
	"unicode"
)

const (
	localHashEmbedDimension = 512
	// LocalHashVerifierThreshold is calibrated against both synthetic and
	// live production pairs. Short synthetic claim/evidence pairs of similar
	// length score ~0.45-0.68 when genuinely grounded and ~-0.05-0.15
	// otherwise. A real generated claim (a short paraphrase) checked against
	// a real, much longer multi-topic Evidence fragment (the acc stand's
	// real corpus) scores lower even when genuinely supported — live,
	// verified-correct attempts scored 0.24-0.26 — because the fragment's
	// vector is diluted by its other, unrelated content; 0.20 keeps that
	// case above threshold while staying well clear of the unrelated-pair
	// noise floor. This is deliberately a different, lower constant than
	// DefaultVerifierThreshold, which is calibrated for real embedding-space
	// cosine similarity, not a hashed lexical proxy.
	LocalHashVerifierThreshold = 0.20
)

// LocalHashEmbedFunc returns a network-free EmbedFunc for NewVerifier.
// workspaceID and operationID are accepted (matching the EmbedFunc shape) but
// unused: this computation is pure and local, with nothing to bind per call.
func LocalHashEmbedFunc() EmbedFunc {
	return func(_ context.Context, _, _, text string) ([]float32, error) {
		return localHashEmbed(text), nil
	}
}

func localHashEmbed(text string) []float32 {
	vector := make([]float32, localHashEmbedDimension)
	cleaned := make([]rune, 0, len(text))
	lastWasSpace := true
	for _, r := range strings.ToLower(text) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			cleaned = append(cleaned, r)
			lastWasSpace = false
		case !lastWasSpace:
			cleaned = append(cleaned, ' ')
			lastWasSpace = true
		}
	}
	if len(cleaned) < 3 {
		return vector
	}
	for i := 0; i+3 <= len(cleaned); i++ {
		trigram := cleaned[i : i+3]
		if trigram[0] == ' ' && trigram[1] == ' ' && trigram[2] == ' ' {
			continue
		}
		hasher := fnv.New32a()
		_, _ = hasher.Write([]byte(string(trigram)))
		sum := hasher.Sum32()
		bucket := int(sum % localHashEmbedDimension)
		sign := float32(1)
		if sum&0x10000 != 0 {
			sign = -1
		}
		vector[bucket] += sign
	}
	return vector
}
