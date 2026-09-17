package modelgateway

// This file is the GEN-1 (ADR-0088) interim claim verifier. It reuses whatever
// already-integrated embedding channel the caller wires in (via EmbedFunc) to
// compare a generated claim's text against its cited Evidence in vector space.
// This is a genuine, disclosed interim semantic check: it is NOT the
// independently qualified, different-family LLM verifier that ADR-0080 §2.3
// ultimately requires for a production GENERATIVE claim, and it must never be
// described as closing that gate. It exists so an unverifiable model claim
// cannot be published just because it is schema-valid and evidence-bounded.

import (
	"context"
	"errors"
	"math"
	"strconv"
)

const (
	// DefaultVerifierThreshold is deliberately conservative: a false accept
	// (an unsupported claim reaching disclosure) is worse than a false reject
	// (a supported claim falling back to the terminal insufficient-evidence
	// state), matching MOD-004/CIT-002's fail-closed intent.
	DefaultVerifierThreshold = 0.62
	maxVerifierClaimBytes    = 2000
	maxVerifierEvidenceItems = MaxEvidencePerClaim
)

// EmbedFunc returns a real embedding vector for one piece of text under the
// caller's own tenant-bound, purpose-scoped embedding client. workspaceID and
// operationID let the caller assemble a real per-question embedding Binding
// (GEN-2: "per-question Binding is assembled normally") instead of a shared,
// workspace-agnostic one; the verifier never constructs or holds a network
// client itself and never sees an organization ID.
type EmbedFunc func(ctx context.Context, workspaceID, operationID, text string) ([]float32, error)

// Verifier is the interim, embedding-similarity claim checker described above.
type Verifier struct {
	embed     EmbedFunc
	threshold float64
}

func NewVerifier(embed EmbedFunc, threshold float64) (*Verifier, error) {
	if embed == nil || threshold <= 0 || threshold > 1 || math.IsNaN(threshold) {
		return nil, &Error{code: CodeInvalid}
	}
	return &Verifier{embed: embed, threshold: threshold}, nil
}

// VerifyClaim reports whether claimText is semantically supported by at least
// one of evidenceTexts. It fails closed (false, non-nil error) on any embedding
// failure rather than treating an unavailable embedder as a pass.
//
// workspaceID and operationIDPrefix bind every embedding call this claim
// makes to the exact question run and claim (GEN-2 per-question Binding): the
// claim text uses operationIDPrefix+":claim" and each evidence text uses
// operationIDPrefix+":evidence:"+<index>, so a caller assembling a real
// embedding.Binding per call can reconstruct a stable, unique operation id
// without the verifier importing the embedding package itself.
func (verifier *Verifier) VerifyClaim(ctx context.Context, workspaceID, operationIDPrefix, claimText string, evidenceTexts []string) (bool, error) {
	if verifier == nil || verifier.embed == nil || ctx == nil {
		return false, &Error{code: CodeInvalid}
	}
	if !validOpaque(workspaceID) || !validOpaque(operationIDPrefix) {
		return false, &Error{code: CodeInvalid}
	}
	if claimText == "" || len(claimText) > maxVerifierClaimBytes || len(evidenceTexts) == 0 || len(evidenceTexts) > maxVerifierEvidenceItems {
		return false, &Error{code: CodeInvalid}
	}
	claimVector, err := verifier.embed(ctx, workspaceID, operationIDPrefix+":claim", claimText)
	if err != nil {
		return false, &Error{code: CodeUnavailable, cause: err}
	}
	best := -1.0
	for index, evidenceText := range evidenceTexts {
		if evidenceText == "" {
			return false, &Error{code: CodeInvalid}
		}
		evidenceVector, err := verifier.embed(ctx, workspaceID, operationIDPrefix+":evidence:"+strconv.Itoa(index), evidenceText)
		if err != nil {
			return false, &Error{code: CodeUnavailable, cause: err}
		}
		similarity, err := cosineSimilarity(claimVector, evidenceVector)
		if err != nil {
			return false, err
		}
		if similarity > best {
			best = similarity
		}
	}
	return best >= verifier.threshold, nil
}

func cosineSimilarity(a, b []float32) (float64, error) {
	if len(a) == 0 || len(a) != len(b) {
		return 0, errors.New("incompatible embedding dimensions")
	}
	var dot, normA, normB float64
	for index := range a {
		av, bv := float64(a[index]), float64(b[index])
		dot += av * bv
		normA += av * av
		normB += bv * bv
	}
	if normA == 0 || normB == 0 {
		return 0, errors.New("degenerate embedding vector")
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB)), nil
}
