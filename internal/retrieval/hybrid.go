package retrieval

import (
	"errors"
	"math"
	"sort"
)

// Channel identifies an independent retrieval signal. The fusion layer knows
// only this vocabulary; providers remain responsible for lexical, vector and
// entity/relationship search and never pass raw text or executable queries
// through it.
type Channel string

const (
	ChannelLexical Channel = "LEXICAL"
	ChannelVector  Channel = "VECTOR"
	ChannelEntity  Channel = "ENTITY_RELATIONSHIP"
)

const (
	maximumHybridHits  = 256
	maximumHybridLimit = 128
	rrfConstant        = 60.0
)

// ChannelHit is a typed, post-provider reference. It is intentionally a
// metadata-only shape: Evidence text, SQL, vectors and citations are absent
// and can only be recovered later through the PostgreSQL authorization gate.
type ChannelHit struct {
	Channel            Channel
	EvidenceFragmentID string
	SourceObjectID     string
	SourceVersionID    string
	ExtractionID       string
	ContentHash        string
	TextHash           string
	AnchorHash         string
	Score              float64
}

// ChannelResult records one provider's bounded coverage. A missing, stale or
// failed channel is preserved as incomplete metadata so the answer authority
// can return UNKNOWN/insufficient evidence rather than silently treating one
// signal as a complete corpus.
type ChannelResult struct {
	Channel          Channel
	Hits             []ChannelHit
	CoverageComplete bool
}

type FusedHit struct {
	EvidenceFragmentID string
	SourceObjectID     string
	SourceVersionID    string
	ExtractionID       string
	ContentHash        string
	TextHash           string
	AnchorHash         string
	Score              float64
	Channels           []Channel
}

type FusionResult struct {
	Hits    []FusedHit
	Partial bool
}

// FuseOptions declares channels that are intentionally absent from a
// deployment profile.  It is not a quality override: a provider that is
// present but returns an incomplete result still contributes its typed hits,
// while the caller must explicitly prove that an omitted channel is optional
// (for example, the durable lexical-only profile used before vector
// qualification).  The default Fuse path remains strict and requires all
// three hybrid channels.
type FuseOptions struct {
	OptionalChannels []Channel
}

// Fuse applies deterministic reciprocal-rank fusion over the declared
// channels. It neither privileges SQL nor assumes a business entity; adding a
// provider changes only the channel result, never the planner or renderer.
func Fuse(results []ChannelResult, limit int) (FusionResult, error) {
	return FuseWithOptions(results, limit, FuseOptions{})
}

// FuseWithOptions applies the same deterministic RRF and lineage guards as
// Fuse, while allowing an administrator-declared optional channel to be
// missing without marking the lexical result partial.  Optionality is kept at
// the fusion boundary so the strict default and all existing callers remain
// unchanged.
func FuseWithOptions(results []ChannelResult, limit int, options FuseOptions) (FusionResult, error) {
	if len(results) == 0 || limit < 1 || limit > maximumHybridLimit {
		return FusionResult{}, invalidFusion("fusion shape invalid")
	}
	optionalChannels := make(map[Channel]struct{}, len(options.OptionalChannels))
	for _, channel := range options.OptionalChannels {
		if !validChannel(channel) {
			return FusionResult{}, invalidFusion("optional channel invalid")
		}
		if _, duplicate := optionalChannels[channel]; duplicate {
			return FusionResult{}, invalidFusion("duplicate optional channel")
		}
		optionalChannels[channel] = struct{}{}
	}
	seenChannels := make(map[Channel]struct{}, len(results))
	byEvidence := make(map[string]*FusedHit)
	partial := false
	for _, result := range results {
		if !validChannel(result.Channel) || len(result.Hits) > maximumHybridHits {
			return FusionResult{}, invalidFusion("channel shape invalid")
		}
		if _, duplicate := seenChannels[result.Channel]; duplicate {
			return FusionResult{}, invalidFusion("duplicate channel")
		}
		seenChannels[result.Channel] = struct{}{}
		if !result.CoverageComplete {
			if _, optional := optionalChannels[result.Channel]; !optional {
				partial = true
			}
		}
		seenEvidence := make(map[string]struct{}, len(result.Hits))
		for rank, hit := range result.Hits {
			if err := validateChannelHit(hit, result.Channel); err != nil {
				return FusionResult{}, err
			}
			if _, duplicate := seenEvidence[hit.EvidenceFragmentID]; duplicate {
				return FusionResult{}, invalidFusion("duplicate evidence in " + string(result.Channel))
			}
			seenEvidence[hit.EvidenceFragmentID] = struct{}{}
			fused := byEvidence[hit.EvidenceFragmentID]
			if fused == nil {
				fused = &FusedHit{EvidenceFragmentID: hit.EvidenceFragmentID,
					SourceObjectID: hit.SourceObjectID, SourceVersionID: hit.SourceVersionID,
					ExtractionID: hit.ExtractionID, ContentHash: hit.ContentHash,
					TextHash: hit.TextHash, AnchorHash: hit.AnchorHash}
				byEvidence[hit.EvidenceFragmentID] = fused
			} else if fused.SourceObjectID != hit.SourceObjectID || fused.SourceVersionID != hit.SourceVersionID ||
				fused.ExtractionID != hit.ExtractionID || fused.ContentHash != hit.ContentHash ||
				fused.TextHash != hit.TextHash || fused.AnchorHash != hit.AnchorHash {
				// The same Evidence ID cannot have two lineages. A provider that
				// returns one is not merely low quality; it is an integrity failure.
				return FusionResult{}, invalidFusion("evidence lineage mismatch")
			}
			fused.Score += 1 / (rrfConstant + float64(rank+1))
			fused.Channels = append(fused.Channels, result.Channel)
		}
	}
	// A true hybrid run needs all three declared signals. Until every provider
	// is qualified, the result is intentionally marked partial and the question
	// authority must not publish it as a complete answer.
	if _, ok := seenChannels[ChannelLexical]; !ok {
		partial = true
	}
	if _, ok := seenChannels[ChannelVector]; !ok {
		if _, optional := optionalChannels[ChannelVector]; !optional {
			partial = true
		}
	}
	if _, ok := seenChannels[ChannelEntity]; !ok {
		if _, optional := optionalChannels[ChannelEntity]; !optional {
			partial = true
		}
	}
	fused := make([]FusedHit, 0, len(byEvidence))
	for _, hit := range byEvidence {
		sort.Slice(hit.Channels, func(i, j int) bool { return hit.Channels[i] < hit.Channels[j] })
		fused = append(fused, *hit)
	}
	sort.SliceStable(fused, func(i, j int) bool {
		if fused[i].Score != fused[j].Score {
			return fused[i].Score > fused[j].Score
		}
		return fused[i].EvidenceFragmentID < fused[j].EvidenceFragmentID
	})
	if len(fused) > limit {
		fused = fused[:limit]
		partial = true
	}
	return FusionResult{Hits: fused, Partial: partial}, nil
}

func invalidFusion(reason string) error {
	return &Error{code: CodeExecutorInvalid, cause: errors.New(reason)}
}

func validChannel(channel Channel) bool {
	return channel == ChannelLexical || channel == ChannelVector || channel == ChannelEntity
}

func validateChannelHit(hit ChannelHit, expected Channel) error {
	if hit.Channel != expected {
		return &Error{code: CodeExecutorInvalid, cause: errors.New("channel identity mismatch")}
	}
	if !validOpaque(hit.EvidenceFragmentID) || !validOpaque(hit.SourceObjectID) ||
		!validOpaque(hit.SourceVersionID) || !validOpaque(hit.ExtractionID) {
		return &Error{code: CodeExecutorInvalid, cause: errors.New("channel lineage shape invalid")}
	}
	if !validDigest(hit.ContentHash) || !validDigest(hit.TextHash) || !validDigest(hit.AnchorHash) {
		return &Error{code: CodeExecutorInvalid, cause: errors.New("channel digest shape invalid")}
	}
	if hit.Score < 0 || math.IsNaN(hit.Score) || math.IsInf(hit.Score, 0) {
		return &Error{code: CodeExecutorInvalid, cause: errors.New("channel score invalid")}
	}
	return nil
}

func validDigest(value string) bool {
	return validSHA256(value) || validHMAC(value)
}
