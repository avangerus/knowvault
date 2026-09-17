package retrieval

import (
	"math"
	"strings"
	"testing"
)

func hybridHit(channel Channel, id, object string, score float64) ChannelHit {
	return ChannelHit{
		Channel: channel, EvidenceFragmentID: id, SourceObjectID: object,
		SourceVersionID: "version-" + object, ExtractionID: "extraction-" + object,
		ContentHash: "sha256:" + strings.Repeat("a", 64),
		TextHash:    "hmac-sha256:k1:" + strings.Repeat("b", 64),
		AnchorHash:  "hmac-sha256:k1:" + strings.Repeat("c", 64), Score: score,
	}
}

func TestFuseRequiresAllHybridChannelsAndRanksDeterministically(t *testing.T) {
	result, err := Fuse([]ChannelResult{
		{Channel: ChannelLexical, CoverageComplete: true, Hits: []ChannelHit{
			hybridHit(ChannelLexical, "fragment-a", "object-a", 8),
			hybridHit(ChannelLexical, "fragment-b", "object-b", 7),
		}},
		{Channel: ChannelVector, CoverageComplete: true, Hits: []ChannelHit{
			hybridHit(ChannelVector, "fragment-b", "object-b", 0.9),
			hybridHit(ChannelVector, "fragment-c", "object-c", 0.8),
		}},
		{Channel: ChannelEntity, CoverageComplete: true, Hits: []ChannelHit{
			hybridHit(ChannelEntity, "fragment-c", "object-c", 0.7),
		}},
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if result.Partial || len(result.Hits) != 3 {
		t.Fatalf("complete hybrid result=%+v", result)
	}
	if result.Hits[0].EvidenceFragmentID != "fragment-b" || len(result.Hits[1].Channels) != 2 {
		t.Fatalf("unexpected RRF order/channels=%+v", result.Hits)
	}
	missing, err := Fuse([]ChannelResult{{Channel: ChannelLexical, CoverageComplete: true}}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !missing.Partial {
		t.Fatal("missing vector/entity channels reported complete")
	}
}

func TestFuseWithOptionsAllowsExplicitLexicalOnlyProfile(t *testing.T) {
	result, err := FuseWithOptions([]ChannelResult{
		{Channel: ChannelLexical, CoverageComplete: true, Hits: []ChannelHit{
			hybridHit(ChannelLexical, "fragment-a", "object-a", 1),
		}},
	}, 8, FuseOptions{OptionalChannels: []Channel{ChannelVector, ChannelEntity}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Partial || len(result.Hits) != 1 {
		t.Fatalf("explicit lexical-only result=%+v", result)
	}
	if _, err := FuseWithOptions([]ChannelResult{{Channel: ChannelLexical, CoverageComplete: true}}, 8,
		FuseOptions{OptionalChannels: []Channel{ChannelVector}}); err != nil {
		t.Fatal("optional vector should not make lexical fusion invalid: ", err)
	}
	missingEntity, err := FuseWithOptions([]ChannelResult{{Channel: ChannelLexical, CoverageComplete: true}}, 8,
		FuseOptions{OptionalChannels: []Channel{ChannelVector}})
	if err != nil {
		t.Fatal(err)
	}
	if !missingEntity.Partial {
		t.Fatal("non-optional entity channel reported complete")
	}
}

func TestFuseWithOptionsRejectsInvalidOptionalChannel(t *testing.T) {
	if _, err := FuseWithOptions([]ChannelResult{{Channel: ChannelLexical, CoverageComplete: true}}, 8,
		FuseOptions{OptionalChannels: []Channel{"INVALID"}}); err == nil {
		t.Fatal("invalid optional channel accepted")
	}
}

func TestFuseRejectsLineageDriftAndDuplicateChannel(t *testing.T) {
	base := hybridHit(ChannelLexical, "fragment-a", "object-a", 1)
	foreign := base
	foreign.SourceVersionID = "version-other"
	if _, err := Fuse([]ChannelResult{
		{Channel: ChannelLexical, CoverageComplete: true, Hits: []ChannelHit{base}},
		{Channel: ChannelVector, CoverageComplete: true, Hits: []ChannelHit{foreign}},
	}, 8); err == nil {
		t.Fatal("lineage drift accepted")
	}
	if _, err := Fuse([]ChannelResult{
		{Channel: ChannelLexical, CoverageComplete: true},
		{Channel: ChannelLexical, CoverageComplete: true},
	}, 8); err == nil {
		t.Fatal("duplicate channel accepted")
	}
	base.Score = math.NaN()
	if _, err := Fuse([]ChannelResult{{Channel: ChannelLexical, CoverageComplete: true, Hits: []ChannelHit{base}}}, 8); err == nil {
		t.Fatal("non-finite provider score accepted")
	}
}
