package metriccompare

import (
	"errors"
	"strings"
	"testing"
)

func TestEvidenceDigestBindsComparisonSemantics(t *testing.T) {
	profile := testProfile(t)
	comparison, err := ParseResult(comparisonResult(), "2026-09-10", "2026-09-09", profile)
	if err != nil {
		t.Fatal(err)
	}
	rawDigest := "sha256:" + strings.Repeat("a", 64)
	want, err := EvidenceDigest(comparison, 7, rawDigest)
	if err != nil || !digestPattern.MatchString(want) {
		t.Fatalf("evidence digest = %q, %v", want, err)
	}
	again, err := EvidenceDigest(comparison, 7, rawDigest)
	if err != nil || again != want {
		t.Fatalf("digest is not deterministic: %q, %v", again, err)
	}
	reversed, err := ParseResult(comparisonResult(), "2026-09-09", "2026-09-10", profile)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]struct {
		comparison Comparison
		revision   int64
		rawDigest  string
	}{
		"requested order":  {reversed, 7, rawDigest},
		"schema revision":  {comparison, 8, rawDigest},
		"raw table digest": {comparison, 7, "sha256:" + strings.Repeat("b", 64)},
		"profile hash":     {func() Comparison { v := comparison; v.ProfileHash = "sha256:" + strings.Repeat("b", 64); return v }(), 7, rawDigest},
		"unit":             {func() Comparison { v := comparison; v.Unit = "tonnes"; return v }(), 7, rawDigest},
		"observed total": {func() Comparison {
			v := comparison
			v.First.Value = "3889"
			v.Delta = "-251"
			v.PercentChange = "-6.06"
			return v
		}(), 7, rawDigest},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := EvidenceDigest(input.comparison, input.revision, input.rawDigest)
			if err != nil || got == want {
				t.Fatalf("change not bound: %q, %v", got, err)
			}
		})
	}
}

func TestEvidenceDigestRejectsInvalidDerivedValues(t *testing.T) {
	comparison, err := ParseResult(comparisonResult(), "2026-09-10", "2026-09-09", testProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	rawDigest := "sha256:" + strings.Repeat("a", 64)
	for name, mutate := range map[string]func(*Comparison){
		"delta":     func(v *Comparison) { v.Delta = "252" },
		"percent":   func(v *Comparison) { v.PercentChange = "6.09" },
		"row count": func(v *Comparison) { v.First.NonNullCount-- },
	} {
		t.Run(name, func(t *testing.T) {
			value := comparison
			mutate(&value)
			if got, err := EvidenceDigest(value, 7, rawDigest); got != "" || !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid comparison accepted: %q, %v", got, err)
			}
		})
	}
}
