package metriccompare

import (
	"strings"
	"testing"
)

func TestReadableComparisonLeadsWithOneCorrectBaseline(t *testing.T) {
	for _, test := range []struct{ first, second, percentage, delta string }{
		{"3888", "4140", "6.48%", "252"},
		{"4140", "3888", "6.48%", "252"},
		{"1.00005", "1", "0.01%", "0.00005"},
		{"10", "0", "", "10"},
		{"-10", "-20", "50.00%", "10"},
		{"0", "0", "", "0"},
	} {
		result := comparisonResult()
		result.Rows[0][5], result.Rows[1][5] = cell(test.first), cell(test.second)
		comparison, err := ParseResult(result, "2026-09-10", "2026-09-09", testProfile(t))
		if err != nil {
			t.Fatal(err)
		}
		for _, language := range []string{"en", "ru"} {
			text, err := PresentReadable(comparison, language)
			if err != nil {
				t.Fatal(err)
			}
			lede, _, _ := strings.Cut(text, "\n\n")
			if !strings.Contains(lede, test.delta) || !strings.Contains(lede, test.percentage) || strings.Count(lede, "%") > 1 ||
				strings.HasPrefix(lede, "Metric") || !strings.Contains(text, "- 2026-09-10 = "+test.first) || !strings.Contains(text, "- 2026-09-09 = "+test.second) {
				t.Fatalf("%s readable result: %s", language, text)
			}
			if test.percentage == "" && strings.Contains(lede, "%") {
				t.Fatalf("undefined percentage: %s", lede)
			}
			if language == "en" && (!strings.Contains(text, "coverage") && !strings.Contains(text, "covered") || !strings.Contains(text, "not a verified count")) {
				t.Fatalf("missing limits: %s", text)
			}
		}
	}
}

func TestReadableComparisonRejectsInvalidInput(t *testing.T) {
	comparison, err := ParseResult(comparisonResult(), "2026-09-10", "2026-09-09", testProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PresentReadable(comparison, "fr"); err != ErrInvalid {
		t.Fatal("unknown language accepted")
	}
	comparison.Second.Date = comparison.First.Date
	if _, err := PresentReadable(comparison, "en"); err != ErrInvalid {
		t.Fatal("same date accepted")
	}
}
