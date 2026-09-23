package metriccompare

import (
	"strings"
	"testing"
)

func presentationForValues(t *testing.T, first, second string) string {
	return presentationForValuesInLanguage(t, first, second, "en")
}

func presentationForValuesInLanguage(t *testing.T, first, second, language string) string {
	t.Helper()
	result := comparisonResult()
	result.Rows[0][5] = cell(first)
	result.Rows[1][5] = cell(second)
	comparison, err := ParseResult(result, "2026-09-10", "2026-09-09", testProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	text, err := PresentInLanguage(comparison, language)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestPresentRussianDirectionsAndZeroBaseline(t *testing.T) {
	text := presentationForValuesInLanguage(t, "3888", "4140", "ru")
	for _, want := range []string{
		"\u041C\u0435\u0442\u0440\u0438\u043A\u0430 work.assignments, \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0435 \u0441\u0440\u0435\u0437\u044B: 2026-09-10 = 3888 (\u0441\u0440\u0435\u0437: 2026-09-10T00:00:00+03:00; \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0445 \u0441\u0443\u0431\u044A\u0435\u043A\u0442\u043E\u0432: 407; \u0441\u0442\u0440\u043E\u043A \u0432 \u0440\u0430\u0441\u0447\u0451\u0442\u0435: 407); 2026-09-09 = 4140 (\u0441\u0440\u0435\u0437: 2026-09-09T00:00:00+03:00; \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0445 \u0441\u0443\u0431\u044A\u0435\u043A\u0442\u043E\u0432: 457; \u0441\u0442\u0440\u043E\u043A \u0432 \u0440\u0430\u0441\u0447\u0451\u0442\u0435: 457) (\u0435\u0434\u0438\u043D\u0438\u0446\u0430 \u0438\u0437\u043C\u0435\u0440\u0435\u043D\u0438\u044F: \u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430)",
		"2026-09-09 \u0438\u043C\u0435\u0435\u0442 \u0431\u043E\u043B\u044C\u0448\u0435\u0435 \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435; 2026-09-10 \u0438\u043C\u0435\u0435\u0442 \u043C\u0435\u043D\u044C\u0448\u0435\u0435 \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435",
		"\u0430\u0431\u0441\u043E\u043B\u044E\u0442\u043D\u0430\u044F \u0440\u0430\u0437\u043D\u0438\u0446\u0430: 252;",
		"2026-09-09 \u043D\u0430 6.48% \u0432\u044B\u0448\u0435, \u0447\u0435\u043C 2026-09-10 (\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: 2026-09-10 = 3888)",
		"2026-09-10 \u043D\u0430 6.09% \u043D\u0438\u0436\u0435, \u0447\u0435\u043C 2026-09-09 (\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: 2026-09-09 = 4140)",
		"\u041E\u0445\u0432\u0430\u0442 \u0432\u0441\u0435\u0439 \u0441\u043E\u0432\u043E\u043A\u0443\u043F\u043D\u043E\u0441\u0442\u0438 \u044D\u0442\u0438\u043C\u0438 \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u043C\u0438 \u0441\u0440\u0435\u0437\u0430\u043C\u0438 \u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043D",
		"\u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430\u044F \u0435\u0434\u0438\u043D\u0438\u0446\u0430 \u0438\u0437\u043C\u0435\u0440\u0435\u043D\u0438\u044F \u043D\u0435 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0430\u0435\u0442 \u043A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u044B\u0445 \u043E\u0431\u044A\u0435\u043A\u0442\u043E\u0432",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Russian presentation missing %q: %s", want, text)
		}
	}
	zero := presentationForValuesInLanguage(t, "10", "0", "ru")
	if !strings.Contains(zero, "\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: 2026-09-09 = 0, \u0440\u0430\u0432\u0435\u043D \u043D\u0443\u043B\u044E") ||
		!strings.Contains(zero, "2026-09-09 \u043D\u0430 100.00% \u043D\u0438\u0436\u0435, \u0447\u0435\u043C 2026-09-10") ||
		!strings.Contains(zero, "\u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0445 \u0441\u0443\u0431\u044A\u0435\u043A\u0442\u043E\u0432: 407; \u0441\u0442\u0440\u043E\u043A \u0432 \u0440\u0430\u0441\u0447\u0451\u0442\u0435: 407") ||
		strings.Contains(zero, "100.00% \u0432\u044B\u0448\u0435, \u0447\u0435\u043C 2026-09-09") {
		t.Fatalf("Russian zero-baseline presentation is misleading: %s", zero)
	}
}

func TestPresentRejectsUnknownLanguage(t *testing.T) {
	comparison, err := ParseResult(comparisonResult(), "2026-09-10", "2026-09-09", testProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	english, err := PresentInLanguage(comparison, "en")
	if err != nil {
		t.Fatal(err)
	}
	if wrapped, err := Present(comparison); err != nil || wrapped != english {
		t.Fatalf("English wrapper = %q, %v; want %q", wrapped, err, english)
	}
	if text, err := PresentInLanguage(comparison, "fr"); err != ErrInvalid || text != "" {
		t.Fatalf("unknown language = %q, %v; want ErrInvalid", text, err)
	}
}

func TestPresentObservedSnapshotBothDirections(t *testing.T) {
	text := presentationForValues(t, "3888", "4140")
	for _, want := range []string{
		"Metric work.assignments, observed snapshot values:",
		"2026-09-10 = 3888 (snapshot: 2026-09-10T00:00:00+03:00; observed subjects: 407; contributing rows: 407); 2026-09-09 = 4140 (snapshot: 2026-09-09T00:00:00+03:00; observed subjects: 457; contributing rows: 457) (unit: unknown)",
		"2026-09-09 has the higher value; 2026-09-10 has the lower value",
		"absolute difference: 252;",
		"2026-09-09 is 6.48% higher relative to 2026-09-10 (denominator: 2026-09-10 = 3888)",
		"2026-09-10 is 6.09% lower relative to 2026-09-09 (denominator: 2026-09-09 = 4140)",
		"Full-population coverage of these observed snapshots is unknown",
		"unknown unit does not establish a count of individual items",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("presentation missing %q: %s", want, text)
		}
	}
}

func TestPresentExactDecimalAndLargeValues(t *testing.T) {
	text := presentationForValues(t, "1000000000000000000000000000000.005", "1000000000000000000000000000000")
	if !strings.Contains(text, "absolute difference: 0.005;") ||
		!strings.Contains(text, "0.00% higher") || !strings.Contains(text, "0.00% lower") {
		t.Fatalf("large decimal presentation lost precision: %s", text)
	}
	text = presentationForValues(t, "1.00005", "1")
	if !strings.Contains(text, "absolute difference: 0.00005;") || !strings.Contains(text, "0.01% higher") {
		t.Fatalf("half-away-from-zero rounding changed: %s", text)
	}
}

func TestPresentNonPositiveBaselinesAndEqualValues(t *testing.T) {
	for _, test := range []struct {
		name, first, second string
		wants               []string
		forbidden           string
	}{
		{"zero baseline", "10", "0", []string{"absolute difference: 10;", "denominator: 2026-09-09 = 0, non-positive", "100.00% lower relative to 2026-09-10"}, "higher relative to 2026-09-09"},
		{"negative values", "-10.25", "-20.5", []string{"2026-09-10 has the higher value", "absolute difference: 10.25;", "50.00% of the baseline magnitude (denominator: |-20.5| = 20.5)", "100.00% of the baseline magnitude (denominator: |-10.25| = 10.25)"}, "% higher"},
		{"equal values", "0", "0", []string{"The values are equal;", "absolute difference: 0;", "denominator: 2026-09-09 = 0, non-positive", "denominator: 2026-09-10 = 0, non-positive"}, "% equal"},
		{"equal positive values", "1.25", "1.25", []string{"The values are equal;", "absolute difference: 0;", "2026-09-10 equals 2026-09-09 (0.00% difference; denominator: 2026-09-09 = 1.25)", "2026-09-09 equals 2026-09-10 (0.00% difference; denominator: 2026-09-10 = 1.25)"}, "% higher"},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := presentationForValues(t, test.first, test.second)
			for _, want := range test.wants {
				if !strings.Contains(text, want) {
					t.Fatalf("presentation missing %q: %s", want, text)
				}
			}
			if strings.Contains(text, test.forbidden) {
				t.Fatalf("presentation contains misleading percentage %q: %s", test.forbidden, text)
			}
		})
	}
}
