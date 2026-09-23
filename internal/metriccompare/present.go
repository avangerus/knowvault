package metriccompare

import (
	"fmt"
	"math/big"
	"strings"
)

// Present uses English for a validated comparison.
func Present(comparison Comparison) (string, error) {
	return PresentInLanguage(comparison, "en")
}

// PresentInLanguage describes a validated comparison in English or Russian
// without assuming what the metric counts or whether an observed snapshot
// covers the full population. Percentages name their denominator; a
// non-positive denominator has no meaningful higher/lower percentage.
func PresentInLanguage(comparison Comparison, language string) (string, error) {
	if language != "en" && language != "ru" {
		return "", ErrInvalid
	}
	first, firstScale, firstOK := parseDecimal(comparison.First.Value)
	second, secondScale, secondOK := parseDecimal(comparison.Second.Value)
	if !firstOK || !secondOK || !validDate(comparison.First.Date) || !validDate(comparison.Second.Date) ||
		comparison.First.Date == comparison.Second.Date || comparison.Unit == "" || comparison.Coverage != ObservedSnapshot {
		return "", ErrInvalid
	}
	scale := firstScale
	if secondScale > scale {
		scale = secondScale
	}
	difference := new(big.Rat).Sub(first, second)
	if difference.Sign() < 0 {
		difference.Neg(difference)
	}
	unit := comparison.Unit
	if language == "ru" && unit == "unknown" {
		unit = "\u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430"
	}
	var sentences []string
	if language == "ru" {
		sentences = append(sentences, fmt.Sprintf("\u041C\u0435\u0442\u0440\u0438\u043A\u0430 %s, \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0435 \u0441\u0440\u0435\u0437\u044B: %s (\u0441\u0440\u0435\u0437: %s; \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0445 \u0441\u0443\u0431\u044A\u0435\u043A\u0442\u043E\u0432: %d; \u0441\u0442\u0440\u043E\u043A \u0432 \u0440\u0430\u0441\u0447\u0451\u0442\u0435: %d); %s (\u0441\u0440\u0435\u0437: %s; \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u0445 \u0441\u0443\u0431\u044A\u0435\u043A\u0442\u043E\u0432: %d; \u0441\u0442\u0440\u043E\u043A \u0432 \u0440\u0430\u0441\u0447\u0451\u0442\u0435: %d) (\u0435\u0434\u0438\u043D\u0438\u0446\u0430 \u0438\u0437\u043C\u0435\u0440\u0435\u043D\u0438\u044F: %s).",
			comparison.MetricID, snapshotValue(comparison.First), comparison.First.SnapshotAt, comparison.First.DistinctSubjects, comparison.First.ContributingRows,
			snapshotValue(comparison.Second), comparison.Second.SnapshotAt, comparison.Second.DistinctSubjects, comparison.Second.ContributingRows, unit))
	} else {
		sentences = append(sentences, fmt.Sprintf("Metric %s, observed snapshot values: %s (snapshot: %s; observed subjects: %d; contributing rows: %d); %s (snapshot: %s; observed subjects: %d; contributing rows: %d) (unit: %s).",
			comparison.MetricID, snapshotValue(comparison.First), comparison.First.SnapshotAt, comparison.First.DistinctSubjects, comparison.First.ContributingRows,
			snapshotValue(comparison.Second), comparison.Second.SnapshotAt, comparison.Second.DistinctSubjects, comparison.Second.ContributingRows, unit))
	}
	var relation string
	switch first.Cmp(second) {
	case 1:
		relation = relativeValues(comparison.First.Date, comparison.Second.Date, language)
	case -1:
		relation = relativeValues(comparison.Second.Date, comparison.First.Date, language)
	default:
		if language == "ru" {
			relation = "\u0417\u043D\u0430\u0447\u0435\u043D\u0438\u044F \u0440\u0430\u0432\u043D\u044B."
		} else {
			relation = "The values are equal."
		}
	}
	change := []string{strings.TrimSuffix(relation, ".")}
	if language == "ru" {
		change = append(change, "\u0430\u0431\u0441\u043E\u043B\u044E\u0442\u043D\u0430\u044F \u0440\u0430\u0437\u043D\u0438\u0446\u0430: "+compactDecimal(difference, scale))
	} else {
		change = append(change, "absolute difference: "+compactDecimal(difference, scale))
	}
	change = append(change, strings.TrimSuffix(directionalPercentage(comparison.First, comparison.Second, first, second, language), "."))
	change = append(change, strings.TrimSuffix(directionalPercentage(comparison.Second, comparison.First, second, first, language), "."))
	sentences = append(sentences, strings.Join(change, "; ")+".")
	var caveat string
	if language == "ru" {
		caveat = "\u041E\u0445\u0432\u0430\u0442 \u0432\u0441\u0435\u0439 \u0441\u043E\u0432\u043E\u043A\u0443\u043F\u043D\u043E\u0441\u0442\u0438 \u044D\u0442\u0438\u043C\u0438 \u043D\u0430\u0431\u043B\u044E\u0434\u0430\u0435\u043C\u044B\u043C\u0438 \u0441\u0440\u0435\u0437\u0430\u043C\u0438 \u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043D; \u043F\u0440\u043E\u0446\u0435\u043D\u0442\u044B \u043E\u043A\u0440\u0443\u0433\u043B\u0435\u043D\u044B \u0434\u043E \u0434\u0432\u0443\u0445 \u0437\u043D\u0430\u043A\u043E\u0432 \u043F\u043E\u0441\u043B\u0435 \u0437\u0430\u043F\u044F\u0442\u043E\u0439"
	} else {
		caveat = "Full-population coverage of these observed snapshots is unknown; percentages are rounded to two decimal places"
	}
	if comparison.Unit == "unknown" {
		if language == "ru" {
			caveat += "; \u043D\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430\u044F \u0435\u0434\u0438\u043D\u0438\u0446\u0430 \u0438\u0437\u043C\u0435\u0440\u0435\u043D\u0438\u044F \u043D\u0435 \u043F\u043E\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0430\u0435\u0442 \u043A\u043E\u043B\u0438\u0447\u0435\u0441\u0442\u0432\u043E \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u044B\u0445 \u043E\u0431\u044A\u0435\u043A\u0442\u043E\u0432"
		} else {
			caveat += "; the unknown unit does not establish a count of individual items"
		}
	}
	return strings.Join(append(sentences, caveat+"."), " "), nil
}

func snapshotValue(value DailyValue) string {
	return value.Date + " = " + value.Value
}

func relativeValues(higher, lower, language string) string {
	if language == "ru" {
		return fmt.Sprintf("%s \u0438\u043C\u0435\u0435\u0442 \u0431\u043E\u043B\u044C\u0448\u0435\u0435 \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435; %s \u0438\u043C\u0435\u0435\u0442 \u043C\u0435\u043D\u044C\u0448\u0435\u0435 \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u0435.", higher, lower)
	}
	return fmt.Sprintf("%s has the higher value; %s has the lower value.", higher, lower)
}

func directionalPercentage(target, baseline DailyValue, targetValue, baselineValue *big.Rat, language string) string {
	if baselineValue.Sign() == 0 {
		if language == "ru" {
			return fmt.Sprintf("\u041F\u0440\u043E\u0446\u0435\u043D\u0442 \u0434\u043B\u044F %s \u043E\u0442\u043D\u043E\u0441\u0438\u0442\u0435\u043B\u044C\u043D\u043E %s \u043D\u0435 \u043E\u043F\u0440\u0435\u0434\u0435\u043B\u0451\u043D (\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: %s = %s, \u0440\u0430\u0432\u0435\u043D \u043D\u0443\u043B\u044E).",
				target.Date, baseline.Date, baseline.Date, baseline.Value)
		}
		return fmt.Sprintf("Percentage for %s relative to %s is undefined (denominator: %s = %s, non-positive).",
			target.Date, baseline.Date, baseline.Date, baseline.Value)
	}
	if baselineValue.Sign() < 0 {
		magnitude := new(big.Rat).Abs(new(big.Rat).Sub(targetValue, baselineValue))
		denominator := new(big.Rat).Abs(baselineValue)
		value, _ := percent(new(big.Rat).Add(magnitude, denominator), denominator)
		_, scale, _ := parseDecimal(baseline.Value)
		if language == "ru" {
			return fmt.Sprintf("\u0410\u0431\u0441\u043E\u043B\u044E\u0442\u043D\u0430\u044F \u0440\u0430\u0437\u043D\u0438\u0446\u0430 \u0434\u043B\u044F %s \u043E\u0442\u043D\u043E\u0441\u0438\u0442\u0435\u043B\u044C\u043D\u043E %s \u0441\u043E\u0441\u0442\u0430\u0432\u043B\u044F\u0435\u0442 %s%% \u043E\u0442 \u043C\u043E\u0434\u0443\u043B\u044F \u0431\u0430\u0437\u043E\u0432\u043E\u0433\u043E \u0437\u043D\u0430\u0447\u0435\u043D\u0438\u044F (\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: |%s| = %s).",
				target.Date, baseline.Date, value, baseline.Value, compactDecimal(denominator, scale))
		}
		return fmt.Sprintf("The absolute difference for %s relative to %s is %s%% of the baseline magnitude (denominator: |%s| = %s).",
			target.Date, baseline.Date, value, baseline.Value, compactDecimal(denominator, scale))
	}
	value, _ := percent(targetValue, baselineValue)
	value = strings.TrimPrefix(value, "-")
	if targetValue.Cmp(baselineValue) == 0 {
		if language == "ru" {
			return fmt.Sprintf("%s \u0440\u0430\u0432\u043D\u043E %s (\u0440\u0430\u0437\u043D\u0438\u0446\u0430 %s%%; \u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: %s = %s).",
				target.Date, baseline.Date, value, baseline.Date, baseline.Value)
		}
		return fmt.Sprintf("%s equals %s (%s%% difference; denominator: %s = %s).",
			target.Date, baseline.Date, value, baseline.Date, baseline.Value)
	}
	direction := "higher"
	if targetValue.Cmp(baselineValue) < 0 {
		direction = "lower"
	}
	if language == "ru" {
		if direction == "lower" {
			return fmt.Sprintf("%s \u043D\u0430 %s%% \u043D\u0438\u0436\u0435, \u0447\u0435\u043C %s (\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: %s = %s).",
				target.Date, value, baseline.Date, baseline.Date, baseline.Value)
		}
		return fmt.Sprintf("%s \u043D\u0430 %s%% \u0432\u044B\u0448\u0435, \u0447\u0435\u043C %s (\u0437\u043D\u0430\u043C\u0435\u043D\u0430\u0442\u0435\u043B\u044C: %s = %s).",
			target.Date, value, baseline.Date, baseline.Date, baseline.Value)
	}
	return fmt.Sprintf("%s is %s%% %s relative to %s (denominator: %s = %s).",
		target.Date, value, direction, baseline.Date, baseline.Date, baseline.Value)
}
