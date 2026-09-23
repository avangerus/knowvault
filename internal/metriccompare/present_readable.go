package metriccompare

import (
	"fmt"
	"math/big"
	"strings"
)

// PresentReadable is the v3 presentation. PresentInLanguage is frozen for
// stored v2 answers: changing those bytes would invalidate their evidence.
func PresentReadable(comparison Comparison, language string) (string, error) {
	if _, err := PresentInLanguage(comparison, language); err != nil {
		return "", err
	}
	first, firstScale, _ := parseDecimal(comparison.First.Value)
	second, secondScale, _ := parseDecimal(comparison.Second.Value)
	difference := new(big.Rat).Abs(new(big.Rat).Sub(first, second))
	delta := compactDecimal(difference, max(firstScale, secondScale))
	higher, lower, highValue, lowValue := comparison.First, comparison.Second, first, second
	if first.Cmp(second) < 0 {
		higher, lower, highValue, lowValue = comparison.Second, comparison.First, second, first
	}
	lede := directionalPercentage(higher, lower, highValue, lowValue, language)
	if highValue.Cmp(lowValue) == 0 {
		lede = "The values are equal."
		if language == "ru" {
			lede = "\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u044f \u0440\u0430\u0432\u043d\u044b."
		}
	} else if lowValue.Sign() <= 0 {
		lede = relativeValues(higher.Date, lower.Date, language) + " " + lede
	}
	values := fmt.Sprintf("Metric %s:\n- %s\n- %s\n\nUnit: %s.", comparison.MetricID, snapshotValue(comparison.First), snapshotValue(comparison.Second), comparison.Unit)
	caveat := "These values describe observed snapshots; whether all records are covered is unknown. Percentages are rounded to two decimal places."
	differenceLabel := "Absolute difference"
	if language == "ru" {
		differenceLabel = "\u0420\u0430\u0437\u043d\u0438\u0446\u0430"
		unit := comparison.Unit
		if unit == "unknown" {
			unit = "\u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u0430"
		}
		values = fmt.Sprintf("\u041c\u0435\u0442\u0440\u0438\u043a\u0430 %s:\n- %s\n- %s\n\n\u0415\u0434\u0438\u043d\u0438\u0446\u0430 \u0438\u0437\u043c\u0435\u0440\u0435\u043d\u0438\u044f: %s.", comparison.MetricID, snapshotValue(comparison.First), snapshotValue(comparison.Second), unit)
		caveat = "\u0421\u0440\u0430\u0432\u043d\u0435\u043d\u044b \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b\u0435 \u0441\u0440\u0435\u0437\u044b \u0434\u0430\u043d\u043d\u044b\u0445; \u043f\u043e\u043b\u043d\u043e\u0442\u0430 \u043e\u0445\u0432\u0430\u0442\u0430 \u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u0430. \u041f\u0440\u043e\u0446\u0435\u043d\u0442\u044b \u043e\u043a\u0440\u0443\u0433\u043b\u0435\u043d\u044b \u0434\u043e \u0434\u0432\u0443\u0445 \u0437\u043d\u0430\u043a\u043e\u0432."
	}
	if comparison.Unit == "unknown" {
		if language == "ru" {
			caveat += " \u042d\u0442\u043e \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f \u043f\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044f, \u0430 \u043d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u043e\u0435 \u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u043e\u0442\u0434\u0435\u043b\u044c\u043d\u044b\u0445 \u043e\u0431\u044a\u0435\u043a\u0442\u043e\u0432."
		} else {
			caveat += " These are indicator values, not a verified count of individual items."
		}
	}
	lede = strings.NewReplacer("denominator:", "baseline:", "\u0437\u043d\u0430\u043c\u0435\u043d\u0430\u0442\u0435\u043b\u044c:", "\u0431\u0430\u0437\u0430:").Replace(lede)
	lede += " " + differenceLabel + ": " + delta + "."
	return lede + "\n\n" + values + "\n\n" + caveat, nil
}
