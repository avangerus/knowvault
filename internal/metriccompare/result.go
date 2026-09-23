package metriccompare

import (
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/tzrules"
)

const ObservedSnapshot = "OBSERVED_SNAPSHOT"

// TableResult is the transport-neutral text table returned by the approved
// comparison read. The caller converts its governed-query result into this
// shape without granting this package access to the database executor.
type TableResult struct {
	Columns  []string
	Rows     [][]*string
	RowCount int
}

var decimalText = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)$`)

// DailyValue is the total of the observed subjects at one selected snapshot.
// It does not assert that the snapshot contains the entire population.
type DailyValue struct {
	Date             string
	SnapshotAt       string
	ContributingRows int64
	DistinctSubjects int64
	NonNullCount     int64
	Value            string
}

// Comparison is a value-only, validated projection. First and Second follow
// the caller's requested order, regardless of the SQL result's row order.
// Delta is First minus Second. PercentChange is Delta / Second * 100,
// rounded to two decimal places, with ties away from zero. It is empty when
// Second is zero because a percentage change from zero is undefined.
type Comparison struct {
	MetricID      string
	ProfileHash   string
	Unit          string
	Coverage      string
	First         DailyValue
	Second        DailyValue
	Delta         string
	PercentChange string
}

func parseDecimal(value string) (*big.Rat, int, bool) {
	if len(value) == 0 || len(value) > 128 || !decimalText.MatchString(value) {
		return nil, 0, false
	}
	r, ok := new(big.Rat).SetString(value)
	if !ok {
		return nil, 0, false
	}
	scale := 0
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		scale = len(value) - dot - 1
	}
	return r, scale, true
}

func compactDecimal(r *big.Rat, scale int) string {
	value := r.FloatString(scale)
	if strings.Contains(value, ".") {
		value = strings.TrimRight(strings.TrimRight(value, "0"), ".")
	}
	if value == "-0" || value == "" {
		return "0"
	}
	return value
}

func percent(first, second *big.Rat) (string, bool) {
	if second.Sign() == 0 {
		return "", false
	}
	// Units of 0.01 percent: (first-second)/second * 10,000.
	scaled := new(big.Rat).Mul(new(big.Rat).Sub(first, second), big.NewRat(10000, 1))
	scaled.Quo(scaled, second)
	negative := scaled.Sign() < 0
	if negative {
		scaled.Neg(scaled)
	}
	whole, remainder := new(big.Int).QuoRem(scaled.Num(), scaled.Denom(), new(big.Int))
	if new(big.Int).Lsh(remainder, 1).Cmp(scaled.Denom()) >= 0 {
		whole.Add(whole, big.NewInt(1))
	}
	result := new(big.Rat).SetFrac(whole, big.NewInt(100)).FloatString(2)
	if negative && whole.Sign() != 0 {
		result = "-" + result
	}
	return result, true
}

func parseSnapshot(value, date, timezone string) (string, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999-0700",
	} {
		parsed, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		location, err := tzrules.Load(timezone)
		if err != nil || parsed.In(location).Format("2006-01-02") != date {
			return "", false
		}
		return parsed.Format(time.RFC3339Nano), true
	}
	return "", false
}

// ParseResult accepts only the exact projection emitted by Compile. Any
// missing/duplicate period, absent measure, partial subjects, or altered
// result shape is refused rather than converted into a plausible total.
func ParseResult(result TableResult, firstDate, secondDate string, profile Profile) (Comparison, error) {
	if profile.hash == "" || !validDate(firstDate) || !validDate(secondDate) || firstDate == secondDate ||
		result.RowCount != 2 || len(result.Rows) != 2 || len(result.Columns) != 6 {
		return Comparison{}, ErrInvalid
	}
	expected := [...]string{"local_date", "snapshot_at", "contributing_rows", "distinct_subjects", "nonnull_count", "value"}
	for i, column := range expected {
		if result.Columns[i] != column {
			return Comparison{}, ErrInvalid
		}
	}
	values := make(map[string]DailyValue, 2)
	amounts := make(map[string]*big.Rat, 2)
	scales := make(map[string]int, 2)
	for _, row := range result.Rows {
		if len(row) != 6 {
			return Comparison{}, ErrInvalid
		}
		for _, cell := range row {
			if cell == nil {
				return Comparison{}, ErrInvalid
			}
		}
		date := *row[0]
		if (date != firstDate && date != secondDate) || values[date].Date != "" {
			return Comparison{}, ErrInvalid
		}
		snapshot, ok := parseSnapshot(*row[1], date, profile.spec.Timezone)
		if !ok {
			return Comparison{}, ErrInvalid
		}
		counts := [3]int64{}
		for i := range counts {
			parsed, err := strconv.ParseInt(*row[i+2], 10, 64)
			if err != nil || parsed < 1 {
				return Comparison{}, ErrInvalid
			}
			counts[i] = parsed
		}
		if counts[0] != counts[1] || counts[0] != counts[2] {
			return Comparison{}, ErrInvalid
		}
		amount, scale, ok := parseDecimal(*row[5])
		if !ok {
			return Comparison{}, ErrInvalid
		}
		values[date] = DailyValue{Date: date, SnapshotAt: snapshot, ContributingRows: counts[0],
			DistinctSubjects: counts[1], NonNullCount: counts[2], Value: compactDecimal(amount, scale)}
		amounts[date], scales[date] = amount, scale
	}
	if len(values) != 2 {
		return Comparison{}, ErrInvalid
	}
	delta := new(big.Rat).Sub(amounts[firstDate], amounts[secondDate])
	deltaScale := scales[firstDate]
	if scales[secondDate] > deltaScale {
		deltaScale = scales[secondDate]
	}
	change, _ := percent(amounts[firstDate], amounts[secondDate])
	return Comparison{MetricID: profile.MetricID(), ProfileHash: profile.Hash(), Unit: profile.Unit(),
		Coverage: ObservedSnapshot, First: values[firstDate], Second: values[secondDate],
		Delta: compactDecimal(delta, deltaScale), PercentChange: change}, nil
}
