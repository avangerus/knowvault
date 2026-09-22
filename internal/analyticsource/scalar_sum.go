package analyticsource

import (
	"bytes"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// scalarSum is the private, deterministic proof that one already-authorized
// bounded snapshot reduces to exactly one scalar SUM: the canonical decimal
// value, the actual number of contributing rows and the validated snapshot
// hash. Every field is unexported and there is deliberately no accessor, no
// JSON method and no String/GoString, so a caller can observe only the generic
// zero comparison and nothing here reports covered subjects, a receipt, SQL or
// an authority fact.
type scalarSum struct {
	value            string
	contributingRows int64
	snapshotHash     string
}

var (
	scalarSumHashPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	scalarSumIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	scalarSumNumericPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
)

// reduceScalarSum re-proves one ScalarRead from its own bytes and sums the
// selected measure column with exact integer arithmetic. It trusts nothing the
// executor already checked: the mapping ordinals, the snapshot completeness,
// count, decoded size and hash, every retained row's canonical bytes and hash,
// every row's unique positive ordinals, the presence of the selected measure and
// identity entries, non-NULL identity values, a duplicate-free composite grain,
// a consistent measure type and a consistent NUMERIC scale are all validated
// before any result is published.
//
// The sum is accumulated as a math/big integer coefficient at one decimal
// scale, never as a float, and emitted as a plain canonical decimal with no
// exponent or leading zeroes, trimmed fractional trailing zeroes and zero
// normalized to "0". Every refusal returns the exact zero scalarSum and the
// exact unwrapped errMismatch, and no caller-owned row or value is mutated.
func reduceScalarSum(read ScalarRead) (scalarSum, error) {
	if read.measureOrdinal <= 0 || len(read.identityOrdinals) == 0 {
		return scalarSum{}, errMismatch
	}
	identityOrdinals := make(map[int]struct{}, len(read.identityOrdinals))
	for _, ordinal := range read.identityOrdinals {
		if ordinal <= 0 || ordinal == read.measureOrdinal {
			return scalarSum{}, errMismatch
		}
		if _, duplicate := identityOrdinals[ordinal]; duplicate {
			return scalarSum{}, errMismatch
		}
		identityOrdinals[ordinal] = struct{}{}
	}

	snapshot := read.snapshot
	if !snapshot.CoverageComplete || snapshot.RowCount <= 0 || len(snapshot.Rows) == 0 ||
		snapshot.RowCount != len(snapshot.Rows) {
		return scalarSum{}, errMismatch
	}
	decodedBytes := 0
	for _, row := range snapshot.Rows {
		if len(row.Canonical) == 0 || row.Hash == "" {
			return scalarSum{}, errMismatch
		}
		decodedBytes += len(row.Canonical)
	}
	if decodedBytes != snapshot.DecodedBytes || !scalarSumHashPattern.MatchString(snapshot.SnapshotHash) {
		return scalarSum{}, errMismatch
	}
	recomputed, err := postgresqlquery.SnapshotSetHash(snapshot.Rows)
	if err != nil || recomputed != snapshot.SnapshotHash {
		return scalarSum{}, errMismatch
	}

	sum := new(big.Int)
	scale := -1
	var measureType postgresqlquery.LogicalType
	var measureTag, measureFingerprint string
	measureSeen := false
	grainSeen := make(map[string]struct{}, len(snapshot.Rows))

	for _, row := range snapshot.Rows {
		canonical, err := canon.CanonicalJSON(row.Values)
		if err != nil || !bytes.Equal(canonical, row.Canonical) || canon.Hash(canonical) != row.Hash {
			return scalarSum{}, errMismatch
		}
		seenOrdinals := make(map[int]struct{}, len(row.Values))
		measureEntry := postgresqlquery.ValueEntry{}
		measureFound := false
		identityEntries := make([]postgresqlquery.ValueEntry, 0, len(identityOrdinals))
		for _, entry := range row.Values {
			if entry.Ordinal <= 0 {
				return scalarSum{}, errMismatch
			}
			if _, duplicate := seenOrdinals[entry.Ordinal]; duplicate {
				return scalarSum{}, errMismatch
			}
			seenOrdinals[entry.Ordinal] = struct{}{}
			if entry.Ordinal == read.measureOrdinal {
				measureEntry, measureFound = entry, true
			}
			if _, selected := identityOrdinals[entry.Ordinal]; selected {
				identityEntries = append(identityEntries, entry)
			}
		}
		if !measureFound || len(identityEntries) != len(identityOrdinals) {
			return scalarSum{}, errMismatch
		}
		for _, entry := range identityEntries {
			if entry.ValueTag == "NULL" {
				return scalarSum{}, errMismatch
			}
		}
		sort.Slice(identityEntries, func(i, j int) bool {
			return identityEntries[i].Ordinal < identityEntries[j].Ordinal
		})
		grain, err := canon.CanonicalJSON(identityEntries)
		if err != nil {
			return scalarSum{}, errMismatch
		}
		if _, duplicate := grainSeen[string(grain)]; duplicate {
			return scalarSum{}, errMismatch
		}
		grainSeen[string(grain)] = struct{}{}

		if measureEntry.ValueTag == "NULL" {
			return scalarSum{}, errMismatch
		}
		text, ok := measureEntry.Value.(string)
		if !ok {
			return scalarSum{}, errMismatch
		}
		var coefficient *big.Int
		var rowScale int
		switch {
		case measureEntry.LogicalType == postgresqlquery.TypeInt && measureEntry.ValueTag == "INT" &&
			scalarSumIntegerPattern.MatchString(text) && text != "-0":
			coefficient, ok = new(big.Int).SetString(text, 10)
			if !ok {
				return scalarSum{}, errMismatch
			}
			rowScale = 0
		case measureEntry.LogicalType == postgresqlquery.TypeNumeric && measureEntry.ValueTag == "NUMERIC" &&
			scalarSumNumericPattern.MatchString(text):
			coefficient, rowScale, ok = scalarSumNumericCoefficient(text)
			if !ok {
				return scalarSum{}, errMismatch
			}
		default:
			return scalarSum{}, errMismatch
		}
		if measureSeen {
			if measureEntry.LogicalType != measureType || measureEntry.ValueTag != measureTag ||
				measureEntry.TypeFingerprint != measureFingerprint || rowScale != scale {
				return scalarSum{}, errMismatch
			}
		} else {
			measureType = measureEntry.LogicalType
			measureTag = measureEntry.ValueTag
			measureFingerprint = measureEntry.TypeFingerprint
			measureSeen = true
			scale = rowScale
		}
		sum.Add(sum, coefficient)
	}

	return scalarSum{
		value:            scalarSumDecimal(sum, scale),
		contributingRows: int64(len(snapshot.Rows)),
		snapshotHash:     snapshot.SnapshotHash,
	}, nil
}

// scalarSumNumericCoefficient splits one canonical NUMERIC string into its
// integer coefficient and its decimal scale. The scale is the exact number of
// canonical fractional digits, so one column's values can be proven scale
// consistent before any addition. A negative zero is refused because it is not
// a canonical NUMERIC.
func scalarSumNumericCoefficient(text string) (*big.Int, int, bool) {
	unsigned := strings.TrimPrefix(text, "-")
	digits := unsigned
	scale := 0
	if dot := strings.IndexByte(unsigned, '.'); dot >= 0 {
		scale = len(unsigned) - dot - 1
		digits = unsigned[:dot] + unsigned[dot+1:]
	}
	coefficient, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, 0, false
	}
	if strings.HasPrefix(text, "-") {
		if coefficient.Sign() == 0 {
			return nil, 0, false
		}
		coefficient.Neg(coefficient)
	}
	return coefficient, scale, true
}

// scalarSumDecimal renders one integer coefficient at one decimal scale as a
// plain canonical decimal: no exponent, no leading zeroes, fractional trailing
// zeroes trimmed and zero normalized to "0".
func scalarSumDecimal(coefficient *big.Int, scale int) string {
	if coefficient == nil || coefficient.Sign() == 0 {
		return "0"
	}
	negative := coefficient.Sign() < 0
	digits := new(big.Int).Abs(coefficient).String()
	if scale > 0 {
		if len(digits) <= scale {
			digits = strings.Repeat("0", scale-len(digits)+1) + digits
		}
		integerPart := digits[:len(digits)-scale]
		fraction := strings.TrimRight(digits[len(digits)-scale:], "0")
		if fraction == "" {
			digits = integerPart
		} else {
			digits = integerPart + "." + fraction
		}
	}
	if negative {
		return "-" + digits
	}
	return digits
}
