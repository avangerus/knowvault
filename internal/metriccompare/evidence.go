package metriccompare

import (
	"math/big"
	"regexp"

	"knowvault.local/verified-workspace/internal/source/canon"
)

const EvidenceSchemaVersion = 1

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type evidenceDay struct {
	Date             string `json:"date"`
	SnapshotAt       string `json:"snapshot_at"`
	ContributingRows int64  `json:"contributing_rows"`
	DistinctSubjects int64  `json:"distinct_subjects"`
	NonNullCount     int64  `json:"nonnull_count"`
	Value            string `json:"value"`
}

func evidenceDayFrom(value DailyValue) evidenceDay {
	return evidenceDay{value.Date, value.SnapshotAt, value.ContributingRows,
		value.DistinctSubjects, value.NonNullCount, value.Value}
}

// EvidenceDigest binds the validated comparison to the exact governed text
// table digest. The schema version describes this canonical payload, while
// the profile hash identifies the operator-approved metric configuration.
// An auditor can recompute the raw digest from the governed table, parse that
// table with the identified profile and ordered dates, then recompute this one.
func EvidenceDigest(comparison Comparison, exposedSchemaRevision int64, rawResultDigest string) (string, error) {
	if exposedSchemaRevision < 1 || comparison.MetricID == "" || comparison.Unit == "" ||
		comparison.Coverage != ObservedSnapshot || !digestPattern.MatchString(comparison.ProfileHash) ||
		!digestPattern.MatchString(rawResultDigest) || !validDate(comparison.First.Date) ||
		!validDate(comparison.Second.Date) || comparison.First.Date == comparison.Second.Date {
		return "", ErrInvalid
	}
	first, _, firstOK := parseDecimal(comparison.First.Value)
	second, _, secondOK := parseDecimal(comparison.Second.Value)
	if !firstOK || !secondOK || comparison.First.SnapshotAt == "" || comparison.Second.SnapshotAt == "" ||
		comparison.First.ContributingRows < 1 || comparison.Second.ContributingRows < 1 ||
		comparison.First.ContributingRows != comparison.First.DistinctSubjects ||
		comparison.First.ContributingRows != comparison.First.NonNullCount ||
		comparison.Second.ContributingRows != comparison.Second.DistinctSubjects ||
		comparison.Second.ContributingRows != comparison.Second.NonNullCount {
		return "", ErrInvalid
	}
	delta, _, deltaOK := parseDecimal(comparison.Delta)
	change, hasChange := percent(first, second)
	if !deltaOK || delta.Cmp(new(big.Rat).Sub(first, second)) != 0 ||
		(hasChange && comparison.PercentChange != change) || (!hasChange && comparison.PercentChange != "") {
		return "", ErrInvalid
	}
	payload := struct {
		SchemaVersion         int         `json:"schema_version"`
		MetricID              string      `json:"metric_id"`
		ProfileHash           string      `json:"profile_hash"`
		ExposedSchemaRevision int64       `json:"exposed_schema_revision"`
		Unit                  string      `json:"unit"`
		Coverage              string      `json:"coverage"`
		First                 evidenceDay `json:"first"`
		Second                evidenceDay `json:"second"`
		Delta                 string      `json:"delta"`
		PercentChange         string      `json:"percent_change"`
		RawResultDigest       string      `json:"raw_result_digest"`
	}{EvidenceSchemaVersion, comparison.MetricID, comparison.ProfileHash, exposedSchemaRevision,
		comparison.Unit, comparison.Coverage, evidenceDayFrom(comparison.First), evidenceDayFrom(comparison.Second),
		comparison.Delta, comparison.PercentChange, rawResultDigest}
	canonical, err := canon.CanonicalJSON(payload)
	if err != nil {
		return "", ErrInvalid
	}
	return canon.Hash(canonical), nil
}
