package tzrules

import (
	"slices"
	"time"
)

// civilLayout is the canonical offset-free wall grammar; maxCivilIntervals
// bounds the public interval walk; civilSpan is the widest TZif signed int32
// UTC offset magnitude in seconds, so the walk reaches every candidate instant.
const (
	civilLayout       = "2006-01-02T15:04:05.999999999"
	maxCivilIntervals = 4096
	civilSpan         = 1 << 31
)

// ResolveCivil returns the single unique UTC instant whose civil text in
// zoneName is exactly canonicalWall. Malformed walls, unavailable zones, gaps,
// folds, out-of-range instants, anomalies, and exhausted budgets all return the
// zero time and errUnavailable, exposing no zone detail.
func ResolveCivil(zoneName, canonicalWall string) (time.Time, error) {
	instant, matches, err := resolveCivil(zoneName, canonicalWall, maxCivilIntervals)
	if err != nil || matches != 1 {
		return time.Time{}, errUnavailable
	}
	return instant, nil
}

// resolveCivil returns the instant canonicalWall maps to in zoneName (zero
// unless exactly one instant maps) and how many distinct instants map to it.
func resolveCivil(zoneName, canonicalWall string, limit int) (time.Time, int, error) {
	naive, ok := parseCivilWall(canonicalWall)
	if !ok {
		return time.Time{}, 0, errUnavailable
	}
	location, err := Load(zoneName)
	if err != nil {
		return time.Time{}, 0, errUnavailable
	}
	offsets, err := civilOffsets(location, naive, limit)
	if err != nil {
		return time.Time{}, 0, errUnavailable
	}
	var instant time.Time
	matches := 0
	for _, offset := range offsets {
		candidate := naive.Add(-time.Duration(offset) * time.Second)
		if year := candidate.Year(); year < 1 || year > 9999 {
			continue
		}
		// A candidate counts only when the zone's real offset at that instant
		// is offset and every local civil field and nanosecond renders exactly
		// like the requested wall. Unique offsets keep the instants distinct.
		local := candidate.In(location)
		if _, actual := local.Zone(); actual != offset || local.Format(civilLayout) != canonicalWall {
			continue
		}
		instant, matches = candidate, matches+1
	}
	if matches != 1 {
		return time.Time{}, matches, nil
	}
	return instant, 1, nil
}

// parseCivilWall parses exactly the canonical wall grammar into a naive UTC
// instant, rejecting year zero and every spelling that does not round-trip.
func parseCivilWall(text string) (time.Time, bool) {
	naive, err := time.Parse(civilLayout, text)
	if err != nil || naive.Year() == 0 || naive.Format(civilLayout) != text {
		return time.Time{}, false
	}
	return naive, true
}

// civilOffsets walks every zone interval of location that covers the naive
// instant plus or minus the widest int32 offset, returning the unique offsets
// in reverse walk order. It fails closed on an invalid offset, non-advancing
// bound, or exhausted budget.
func civilOffsets(location *time.Location, naive time.Time, limit int) ([]int, error) {
	low := naive.Add(-civilSpan * time.Second)
	high := naive.Add(civilSpan * time.Second).Add(time.Second)
	offsets := make([]int, 0, 8)
	cursor := high.Add(-time.Nanosecond).In(location)
	for intervals := 0; ; intervals++ {
		if intervals >= limit {
			return nil, errUnavailable
		}
		_, offset := cursor.Zone()
		if int64(offset) < -civilSpan || int64(offset) > civilSpan-1 {
			return nil, errUnavailable
		}
		if !slices.Contains(offsets, offset) {
			offsets = append(offsets, offset)
		}
		start, _ := cursor.ZoneBounds()
		if !start.IsZero() && start.After(cursor) {
			return nil, errUnavailable
		}
		yearStart := time.Date(cursor.UTC().Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		boundary := yearStart
		if !start.IsZero() && start.After(boundary) {
			boundary = start
		}
		if !boundary.After(low) {
			return offsets, nil
		}
		next := boundary.Add(-time.Nanosecond)
		if !next.Before(cursor) {
			return nil, errUnavailable
		}
		cursor = next.In(location)
	}
}
