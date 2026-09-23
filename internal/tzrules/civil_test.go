package tzrules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustParseUTC(t *testing.T, text string) time.Time {
	t.Helper()
	instant, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	return instant
}

// TestResolveCivilUniqueInstants pins unique resolution, canonical nanoseconds,
// and deterministic repetition across UTC, a fixed-offset zone, both 2026 New
// York transitions, both 2026 Lord Howe half-hour transitions, and the skipped
// Samoa day, always asserting the exact UTC instant.
func TestResolveCivilUniqueInstants(t *testing.T) {
	cases := []struct{ zone, wall, want string }{
		{"UTC", "2026-03-08T02:30:00", "2026-03-08T02:30:00Z"},
		{"UTC", "2026-06-15T12:34:56.123456789", "2026-06-15T12:34:56.123456789Z"},
		{"UTC", "0001-01-01T00:00:00", "0001-01-01T00:00:00Z"},
		{"UTC", "9999-12-31T23:59:59.999999999", "9999-12-31T23:59:59.999999999Z"},
		{"Europe/Moscow", "2026-03-08T02:30:00", "2026-03-07T23:30:00Z"},
		{"Europe/Moscow", "2026-06-15T12:34:56.123456789", "2026-06-15T09:34:56.123456789Z"},
		{"America/New_York", "2026-03-08T01:59:59", "2026-03-08T06:59:59Z"},
		{"America/New_York", "2026-03-08T03:00:00", "2026-03-08T07:00:00Z"},
		{"America/New_York", "2026-11-01T00:59:59", "2026-11-01T04:59:59Z"},
		{"America/New_York", "2026-11-01T02:00:00", "2026-11-01T07:00:00Z"},
		{"Australia/Lord_Howe", "2026-10-04T01:59:59", "2026-10-03T15:29:59Z"},
		{"Australia/Lord_Howe", "2026-10-04T02:30:00", "2026-10-03T15:30:00Z"},
		{"Australia/Lord_Howe", "2026-04-05T01:29:59", "2026-04-04T14:29:59Z"},
		{"Australia/Lord_Howe", "2026-04-05T02:00:00", "2026-04-04T15:30:00Z"},
		{"Pacific/Apia", "2011-12-29T12:00:00", "2011-12-29T22:00:00Z"},
		{"Pacific/Apia", "2011-12-31T12:00:00", "2011-12-30T22:00:00Z"},
	}
	for _, testCase := range cases {
		want := mustParseUTC(t, testCase.want)
		for repeat := 0; repeat < 2; repeat++ {
			got, err := ResolveCivil(testCase.zone, testCase.wall)
			if err != nil || !got.Equal(want) {
				t.Fatalf("ResolveCivil(%q, %q) = %v, %v; want %v, nil", testCase.zone, testCase.wall, got, err, want)
			}
			if got.Location() != time.UTC {
				t.Fatalf("ResolveCivil(%q, %q) location = %v, want UTC", testCase.zone, testCase.wall, got.Location())
			}
		}
	}
}

func TestResolveCivilNewYorkYearBoundaries(t *testing.T) {
	cases := []struct{ wall, want string }{
		{"2008-12-31T12:00:00", "2008-12-31T17:00:00Z"},
		{"2009-01-01T12:00:00", "2009-01-01T17:00:00Z"},
		{"2099-12-31T12:00:00", "2099-12-31T17:00:00Z"},
		{"2100-01-01T12:00:00", "2100-01-01T17:00:00Z"},
		{"2399-12-31T12:00:00", "2399-12-31T17:00:00Z"},
		{"2400-01-01T12:00:00", "2400-01-01T17:00:00Z"},
	}
	for _, testCase := range cases {
		want := mustParseUTC(t, testCase.want)
		got, err := ResolveCivil("America/New_York", testCase.wall)
		if err != nil || !got.Equal(want) {
			t.Fatalf("ResolveCivil(America/New_York, %q) = %v, %v; want %v, nil", testCase.wall, got, err, want)
		}
	}
}

// TestResolveCivilMappingCounts proves the private mapping count is zero for a
// gap, one for a unique wall, and two for a fold, and that the public API
// returns an instant only for the count of one.
func TestResolveCivilMappingCounts(t *testing.T) {
	cases := []struct {
		zone  string
		wall  string
		count int
	}{
		{"UTC", "2026-03-08T02:30:00", 1},
		{"Europe/Moscow", "2026-03-08T02:30:00", 1},
		{"America/New_York", "2026-03-08T02:30:00", 0},
		{"America/New_York", "2026-11-01T01:30:00", 2},
		{"Australia/Lord_Howe", "2026-10-04T02:15:00", 0},
		{"Australia/Lord_Howe", "2026-04-05T01:45:00", 2},
		{"Pacific/Apia", "2011-12-30T12:00:00", 0},
	}
	for _, testCase := range cases {
		instant, count, err := resolveCivil(testCase.zone, testCase.wall, maxCivilIntervals)
		if err != nil || count != testCase.count {
			t.Fatalf("resolveCivil(%q, %q) count = %d, %v; want %d, nil", testCase.zone, testCase.wall, count, err, testCase.count)
		}
		got, publicErr := ResolveCivil(testCase.zone, testCase.wall)
		if testCase.count == 1 {
			if publicErr != nil || !got.Equal(instant) {
				t.Fatalf("ResolveCivil(%q, %q) = %v, %v; want %v, nil", testCase.zone, testCase.wall, got, publicErr, instant)
			}
			continue
		}
		if !instant.IsZero() || publicErr != errUnavailable || !got.IsZero() {
			t.Fatalf("ambiguous %q %q = %v, %d, %v and %v, %v; want zero, %v", testCase.zone, testCase.wall, instant, count, err, got, publicErr, errUnavailable)
		}
	}
}

// TestResolveCivilMalformedWalls rejects every non-canonical spelling: bad
// separators and widths, impossible dates and clocks, leap seconds, offsets and
// Z, year zero, year 10000, signed or padded years, and non-canonical fractions.
func TestResolveCivilMalformedWalls(t *testing.T) {
	walls := []string{
		"", "2026-03-08", "20260308T023000", "2026-03-08T02:30", "2026-03-08T02:30:0",
		"2026-03-08 02:30:00", "2026-03-08t02:30:00", "2026-3-08T02:30:00", "2026-03-8T02:30:00",
		"2026-03-08T2:30:00", "2026-03-08T02:3:00", "+2026-03-08T02:30:00", "-001-01-01T00:00:00",
		"2026-02-29T00:00:00", "2026-04-31T00:00:00", "2026-13-01T00:00:00", "2026-00-10T00:00:00",
		"2026-01-00T00:00:00", "2026-03-08T24:00:00", "2026-03-08T02:60:00", "2026-03-08T02:30:60",
		"2026-03-08T02:30:00Z", "2026-03-08T02:30:00+03:00", "2026-03-08T02:30:00.5Z",
		"2026-03-08T02:30:00.", "2026-03-08T02:30:00.0", "2026-03-08T02:30:00.50",
		"2026-03-08T02:30:00.000000000", "2026-03-08T02:30:00.1234567890", "2026-03-08T02:30:00.123456789x",
		"0000-01-01T00:00:00", "0000-12-31T23:59:59.999999999", "10000-01-01T00:00:00",
	}
	for _, wall := range walls {
		instant, err := ResolveCivil("UTC", wall)
		if err != errUnavailable || !instant.IsZero() {
			t.Fatalf("ResolveCivil(UTC, %q) = %v, %v; want zero, %v", wall, instant, err, errUnavailable)
		}
	}
}

// TestResolveCivilRejectedZones rejects host-specific shorthands, the reserved
// Local name, and unknown members without echoing the name.
func TestResolveCivilRejectedZones(t *testing.T) {
	zones := []string{"", "Local", "CET", "EST", "UTCx", "Etc/UTC", "Etc/GMT+5", "Europe/Nowhere", "America/New_York "}
	for _, zone := range zones {
		instant, err := ResolveCivil(zone, "2026-06-15T12:00:00")
		if err != errUnavailable || !instant.IsZero() {
			t.Fatalf("ResolveCivil(%q, wall) = %v, %v; want zero, %v", zone, instant, err, errUnavailable)
		}
	}
}

// TestResolveCivilIgnoresHostZoneDatabase proves resolution ignores a poisoned
// TZ and ZONEINFO tree and still reads only the embedded verified archive.
func TestResolveCivilIgnoresHostZoneDatabase(t *testing.T) {
	directory := t.TempDir()
	poison := filepath.Join(directory, "Europe", "Moscow")
	if err := os.MkdirAll(filepath.Dir(poison), 0o755); err != nil {
		t.Fatalf("create zone directory: %v", err)
	}
	if err := os.WriteFile(poison, []byte("not a TZif file"), 0o644); err != nil {
		t.Fatalf("write poison zone: %v", err)
	}
	t.Setenv("TZ", "Pacific/Kiritimati")
	t.Setenv("ZONEINFO", directory)
	got, err := ResolveCivil("Europe/Moscow", "2026-06-15T12:34:56.123456789")
	if want := time.Date(2026, 6, 15, 9, 34, 56, 123456789, time.UTC); err != nil || !got.Equal(want) {
		t.Fatalf("poisoned host database = %v, %v; want %v, nil", got, err, want)
	}
}

// TestResolveCivilYearRange rejects candidates whose UTC year leaves 1..9999
// while the boundary instants inside that range still resolve.
func TestResolveCivilYearRange(t *testing.T) {
	if instant, err := ResolveCivil("Europe/Moscow", "0001-01-01T00:00:00"); err != errUnavailable || !instant.IsZero() {
		t.Fatalf("candidate underflow = %v, %v; want zero, %v", instant, err, errUnavailable)
	}
	if instant, err := ResolveCivil("America/New_York", "9999-12-31T23:59:59"); err != errUnavailable || !instant.IsZero() {
		t.Fatalf("candidate overflow = %v, %v; want zero, %v", instant, err, errUnavailable)
	}
	first, firstErr := ResolveCivil("UTC", "0001-01-01T00:00:00")
	if want := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC); firstErr != nil || !first.Equal(want) {
		t.Fatalf("first instant = %v, %v; want %v, nil", first, firstErr, want)
	}
	last, lastErr := ResolveCivil("UTC", "9999-12-31T23:59:59.999999999")
	if want := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC); lastErr != nil || !last.Equal(want) {
		t.Fatalf("last instant = %v, %v; want %v, nil", last, lastErr, want)
	}
}

// TestResolveCivilIntervalBudget proves an exhausted interval budget fails
// closed while the public 4096 budget resolves the same wall.
func TestResolveCivilIntervalBudget(t *testing.T) {
	const wall = "2026-06-15T12:34:56"
	instant, count, err := resolveCivil("America/New_York", wall, 1)
	if err != errUnavailable || count != 0 || !instant.IsZero() {
		t.Fatalf("exhausted budget = %v, %d, %v; want zero, 0, %v", instant, count, err, errUnavailable)
	}
	instant, count, err = resolveCivil("America/New_York", wall, maxCivilIntervals)
	if err != nil || count != 1 {
		t.Fatalf("full budget = %v, %d, %v; want one unique instant", instant, count, err)
	}
	if got, publicErr := ResolveCivil("America/New_York", wall); publicErr != nil || !got.Equal(instant) {
		t.Fatalf("public resolver = %v, %v; want %v, nil", got, publicErr, instant)
	}
}
