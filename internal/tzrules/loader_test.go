package tzrules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBundleAssetFacts(t *testing.T) {
	raw, err := os.ReadFile("zoneinfo.zip")
	if err != nil {
		t.Fatalf("read embedded asset: %v", err)
	}
	if len(raw) != bundleSize {
		t.Fatalf("asset size = %d, want %d", len(raw), bundleSize)
	}
	sum := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != BundleSHA256 {
		t.Fatalf("asset digest = %s, want %s", got, BundleSHA256)
	}
	const frozen = "sha256:8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8"
	if BundleSHA256 != frozen {
		t.Fatalf("BundleSHA256 = %q, want %q", BundleSHA256, frozen)
	}
	if !bytes.Equal(raw, bundle) {
		t.Fatal("embedded bundle differs byte-for-byte from zoneinfo.zip")
	}
}

func TestLoadUTC(t *testing.T) {
	location, err := Load("UTC")
	if err != nil {
		t.Fatalf("Load(UTC) error = %v", err)
	}
	if location != time.UTC {
		t.Fatalf("Load(UTC) = %v, want time.UTC", location)
	}
}

func TestLoadKnownZones(t *testing.T) {
	cases := []struct {
		name string
		at   string
		want string
	}{
		{"Europe/Moscow", "2024-01-15T09:00:00Z", "2024-01-15T12:00:00+03:00"},
		{"Europe/Moscow", "2024-07-15T09:00:00Z", "2024-07-15T12:00:00+03:00"},
		{"America/New_York", "2024-01-15T09:00:00Z", "2024-01-15T04:00:00-05:00"},
		{"America/New_York", "2024-07-15T09:00:00Z", "2024-07-15T05:00:00-04:00"},
	}
	for _, testCase := range cases {
		location, err := Load(testCase.name)
		if err != nil {
			t.Fatalf("Load(%q) error = %v", testCase.name, err)
		}
		if location.String() != testCase.name {
			t.Fatalf("Load(%q).String() = %q", testCase.name, location.String())
		}
		instant, err := time.Parse(time.RFC3339, testCase.at)
		if err != nil {
			t.Fatalf("parse %q: %v", testCase.at, err)
		}
		if got := instant.In(location).Format(time.RFC3339); got != testCase.want {
			t.Fatalf("%s at %s = %s, want %s", testCase.name, testCase.at, got, testCase.want)
		}
	}
}

func TestLoadRejectsNames(t *testing.T) {
	names := []string{
		"", "Local", "localtime", "posixrules", "UTCx", "CET", "EST", "GMT", "Etc/UTC", "Etc/GMT+5",
		"posix/America/New_York", "right/America/New_York", "US/Eastern", "Brazil/East",
		"Europe/", "Europe//Moscow", "/Europe/Moscow", "Europe/Moscow/", "Europe/./Moscow",
		"Europe/../Moscow", `Europe\Moscow`, "Europe/Moscow ", "Europe/Moskva\r",
		"Europe/München", "Moscow", "europe/moscow", "Europe/Nowhere",
		"America/Not_A_Zone", "America/" + strings.Repeat("X", 56), "America/" + strings.Repeat("X", 60),
	}
	for _, name := range names {
		location, err := Load(name)
		if err != errUnavailable {
			t.Fatalf("Load(%q) error = %v, want %v", name, err, errUnavailable)
		}
		if location != nil {
			t.Fatalf("Load(%q) location = %v, want nil", name, location)
		}
		if name != "" && strings.Contains(err.Error(), name) {
			t.Fatalf("Load(%q) error echoes the name: %q", name, err)
		}
		if err.Error() != errUnavailable.Error() {
			t.Fatalf("Load(%q) error text = %q", name, err.Error())
		}
	}
}

func TestLoadIgnoresHostZoneDatabase(t *testing.T) {
	directory := t.TempDir()
	poison := filepath.Join(directory, "Europe", "Moscow")
	if err := os.MkdirAll(filepath.Dir(poison), 0o755); err != nil {
		t.Fatalf("create zone directory: %v", err)
	}
	if err := os.WriteFile(poison, []byte("not a TZif file"), 0o644); err != nil {
		t.Fatalf("write poison zone: %v", err)
	}
	t.Setenv("TZ", "America/Los_Angeles")
	t.Setenv("ZONEINFO", directory)
	location, err := Load("Europe/Moscow")
	if err != nil {
		t.Fatalf("Load(Europe/Moscow) error = %v", err)
	}
	instant := time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC)
	if got := instant.In(location).Format(time.RFC3339); got != "2024-01-15T12:00:00+03:00" {
		t.Fatalf("Europe/Moscow at %s = %s", instant, got)
	}
	if utc, err := Load("UTC"); err != nil || utc != time.UTC {
		t.Fatalf("Load(UTC) = %v, %v; want time.UTC, nil", utc, err)
	}
}

func TestConcurrentLoads(t *testing.T) {
	expected := map[string]string{
		"Europe/Moscow":    "2024-01-15T12:00:00+03:00",
		"America/New_York": "2024-01-15T04:00:00-05:00",
		"Asia/Tokyo":       "2024-01-15T18:00:00+09:00",
	}
	instant := time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC)
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for round := 0; round < 16; round++ {
				if utc, err := Load("UTC"); err != nil || utc != time.UTC {
					t.Errorf("Load(UTC) = %v, %v; want time.UTC, nil", utc, err)
				}
				for name, want := range expected {
					location, err := Load(name)
					if err != nil {
						t.Errorf("Load(%q) error = %v", name, err)
						continue
					}
					if got := instant.In(location).Format(time.RFC3339); got != want {
						t.Errorf("%s at %s = %s, want %s", name, instant, got, want)
					}
				}
				if location, err := Load("Europe/Nowhere"); err != errUnavailable || location != nil {
					t.Errorf("Load(Europe/Nowhere) = %v, %v; want nil, %v", location, err, errUnavailable)
				}
			}
		}()
	}
	wait.Wait()
}
