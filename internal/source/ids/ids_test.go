package ids

import (
	"regexp"
	"testing"
	"time"
)

var schemaPattern = regexp.MustCompile(`^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func TestNewMatchesSchemaPatternAndIsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 2000; i++ {
		id, err := New("object")
		if err != nil {
			t.Fatal(err)
		}
		if !schemaPattern.MatchString(id) {
			t.Fatalf("id %q does not match the schema pattern", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestNewRejectsInvalidPrefix(t *testing.T) {
	for _, p := range []string{"", "A", "x", "Object", "with_underscore", "waytoolongprefixxx"} {
		if _, err := New(p); err == nil {
			t.Fatalf("prefix %q unexpectedly accepted", p)
		}
	}
}

func TestEncodeFirstCharStaysInRange(t *testing.T) {
	// Even at the far-future max 48-bit millisecond timestamp the first ULID
	// character must remain in [0-7].
	id, err := newAt("version", time.UnixMilli((1<<48)-1))
	if err != nil {
		t.Fatal(err)
	}
	if !schemaPattern.MatchString(id) {
		t.Fatalf("max-timestamp id %q violates the schema pattern", id)
	}
}
