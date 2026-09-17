package buildinfo

import "testing"

func TestNewInfoPreservesExactBuildValues(t *testing.T) {
	t.Parallel()

	got := newInfo("1.2.3", "abc123", "2026-07-14T12:00:00Z", "go1.26.5", "jsonv2")
	if got.Version != "1.2.3" || got.Revision != "abc123" || got.BuiltAt != "2026-07-14T12:00:00Z" {
		t.Fatalf("build identity changed: %#v", got)
	}
	if got.GoVersion != "go1.26.5" || got.GoExperiment != "jsonv2" {
		t.Fatalf("toolchain identity changed: %#v", got)
	}
}

func TestNewInfoFailsSafeToVisibleUnknownValues(t *testing.T) {
	t.Parallel()

	got := newInfo("", "", "", "", "")
	if got.Version != "dev" {
		t.Fatalf("empty version must be visible as dev, got %q", got.Version)
	}
	for name, value := range map[string]string{
		"revision": got.Revision, "built_at": got.BuiltAt,
		"go_version": got.GoVersion, "go_experiment": got.GoExperiment,
	} {
		if value != "unknown" {
			t.Fatalf("empty %s must be visible as unknown, got %q", name, value)
		}
	}
}

func TestCurrentIsAlwaysPopulated(t *testing.T) {
	t.Parallel()

	got := Current()
	if got.Version == "" || got.Revision == "" || got.BuiltAt == "" || got.GoVersion == "" || got.GoExperiment == "" {
		t.Fatalf("current build info contains an ambiguous empty field: %#v", got)
	}
}
