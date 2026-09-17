package purgercomposition

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
)

func TestRuntimeRejectsInvalidStartupInputs(t *testing.T) {
	if _, err := NewProduction(nil, Config{}, buildinfo.Info{}); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("nil context returned %v", err)
	}
	if _, err := NewProduction(context.Background(), Config{}, buildinfo.Info{}); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("invalid config returned %v", err)
	}
}
