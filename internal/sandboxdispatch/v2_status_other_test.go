//go:build !linux

package sandboxdispatch

import (
	"errors"
	"testing"
)

func TestActivatedSupervisorStatusIsUnsupportedOnOtherPlatforms(t *testing.T) {
	_, err := newV2StatusWriter("/tmp/supervisor/status.json")
	if !errors.Is(err, ErrSupervisorStatusUnsupported) {
		t.Fatalf("activated status writer error = %v, want unsupported", err)
	}
}
