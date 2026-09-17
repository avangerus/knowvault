//go:build linux

package parserv2harness

import "testing"

func TestSubmitProxyLifetimeIsOwnedByHarness(t *testing.T) {
	args := submitProxyCommandArgs()
	for _, arg := range args {
		if arg == "-test.timeout=0" {
			return
		}
	}
	t.Fatalf("submit proxy args %q restore a per-job test alarm; Harness.Close must own its lifetime", args)
}
