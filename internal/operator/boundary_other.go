//go:build !linux

package operator

import "errors"

// verifyMountBoundary fails closed on hosts where the root-owned mount
// boundary cannot be proven: generation refuses to write rather than
// claiming a verified mount without the verification platform.
func verifyMountBoundary(mountRoot string) error {
	return errors.New("mount boundary verification is unavailable on this platform")
}
