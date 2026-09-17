//go:build !linux

package secretmount

import "knowvault.local/verified-workspace/internal/platform/runtimeidentity"

// Mounted secrets intentionally have no permissive fallback on unsupported
// platforms. Production composition must fail at startup instead.
func openMountedRootForConsumer(string, runtimeidentity.MountConsumer) (*mountedRoot, error) {
	return nil, &Error{code: CodeUnavailable}
}

func (root *mountedRoot) read(string, int) ([]byte, error) {
	return nil, &Error{code: CodeUnavailable}
}

func (root *mountedRoot) Close() error { return nil }
