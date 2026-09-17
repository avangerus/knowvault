//go:build !linux

package trustbundle

import "knowvault.local/verified-workspace/internal/platform/runtimeidentity"

func openMountedRootForConsumer(string, runtimeidentity.MountConsumer) (*mountedRoot, error) {
	return nil, &Error{code: CodeUnavailable}
}
func (*mountedRoot) read(string, int) ([]byte, error) { return nil, &Error{code: CodeUnavailable} }
func (*mountedRoot) Close() error                     { return nil }
