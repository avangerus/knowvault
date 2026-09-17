//go:build !linux

package search

import "knowvault.local/verified-workspace/internal/platform/runtimeidentity"

func openSearchMountedRootForConsumer(string, runtimeidentity.MountConsumer) (*searchMountedRoot, error) {
	return nil, &Error{code: CodeMountUnavailable}
}

func (*searchMountedRoot) read(string, int) ([]byte, error) {
	return nil, &Error{code: CodeMountUnavailable}
}

func (*searchMountedRoot) Close() error { return nil }
