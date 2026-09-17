//go:build !linux

package embedding

import "knowvault.local/verified-workspace/internal/platform/runtimeidentity"

func openEmbeddingMountedRootForConsumer(string, runtimeidentity.MountConsumer) (*embeddingMountedRoot, error) {
	return nil, &Error{code: CodeMountUnavailable}
}

func (*embeddingMountedRoot) read(string, int) ([]byte, error) {
	return nil, &Error{code: CodeMountUnavailable}
}

func (*embeddingMountedRoot) Close() error { return nil }
