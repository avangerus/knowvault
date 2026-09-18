//go:build !linux

package reranking

import "knowvault.local/verified-workspace/internal/platform/runtimeidentity"

func openRerankingMountedRootForConsumer(string, runtimeidentity.MountConsumer) (*rerankingMountedRoot, error) {
	return nil, &Error{code: CodeMountUnavailable}
}

func (*rerankingMountedRoot) read(string, int) ([]byte, error) {
	return nil, &Error{code: CodeMountUnavailable}
}

func (*rerankingMountedRoot) Close() error { return nil }
