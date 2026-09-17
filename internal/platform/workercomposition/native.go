package workercomposition

import (
	"context"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/source/dispatchparser"
)

const NativeProfileRevision = dispatchparser.SandboxProfileRevision
const canonicalNativeSubmitSocket = "/run/knowvault/sandbox/submit/dispatcher.sock"

// CheckNativeReadiness is the worker's content-free native probe. It does not
// open database, source or secret mounts; configured-but-unavailable and
// disabled are both explicit non-ready results.
func CheckNativeReadiness(ctx context.Context, config Config) error {
	if !validConfig(config) {
		return workerError(CodeConfigInvalid)
	}
	if !config.NativeEnabled() {
		return workerError(CodeNativeDisabled)
	}
	if dispatchparser.CheckProductionReadiness(ctx, canonicalNativeSubmitSocket) != nil {
		return workerError(CodeNativeNotReady)
	}
	return nil
}

func nativeExtractors(config Config) (ingestion.OfficeExtractor, ingestion.PDFExtractor, error) {
	if !config.NativeEnabled() {
		return nil, nil, nil
	}
	return dispatchparser.NewProduction(canonicalNativeSubmitSocket)
}
