package main

import (
	"context"
	"log/slog"
	"os"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/lifecycle"
)

func main() {
	ctx, stop := lifecycle.SignalContext(context.Background())
	defer stop()

	info := buildinfo.Current()
	slog.Info("component scaffold started", "component", "knowvault-connector", "version", info.Version, "revision", info.Revision)
	if err := lifecycle.Wait(ctx); err != nil {
		slog.Error("component scaffold stopped with error", "component", "knowvault-connector", "error_code", "LIFECYCLE_WAIT_FAILED")
		os.Exit(1)
	}
}
