// Command dispatcher is the production per-object sandbox broker (ADR-0068):
// the fourth allowed binary at the orchestration boundary. It leases one
// document at a time to a registered parser worker over a unix socket and never
// creates a container or invokes a container runtime.
package main

import (
	"context"
	"log/slog"
	"os"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/dispatchercomposition"
	"knowvault.local/verified-workspace/internal/platform/lifecycle"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := lifecycle.SignalContext(context.Background())
	defer stop()

	info := buildinfo.Current()
	config, err := dispatchercomposition.LoadProduction()
	if err != nil {
		slog.Error("component configuration rejected", "component", "knowvault-sandbox-dispatcher", "error_code", dispatchercomposition.CodeOf(err))
		return 1
	}

	runtime, err := dispatchercomposition.NewProduction(config)
	if err != nil {
		slog.Error("component startup rejected", "component", "knowvault-sandbox-dispatcher", "error_code", dispatchercomposition.CodeOf(err))
		return 1
	}
	defer runtime.Close()

	slog.Info("component starting", "component", "knowvault-sandbox-dispatcher", "version", info.Version, "revision", info.Revision)
	if err := runtime.Run(ctx); err != nil {
		slog.Error("component stopped with error", "component", "knowvault-sandbox-dispatcher", "error_code", dispatchercomposition.CodeOf(err))
		return 1
	}
	return 0
}
