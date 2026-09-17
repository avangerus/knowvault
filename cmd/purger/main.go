package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/lifecycle"
	"knowvault.local/verified-workspace/internal/platform/purgercomposition"
)

func main() { os.Exit(run()) }

const startupTimeout = 30 * time.Second

func run() int {
	ctx, stop := lifecycle.SignalContext(context.Background())
	defer stop()
	config, err := purgercomposition.LoadProduction()
	if err != nil {
		slog.Error("component configuration rejected", "component", "knowvault-purger", "error_code", purgercomposition.CodeOf(err))
		return 1
	}
	startupContext, cancel := context.WithTimeout(ctx, startupTimeout)
	runtime, err := purgercomposition.NewProduction(startupContext, config, buildinfo.Current())
	cancel()
	if err != nil {
		slog.Error("component startup rejected", "component", "knowvault-purger", "error_code", purgercomposition.CodeOf(err))
		return 1
	}
	defer runtime.Close()
	slog.Info("component starting", "component", "knowvault-purger", "version", buildinfo.Current().Version, "revision", buildinfo.Current().Revision)
	if err := runtime.Run(ctx); err != nil {
		slog.Error("component stopped with error", "component", "knowvault-purger", "error_code", purgercomposition.CodeOf(err))
		return 1
	}
	return 0
}
