package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/composition"
	"knowvault.local/verified-workspace/internal/platform/lifecycle"
)

func main() {
	os.Exit(run())
}

const productionStartupTimeout = 30 * time.Second

func run() int {
	ctx, stop := lifecycle.SignalContext(context.Background())
	defer stop()

	info := buildinfo.Current()
	config, err := composition.LoadProduction()
	if err != nil {
		slog.Error("component configuration rejected", "component", "knowvault-server", "error_code", composition.CodeOf(err))
		return 1
	}

	startupContext, cancelStartup := context.WithTimeout(ctx, productionStartupTimeout)
	runtime, err := composition.NewProduction(startupContext, config, info)
	cancelStartup()
	if err != nil {
		slog.Error("component startup rejected", startupErrorLogArgs(err)...)
		return 1
	}
	defer runtime.Close()

	slog.Info("component starting", "component", "knowvault-server", "version", info.Version, "revision", info.Revision)
	if err := runtime.Run(ctx); err != nil {
		slog.Error("component stopped with error", "component", "knowvault-server", "error_code", composition.CodeOf(err))
		return 1
	}
	return 0
}

func startupErrorLogArgs(err error) []any {
	return []any{
		"component", "knowvault-server",
		"error_code", composition.CodeOf(err),
		"startup_stage", string(composition.StartupStageOf(err)),
	}
}
