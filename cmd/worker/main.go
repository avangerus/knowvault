package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/lifecycle"
	"knowvault.local/verified-workspace/internal/platform/workercomposition"
)

func main() {
	os.Exit(run())
}

const productionStartupTimeout = 30 * time.Second

func runArguments(arguments []string) int {
	if len(arguments) != 1 || arguments[0] != "native-readiness" {
		slog.Error("worker command rejected", "error_code", "WORKER_COMMAND_INVALID")
		return 2
	}
	config, err := workercomposition.LoadProduction()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = workercomposition.CheckNativeReadiness(ctx, config)
	}
	if err != nil {
		slog.Error("native parser not ready", "error_code", workercomposition.CodeOf(err))
		return 1
	}
	slog.Info("native parsers ready", "profile", workercomposition.NativeProfileRevision)
	return 0
}

func run() int {
	if len(os.Args) > 1 {
		return runArguments(os.Args[1:])
	}
	ctx, stop := lifecycle.SignalContext(context.Background())
	defer stop()

	info := buildinfo.Current()
	config, err := workercomposition.LoadProduction()
	if err != nil {
		slog.Error("component configuration rejected", "component", "knowvault-worker", "error_code", workercomposition.CodeOf(err))
		return 1
	}

	startupContext, cancelStartup := context.WithTimeout(ctx, productionStartupTimeout)
	runtime, err := workercomposition.NewProduction(startupContext, config, info)
	cancelStartup()
	if err != nil {
		slog.Error("component startup rejected", "component", "knowvault-worker", "error_code", workercomposition.CodeOf(err), "error_class", workercomposition.DiagnosticClass(err))
		return 1
	}
	defer runtime.Close()

	slog.Info("component starting", "component", "knowvault-worker", "version", info.Version, "revision", info.Revision)
	if err := runtime.Run(ctx); err != nil {
		slog.Error("component stopped with error", "component", "knowvault-worker", "error_code", workercomposition.CodeOf(err))
		return 1
	}
	return 0
}
