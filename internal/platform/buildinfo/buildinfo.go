// Package buildinfo exposes immutable build metadata injected by the release build.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// These values are replaced with -ldflags by the reviewed image build.
var (
	Version  = "dev"
	Revision = "unknown"
	BuiltAt  = "unknown"
)

// Info is the public, content-free identity of a running binary.
type Info struct {
	Version      string
	Revision     string
	BuiltAt      string
	GoVersion    string
	GoExperiment string
}

// Current returns a snapshot. It never reads source, tenant, or secret data.
func Current() Info {
	return newInfo(Version, Revision, BuiltAt, runtime.Version(), buildSetting("GOEXPERIMENT"))
}

func newInfo(version, revision, builtAt, goVersion, goExperiment string) Info {
	return Info{
		Version:      valueOr(version, "dev"),
		Revision:     valueOr(revision, "unknown"),
		BuiltAt:      valueOr(builtAt, "unknown"),
		GoVersion:    valueOr(goVersion, "unknown"),
		GoExperiment: valueOr(goExperiment, "unknown"),
	}
}

func buildSetting(key string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
