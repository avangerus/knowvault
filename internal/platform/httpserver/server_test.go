package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestConfigFromEnvironmentUsesSafeDefaultAndExplicitOverride(t *testing.T) {
	t.Parallel()

	defaultConfig := ConfigFromEnvironment(func(string) (string, bool) { return "", false })
	if defaultConfig.Address != DefaultAddress || defaultConfig.ShutdownTimeout != 75*time.Second {
		t.Fatalf("default config address=%q shutdown=%s", defaultConfig.Address, defaultConfig.ShutdownTimeout)
	}
	overridden := ConfigFromEnvironment(func(name string) (string, bool) {
		if name != AddressEnvironment {
			t.Fatalf("lookup key = %q, want %q", name, AddressEnvironment)
		}
		return " 127.0.0.1:18080 ", true
	})
	if overridden.Address != "127.0.0.1:18080" {
		t.Fatalf("override address = %q", overridden.Address)
	}
}

func TestNewAppliesAllResourceBoundsAndNoDefaultLogger(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	server, err := New(config, http.NotFoundHandler())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if server.Addr != config.Address || server.ReadHeaderTimeout != config.ReadHeaderTimeout ||
		server.ReadTimeout != config.ReadTimeout || server.WriteTimeout != config.WriteTimeout ||
		server.IdleTimeout != config.IdleTimeout || server.MaxHeaderBytes != config.MaxHeaderBytes {
		t.Fatalf("server bounds do not match config: %#v", server)
	}
	if server.ErrorLog == nil || server.ErrorLog.Writer() != io.Discard {
		t.Fatal("server error logger must discard unstructured internal errors")
	}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Config){
		"empty address":       func(config *Config) { config.Address = "" },
		"missing port":        func(config *Config) { config.Address = "localhost" },
		"zero port":           func(config *Config) { config.Address = "127.0.0.1:0" },
		"zero header timeout": func(config *Config) { config.ReadHeaderTimeout = 0 },
		"zero read timeout":   func(config *Config) { config.ReadTimeout = 0 },
		"zero write timeout":  func(config *Config) { config.WriteTimeout = 0 },
		"zero idle timeout":   func(config *Config) { config.IdleTimeout = 0 },
		"zero shutdown":       func(config *Config) { config.ShutdownTimeout = 0 },
		"zero header limit":   func(config *Config) { config.MaxHeaderBytes = 0 },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := DefaultConfig()
			mutate(&config)
			_, err := New(config, http.NotFoundHandler())
			if CodeOf(err) != CodeConfigInvalid {
				t.Fatalf("CodeOf(error) = %q, want %q", CodeOf(err), CodeConfigInvalid)
			}
		})
	}
	if _, err := New(DefaultConfig(), nil); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("nil handler code = %q, want %q", CodeOf(err), CodeConfigInvalid)
	}
}

func TestRunnerServesAndShutsDownAfterCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	config := DefaultConfig()
	server, err := New(config, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	runner := Runner{Server: server, ShutdownTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runner.Serve(ctx, listener) }()

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		cancel()
		t.Fatalf("GET: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		cancel()
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("graceful shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not stop after cancellation")
	}
}

func TestRunnerReturnsContentFreeServeCode(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	server, err := New(DefaultConfig(), http.NotFoundHandler())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = (Runner{Server: server, ShutdownTimeout: time.Second}).Serve(context.Background(), listener)
	if CodeOf(err) != CodeServeFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", CodeOf(err), CodeServeFailed)
	}
	if err.Error() != string(CodeServeFailed) {
		t.Fatalf("error string disclosed internal detail: %q", err)
	}
	if !errors.As(err, new(*Error)) {
		t.Fatalf("error type = %T, want *Error", err)
	}
}

func TestRunnerReturnsContentFreeListenCode(t *testing.T) {
	t.Parallel()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupied.Close()

	config := DefaultConfig()
	config.Address = occupied.Addr().String()
	server, err := New(config, http.NotFoundHandler())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = (Runner{Server: server, ShutdownTimeout: time.Second}).ListenAndServe(context.Background())
	if CodeOf(err) != CodeListenFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", CodeOf(err), CodeListenFailed)
	}
	if err.Error() != string(CodeListenFailed) {
		t.Fatalf("error string disclosed internal detail: %q", err)
	}
}

func TestRunnerRejectsCancelledContextBeforeListening(t *testing.T) {
	server, err := New(DefaultConfig(), http.NotFoundHandler())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = (Runner{Server: server, ShutdownTimeout: time.Second}).ListenAndServe(ctx)
	if CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", CodeOf(err), CodeConfigInvalid)
	}
}
