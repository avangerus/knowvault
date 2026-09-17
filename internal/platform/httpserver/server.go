// Package httpserver owns the bounded lifecycle of the stdlib HTTP server.
package httpserver

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	AddressEnvironment = "KNOWVAULT_HTTP_ADDR"
	DefaultAddress     = ":8080"

	CodeConfigInvalid  ErrorCode = "HTTP_CONFIG_INVALID"
	CodeListenFailed   ErrorCode = "HTTP_LISTEN_FAILED"
	CodeServeFailed    ErrorCode = "HTTP_SERVE_FAILED"
	CodeShutdownFailed ErrorCode = "HTTP_SHUTDOWN_FAILED"
	CodeUnexpected     ErrorCode = "HTTP_UNEXPECTED"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 60 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 75 * time.Second
	defaultMaxHeaderBytes    = 64 << 10
)

// ErrorCode is safe to emit to structured logs.
type ErrorCode string

// Error preserves a machine-readable code while keeping its string form content-free.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string {
	return string(e.code)
}

func (e *Error) Unwrap() error {
	return e.cause
}

// CodeOf returns a content-free code for any server orchestration error.
func CodeOf(err error) ErrorCode {
	var serverError *Error
	if errors.As(err, &serverError) {
		return serverError.code
	}
	return CodeUnexpected
}

// Config fixes all resource bounds of the public listener.
type Config struct {
	Address           string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
}

// DefaultConfig returns the accepted Stage 0 listener profile.
func DefaultConfig() Config {
	return Config{
		Address:           DefaultAddress,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		ShutdownTimeout:   defaultShutdownTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}
}

// ConfigFromEnvironment applies only the explicitly supported address override.
func ConfigFromEnvironment(lookup func(string) (string, bool)) Config {
	config := DefaultConfig()
	if lookup == nil {
		return config
	}
	if address, ok := lookup(AddressEnvironment); ok {
		config.Address = strings.TrimSpace(address)
	}
	return config
}

// New constructs an HTTP server without the process-global DefaultServeMux or default error logger.
func New(config Config, handler http.Handler) (*http.Server, error) {
	if handler == nil || !validConfig(config) {
		return nil, newError(CodeConfigInvalid, nil)
	}
	return &http.Server{
		Addr:              config.Address,
		Handler:           handler,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		ReadTimeout:       config.ReadTimeout,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    config.MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}, nil
}

// Runner binds one server and owns graceful shutdown.
type Runner struct {
	Server          *http.Server
	ShutdownTimeout time.Duration
}

// ListenAndServe binds the configured TCP address and serves until cancellation or failure.
func (r Runner) ListenAndServe(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || r.Server == nil || r.ShutdownTimeout <= 0 {
		return newError(CodeConfigInvalid, nil)
	}
	listener, err := net.Listen("tcp", r.Server.Addr)
	if err != nil {
		return newError(CodeListenFailed, err)
	}
	return r.Serve(ctx, listener)
}

// Serve is the listener-injected orchestration seam used by tests and controlled runtimes.
func (r Runner) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil || r.Server == nil || listener == nil || r.ShutdownTimeout <= 0 {
		return newError(CodeConfigInvalid, nil)
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- r.Server.Serve(listener)
	}()

	select {
	case err := <-serveResult:
		if err == nil {
			return nil
		}
		return newError(CodeServeFailed, err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), r.ShutdownTimeout)
		defer cancel()
		if err := r.Server.Shutdown(shutdownContext); err != nil {
			_ = r.Server.Close()
			<-serveResult
			return newError(CodeShutdownFailed, err)
		}
		if err := <-serveResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return newError(CodeServeFailed, err)
		}
		return nil
	}
}

func validConfig(config Config) bool {
	if config.ReadHeaderTimeout <= 0 || config.ReadTimeout <= 0 || config.WriteTimeout <= 0 ||
		config.IdleTimeout <= 0 || config.ShutdownTimeout <= 0 || config.MaxHeaderBytes <= 0 {
		return false
	}
	_, port, err := net.SplitHostPort(config.Address)
	if err != nil {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535
}

func newError(code ErrorCode, cause error) error {
	return &Error{code: code, cause: cause}
}
