//go:build linux

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// startProxy fronts the product server's plain HTTP listener with the
// public TLS origin https://localhost:8443, exactly the deployment topology:
// the product process binds :8080, TLS terminates in front of it, and the
// Origin/CSRF contract the API verifies is the public origin. The certificate
// is the e2e CA-signed localhost leaf the harness client trusts.
func startProxy(ctx context.Context, cfg config) error {
	target, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	server := &http.Server{
		Addr:              ":8443",
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = server.ListenAndServeTLS(cfg.caDir+"/localhost.crt", cfg.caDir+"/localhost.key")
	}()
	if err := waitHTTP(ctx, cfg, cfg.publicOrigin+"/", 20*time.Second); err != nil {
		// The proxy can answer before the product server is up; readiness here
		// only proves the TLS front accepted a connection.
		return fmt.Errorf("proxy readiness: %w", err)
	}
	return nil
}
