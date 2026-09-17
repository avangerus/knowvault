package oidc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"knowvault.local/verified-workspace/internal/platform/trustbundle"
)

const (
	hardenedHTTPTimeout              = 15 * time.Second
	productionDialTimeout            = 5 * time.Second
	productionTCPKeepAlive           = 30 * time.Second
	productionTLSHandshakeTimeout    = 5 * time.Second
	productionResponseHeaderTimeout  = 10 * time.Second
	productionExpectContinueTimeout  = time.Second
	productionIdleConnectionTimeout  = 90 * time.Second
	productionMaxIdleConnections     = 32
	productionMaxIdleConnectionsHost = 8
	productionMaxConnectionsHost     = 16
	productionMaxResponseHeaderBytes = 1 << 20
	maximumOIDCResponseBodyBytes     = int64(4 << 20)
)

// HardenedHTTPClient is the only client accepted by OIDC discovery and token
// exchange. Its timeout, HTTPS-only transport and redirect policy cannot be
// weakened by the HTTP handler.
type HardenedHTTPClient struct{ client *http.Client }

func (HardenedHTTPClient) String() string   { return "oidc.HardenedHTTPClient{[REDACTED]}" }
func (HardenedHTTPClient) GoString() string { return "oidc.HardenedHTTPClient{[REDACTED]}" }

// NewProductionHTTPClient builds the complete OIDC network profile from an
// explicit trust store. It never consults system roots or proxy environment
// variables and does not retain the caller's mutable CertPool.
func NewProductionHTTPClient(roots trustbundle.OIDCRoots) (*HardenedHTTPClient, error) {
	rootCopy, err := roots.NewCertPool()
	if err != nil || len(rootCopy.Subjects()) == 0 {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	dialer := &net.Dialer{Timeout: productionDialTimeout, KeepAlive: productionTCPKeepAlive}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           productionMaxIdleConnections,
		MaxIdleConnsPerHost:    productionMaxIdleConnectionsHost,
		MaxConnsPerHost:        productionMaxConnectionsHost,
		IdleConnTimeout:        productionIdleConnectionTimeout,
		TLSHandshakeTimeout:    productionTLSHandshakeTimeout,
		ResponseHeaderTimeout:  productionResponseHeaderTimeout,
		ExpectContinueTimeout:  productionExpectContinueTimeout,
		MaxResponseHeaderBytes: productionMaxResponseHeaderBytes,
		DisableCompression:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCopy,
		},
	}
	return newHardenedHTTPClient(transport)
}

// NewHardenedHTTPClient is a non-production seam for deterministic protocol
// tests. Production composition must use NewProductionHTTPClient so transport
// policy and trust roots cannot be supplied by the caller.
func NewHardenedHTTPClient(transport *http.Transport) (*HardenedHTTPClient, error) {
	if transport == nil || transport.DialTLS != nil || transport.DialTLSContext != nil || len(transport.TLSNextProto) != 0 ||
		(transport.TLSClientConfig != nil && (transport.TLSClientConfig.InsecureSkipVerify ||
			(transport.TLSClientConfig.MinVersion != 0 && transport.TLSClientConfig.MinVersion < tls.VersionTLS12) ||
			(transport.TLSClientConfig.MaxVersion != 0 && transport.TLSClientConfig.MaxVersion < tls.VersionTLS12))) {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	return newHardenedHTTPClient(transport.Clone())
}

// newHardenedHTTPClient is the package-private deterministic test seam.
func newHardenedHTTPClient(transport http.RoundTripper) (*HardenedHTTPClient, error) {
	if transport == nil {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	return &HardenedHTTPClient{client: &http.Client{
		Transport: httpsOnlyRoundTripper{delegate: boundedResponseRoundTripper{delegate: transport}},
		Timeout:   hardenedHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

// CloseIdleConnections releases pooled OIDC discovery, token and JWKS
// connections during process shutdown. It never exposes the wrapped transport
// or turns lifecycle cleanup into a caller-selectable network capability.
func (value *HardenedHTTPClient) CloseIdleConnections() {
	if value == nil || value.client == nil || value.client.Transport == nil {
		return
	}
	if closer, ok := value.client.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// boundedResponseRoundTripper owns the one streaming response limit shared by
// discovery, JWKS and token exchange. It never buffers a provider response.
type boundedResponseRoundTripper struct{ delegate http.RoundTripper }

func (boundedResponseRoundTripper) String() string {
	return "oidc.boundedResponseRoundTripper{[REDACTED]}"
}
func (boundedResponseRoundTripper) GoString() string {
	return "oidc.boundedResponseRoundTripper{[REDACTED]}"
}

func (transport boundedResponseRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.delegate == nil {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	response, err := transport.delegate.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	if response.ContentLength < -1 || response.ContentLength > maximumOIDCResponseBodyBytes {
		_ = response.Body.Close()
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	response.Body = &boundedResponseBody{body: response.Body, remaining: maximumOIDCResponseBodyBytes}
	return response, nil
}

func (transport boundedResponseRoundTripper) CloseIdleConnections() {
	if closer, ok := transport.delegate.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type boundedResponseBody struct {
	body      io.ReadCloser
	remaining int64
	finished  bool
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func (body *boundedResponseBody) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if body == nil || body.body == nil {
		return 0, &Error{code: CodeConfigurationInvalid}
	}
	if body.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	if body.finished {
		return 0, io.EOF
	}
	if body.remaining > 0 {
		if int64(len(destination)) > body.remaining {
			destination = destination[:int(body.remaining)]
		}
		count, err := body.body.Read(destination)
		if count < 0 || count > len(destination) {
			_ = body.Close()
			return 0, &Error{code: CodeConfigurationInvalid}
		}
		body.remaining -= int64(count)
		if err == io.EOF {
			body.finished = true
		}
		if count == 0 && err == nil {
			_ = body.Close()
			return 0, &Error{code: CodeConfigurationInvalid}
		}
		return count, err
	}

	var probe [1]byte
	count, err := body.body.Read(probe[:])
	if count > 0 {
		_ = body.Close()
		return 0, &Error{code: CodeConfigurationInvalid}
	}
	if err == io.EOF {
		body.finished = true
		return 0, io.EOF
	}
	if err == nil {
		_ = body.Close()
		return 0, &Error{code: CodeConfigurationInvalid}
	}
	return 0, err
}

func (body *boundedResponseBody) Close() error {
	if body == nil || body.body == nil {
		return nil
	}
	body.closed.Store(true)
	body.closeOnce.Do(func() { body.closeErr = body.body.Close() })
	return body.closeErr
}

type httpsOnlyRoundTripper struct{ delegate http.RoundTripper }

func (httpsOnlyRoundTripper) String() string   { return "oidc.httpsOnlyRoundTripper{[REDACTED]}" }
func (httpsOnlyRoundTripper) GoString() string { return "oidc.httpsOnlyRoundTripper{[REDACTED]}" }

func (transport httpsOnlyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil || transport.delegate == nil {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	return transport.delegate.RoundTrip(request)
}

func (transport httpsOnlyRoundTripper) CloseIdleConnections() {
	if closer, ok := transport.delegate.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (value *HardenedHTTPClient) valid() bool {
	return value != nil && value.client != nil && value.client.Transport != nil && value.client.Timeout == hardenedHTTPTimeout && value.client.CheckRedirect != nil && value.client.Jar == nil
}
