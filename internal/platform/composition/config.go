// Package composition owns the production process composition root.
//
// This file deliberately contains only validated, non-secret startup
// configuration. Secret material crosses a separate mounted-file boundary.
package composition

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/netcanon"
)

const (
	organizationIDEnvironment  = "KNOWVAULT_ORGANIZATION_ID"
	providerIDEnvironment      = "KNOWVAULT_PROVIDER_ID"
	publicOriginEnvironment    = "KNOWVAULT_PUBLIC_ORIGIN"
	httpAddressEnvironment     = "KNOWVAULT_HTTP_ADDR"
	knowVaultEnvironmentPrefix = "KNOWVAULT_"
	maximumOriginBytes         = 2048
	maximumAddressBytes        = 256
)

// ErrorCode is safe for a startup log. It never contains an environment name
// or value because either can expose deployment details.
type ErrorCode string

const CodeConfigInvalid ErrorCode = "COMPOSITION_CONFIG_INVALID"

type Error struct {
	code  ErrorCode
	stage StartupStage
}

func (value *Error) Error() string { return string(value.code) }

func CodeOf(err error) ErrorCode {
	var configurationError *Error
	if errors.As(err, &configurationError) {
		return configurationError.code
	}
	return CodeConfigInvalid
}

// Config is the complete non-secret production startup configuration. Its
// fields are private so later constructors cannot accidentally consume an
// unvalidated zero or ad-hoc configuration.
type Config struct {
	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	publicOrigin   string
	httpAddress    string
}

func (Config) String() string   { return "composition.Config{[REDACTED]}" }
func (Config) GoString() string { return "composition.Config{[REDACTED]}" }

func (value Config) OrganizationID() identity.OrganizationID { return value.organizationID }
func (value Config) ProviderID() identity.ProviderID         { return value.providerID }
func (value Config) PublicOrigin() string                    { return value.publicOrigin }
func (value Config) HTTPAddress() string                     { return value.httpAddress }

// LoadProduction snapshots the process environment exactly once. Only the
// four allowlisted KNOWVAULT_* variables participate; every other variable in
// that namespace fails closed.
func LoadProduction() (Config, error) {
	environment := os.Environ()
	return loadProduction(environment)
}

func loadProduction(environment []string) (Config, error) {
	allowed := map[string]struct{}{
		organizationIDEnvironment: {},
		providerIDEnvironment:     {},
		publicOriginEnvironment:   {},
		httpAddressEnvironment:    {},
	}
	values := make(map[string]string, len(allowed))
	seenFolded := make(map[string]struct{}, len(allowed))

	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			if hasASCIIPrefixFold(entry, knowVaultEnvironmentPrefix) {
				return Config{}, &Error{code: CodeConfigInvalid}
			}
			continue
		}
		if !hasASCIIPrefixFold(name, knowVaultEnvironmentPrefix) {
			continue
		}
		foldedName := strings.ToUpper(name)
		if _, duplicate := seenFolded[foldedName]; duplicate {
			return Config{}, &Error{code: CodeConfigInvalid}
		}
		seenFolded[foldedName] = struct{}{}
		if _, accepted := allowed[name]; !accepted {
			return Config{}, &Error{code: CodeConfigInvalid}
		}
		values[name] = value
	}

	if len(values) != len(allowed) {
		return Config{}, &Error{code: CodeConfigInvalid}
	}
	organizationID := values[organizationIDEnvironment]
	providerID := values[providerIDEnvironment]
	publicOrigin := values[publicOriginEnvironment]
	httpAddress := values[httpAddressEnvironment]
	if !validOpaqueID(organizationID) || !validOpaqueID(providerID) || !validPublicOrigin(publicOrigin) ||
		!validHTTPAddress(httpAddress) {
		return Config{}, &Error{code: CodeConfigInvalid}
	}

	return Config{
		organizationID: identity.OrganizationID(organizationID), providerID: identity.ProviderID(providerID),
		publicOrigin: publicOrigin, httpAddress: httpAddress,
	}, nil
}

func hasASCIIPrefixFold(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func validText(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !validText(value, 128) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validPublicOrigin(value string) bool {
	if !validText(value, maximumOriginBytes) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.ForceQuery ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value {
		return false
	}
	hostname := parsed.Hostname()
	if !netcanon.ValidCanonicalHost(hostname) || strings.HasSuffix(hostname, ".") {
		return false
	}
	port := parsed.Port()
	if port == "" {
		expectedHost := hostname
		if strings.Contains(hostname, ":") {
			expectedHost = "[" + hostname + "]"
		}
		return parsed.Host == expectedHost
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535 && port != "443" && strconv.Itoa(portNumber) == port &&
		parsed.Host == net.JoinHostPort(hostname, port)
}

func validHTTPAddress(value string) bool {
	if !validText(value, maximumAddressBytes) {
		return false
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || (host != "" && !netcanon.ValidCanonicalHost(host)) {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535 && strconv.Itoa(portNumber) == port &&
		net.JoinHostPort(host, port) == value
}

// The canonical-hostname rule lives in netcanon and is shared with the
// deployment operator; neither component maintains a second implementation.
