// Package purgercomposition owns the production composition root for the
// privileged conversation-purge runner.  It intentionally has a smaller
// capability set than the ingestion worker and has no listener or connector
// surface.
package purgercomposition

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
)

const (
	organizationIDEnvironment = "KNOWVAULT_ORGANIZATION_ID"
	providerIDEnvironment     = "KNOWVAULT_PROVIDER_ID"
	purgerIDEnvironment       = "KNOWVAULT_PURGER_ID"
	leaseEnvironment          = "KNOWVAULT_PURGER_LEASE_SECONDS"
	pollEnvironment           = "KNOWVAULT_PURGER_POLL_SECONDS"
	environmentPrefix         = "KNOWVAULT_"
	minimumLeaseSeconds       = 10
	maximumLeaseSeconds       = 3600
	minimumPollSeconds        = 1
	maximumPollSeconds        = 300
)

type ErrorCode string

const (
	CodeConfigInvalid ErrorCode = "PURGER_CONFIG_INVALID"
	CodeStartupFailed ErrorCode = "PURGER_STARTUP_FAILED"
	CodeRuntimeFailed ErrorCode = "PURGER_RUNTIME_FAILED"
	CodeCleanupFailed ErrorCode = "PURGER_CLEANUP_FAILED"
)

type Error struct{ code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return string(CodeRuntimeFailed)
	}
	return string(e.code)
}

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.code
	}
	return CodeRuntimeFailed
}

type Config struct {
	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	purgerID       string
	leaseSeconds   int
	pollSeconds    int
}

func (c Config) String() string   { return "purgercomposition.Config{[REDACTED]}" }
func (c Config) GoString() string { return "purgercomposition.Config{[REDACTED]}" }

func (c Config) OrganizationID() identity.OrganizationID { return c.organizationID }
func (c Config) ProviderID() identity.ProviderID         { return c.providerID }
func (c Config) PurgerID() string                        { return c.purgerID }
func (c Config) LeaseSeconds() int                       { return c.leaseSeconds }
func (c Config) PollSeconds() int                        { return c.pollSeconds }

func LoadProduction() (Config, error) { return loadProduction(os.Environ()) }

func loadProduction(environment []string) (Config, error) {
	allowed := map[string]struct{}{
		organizationIDEnvironment: {}, providerIDEnvironment: {}, purgerIDEnvironment: {},
		leaseEnvironment: {}, pollEnvironment: {},
	}
	values := make(map[string]string, len(allowed))
	seenFolded := make(map[string]struct{}, len(allowed))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			if hasASCIIPrefixFold(entry, environmentPrefix) {
				return Config{}, purgerError(CodeConfigInvalid)
			}
			continue
		}
		if !hasASCIIPrefixFold(name, environmentPrefix) {
			continue
		}
		folded := strings.ToUpper(name)
		if _, duplicate := seenFolded[folded]; duplicate {
			return Config{}, purgerError(CodeConfigInvalid)
		}
		seenFolded[folded] = struct{}{}
		if _, accepted := allowed[name]; !accepted {
			return Config{}, purgerError(CodeConfigInvalid)
		}
		values[name] = value
	}
	if len(values) != len(allowed) {
		return Config{}, purgerError(CodeConfigInvalid)
	}
	lease, ok := parseCanonicalInt(values[leaseEnvironment], minimumLeaseSeconds, maximumLeaseSeconds)
	if !ok {
		return Config{}, purgerError(CodeConfigInvalid)
	}
	poll, ok := parseCanonicalInt(values[pollEnvironment], minimumPollSeconds, maximumPollSeconds)
	if !ok || poll >= lease {
		return Config{}, purgerError(CodeConfigInvalid)
	}
	if !validOpaqueID(values[organizationIDEnvironment]) || !validOpaqueID(values[providerIDEnvironment]) || !validOpaqueID(values[purgerIDEnvironment]) {
		return Config{}, purgerError(CodeConfigInvalid)
	}
	return Config{
		organizationID: identity.OrganizationID(values[organizationIDEnvironment]),
		providerID:     identity.ProviderID(values[providerIDEnvironment]),
		purgerID:       values[purgerIDEnvironment], leaseSeconds: lease, pollSeconds: poll,
	}, nil
}

func purgerError(code ErrorCode) error { return &Error{code: code} }

func hasASCIIPrefixFold(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func parseCanonicalInt(value string, minimum, maximum int) (int, bool) {
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil && value == strconv.Itoa(parsed) && parsed >= minimum && parsed <= maximum
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_-.:", r) {
			continue
		}
		return false
	}
	return true
}
