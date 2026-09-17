// Package workercomposition owns the production worker composition root.
//
// It is intentionally separate from the HTTP composition package: a worker
// has no listener, public origin or browser capability, and uses the durable
// worker database role.
package workercomposition

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
	workerIDEnvironment       = "KNOWVAULT_WORKER_ID"
	leaseEnvironment          = "KNOWVAULT_WORKER_LEASE_SECONDS"
	pollEnvironment           = "KNOWVAULT_WORKER_POLL_SECONDS"
	nativeProfileEnvironment  = "KNOWVAULT_WORKER_NATIVE_PROFILE"
	environmentPrefix         = "KNOWVAULT_"
	minimumLeaseSeconds       = 10
	maximumLeaseSeconds       = 3600
	minimumPollSeconds        = 1
	maximumPollSeconds        = 300
)

// ErrorCode is content-free and safe for startup logs.
type ErrorCode string

const (
	CodeConfigInvalid     ErrorCode = "WORKER_CONFIG_INVALID"
	CodeStartupFailed     ErrorCode = "WORKER_STARTUP_FAILED"
	CodeRuntimeState      ErrorCode = "WORKER_RUNTIME_STATE_INVALID"
	CodeRuntimeFailed     ErrorCode = "WORKER_RUNTIME_FAILED"
	CodeCleanupFailed     ErrorCode = "WORKER_CLEANUP_FAILED"
	CodeJobLoopFailed     ErrorCode = "WORKER_JOB_LOOP_FAILED"
	CodeJobUnsupported    ErrorCode = "WORKER_JOB_UNSUPPORTED"
	CodeMountsUnavailable ErrorCode = "WORKER_MOUNTS_UNAVAILABLE"
	CodeNativeDisabled    ErrorCode = "WORKER_NATIVE_DISABLED"
	CodeNativeNotReady    ErrorCode = "WORKER_NATIVE_NOT_READY"
	// CodeSearchProfileRevisionDrift is logged (never persisted) when a staged
	// retrieval profile revision names a vector space this indexer does not
	// mount. It is content-free: the identities stay out of the log line.
	CodeSearchProfileRevisionDrift ErrorCode = "WORKER_SEARCH_PROFILE_REVISION_DRIFT"
)

// Error optionally carries a startup stage and the content-free cause code of
// the collaborator that rejected it. Both fields are internal: Error() still
// reports only the bare ErrorCode, exactly as before, so nothing about this
// addition can leak through a code path that only calls Error() or CodeOf.
type Error struct {
	code  ErrorCode
	stage string
	cause string
}

func (value *Error) Error() string {
	if value == nil {
		return string(CodeRuntimeFailed)
	}
	return string(value.code)
}

func CodeOf(err error) ErrorCode {
	var workerError *Error
	if errors.As(err, &workerError) && workerError != nil {
		return workerError.code
	}
	return CodeRuntimeFailed
}

// DiagnosticClass reports which startup stage rejected worker composition, as
// a content-free label safe for operator logs: the fixed stage tag this
// package assigns internally (never a path, secret or identity), optionally
// joined with the failing collaborator's own content-free ErrorCode (every
// collaborator package's Error.Error() is documented and implemented to
// return exactly its bare code, so reusing it here introduces no new
// disclosure surface). It is "" for any error that did not originate from
// NewProduction's staged acquisition, so a caller can log it unconditionally
// alongside CodeOf without special-casing other error paths.
func DiagnosticClass(err error) string {
	var workerError *Error
	if !errors.As(err, &workerError) || workerError == nil || workerError.stage == "" {
		return ""
	}
	if workerError.cause == "" {
		return workerError.stage
	}
	return workerError.stage + ":" + workerError.cause
}

// startupError tags a staged-acquisition failure with the stage that
// rejected it and, when known, the failing collaborator's own content-free
// cause code. cause is a string captured once at construction (via
// cause.Error(), never the error value itself) so this type never becomes a
// vector for holding onto larger, less-audited error state.
func startupError(stage string, cause error) error {
	causeCode := ""
	if cause != nil {
		causeCode = cause.Error()
	}
	return &Error{code: CodeStartupFailed, stage: stage, cause: causeCode}
}

// Config is the complete non-secret worker startup snapshot. The source mount
// registry and all secret material are fixed production capabilities acquired
// by NewProduction, never configuration strings supplied to handlers.
type Config struct {
	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	workerID       string
	leaseSeconds   int
	pollSeconds    int
	nativeEnabled  bool
}

func (Config) String() string   { return "workercomposition.Config{[REDACTED]}" }
func (Config) GoString() string { return "workercomposition.Config{[REDACTED]}" }

func (value Config) OrganizationID() identity.OrganizationID { return value.organizationID }
func (value Config) ProviderID() identity.ProviderID         { return value.providerID }
func (value Config) WorkerID() string                        { return value.workerID }
func (value Config) LeaseSeconds() int                       { return value.leaseSeconds }
func (value Config) PollSeconds() int                        { return value.pollSeconds }
func (value Config) NativeEnabled() bool                     { return value.nativeEnabled }

// LoadProduction snapshots the environment exactly once. The worker has its
// own closed allowlist; server-only variables and all unknown KNOWVAULT_*
// variables are rejected rather than silently ignored.
func LoadProduction() (Config, error) {
	return loadProduction(os.Environ())
}

func loadProduction(environment []string) (Config, error) {
	allowed := map[string]struct{}{
		organizationIDEnvironment: {},
		providerIDEnvironment:     {},
		workerIDEnvironment:       {},
		leaseEnvironment:          {},
		pollEnvironment:           {},
		nativeProfileEnvironment:  {},
	}
	values := make(map[string]string, len(allowed))
	seenFolded := make(map[string]struct{}, len(allowed))

	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			if hasASCIIPrefixFold(entry, environmentPrefix) {
				return Config{}, workerError(CodeConfigInvalid)
			}
			continue
		}
		if !hasASCIIPrefixFold(name, environmentPrefix) {
			continue
		}
		folded := strings.ToUpper(name)
		if _, duplicate := seenFolded[folded]; duplicate {
			return Config{}, workerError(CodeConfigInvalid)
		}
		seenFolded[folded] = struct{}{}
		if _, accepted := allowed[name]; !accepted {
			return Config{}, workerError(CodeConfigInvalid)
		}
		values[name] = value
	}
	for name := range allowed {
		if _, found := values[name]; !found && name != nativeProfileEnvironment {
			return Config{}, workerError(CodeConfigInvalid)
		}
	}
	nativeEnabled := false
	if profile, present := values[nativeProfileEnvironment]; present {
		switch profile {
		case "disabled":
		case NativeProfileRevision:
			nativeEnabled = true
		default:
			return Config{}, workerError(CodeConfigInvalid)
		}
	}

	leaseSeconds, ok := parseCanonicalInt(values[leaseEnvironment], minimumLeaseSeconds, maximumLeaseSeconds)
	if !ok {
		return Config{}, workerError(CodeConfigInvalid)
	}
	pollSeconds, ok := parseCanonicalInt(values[pollEnvironment], minimumPollSeconds, maximumPollSeconds)
	if !ok || pollSeconds >= leaseSeconds {
		return Config{}, workerError(CodeConfigInvalid)
	}
	if !validOpaqueID(values[organizationIDEnvironment]) || !validOpaqueID(values[providerIDEnvironment]) || !validOpaqueID(values[workerIDEnvironment]) {
		return Config{}, workerError(CodeConfigInvalid)
	}

	return Config{
		organizationID: identity.OrganizationID(values[organizationIDEnvironment]),
		providerID:     identity.ProviderID(values[providerIDEnvironment]),
		workerID:       values[workerIDEnvironment],
		leaseSeconds:   leaseSeconds,
		pollSeconds:    pollSeconds,
		nativeEnabled:  nativeEnabled,
	}, nil
}

func workerError(code ErrorCode) error { return &Error{code: code} }

func hasASCIIPrefixFold(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func parseCanonicalInt(value string, minimum, maximum int) (int, bool) {
	parsed, err := strconv.Atoi(value)
	valid := err == nil && value == strconv.Itoa(parsed) && parsed >= minimum && parsed <= maximum
	return parsed, valid
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}
