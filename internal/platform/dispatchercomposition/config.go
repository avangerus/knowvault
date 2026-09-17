// Package dispatchercomposition owns the production dispatcher composition root.
//
// It is intentionally separate from the worker composition: the dispatcher is
// the orchestration-boundary broker (ADR-0068), it holds no database, job or
// secret capability, and its only production capability is the kernel observer
// plus the supervisor killer — both acquired by NewProduction, never supplied
// as configuration strings.
package dispatchercomposition

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

const (
	rootDirEnvironment         = "KNOWVAULT_DISPATCHER_ROOT_DIR"
	submitSocketEnvironment    = "KNOWVAULT_DISPATCHER_SUBMIT_SOCKET"
	handoffSocketEnvironment   = "KNOWVAULT_DISPATCHER_HANDOFF_SOCKET"
	officeSocketEnvironment    = "KNOWVAULT_DISPATCHER_OFFICE_REGISTER_SOCKET"
	pdfSocketEnvironment       = "KNOWVAULT_DISPATCHER_PDF_REGISTER_SOCKET"
	supervisorUIDEnvironment   = "KNOWVAULT_DISPATCHER_SUPERVISOR_UID"
	supervisorGIDEnvironment   = "KNOWVAULT_DISPATCHER_SUPERVISOR_GID"
	submitterUIDEnvironment    = "KNOWVAULT_DISPATCHER_SUBMITTER_UID"
	submitterGIDEnvironment    = "KNOWVAULT_DISPATCHER_SUBMITTER_GID"
	officeWorkerUIDEnvironment = "KNOWVAULT_DISPATCHER_OFFICE_WORKER_UID"
	officeWorkerGIDEnvironment = "KNOWVAULT_DISPATCHER_OFFICE_WORKER_GID"
	pdfWorkerUIDEnvironment    = "KNOWVAULT_DISPATCHER_PDF_WORKER_UID"
	pdfWorkerGIDEnvironment    = "KNOWVAULT_DISPATCHER_PDF_WORKER_GID"
	maxPayloadEnvironment      = "KNOWVAULT_DISPATCHER_MAX_PAYLOAD_BYTES"
	frameTimeoutEnvironment    = "KNOWVAULT_DISPATCHER_FRAME_TIMEOUT_MS"
	environmentPrefix          = "KNOWVAULT_"

	minimumMaxPayload = 1024
	maximumMaxPayload = 64 * 1024 * 1024
	minimumFrameMS    = 100
	maximumFrameMS    = 60000
	maximumIdentity   = 2147483647

	canonicalRootDir         = "/run/knowvault/sandbox"
	canonicalSubmitSocket    = "/run/knowvault/sandbox/submit/dispatcher.sock"
	canonicalHandoffSocket   = "/run/knowvault/sandbox/supervisor/handoff.sock"
	canonicalStatusPath      = "/run/knowvault/sandbox/supervisor/status.json"
	canonicalOfficeSocket    = "/run/knowvault/sandbox/office/register.sock"
	canonicalPDFSocket       = "/run/knowvault/sandbox/pdf/register.sock"
	canonicalSupervisorUID   = 0
	canonicalSupervisorGID   = 0
	canonicalSubmitterUID    = 65530
	canonicalSubmitterGID    = 65530
	canonicalOfficeWorkerUID = 65532
	canonicalOfficeWorkerGID = 65532
	canonicalPDFWorkerUID    = 65533
	canonicalPDFWorkerGID    = 65533
	canonicalMaxPayload      = 64 * 1024 * 1024
	canonicalFrameTimeoutMS  = 5000
)

// ErrorCode is content-free and safe for startup logs.
type ErrorCode string

const (
	CodeConfigInvalid ErrorCode = "DISPATCHER_CONFIG_INVALID"
	CodeStartupFailed ErrorCode = "DISPATCHER_STARTUP_FAILED"
	CodeRuntimeFailed ErrorCode = "DISPATCHER_RUNTIME_FAILED"
	CodeCleanupFailed ErrorCode = "DISPATCHER_CLEANUP_FAILED"
)

type Error struct{ code ErrorCode }

func (value *Error) Error() string {
	if value == nil {
		return string(CodeRuntimeFailed)
	}
	return string(value.code)
}

func CodeOf(err error) ErrorCode {
	var dispatcherError *Error
	if errors.As(err, &dispatcherError) && dispatcherError != nil {
		return dispatcherError.code
	}
	return CodeRuntimeFailed
}

// Config is the complete non-secret dispatcher startup snapshot.
type Config struct {
	rootDir                      string
	submitSocketPath             string
	supervisorHandoffSocketPath  string
	officeRegistrationSocketPath string
	pdfRegistrationSocketPath    string
	supervisorUID                int
	supervisorGID                int
	submitterUID                 int
	submitterGID                 int
	officeWorkerUID              int
	officeWorkerGID              int
	pdfWorkerUID                 int
	pdfWorkerGID                 int
	maxPayloadBytes              int
	frameTimeout                 time.Duration
}

func stringsBeforeLastSlash(value string) string {
	index := strings.LastIndexByte(value, '/')
	if index <= 0 {
		return ""
	}
	return value[:index]
}

func (Config) String() string   { return "dispatchercomposition.Config{[REDACTED]}" }
func (Config) GoString() string { return "dispatchercomposition.Config{[REDACTED]}" }

func (value Config) RootDir() string                     { return value.rootDir }
func (value Config) SubmitSocketPath() string            { return value.submitSocketPath }
func (value Config) SupervisorHandoffSocketPath() string { return value.supervisorHandoffSocketPath }
func (value Config) supervisorStatusPath() string {
	return stringsBeforeLastSlash(value.supervisorHandoffSocketPath) + "/status.json"
}
func (value Config) OfficeRegistrationSocketPath() string { return value.officeRegistrationSocketPath }
func (value Config) PDFRegistrationSocketPath() string    { return value.pdfRegistrationSocketPath }
func (value Config) SupervisorUID() int                   { return value.supervisorUID }
func (value Config) SupervisorGID() int                   { return value.supervisorGID }
func (value Config) SubmitterUID() int                    { return value.submitterUID }
func (value Config) SubmitterGID() int                    { return value.submitterGID }
func (value Config) OfficeWorkerUID() int                 { return value.officeWorkerUID }
func (value Config) OfficeWorkerGID() int                 { return value.officeWorkerGID }
func (value Config) PDFWorkerUID() int                    { return value.pdfWorkerUID }
func (value Config) PDFWorkerGID() int                    { return value.pdfWorkerGID }
func (value Config) MaxPayloadBytes() int                 { return value.maxPayloadBytes }
func (value Config) FrameTimeout() time.Duration          { return value.frameTimeout }

func (value Config) matchesManifestTuple() bool {
	return value.rootDir == canonicalRootDir &&
		value.submitSocketPath == canonicalSubmitSocket &&
		value.supervisorHandoffSocketPath == canonicalHandoffSocket &&
		value.supervisorStatusPath() == canonicalStatusPath &&
		value.officeRegistrationSocketPath == canonicalOfficeSocket &&
		value.pdfRegistrationSocketPath == canonicalPDFSocket &&
		value.supervisorUID == canonicalSupervisorUID && value.supervisorGID == canonicalSupervisorGID &&
		value.submitterUID == canonicalSubmitterUID && value.submitterGID == canonicalSubmitterGID &&
		value.officeWorkerUID == canonicalOfficeWorkerUID && value.officeWorkerGID == canonicalOfficeWorkerGID &&
		value.pdfWorkerUID == canonicalPDFWorkerUID && value.pdfWorkerGID == canonicalPDFWorkerGID &&
		value.maxPayloadBytes == canonicalMaxPayload && value.frameTimeout == time.Duration(canonicalFrameTimeoutMS)*time.Millisecond
}

// v2Config converts the immutable startup snapshot to the broker's v2
// capability configuration. Registry entries are code/deployment-owned; no
// parser identity, limit or artifact hash is accepted from a request or env.
func (value Config) v2Config() sandboxdispatch.V2Config {
	return sandboxdispatch.V2Config{
		RootDir:                         value.rootDir,
		SubmitSocketPath:                value.submitSocketPath,
		SupervisorHandoffSocketPath:     value.supervisorHandoffSocketPath,
		SupervisorStatusPath:            value.supervisorStatusPath(),
		OfficeRegistrationSocketPath:    value.officeRegistrationSocketPath,
		PDFRegistrationSocketPath:       value.pdfRegistrationSocketPath,
		SubmitSocketRootDir:             stringsBeforeLastSlash(value.submitSocketPath),
		SupervisorHandoffSocketRootDir:  stringsBeforeLastSlash(value.supervisorHandoffSocketPath),
		OfficeRegistrationSocketRootDir: stringsBeforeLastSlash(value.officeRegistrationSocketPath),
		PDFRegistrationSocketRootDir:    stringsBeforeLastSlash(value.pdfRegistrationSocketPath),
		MaxPayloadBytes:                 value.maxPayloadBytes,
		FrameTimeout:                    value.frameTimeout,
		Registry:                        sandboxdispatch.ProductionV2Registry(value.officeWorkerUID, value.officeWorkerGID, value.pdfWorkerUID, value.pdfWorkerGID),
		SupervisorUID:                   value.supervisorUID,
		SupervisorGID:                   value.supervisorGID,
		SubmitterUID:                    value.submitterUID,
		SubmitterGID:                    value.submitterGID,
		WorkerUIDByParser: map[string]int{
			sandboxdispatch.ParserTypeOffice: value.officeWorkerUID,
			sandboxdispatch.ParserTypePDF:    value.pdfWorkerUID,
		},
		WorkerGIDByParser: map[string]int{
			sandboxdispatch.ParserTypeOffice: value.officeWorkerGID,
			sandboxdispatch.ParserTypePDF:    value.pdfWorkerGID,
		},
	}
}

// LoadProduction snapshots the environment exactly once. The dispatcher has its
// own closed allowlist; all unknown KNOWVAULT_* variables are rejected rather
// than silently ignored.
func LoadProduction() (Config, error) {
	return loadProduction(os.Environ())
}

func loadProduction(environment []string) (Config, error) {
	allowed := map[string]struct{}{
		rootDirEnvironment:         {},
		submitSocketEnvironment:    {},
		handoffSocketEnvironment:   {},
		officeSocketEnvironment:    {},
		pdfSocketEnvironment:       {},
		supervisorUIDEnvironment:   {},
		supervisorGIDEnvironment:   {},
		submitterUIDEnvironment:    {},
		submitterGIDEnvironment:    {},
		officeWorkerUIDEnvironment: {},
		officeWorkerGIDEnvironment: {},
		pdfWorkerUIDEnvironment:    {},
		pdfWorkerGIDEnvironment:    {},
		maxPayloadEnvironment:      {},
		frameTimeoutEnvironment:    {},
	}
	values := make(map[string]string, len(allowed))
	seenFolded := make(map[string]struct{}, len(allowed))

	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			if hasASCIIPrefixFold(entry, environmentPrefix) {
				return Config{}, dispatcherError(CodeConfigInvalid)
			}
			continue
		}
		if !hasASCIIPrefixFold(name, environmentPrefix) {
			continue
		}
		folded := strings.ToUpper(name)
		if _, duplicate := seenFolded[folded]; duplicate {
			return Config{}, dispatcherError(CodeConfigInvalid)
		}
		seenFolded[folded] = struct{}{}
		if _, accepted := allowed[name]; !accepted {
			return Config{}, dispatcherError(CodeConfigInvalid)
		}
		values[name] = value
	}
	if len(values) != len(allowed) {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}

	maxPayload, ok := parseCanonicalInt(values[maxPayloadEnvironment], minimumMaxPayload, maximumMaxPayload)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	frameMS, ok := parseCanonicalInt(values[frameTimeoutEnvironment], minimumFrameMS, maximumFrameMS)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	rootDir, ok := parseCanonicalAbsolutePath(values[rootDirEnvironment])
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	submitSocket, ok := parseCanonicalUnixSocket(values[submitSocketEnvironment])
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	handoffSocket, ok := parseCanonicalUnixSocket(values[handoffSocketEnvironment])
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	officeSocket, ok := parseCanonicalUnixSocket(values[officeSocketEnvironment])
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	pdfSocket, ok := parseCanonicalUnixSocket(values[pdfSocketEnvironment])
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	parseIdentity := func(name string, minimum int) (int, bool) {
		return parseCanonicalInt(values[name], minimum, maximumIdentity)
	}
	supervisorUID, ok := parseIdentity(supervisorUIDEnvironment, 0)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	supervisorGID, ok := parseIdentity(supervisorGIDEnvironment, 0)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	submitterUID, ok := parseIdentity(submitterUIDEnvironment, 0)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	submitterGID, ok := parseIdentity(submitterGIDEnvironment, 0)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	officeUID, ok := parseIdentity(officeWorkerUIDEnvironment, 1)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	officeGID, ok := parseIdentity(officeWorkerGIDEnvironment, 1)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	pdfUID, ok := parseIdentity(pdfWorkerUIDEnvironment, 1)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	pdfGID, ok := parseIdentity(pdfWorkerGIDEnvironment, 1)
	if !ok {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}

	config := Config{
		rootDir: rootDir, submitSocketPath: submitSocket, supervisorHandoffSocketPath: handoffSocket,
		officeRegistrationSocketPath: officeSocket, pdfRegistrationSocketPath: pdfSocket,
		supervisorUID: supervisorUID, supervisorGID: supervisorGID,
		submitterUID: submitterUID, submitterGID: submitterGID,
		officeWorkerUID: officeUID, officeWorkerGID: officeGID,
		pdfWorkerUID: pdfUID, pdfWorkerGID: pdfGID,
		maxPayloadBytes: maxPayload, frameTimeout: time.Duration(frameMS) * time.Millisecond,
	}
	if !config.matchesManifestTuple() {
		return Config{}, dispatcherError(CodeConfigInvalid)
	}
	return config, nil
}

func dispatcherError(code ErrorCode) error { return &Error{code: code} }

func hasASCIIPrefixFold(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func parseCanonicalInt(value string, minimum, maximum int) (int, bool) {
	parsed, err := strconv.Atoi(value)
	valid := err == nil && value == strconv.Itoa(parsed) && parsed >= minimum && parsed <= maximum
	return parsed, valid
}

func parseCanonicalAbsolutePath(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) || !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") || strings.Contains(value, "/./") || strings.Contains(value, "/../") || strings.ContainsAny(value, "\x00\r\n\t") {
		return "", false
	}
	return value, true
}

func parseCanonicalUnixSocket(value string) (string, bool) {
	if !strings.HasPrefix(value, "unix://") {
		return "", false
	}
	return parseCanonicalAbsolutePath(strings.TrimPrefix(value, "unix://"))
}
