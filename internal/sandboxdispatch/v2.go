package sandboxdispatch

// This file is the SAFE one-shot v2 runtime. It is intentionally separate from
// dispatch.go: v1 keeps its accepted reusable, single-socket protocol while v2
// has physically separate submit/Office/PDF listeners (and an optional OCR
// listener), a registry-owned
// capability tuple, and a worker registration that can be consumed exactly once.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	RegistrationVersionV2         = "sandbox-registration-v2"
	RegistrationAcceptedVersionV2 = "sandbox-registration-accepted-v2"
	SupervisorHandoffVersionV1    = "sandbox-supervisor-handoff-v1"
	SupervisorHandoffAcceptedV1   = "sandbox-supervisor-handoff-accepted-v1"
	maxV2HandoffLifetime          = 15 * time.Minute
	maxV2ReplayEntries            = 4096
	maxV2Connections              = 1024
	// Replay identities survive their protocol deadline for a bounded window,
	// so a terminal token cannot be replayed immediately after expiry.  The
	// map is never allowed to evict a live marker; admission is refused when
	// the bounded table is full.
	v2ReplayRetention = 15 * time.Minute
)

var supervisorHandoffIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{31,127}$`)
var namespaceInodeRe = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var cgroupPathRe = regexp.MustCompile(`^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

func validNamespaceInode(value string) bool { return namespaceInodeRe.MatchString(value) }
func validCgroupPath(value string) bool {
	return len(value) <= 4096 && cgroupPathRe.MatchString(value)
}

// RegisterHelloV2 binds a fresh one-shot parser peer to the qualified artifact
// and protected profile selected by the deployment registry. ParserType is also
// checked against the physical listener; it is descriptive, never a role
// selector.
type RegisterHelloV2 struct {
	SchemaVersion              string   `json:"schema_version"`
	WorkerID                   string   `json:"worker_id"`
	ParserType                 string   `json:"parser_type"`
	ArtifactHash               string   `json:"artifact_hash"`
	SandboxProfileRevision     string   `json:"sandbox_profile_revision"`
	ObservationProfileRevision string   `json:"observation_profile_revision"`
	SupervisorHandoffID        string   `json:"supervisor_handoff_id"`
	OneShot                    bool     `json:"one_shot"`
	MaxLeases                  int      `json:"max_leases"`
	Capabilities               []string `json:"capabilities"`
}

// SupervisorHandoffV1 is the JSON metadata accompanying one pidfd transferred
// through the dedicated handoff socket. The descriptor itself never appears in
// JSON. A handoff is single-use and registration correlation is by HandoffID.
type SupervisorHandoffV1 struct {
	SchemaVersion              string `json:"schema_version"`
	HandoffID                  string `json:"handoff_id"`
	ParserType                 string `json:"parser_type"`
	ArtifactHash               string `json:"artifact_hash"`
	SandboxProfileRevision     string `json:"sandbox_profile_revision"`
	ObservationProfileRevision string `json:"observation_profile_revision"`
	PIDFDTransport             string `json:"pidfd_transport"`
	PIDNamespaceInode          string `json:"pid_namespace_inode"`
	CgroupPath                 string `json:"cgroup_path"`
	ExpectedWorkerUID          int    `json:"expected_worker_uid"`
	ExpectedWorkerGID          int    `json:"expected_worker_gid"`
	IssuedAt                   string `json:"issued_at"`
	ExpiresAt                  string `json:"expires_at"`
	OneShot                    bool   `json:"one_shot"`
	MaxLeases                  int    `json:"max_leases"`
}

func (h SupervisorHandoffV1) Validate(now time.Time) error {
	if h.SchemaVersion != SupervisorHandoffVersionV1 || !supervisorHandoffIDRe.MatchString(h.HandoffID) ||
		(h.ParserType != ParserTypeOffice && h.ParserType != ParserTypePDF && h.ParserType != ParserTypeOCR) || h.PIDFDTransport != "SCM_RIGHTS" ||
		!sha256Re.MatchString(h.ArtifactHash) || !validProfileRevision(h.SandboxProfileRevision) || !validProfileRevision(h.ObservationProfileRevision) ||
		!validNamespaceInode(h.PIDNamespaceInode) || !validCgroupPath(h.CgroupPath) || h.ExpectedWorkerUID < 1 ||
		h.ExpectedWorkerUID > 2147483647 || h.ExpectedWorkerGID < 1 || h.ExpectedWorkerGID > 2147483647 || !h.OneShot || h.MaxLeases != 1 {
		return fmt.Errorf("%w: supervisor handoff", ErrRegistrationRejected)
	}
	issued, err := parseTimestamp(h.IssuedAt)
	if err != nil || issued.After(now) {
		return fmt.Errorf("%w: supervisor issued_at", ErrRegistrationRejected)
	}
	expires, err := parseTimestamp(h.ExpiresAt)
	if err != nil || !expires.After(issued) || !expires.After(now) || expires.Sub(issued) > maxV2HandoffLifetime {
		return fmt.Errorf("%w: supervisor expires_at", ErrRegistrationRejected)
	}
	return nil
}

func (h RegisterHelloV2) Validate(expectedParser string) error {
	if h.SchemaVersion != RegistrationVersionV2 || !validID(h.WorkerID) ||
		h.ParserType != expectedParser || !validParserType(h.ParserType) ||
		!sha256Re.MatchString(h.ArtifactHash) || !validProfileRevision(h.SandboxProfileRevision) ||
		!validProfileRevision(h.ObservationProfileRevision) || !supervisorHandoffIDRe.MatchString(h.SupervisorHandoffID) || !h.OneShot || h.MaxLeases != 1 {
		return fmt.Errorf("%w: v2 registration", ErrRegistrationRejected)
	}
	if len(h.Capabilities) != 2 || h.Capabilities[0] != CapabilityPullJob || h.Capabilities[1] != CapabilityPushOutcome {
		return fmt.Errorf("%w: v2 capabilities", ErrRegistrationRejected)
	}
	return nil
}

// RegistrationV2 is the schema-facing name used by deployment code.
type RegistrationV2 = RegisterHelloV2

// V2PeerHandle is the supervisor-owned identity of a one-shot parser peer. The
// built-in Linux admission path fills PIDFD/NamespaceID from the dedicated
// PID namespace and cgroup evidence; the dispatcher never accepts these fields
// from a worker frame as authority.
type V2PeerHandle struct {
	WorkerID     string
	ParserType   string
	ArtifactHash string
	// ArtifactIdentity is retained as a descriptive alias for callers that
	// used the pre-schema terminology; both fields are always identical.
	ArtifactIdentity           string
	SandboxProfileRevision     string
	ObservationProfileRevision string
	Observation                Observation
	PIDFD                      int
	NamespaceID                string
	// cgroupFD pins the exact cgroup instance observed at registration. It is
	// intentionally private: callers cannot substitute a path/descriptor.
	cgroupFD int
}

// V2Supervisor is the mandatory process-lifetime boundary for v2. Every call
// receives a caller-owned deadline context. ConfirmGone must prove that the
// parser pidfd has exited and its dedicated cgroup is empty; Teardown must
// fence/kill the peer and descendants. No successful result is relayed unless
// ConfirmGone succeeds.
type V2Supervisor interface {
	Teardown(context.Context, V2PeerHandle) error
	ConfirmGone(context.Context, V2PeerHandle) error
}

// V2RegistryEntry is one deployment-owned capability. Submitters can request
// only the exact ParserRequest tuple and media pair in this registry. The
// registered worker must present the same qualified artifact and sandbox
// profile. MaxLeaseDuration, when set, bounds the requested deadline window.
type V2RegistryEntry struct {
	ParserRequest    ParserRequestV1
	ArtifactIdentity string
	// ArtifactHash is the schema name. ArtifactIdentity is accepted as a
	// source-compatible alias, but NewV2 normalizes and compares one value.
	ArtifactHash     string
	MediaType        string
	MaxLeaseDuration time.Duration
	// ExpectedLimits is the immutable kernel profile for this capability. The
	// registration observer must match its CPU, memory and PID bounds exactly;
	// the wall-clock member is also the only accepted submit deadline window.
	ExpectedLimits Limits
	// RuntimeProfileHash is pinned by the deployment registry rather than
	// minted from worker input. NewV2 validates it against ExpectedLimits.
	RuntimeProfileHash string
	// ExpectedWorkerUID/GID are the role policy for the parser socket. The
	// values in a supervisor handoff must match both this policy and the
	// registration socket's SO_PEERCRED.
	ExpectedWorkerUID int
	ExpectedWorkerGID int
}

func (e V2RegistryEntry) artifactHash() string {
	if e.ArtifactHash != "" {
		return e.ArtifactHash
	}
	return e.ArtifactIdentity
}

// V2Capability is a descriptive alias for callers that prefer capability
// terminology; it has no different semantics.
type V2Capability = V2RegistryEntry

// V2Config owns the four mandatory, physically distinct v2 sockets. The OCR
// registration socket/role is optional and is enabled only when all of its
// socket, role identity, and registry entries are supplied together.
// SubmitSocketPath is reachable by submitters only; each parser registration
// socket is mounted only into its matching one-shot worker.
type V2Config struct {
	// RootDir is the pre-created, dispatcher-owned deployment root. Each role
	// socket must be the direct child of its own role root below this directory;
	// sharing a parent (or placing a socket outside RootDir) is rejected.
	RootDir                     string
	SubmitSocketPath            string
	SupervisorHandoffSocketPath string
	// SupervisorStatusPath is optional for isolated protocol callers. Production
	// composition supplies the canonical status.json sibling of the handoff
	// socket; arbitrary production paths are rejected.
	SupervisorStatusPath            string
	OfficeRegistrationSocketPath    string
	PDFRegistrationSocketPath       string
	OCRRegistrationSocketPath       string
	SubmitSocketRootDir             string
	SupervisorHandoffSocketRootDir  string
	OfficeRegistrationSocketRootDir string
	PDFRegistrationSocketRootDir    string
	OCRRegistrationSocketRootDir    string
	MaxPayloadBytes                 int
	FrameTimeout                    time.Duration
	Registry                        []V2RegistryEntry
	// SupervisorUID/GID are the only credentials admitted on the dedicated
	// supervisor-handoff socket. Worker credentials are pinned per registry
	// capability, not supplied by a worker frame.
	SupervisorUID int
	SupervisorGID int
	// SubmitterUID/GID are the exact credentials admitted on the submit socket
	// and the owner of that socket. They are independent of supervisor and
	// parser role identities.
	SubmitterUID int
	SubmitterGID int
	// WorkerUIDByParser/GIDByParser are deployment-owned role policy maps. Both
	// maps must contain exactly OFFICE and PDF entries, plus OCR when the
	// optional OCR role is enabled. They are copied before the dispatcher starts
	// so callers cannot mutate authority concurrently.
	WorkerUIDByParser map[string]int
	WorkerGIDByParser map[string]int
}

type v2Worker struct {
	conn    *net.UnixConn
	hello   RegisterHelloV2
	entry   V2RegistryEntry
	obs     Observation
	peer    V2PeerHandle
	handoff SupervisorHandoffV1
	active  *v2Lease
	ready   bool
	used    bool
	writeMu sync.Mutex
}

type v2Lease struct {
	job           JobV2
	requestBytes  []byte
	worker        *v2Worker
	lease         LeaseV2
	payload       []byte
	resultBytes   []byte
	resultSeen    bool
	outcomeSeen   bool
	transferSent  bool
	runtimeHash   string
	executionID   string
	result        chan v2JobResult
	deadline      *time.Timer
	resolved      bool
	fencing       bool
	cleanupProven bool
}

type v2JobResult struct {
	outcome      OutcomeV2
	result       []byte
	confirmation *LimitConfirmationV2
	retryable    bool
}

// DispatcherV2 is the SAFE one-shot dispatcher. It never starts a parser
// process; an external supervisor supplies each fresh peer and its evidence.
type DispatcherV2 struct {
	cfg        V2Config
	observer   KernelObserver
	supervisor V2Supervisor
	submitLn   *net.UnixListener
	handoffLn  *net.UnixListener
	officeLn   *net.UnixListener
	pdfLn      *net.UnixListener
	ocrLn      *net.UnixListener

	mu                sync.Mutex
	workers           map[string]*v2Worker
	leases            map[string]*v2Lease
	terminal          map[string]time.Time
	handoffs          map[string]*v2Handoff
	handoffTerminal   map[string]time.Time
	conns             map[*net.UnixConn]struct{}
	closed            bool
	red               bool
	redCleanupStarted bool
	closeOnce         sync.Once
	connWG            sync.WaitGroup
	statusWriter      v2StatusWriter
	statusEpoch       string
	statusSequence    uint64
	statusRoles       map[string]v2StatusRoleState
	statusWriteMu     sync.Mutex
	statusLifeMu      sync.Mutex
	statusStop        chan struct{}
	statusDone        chan struct{}
	statusStarted     bool
	statusStopped     bool
	statusCloseOnce   sync.Once
	// relayMu linearizes submitter result publication with the RED latch. It
	// is deliberately separate from d.mu so RED can close blocked sockets
	// without a lock-order deadlock.
	relayMu sync.Mutex
}

// ParserReady reports advisory one-shot capacity for a parser role. It does
// not reserve the worker: submit admission remains the only authority and may
// still return TRANSFER_RETRY if the peer exits concurrently. External
// supervisors use this signal only to avoid publishing readiness before the
// accepted handoff has completed the worker registration handshake.
func (d *DispatcherV2) ParserReady(parserType string) bool {
	if d == nil || (parserType != ParserTypeOffice && parserType != ParserTypePDF && parserType != ParserTypeOCR) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	worker := d.workers[parserType]
	return !d.closed && !d.red && worker != nil && worker.ready && !worker.used && worker.active == nil
}

type v2Handoff struct {
	metadata           SupervisorHandoffV1
	pidfd              int
	cgroupFD           int
	statusCgroupPinned bool
	// peerPID is captured while fdinfo still contains the live PID. It lets
	// expiry/shutdown perform the special reaped-pidfd ConfirmGone path after
	// fdinfo transitions to Pid:-1 without weakening early admission proof.
	peerPID  int
	state    v2HandoffState
	reap     *time.Timer
	fdClosed bool
}

type v2HandoffState uint8

const (
	v2HandoffReceived v2HandoffState = iota + 1
	v2HandoffAcknowledged
	v2HandoffConsumed
	v2HandoffExpired
	v2HandoffClosed
)

// fenceV2Handoff takes ownership of an accepted-but-unregistered descriptor,
// kills the corresponding sandbox and proves it gone before closing the FD.
// It is used on ACK failure, expiry, registration rejection and shutdown so a
// supervisor cannot leak a live process merely because registration stopped
// halfway through.
func (d *DispatcherV2) fenceV2Handoff(handoff *v2Handoff) {
	if handoff == nil {
		return
	}
	d.mu.Lock()
	pidfd := handoff.pidfd
	if pidfd >= 0 {
		handoff.pidfd = -1
		handoff.fdClosed = true
	}
	cgroupFD := -1
	statusCgroupPinned := handoff.statusCgroupPinned
	if statusCgroupPinned {
		cgroupFD = handoff.cgroupFD
		handoff.cgroupFD = -1
		handoff.statusCgroupPinned = false
	}
	d.mu.Unlock()
	if pidfd < 0 {
		closeV2CgroupFD(cgroupFD)
		return
	}
	proofOK := false
	defer func() {
		closeV2PeerFD(pidfd)
		closeV2CgroupFD(cgroupFD)
		if proofOK && statusCgroupPinned && cgroupFD >= 0 {
			d.setV2RoleStatus(handoff.metadata.ParserType, handoff.metadata.HandoffID, v2RoleReaped, time.Time{})
		}
	}()
	pid, err := readV2PidfdPID(pidfd)
	if err != nil {
		d.markV2Red()
		return
	}
	if pid > 0 {
		if err := validateV2Pidfd(pidfd, pid, handoff.metadata.PIDNamespaceInode, handoff.metadata.CgroupPath); err != nil {
			d.markV2Red()
			return
		}
	} else if pid != -1 || handoff.peerPID < 1 {
		d.markV2Red()
		return
	}
	if statusCgroupPinned && cgroupFD < 0 {
		d.markV2Red()
		return
	}
	peer := V2PeerHandle{
		ParserType: handoff.metadata.ParserType, PIDFD: pidfd,
		NamespaceID: handoff.metadata.PIDNamespaceInode,
		Observation: Observation{PID: handoff.peerPID, CgroupPath: handoff.metadata.CgroupPath},
		cgroupFD:    cgroupFD,
	}
	proofOK = d.teardownAndConfirmV2(peer)
	if !proofOK || !statusCgroupPinned || cgroupFD < 0 {
		return
	}
	entry, ok := d.registryEntryForHandoff(handoff.metadata)
	if !ok {
		proofOK = false
		d.markV2Red()
		return
	}
	finalLimits, _, finalErr := readV2FinalLimits(handoff.metadata.CgroupPath, entry.ExpectedLimits.WallClockMS, cgroupFD)
	if finalErr != nil || !exactV2Limits(entry.ExpectedLimits, finalLimits) {
		proofOK = false
		d.markV2Red()
	}
}

func (d *DispatcherV2) supervisorContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d.cfg.FrameTimeout)
}

func mustParseV2Time(raw string) time.Time {
	parsed, _ := parseTimestamp(raw)
	return parsed
}

func (c V2Config) officePath() string {
	return c.OfficeRegistrationSocketPath
}

func (c V2Config) pdfPath() string {
	return c.PDFRegistrationSocketPath
}

func (c V2Config) ocrPath() string {
	return c.OCRRegistrationSocketPath
}

func (c V2Config) ocrRoleRequested() bool {
	return c.OCRRegistrationSocketPath != "" || c.OCRRegistrationSocketRootDir != ""
}

func (c V2Config) roleRoots() []string {
	roots := []string{c.SubmitSocketRootDir, c.SupervisorHandoffSocketRootDir, c.OfficeRegistrationSocketRootDir, c.PDFRegistrationSocketRootDir}
	if c.ocrRoleRequested() {
		roots = append(roots, c.OCRRegistrationSocketRootDir)
	}
	return roots
}

func (c V2Config) workerIdentity(parserType string) ([2]int, bool) {
	uid, uidOK := c.WorkerUIDByParser[parserType]
	gid, gidOK := c.WorkerGIDByParser[parserType]
	if !uidOK || !gidOK {
		return [2]int{}, false
	}
	return [2]int{uid, gid}, true
}

func cloneV2IntMap(source map[string]int) map[string]int {
	clone := make(map[string]int, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func expectedV2LeaseDuration(limits Limits) (time.Duration, bool) {
	if limits.WallClockMS < 1 || limits.WallClockMS > int64((1<<63-1)/int64(time.Millisecond)) {
		return 0, false
	}
	return time.Duration(limits.WallClockMS) * time.Millisecond, true
}

func validateV2RoleLayout(cfg V2Config, paths []string) error {
	if cfg.RootDir == "" || !filepath.IsAbs(cfg.RootDir) {
		return fmt.Errorf("%w: v2 root directory", ErrInvalidConfig)
	}
	root := filepath.Clean(cfg.RootDir)
	if !v2PathIsWithin(root, root) || filepath.Dir(root) == root {
		return fmt.Errorf("%w: v2 root directory", ErrInvalidConfig)
	}
	if err := validateV2DirectoryAncestry(root, root); err != nil {
		return fmt.Errorf("%w: v2 root directory", ErrInvalidConfig)
	}
	if err := validateV2FullAncestry(root); err != nil || validateV2DirectoryOwner(root) != nil {
		return fmt.Errorf("%w: v2 root directory", ErrInvalidConfig)
	}
	roots := cfg.roleRoots()
	if len(paths) != len(roots) {
		return fmt.Errorf("%w: v2 role layout cardinality", ErrInvalidConfig)
	}
	seen := make(map[string]struct{}, len(roots))
	for i, roleRoot := range roots {
		if roleRoot == "" || !filepath.IsAbs(roleRoot) {
			return fmt.Errorf("%w: v2 role root", ErrInvalidConfig)
		}
		roleRoot = filepath.Clean(roleRoot)
		if _, duplicate := seen[roleRoot]; duplicate {
			return fmt.Errorf("%w: v2 role-root separation", ErrInvalidConfig)
		}
		for prior := range seen {
			if v2PathIsWithin(prior, roleRoot) || v2PathIsWithin(roleRoot, prior) {
				return fmt.Errorf("%w: v2 role-root nesting", ErrInvalidConfig)
			}
		}
		seen[roleRoot] = struct{}{}
		if !v2PathIsWithin(root, roleRoot) || roleRoot == root {
			return fmt.Errorf("%w: v2 role-root containment", ErrInvalidConfig)
		}
		if err := validateV2DirectoryAncestry(root, roleRoot); err != nil {
			return fmt.Errorf("%w: v2 role-root ancestry", ErrInvalidConfig)
		}
		if err := validateV2DirectoryOwner(roleRoot); err != nil {
			return fmt.Errorf("%w: v2 role-root owner", ErrInvalidConfig)
		}
		if filepath.Dir(paths[i]) != roleRoot {
			return fmt.Errorf("%w: v2 socket role-root binding", ErrInvalidConfig)
		}
	}
	return nil
}

func v2PathIsWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

// validateV2DirectoryAncestry performs the deployment-owned, symlink-free
// layout check before any listener is opened. The Linux implementation also
// verifies exact euid ownership and non-group/world-writable modes.
func validateV2DirectoryAncestry(root, target string) error {
	if err := validateV2Directory(root); err != nil {
		return err
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ErrInvalidConfig
	}
	current := root
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := validateV2Directory(current); err != nil {
			return err
		}
	}
	return nil
}

func validateV2FullAncestry(target string) error {
	current := filepath.Clean(target)
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return ErrInvalidConfig
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateV2Directory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidConfig
	}
	return nil
}

// NewV2 validates the registry and opens the four mandatory sockets plus the
// optional OCR socket when configured. The paths are required to be distinct,
// so no peer can select a role by its first frame.
func NewV2(cfg V2Config) (*DispatcherV2, error) {
	if cfg.SubmitSocketPath == "" || cfg.SupervisorHandoffSocketPath == "" || cfg.officePath() == "" || cfg.pdfPath() == "" ||
		!validV2SupervisorStatusPath(cfg.SupervisorStatusPath, cfg.SupervisorHandoffSocketPath) ||
		cfg.MaxPayloadBytes <= 0 || cfg.FrameTimeout <= 0 || cfg.SupervisorUID < 0 || cfg.SupervisorGID < 0 || cfg.SupervisorUID > 2147483647 || cfg.SupervisorGID > 2147483647 ||
		cfg.SubmitterUID < 0 || cfg.SubmitterGID < 0 || cfg.SubmitterUID > 2147483647 || cfg.SubmitterGID > 2147483647 ||
		len(cfg.Registry) == 0 {
		return nil, fmt.Errorf("%w: v2 configuration", ErrInvalidConfig)
	}
	ocrRegistry, ocrUID, ocrGID := false, false, false
	for _, entry := range cfg.Registry {
		ocrRegistry = ocrRegistry || entry.ParserRequest.ParserType == ParserTypeOCR
	}
	_, ocrUID = cfg.WorkerUIDByParser[ParserTypeOCR]
	_, ocrGID = cfg.WorkerGIDByParser[ParserTypeOCR]
	ocrRequested := cfg.ocrRoleRequested() || ocrRegistry || ocrUID || ocrGID
	if ocrRequested && (!cfg.ocrRoleRequested() || cfg.ocrPath() == "" || cfg.OCRRegistrationSocketRootDir == "" || !ocrRegistry || !ocrUID || !ocrGID) {
		return nil, fmt.Errorf("%w: v2 OCR role requires socket, root, registry and identity", ErrInvalidConfig)
	}
	expectedRoleCount := 2
	if ocrRequested {
		expectedRoleCount++
	}
	if len(cfg.WorkerUIDByParser) != expectedRoleCount || len(cfg.WorkerGIDByParser) != expectedRoleCount {
		return nil, fmt.Errorf("%w: v2 worker role policy", ErrInvalidConfig)
	}
	roles := []string{ParserTypeOffice, ParserTypePDF}
	if ocrRequested {
		roles = append(roles, ParserTypeOCR)
	}
	for _, role := range roles {
		uid, uidOK := cfg.WorkerUIDByParser[role]
		gid, gidOK := cfg.WorkerGIDByParser[role]
		if !uidOK || !gidOK || uid < 1 || uid > 2147483647 || gid < 1 || gid > 2147483647 {
			return nil, fmt.Errorf("%w: v2 worker role policy", ErrInvalidConfig)
		}
	}
	// Socket mode 0600 makes UID the authority. Every role therefore needs a
	// distinct UID; matching only the complete UID/GID pair would let a peer
	// reachable through one role's mount authenticate as another role.
	roleUIDs := []struct {
		name string
		uid  int
		gid  int
	}{
		{"supervisor", cfg.SupervisorUID, cfg.SupervisorGID},
		{"submitter", cfg.SubmitterUID, cfg.SubmitterGID},
		{"office", cfg.WorkerUIDByParser[ParserTypeOffice], cfg.WorkerGIDByParser[ParserTypeOffice]},
		{"pdf", cfg.WorkerUIDByParser[ParserTypePDF], cfg.WorkerGIDByParser[ParserTypePDF]},
	}
	if ocrRequested {
		roleUIDs = append(roleUIDs, struct {
			name string
			uid  int
			gid  int
		}{"ocr", cfg.WorkerUIDByParser[ParserTypeOCR], cfg.WorkerGIDByParser[ParserTypeOCR]})
	}
	for i := range roleUIDs {
		for j := i + 1; j < len(roleUIDs); j++ {
			if roleUIDs[i].uid == roleUIDs[j].uid {
				return nil, fmt.Errorf("%w: v2 role UID overlap %s/%s", ErrInvalidConfig, roleUIDs[i].name, roleUIDs[j].name)
			}
			if roleUIDs[i].gid == roleUIDs[j].gid {
				return nil, fmt.Errorf("%w: v2 role GID overlap %s/%s", ErrInvalidConfig, roleUIDs[i].name, roleUIDs[j].name)
			}
		}
	}
	// Copy the role maps before storing cfg: map mutation by a caller after
	// construction must never change admission authority.
	cfg.WorkerUIDByParser = cloneV2IntMap(cfg.WorkerUIDByParser)
	cfg.WorkerGIDByParser = cloneV2IntMap(cfg.WorkerGIDByParser)
	observer, supervisor, err := newV2PlatformSupervisor(cfg.FrameTimeout)
	if err != nil {
		return nil, err
	}
	paths := []string{filepath.Clean(cfg.SubmitSocketPath), filepath.Clean(cfg.SupervisorHandoffSocketPath), filepath.Clean(cfg.officePath()), filepath.Clean(cfg.pdfPath())}
	if ocrRequested {
		paths = append(paths, filepath.Clean(cfg.ocrPath()))
	}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if _, exists := seenPaths[path]; exists {
			return nil, fmt.Errorf("%w: v2 socket separation", ErrInvalidConfig)
		}
		seenPaths[path] = struct{}{}
	}
	if err := validateV2RoleLayout(cfg, paths); err != nil {
		return nil, err
	}
	cfg.RootDir = filepath.Clean(cfg.RootDir)
	cfg.SubmitSocketPath, cfg.SupervisorHandoffSocketPath = paths[0], paths[1]
	cfg.OfficeRegistrationSocketPath, cfg.PDFRegistrationSocketPath = paths[2], paths[3]
	if ocrRequested {
		cfg.OCRRegistrationSocketPath = paths[4]
	}
	roots := cfg.roleRoots()
	for i := range roots {
		roots[i] = filepath.Clean(roots[i])
	}
	cfg.SubmitSocketRootDir, cfg.SupervisorHandoffSocketRootDir = roots[0], roots[1]
	cfg.OfficeRegistrationSocketRootDir, cfg.PDFRegistrationSocketRootDir = roots[2], roots[3]
	if ocrRequested {
		cfg.OCRRegistrationSocketRootDir = roots[4]
	}
	seen := make(map[string]struct{}, len(cfg.Registry))
	rolePolicy := make(map[string]V2RegistryEntry, len(roles))
	hasOffice, hasPDF := false, false
	hasOCR := false
	for _, entry := range cfg.Registry {
		artifactHash := entry.artifactHash()
		expectedWindow, expectedWindowOK := expectedV2LeaseDuration(entry.ExpectedLimits)
		if err := entry.ParserRequest.Validate(); err != nil ||
			(entry.ArtifactHash != "" && entry.ArtifactIdentity != "" && entry.ArtifactHash != entry.ArtifactIdentity) ||
			(entry.ParserRequest.ParserType != ParserTypeOffice && entry.ParserRequest.ParserType != ParserTypePDF && entry.ParserRequest.ParserType != ParserTypeOCR) ||
			!sha256Re.MatchString(artifactHash) || !mediaTypeRe.MatchString(entry.MediaType) ||
			entry.MediaType != mediaTypeFor(entry.ParserRequest.MediaFamily) ||
			(entry.MaxLeaseDuration <= 0) || !entry.ExpectedLimits.valid() || !expectedWindowOK ||
			(entry.MaxLeaseDuration != expectedWindow) ||
			entry.RuntimeProfileHash != RuntimeProfileHash(entry.ParserRequest.ParserType, entry.ParserRequest.SandboxProfileRevision, entry.ExpectedLimits) ||
			entry.ExpectedWorkerUID < 1 || entry.ExpectedWorkerUID > 2147483647 ||
			entry.ExpectedWorkerGID < 1 || entry.ExpectedWorkerGID > 2147483647 {
			return nil, fmt.Errorf("%w: v2 registry", ErrInvalidConfig)
		}
		key := registryKey(entry.ParserRequest, entry.MediaType)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate v2 capability", ErrInvalidConfig)
		}
		seen[key] = struct{}{}
		if roleUID, ok := cfg.workerIdentity(entry.ParserRequest.ParserType); !ok || roleUID[0] != entry.ExpectedWorkerUID || roleUID[1] != entry.ExpectedWorkerGID {
			return nil, fmt.Errorf("%w: v2 worker role policy", ErrInvalidConfig)
		}
		if previous, ok := rolePolicy[entry.ParserRequest.ParserType]; ok {
			if !sameV2RegistrationPolicy(previous, entry) {
				// A registration identifies only the physical parser role. Multiple
				// media capabilities may share that role only when the worker and
				// kernel authority they register are exactly the same.
				return nil, fmt.Errorf("%w: heterogeneous v2 parser role", ErrInvalidConfig)
			}
		} else {
			rolePolicy[entry.ParserRequest.ParserType] = entry
		}
		hasOffice = hasOffice || entry.ParserRequest.ParserType == ParserTypeOffice
		hasPDF = hasPDF || entry.ParserRequest.ParserType == ParserTypePDF
		hasOCR = hasOCR || entry.ParserRequest.ParserType == ParserTypeOCR
	}
	if !hasOffice || !hasPDF {
		return nil, fmt.Errorf("%w: v2 office/pdf registry", ErrInvalidConfig)
	}
	if hasOCR != ocrRequested {
		return nil, fmt.Errorf("%w: v2 OCR registry/socket mismatch", ErrInvalidConfig)
	}
	registry := append([]V2RegistryEntry(nil), cfg.Registry...)
	for i := range registry {
		artifactHash := registry[i].artifactHash()
		registry[i].ArtifactHash = artifactHash
		registry[i].ArtifactIdentity = artifactHash
	}
	cfg.Registry = registry
	listeners := make([]*net.UnixListener, 0, len(paths))
	for index, path := range paths {
		if err := prepareV2SocketPath(path); err != nil {
			closeV2Listeners(listeners)
			return nil, fmt.Errorf("%w: v2 socket path", ErrInvalidConfig)
		}
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			closeV2Listeners(listeners)
			return nil, fmt.Errorf("%w: v2 listen", ErrInvalidConfig)
		}
		if err := chmodSocket(path); err != nil {
			_ = ln.Close()
			closeV2Listeners(listeners)
			return nil, fmt.Errorf("%w: v2 socket mode", ErrInvalidConfig)
		}
		// Parser listeners are owner-only and owned by the exact worker role
		// identity. This keeps the socket usable by a non-root parser without
		// widening it to group/world access; submit and supervisor listeners
		// remain owned by the dispatcher/supervisor boundary.
		if index == 0 {
			if chownV2Socket(path, cfg.SubmitterUID, cfg.SubmitterGID) != nil {
				_ = ln.Close()
				closeV2Listeners(listeners)
				return nil, fmt.Errorf("%w: v2 submit socket owner", ErrInvalidConfig)
			}
		} else if index == 1 {
			if chownV2Socket(path, cfg.SupervisorUID, cfg.SupervisorGID) != nil {
				_ = ln.Close()
				closeV2Listeners(listeners)
				return nil, fmt.Errorf("%w: v2 supervisor socket owner", ErrInvalidConfig)
			}
		} else {
			parserType := roles[index-2]
			identity, ok := cfg.workerIdentity(parserType)
			if !ok || chownV2ParserSocket(path, identity[0], identity[1]) != nil {
				_ = ln.Close()
				closeV2Listeners(listeners)
				return nil, fmt.Errorf("%w: v2 parser socket owner", ErrInvalidConfig)
			}
		}
		listeners = append(listeners, ln)
	}
	dispatcher := &DispatcherV2{
		cfg: cfg, observer: observer, supervisor: supervisor, submitLn: listeners[0], handoffLn: listeners[1], officeLn: listeners[2], pdfLn: listeners[3],
		workers: make(map[string]*v2Worker), leases: make(map[string]*v2Lease), terminal: make(map[string]time.Time), handoffs: make(map[string]*v2Handoff), handoffTerminal: make(map[string]time.Time),
		conns: make(map[*net.UnixConn]struct{}), statusRoles: initialV2StatusRoles(cfg),
	}
	if ocrRequested {
		dispatcher.ocrLn = listeners[4]
	}
	if err := dispatcher.initializeV2Status(); err != nil {
		closeV2Listeners(listeners)
		return nil, err
	}
	return dispatcher, nil
}

func sameV2RegistrationPolicy(left, right V2RegistryEntry) bool {
	return left.ParserRequest.ParserType == right.ParserRequest.ParserType &&
		left.ParserRequest.SandboxProfileRevision == right.ParserRequest.SandboxProfileRevision &&
		left.ParserRequest.ObservationProfileRevision == right.ParserRequest.ObservationProfileRevision &&
		left.artifactHash() == right.artifactHash() &&
		left.ExpectedLimits == right.ExpectedLimits &&
		left.RuntimeProfileHash == right.RuntimeProfileHash &&
		left.ExpectedWorkerUID == right.ExpectedWorkerUID &&
		left.ExpectedWorkerGID == right.ExpectedWorkerGID
}

// Close releases every v2 listener and fences any accepted peer. It is useful
// for embedding runtimes that construct a dispatcher before starting their
// serve loop; ListenAndServe performs the same shutdown automatically.
func (d *DispatcherV2) Close() {
	if d == nil {
		return
	}
	d.closeV2Listeners()
	d.shutdownV2()
	d.stopV2StatusHeartbeat()
}

func closeV2Listeners(listeners []*net.UnixListener) {
	for _, listener := range listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
}

// Socket paths are exposed separately so composition can mount each one with a
// least-privilege role. No combined v2 socket is provided.
func (d *DispatcherV2) SubmitSocketPath() string             { return d.cfg.SubmitSocketPath }
func (d *DispatcherV2) OfficeRegistrationSocketPath() string { return d.cfg.officePath() }
func (d *DispatcherV2) PDFRegistrationSocketPath() string    { return d.cfg.pdfPath() }
func (d *DispatcherV2) OCRRegistrationSocketPath() string    { return d.cfg.ocrPath() }
func (d *DispatcherV2) SupervisorHandoffSocketPath() string  { return d.cfg.SupervisorHandoffSocketPath }

// Ready reports the fail-closed readiness latch. A supervisor/ConfirmGone
// failure permanently fences new v2 work until this runtime is replaced.
func (d *DispatcherV2) Ready() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.closed && !d.red
}

// ListenAndServe accepts the mandatory listener roles and the optional OCR
// registration role until ctx is cancelled. A shutdown tears down every active
// peer before closing its sockets.
func (d *DispatcherV2) ListenAndServe(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	defer d.stopV2StatusHeartbeat()
	type acceptSpec struct {
		listener *net.UnixListener
		role     string
		submit   bool
	}
	specs := []acceptSpec{
		{listener: d.submitLn, submit: true},
		{listener: d.handoffLn},
		{listener: d.officeLn, role: ParserTypeOffice},
		{listener: d.pdfLn, role: ParserTypePDF},
	}
	if d.ocrLn != nil {
		specs = append(specs, acceptSpec{listener: d.ocrLn, role: ParserTypeOCR})
	}
	errCh := make(chan error, len(specs))
	var acceptWG sync.WaitGroup
	for _, spec := range specs {
		spec := spec
		acceptWG.Add(1)
		go func() {
			defer acceptWG.Done()
			for {
				conn, err := spec.listener.AcceptUnix()
				if err != nil {
					errCh <- err
					return
				}
				d.trackV2Conn(conn)
				if spec.submit {
					d.connWG.Add(1)
					go func() { defer d.connWG.Done(); d.handleV2Submitter(conn) }()
				} else if spec.listener == d.handoffLn {
					d.connWG.Add(1)
					go func() { defer d.connWG.Done(); d.handleV2Handoff(conn) }()
				} else {
					d.connWG.Add(1)
					go func() { defer d.connWG.Done(); d.handleV2Registration(conn, spec.role) }()
				}
			}
		}()
	}
	select {
	case <-ctx.Done():
		d.closeV2Listeners()
	case err := <-errCh:
		d.closeV2Listeners()
		if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			acceptWG.Wait()
			d.shutdownV2()
			return err
		}
	}
	acceptWG.Wait()
	d.shutdownV2()
	return nil
}

func (d *DispatcherV2) closeV2Listeners() {
	d.closeOnce.Do(func() {
		closeV2Listeners([]*net.UnixListener{d.submitLn, d.handoffLn, d.officeLn, d.pdfLn, d.ocrLn})
	})
}

func (d *DispatcherV2) trackV2Conn(conn *net.UnixConn) {
	d.mu.Lock()
	if d.closed || d.red || !v2ConnectionCapacityAvailable(len(d.conns)) {
		capacityExceeded := !d.closed && !d.red && !v2ConnectionCapacityAvailable(len(d.conns))
		d.mu.Unlock()
		_ = conn.Close()
		if capacityExceeded {
			// Connection tracking is bounded and fail-closed. Latch RED so a
			// flood cannot leave an untracked handler outside the drain set.
			d.markV2Red()
		}
		return
	}
	d.conns[conn] = struct{}{}
	d.mu.Unlock()
}

func v2ConnectionCapacityAvailable(count int) bool {
	return count >= 0 && count < maxV2Connections
}

func validV2Observation(obs Observation) bool {
	return obs.Limits.CPUMillis >= 1 && obs.Limits.MemoryBytes >= 1 && obs.Limits.PIDsMax >= 1 && obs.PID > 0 && !obs.ObservedAt.IsZero() && obs.CgroupPath != ""
}

func (d *DispatcherV2) markV2Red() {
	if d.latchV2Red() {
		d.publishV2Status()
	}
}

// latchV2Red closes admission and fences current peers without recursively
// attempting to write status. Status-write failures call this synchronous
// latch directly and make only one best-effort RED publication afterward.
func (d *DispatcherV2) latchV2Red() bool {
	// A result relay holds relayMu while checking the latch and writing its
	// bounded terminal frames. Taking the same mutex before setting RED makes
	// the latch a true publication barrier: an in-flight relay finishes before
	// RED, and every later relay observes RED and emits nothing.
	d.relayMu.Lock()
	d.mu.Lock()
	if d.red && d.redCleanupStarted {
		d.mu.Unlock()
		d.relayMu.Unlock()
		return false
	}
	d.red = true
	d.redCleanupStarted = true
	for role, status := range d.statusRoles {
		status.State = v2RoleRed
		status.LeaseDeadline = time.Time{}
		d.statusRoles[role] = status
	}
	active := make([]*v2Lease, 0, len(d.leases))
	for _, lease := range d.leases {
		active = append(active, lease)
	}
	workers := make([]*v2Worker, 0, len(d.workers))
	for _, worker := range d.workers {
		workers = append(workers, worker)
	}
	handoffs := make([]*v2Handoff, 0, len(d.handoffs))
	for id, handoff := range d.handoffs {
		handoffs = append(handoffs, handoff)
		delete(d.handoffs, id)
		if handoff != nil {
			recordV2ReplayLocked(d.handoffTerminal, id, mustParseV2Time(handoff.metadata.ExpiresAt))
			handoff.state = v2HandoffClosed
			if handoff.reap != nil {
				handoff.reap.Stop()
				handoff.reap = nil
			}
		}
	}
	conns := make([]*net.UnixConn, 0, len(d.conns))
	for conn := range d.conns {
		conns = append(conns, conn)
	}
	d.mu.Unlock()
	d.relayMu.Unlock()
	// Closing listeners prevents any new admission while the bounded teardown
	// drain runs. Never wait on connWG here: markV2Red can execute on one of the
	// handlers being drained.
	d.closeV2Listeners()
	for _, lease := range active {
		d.abortV2(lease, lease.transferSent)
	}
	for _, worker := range workers {
		d.dropV2Worker(worker)
	}
	for _, handoff := range handoffs {
		d.fenceV2Handoff(handoff)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	return true
}

// pruneV2ReplayLocked bounds replay identity retention to the protocol's own
// expiry windows. It is called before each admission and records are also
// capped defensively so hostile valid identifiers cannot grow process memory.
func (d *DispatcherV2) pruneV2ReplayLocked(now time.Time) {
	for id, expires := range d.terminal {
		if !expires.After(now) {
			delete(d.terminal, id)
		}
	}
	for id, expires := range d.handoffTerminal {
		if !expires.After(now) {
			delete(d.handoffTerminal, id)
		}
	}
}

func recordV2ReplayLocked(replays map[string]time.Time, id string, expires time.Time) bool {
	if id == "" {
		return false
	}
	if expires.IsZero() {
		return false
	}
	expires = expires.Add(v2ReplayRetention)
	if len(replays) >= maxV2ReplayEntries {
		// Never evict a live replay marker. The caller must reject admission
		// while the table is full; silently dropping one would reopen replay.
		return false
	}
	replays[id] = expires
	return true
}

func (d *DispatcherV2) untrackV2Conn(conn *net.UnixConn) {
	d.mu.Lock()
	delete(d.conns, conn)
	d.mu.Unlock()
}

func (d *DispatcherV2) handleV2Handoff(conn *net.UnixConn) {
	defer d.untrackV2Conn(conn)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.FrameTimeout))
	if uid, gid, err := v2PeerCredentials(conn); err != nil || uid != d.cfg.SupervisorUID || gid != d.cfg.SupervisorGID {
		return
	}
	kind, body, pidfd, err := readV2HandoffFrame(conn, maxFrameBody)
	if err != nil {
		d.markV2Red()
		return
	}
	if kind != kindSupervisorHandoffV2 {
		closeV2PeerFD(pidfd)
		d.markV2Red()
		return
	}
	var metadata SupervisorHandoffV1
	if err := decodeStrict(body, &metadata); err != nil || metadata.Validate(time.Now().UTC()) != nil {
		closeV2PeerFD(pidfd)
		d.markV2Red()
		return
	}
	roleIdentity, roleOK := d.cfg.workerIdentity(metadata.ParserType)
	if !roleOK || metadata.ExpectedWorkerUID != roleIdentity[0] || metadata.ExpectedWorkerGID != roleIdentity[1] || !d.registryForHandoff(metadata) {
		d.fenceV2Handoff(&v2Handoff{metadata: metadata, pidfd: pidfd})
		return
	}
	// Bind the descriptor to the supervisor's declared process boundary before
	// acknowledging it. Registration repeats this proof against SO_PEERCRED,
	// but an unverified handoff must never sit in the pending map waiting for a
	// worker to claim it.
	peerPID, peerErr := readV2PidfdPID(pidfd)
	if peerErr != nil || validateV2Pidfd(pidfd, peerPID, metadata.PIDNamespaceInode, metadata.CgroupPath) != nil {
		closeV2PeerFD(pidfd)
		d.markV2Red()
		return
	}
	statusCgroupFD := -1
	statusCgroupPinned := false
	if d.statusWriter != nil {
		statusCgroupFD, peerErr = openV2StatusCgroupFD(metadata.CgroupPath)
		if peerErr != nil {
			d.markV2Red()
			d.fenceV2Handoff(&v2Handoff{metadata: metadata, pidfd: pidfd})
			return
		}
		statusCgroupPinned = true
	}
	newHandoff := func() *v2Handoff {
		return &v2Handoff{metadata: metadata, pidfd: pidfd, cgroupFD: statusCgroupFD, statusCgroupPinned: statusCgroupPinned}
	}
	d.mu.Lock()
	if d.closed || d.red {
		d.mu.Unlock()
		d.fenceV2Handoff(newHandoff())
		return
	}
	d.pruneV2ReplayLocked(time.Now().UTC())
	if len(d.handoffs) >= maxV2ReplayEntries || len(d.handoffTerminal) >= maxV2ReplayEntries {
		d.mu.Unlock()
		d.fenceV2Handoff(newHandoff())
		return
	}
	if _, exists := d.handoffs[metadata.HandoffID]; exists {
		d.mu.Unlock()
		d.fenceV2Handoff(newHandoff())
		return
	}
	if _, used := d.handoffTerminal[metadata.HandoffID]; used {
		d.mu.Unlock()
		d.fenceV2Handoff(newHandoff())
		return
	}
	if d.statusWriter != nil && !d.canSetV2HandoffStatusLocked(metadata.ParserType, metadata.HandoffID) {
		d.mu.Unlock()
		d.fenceV2Handoff(newHandoff())
		return
	}
	handoff := &v2Handoff{metadata: metadata, pidfd: pidfd, cgroupFD: statusCgroupFD, statusCgroupPinned: statusCgroupPinned, peerPID: peerPID, state: v2HandoffReceived}
	d.handoffs[metadata.HandoffID] = handoff
	// Registration is forbidden from observing/consuming this handoff until the
	// bounded ACK has completed. Holding d.mu over the write closes the race in
	// which an ACK failure could otherwise leave a worker with a stolen pidfd.
	_ = conn.SetWriteDeadline(time.Now().Add(d.cfg.FrameTimeout))
	if writeFrame(conn, kindSupervisorHandoffAcceptedV2, []byte(SupervisorHandoffAcceptedV1)) != nil {
		delete(d.handoffs, metadata.HandoffID)
		recordV2ReplayLocked(d.handoffTerminal, metadata.HandoffID, mustParseV2Time(metadata.ExpiresAt))
		handoff.state = v2HandoffClosed
		d.mu.Unlock()
		d.fenceV2Handoff(handoff)
		return
	}
	handoff.state = v2HandoffAcknowledged
	handoff.reap = time.AfterFunc(time.Until(mustParseV2Time(metadata.ExpiresAt)), func() { d.expireV2Handoff(handoff) })
	statusChanged := d.setV2HandoffStatusLocked(metadata.ParserType, metadata.HandoffID)
	d.mu.Unlock()
	if d.statusWriter != nil && !statusChanged {
		d.markV2Red()
		return
	}
	if statusChanged {
		d.publishV2Status()
	}
}

func (d *DispatcherV2) shutdownV2() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	type shutdownLease struct {
		lease       *v2Lease
		transferred bool
	}
	active := make([]shutdownLease, 0, len(d.leases))
	for _, lease := range d.leases {
		active = append(active, shutdownLease{lease: lease, transferred: lease.transferSent})
	}
	conns := make([]*net.UnixConn, 0, len(d.conns))
	for conn := range d.conns {
		conns = append(conns, conn)
	}
	handoffs := make([]*v2Handoff, 0, len(d.handoffs))
	for id, handoff := range d.handoffs {
		handoffs = append(handoffs, handoff)
		delete(d.handoffs, id)
		if handoff != nil {
			handoff.state = v2HandoffClosed
			if handoff.reap != nil {
				handoff.reap.Stop()
				handoff.reap = nil
			}
		}
	}
	d.mu.Unlock()
	d.publishV2Status()
	for _, target := range active {
		d.abortV2(target.lease, target.transferred)
	}
	for _, handoff := range handoffs {
		d.fenceV2Handoff(handoff)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	d.connWG.Wait()
}

func (d *DispatcherV2) handleV2Registration(conn *net.UnixConn, role string) {
	defer d.untrackV2Conn(conn)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.FrameTimeout))
	kind, body, err := readFrame(conn, maxFrameBody)
	if err != nil || kind != kindRegisterV2 {
		return
	}
	var hello RegisterHelloV2
	if err := decodeStrict(body, &hello); err != nil || hello.Validate(role) != nil {
		return
	}
	entry, ok := d.registryForRegistration(hello)
	if !ok {
		return
	}
	handoff, ok := d.takeV2Handoff(hello)
	if !ok {
		return
	}
	keepHandoff := true
	defer func() {
		if keepHandoff {
			d.fenceV2Handoff(handoff)
		}
	}()
	obs, err := d.observer.Observe(conn)
	if err != nil {
		return
	}
	if !validV2Observation(obs) {
		return
	}
	if handoff.metadata.CgroupPath != obs.CgroupPath {
		return
	}
	peerPID, uid, gid, err := v2PeerCredentialsFull(conn)
	if err != nil || peerPID != obs.PID || uid != handoff.metadata.ExpectedWorkerUID || gid != handoff.metadata.ExpectedWorkerGID ||
		uid != entry.ExpectedWorkerUID || gid != entry.ExpectedWorkerGID {
		return
	}
	if obs.Limits.CPUMillis != entry.ExpectedLimits.CPUMillis || obs.Limits.MemoryBytes != entry.ExpectedLimits.MemoryBytes || obs.Limits.PIDsMax != entry.ExpectedLimits.PIDsMax ||
		(obs.Limits.WallClockMS != 0 && obs.Limits.WallClockMS != entry.ExpectedLimits.WallClockMS) {
		return
	}
	peer, err := proveV2Peer(hello, handoff.metadata, handoff.pidfd, peerPID, obs, uid, gid, entry)
	if err != nil {
		return
	}
	obs = peer.Observation
	worker := &v2Worker{
		conn: conn, hello: hello, entry: entry, obs: obs,
		peer: peer, handoff: handoff.metadata,
	}
	statusCgroupFD, installed := d.installV2ProvedWorker(role, worker, handoff)
	if !installed {
		return
	}
	// Ownership of the received pidfd moves from the pending handoff to this
	// registered worker. Every path from here is closed by dropV2Worker (or by a
	// resolved lease); the deferred pending-handoff close must not race a reused
	// descriptor number after registration failure.
	keepHandoff = false
	closeV2CgroupFD(statusCgroupFD)
	worker.writeMu.Lock()
	if err := conn.SetWriteDeadline(time.Now().Add(d.cfg.FrameTimeout)); err != nil || writeFrame(conn, kindRegisterV2Accepted, []byte(RegistrationAcceptedVersionV2)) != nil {
		worker.writeMu.Unlock()
		d.dropV2Worker(worker)
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		worker.writeMu.Unlock()
		d.dropV2Worker(worker)
		return
	}
	worker.writeMu.Unlock()
	d.mu.Lock()
	if d.workers[role] != worker || worker.used {
		d.mu.Unlock()
		d.dropV2Worker(worker)
		return
	}
	worker.ready = true
	statusChanged := d.setV2RoleStatusLocked(role, worker.handoff.HandoffID, v2RoleReady, time.Time{})
	d.mu.Unlock()
	if d.statusWriter != nil && !statusChanged {
		d.markV2Red()
		return
	}
	if statusChanged && !d.publishV2Status() {
		return
	}
	d.serveV2Worker(worker)
	d.dropV2Worker(worker)
}

// installV2ProvedWorker transfers the second, independently opened cgroup
// descriptor to the worker only after the post-proof admission checks pass.
// The pidfd remains owned by handoff until this function succeeds and the
// caller clears keepHandoff; rejected proofs close only this new cgroup fd.
func (d *DispatcherV2) installV2ProvedWorker(role string, worker *v2Worker, handoff *v2Handoff) (int, bool) {
	d.mu.Lock()
	if d.closed || d.red || d.workers[role] != nil {
		d.mu.Unlock()
		closeV2CgroupFD(worker.peer.cgroupFD)
		worker.peer.cgroupFD = -1
		return -1, false
	}
	d.workers[role] = worker
	statusCgroupFD := -1
	if handoff.statusCgroupPinned {
		statusCgroupFD = handoff.cgroupFD
		handoff.cgroupFD = -1
		handoff.statusCgroupPinned = false
	}
	d.mu.Unlock()
	return statusCgroupFD, true
}

func (d *DispatcherV2) takeV2Handoff(hello RegisterHelloV2) (*v2Handoff, bool) {
	d.mu.Lock()
	if _, used := d.handoffTerminal[hello.SupervisorHandoffID]; used {
		d.mu.Unlock()
		return nil, false
	}
	handoff, ok := d.handoffs[hello.SupervisorHandoffID]
	if !ok || handoff == nil || handoff.state != v2HandoffAcknowledged || handoff.metadata.ParserType != hello.ParserType || handoff.metadata.ExpiresAt == "" ||
		handoff.metadata.ArtifactHash != hello.ArtifactHash || handoff.metadata.SandboxProfileRevision != hello.SandboxProfileRevision || handoff.metadata.ObservationProfileRevision != hello.ObservationProfileRevision {
		d.mu.Unlock()
		return nil, false
	}
	expires, err := parseTimestamp(handoff.metadata.ExpiresAt)
	if err != nil || !expires.After(time.Now().UTC()) {
		delete(d.handoffs, hello.SupervisorHandoffID)
		recordV2ReplayLocked(d.handoffTerminal, hello.SupervisorHandoffID, expires)
		handoff.state = v2HandoffExpired
		if handoff.reap != nil {
			handoff.reap.Stop()
			handoff.reap = nil
		}
		d.mu.Unlock()
		d.fenceV2Handoff(handoff)
		return nil, false
	}
	handoff.state = v2HandoffConsumed
	if handoff.reap != nil {
		handoff.reap.Stop()
		handoff.reap = nil
	}
	delete(d.handoffs, hello.SupervisorHandoffID)
	recordV2ReplayLocked(d.handoffTerminal, hello.SupervisorHandoffID, mustParseV2Time(handoff.metadata.ExpiresAt))
	d.mu.Unlock()
	return handoff, true
}

// expireV2Handoff reaps an acknowledged handoff that never reached a worker
// registration. The identity is retained in handoffTerminal, so the same
// correlation token cannot replay a closed descriptor after expiry.
func (d *DispatcherV2) expireV2Handoff(handoff *v2Handoff) {
	if handoff == nil {
		return
	}
	d.mu.Lock()
	if handoff.state != v2HandoffAcknowledged || d.handoffs[handoff.metadata.HandoffID] != handoff {
		d.mu.Unlock()
		return
	}
	delete(d.handoffs, handoff.metadata.HandoffID)
	recordV2ReplayLocked(d.handoffTerminal, handoff.metadata.HandoffID, mustParseV2Time(handoff.metadata.ExpiresAt))
	handoff.state = v2HandoffExpired
	handoff.reap = nil
	d.mu.Unlock()
	d.fenceV2Handoff(handoff)
}

func (d *DispatcherV2) registryForRegistration(hello RegisterHelloV2) (V2RegistryEntry, bool) {
	for _, entry := range d.cfg.Registry {
		if entry.ParserRequest.ParserType == hello.ParserType && entry.ParserRequest.SandboxProfileRevision == hello.SandboxProfileRevision && entry.ParserRequest.ObservationProfileRevision == hello.ObservationProfileRevision && entry.artifactHash() == hello.ArtifactHash {
			return entry, true
		}
	}
	return V2RegistryEntry{}, false
}

func (d *DispatcherV2) registryForHandoff(handoff SupervisorHandoffV1) bool {
	_, ok := d.registryEntryForHandoff(handoff)
	return ok
}

func (d *DispatcherV2) registryEntryForHandoff(handoff SupervisorHandoffV1) (V2RegistryEntry, bool) {
	for _, entry := range d.cfg.Registry {
		if entry.ParserRequest.ParserType == handoff.ParserType &&
			entry.artifactHash() == handoff.ArtifactHash &&
			entry.ParserRequest.SandboxProfileRevision == handoff.SandboxProfileRevision &&
			entry.ParserRequest.ObservationProfileRevision == handoff.ObservationProfileRevision {
			return entry, true
		}
	}
	return V2RegistryEntry{}, false
}

func (d *DispatcherV2) dropV2Worker(worker *v2Worker) {
	d.mu.Lock()
	if d.workers[worker.hello.ParserType] == worker {
		delete(d.workers, worker.hello.ParserType)
	}
	active := worker.active
	worker.active = nil
	worker.ready = false
	d.mu.Unlock()
	if active != nil {
		d.abortV2(active, active.transferSent)
		return
	}
	// A registered one-shot peer can disconnect before receiving a lease. It
	// still consumed a supervisor handoff and must be proven gone; merely closing
	// the dispatcher copy of its pidfd would leave an untracked JVM/cgroup alive.
	if worker.peer.PIDFD >= 0 {
		cleanupProven := false
		if d.statusWriter != nil {
			cleanupProven = d.teardownAndConfirmV2Final(worker.peer, worker.entry.ExpectedLimits)
		} else {
			_ = d.teardownAndConfirmV2(worker.peer)
		}
		closeV2PeerFD(worker.peer.PIDFD)
		worker.peer.PIDFD = -1
		closeV2CgroupFD(worker.peer.cgroupFD)
		worker.peer.cgroupFD = -1
		if cleanupProven {
			d.setV2RoleStatus(worker.hello.ParserType, worker.handoff.HandoffID, v2RoleReaped, time.Time{})
		}
	}
	closeV2CgroupFD(worker.peer.cgroupFD)
	worker.peer.cgroupFD = -1
}

func (d *DispatcherV2) serveV2Worker(worker *v2Worker) {
	for {
		kind, body, err := readFrameWith(worker.conn, func(kind frameKind) int {
			if kind == kindResult {
				return d.cfg.MaxPayloadBytes
			}
			return maxFrameBody
		})
		if err != nil {
			return
		}
		switch kind {
		case kindClaim:
			if !d.handleV2Claim(worker, body) {
				return
			}
		case kindResult:
			if !d.handleV2Result(worker, body) {
				return
			}
		case kindOutcome:
			if !d.handleV2Outcome(worker, body) {
				return
			}
		default:
			return
		}
	}
}

func (d *DispatcherV2) handleV2Claim(worker *v2Worker, body []byte) bool {
	var claim Claim
	if err := decodeStrict(body, &claim); err != nil {
		return false
	}
	d.mu.Lock()
	active := worker.active
	if active == nil || active.resolved || active.lease.State != LeaseOffered ||
		claim.LeaseID != active.lease.LeaseID || claim.WorkerID != worker.hello.WorkerID {
		d.mu.Unlock()
		return false
	}
	active.lease.State = LeaseClaimed
	active.lease.State = LeaseTransferred
	active.transferSent = true
	leaseBytes, err := json.Marshal(active.lease)
	headerBytes, header := d.v2TransferHeaderLocked(active)
	payload := append([]byte(nil), active.payload...)
	d.mu.Unlock()
	if err != nil {
		d.abortV2(active, true)
		return false
	}
	if err := d.writeV2Transfer(worker, leaseBytes, headerBytes, payload); err != nil {
		d.abortV2(active, true)
		return false
	}
	_ = header
	return true
}

func (d *DispatcherV2) writeV2Transfer(worker *v2Worker, leaseBody, headerBody, payload []byte) error {
	worker.writeMu.Lock()
	defer worker.writeMu.Unlock()
	if err := writeFrame(worker.conn, kindLeaseV2, leaseBody); err != nil {
		return err
	}
	return writePayloadFrame(worker.conn, headerBody, payload)
}

func (d *DispatcherV2) handleV2Result(worker *v2Worker, body []byte) bool {
	d.mu.Lock()
	active := worker.active
	if active == nil || active.resolved || !active.transferSent || active.outcomeSeen || active.resultSeen || int64(len(body)) > active.job.ParserRequest.MaxOutputBytes {
		d.mu.Unlock()
		if active != nil && active.transferSent {
			d.abortV2(active, true)
		}
		return false
	}
	active.resultSeen = true
	active.resultBytes = append([]byte(nil), body...)
	d.mu.Unlock()
	return true
}

func (d *DispatcherV2) handleV2Outcome(worker *v2Worker, body []byte) bool {
	var outcome OutcomeV2
	if err := decodeStrict(body, &outcome); err != nil {
		if active := d.activeV2Worker(worker); active != nil && active.transferSent {
			d.abortV2(active, true)
		}
		return false
	}
	if err := outcome.Validate(); err != nil {
		if active := d.activeV2Worker(worker); active != nil && active.transferSent {
			d.abortV2(active, true)
		}
		return false
	}
	if !exactParserRequestInOutcome(body, outcome.ParserRequest) {
		if active := d.activeV2Worker(worker); active != nil && active.transferSent {
			d.abortV2(active, true)
		}
		return false
	}
	d.mu.Lock()
	active := worker.active
	if active == nil || active.resolved || active.outcomeSeen || d.leases[outcome.LeaseID] != active ||
		outcome.JobID != active.job.JobID || outcome.WorkerID == nil || *outcome.WorkerID != worker.hello.WorkerID ||
		outcome.ParserRequest != active.job.ParserRequest || outcome.OutputContract != active.job.ParserRequest.OutputContract {
		d.mu.Unlock()
		if active != nil && active.transferSent {
			d.abortV2(active, true)
		}
		return false
	}
	reportedAt, _ := parseTimestamp(outcome.ReportedAt)
	if reportedAt.Before(active.issuedAt()) || reportedAt.After(active.deadlineAt()) ||
		outcome.RuntimeProfileHash == nil || *outcome.RuntimeProfileHash != active.runtimeHash ||
		outcome.ExecutionConfirmationID == nil || *outcome.ExecutionConfirmationID != active.executionID {
		d.mu.Unlock()
		d.abortV2(active, true)
		return false
	}
	active.outcomeSeen = true
	resultBytes := append([]byte(nil), active.resultBytes...)
	transfer := outcome.Handoff.TransferState
	if transfer != TransferConfirmed || !active.resultSeen || outcome.ResultDigest == nil || digestFor(resultBytes) != *outcome.ResultDigest {
		d.mu.Unlock()
		d.abortV2(active, true)
		return false
	}
	peer := active.worker.peer
	d.mu.Unlock()
	if !d.ensureV2Gone(peer) {
		d.finishV2Quarantine(active)
		return false
	}
	finalLimits, finalObservedAt, finalErr := readV2FinalLimits(peer.Observation.CgroupPath, active.worker.entry.ExpectedLimits.WallClockMS, peer.cgroupFD)
	if finalErr != nil || !exactV2Limits(active.worker.entry.ExpectedLimits, finalLimits) {
		d.markV2Red()
		d.finishV2Quarantine(active)
		return false
	}
	d.mu.Lock()
	if d.red || d.closed || active.resolved || d.leases[active.lease.LeaseID] != active {
		d.mu.Unlock()
		return false
	}
	// The worker echoed the admission-time execution identity. The final
	// confirmation is dispatcher-owned and receives a fresh identity bound to
	// the final post-exit kernel read before it is relayed.
	active.executionID = ExecutionConfirmationID(active.runtimeHash, active.lease.LeaseID, active.lease.JobID, active.lease.WorkerID, finalObservedAt)
	outcome.Handoff.ConfirmationID = active.executionID
	outcome.ExecutionConfirmationID = stringPtrV2(active.executionID)
	active.lease.State = LeaseCompleted
	confirmation := d.v2ConfirmationLocked(active, finalLimits, finalObservedAt)
	active.cleanupProven = d.statusWriter != nil
	statusChanged := d.resolveV2Locked(active, v2JobResult{outcome: outcome, result: resultBytes, confirmation: confirmation})
	d.mu.Unlock()
	if statusChanged {
		d.publishV2Status()
	}
	return false
}

func exactV2Limits(expected, observed Limits) bool {
	return expected.CPUMillis == observed.CPUMillis && expected.MemoryBytes == observed.MemoryBytes && expected.PIDsMax == observed.PIDsMax && expected.WallClockMS == observed.WallClockMS
}

func (d *DispatcherV2) activeV2Worker(worker *v2Worker) *v2Lease {
	d.mu.Lock()
	defer d.mu.Unlock()
	return worker.active
}

func (d *DispatcherV2) handleV2Submitter(conn *net.UnixConn) {
	defer d.untrackV2Conn(conn)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.FrameTimeout))
	if uid, gid, err := v2PeerCredentials(conn); err != nil || uid != d.cfg.SubmitterUID || gid != d.cfg.SubmitterGID {
		return
	}
	kind, body, err := readFrame(conn, maxFrameBody)
	if err != nil {
		return
	}
	if kind == kindNativeReadinessV2 {
		d.handleV2NativeReadiness(conn, body)
		return
	}
	if kind != kindJobV2 {
		return
	}
	var job JobV2
	if err := decodeStrict(body, &job); err != nil {
		return
	}
	if !exactParserRequestInOutcome(body, job.ParserRequest) {
		return
	}
	now := time.Now().UTC()
	submittedAt, deadlineAt, err := job.Validate(now)
	if err != nil {
		return
	}
	jobEntry, ok := d.registryForJob(job, submittedAt, deadlineAt)
	if !ok {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.FrameTimeout))
	header, payload, err := readPayloadFrameV2(conn, d.cfg.MaxPayloadBytes)
	if err != nil || (header.LeaseID != "" && header.LeaseID != job.LeaseID) || header.RuntimeProfileHash != "" || header.ExecutionConfirmationID != "" {
		return
	}
	if int64(len(payload)) > job.ParserRequest.MaxInputBytes || digestFor(payload) != job.InputArtifact.ContentDigest {
		return
	}
	terminalDeadline := deadlineAt
	if terminalDeadline.Before(time.Now()) {
		return
	}
	if err := conn.SetDeadline(terminalDeadline); err != nil {
		return
	}
	requestBytes, err := json.Marshal(job.ParserRequest)
	if err != nil {
		return
	}
	d.mu.Lock()
	if d.closed || d.red {
		d.mu.Unlock()
		return
	}
	worker := d.workers[job.ParserRequest.ParserType]
	d.pruneV2ReplayLocked(time.Now().UTC())
	// Reserve a replay-table slot for every admitted lease. A terminal lease
	// must never discover a full table and lose its replay fence.
	if len(d.terminal)+len(d.leases) >= maxV2ReplayEntries {
		d.mu.Unlock()
		return
	}
	if _, done := d.terminal[job.LeaseID]; done {
		d.mu.Unlock()
		return
	}
	if worker == nil || !worker.ready || worker.used || worker.active != nil ||
		!sameV2RegistrationPolicy(worker.entry, jobEntry) {
		d.mu.Unlock()
		d.writeV2SubmitResult(conn, v2JobResult{outcome: retryOutcomeV2ForJob(job), retryable: true})
		return
	}
	worker.used = true
	attempt := 1
	lease := &v2Lease{
		job: job, requestBytes: requestBytes, worker: worker, payload: append([]byte(nil), payload...),
		lease:  LeaseV2{SchemaVersion: LeaseVersionV2, LeaseID: job.LeaseID, JobID: job.JobID, WorkerID: worker.hello.WorkerID, ParserRequest: job.ParserRequest, IssuedAt: submittedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: deadlineAt.UTC().Format(time.RFC3339Nano), Attempt: attempt, State: LeaseOffered},
		result: make(chan v2JobResult, 1),
	}
	lease.runtimeHash = d.v2RuntimeHashLocked(lease)
	lease.executionID = d.v2ExecutionIDLocked(lease)
	worker.active = lease
	d.leases[job.LeaseID] = lease
	lease.deadline = time.AfterFunc(time.Until(deadlineAt), func() { d.expireV2(lease) })
	offerBytes, err := json.Marshal(lease.lease)
	statusChanged := d.setV2RoleStatusLocked(job.ParserRequest.ParserType, worker.handoff.HandoffID, v2RoleBusy, deadlineAt)
	d.mu.Unlock()
	if d.statusWriter != nil && !statusChanged {
		d.markV2Red()
		return
	}
	if statusChanged && !d.publishV2Status() {
		return
	}
	if err != nil || d.writeV2Offer(worker, offerBytes) != nil {
		d.abortV2(lease, false)
		return
	}
	result := <-lease.result
	d.writeV2SubmitResult(conn, result)
}

func (d *DispatcherV2) writeV2Offer(worker *v2Worker, body []byte) error {
	worker.writeMu.Lock()
	defer worker.writeMu.Unlock()
	return writeFrame(worker.conn, kindLeaseV2, body)
}

func (d *DispatcherV2) writeV2SubmitResult(conn *net.UnixConn, result v2JobResult) {
	// RED is a linearization point: once latched, no terminal outcome, result,
	// or limits frame may be published to a submitter. The lock is held only
	// for the gate; socket I/O remains bounded by the caller's deadline and is
	// never performed while d.mu is held.
	d.relayMu.Lock()
	d.mu.Lock()
	if d.red || d.closed {
		d.mu.Unlock()
		d.relayMu.Unlock()
		return
	}
	d.mu.Unlock()
	_ = writeFrame(conn, kindOutcome, marshalOutcome(result.outcome))
	if result.result != nil {
		_ = writeResultFrame(conn, result.result, d.cfg.MaxPayloadBytes)
	}
	if result.confirmation != nil {
		_ = writeFrame(conn, kindLimits, marshalOutcome(result.confirmation))
	}
	d.relayMu.Unlock()
}

func (d *DispatcherV2) registryForJob(job JobV2, submitted, deadline time.Time) (V2RegistryEntry, bool) {
	for _, entry := range d.cfg.Registry {
		if entry.ParserRequest != job.ParserRequest || entry.MediaType != job.InputArtifact.MediaType {
			continue
		}
		window := deadline.Sub(submitted)
		if entry.MaxLeaseDuration > 0 && window > entry.MaxLeaseDuration {
			continue
		}
		// Wall-clock is a pinned finite limit, not a submitter-selected hint.
		// RFC3339 timestamps are parsed before this comparison, so fractional
		// windows remain exact and cannot drift during lease construction.
		if entry.ExpectedLimits.WallClockMS != window.Milliseconds() {
			continue
		}
		return entry, true
	}
	return V2RegistryEntry{}, false
}

func registryKey(request ParserRequestV1, mediaType string) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%s", request.ParserType, request.Operation, request.MediaFamily, request.SandboxProfileRevision, request.ObservationProfileRevision, mediaType, request.MaxInputBytes, request.MaxOutputBytes, request.MaxUnits, request.MaxPages, request.MaxDecodedPixels, request.OutputContract)
}

func (d *DispatcherV2) v2RuntimeHashLocked(active *v2Lease) string {
	return active.worker.entry.RuntimeProfileHash
}

func (d *DispatcherV2) v2ExecutionIDLocked(active *v2Lease) string {
	observed := active.obsTime()
	return ExecutionConfirmationID(active.runtimeHash, active.lease.LeaseID, active.lease.JobID, active.lease.WorkerID, observed)
}

func (d *DispatcherV2) v2TransferHeaderLocked(active *v2Lease) ([]byte, PayloadHeaderV2) {
	header := PayloadHeaderV2{LeaseID: active.lease.LeaseID, RuntimeProfileHash: active.runtimeHash, ExecutionConfirmationID: active.executionID}
	raw, _ := json.Marshal(header)
	return raw, header
}

func (d *DispatcherV2) v2ConfirmationLocked(active *v2Lease, limits Limits, observed time.Time) *LimitConfirmationV2 {
	return &LimitConfirmationV2{SchemaVersion: LimitsVersionV2, LeaseID: active.lease.LeaseID, JobID: active.lease.JobID, WorkerID: active.lease.WorkerID, ObservedAt: observed.UTC().Format(time.RFC3339), ObservationMethod: "KERNEL_CGROUP_NAMESPACE", ParserRequest: active.job.ParserRequest, Limits: limits, RuntimeProfileHash: active.runtimeHash, ExecutionConfirmationID: active.executionID, Confirmed: true}
}

func (d *DispatcherV2) ensureV2Gone(peer V2PeerHandle) bool {
	ctx, cancel := d.supervisorContext()
	confirmErr := d.supervisor.ConfirmGone(ctx, peer)
	cancel()
	if confirmErr == nil {
		return true
	}
	d.markV2Red()
	ctx, cancel = d.supervisorContext()
	teardownErr := d.supervisor.Teardown(ctx, peer)
	cancel()
	if teardownErr != nil {
		d.markV2Red()
		return false
	}
	ctx, cancel = d.supervisorContext()
	confirmErr = d.supervisor.ConfirmGone(ctx, peer)
	cancel()
	if confirmErr != nil {
		d.markV2Red()
		return false
	}
	// The initial proof failed, so readiness remains red even if teardown
	// eventually made this particular peer disappear.
	return false
}

func (d *DispatcherV2) teardownAndConfirmV2(peer V2PeerHandle) bool {
	ctx, cancel := d.supervisorContext()
	teardownErr := d.supervisor.Teardown(ctx, peer)
	cancel()
	ctx, cancel = d.supervisorContext()
	confirmErr := d.supervisor.ConfirmGone(ctx, peer)
	cancel()
	if teardownErr != nil || confirmErr != nil {
		d.markV2Red()
	}
	return teardownErr == nil && confirmErr == nil
}

// teardownAndConfirmV2Final is used by status-enabled cleanup paths. A role
// cannot be reported reaped until the existing supervisor proof, final cgroup
// limit read, and dispatcher-owned FD closure have all completed.
func (d *DispatcherV2) teardownAndConfirmV2Final(peer V2PeerHandle, expected Limits) bool {
	if peer.PIDFD < 0 || peer.cgroupFD < 0 || expected.WallClockMS < 1 {
		d.markV2Red()
		return false
	}
	if !d.teardownAndConfirmV2(peer) {
		return false
	}
	finalLimits, _, err := readV2FinalLimits(peer.Observation.CgroupPath, expected.WallClockMS, peer.cgroupFD)
	if err != nil || !exactV2Limits(expected, finalLimits) {
		d.markV2Red()
		return false
	}
	return true
}

func (d *DispatcherV2) abortV2(active *v2Lease, transferred bool) {
	if active == nil {
		return
	}
	d.mu.Lock()
	if active.resolved || active.fencing || d.leases[active.lease.LeaseID] != active {
		d.mu.Unlock()
		return
	}
	active.fencing = true
	transferred = transferred || active.transferSent
	d.mu.Unlock()
	// A consumed registration owns a fresh peer even before bytes cross the
	// parser handoff. Fence and prove that peer gone on every abort; retryability
	// is only the submitter-facing classification, never permission to leave a
	// used JVM/cgroup alive for another lease.
	cleanupProven := false
	if d.statusWriter != nil {
		cleanupProven = d.teardownAndConfirmV2Final(active.worker.peer, active.worker.entry.ExpectedLimits)
	} else {
		_ = d.teardownAndConfirmV2(active.worker.peer)
	}
	d.mu.Lock()
	if active.resolved || d.leases[active.lease.LeaseID] != active {
		active.fencing = false
		d.mu.Unlock()
		return
	}
	active.fencing = false
	active.cleanupProven = cleanupProven
	if transferred || active.transferSent {
		active.lease.State = LeaseQuarantined
		statusChanged := d.resolveV2Locked(active, v2JobResult{outcome: quarantinedOutcomeV2(active)})
		d.mu.Unlock()
		if statusChanged {
			d.publishV2Status()
		}
	} else {
		active.lease.State = LeaseExpired
		statusChanged := d.resolveV2Locked(active, v2JobResult{outcome: retryOutcomeV2ForJob(active.job), retryable: true})
		d.mu.Unlock()
		if statusChanged {
			d.publishV2Status()
		}
	}
}

// finishV2Quarantine resolves an already-fenced post-transfer lease without
// invoking the supervisor a second time. It is used when the mandatory
// ConfirmGone/Teardown sequence has already been attempted and failed.
func (d *DispatcherV2) finishV2Quarantine(active *v2Lease) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if active == nil || active.resolved || d.leases[active.lease.LeaseID] != active {
		return
	}
	active.lease.State = LeaseQuarantined
	d.resolveV2Locked(active, v2JobResult{outcome: quarantinedOutcomeV2(active)})
}

func (d *DispatcherV2) expireV2(active *v2Lease) {
	if active == nil {
		return
	}
	d.mu.Lock()
	if active.resolved || d.leases[active.lease.LeaseID] != active {
		d.mu.Unlock()
		return
	}
	transferred := active.transferSent
	d.mu.Unlock()
	d.abortV2(active, transferred)
}

func (d *DispatcherV2) resolveV2Locked(active *v2Lease, result v2JobResult) bool {
	if active.deadline != nil {
		active.deadline.Stop()
	}
	active.resolved = true
	if active.worker.active == active {
		active.worker.active = nil
	}
	delete(d.leases, active.lease.LeaseID)
	if !result.retryable {
		recordV2ReplayLocked(d.terminal, active.lease.LeaseID, active.deadlineAt())
	}
	closeV2PeerFD(active.worker.peer.PIDFD)
	active.worker.peer.PIDFD = -1
	closeV2CgroupFD(active.worker.peer.cgroupFD)
	active.worker.peer.cgroupFD = -1
	statusChanged := false
	if d.statusWriter != nil && active.cleanupProven && !d.red {
		statusChanged = d.setV2RoleStatusLocked(active.worker.hello.ParserType, active.worker.handoff.HandoffID, v2RoleReaped, time.Time{})
	}
	select {
	case active.result <- result:
	default:
	}
	return statusChanged
}

func retryOutcomeV2ForJob(job JobV2) OutcomeV2 {
	return OutcomeV2{SchemaVersion: OutcomeVersionV2, LeaseID: job.LeaseID, JobID: job.JobID, ParserRequest: job.ParserRequest, Handoff: Handoff{TransferState: TransferRetry, ConfirmationID: "dispatcher:" + job.LeaseID}, Status: StatusFailed, ReportedAt: time.Now().UTC().Format(time.RFC3339), OutputContract: job.ParserRequest.OutputContract}
}

func quarantinedOutcomeV2(active *v2Lease) OutcomeV2 {
	runtimeHash, executionID := active.runtimeHash, active.executionID
	return OutcomeV2{SchemaVersion: OutcomeVersionV2, LeaseID: active.lease.LeaseID, JobID: active.lease.JobID, WorkerID: stringPtrV2(active.lease.WorkerID), ParserRequest: active.job.ParserRequest, Handoff: Handoff{TransferState: TransferQuarantine, ConfirmationID: executionID}, Status: StatusQuarantine, ReportedAt: time.Now().UTC().Format(time.RFC3339), OutputContract: active.job.ParserRequest.OutputContract, RuntimeProfileHash: stringPtrV2(runtimeHash), ExecutionConfirmationID: stringPtrV2(executionID)}
}

func stringPtrV2(value string) *string { return &value }

func digestFor(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func exactParserRequestInOutcome(body []byte, request ParserRequestV1) bool {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false
	}
	raw, ok := envelope["parser_request"]
	if !ok {
		return false
	}
	expected, err := json.Marshal(request)
	return err == nil && bytes.Equal(raw, expected)
}

func (l *v2Lease) issuedAt() time.Time {
	parsed, _ := parseTimestamp(l.lease.IssuedAt)
	return parsed
}

func (l *v2Lease) deadlineAt() time.Time {
	parsed, _ := parseTimestamp(l.lease.ExpiresAt)
	return parsed
}

func (l *v2Lease) obsTime() time.Time { return l.worker.obs.ObservedAt }
