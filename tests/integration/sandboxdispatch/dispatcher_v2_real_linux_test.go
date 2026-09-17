//go:build linux

package sandboxdispatch_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

const (
	v2RealHelperEnv    = "KNOWVAULT_V2_REAL_HELPER"
	v2RequireRealV2Env = "KNOWVAULT_REQUIRE_REAL_V2"
	v2RealHash         = "sha256:47f212973cf7618f63c22f2fa5f5900df842848f023b49acab906fafc265c1f9"
	realOfficeUID      = 65532
	realOfficeGID      = 65532
	realPDFUID         = 65533
	realPDFGID         = 65533
	realSubmitterUID   = 65530
	realSubmitterGID   = 65530
)

// realV2PrerequisiteFailure keeps the default developer test friendly on
// hosts without a writable cgroup v2 hierarchy or PID namespaces, while the
// dedicated privileged CI invocation can require proof instead of allowing a
// green run with every kernel exercise skipped.
func realV2PrerequisiteFailure(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(v2RequireRealV2Env) == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// TestV2RealWorkerHelper is invoked in a fresh PID namespace by the parent
// acceptance test. It deliberately uses the public worker client and no test
// supervisor/observer injection; the parent supplies the real pidfd handoff.
func TestV2RealWorkerHelper(t *testing.T) {
	if os.Getenv(v2RealHelperEnv) != "1" {
		return
	}
	role := os.Getenv("KNOWVAULT_V2_REAL_ROLE")
	workerID := os.Getenv("KNOWVAULT_V2_REAL_WORKER_ID")
	gate := os.Getenv("KNOWVAULT_V2_REAL_GATE")
	registered := os.Getenv("KNOWVAULT_V2_REAL_REGISTERED")
	for {
		if contents, err := os.ReadFile(gate); err == nil && len(contents) != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	client := &sandboxdispatch.WorkerClient{
		V2OfficeRegistrationSocketPath: os.Getenv("KNOWVAULT_V2_REAL_OFFICE_SOCKET"),
		V2PDFRegistrationSocketPath:    os.Getenv("KNOWVAULT_V2_REAL_PDF_SOCKET"),
		MaxPayloadBytes:                1 << 20,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	worker, err := client.RegisterV2(ctx, workerID, role, sandboxdispatch.V2RegistrationOptions{
		ArtifactHash:               v2RealHash,
		SandboxProfileRevision:     os.Getenv("KNOWVAULT_V2_REAL_SANDBOX_PROFILE"),
		ObservationProfileRevision: os.Getenv("KNOWVAULT_V2_REAL_OBSERVATION_PROFILE"),
		SupervisorHandoffID:        os.Getenv("KNOWVAULT_V2_REAL_HANDOFF_ID"),
	})
	if err != nil {
		t.Fatalf("real worker registration: %v", err)
	}
	if err := os.WriteFile(registered, []byte("registered"), 0o600); err != nil {
		t.Fatalf("registration marker: %v", err)
	}
	if os.Getenv("KNOWVAULT_V2_REAL_MODE") == "disconnect" {
		_ = worker.Close()
		return
	}
	lease, payload, header, err := worker.PullV2(ctx)
	if err != nil {
		t.Fatalf("real worker pull: %v", err)
	}
	result := append([]byte("real-result:"), payload...)
	digest := sha256.Sum256(result)
	digestValue := "sha256:" + hex.EncodeToString(digest[:])
	workerName := lease.WorkerID
	outcome := sandboxdispatch.OutcomeV2{
		SchemaVersion: sandboxdispatch.OutcomeVersionV2, LeaseID: lease.LeaseID, JobID: lease.JobID,
		WorkerID: &workerName, ParserRequest: lease.ParserRequest,
		Handoff: sandboxdispatch.Handoff{TransferState: sandboxdispatch.TransferConfirmed, ConfirmationID: header.ExecutionConfirmationID},
		Status:  sandboxdispatch.StatusSucceeded, ReportedAt: time.Now().UTC().Format(time.RFC3339),
		OutputContract: lease.ParserRequest.OutputContract, ResultDigest: &digestValue,
		RuntimeProfileHash: &header.RuntimeProfileHash, ExecutionConfirmationID: &header.ExecutionConfirmationID,
	}
	if err := worker.ReportV2(outcome, result); err != nil {
		t.Fatalf("real worker report: %v", err)
	}
}

func TestV2RealSubmitterHelper(t *testing.T) {
	if os.Getenv("KNOWVAULT_V2_REAL_SUBMIT_HELPER") != "1" {
		return
	}
	var job sandboxdispatch.JobV2
	if err := json.Unmarshal([]byte(os.Getenv("KNOWVAULT_V2_REAL_JOB")), &job); err != nil {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(os.Getenv("KNOWVAULT_V2_REAL_PAYLOAD"))
	if err != nil {
		return
	}
	result, retry, submitErr := (&sandboxdispatch.Submitter{
		V2SubmitSocketPath: os.Getenv("KNOWVAULT_V2_REAL_SUBMIT_SOCKET"), MaxPayloadBytes: 1 << 20, FrameTimeout: 2 * time.Second,
	}).SubmitV2(context.Background(), job, payload)
	report := struct {
		Result sandboxdispatch.SubmitResultV2
		Retry  bool
		Error  string
	}{Result: result, Retry: retry}
	if submitErr != nil {
		report.Error = submitErr.Error()
	}
	data, marshalErr := json.Marshal(report)
	if marshalErr == nil {
		path := os.Getenv("KNOWVAULT_V2_REAL_SUBMIT_RESULT")
		tmp := path + ".tmp"
		if os.WriteFile(tmp, data, 0o600) == nil {
			_ = os.Rename(tmp, path)
		}
	}
}

func TestDispatcherV2RealPidfdWorker(t *testing.T) {
	env := newRealV2Environment(t, "success")
	defer env.close()

	payload := []byte("real pidfd payload")
	request := realV2ParserRequest()
	now := time.Now().UTC().Truncate(time.Second)
	job := sandboxdispatch.JobV2{
		SchemaVersion: sandboxdispatch.JobVersionV2, JobID: "real-job-1", LeaseID: "real-lease-1",
		ParserRequest: request,
		InputArtifact: sandboxdispatch.InputArtifact{ArtifactID: "real-artifact-1", ContentDigest: digestV2Real(payload), MediaType: "application/pdf"},
		SubmittedAt:   now.Format(time.RFC3339), DeadlineAt: now.Add(10 * time.Second).Format(time.RFC3339),
		WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN",
	}
	result, retry, err := env.submitAsNonRoot(t, job, payload)
	if err != nil || retry || result.Outcome.Handoff.TransferState != sandboxdispatch.TransferConfirmed || result.Confirmation == nil {
		t.Fatalf("real v2 result: retry=%v err=%v outcome=%#v confirmation=%#v", retry, err, result.Outcome, result.Confirmation)
	}
	if string(result.Result) != "real-result:"+string(payload) {
		t.Fatalf("real v2 result bytes: %q", result.Result)
	}
}

func TestDispatcherV2RealPreTransferDisconnectIsRetry(t *testing.T) {
	env := newRealV2Environment(t, "disconnect")
	defer env.close()
	payload := []byte("disconnect before transfer")
	request := realV2ParserRequest()
	now := time.Now().UTC().Truncate(time.Second)
	job := sandboxdispatch.JobV2{
		SchemaVersion: sandboxdispatch.JobVersionV2, JobID: "real-job-disconnect", LeaseID: "real-lease-disconnect",
		ParserRequest: request,
		InputArtifact: sandboxdispatch.InputArtifact{ArtifactID: "real-artifact-disconnect", ContentDigest: digestV2Real(payload), MediaType: "application/pdf"},
		SubmittedAt:   now.Format(time.RFC3339), DeadlineAt: now.Add(10 * time.Second).Format(time.RFC3339),
		WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN",
	}
	result, retry, err := env.submitAsNonRoot(t, job, payload)
	if err != nil || !retry || result.Outcome.Handoff.TransferState != sandboxdispatch.TransferRetry {
		t.Fatalf("real pre-transfer disconnect: retry=%v err=%v outcome=%#v", retry, err, result.Outcome)
	}
}

func TestDispatcherV2RealReapedPendingHandoffCleanupNoRed(t *testing.T) {
	env := newRealV2Environment(t, "reaped-pending")
	defer env.close()
	// The supervisor ACKs while the worker is live, then the worker is reaped
	// before registration. Expiry must use the saved positive PID together with
	// the pidfd's Pid:-1 branch and clean the empty cgroup without false RED.
	time.Sleep(750 * time.Millisecond)
	if !env.dispatcher.Ready() {
		t.Fatal("reaped pending-handoff cleanup latched RED")
	}
}

type realV2Environment struct {
	dispatcher       *sandboxdispatch.DispatcherV2
	cancel           context.CancelFunc
	root             string
	cgroup           string
	submit           string
	child            *exec.Cmd
	gate             string
	registered       string
	helperPath       string
	markers          string
	submitterMarkers string
	done             chan struct{}
}

func (e *realV2Environment) submitAsNonRoot(t *testing.T, job sandboxdispatch.JobV2, payload []byte) (sandboxdispatch.SubmitResultV2, bool, error) {
	t.Helper()
	if e.helperPath == "" {
		t.Fatal("real worker helper was not staged")
	}
	if e.submitterMarkers == "" {
		e.submitterMarkers = filepath.Join(e.root, "submitter-markers")
		if err := os.Mkdir(e.submitterMarkers, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(e.submitterMarkers, realSubmitterUID, realSubmitterGID); err != nil {
			t.Fatal(err)
		}
	}
	resultPath := filepath.Join(e.submitterMarkers, "result")
	if err := os.WriteFile(resultPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(resultPath, realSubmitterUID, realSubmitterGID); err != nil {
		t.Fatal(err)
	}
	jobBytes, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(e.helperPath, "-test.run", "^TestV2RealSubmitterHelper$", "-test.v", "-test.timeout=30s")
	child.Env = append(os.Environ(),
		"KNOWVAULT_V2_REAL_SUBMIT_HELPER=1", "KNOWVAULT_V2_REAL_SUBMIT_SOCKET="+e.submit,
		"KNOWVAULT_V2_REAL_JOB="+string(jobBytes), "KNOWVAULT_V2_REAL_PAYLOAD="+base64.StdEncoding.EncodeToString(payload),
		"KNOWVAULT_V2_REAL_SUBMIT_RESULT="+resultPath)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: realSubmitterUID, Gid: realSubmitterGID, NoSetGroups: true}}
	if err := child.Start(); err != nil {
		t.Fatalf("non-root submitter start: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if contents, readErr := os.ReadFile(resultPath); readErr == nil && len(contents) != 0 {
			_ = child.Wait()
			var report struct {
				Result sandboxdispatch.SubmitResultV2
				Retry  bool
				Error  string
			}
			if err := json.Unmarshal(contents, &report); err != nil {
				t.Fatalf("non-root submitter report: %v", err)
			}
			if report.Error != "" {
				return sandboxdispatch.SubmitResultV2{}, report.Retry, errors.New(report.Error)
			}
			return report.Result, report.Retry, nil
		}
		if !time.Now().Before(deadline) {
			_ = child.Process.Kill()
			_ = child.Wait()
			t.Fatal("non-root submitter did not report")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newRealV2Environment(t *testing.T, mode string) *realV2Environment {
	t.Helper()
	if os.Geteuid() != 0 {
		realV2PrerequisiteFailure(t, "real v2 pidfd acceptance requires root for cgroup/pid namespace setup")
	}
	rootBase := "/run"
	root, err := os.MkdirTemp(rootBase, "kv-v2-accept-")
	if err != nil {
		realV2PrerequisiteFailure(t, "secure deployment root unavailable: %v", err)
	}
	roleRoots := []string{filepath.Join(root, "submit"), filepath.Join(root, "supervisor"), filepath.Join(root, "office"), filepath.Join(root, "pdf")}
	for _, roleRoot := range roleRoots {
		if err := os.Mkdir(roleRoot, 0o700); err != nil {
			_ = os.RemoveAll(root)
			realV2PrerequisiteFailure(t, "role root unavailable: %v", err)
		}
	}
	// Keep the deployment tree owned by the root dispatcher while granting the
	// dedicated non-root parser only traversal. NewV2 assigns each parser
	// listener to the exact worker UID/GID with owner-only mode. Group/world
	// writes remain forbidden on every directory in the authority chain.
	if err := os.Chmod(root, 0o711); err != nil {
		_ = os.RemoveAll(root)
		realV2PrerequisiteFailure(t, "deployment root permissions unavailable: %v", err)
	}
	for index, roleRoot := range roleRoots {
		workerGID := realPDFGID
		if index == 0 {
			workerGID = realSubmitterGID
		}
		if index == 2 {
			workerGID = realOfficeGID
		}
		if err := os.Chown(roleRoot, -1, workerGID); err != nil {
			_ = os.RemoveAll(root)
			realV2PrerequisiteFailure(t, "role root group unavailable: %v", err)
		}
		if err := os.Chmod(roleRoot, 0o710); err != nil {
			_ = os.RemoveAll(root)
			realV2PrerequisiteFailure(t, "role root permissions unavailable: %v", err)
		}
	}
	cgroup := filepath.Join("/sys/fs/cgroup", "kv-v2-accept-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(cgroup, 0o700); err != nil {
		_ = os.RemoveAll(root)
		realV2PrerequisiteFailure(t, "dedicated cgroup unavailable: %v", err)
	}
	cleanupCgroup := func() {
		_ = os.Remove(filepath.Join(cgroup, "cgroup.procs"))
		_ = os.Remove(cgroup)
	}
	if err := configureRealCgroup(cgroup); err != nil {
		cleanupCgroup()
		_ = os.RemoveAll(root)
		realV2PrerequisiteFailure(t, "dedicated cgroup limits unavailable: %v", err)
	}
	request := realV2ParserRequest()
	limits := sandboxdispatch.Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: 10_000}
	entry := sandboxdispatch.V2RegistryEntry{ParserRequest: request, ArtifactHash: v2RealHash, MediaType: "application/pdf", MaxLeaseDuration: 10 * time.Second, ExpectedLimits: limits, RuntimeProfileHash: sandboxdispatch.RuntimeProfileHash(request.ParserType, request.SandboxProfileRevision, limits), ExpectedWorkerUID: realPDFUID, ExpectedWorkerGID: realPDFGID}
	dispatcher, err := sandboxdispatch.NewV2(sandboxdispatch.V2Config{
		RootDir:          root,
		SubmitSocketPath: filepath.Join(roleRoots[0], "submit.sock"), SupervisorHandoffSocketPath: filepath.Join(roleRoots[1], "handoff.sock"),
		OfficeRegistrationSocketPath: filepath.Join(roleRoots[2], "office.sock"), PDFRegistrationSocketPath: filepath.Join(roleRoots[3], "pdf.sock"),
		SubmitSocketRootDir: roleRoots[0], SupervisorHandoffSocketRootDir: roleRoots[1], OfficeRegistrationSocketRootDir: roleRoots[2], PDFRegistrationSocketRootDir: roleRoots[3],
		MaxPayloadBytes: 1 << 20, FrameTimeout: 2 * time.Second, Registry: []sandboxdispatch.V2RegistryEntry{entry, officeV2Entry(limits)},
		SupervisorUID: os.Geteuid(), SupervisorGID: os.Getegid(), SubmitterUID: realSubmitterUID, SubmitterGID: realSubmitterGID, WorkerUIDByParser: map[string]int{sandboxdispatch.ParserTypeOffice: realOfficeUID, sandboxdispatch.ParserTypePDF: realPDFUID}, WorkerGIDByParser: map[string]int{sandboxdispatch.ParserTypeOffice: realOfficeGID, sandboxdispatch.ParserTypePDF: realPDFGID},
	})
	if err != nil {
		cleanupCgroup()
		_ = os.RemoveAll(root)
		realV2PrerequisiteFailure(t, "real dispatcher unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = dispatcher.ListenAndServe(ctx); close(done) }()
	env := &realV2Environment{dispatcher: dispatcher, cancel: cancel, root: root, cgroup: cgroup, submit: dispatcher.SubmitSocketPath(), done: done}
	t.Cleanup(env.close)
	env.startWorker(t, mode, request)
	return env
}

func (e *realV2Environment) startWorker(t *testing.T, mode string, request sandboxdispatch.ParserRequestV1) {
	t.Helper()
	markerDir := filepath.Join(e.root, "worker-markers")
	if err := os.Mkdir(markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(markerDir, realPDFUID, realPDFGID); err != nil {
		t.Fatal(err)
	}
	e.gate = filepath.Join(markerDir, "start")
	e.registered = filepath.Join(markerDir, "registered")
	e.markers = markerDir
	// Pre-create the gate owned by the worker. The root test supervisor writes
	// its readiness byte later, while the worker can read it without widening
	// the deployment tree permissions.
	if err := os.WriteFile(e.gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(e.gate, realPDFUID, realPDFGID); err != nil {
		t.Fatal(err)
	}
	handoffID := "h_" + strings.Repeat("r", 32) + strconv.Itoa(os.Getpid())
	// `go test` places its binary under a root-only temporary directory. Copy
	// it into the deployment root so the non-root helper can exec it while the
	// parent remains the root-owned dispatcher supervisor.
	helperPath := filepath.Join(e.root, "worker-helper")
	e.helperPath = helperPath
	executable, err := os.Executable()
	if err != nil {
		realV2PrerequisiteFailure(t, "worker test executable unavailable: %v", err)
	}
	helperBinary, err := os.ReadFile(executable)
	if err != nil {
		realV2PrerequisiteFailure(t, "worker helper binary unavailable: %v", err)
	}
	if err := os.WriteFile(helperPath, helperBinary, 0o755); err != nil {
		realV2PrerequisiteFailure(t, "worker helper staging unavailable: %v", err)
	}
	child := exec.Command(helperPath, "-test.run", "^TestV2RealWorkerHelper$", "-test.v", "-test.timeout=30s")
	child.Env = append(os.Environ(),
		v2RealHelperEnv+"=1", "KNOWVAULT_V2_REAL_ROLE="+sandboxdispatch.ParserTypePDF, "KNOWVAULT_V2_REAL_WORKER_ID=real-worker",
		"KNOWVAULT_V2_REAL_GATE="+e.gate, "KNOWVAULT_V2_REAL_REGISTERED="+e.registered,
		"KNOWVAULT_V2_REAL_OFFICE_SOCKET="+e.dispatcher.OfficeRegistrationSocketPath(), "KNOWVAULT_V2_REAL_PDF_SOCKET="+e.dispatcher.PDFRegistrationSocketPath(),
		"KNOWVAULT_V2_REAL_SANDBOX_PROFILE="+request.SandboxProfileRevision, "KNOWVAULT_V2_REAL_OBSERVATION_PROFILE="+request.ObservationProfileRevision,
		"KNOWVAULT_V2_REAL_HANDOFF_ID="+handoffID, "KNOWVAULT_V2_REAL_MODE="+mode)
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID, Credential: &syscall.Credential{Uid: realPDFUID, Gid: realPDFGID, NoSetGroups: true}}
	if err := child.Start(); err != nil {
		_ = os.Remove(e.cgroup)
		_ = os.RemoveAll(e.root)
		realV2PrerequisiteFailure(t, "fresh PID namespace worker unavailable: %v", err)
	}
	e.child = child
	pidfd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = os.Remove(e.cgroup)
		_ = os.RemoveAll(e.root)
		realV2PrerequisiteFailure(t, "worker pidfd unavailable: %v", err)
	}
	defer unix.Close(pidfd)
	namespace := readRealNamespace(child.Process.Pid)
	if namespace == "" {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = os.Remove(e.cgroup)
		_ = os.RemoveAll(e.root)
		realV2PrerequisiteFailure(t, "worker kernel identity unavailable")
	}
	if err := os.WriteFile(filepath.Join(e.cgroup, "cgroup.procs"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = os.Remove(e.cgroup)
		_ = os.RemoveAll(e.root)
		realV2PrerequisiteFailure(t, "cannot place worker in dedicated cgroup: %v", err)
	}
	cgroupPath := readRealCgroupPath(child.Process.Pid)
	if cgroupPath == "" {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = os.Remove(e.cgroup)
		_ = os.RemoveAll(e.root)
		realV2PrerequisiteFailure(t, "worker cgroup identity unavailable")
	}
	issued := time.Now().UTC()
	handoffLifetime := 10 * time.Second
	if mode == "reaped-pending" {
		handoffLifetime = 500 * time.Millisecond
	}
	metadata := sandboxdispatch.SupervisorHandoffV1{SchemaVersion: sandboxdispatch.SupervisorHandoffVersionV1, HandoffID: handoffID, ParserType: sandboxdispatch.ParserTypePDF, ArtifactHash: v2RealHash, SandboxProfileRevision: request.SandboxProfileRevision, ObservationProfileRevision: request.ObservationProfileRevision, PIDFDTransport: "SCM_RIGHTS", PIDNamespaceInode: namespace, CgroupPath: cgroupPath, ExpectedWorkerUID: realPDFUID, ExpectedWorkerGID: realPDFGID, IssuedAt: issued.Format(time.RFC3339Nano), ExpiresAt: issued.Add(handoffLifetime).Format(time.RFC3339Nano), OneShot: true, MaxLeases: 1}
	if err := sendRealHandoff(e.dispatcher.SupervisorHandoffSocketPath(), metadata, pidfd); err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		_ = os.Remove(e.cgroup)
		_ = os.RemoveAll(e.root)
		realV2PrerequisiteFailure(t, "real supervisor handoff unavailable: %v", err)
	}
	if mode == "reaped-pending" {
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err := child.Wait(); err != nil {
			// SIGKILL is the expected process result; Wait still reaps the
			// child and transitions the pidfd to Pid:-1.
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatal(err)
			}
		}
		return
	}
	if err := os.WriteFile(e.gate, []byte("start"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if contents, err := os.ReadFile(e.registered); err == nil && len(contents) != 0 {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("real worker did not register")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *realV2Environment) close() {
	if e.cancel != nil {
		e.cancel()
	}
	if e.child != nil {
		_ = e.child.Process.Kill()
		_ = e.child.Wait()
	}
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
	}
	_ = os.Remove(filepath.Join(e.cgroup, "cgroup.kill"))
	_ = os.Remove(e.cgroup)
	_ = os.RemoveAll(e.root)
}

func configureRealCgroup(path string) error {
	for name, value := range map[string]string{"cpu.max": "10000 100000\n", "memory.max": "67108864\n", "pids.max": "16\n"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func sendRealHandoff(path string, metadata sandboxdispatch.SupervisorHandoffV1, pidfd int) error {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	body, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	frame := make([]byte, 5+len(body))
	frame[0] = 14
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	if _, _, err := conn.WriteMsgUnix(frame, unix.UnixRights(pidfd), nil); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	ack := make([]byte, binary.BigEndian.Uint32(header[1:]))
	if _, err := io.ReadFull(conn, ack); err != nil {
		return err
	}
	if header[0] != 15 || string(ack) != sandboxdispatch.SupervisorHandoffAcceptedV1 {
		return os.ErrInvalid
	}
	return nil
}

func readRealCgroupPath(pid int) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Split(line, "::")
		if len(parts) == 2 && parts[0] == "0" {
			return parts[1]
		}
	}
	return ""
}

func readRealNamespace(pid int) string {
	link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/pid")
	if err != nil || !strings.HasPrefix(link, "pid:[") || !strings.HasSuffix(link, "]") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "pid:["), "]")
}

func realV2ParserRequest() sandboxdispatch.ParserRequestV1 {
	return sandboxdispatch.ParserRequestV1{SchemaVersion: sandboxdispatch.ParserRequestVersionV1, ParserType: sandboxdispatch.ParserTypePDF, Operation: sandboxdispatch.OperationObservePDFText, MediaFamily: "PDF", SandboxProfileRevision: "document-parser-sandbox-v2", ObservationProfileRevision: "pdf-obs-v1", MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxUnits: 100, MaxPages: 100, MaxDecodedPixels: 1 << 20, OutputContract: "pdf-parser-result-v1"}
}

func officeV2Entry(limits sandboxdispatch.Limits) sandboxdispatch.V2RegistryEntry {
	request := sandboxdispatch.ParserRequestV1{SchemaVersion: sandboxdispatch.ParserRequestVersionV1, ParserType: sandboxdispatch.ParserTypeOffice, Operation: sandboxdispatch.OperationObserveStructure, MediaFamily: "DOCX", SandboxProfileRevision: "document-parser-sandbox-v2", ObservationProfileRevision: "office-obs-v1", MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxUnits: 100, MaxPages: 100, MaxDecodedPixels: 1 << 20, OutputContract: sandboxdispatch.OutputContractV1}
	return sandboxdispatch.V2RegistryEntry{ParserRequest: request, ArtifactHash: v2RealHash, MediaType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", MaxLeaseDuration: 10 * time.Second, ExpectedLimits: limits, RuntimeProfileHash: sandboxdispatch.RuntimeProfileHash(request.ParserType, request.SandboxProfileRevision, limits), ExpectedWorkerUID: realOfficeUID, ExpectedWorkerGID: realOfficeGID}
}

func digestV2Real(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
