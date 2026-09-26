//go:build linux

// Package parserv2harness is a test-only external supervisor for the released
// document-parser image. It deliberately lives outside internal/sandboxdispatch:
// DispatcherV2 must remain process-launch-free, while this harness owns the
// qualification-only image extraction, process creation and kernel setup.
package parserv2harness

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

const (
	// The default is the current locally qualified candidate. Callers may still
	// override it with KNOWVAULT_TEST_OFFICE_WORKER_IMAGE, but silently falling
	// back to the superseded qualification-k image would fail closed on its stale
	// artifact identity and make the live gate non-reproducible.
	DefaultImage             = "knowvault-document-parser:2.1.0"
	QualifiedArtifactHash    = "sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414"
	QualifiedOCRArtifactHash = "sha256:669281adf0c513c65b525742ed289e73a044c27018f7d833a4769901b8640f82"
	RequireRealV2Env         = "KNOWVAULT_REQUIRE_REAL_V2"

	officeUID = 65532
	officeGID = 65532
	pdfUID    = 65533
	pdfGID    = 65533
	ocrUID    = 65534
	ocrGID    = 65534
	submitUID = 65530
	submitGID = 65530

	// These values are the production parser capability limits. The cgroup
	// values are intentionally written as their exact v2 forms; the dispatcher
	// independently observes and compares the resulting kernel values.
	cpuQuotaMicros = "10000 100000\n" // 100 CPU millis
	memoryMax      = "67108864\n"     // 64 MiB
	pidsMax        = "16\n"
	memoryMaxOCR   = "268435456\n" // 256 MiB for Python + Tesseract
	pidsMaxOCR     = "32\n"
	wallClock      = 120 * time.Second
)

// Harness runs one production DispatcherV2 and a submit proxy. The proxy is
// part of the external supervisor: it sees an opaque v2 job only to select the
// already-registered parser role, then forwards the original frames unchanged.
// It is not a parser and has no source/document interpretation capability.
type Harness struct {
	logf     func(string, ...any)
	image    string
	ocrImage bool
	root     string
	base     string

	dispatcher *sandboxdispatch.DispatcherV2
	cancel     context.CancelFunc
	done       chan struct{}

	proxyPath   string
	proxyCmd    *exec.Cmd
	controlLn   *net.UnixListener
	controlPath string
	controlDone chan struct{}

	roleRoots map[string]string
	roleUID   map[string]int
	roleGID   map[string]int
	roleMu    map[string]*sync.Mutex
	current   map[string]*workerProcess
	workers   []*workerProcess
	mu        sync.Mutex
	closeOnce sync.Once
	seq       uint64
}

type workerProcess struct {
	cmd      *exec.Cmd
	done     chan struct{}
	rootfs   string
	cgroup   string
	roleRoot string
	gate     string
	pidfd    int
}

// New builds a real v2 harness. Missing host capabilities are skippable during
// ordinary developer runs, but are fatal under KNOWVAULT_REQUIRE_REAL_V2=1.
// The image is never run through Docker: only its merged filesystem bytes are
// exported and the selected entrypoint is exec'd inside the extracted rootfs.
func New(t testing.TB, image string) *Harness {
	t.Helper()
	image = strings.TrimSpace(image)
	if image == "" {
		image = DefaultImage
	}
	ocrImage := isOCRImage(image)
	if os.Geteuid() != 0 {
		prerequisiteFailure(t, "real v2 Java qualification requires root for chroot, cgroup and PID namespace setup")
		return nil
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		prerequisiteFailure(t, "unified cgroup v2 hierarchy unavailable: %v", err)
		return nil
	}
	if err := probeTmpfs(); err != nil {
		prerequisiteFailure(t, "tmpfs scratch mount unavailable: %v", err)
		return nil
	}
	for _, tool := range []string{"/usr/bin/nsenter", "/usr/bin/mount"} {
		info, err := os.Stat(tool)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			prerequisiteFailure(t, "private worker proc mount requires %s", tool)
			return nil
		}
	}

	root, err := os.MkdirTemp("/run", "knowvault-parserv2-")
	if err != nil {
		prerequisiteFailure(t, "secure supervisor root unavailable: %v", err)
		return nil
	}
	cleanupRoot := true
	defer func() {
		if cleanupRoot {
			_ = os.RemoveAll(root)
		}
	}()
	if err := os.Chmod(root, 0o710); err != nil {
		prerequisiteFailure(t, "supervisor root permissions unavailable: %v", err)
		return nil
	}
	roles := map[string]string{
		sandboxdispatch.ParserTypeOffice: filepath.Join(root, "office"),
		sandboxdispatch.ParserTypePDF:    filepath.Join(root, "pdf"),
	}
	if ocrImage {
		roles[sandboxdispatch.ParserTypeOCR] = filepath.Join(root, "ocr")
	}
	roleRoots := map[string]string{
		"submit":                         filepath.Join(root, "submit"),
		"supervisor":                     filepath.Join(root, "supervisor"),
		sandboxdispatch.ParserTypeOffice: roles[sandboxdispatch.ParserTypeOffice],
		sandboxdispatch.ParserTypePDF:    roles[sandboxdispatch.ParserTypePDF],
	}
	if ocrImage {
		roleRoots[sandboxdispatch.ParserTypeOCR] = roles[sandboxdispatch.ParserTypeOCR]
	}
	roleUID := map[string]int{
		"submit": submitUID, "supervisor": os.Geteuid(),
		sandboxdispatch.ParserTypeOffice: officeUID,
		sandboxdispatch.ParserTypePDF:    pdfUID,
	}
	if ocrImage {
		roleUID[sandboxdispatch.ParserTypeOCR] = ocrUID
	}
	roleGID := map[string]int{
		"submit": submitGID, "supervisor": os.Getegid(),
		sandboxdispatch.ParserTypeOffice: officeGID,
		sandboxdispatch.ParserTypePDF:    pdfGID,
	}
	if ocrImage {
		roleGID[sandboxdispatch.ParserTypeOCR] = ocrGID
	}
	for _, roleRoot := range roleRoots {
		if err := os.Mkdir(roleRoot, 0o710); err != nil {
			prerequisiteFailure(t, "role root unavailable: %v", err)
			return nil
		}
		group := os.Getegid()
		for name, candidate := range roleRoots {
			if candidate == roleRoot {
				group = roleGID[name]
				break
			}
		}
		if err := os.Chown(roleRoot, 0, group); err != nil {
			prerequisiteFailure(t, "role root group unavailable: %v", err)
			return nil
		}
	}

	base := filepath.Join(root, "image-base")
	if err := extractImage(image, base); err != nil {
		prerequisiteFailure(t, "cannot extract qualified parser image %s: %v", image, err)
		return nil
	}

	limits := sandboxdispatch.Limits{
		CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16,
		WallClockMS: int64(wallClock / time.Millisecond),
	}
	if ocrImage {
		// OCR is an evidence-only qualification image until its supply-chain
		// gates close. Keep its larger native-engine envelope in this external
		// supervisor rather than exposing an unqualified capability from the
		// production registry.
		limits = sandboxdispatch.Limits{CPUMillis: 100, MemoryBytes: 256 << 20, PIDsMax: 32, WallClockMS: int64(wallClock / time.Millisecond)}
	}
	registry := []sandboxdispatch.V2RegistryEntry{
		registryEntry(sandboxdispatch.ParserTypeOffice, "DOCX", limits),
		registryEntry(sandboxdispatch.ParserTypeOffice, "PPTX", limits),
		registryEntry(sandboxdispatch.ParserTypeOffice, "XLSX", limits),
		registryEntry(sandboxdispatch.ParserTypePDF, "PDF", limits),
	}
	// The PDF role owns two closed capabilities: text observation first, then
	// deterministic page rendering after the observer explicitly classifies a
	// scanned/mixed document. Keep both tuples registered on the same physical
	// PDF role so the qualification harness exercises the production
	// dispatchparser.PDF.Render boundary instead of a test-only renderer.
	render := registryEntry(sandboxdispatch.ParserTypePDF, "PDF", limits)
	render.ParserRequest.Operation = sandboxdispatch.OperationRenderPDFPages
	render.ParserRequest.OutputContract = sandboxdispatch.ProductionPDFRenderOutputContract
	render.ParserRequest.RendererProfileRevision = sandboxdispatch.ProductionPDFRendererRevision
	render.ParserRequest.MaxDecodedPixels = sandboxdispatch.ProductionRenderMaxDecodedPixels
	registry = append(registry, render)
	if ocrImage {
		registry = append(registry, registryEntry(sandboxdispatch.ParserTypeOCR, "PNG", limits))
		registry = append(registry, registryEntry(sandboxdispatch.ParserTypeOCR, "JPEG", limits))
	}
	submitRoot := roleRoots["submit"]
	supervisorRoot := roleRoots["supervisor"]
	config := sandboxdispatch.V2Config{
		RootDir:                         root,
		SubmitSocketPath:                filepath.Join(submitRoot, "dispatcher.sock"),
		SupervisorHandoffSocketPath:     filepath.Join(supervisorRoot, "handoff.sock"),
		OfficeRegistrationSocketPath:    filepath.Join(roleRoots[sandboxdispatch.ParserTypeOffice], "register.sock"),
		PDFRegistrationSocketPath:       filepath.Join(roleRoots[sandboxdispatch.ParserTypePDF], "register.sock"),
		SubmitSocketRootDir:             submitRoot,
		SupervisorHandoffSocketRootDir:  supervisorRoot,
		OfficeRegistrationSocketRootDir: roleRoots[sandboxdispatch.ParserTypeOffice],
		PDFRegistrationSocketRootDir:    roleRoots[sandboxdispatch.ParserTypePDF],
		MaxPayloadBytes:                 64 << 20,
		FrameTimeout:                    5 * time.Second,
		Registry:                        registry,
		SupervisorUID:                   os.Geteuid(),
		SupervisorGID:                   os.Getegid(),
		SubmitterUID:                    submitUID,
		SubmitterGID:                    submitGID,
		WorkerUIDByParser: map[string]int{
			sandboxdispatch.ParserTypeOffice: officeUID,
			sandboxdispatch.ParserTypePDF:    pdfUID,
		},
		WorkerGIDByParser: map[string]int{
			sandboxdispatch.ParserTypeOffice: officeGID,
			sandboxdispatch.ParserTypePDF:    pdfGID,
		},
	}
	if ocrImage {
		config.OCRRegistrationSocketPath = filepath.Join(roleRoots[sandboxdispatch.ParserTypeOCR], "register.sock")
		config.OCRRegistrationSocketRootDir = roleRoots[sandboxdispatch.ParserTypeOCR]
		config.WorkerUIDByParser[sandboxdispatch.ParserTypeOCR] = ocrUID
		config.WorkerGIDByParser[sandboxdispatch.ParserTypeOCR] = ocrGID
	}
	dispatcher, err := sandboxdispatch.NewV2(config)
	if err != nil {
		prerequisiteFailure(t, "real DispatcherV2 unavailable: %v", err)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = dispatcher.ListenAndServe(ctx)
		close(done)
	}()

	// The dispatcher submit socket has a distinct non-root submitter principal.
	// The parent test process is the root supervisor, so a tiny test-binary
	// helper owns the public facade socket as uid/gid 65530 and dials the private
	// dispatcher socket. Requests cross the control socket only to ask this
	// root supervisor to admit the matching fresh parser process.
	controlRoot := filepath.Join(root, "control")
	if err := os.Mkdir(controlRoot, 0o710); err != nil {
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter control root unavailable: %v", err)
		return nil
	}
	if err := os.Chown(controlRoot, 0, submitGID); err != nil {
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter control root group unavailable: %v", err)
		return nil
	}
	controlPath := filepath.Join(controlRoot, "supervise.sock")
	controlLn, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlPath, Net: "unix"})
	if err != nil {
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter control listener unavailable: %v", err)
		return nil
	}
	if err := os.Chown(controlPath, submitUID, submitGID); err != nil {
		_ = controlLn.Close()
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter control socket owner unavailable: %v", err)
		return nil
	}
	if err := os.Chmod(controlPath, 0o600); err != nil {
		_ = controlLn.Close()
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter control socket permissions unavailable: %v", err)
		return nil
	}
	// The public facade is created by the non-root submitter itself. Keep it in
	// a submitter-owned directory: DispatcherV2's private submit role root is
	// intentionally owner-only for its pre-created socket and is not writable by
	// the submitter.
	publicRoot := filepath.Join(root, "public")
	if err := os.Mkdir(publicRoot, 0o700); err != nil {
		_ = controlLn.Close()
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter facade root unavailable: %v", err)
		return nil
	}
	if err := os.Chown(publicRoot, submitUID, submitGID); err != nil {
		_ = controlLn.Close()
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter facade root owner unavailable: %v", err)
		return nil
	}
	proxyPath := filepath.Join(publicRoot, "facade.sock")
	proxyHelper := filepath.Join(submitRoot, "submitter-helper")
	if err := stageBinary(proxyHelper); err != nil {
		_ = controlLn.Close()
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "submitter helper staging unavailable: %v", err)
		return nil
	}
	// The submit proxy serves the whole Harness and therefore many independent
	// one-shot parser leases. A per-parser wall-clock timeout here kills the
	// control plane after the first hostile 120-second input and silently turns
	// later valid documents into quarantines. Harness.Close is its bounded owner
	// and always kills/waits the child, so the helper's test alarm is disabled.
	proxyCmd := exec.Command(proxyHelper, submitProxyCommandArgs()...)
	proxyCmd.Dir = "/"
	proxyCmd.Env = append(os.Environ(),
		"KNOWVAULT_P2_SUBMIT_PROXY_HELPER=1",
		"KNOWVAULT_P2_SUBMIT_PROXY_CONTROL="+controlPath,
		"KNOWVAULT_P2_SUBMIT_PROXY_PUBLIC="+proxyPath,
		"KNOWVAULT_P2_SUBMIT_PROXY_DISPATCHER="+dispatcher.SubmitSocketPath(),
	)
	proxyCmd.Stdout = os.Stderr
	proxyCmd.Stderr = os.Stderr
	proxyCmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: submitUID, Gid: submitGID, NoSetGroups: true}}
	if err := proxyCmd.Start(); err != nil {
		_ = controlLn.Close()
		cancel()
		dispatcher.Close()
		prerequisiteFailure(t, "non-root submitter helper unavailable: %v", err)
		return nil
	}
	h := &Harness{
		logf:  t.Logf,
		image: image, ocrImage: ocrImage, root: root, base: base, dispatcher: dispatcher,
		cancel: cancel, done: done, proxyPath: proxyPath, proxyCmd: proxyCmd,
		controlLn: controlLn, controlPath: controlPath, controlDone: make(chan struct{}),
		roleRoots: roleRoots, roleUID: roleUID, roleGID: roleGID,
		roleMu: map[string]*sync.Mutex{
			sandboxdispatch.ParserTypeOffice: &sync.Mutex{}, sandboxdispatch.ParserTypePDF: &sync.Mutex{},
		},
		current: make(map[string]*workerProcess),
	}
	if ocrImage {
		h.roleMu[sandboxdispatch.ParserTypeOCR] = &sync.Mutex{}
	}
	cleanupRoot = false
	t.Cleanup(h.Close)
	go h.serveControl()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(proxyPath); err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			prerequisiteFailure(t, "non-root submitter helper did not create its facade socket")
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return h
}

func submitProxyCommandArgs() []string {
	return []string{"-test.run", "^TestParserV2SubmitProxyHelper$", "-test.v", "-test.timeout=0"}
}

func prerequisiteFailure(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv(RequireRealV2Env) == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func probeTmpfs() error {
	dir, err := os.MkdirTemp("/run", "knowvault-tmpfs-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "size=64m"); err != nil {
		return err
	}
	return unix.Unmount(dir, 0)
}

func isOCRImage(image string) bool {
	name := strings.ToLower(strings.TrimSpace(image))
	// CI may use a neutral qualification tag so the evidence-only worker name
	// does not leak into production workflow metadata. Local runs retain the
	// descriptive tag for discoverability.
	return strings.Contains(name, "tesseract-ocr") || strings.Contains(name, "ocr-worker")
}

func removeSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("existing path is not a unix socket")
	}
	return os.Remove(path)
}

func registryEntry(parserType, media string, limits sandboxdispatch.Limits) sandboxdispatch.V2RegistryEntry {
	operation, output := sandboxdispatch.OperationObserveStructure, "document-parser-result-v1"
	mediaType := "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	observation := "office-obs-v1"
	artifact := QualifiedArtifactHash
	if media == "PPTX" {
		mediaType = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	}
	if media == "XLSX" {
		mediaType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}
	if parserType == sandboxdispatch.ParserTypePDF {
		operation, output, mediaType = sandboxdispatch.OperationObservePDFText, "pdf-parser-result-v1", "application/pdf"
		observation = "pdf-obs-v1"
	}
	if parserType == sandboxdispatch.ParserTypeOCR {
		operation, output = sandboxdispatch.OperationObserveOCRTokens, "ocr-result-v1"
		observation = "ocr-observation-v1"
		artifact = QualifiedOCRArtifactHash
		mediaType = "image/png"
		if media == "JPEG" {
			mediaType = "image/jpeg"
		}
	}
	request := sandboxdispatch.ParserRequestV1{
		SchemaVersion: sandboxdispatch.ParserRequestVersionV1,
		ParserType:    parserType, Operation: operation, MediaFamily: media,
		SandboxProfileRevision:     sandboxdispatch.ProductionSandboxProfileRevision,
		ObservationProfileRevision: observation,
		MaxInputBytes:              64 << 20, MaxOutputBytes: 16 << 20,
		MaxUnits: 100000, MaxPages: 10000, MaxDecodedPixels: 1,
		OutputContract: output,
	}
	if parserType == sandboxdispatch.ParserTypeOCR {
		request.OCRProfileRevision = "tessdata-v1"
		request.SandboxProfileRevision = "ocr-sandbox-v1"
		request.MaxPages = 1
		request.MaxDecodedPixels = 100_000_000
		request.MaxInputBytes = 32 << 20
		request.MaxOutputBytes = 8 << 20
	}
	return sandboxdispatch.V2RegistryEntry{
		ParserRequest: request, ArtifactHash: artifact,
		MediaType: mediaType, MaxLeaseDuration: wallClock,
		ExpectedLimits:     limits,
		RuntimeProfileHash: sandboxdispatch.RuntimeProfileHash(parserType, request.SandboxProfileRevision, limits),
		ExpectedWorkerUID: map[string]int{
			sandboxdispatch.ParserTypeOffice: officeUID,
			sandboxdispatch.ParserTypePDF:    pdfUID,
			sandboxdispatch.ParserTypeOCR:    ocrUID,
		}[parserType],
		ExpectedWorkerGID: map[string]int{
			sandboxdispatch.ParserTypeOffice: officeGID,
			sandboxdispatch.ParserTypePDF:    pdfGID,
			sandboxdispatch.ParserTypeOCR:    ocrGID,
		}[parserType],
	}
}

// SubmitSocketPath is intentionally the proxy path, not the dispatcher's
// private submit listener. NewProduction therefore retains its exact typed
// submitter while the external supervisor gets one chance to start the real
// worker for each object.
func (h *Harness) SubmitSocketPath() string {
	if h == nil {
		return ""
	}
	return h.proxyPath
}

func (h *Harness) Close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		if h.controlLn != nil {
			_ = h.controlLn.Close()
		}
		if h.proxyCmd != nil && h.proxyCmd.Process != nil {
			_ = h.proxyCmd.Process.Kill()
		}
		if h.cancel != nil {
			h.cancel()
		}
		if h.dispatcher != nil {
			h.dispatcher.Close()
		}
		h.mu.Lock()
		workers := append([]*workerProcess(nil), h.workers...)
		h.mu.Unlock()
		for _, worker := range workers {
			if worker == nil {
				continue
			}
			if worker.pidfd >= 0 {
				_ = unix.PidfdSendSignal(worker.pidfd, unix.SIGKILL, nil, 0)
				_ = unix.Close(worker.pidfd)
				worker.pidfd = -1
			} else if worker.cmd != nil && worker.cmd.Process != nil {
				_ = worker.cmd.Process.Kill()
			}
		}
		for _, worker := range workers {
			if worker == nil || worker.cmd == nil {
				continue
			}
			select {
			case <-worker.done:
				if h.logf != nil && worker.cmd.ProcessState != nil {
					h.logf("parser process exit: code=%d success=%t", worker.cmd.ProcessState.ExitCode(), worker.cmd.ProcessState.Success())
				}
			case <-time.After(5 * time.Second):
				if h.logf != nil {
					h.logf("parser process exit: wait deadline exceeded")
				}
			}
			if h.logf != nil {
				// Fixed kernel counters only: never copy parser stderr, source
				// bytes, job IDs or exception messages into qualification logs.
				for _, name := range []string{"memory.events", "memory.peak", "pids.events", "pids.peak", "cpu.stat"} {
					raw, err := os.ReadFile(filepath.Join(worker.cgroup, name))
					if err == nil && len(raw) <= 4096 {
						h.logf("parser kernel %s: %q", name, raw)
					}
				}
				if info, err := os.Stat(filepath.Join(worker.rootfs, "tmp")); err == nil {
					h.logf("parser scratch mode: %s", info.Mode())
				}
			}
			_ = unix.Unmount(filepath.Join(worker.rootfs, "run", "knowvault"), unix.MNT_DETACH)
			_ = unix.Unmount(filepath.Join(worker.rootfs, "tmp"), unix.MNT_DETACH)
			_ = os.Remove(worker.cgroup)
			_ = os.RemoveAll(worker.rootfs)
		}
		if h.proxyCmd != nil {
			_ = h.proxyCmd.Wait()
		}
		select {
		case <-h.controlDone:
		case <-time.After(5 * time.Second):
		}
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
		}
		_ = os.Remove(h.proxyPath)
		_ = os.RemoveAll(h.root)
	})
}

func (h *Harness) serveControl() {
	for {
		conn, err := h.controlLn.AcceptUnix()
		if err != nil {
			close(h.controlDone)
			return
		}
		go h.handleControl(conn)
	}
}

func (h *Harness) handleControl(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(wallClock + 10*time.Second))
	_, job, err := readJobFrame(conn)
	if err != nil {
		return
	}
	_, err = readPayloadFrame(conn, 64<<20)
	if err != nil {
		return
	}
	role := job.ParserRequest.ParserType
	roleLock := h.roleMu[role]
	if roleLock == nil {
		return
	}
	roleLock.Lock()
	defer roleLock.Unlock()
	if err := h.ensureWorker(role); err != nil {
		return
	}
	if err := h.waitWorkerReady(role, 15*time.Second); err != nil {
		_ = writeControlFrame(conn, controlError, []byte("worker unavailable"))
		return
	}
	if err := writeControlFrame(conn, controlReady, []byte("ready")); err != nil {
		return
	}
	for {
		kind, _, err := readControlFrame(conn)
		if err != nil {
			return
		}
		switch kind {
		case controlDone:
			return
		default:
			return
		}
	}
}

func (h *Harness) waitWorkerReady(role string, timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("invalid worker readiness timeout")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if h.dispatcher.ParserReady(role) {
			return nil
		}
		worker := h.currentWorker(role)
		if worker == nil {
			return errors.New("worker disappeared before registration")
		}
		select {
		case <-worker.done:
			h.clearWorker(role, worker)
			return errors.New("worker exited before registration")
		case <-ticker.C:
		case <-deadline.C:
			return errors.New("worker registration timed out")
		}
	}
}

const (
	controlReady byte = 21 + iota
	controlRetry
	controlDone
	controlError
)

func writeControlFrame(conn net.Conn, kind byte, body []byte) error {
	if len(body) == 0 || len(body) > 64<<10 {
		return errors.New("invalid control frame")
	}
	header := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:], uint32(len(body)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

func readControlFrame(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 1 || length > 64<<10 {
		return 0, nil, errors.New("invalid control frame length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return header[0], body, nil
}

// RunSubmitProxyHelper is the non-root submitter half of the test supervisor.
// The helper is exec'd from the test binary with uid/gid 65530.  It owns the
// public facade socket, therefore DispatcherV2 observes the exact configured
// submitter credentials when the helper dials the private submit socket.
//
// A request is copied byte-for-byte over the root supervisor control socket so
// the supervisor can admit one fresh worker before the request reaches the
// dispatcher.  The helper never interprets source bytes and never invokes a
// parser; it only relays v2 frames and retries the same opaque request when the
// dispatcher reports TRANSFER_RETRY.
func RunSubmitProxyHelper() error {
	if os.Getenv("KNOWVAULT_P2_SUBMIT_PROXY_HELPER") != "1" {
		return errors.New("submit proxy helper was not requested")
	}
	publicPath := os.Getenv("KNOWVAULT_P2_SUBMIT_PROXY_PUBLIC")
	controlPath := os.Getenv("KNOWVAULT_P2_SUBMIT_PROXY_CONTROL")
	dispatcherPath := os.Getenv("KNOWVAULT_P2_SUBMIT_PROXY_DISPATCHER")
	if publicPath == "" || controlPath == "" || dispatcherPath == "" {
		return errors.New("submit proxy helper paths are incomplete")
	}
	if err := removeSocket(publicPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: publicPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(publicPath, 0o600); err != nil {
		return err
	}
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		go serveSubmitProxyRequest(conn, controlPath, dispatcherPath)
	}
}

func serveSubmitProxyRequest(client *net.UnixConn, controlPath, dispatcherPath string) {
	defer client.Close()
	deadline := time.Now().Add(wallClock + 10*time.Second)
	_ = client.SetDeadline(deadline)
	jobFrame, job, err := readJobFrame(client)
	if err != nil {
		return
	}
	payloadFrame, err := readPayloadFrame(client, 64<<20)
	if err != nil {
		return
	}
	control, err := net.DialTimeout("unix", controlPath, 5*time.Second)
	if err != nil {
		return
	}
	defer control.Close()
	_ = control.SetDeadline(deadline)
	if err := writeAll(control, jobFrame); err != nil {
		return
	}
	if err := writeAll(control, payloadFrame); err != nil {
		return
	}
	kind, _, err := readControlFrame(control)
	if err != nil || kind != controlReady {
		return
	}
	// controlReady now means the fresh one-shot worker completed registration,
	// not merely that its supervisor handoff was accepted. Submit exactly once:
	// an unexpected pre-transfer retry is returned to the real caller, which
	// must mint a fresh parser job instead of replaying the same v2 job id.
	response, _, forwardErr := forwardToDispatcher(dispatcherPath, jobFrame, payloadFrame, job)
	if forwardErr != nil {
		_ = writeControlFrame(control, controlDone, []byte("dispatcher-error"))
		return
	}
	if err := writeAll(client, response); err != nil {
		_ = writeControlFrame(control, controlDone, []byte("client-closed"))
		return
	}
	_ = writeControlFrame(control, controlDone, []byte("done"))
}

func forwardToDispatcher(socketPath string, jobFrame, payloadFrame []byte, job sandboxdispatch.JobV2) ([]byte, bool, error) {
	backend, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, false, err
	}
	defer backend.Close()
	deadline := time.Now().Add(wallClock + 10*time.Second)
	if parsed, err := time.Parse(time.RFC3339Nano, job.DeadlineAt); err == nil && parsed.Before(deadline) {
		deadline = parsed
	}
	if err := backend.SetDeadline(deadline); err != nil {
		return nil, false, err
	}
	if err := writeAll(backend, jobFrame); err != nil {
		return nil, false, err
	}
	if err := writeAll(backend, payloadFrame); err != nil {
		return nil, false, err
	}
	response, err := io.ReadAll(backend)
	if err != nil {
		return response, false, err
	}
	if len(response) < 5 || response[0] != 6 {
		return response, false, errors.New("invalid v2 dispatcher response")
	}
	length := binary.BigEndian.Uint32(response[1:5])
	if length < 1 || int64(5+length) > int64(len(response)) {
		return response, false, errors.New("invalid v2 dispatcher outcome")
	}
	var outcome sandboxdispatch.OutcomeV2
	if err := json.Unmarshal(response[5:5+length], &outcome); err != nil {
		return response, false, err
	}
	return response, outcome.Handoff.TransferState == sandboxdispatch.TransferRetry, nil
}

func (h *Harness) currentWorker(role string) *workerProcess {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current[role]
}

func (h *Harness) clearWorker(role string, worker *workerProcess) {
	h.mu.Lock()
	if h.current[role] == worker {
		delete(h.current, role)
	}
	h.mu.Unlock()
}

func (h *Harness) ensureWorker(role string) error {
	h.mu.Lock()
	current := h.current[role]
	h.mu.Unlock()
	if current != nil {
		select {
		case <-current.done:
			h.clearWorker(role, current)
			// Let DispatcherV2's registration goroutine observe the old
			// socket closure and remove its one-shot worker before replacing
			// the role. This is bounded and only occurs after process exit.
			time.Sleep(25 * time.Millisecond)
		default:
			return nil
		}
	}
	worker, err := h.startWorker(role)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.current[role] = worker
	h.workers = append(h.workers, worker)
	h.mu.Unlock()
	return nil
}

func (h *Harness) startWorker(role string) (*workerProcess, error) {
	if role != sandboxdispatch.ParserTypeOffice && role != sandboxdispatch.ParserTypePDF && role != sandboxdispatch.ParserTypeOCR {
		return nil, errors.New("unknown parser role")
	}
	if role == sandboxdispatch.ParserTypeOCR && !h.ocrImage {
		return nil, errors.New("OCR parser role requires an OCR image")
	}
	uid, gid := h.roleUID[role], h.roleGID[role]
	if uid < 1 || gid < 1 {
		return nil, errors.New("parser role identity unavailable")
	}
	h.mu.Lock()
	h.seq++
	seq := h.seq
	h.mu.Unlock()
	rootfs := filepath.Join(h.root, fmt.Sprintf("worker-%06d", seq))
	if err := cloneRootfs(h.base, rootfs); err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(rootfs)
		}
	}()
	if err := prepareWorkerRootfs(rootfs, h.roleRoots[role]); err != nil {
		return nil, err
	}
	roleRoot := h.roleRoots[role]
	gate := filepath.Join(roleRoot, fmt.Sprintf("start-%06d", seq))
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		return nil, err
	}
	if err := os.Chown(gate, uid, gid); err != nil {
		return nil, err
	}
	defer func() {
		if cleanup {
			_ = os.Remove(gate)
		}
	}()
	if err := unix.Mount(roleRoot, filepath.Join(rootfs, "run", "knowvault"), "", unix.MS_BIND, ""); err != nil {
		return nil, err
	}
	mountedRole := true
	defer func() {
		if cleanup && mountedRole {
			_ = unix.Unmount(filepath.Join(rootfs, "run", "knowvault"), unix.MNT_DETACH)
		}
	}()
	tmpPath := filepath.Join(rootfs, "tmp")
	if err := unix.Mount("tmpfs", tmpPath, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "size=64m"); err != nil {
		return nil, err
	}
	mountedTmp := true
	defer func() {
		if cleanup && mountedTmp {
			_ = unix.Unmount(tmpPath, unix.MNT_DETACH)
		}
	}()
	if err := stageExecHelper(rootfs); err != nil {
		return nil, err
	}
	// Include a process-start timestamp so a subsequent test binary invocation
	// cannot collide with cgroups left by an interrupted prior qualification.
	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("knowvault-parserv2-%d-%d-%06d", os.Getpid(), time.Now().UnixNano(), seq))
	if err := os.Mkdir(cgroup, 0o700); err != nil {
		return nil, err
	}
	cleanupCgroup := true
	defer func() {
		if cleanup && cleanupCgroup {
			_ = os.Remove(filepath.Join(cgroup, "cgroup.kill"))
			_ = os.Remove(cgroup)
		}
	}()
	if err := configureCgroup(cgroup, role); err != nil {
		return nil, err
	}
	handoffID := fmt.Sprintf("h_%s%08d", strings.Repeat("j", 32), seq)
	workerID := fmt.Sprintf("parser-%s-%06d", strings.ToLower(role), seq)
	socketPath := "/run/knowvault/register.sock"
	cmd := exec.Command("/app/knowvault-parser-exec-helper", "-test.run", "^TestParserV2ExecHelper$", "-test.v", "-test.timeout=130s")
	cmd.Dir = "/"
	cmd.Env = append(os.Environ(),
		"KNOWVAULT_P2_EXEC_HELPER=1",
		"KNOWVAULT_P2_EXEC_GATE=/run/knowvault/"+filepath.Base(gate),
		"KNOWVAULT_P2_EXEC_SOCKET=unix://"+socketPath,
		"KNOWVAULT_P2_EXEC_WORKER_ID="+workerID,
		"KNOWVAULT_P2_EXEC_PARSER_TYPE="+role,
		"KNOWVAULT_P2_EXEC_HANDOFF_ID="+handoffID,
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		Chroot:     rootfs,
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true},
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	worker := &workerProcess{cmd: cmd, done: make(chan struct{}), rootfs: rootfs, cgroup: cgroup, roleRoot: roleRoot, gate: gate, pidfd: -1}
	go func() {
		err := cmd.Wait()
		_ = err
		close(worker.done)
	}()
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		<-worker.done
		return nil, err
	}
	worker.pidfd = pidfd
	namespace, err := readPIDNamespace(cmd.Process.Pid)
	if err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
		worker.pidfd = -1
		<-worker.done
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
		worker.pidfd = -1
		<-worker.done
		return nil, err
	}
	cgroupPath, err := readCgroupPath(cmd.Process.Pid)
	if err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
		worker.pidfd = -1
		<-worker.done
		return nil, err
	}
	// Mount only after the gated, non-root child is inside its configured
	// cgroup, and verify the private proc view before offering the handoff.
	if err := mountWorkerProc(cmd.Process.Pid, pidfd, rootfs, namespace, cgroup, cgroupPath, uid, gid); err != nil {
		h.logf("parser runtime setup: %s", err.Error()) // closed content-free messages only
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
		worker.pidfd = -1
		<-worker.done
		return nil, err
	}
	issued := time.Now().UTC()
	artifactHash := QualifiedArtifactHash
	sandboxProfile := sandboxdispatch.ProductionSandboxProfileRevision
	observationProfile := map[string]string{
		sandboxdispatch.ParserTypeOffice: "office-obs-v1",
		sandboxdispatch.ParserTypePDF:    "pdf-obs-v1",
		sandboxdispatch.ParserTypeOCR:    "ocr-observation-v1",
	}[role]
	if role == sandboxdispatch.ParserTypeOCR {
		artifactHash = QualifiedOCRArtifactHash
		sandboxProfile = "ocr-sandbox-v1"
	}
	metadata := sandboxdispatch.SupervisorHandoffV1{
		SchemaVersion: sandboxdispatch.SupervisorHandoffVersionV1,
		HandoffID:     handoffID, ParserType: role, PIDFDTransport: "SCM_RIGHTS",
		ArtifactHash:               artifactHash,
		SandboxProfileRevision:     sandboxProfile,
		ObservationProfileRevision: observationProfile,
		PIDNamespaceInode:          namespace, CgroupPath: cgroupPath,
		ExpectedWorkerUID: uid, ExpectedWorkerGID: gid,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(15 * time.Second).Format(time.RFC3339),
		OneShot: true, MaxLeases: 1,
	}
	if err := sendHandoff(h.dispatcher.SupervisorHandoffSocketPath(), metadata, pidfd); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
		worker.pidfd = -1
		<-worker.done
		return nil, err
	}
	if err := os.WriteFile(gate, []byte("release"), 0o600); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
		worker.pidfd = -1
		<-worker.done
		return nil, err
	}
	cleanup = false
	cleanupCgroup = false
	mountedRole = false
	mountedTmp = false
	return worker, nil
}

func configureCgroup(path, role string) error {
	memory, pids := memoryMax, pidsMax
	if role == sandboxdispatch.ParserTypeOCR {
		memory, pids = memoryMaxOCR, pidsMaxOCR
	}
	for name, value := range map[string]string{
		"cpu.max": cpuQuotaMicros, "memory.max": memory, "pids.max": pids,
	} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func prepareWorkerRootfs(rootfs, _ string) error {
	for _, dir := range []string{"/run", "/run/knowvault", "/tmp", "/dev", "/proc"} {
		path := filepath.Join(rootfs, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
	}
	if err := os.Chmod(filepath.Join(rootfs, "tmp"), 0o1777); err != nil {
		return err
	}
	// The scratch image intentionally carries no device tree. These are the
	// four read-only character devices the JVM/PDFBox runtime may need; no host
	// filesystem is exposed through a broad /dev bind mount.
	for _, device := range []struct {
		name string
		mode uint32
		dev  int
	}{
		{"null", unix.S_IFCHR | 0o666, int(unix.Mkdev(1, 3))},
		{"zero", unix.S_IFCHR | 0o666, int(unix.Mkdev(1, 5))},
		{"random", unix.S_IFCHR | 0o444, int(unix.Mkdev(1, 8))},
		{"urandom", unix.S_IFCHR | 0o444, int(unix.Mkdev(1, 9))},
	} {
		path := filepath.Join(rootfs, "dev", device.name)
		if err := unix.Mknod(path, device.mode, device.dev); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		// mknod applies the supervisor's umask. Restore the exact device
		// permissions required by the non-root worker (matching a minimal
		// container /dev), otherwise Python's subprocess.DEVNULL cannot open
		// /dev/null after the credential drop.
		if err := os.Chmod(path, os.FileMode(device.mode&0o777)); err != nil {
			return err
		}
	}
	return nil
}

func mountWorkerProc(pid, pidfd int, rootfs, namespace, cgroup, cgroupPath string, uid, gid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	procTarget := filepath.Join(rootfs, "proc")
	info, err := os.Lstat(procTarget)
	if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("private worker proc target invalid")
	}
	mountNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil || unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil {
		return errors.New("private worker proc target unavailable")
	}
	// nsenter forks after setns(CLONE_NEWPID), so mount(2) observes the worker
	// PID namespace. Keep the supervisor root for the external mount binary;
	// only the dedicated worker mount namespace is modified. These temporary
	// helpers remain in the supervisor cgroup and exit before handoff is offered.
	for _, args := range [][]string{
		{"--make-rprivate", "/"},
		{"-t", "proc", "-o", "ro,nosuid,nodev,noexec", "proc", procTarget},
	} {
		argv := []string{"--target", strconv.Itoa(pid), "--mount", "--pid", "--", "/usr/bin/mount"}
		cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", append(argv, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		if err := cmd.Run(); err != nil {
			return errors.New("private worker proc mount failed")
		}
	}
	observedMountNS, mountErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	observedPIDNS, pidErr := readPIDNamespace(pid)
	observedCgroup, cgroupErr := readCgroupPath(pid)
	members, membersErr := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil || mountErr != nil || observedMountNS != mountNS || pidErr != nil || observedPIDNS != namespace || cgroupErr != nil || observedCgroup != cgroupPath || membersErr != nil || strings.TrimSpace(string(members)) != strconv.Itoa(pid) {
		return errors.New("private worker proc identity changed")
	}
	// /proc/<host-pid>/root traverses the target's mount table, including mounts
	// absent from the supervisor's view. PID 1 must be this namespace's helper.
	view := fmt.Sprintf("/proc/%d/root/proc", pid)
	var fs unix.Statfs_t
	flags := int64(unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if err := unix.Statfs(view, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC || fs.Flags&flags != flags {
		return errors.New("private worker proc flags invalid")
	}
	initNS, err := os.Readlink(filepath.Join(view, "1", "ns", "pid"))
	if err != nil || initNS != "pid:["+namespace+"]" {
		return errors.New("private worker proc PID namespace invalid")
	}
	status, err := os.ReadFile(filepath.Join(view, "1", "status"))
	if err != nil {
		return errors.New("private worker proc status unavailable")
	}
	for name, want := range map[string]string{"Uid:": strconv.Itoa(uid), "Gid:": strconv.Itoa(gid), "NSpid:": "1"} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != name {
				continue
			}
			found = true
			for _, value := range fields[1:] {
				if value != want {
					return errors.New("private worker proc credentials invalid")
				}
			}
		}
		if !found {
			return errors.New("private worker proc credentials missing")
		}
	}
	return nil
}

func stageExecHelper(rootfs string) error {
	return stageBinary(filepath.Join(rootfs, "app", "knowvault-parser-exec-helper"))
}

func stageBinary(path string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		return err
	}
	return os.Chmod(path, 0o755)
}

func cloneRootfs(source, destination string) error {
	if err := os.Mkdir(destination, 0o755); err != nil {
		return err
	}
	return cloneTree(source, destination)
}

func cloneTree(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(source, entry.Name())
		dst := filepath.Join(destination, entry.Name())
		info, err := os.Lstat(src)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := os.Mkdir(dst, info.Mode().Perm()); err != nil {
				return err
			}
			if err := cloneTree(src, dst); err != nil {
				return err
			}
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, dst); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := os.Link(src, dst); err != nil {
				in, openErr := os.Open(src)
				if openErr != nil {
					return err
				}
				out, createErr := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, info.Mode().Perm())
				if createErr != nil {
					_ = in.Close()
					return createErr
				}
				_, copyErr := io.Copy(out, in)
				_ = in.Close()
				_ = out.Close()
				if copyErr != nil {
					return copyErr
				}
			}
		default:
			return fmt.Errorf("unsupported image entry %s", src)
		}
	}
	return nil
}

type imageInspect struct {
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		User       string   `json:"User"`
		WorkingDir string   `json:"WorkingDir"`
		Env        []string `json:"Env"`
	} `json:"Config"`
}

// documentParserImageEntrypoint is the single source for both the image-config
// assertion and the qualification exec. The helper may append only the closed
// dispatcher-once arguments; it cannot add JVM flags absent from the image.
func documentParserImageEntrypoint() []string {
	return []string{
		"/opt/jre/bin/java", "-XX:ActiveProcessorCount=1", "-XX:MaxRAMPercentage=75.0", "-XX:+ExitOnOutOfMemoryError",
		"-Dlog4j2.loggerContextFactory=org.apache.logging.log4j.simple.SimpleLoggerContextFactory",
		"-Dlog4j2.simplelogLevel=OFF", "-Dlog4j2.defaultStatusLevel=OFF", "-Dlog4j2.status.entries=0",
		"-Djava.awt.headless=true", "-Dfile.encoding=UTF-8", "-Djava.io.tmpdir=/tmp",
		"-Duser.language=en", "-Duser.country=US", "-cp", "/app/document-parser-worker.jar:/app/lib/*",
		"local.knowvault.docparser.Main",
	}
}

func documentParserImageEnvironment() []string {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
}

func extractImage(image, destination string) error {
	inspect, err := dockerOutput("inspect", image)
	if err != nil {
		return err
	}
	var images []imageInspect
	if err := json.Unmarshal(inspect, &images); err != nil || len(images) != 1 {
		return errors.New("qualified image inspect failed")
	}
	if isOCRImage(image) {
		wantEntrypoint := []string{"python3", "/opt/ocr/worker.py"}
		if !sameStrings(images[0].Config.Entrypoint, wantEntrypoint) || len(images[0].Config.Cmd) != 0 || images[0].Config.User != "65532:65532" || images[0].Config.WorkingDir != "/opt/ocr" {
			return errors.New("qualified OCR image entrypoint/user/working-directory drift")
		}
	} else {
		wantEntrypoint := documentParserImageEntrypoint()
		if !sameStrings(images[0].Config.Entrypoint, wantEntrypoint) || !sameStrings(images[0].Config.Env, documentParserImageEnvironment()) || len(images[0].Config.Cmd) != 0 || images[0].Config.User != "65532:65532" || images[0].Config.WorkingDir != "/app" {
			return errors.New("qualified parser image entrypoint/user/working-directory drift")
		}
	}
	container, err := dockerOutput("create", "--platform", "linux/amd64", image)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(container))
	defer func() { _, _ = dockerOutput("rm", "-v", id) }()
	archivePath := destination + ".tar"
	if _, err := dockerOutput("export", "--output", archivePath, id); err != nil {
		return err
	}
	defer os.Remove(archivePath)
	if err := os.Mkdir(destination, 0o755); err != nil {
		return err
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	err = extractTar(archive, destination)
	_ = archive.Close()
	if err != nil {
		return err
	}
	if isOCRImage(image) {
		identity, err := os.ReadFile(filepath.Join(destination, "opt", "ocr", "identity.json"))
		if err != nil || !strings.Contains(string(identity), `"worker_artifact_hash":"`+QualifiedOCRArtifactHash+`"`) {
			return errors.New("qualified OCR artifact identity mismatch")
		}
	} else {
		artifact, err := os.ReadFile(filepath.Join(destination, "app", "artifact.sha256"))
		if err != nil || strings.TrimSpace(string(artifact)) != QualifiedArtifactHash {
			return errors.New("qualified parser artifact identity mismatch")
		}
	}
	return nil
}

func dockerOutput(args ...string) ([]byte, error) {
	command := exec.Command("docker", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

func extractTar(input io.Reader, destination string) error {
	reader := tar.NewReader(input)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(header.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe image archive path")
		}
		target := filepath.Join(destination, name)
		if !pathWithin(destination, target) {
			return fmt.Errorf("image archive path escaped rootfs")
		}
		// `docker export` materializes these five container-runtime entries even
		// for a scratch image. They are not image bytes (and /etc/mtab points at
		// the host namespace), so omit them before constructing the exact image
		// rootfs used by the Java process.
		switch name {
		case "etc", "etc/hostname", "etc/hosts", "etc/mtab", "etc/resolv.conf":
			continue
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, header.FileInfo().Mode().Perm()); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, header.FileInfo().Mode().Perm())
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(file, reader)
			_ = file.Close()
			if copyErr != nil {
				return copyErr
			}
		case tar.TypeSymlink:
			linkName := filepath.FromSlash(header.Linkname)
			if filepath.IsAbs(linkName) {
				// OCI/Docker rootfs layers commonly use an absolute target such as
				// /usr/bin/python3.  Inside the extracted, chrooted tree that target
				// must remain rooted at destination; rewrite it to a relative link
				// after proving the root-relative target stays within the tree.
				rootTarget := filepath.Join(destination, strings.TrimPrefix(linkName, string(filepath.Separator)))
				if !pathWithin(destination, rootTarget) {
					return fmt.Errorf("unsafe image symlink")
				}
				relative, err := filepath.Rel(filepath.Dir(target), rootTarget)
				if err != nil {
					return fmt.Errorf("unsafe image symlink")
				}
				linkName = relative
			} else if strings.HasPrefix(filepath.Clean(filepath.Join(filepath.Dir(name), linkName)), ".."+string(filepath.Separator)) {
				return fmt.Errorf("unsafe image symlink")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(linkName, target); err != nil {
				return err
			}
		case tar.TypeLink:
			link := filepath.Clean(filepath.FromSlash(header.Linkname))
			if filepath.IsAbs(link) || link == ".." || strings.HasPrefix(link, ".."+string(filepath.Separator)) {
				return fmt.Errorf("unsafe image hardlink")
			}
			if err := os.Link(filepath.Join(destination, link), target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported image archive entry")
		}
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			_ = os.Chmod(target, header.FileInfo().Mode().Perm())
			_ = os.Chown(target, header.Uid, header.Gid)
		}
	}
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func readJobFrame(conn net.Conn) ([]byte, sandboxdispatch.JobV2, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 10 {
		return nil, sandboxdispatch.JobV2{}, errors.New("invalid v2 job frame")
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 1 || length > 64<<10 {
		return nil, sandboxdispatch.JobV2{}, errors.New("invalid v2 job length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, sandboxdispatch.JobV2{}, err
	}
	var job sandboxdispatch.JobV2
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, sandboxdispatch.JobV2{}, err
	}
	return append(header, body...), job, nil
}

func readPayloadFrame(conn net.Conn, maxPayload int) ([]byte, error) {
	prefix := make([]byte, 9)
	if _, err := io.ReadFull(conn, prefix); err != nil || prefix[0] != 3 {
		return nil, errors.New("invalid v2 payload frame")
	}
	headerLength := binary.BigEndian.Uint32(prefix[1:5])
	payloadLength := binary.BigEndian.Uint32(prefix[5:9])
	if headerLength < 1 || headerLength > 4<<10 || payloadLength < 1 || int64(payloadLength) > int64(maxPayload) {
		return nil, errors.New("invalid v2 payload length")
	}
	body := make([]byte, int64(headerLength)+int64(payloadLength))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(prefix, body...), nil
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readPIDNamespace(pid int) (string, error) {
	link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/pid")
	if err != nil {
		return "", err
	}
	const prefix, suffix = "pid:[", "]"
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, suffix) {
		return "", errors.New("invalid PID namespace")
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, prefix), suffix), nil
}

func readCgroupPath(pid int) (string, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Split(line, "::")
		if len(parts) == 2 && parts[0] == "0" && parts[1] != "" {
			return parts[1], nil
		}
	}
	return "", errors.New("unified cgroup path unavailable")
}

func sendHandoff(path string, metadata sandboxdispatch.SupervisorHandoffV1, pidfd int) error {
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
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 1 || length > 64<<10 {
		return errors.New("invalid handoff acknowledgment")
	}
	ack := make([]byte, length)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return err
	}
	if header[0] != 15 || string(ack) != sandboxdispatch.SupervisorHandoffAcceptedV1 {
		return errors.New("supervisor handoff rejected")
	}
	return nil
}

// ExecImageEntrypoint is called by TestParserV2ExecHelper after the parent has
// completed the pidfd handoff. It replaces the helper process in-place, so the
// pidfd, PID namespace and cgroup all refer to the real Java process.
func ExecImageEntrypoint() error {
	if os.Getenv("KNOWVAULT_P2_EXEC_HELPER") != "1" {
		return errors.New("parser exec helper was not requested")
	}
	gate := os.Getenv("KNOWVAULT_P2_EXEC_GATE")
	for {
		contents, err := os.ReadFile(gate)
		if err == nil && len(contents) != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	socket := os.Getenv("KNOWVAULT_P2_EXEC_SOCKET")
	workerID := os.Getenv("KNOWVAULT_P2_EXEC_WORKER_ID")
	parserType := os.Getenv("KNOWVAULT_P2_EXEC_PARSER_TYPE")
	handoffID := os.Getenv("KNOWVAULT_P2_EXEC_HANDOFF_ID")
	if parserType == sandboxdispatch.ParserTypeOCR {
		// The OCR candidate is a non-root Python image, but it participates in
		// the same one-shot DispatcherV2 handoff and receives the same opaque
		// framed payload.  Exec replaces this test helper so pidfd/cgroup proof
		// remains bound to the actual OCR process rather than a shim.
		argv := []string{
			"python3", "/opt/ocr/worker.py", "--mode=dispatcher-once", "--socket=" + socket,
			"--worker-id=" + workerID, "--parser-type=" + parserType,
			"--supervisor-handoff-id=" + handoffID,
		}
		return syscall.Exec("/usr/local/bin/python3", argv, os.Environ())
	}
	argv := append([]string(nil), documentParserImageEntrypoint()...)
	argv = append(argv,
		"--mode=dispatcher-once", "--socket="+socket, "--worker-id="+workerID,
		"--parser-type="+parserType, "--supervisor-handoff-id="+handoffID,
	)
	if err := os.Chdir("/app"); err != nil {
		return err
	}
	return syscall.Exec(argv[0], argv, documentParserImageEnvironment())
}
