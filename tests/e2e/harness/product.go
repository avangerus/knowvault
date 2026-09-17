//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// managedProcess is one spawned product binary with its output log. The
// process runs as the pinned runtime group; kill sends SIGKILL, the failure
// mode a crashed worker dies with.
type managedProcess struct {
	name    string
	logPath string
	command *exec.Cmd
	exit    chan error
	exited  bool
}

func (process *managedProcess) String() string { return process.name }

// wait polls the process for a non-blocking exit. A nil return means the
// process is still running; an error is the captured exit state.
func (process *managedProcess) wait() error {
	if process == nil || process.exited {
		if process == nil {
			return fmt.Errorf("nil process")
		}
		return fmt.Errorf("%s already exited", process.name)
	}
	select {
	case err := <-process.exit:
		process.exited = true
		return err
	default:
		return nil
	}
}

func (process *managedProcess) kill() error {
	if process == nil || process.exited {
		return fmt.Errorf("%s not running", process.name)
	}
	if err := process.command.Process.Kill(); err != nil {
		return fmt.Errorf("kill %s: %w", process.name, err)
	}
	select {
	case <-process.exit:
		process.exited = true
		return nil
	case <-time.After(10 * time.Second):
		return fmt.Errorf("%s did not exit after SIGKILL", process.name)
	}
}

// logFull returns the whole process log for failure diagnostics where the
// interesting part is not at the tail (e.g. a SIGQUIT goroutine dump whose
// tail is only register values). Capped to keep the harness report bounded.
func (process *managedProcess) logFull() string {
	if process == nil {
		return ""
	}
	raw, err := os.ReadFile(process.logPath)
	if err != nil {
		return ""
	}
	const capBytes = 256 << 10
	if len(raw) > capBytes {
		return string(raw[len(raw)-capBytes:])
	}
	return string(raw)
}

// logTail returns the last lines of the process log for failure diagnostics.
func (process *managedProcess) logTail() string {
	if process == nil {
		return ""
	}
	raw, err := os.ReadFile(process.logPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return strings.Join(lines, "\n")
}

// spawn starts one product binary under the pinned runtime group with exactly
// the allowlisted KNOWVAULT_* variables of that binary. The composition layer
// fails closed on any other KNOWVAULT_* name, so the environment is
// constructed explicitly and never inherits the harness configuration.
func spawn(ctx context.Context, binaryPath, logPath string, environment map[string]string, arguments ...string) (*managedProcess, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.Command(binaryPath, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: runtimeGID, Gid: runtimeGID}}
	command.Env = productEnvironment(environment)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	process := &managedProcess{name: filepath.Base(binaryPath), logPath: logPath, command: command, exit: make(chan error, 1)}
	go func() {
		waitErr := command.Wait()
		_ = logFile.Close()
		process.exit <- waitErr
	}()
	return process, nil
}

// spawnWorkerChroot starts the worker inside its own chroot, the container-
// equivalent of the deployment's separate worker container: the harness
// re-executes itself in the worker-exec mode, that branch chroots into the
// prepared worker root, drops to the runtime group and execs the worker
// binary. The worker sees /run/knowvault/secrets, /run/knowvault/trust and
// /run/knowvault/sources inside the chroot with its own database URL, exactly
// as DEPLOYMENT.md §4 prescribes for the worker mount. The log file
// descriptor is opened before the chroot, so the harness keeps reading the
// log by its host-side path.
func spawnWorkerChroot(ctx context.Context, logPath, chrootDir string, environment map[string]string) (*managedProcess, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	// The worker chroot has no /e2e/certs, so the process-wide certificate
	// file must point at the CA copy placed at the chroot root.
	workerEnv := make([]string, 0, len(environment)+4)
	for _, name := range sortedEnvNames(environment) {
		workerEnv = append(workerEnv, name+"="+environment[name])
	}
	workerEnv = append(workerEnv, "SSL_CERT_FILE=/ca.pem", "PATH=/",
		"E2E_WORKER_CHROOT="+chrootDir, "E2E_WORKER_BINARY=/knowvault-worker")
	command := exec.Command("/e2e-harness", "worker-exec")
	command.Env = workerEnv
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	process := &managedProcess{name: "knowvault-worker", logPath: logPath, command: command, exit: make(chan error, 1)}
	go func() {
		waitErr := command.Wait()
		_ = logFile.Close()
		process.exit <- waitErr
	}()
	return process, nil
}

// sortedEnvNames returns the environment names sorted for a stable product
// environment listing.
func sortedEnvNames(environment map[string]string) []string {
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// productEnvironment merges the explicit product variables with a minimal
// fixed base: the process-wide certificate file for the scratch runtime's
// missing system trust store, and a stable PATH so the binaries find nothing
// unexpected. No E2E_* variable is passed through.
func productEnvironment(environment map[string]string) []string {
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(names)+2)
	for _, name := range names {
		result = append(result, name+"="+environment[name])
	}
	result = append(result, "SSL_CERT_FILE="+certificateFile(), "PATH=/")
	return result
}

// certificateFile is the process-wide trust anchor the harness pinned at
// startup; product binaries inherit it for any stdlib TLS they open directly.
func certificateFile() string { return os.Getenv("SSL_CERT_FILE") }

// prepareSourceMount lays out the pinned source mount for the worker exactly
// as the deployment document prescribes: the manifest at the mount root, one
// entry directory per source root, the corpus below the registered relative
// root, everything owned by root:65532 with group-readable modes and no
// group/world write bits (the worker mount loader rejects those). The mount
// root is the caller-provided worker chroot path: the worker sees it at
// /run/knowvault/sources inside its own container-equivalent filesystem.
func prepareSourceMount(ctx context.Context, cfg config, mountRoot string) error {
	manifest := map[string]any{
		"schema": "knowvault-source-mount-manifest-v1",
		"roots": []map[string]string{
			{"alias": "e2e-root", "identity": "e2e-root-id", "directory": "corpus"},
		},
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(mountRoot, "manifest.json")
	if err := os.WriteFile(manifestPath, rawManifest, 0o440); err != nil {
		return fmt.Errorf("write source manifest: %w", err)
	}
	if err := syscall.Chown(manifestPath, 0, runtimeGID); err != nil {
		return fmt.Errorf("chown source manifest: %w", err)
	}

	inbox := filepath.Join(mountRoot, "corpus", "inbox")
	if err := os.MkdirAll(inbox, 0o750); err != nil {
		return fmt.Errorf("mkdir corpus inbox: %w", err)
	}
	entries, err := os.ReadDir(cfg.corpusDir)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(cfg.corpusDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("read corpus %s: %w", entry.Name(), err)
		}
		target := filepath.Join(inbox, entry.Name())
		if err := os.WriteFile(target, content, 0o640); err != nil {
			return fmt.Errorf("write corpus %s: %w", entry.Name(), err)
		}
		if err := syscall.Chown(target, 0, runtimeGID); err != nil {
			return fmt.Errorf("chown corpus %s: %w", entry.Name(), err)
		}
	}
	// The directory chain below the mount root is created by the harness, so
	// it must carry the same 0:65532 ownership as the image-provided root.
	for _, dir := range []string{
		filepath.Join(mountRoot, "corpus"),
		inbox,
	} {
		if err := syscall.Chown(dir, 0, runtimeGID); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
	}
	return nil
}

// startServer spawns the product server and blocks until the full login
// surface answers through the TLS front: a completed /auth/login response
// proves the OIDC preflight, provider configuration and mount resolution all
// succeeded inside the product process.
func startServer(ctx context.Context, cfg config) (*managedProcess, error) {
	process, err := spawn(ctx, "/knowvault-server", "/e2e/run/server.log", map[string]string{
		"KNOWVAULT_ORGANIZATION_ID": cfg.organizationID,
		"KNOWVAULT_PROVIDER_ID":     cfg.providerID,
		"KNOWVAULT_PUBLIC_ORIGIN":   cfg.publicOrigin,
		"KNOWVAULT_HTTP_ADDR":       cfg.httpAddr,
	})
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if exitErr := process.wait(); exitErr != nil {
			return nil, fmt.Errorf("server exited during startup: %v\n%s", exitErr, process.logTail())
		}
		if serverReady(ctx, cfg) {
			return process, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("server did not become ready\n%s", process.logTail())
}

// serverReady probes the login route through the public origin. Readiness is
// the product's own 3xx OIDC authorization redirect: it proves the preflight,
// provider configuration and mount resolution all succeeded inside the
// product process. Any other status — including the proxy's 502 for a
// not-yet-listening backend — is not ready, and redirects are not followed.
func serverReady(ctx context.Context, cfg config) bool {
	request, err := httpNewRequest(ctx, "GET", cfg.publicOrigin+"/auth/login")
	if err != nil {
		return false
	}
	client := &http.Client{
		Transport: harnessHTTPClient().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode >= 300 && response.StatusCode < 400
}

// startWorker spawns the product worker with the deployment-document
// environment: the five worker variables only, the fixed service principal
// resolved inside the worker composition, poll strictly below lease so a
// crash leaves a recoverable attempt.
func startWorker(ctx context.Context, cfg config) (*managedProcess, error) {
	worker, err := spawnWorkerChroot(ctx, "/e2e/run/worker.log", workerChrootDir, map[string]string{
		"KNOWVAULT_ORGANIZATION_ID":      cfg.organizationID,
		"KNOWVAULT_PROVIDER_ID":          cfg.providerID,
		"KNOWVAULT_WORKER_ID":            "e2e-worker",
		"KNOWVAULT_WORKER_LEASE_SECONDS": "10",
		"KNOWVAULT_WORKER_POLL_SECONDS":  "1",
	})
	if err != nil {
		return nil, err
	}
	// Give the worker its startup window: mounts, database and queue all
	// acquire before the first poll, and a startup failure must surface here
	// with the log instead of as a silently missing claim later.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exitErr := worker.wait(); exitErr != nil {
			return nil, fmt.Errorf("worker exited during startup: %v\n%s", exitErr, worker.logTail())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return worker, nil
}
