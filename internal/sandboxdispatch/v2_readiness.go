package sandboxdispatch

import (
	"context"
	"errors"
	"net"
	"time"
)

// The probe has no caller-selected role, path, job, identity or payload. Its
// exact body binds the caller to the locked native profile and artifact. It is
// served only after the ordinary submit socket's UID/GID check.
const nativeReadinessBodyV2 = "sandbox-native-readiness-v1/" + ProductionSandboxProfileRevision + "/" + ProductionParserArtifactHash
const nativeReadyBodyV2 = "ready/" + nativeReadinessBodyV2
const nativeUnavailableBodyV2 = "unavailable/" + nativeReadinessBodyV2

var ErrNativeNotReady = errors.New("sandboxdispatch: native parsers not ready")

// CheckNativeReadiness reports available OFFICE and text-PDF capacity at the
// instant of the reply. It never admits a job or reserves a parser. Normal job
// admission remains authoritative after this advisory snapshot.
func (s *Submitter) CheckNativeReadiness(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.V2SubmitSocketPath == "" || s.FrameTimeout <= 0 {
		return ErrNativeNotReady
	}
	deadline := time.Now().Add(s.FrameTimeout)
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "unix", s.V2SubmitSocketPath)
	if err != nil {
		return ErrNativeNotReady
	}
	defer conn.Close()
	if conn.SetDeadline(deadline) != nil {
		return ErrNativeNotReady
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if writeFrame(conn, kindNativeReadinessV2, []byte(nativeReadinessBodyV2)) != nil {
		return ErrNativeNotReady
	}
	kind, body, err := readFrame(conn, len(nativeUnavailableBodyV2))
	if err != nil || kind != kindNativeReadinessResultV2 || string(body) != nativeReadyBodyV2 || ctx.Err() != nil {
		return ErrNativeNotReady
	}
	return nil
}

func (d *DispatcherV2) handleV2NativeReadiness(conn *net.UnixConn, body []byte) {
	if string(body) != nativeReadinessBodyV2 {
		return
	}
	if conn.SetWriteDeadline(time.Now().Add(d.cfg.FrameTimeout)) != nil {
		return
	}
	// The same barrier as result publication prevents a ready reply after RED
	// has been latched. No job/replay/lease table is changed by this exchange.
	d.relayMu.Lock()
	defer d.relayMu.Unlock()
	d.mu.Lock()
	ready := d.nativeV2ReadyLocked()
	d.mu.Unlock()
	response := nativeUnavailableBodyV2
	if ready {
		response = nativeReadyBodyV2
	}
	_ = writeFrame(conn, kindNativeReadinessResultV2, []byte(response))
}

func (d *DispatcherV2) nativeV2ReadyLocked() bool {
	if d.red || d.closed {
		return false
	}
	expected := ProductionV2Registry(d.cfg.WorkerUIDByParser[ParserTypeOffice], d.cfg.WorkerGIDByParser[ParserTypeOffice],
		d.cfg.WorkerUIDByParser[ParserTypePDF], d.cfg.WorkerGIDByParser[ParserTypePDF])
	for _, entry := range expected {
		if entry.ParserRequest.Operation == OperationRenderPDFPages {
			continue // OCR/render is not enabled by this native profile.
		}
		registered := false
		for _, actual := range d.cfg.Registry {
			if actual.ParserRequest == entry.ParserRequest && actual.MediaType == entry.MediaType &&
				actual.MaxLeaseDuration == entry.MaxLeaseDuration && sameV2RegistrationPolicy(actual, entry) {
				registered = true
				break
			}
		}
		if !registered {
			return false
		}
		worker := d.workers[entry.ParserRequest.ParserType]
		if worker == nil || !worker.ready || worker.used || worker.active != nil || !sameV2RegistrationPolicy(worker.entry, entry) {
			return false
		}
	}
	return true
}
