//go:build linux

package sandboxdispatch

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readyProbeDispatcher() *DispatcherV2 {
	d := newV2BookkeepingDispatcher()
	d.cfg.FrameTimeout = time.Second
	d.cfg.SubmitterUID, d.cfg.SubmitterGID = os.Geteuid(), os.Getegid()
	d.cfg.WorkerUIDByParser = map[string]int{ParserTypeOffice: 65532, ParserTypePDF: 65533}
	d.cfg.WorkerGIDByParser = map[string]int{ParserTypeOffice: 65532, ParserTypePDF: 65533}
	d.cfg.Registry = ProductionV2Registry(65532, 65532, 65533, 65533)
	for _, entry := range d.cfg.Registry {
		if entry.ParserRequest.Operation != OperationRenderPDFPages {
			d.workers[entry.ParserRequest.ParserType] = &v2Worker{entry: entry, ready: true}
		}
	}
	return d
}

func TestNativeReadinessRequiresAcceptedIdleProductionPeers(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*DispatcherV2)
		want   bool
	}{
		{"ready", func(*DispatcherV2) {}, true},
		{"before-registration", func(d *DispatcherV2) { d.workers = nil }, false},
		{"pdf-not-registered", func(d *DispatcherV2) { delete(d.workers, ParserTypePDF) }, false},
		{"before-ack", func(d *DispatcherV2) { d.workers[ParserTypeOffice].ready = false }, false},
		{"used", func(d *DispatcherV2) { d.workers[ParserTypeOffice].used = true }, false},
		{"busy", func(d *DispatcherV2) { d.workers[ParserTypePDF].active = &v2Lease{} }, false},
		{"red", func(d *DispatcherV2) { d.red = true }, false},
		{"stopping", func(d *DispatcherV2) { d.closed = true }, false},
		{"artifact-drift", func(d *DispatcherV2) { d.workers[ParserTypeOffice].entry.ArtifactHash = "sha256:wrong" }, false},
		{"profile-drift", func(d *DispatcherV2) {
			d.workers[ParserTypePDF].entry.ParserRequest.ObservationProfileRevision = "other"
		}, false},
		{"limits-drift", func(d *DispatcherV2) { d.workers[ParserTypeOffice].entry.ExpectedLimits.PIDsMax++ }, false},
		{"missing-xlsx-capability", func(d *DispatcherV2) { d.cfg.Registry = append(d.cfg.Registry[:2], d.cfg.Registry[3:]...) }, false},
		{"capability-output-drift", func(d *DispatcherV2) { d.cfg.Registry[0].ParserRequest.OutputContract = "wrong" }, false},
		{"capability-duration-drift", func(d *DispatcherV2) { d.cfg.Registry[0].MaxLeaseDuration++ }, false},
		{"uid-drift", func(d *DispatcherV2) { d.workers[ParserTypeOffice].entry.ExpectedWorkerUID++ }, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			d := readyProbeDispatcher()
			item.change(d)
			if got := d.nativeV2ReadyLocked(); got != item.want {
				t.Fatalf("ready=%t want=%t", got, item.want)
			}
		})
	}
}

func TestNativeReadinessWireEnforcesSubmitterCredentialsWithoutAdmission(t *testing.T) {
	for _, mode := range []string{"ready", "not-ready", "wrong-uid", "wrong-gid", "wrong-probe"} {
		t.Run(mode, func(t *testing.T) {
			d := readyProbeDispatcher()
			switch mode {
			case "not-ready":
				d.workers[ParserTypePDF].ready = false
			case "wrong-uid":
				d.cfg.SubmitterUID++
			case "wrong-gid":
				d.cfg.SubmitterGID++
			}
			path := filepath.Join(t.TempDir(), "submit.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				d.trackV2Conn(conn)
				d.handleV2Submitter(conn)
				done <- nil
			}()
			client := &Submitter{V2SubmitSocketPath: path, FrameTimeout: time.Second}
			if mode == "wrong-probe" {
				conn, err := net.Dial("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if err := writeFrame(conn, kindNativeReadinessV2, []byte(nativeReadinessBodyV2+"extra")); err != nil {
					t.Fatal(err)
				}
				if _, _, err := readFrame(conn, maxFrameBody); err == nil {
					t.Fatal("unknown readiness body accepted")
				}
			} else {
				err = client.CheckNativeReadiness(context.Background())
				if (err == nil) != (mode == "ready") {
					t.Fatalf("probe=%s err=%v", mode, err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if len(d.leases) != 0 || len(d.terminal) != 0 || len(d.handoffs) != 0 || len(d.conns) != 0 {
				t.Fatal("readiness created authority or leaked a connection")
			}
			for _, worker := range d.workers {
				if worker.active != nil || worker.used {
					t.Fatal("probe consumed a worker")
				}
			}
		})
	}
}

func TestNativeReadinessClientRejectsUnavailableAndMalformedReplies(t *testing.T) {
	for _, mode := range []string{"wrong-kind", "unknown-body", "unavailable", "oversize", "canceled-in-flight"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "submit.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				kind, body, err := readFrame(conn, maxFrameBody)
				if err != nil || kind != kindNativeReadinessV2 || string(body) != nativeReadinessBodyV2 {
					done <- ErrWireRejected
					return
				}
				if mode == "canceled-in-flight" {
					cancel()
					var b [1]byte
					_, _ = conn.Read(b[:])
					done <- nil
					return
				}
				kind = kindNativeReadinessResultV2
				body = []byte(nativeReadyBodyV2)
				switch mode {
				case "wrong-kind":
					kind = kindResult
				case "unknown-body":
					body = []byte("ready")
				case "unavailable":
					body = []byte(nativeUnavailableBodyV2)
				case "oversize":
					body = make([]byte, 1024)
				}
				done <- writeFrame(conn, kind, body)
			}()
			client := &Submitter{V2SubmitSocketPath: path, FrameTimeout: time.Second}
			if err := client.CheckNativeReadiness(ctx); !errors.Is(err, ErrNativeNotReady) {
				t.Fatalf("invalid reply accepted: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	client := &Submitter{V2SubmitSocketPath: filepath.Join(t.TempDir(), "absent.sock"), FrameTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx, context.Background()} {
		if err := client.CheckNativeReadiness(ctx); !errors.Is(err, ErrNativeNotReady) {
			t.Fatal("absent dispatcher accepted")
		}
	}
}
