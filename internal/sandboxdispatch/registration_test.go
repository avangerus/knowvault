//go:build linux

package sandboxdispatch

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type registrationResponder struct {
	path        string
	listener    *net.UnixListener
	ready       chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
	done        chan error
}

func (r *registrationResponder) Release() { r.releaseOnce.Do(func() { close(r.release) }) }

func newRegistrationResponder(t *testing.T, responseKind frameKind, responseBody []byte, sendResponse bool, waitForRelease bool) *registrationResponder {
	t.Helper()
	directory, err := os.MkdirTemp("", "kv-registration")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "dispatcher.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	responder := &registrationResponder{
		path: path, listener: listener, ready: make(chan struct{}),
		release: make(chan struct{}), done: make(chan error, 1),
	}
	t.Cleanup(func() {
		responder.Release()
		_ = listener.Close()
	})
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			responder.done <- acceptErr
			return
		}
		defer conn.Close()
		kind, _, readErr := readFrame(conn, maxFrameBody)
		if readErr != nil {
			responder.done <- readErr
			return
		}
		if kind != kindRegister {
			responder.done <- errors.New("responder received non-registration frame")
			return
		}
		close(responder.ready)
		if waitForRelease {
			<-responder.release
		}
		if sendResponse {
			var responseErr error
			if len(responseBody) > maxFrameBody {
				var header [5]byte
				header[0] = byte(responseKind)
				binary.BigEndian.PutUint32(header[1:], uint32(len(responseBody)))
				_, responseErr = conn.Write(header[:])
			} else {
				responseErr = writeFrame(conn, responseKind, responseBody)
			}
			if responseErr != nil {
				responder.done <- responseErr
				return
			}
		}
		responder.done <- nil
	}()
	return responder
}

func TestWorkerClientRegisterWaitsForExactAcceptance(t *testing.T) {
	responder := newRegistrationResponder(t, kindRegisterAccepted, []byte(registrationAcceptedBody), true, true)
	client := &WorkerClient{SocketPath: responder.path, MaxPayloadBytes: 1 << 20}
	result := make(chan *WorkerSession, 1)
	errResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		session, err := client.Register(ctx, "worker-1", ParserTypeText)
		result <- session
		errResult <- err
	}()
	select {
	case <-responder.ready:
	case <-time.After(time.Second):
		t.Fatal("registration hello was not observed")
	}
	select {
	case session := <-result:
		if session != nil {
			_ = session.Close()
		}
		t.Fatal("Register returned before acceptance acknowledgment")
	default:
	}
	responder.Release()
	select {
	case session := <-result:
		if session == nil {
			t.Fatalf("Register returned nil session: %v", <-errResult)
		}
		if err := <-errResult; err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Register did not return after acceptance acknowledgment")
	}
	if err := <-responder.done; err != nil {
		t.Fatal(err)
	}
}

func TestWorkerClientRegisterRejectsWrongOrOversizeAcceptance(t *testing.T) {
	cases := map[string]struct {
		kind frameKind
		body []byte
	}{
		"wrong kind":    {kind: kindLimits, body: []byte(registrationAcceptedBody)},
		"wrong body":    {kind: kindRegisterAccepted, body: []byte("sandbox-registration-accepted-v0")},
		"unknown kind":  {kind: frameKind(255), body: []byte(registrationAcceptedBody)},
		"oversize body": {kind: kindRegisterAccepted, body: make([]byte, maxFrameBody+1)},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			responder := newRegistrationResponder(t, testCase.kind, testCase.body, true, false)
			client := &WorkerClient{SocketPath: responder.path, MaxPayloadBytes: 1 << 20}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			session, err := client.Register(ctx, "worker-1", ParserTypeText)
			if session != nil || !errors.Is(err, ErrRegistrationRejected) {
				t.Fatalf("invalid acceptance accepted: session=%v err=%v", session, err)
			}
			if responderErr := <-responder.done; responderErr != nil {
				t.Fatal(responderErr)
			}
		})
	}
}

func TestWorkerClientRegisterCancellationIsBounded(t *testing.T) {
	responder := newRegistrationResponder(t, kindRegisterAccepted, []byte(registrationAcceptedBody), false, true)
	client := &WorkerClient{SocketPath: responder.path, MaxPayloadBytes: 1 << 20}
	// Keep a long safety deadline, but cancel explicitly after the hello is
	// observed. This proves the AfterFunc cancellation path wakes the blocked
	// ACK read; a timeout-only test would not distinguish that path.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan struct {
		session *WorkerSession
		err     error
	}, 1)
	go func() {
		session, err := client.Register(ctx, "worker-1", ParserTypeText)
		result <- struct {
			session *WorkerSession
			err     error
		}{session: session, err: err}
	}()
	select {
	case <-responder.ready:
	case <-time.After(time.Second):
		t.Fatal("registration hello was not observed")
	}
	started := time.Now()
	cancel()
	select {
	case result := <-result:
		if result.session != nil || !errors.Is(result.err, ErrRegistrationRejected) {
			t.Fatalf("missing acceptance accepted after manual cancel: session=%v err=%v", result.session, result.err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("manual registration cancellation was not immediate: %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("manual registration cancellation did not wake the ACK read")
	}
	responder.Release()
	if responderErr := <-responder.done; responderErr != nil {
		t.Fatal(responderErr)
	}
}

func TestWorkerClientRegisterRejectsUnboundedContext(t *testing.T) {
	client := &WorkerClient{SocketPath: filepath.Join(t.TempDir(), "missing.sock"), MaxPayloadBytes: 1 << 20}
	started := time.Now()
	session, err := client.Register(context.Background(), "worker-1", ParserTypeText)
	if session != nil || !errors.Is(err, ErrRegistrationRejected) {
		t.Fatalf("unbounded context accepted: session=%v err=%v", session, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("unbounded registration did not fail closed: %s", elapsed)
	}
}

func TestRegistrationAcceptanceFrameHasExactTransportShape(t *testing.T) {
	if len(registrationAcceptedBody) == 0 {
		t.Fatal("empty registration acceptance body")
	}
	var header [5]byte
	header[0] = byte(kindRegisterAccepted)
	binary.BigEndian.PutUint32(header[1:], uint32(len(registrationAcceptedBody)))
	if header[0] != 9 || binary.BigEndian.Uint32(header[1:]) != uint32(len(RegistrationAcceptedVersion)) {
		t.Fatalf("registration acceptance frame drifted: kind=%d length=%d", header[0], binary.BigEndian.Uint32(header[1:]))
	}
}

// TestWorkerEligibleRequiresAcceptance proves the synchronous admission
// predicate directly: a parser socket is ineligible until the exact ACK has
// completed and the dispatcher publishes ready=true.
func TestWorkerEligibleRequiresAcceptance(t *testing.T) {
	worker := &workerConn{readyCh: make(chan struct{})}
	if workerEligible(worker) {
		t.Fatal("worker became eligible before acceptance")
	}
	worker.ready = true
	if !workerEligible(worker) {
		t.Fatal("accepted worker remained ineligible")
	}
}
