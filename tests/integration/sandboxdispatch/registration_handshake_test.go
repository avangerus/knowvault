//go:build linux

package sandboxdispatch_test

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

// blockingObserver keeps the registration in the kernel-observation phase so
// the peer can be reset before the dispatcher attempts the exact ACK write.
// This is a real unix-socket failure path; the observer only supplies the
// test's kernel observation and does not inject a production fault.
type blockingObserver struct {
	obs      sandboxdispatch.Observation
	observed chan struct{}
	release  chan struct{}
	returned chan struct{}
	once     sync.Once
}

func (o *blockingObserver) Observe(_ *net.UnixConn) (sandboxdispatch.Observation, error) {
	o.once.Do(func() {
		close(o.observed)
		<-o.release
		close(o.returned)
	})
	return o.obs, nil
}

func resetUnixPeer(t *testing.T, conn *net.UnixConn) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		linger := &syscall.Linger{Onoff: 1, Linger: 0}
		socketErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, linger)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
}

// TestDispatcherLoopbackAckFailureReleasesParserSlot proves that a peer reset
// before the registration ACK cannot leave the parser slot reserved. The
// replacement registration is retried only until the dispatcher publishes the
// cleanup; an implementation that drops the cleanup never reaches acceptance.
func TestDispatcherLoopbackAckFailureReleasesParserSlot(t *testing.T) {
	observer := &blockingObserver{
		obs:      defaultObservation(),
		observed: make(chan struct{}),
		release:  make(chan struct{}),
		returned: make(chan struct{}),
	}
	socketPath := startDispatcher(t, observer, &fakeKiller{})
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRawFrame(peer, 1, []byte(`{"worker_id":"failed-worker","parser_type":"TEXT","capabilities":["PULL_JOB","PUSH_OUTCOME"]}`)); err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	select {
	case <-observer.observed:
	case <-time.After(time.Second):
		_ = peer.Close()
		t.Fatal("observer did not see registration")
	}
	// Force a kernel RST while Observe still holds the registration. Once the
	// observer returns, the dispatcher must fail the ACK write and drop the
	// reserved parser binding before closing the socket.
	resetUnixPeer(t, peer)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	close(observer.release)
	select {
	case <-observer.returned:
	case <-time.After(time.Second):
		t.Fatal("observer did not return")
	}

	client := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 100*time.Millisecond)
		session, registerErr := client.Register(attemptCtx, "replacement-worker", sandboxdispatch.ParserTypeText)
		attemptCancel()
		if registerErr == nil {
			if session == nil {
				t.Fatal("replacement registration returned nil session")
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Fatal("ACK failure left a stale parser reservation")
}
