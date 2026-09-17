//go:build !linux

package sandboxdispatch

import "net"

func readV2HandoffFrame(_ *net.UnixConn, _ int) (frameKind, []byte, int, error) {
	return 0, nil, -1, ErrSupervisorHandoffUnavailable
}

func closeV2PeerFD(_ int) {}

func v2PeerCredentials(_ *net.UnixConn) (int, int, error) {
	return 0, 0, ErrSupervisorHandoffUnavailable
}

func v2PeerCredentialsFull(_ *net.UnixConn) (int, int, int, error) {
	return 0, 0, 0, ErrSupervisorHandoffUnavailable
}
