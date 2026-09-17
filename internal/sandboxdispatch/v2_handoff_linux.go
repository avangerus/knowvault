//go:build linux

package sandboxdispatch

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"syscall"
	"unsafe"
)

// readV2HandoffFrame receives one framed JSON metadata document plus exactly
// one pidfd over SCM_RIGHTS. The metadata and descriptor are intentionally
// inseparable at this boundary; a JSON-only peer cannot fabricate evidence.
func readV2HandoffFrame(conn *net.UnixConn, maxBody int) (frameKind, []byte, int, error) {
	var header [5]byte
	oob := make([]byte, 256)
	n, oobn, flags, _, err := conn.ReadMsgUnix(header[:], oob)
	if err != nil {
		if oobn > 0 {
			closeReceivedFDs(oob[:oobn])
		}
		return 0, nil, -1, err
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		closeReceivedFDs(oob[:oobn])
		return 0, nil, -1, fmt.Errorf("%w: supervisor handoff frame", ErrWireRejected)
	}
	if n < 5 {
		if _, err := io.ReadFull(conn, header[n:]); err != nil {
			closeReceivedFDs(oob[:oobn])
			return 0, nil, -1, err
		}
	}
	bodyLen := binary.BigEndian.Uint32(header[1:5])
	if bodyLen == 0 || bodyLen > uint32(maxBody) {
		closeReceivedFDs(oob[:oobn])
		return 0, nil, -1, fmt.Errorf("%w: supervisor handoff length", ErrWireRejected)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		closeReceivedFDs(oob[:oobn])
		return 0, nil, -1, err
	}
	fds, err := parseReceivedFDs(oob[:oobn])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		return 0, nil, -1, fmt.Errorf("%w: supervisor pidfd", ErrWireRejected)
	}
	if err := validateV2PidfdDescriptor(fds[0]); err != nil {
		_ = syscall.Close(fds[0])
		return 0, nil, -1, fmt.Errorf("%w: supervisor pidfd", ErrWireRejected)
	}
	return frameKind(header[0]), body, fds[0], nil
}

func parseReceivedFDs(oob []byte) ([]int, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, message := range messages {
		parsed, err := syscall.ParseUnixRights(&message)
		if err != nil {
			return fds, err
		}
		fds = append(fds, parsed...)
	}
	return fds, nil
}

func closeReceivedFDs(oob []byte) {
	fds, _ := parseReceivedFDs(oob)
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

func closeV2PeerFD(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

func v2PeerCredentials(conn *net.UnixConn) (uid, gid int, err error) {
	_, uid, gid, err = v2PeerCredentialsFull(conn)
	return uid, gid, err
}

func v2PeerCredentialsFull(conn *net.UnixConn) (pid, uid, gid int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var errno syscall.Errno
	var cred [12]byte
	var length uint32 = uint32(len(cred))
	controlErr := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			uintptr(syscall.SOL_SOCKET), uintptr(17), uintptr(unsafe.Pointer(&cred[0])), uintptr(unsafe.Pointer(&length)), 0)
	})
	if controlErr != nil || errno != 0 || length < uint32(len(cred)) {
		if controlErr != nil {
			return 0, 0, 0, controlErr
		}
		return 0, 0, 0, errno
	}
	return int(*(*uint32)(unsafe.Pointer(&cred[0]))), int(*(*uint32)(unsafe.Pointer(&cred[4]))), int(*(*uint32)(unsafe.Pointer(&cred[8]))), nil
}
