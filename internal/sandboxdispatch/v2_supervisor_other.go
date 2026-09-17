//go:build !linux

package sandboxdispatch

import "time"

func newV2PlatformSupervisor(_ time.Duration) (KernelObserver, V2Supervisor, error) {
	return nil, nil, ErrSupervisorHandoffUnavailable
}

func proveV2Peer(RegisterHelloV2, SupervisorHandoffV1, int, int, Observation, int, int, V2RegistryEntry) (V2PeerHandle, error) {
	return V2PeerHandle{}, ErrSupervisorHandoffUnavailable
}

func readV2PidfdPID(int) (int, error) {
	return 0, ErrSupervisorHandoffUnavailable
}

func validateV2Pidfd(int, int, string, string) error {
	return ErrSupervisorHandoffUnavailable
}

func readV2PIDNamespaceInode(int) (string, error) {
	return "", ErrSupervisorHandoffUnavailable
}

func readProcCgroupPath(int) (string, error) {
	return "", ErrSupervisorHandoffUnavailable
}

func readV2FinalLimits(string, int64, int) (Limits, time.Time, error) {
	return Limits{}, time.Time{}, ErrSupervisorHandoffUnavailable
}

func closeV2CgroupFD(int) {}
