//go:build !linux

package sandboxdispatch

func newV2StatusWriter(string) (v2StatusWriter, error) {
	return nil, ErrSupervisorStatusUnsupported
}

func openV2StatusCgroupFD(string) (int, error) {
	return -1, ErrSupervisorStatusUnsupported
}
