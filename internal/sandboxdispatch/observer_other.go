//go:build !linux

package sandboxdispatch

// On any platform without the Linux cgroup namespace observation the production
// observer and killer are fail-closed: every registration is refused with
// ErrObservationUnavailable and every kill attempt reports ErrKillUnavailable.
// The dispatcher never dispatches without kernel evidence.
func newPlatformObserver() KernelObserver { return unavailableObserver{} }

func newPlatformKiller() ProcessKiller { return unavailableKiller{} }

type unavailableKiller struct{}

func (unavailableKiller) Kill(_ Observation) error { return ErrKillUnavailable }

// chmodSocket is a no-op off Linux: no socket is ever created because every
// registration fails closed.
func chmodSocket(_ string) error { return nil }
