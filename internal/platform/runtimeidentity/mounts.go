// Package runtimeidentity defines the closed deployment identities of mounted
// application capabilities. Selection belongs to composition and the operator,
// never to request data, a mount manifest, or the process environment.
package runtimeidentity

const (
	ServerGroupID = 65532
	WorkerGroupID = 65530
)

// MountConsumer selects exactly one ownership contract. The zero value retains
// the existing server/operator contract; ingestion workers explicitly select
// Worker. A reader never accepts both groups for one opened mount.
type MountConsumer uint8

const (
	Server MountConsumer = iota
	Worker
)

func (consumer MountConsumer) GroupID() (uint32, bool) {
	switch consumer {
	case Server:
		return ServerGroupID, true
	case Worker:
		return WorkerGroupID, true
	default:
		return 0, false
	}
}
