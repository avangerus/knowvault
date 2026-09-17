//go:build linux

package operator

import (
	"os"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

// setRuntimeGroup assigns the pinned runtime group (secretmount.RuntimeGID,
// the same constant the image contract pins) to a generated mount path. The
// operator runs as root by deployment contract (the mount boundary check
// already requires a root-owned parent), so the assignment must succeed; a
// failure fails the generation closed.
func setRuntimeGroup(path string) error {
	return setConsumerGroup(path, runtimeidentity.Server)
}

func setConsumerGroup(path string, consumer runtimeidentity.MountConsumer) error {
	group, valid := consumer.GroupID()
	if !valid {
		return MigrationIncompatible("invalid secret consumer")
	}
	return os.Chown(path, -1, int(group))
}
