//go:build !linux

package operator

import "knowvault.local/verified-workspace/internal/platform/runtimeidentity"

// setRuntimeGroup is inert on platforms where the mounted-root boundary is
// unavailable by design: generation already fails closed in verifyMountBoundary
// before any write, and the product mount loader refuses to load there, so no
// consumable mount can exist on such a host.
func setRuntimeGroup(string) error { return nil }

func setConsumerGroup(string, runtimeidentity.MountConsumer) error { return nil }
