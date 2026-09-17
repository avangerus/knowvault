package sandboxdispatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"time"
)

// CanonicalLimitsIdentity derives the extraction identity the dispatcher owns:
// the SHA-256 of the exact JCS-serialized document over the lease/job/worker
// identity, the observation time and the kernel-observed limits, with keys in a
// fixed order. The worker never computes this value — it only echoes the one the
// dispatcher hands it with the payload — and the dispatcher never accepts limits
// from a worker self-report (SAN-004). The serialization order is pinned by this
// function and asserted by a golden test; a drift here silently re-keys every
// extraction identity.
func CanonicalLimitsIdentity(leaseID, jobID, workerID, parserType string, observedAt time.Time, limits Limits) string {
	return canonicalIdentityHash(struct {
		CPUMillis   int64  `json:"cpu_millis"`
		JobID       string `json:"job_id"`
		LeaseID     string `json:"lease_id"`
		MemoryBytes int64  `json:"memory_bytes"`
		ObservedAt  string `json:"observed_at"`
		ParserType  string `json:"parser_type"`
		PIDsMax     int64  `json:"pids_max"`
		WallClockMS int64  `json:"wall_clock_ms"`
		WorkerID    string `json:"worker_id"`
	}{limits.CPUMillis, jobID, leaseID, limits.MemoryBytes, observedAt.UTC().Format(time.RFC3339), parserType, limits.PIDsMax, limits.WallClockMS, workerID})
}

// RuntimeProfileHash is stable across executions of the same sandbox capability:
// it binds only parser type, its pinned profile revision and finite kernel limits.
// Lease/job/worker/time are deliberately excluded so a retry does not mint a new
// runtime identity.
func RuntimeProfileHash(parserType, sandboxProfileRevision string, limits Limits) string {
	return canonicalIdentityHash(struct {
		CPUMillis              int64  `json:"cpu_millis"`
		MemoryBytes            int64  `json:"memory_bytes"`
		ParserType             string `json:"parser_type"`
		PIDsMax                int64  `json:"pids_max"`
		SandboxProfileRevision string `json:"sandbox_profile_revision"`
		WallClockMS            int64  `json:"wall_clock_ms"`
	}{limits.CPUMillis, limits.MemoryBytes, parserType, limits.PIDsMax, sandboxProfileRevision, limits.WallClockMS})
}

// ExecutionConfirmationID binds one kernel observation to the stable runtime
// profile. It is intentionally execution-specific and must never replace the
// runtime profile in an Extraction identity.
func ExecutionConfirmationID(runtimeProfileHash, leaseID, jobID, workerID string, observedAt time.Time) string {
	return canonicalIdentityHash(struct {
		JobID              string `json:"job_id"`
		LeaseID            string `json:"lease_id"`
		ObservedAt         string `json:"observed_at"`
		RuntimeProfileHash string `json:"runtime_profile_hash"`
		WorkerID           string `json:"worker_id"`
	}{jobID, leaseID, observedAt.UTC().Format(time.RFC3339), runtimeProfileHash, workerID})

}

// canonicalIdentityHash hashes only RFC 8785 canonical JSON. The inputs are
// concrete strings and integers, so Marshal/Canonicalize failure is impossible for
// a valid Go value; returning an empty value is nevertheless fail-closed because
// every wire identity validator requires an exact sha256 value.
func canonicalIdentityHash(value any) string {
	raw, err := jsonv2.Marshal(value)
	if err != nil {
		return ""
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return ""
	}
	digest := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ErrKernelBoundUnlimited marks a cgroup value that is "max" or absent: a sandbox
// without a finite kernel bound is not an observation and fails closed.
var ErrKernelBoundUnlimited = errors.New("sandboxdispatch: kernel bound is unlimited")

// parseCgroupMemoryMax parses a cgroup v2 memory.max value ("max" or bytes).
func parseCgroupMemoryMax(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "max" {
		return 0, ErrKernelBoundUnlimited
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 1 {
		return 0, ErrKernelBoundUnlimited
	}
	return value, nil
}

// parseCgroupPIDsMax parses a cgroup v2 pids.max value ("max" or count).
func parseCgroupPIDsMax(raw string) (int64, error) {
	return parseCgroupMemoryMax(raw)
}

// parseCgroupCPUMax parses a cgroup v2 cpu.max value: either "max" or
// "$QUOTA $PERIOD" in microseconds, converted to integer CPU milliseconds.
func parseCgroupCPUMax(raw string) (int64, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return 0, ErrKernelBoundUnlimited
	}
	if fields[0] == "max" {
		return 0, ErrKernelBoundUnlimited
	}
	if len(fields) != 2 {
		return 0, ErrKernelBoundUnlimited
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota < 1 {
		return 0, ErrKernelBoundUnlimited
	}
	period, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || period < 1 {
		return 0, ErrKernelBoundUnlimited
	}
	if quota > (int64(^uint64(0)>>1) / 1000) {
		return 0, ErrKernelBoundUnlimited
	}
	millis := quota * 1000 / period
	if millis < 1 {
		return 0, ErrKernelBoundUnlimited
	}
	return millis, nil
}

// cgroupV2Path extracts the cgroup v2 unified hierarchy path from a /proc/<pid>/cgroup
// file: the single line "0::<path>".
func cgroupV2Path(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "::")
		if len(parts) == 2 && parts[0] == "0" && parts[1] != "" {
			return parts[1], nil
		}
	}
	return "", ErrObservationUnavailable
}
