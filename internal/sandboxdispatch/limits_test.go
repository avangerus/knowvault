package sandboxdispatch

import (
	"errors"
	"testing"
	"time"
)

func TestCgroupParsers(t *testing.T) {
	t.Parallel()

	if _, err := parseCgroupMemoryMax("1073741824\n"); err != nil {
		t.Fatalf("finite memory bound rejected: %v", err)
	}
	if _, err := parseCgroupMemoryMax("max\n"); !errors.Is(err, ErrKernelBoundUnlimited) {
		t.Fatalf("unlimited memory accepted: %v", err)
	}
	if _, err := parseCgroupMemoryMax("\n"); !errors.Is(err, ErrKernelBoundUnlimited) {
		t.Fatalf("empty memory accepted: %v", err)
	}

	millis, err := parseCgroupCPUMax("50000 100000\n")
	if err != nil || millis != 500 {
		t.Fatalf("cpu quota parse: %d, %v", millis, err)
	}
	if _, err := parseCgroupCPUMax("max 100000\n"); !errors.Is(err, ErrKernelBoundUnlimited) {
		t.Fatalf("unlimited cpu accepted: %v", err)
	}
	if _, err := parseCgroupCPUMax("50000\n"); !errors.Is(err, ErrKernelBoundUnlimited) {
		t.Fatalf("half-written cpu.max accepted: %v", err)
	}
	if _, err := parseCgroupCPUMax("9223372036854775807 1\n"); !errors.Is(err, ErrKernelBoundUnlimited) {
		t.Fatal("overflowing cpu quota accepted")
	}

	if _, err := parseCgroupPIDsMax("64\n"); err != nil {
		t.Fatalf("finite pids bound rejected: %v", err)
	}
}

func TestIdentityCanonicalizationAcceptsControlCharacters(t *testing.T) {
	t.Parallel()
	limits := Limits{CPUMillis: 1, MemoryBytes: 1, PIDsMax: 1, WallClockMS: 1}
	identity := CanonicalLimitsIdentity("lease\a", "job\n", "worker\t", "PDF", time.Unix(0, 0), limits)
	if len(identity) != len("sha256:")+64 {
		t.Fatalf("control characters did not yield an identity: %q", identity)
	}
}

func TestCgroupV2PathSingleUnifiedLine(t *testing.T) {
	t.Parallel()

	content := "0::/system.slice/kv-parser-1.scope\n"
	path, err := cgroupV2Path(content)
	if err != nil || path != "/system.slice/kv-parser-1.scope" {
		t.Fatalf("cgroup path: %q, %v", path, err)
	}

	legacyOnly := "2:cpu:/user.slice\n1:memory:/user.slice\n"
	if _, err := cgroupV2Path(legacyOnly); err == nil {
		t.Fatalf("legacy-only cgroup accepted as v2")
	}
}

func TestCanonicalLimitsIdentityGolden(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	identity := CanonicalLimitsIdentity("l1", "j1", "w1", "TEXT", observedAt, Limits{
		CPUMillis:   500,
		MemoryBytes: 536870912,
		PIDsMax:     64,
		WallClockMS: 60000,
	})
	const want = "sha256:dbb0287a11475ee6936a0d938bf842494b899e945a78a6058dfe21bb47be46df"
	if identity != want {
		t.Fatalf("canonical limits identity drifted:\n got %s\nwant %s", identity, want)
	}

	// Every bound is part of the identity: a single drifted field re-keys it.
	other := CanonicalLimitsIdentity("l1", "j1", "w1", "TEXT", observedAt, Limits{
		CPUMillis:   500,
		MemoryBytes: 536870912,
		PIDsMax:     64,
		WallClockMS: 60001,
	})
	if other == identity {
		t.Fatalf("wall clock drift did not re-key the identity")
	}
}

func TestRuntimeProfileAndExecutionConfirmationSplit(t *testing.T) {
	t.Parallel()
	limits := Limits{CPUMillis: 500, MemoryBytes: 536870912, PIDsMax: 64, WallClockMS: 60000}
	profile := RuntimeProfileHash(ParserTypeOCR, "ocr-sandbox-v1", limits)
	if profile != RuntimeProfileHash(ParserTypeOCR, "ocr-sandbox-v1", limits) {
		t.Fatal("runtime profile is not stable")
	}
	if profile == RuntimeProfileHash(ParserTypeOCR, "ocr-sandbox-v2", limits) {
		t.Fatal("profile revision did not re-key runtime profile")
	}
	observed := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	first := ExecutionConfirmationID(profile, "l1", "j1", "w1", observed)
	second := ExecutionConfirmationID(profile, "l2", "j2", "w1", observed)
	if first == second {
		t.Fatal("execution identity omitted lease/job binding")
	}
}
