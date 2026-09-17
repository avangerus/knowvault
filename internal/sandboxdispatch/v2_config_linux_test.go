//go:build linux

package sandboxdispatch

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestV2RoleLayoutRequiresDistinctOwnedRoots(t *testing.T) {
	base := ""
	for _, candidate := range []string{"/run", "/var/run", "."} {
		info, statErr := os.Stat(candidate)
		if statErr == nil && info.IsDir() && info.Mode().Perm()&0o022 == 0 {
			base = candidate
			break
		}
	}
	if base == "" {
		t.Skip("no secure writable test parent")
	}
	root, err := os.MkdirTemp(base, "kv-v2-layout-")
	if err != nil {
		t.Skipf("workspace is not writable: %v", err)
	}
	defer os.RemoveAll(root)
	roots := [4]string{
		filepath.Join(root, "submit"), filepath.Join(root, "supervisor"),
		filepath.Join(root, "office"), filepath.Join(root, "pdf"),
	}
	for _, roleRoot := range roots {
		if err := os.Mkdir(roleRoot, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths := make([]string, 4)
	for i, roleRoot := range roots {
		paths[i] = filepath.Join(roleRoot, "dispatch.sock")
	}
	cfg := V2Config{RootDir: root, SubmitSocketRootDir: roots[0], SupervisorHandoffSocketRootDir: roots[1], OfficeRegistrationSocketRootDir: roots[2], PDFRegistrationSocketRootDir: roots[3]}
	if err := validateV2RoleLayout(cfg, paths); err != nil {
		t.Fatalf("valid role layout rejected: %v", err)
	}

	shared := cfg
	shared.SupervisorHandoffSocketRootDir = roots[0]
	if err := validateV2RoleLayout(shared, paths); err == nil {
		t.Fatal("shared role parent accepted")
	}

	outside := cfg
	outside.PDFRegistrationSocketRootDir = filepath.Join(root, "pdf-link")
	outside.PDFRegistrationSocketPath = filepath.Join(outside.PDFRegistrationSocketRootDir, "dispatch.sock")
	if err := os.Symlink(roots[3], outside.PDFRegistrationSocketRootDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	outsidePaths := append([]string(nil), paths...)
	outsidePaths[3] = outside.PDFRegistrationSocketPath
	if err := validateV2RoleLayout(outside, outsidePaths); err == nil {
		t.Fatal("symlink role ancestry accepted")
	}
}

func TestNewV2RejectsRegistryLimitOrRuntimeDrift(t *testing.T) {
	root, roleRoots, ok := makeSecureV2RoleFixture(t)
	if !ok {
		t.Skip("no secure writable test parent")
	}
	request := ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypePDF, Operation: OperationObservePDFText, MediaFamily: "PDF", SandboxProfileRevision: "pdf-sandbox-v2", ObservationProfileRevision: "pdf-obs-v2", MaxInputBytes: 1024, MaxOutputBytes: 1024, MaxUnits: 10, MaxPages: 10, MaxDecodedPixels: 1024, OutputContract: "pdf-parser-result-v1"}
	limits := Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: 1000}
	entry := V2RegistryEntry{ParserRequest: request, ArtifactHash: "sha256:3b12599c3ada7db8174168fe0a4c685954e3068673ab1ad3e7ede63884428def", MediaType: "application/pdf", MaxLeaseDuration: time.Second, ExpectedLimits: limits, RuntimeProfileHash: RuntimeProfileHash(request.ParserType, request.SandboxProfileRevision, limits), ExpectedWorkerUID: 1, ExpectedWorkerGID: 1}
	office := request
	office.ParserType, office.Operation, office.MediaFamily, office.SandboxProfileRevision, office.ObservationProfileRevision, office.OutputContract = ParserTypeOffice, OperationObserveStructure, "DOCX", "office-sandbox-v2", "office-obs-v2", OutputContractV1
	officeEntry := entry
	officeEntry.ParserRequest = office
	officeEntry.MediaType = mediaTypeFor("DOCX")
	officeEntry.RuntimeProfileHash = RuntimeProfileHash(office.ParserType, office.SandboxProfileRevision, limits)
	officeEntry.ExpectedWorkerUID = 2
	officeEntry.ExpectedWorkerGID = 2

	base := V2Config{RootDir: root, SubmitSocketPath: filepath.Join(roleRoots[0], "submit.sock"), SupervisorHandoffSocketPath: filepath.Join(roleRoots[1], "handoff.sock"), OfficeRegistrationSocketPath: filepath.Join(roleRoots[2], "office.sock"), PDFRegistrationSocketPath: filepath.Join(roleRoots[3], "pdf.sock"), SubmitSocketRootDir: roleRoots[0], SupervisorHandoffSocketRootDir: roleRoots[1], OfficeRegistrationSocketRootDir: roleRoots[2], PDFRegistrationSocketRootDir: roleRoots[3], MaxPayloadBytes: 1 << 20, FrameTimeout: time.Second, Registry: []V2RegistryEntry{officeEntry, entry}, SupervisorUID: os.Geteuid(), SupervisorGID: os.Getegid(), SubmitterUID: 3, SubmitterGID: 3, WorkerUIDByParser: map[string]int{ParserTypeOffice: 2, ParserTypePDF: 1}, WorkerGIDByParser: map[string]int{ParserTypeOffice: 2, ParserTypePDF: 1}}
	drift := base
	drift.Registry = append([]V2RegistryEntry(nil), base.Registry...)
	drift.Registry[1].ExpectedLimits.MemoryBytes++
	if _, err := NewV2(drift); err == nil {
		t.Fatal("registry limit drift accepted")
	}
	drift = base
	drift.Registry = append([]V2RegistryEntry(nil), base.Registry...)
	drift.Registry[1].RuntimeProfileHash = digestFor([]byte("wrong-runtime"))
	if _, err := NewV2(drift); err == nil {
		t.Fatal("registry runtime hash drift accepted")
	}
	dispatcher, err := NewV2(base)
	if err != nil {
		t.Fatalf("valid registry rejected: %v", err)
	}
	dispatcher.closeV2Listeners()
	dispatcher.shutdownV2()
}

func TestNewV2RejectsAnyRoleUIDOverlap(t *testing.T) {
	root, roleRoots, ok := makeSecureV2RoleFixture(t)
	if !ok {
		t.Skip("no secure writable test parent")
	}
	request := ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypePDF, Operation: OperationObservePDFText, MediaFamily: "PDF", SandboxProfileRevision: "pdf-sandbox-v2", ObservationProfileRevision: "pdf-obs-v2", MaxInputBytes: 1024, MaxOutputBytes: 1024, MaxUnits: 10, MaxPages: 10, MaxDecodedPixels: 1024, OutputContract: "pdf-parser-result-v1"}
	limits := Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: 1000}
	pdf := V2RegistryEntry{ParserRequest: request, ArtifactHash: "sha256:3b12599c3ada7db8174168fe0a4c685954e3068673ab1ad3e7ede63884428def", MediaType: "application/pdf", MaxLeaseDuration: time.Second, ExpectedLimits: limits, RuntimeProfileHash: RuntimeProfileHash(request.ParserType, request.SandboxProfileRevision, limits), ExpectedWorkerUID: 11, ExpectedWorkerGID: 11}
	office := pdf
	office.ParserRequest.ParserType, office.ParserRequest.Operation, office.ParserRequest.MediaFamily, office.ParserRequest.SandboxProfileRevision, office.ParserRequest.ObservationProfileRevision, office.ParserRequest.OutputContract = ParserTypeOffice, OperationObserveStructure, "DOCX", "office-sandbox-v2", "office-obs-v2", OutputContractV1
	office.MediaType = mediaTypeFor("DOCX")
	office.RuntimeProfileHash = RuntimeProfileHash(office.ParserRequest.ParserType, office.ParserRequest.SandboxProfileRevision, limits)
	office.ExpectedWorkerUID, office.ExpectedWorkerGID = 12, 12
	base := V2Config{RootDir: root, SubmitSocketPath: filepath.Join(roleRoots[0], "submit.sock"), SupervisorHandoffSocketPath: filepath.Join(roleRoots[1], "handoff.sock"), OfficeRegistrationSocketPath: filepath.Join(roleRoots[2], "office.sock"), PDFRegistrationSocketPath: filepath.Join(roleRoots[3], "pdf.sock"), SubmitSocketRootDir: roleRoots[0], SupervisorHandoffSocketRootDir: roleRoots[1], OfficeRegistrationSocketRootDir: roleRoots[2], PDFRegistrationSocketRootDir: roleRoots[3], MaxPayloadBytes: 1 << 20, FrameTimeout: time.Second, Registry: []V2RegistryEntry{office, pdf}, SupervisorUID: os.Geteuid(), SupervisorGID: os.Getegid(), SubmitterUID: 13, SubmitterGID: 13, WorkerUIDByParser: map[string]int{ParserTypeOffice: 12, ParserTypePDF: 11}, WorkerGIDByParser: map[string]int{ParserTypeOffice: 12, ParserTypePDF: 11}}
	for name, mutate := range map[string]func(*V2Config){
		"office-pdf UID":       func(c *V2Config) { c.WorkerUIDByParser[ParserTypePDF] = c.WorkerUIDByParser[ParserTypeOffice] },
		"submitter-office UID": func(c *V2Config) { c.SubmitterUID = c.WorkerUIDByParser[ParserTypeOffice] },
		"supervisor-pdf UID":   func(c *V2Config) { c.SupervisorUID = c.WorkerUIDByParser[ParserTypePDF] },
	} {
		candidate := base
		candidate.WorkerUIDByParser = cloneV2IntMap(base.WorkerUIDByParser)
		candidate.WorkerGIDByParser = cloneV2IntMap(base.WorkerGIDByParser)
		mutate(&candidate)
		if _, err := NewV2(candidate); err == nil {
			t.Fatalf("%s overlap accepted", name)
		}
	}
}

func TestV2ReplayTableNeverEvictsLiveMarkers(t *testing.T) {
	markers := make(map[string]time.Time, maxV2ReplayEntries)
	for i := 0; i < maxV2ReplayEntries; i++ {
		if !recordV2ReplayLocked(markers, fmt.Sprintf("lease-%d", i), time.Now().Add(time.Hour)) {
			t.Fatalf("marker %d was not recorded", i)
		}
	}
	if recordV2ReplayLocked(markers, "attacker", time.Now().Add(time.Hour)) {
		t.Fatal("full replay table accepted a marker")
	}
	if _, ok := markers["lease-0"]; !ok {
		t.Fatal("live replay marker was evicted")
	}
}

func makeSecureV2RoleFixture(t *testing.T) (string, [4]string, bool) {
	t.Helper()
	for _, base := range []string{"/run", "."} {
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		root, err := os.MkdirTemp(base, "kv-v2-config-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(root) })
		roleRoots := [4]string{filepath.Join(root, "submit"), filepath.Join(root, "supervisor"), filepath.Join(root, "office"), filepath.Join(root, "pdf")}
		for _, roleRoot := range roleRoots {
			if err := os.Mkdir(roleRoot, 0o700); err != nil {
				_ = os.RemoveAll(root)
				return "", [4]string{}, false
			}
		}
		return root, roleRoots, true
	}
	return "", [4]string{}, false
}
