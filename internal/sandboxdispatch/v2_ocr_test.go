package sandboxdispatch

import (
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestV2OptionalOCRRoleKeepsLegacyLayoutAndAddsOneSocket(t *testing.T) {
	legacy := V2Config{}
	if got := len(legacy.roleRoots()); got != 4 {
		t.Fatalf("legacy role layout grew unexpectedly: got %d roots", got)
	}
	ocr := legacy
	ocr.OCRRegistrationSocketPath = "/run/knowvault/sandbox/ocr/register.sock"
	ocr.OCRRegistrationSocketRootDir = "/run/knowvault/sandbox/ocr"
	if got := len(ocr.roleRoots()); got != 5 {
		t.Fatalf("OCR role layout did not add one root: got %d roots", got)
	}
	if !ocr.ocrRoleRequested() {
		t.Fatal("OCR socket configuration was not detected")
	}
}

func TestV2OCRRegistrationAndHandoffContracts(t *testing.T) {
	artifact := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	handoffID := "ocr-handoff-000000000000000000000000000"
	hello := RegisterHelloV2{
		SchemaVersion:              RegistrationVersionV2,
		WorkerID:                   "ocr-worker",
		ParserType:                 ParserTypeOCR,
		ArtifactHash:               artifact,
		SandboxProfileRevision:     "ocr-sandbox-v1",
		ObservationProfileRevision: "ocr-observation-v1",
		SupervisorHandoffID:        handoffID,
		OneShot:                    true,
		MaxLeases:                  1,
		Capabilities:               []string{CapabilityPullJob, CapabilityPushOutcome},
	}
	if err := hello.Validate(ParserTypeOCR); err != nil {
		t.Fatalf("valid OCR registration rejected: %v", err)
	}
	if err := hello.Validate(ParserTypePDF); err == nil {
		t.Fatal("OCR registration accepted on PDF role")
	}

	now := time.Now().UTC()
	now = now.Add(-time.Duration(now.Nanosecond()))
	handoff := SupervisorHandoffV1{
		SchemaVersion:              SupervisorHandoffVersionV1,
		HandoffID:                  handoffID,
		ParserType:                 ParserTypeOCR,
		ArtifactHash:               artifact,
		SandboxProfileRevision:     hello.SandboxProfileRevision,
		ObservationProfileRevision: hello.ObservationProfileRevision,
		PIDFDTransport:             "SCM_RIGHTS",
		PIDNamespaceInode:          "12345",
		CgroupPath:                 "/knowvault/ocr",
		ExpectedWorkerUID:          65534,
		ExpectedWorkerGID:          65534,
		IssuedAt:                   now.Format(time.RFC3339),
		ExpiresAt:                  now.Add(time.Minute).Format(time.RFC3339),
		OneShot:                    true,
		MaxLeases:                  1,
	}
	if err := handoff.Validate(now.Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("valid OCR handoff rejected: %v", err)
	}
	bad := handoff
	bad.ParserType = ParserTypeText
	if err := bad.Validate(now.Add(500 * time.Millisecond)); err == nil {
		t.Fatal("handoff contract accepted a parser role without a dedicated v2 listener")
	}
}

func TestV2ParserReadySupportsOCROnlyWhenWorkerIsRegistered(t *testing.T) {
	dispatcher := &DispatcherV2{workers: map[string]*v2Worker{
		ParserTypeOCR: {ready: true},
	}}
	if !dispatcher.ParserReady(ParserTypeOCR) {
		t.Fatal("registered OCR worker was not reported ready")
	}
	if dispatcher.ParserReady(ParserTypeOffice) {
		t.Fatal("unregistered Office worker was reported ready")
	}
	dispatcher.workers[ParserTypeOCR].used = true
	if dispatcher.ParserReady(ParserTypeOCR) {
		t.Fatal("used OCR worker was reported ready")
	}
}

func TestV2OCRRegistryTupleMatchesBothAdmissionPaths(t *testing.T) {
	request := ParserRequestV1{
		SchemaVersion:              ParserRequestVersionV1,
		ParserType:                 ParserTypeOCR,
		Operation:                  OperationObserveOCRTokens,
		MediaFamily:                "PNG",
		SandboxProfileRevision:     "ocr-sandbox-v1",
		ObservationProfileRevision: "ocr-observation-v1",
		OCRProfileRevision:         "ocr-profile-v1",
		MaxInputBytes:              1,
		MaxOutputBytes:             1,
		MaxUnits:                   1,
		MaxPages:                   1,
		MaxDecodedPixels:           1,
		OutputContract:             "ocr-result-v1",
	}
	entry := V2RegistryEntry{ParserRequest: request, ArtifactHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	dispatcher := &DispatcherV2{cfg: V2Config{Registry: []V2RegistryEntry{entry}}}
	hello := RegisterHelloV2{ParserType: ParserTypeOCR, ArtifactHash: entry.ArtifactHash, SandboxProfileRevision: request.SandboxProfileRevision, ObservationProfileRevision: request.ObservationProfileRevision}
	if _, ok := dispatcher.registryForRegistration(hello); !ok {
		t.Fatal("OCR registry tuple was not accepted for registration")
	}
	handoff := SupervisorHandoffV1{ParserType: ParserTypeOCR, ArtifactHash: entry.ArtifactHash, SandboxProfileRevision: request.SandboxProfileRevision, ObservationProfileRevision: request.ObservationProfileRevision}
	if !dispatcher.registryForHandoff(handoff) {
		t.Fatal("OCR registry tuple was not accepted for supervisor handoff")
	}
}

func TestV2OptionalOCRListenerIsClosedIdempotently(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix listener ownership is Linux-specific")
	}
	path := filepath.Join(t.TempDir(), "ocr-register.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &DispatcherV2{ocrLn: listener}
	dispatcher.closeV2Listeners()
	dispatcher.closeV2Listeners()
	if _, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"}); err == nil {
		t.Fatal("closed OCR registration listener still accepted connections")
	}
}
