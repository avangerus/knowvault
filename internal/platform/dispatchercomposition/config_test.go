package dispatchercomposition

import (
	"os"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

func canonicalV2Environment() []string {
	return []string{
		rootDirEnvironment + "=/run/knowvault/sandbox",
		submitSocketEnvironment + "=unix:///run/knowvault/sandbox/submit/dispatcher.sock",
		handoffSocketEnvironment + "=unix:///run/knowvault/sandbox/supervisor/handoff.sock",
		officeSocketEnvironment + "=unix:///run/knowvault/sandbox/office/register.sock",
		pdfSocketEnvironment + "=unix:///run/knowvault/sandbox/pdf/register.sock",
		supervisorUIDEnvironment + "=0",
		supervisorGIDEnvironment + "=0",
		submitterUIDEnvironment + "=65530",
		submitterGIDEnvironment + "=65530",
		officeWorkerUIDEnvironment + "=65532",
		officeWorkerGIDEnvironment + "=65532",
		pdfWorkerUIDEnvironment + "=65533",
		pdfWorkerGIDEnvironment + "=65533",
		maxPayloadEnvironment + "=67108864",
		frameTimeoutEnvironment + "=5000",
	}
}

func TestLoadProductionAcceptsCompleteV2Configuration(t *testing.T) {
	config, err := loadProduction(canonicalV2Environment())
	if err != nil {
		t.Fatalf("load production: %v", err)
	}
	if config.RootDir() != "/run/knowvault/sandbox" || config.SubmitSocketPath() != "/run/knowvault/sandbox/submit/dispatcher.sock" || config.SupervisorHandoffSocketPath() != "/run/knowvault/sandbox/supervisor/handoff.sock" || config.supervisorStatusPath() != canonicalStatusPath {
		t.Fatalf("unexpected v2 paths: %#v", config)
	}
	if config.OfficeRegistrationSocketPath() == "" || config.PDFRegistrationSocketPath() == "" {
		t.Fatal("parser registration sockets were not loaded")
	}
	if config.SupervisorUID() != 0 || config.SubmitterUID() != 65530 || config.OfficeWorkerUID() != 65532 || config.PDFWorkerUID() != 65533 {
		t.Fatalf("unexpected v2 identities: %#v", config)
	}
	if config.MaxPayloadBytes() != 64<<20 || config.FrameTimeout() != 5*time.Second {
		t.Fatalf("unexpected v2 limits: payload=%d frame=%s", config.MaxPayloadBytes(), config.FrameTimeout())
	}
	v2 := config.v2Config()
	if v2.SubmitSocketRootDir != "/run/knowvault/sandbox/submit" || v2.SupervisorHandoffSocketRootDir != "/run/knowvault/sandbox/supervisor" || v2.SupervisorStatusPath != canonicalStatusPath || v2.OfficeRegistrationSocketRootDir != "/run/knowvault/sandbox/office" || v2.PDFRegistrationSocketRootDir != "/run/knowvault/sandbox/pdf" {
		t.Fatalf("unexpected v2 role roots: %#v", v2)
	}
	if len(v2.Registry) != 5 {
		t.Fatalf("registry entries = %d, want four office/pdf capabilities plus PDF renderer", len(v2.Registry))
	}
	if v2.Registry[0].ParserRequest.ParserType != sandboxdispatch.ParserTypeOffice || v2.Registry[3].ParserRequest.ParserType != sandboxdispatch.ParserTypePDF || v2.Registry[4].ParserRequest.Operation != sandboxdispatch.OperationRenderPDFPages {
		t.Fatalf("registry role order is not deterministic: %#v", v2.Registry)
	}
	for _, entry := range v2.Registry {
		if err := entry.ParserRequest.Validate(); err != nil {
			t.Fatalf("production registry request rejected: %v", err)
		}
		if entry.ArtifactHash != sandboxdispatch.ProductionParserArtifactHash || entry.MaxLeaseDuration != 120*time.Second || entry.RuntimeProfileHash == "" {
			t.Fatalf("production registry identity is not pinned: %#v", entry)
		}
	}
}

func TestLoadProductionRejectsLegacyV1AndUnknownConfiguration(t *testing.T) {
	environment := canonicalV2Environment()
	environment = append(environment, "KNOWVAULT_DISPATCHER_SOCKET=unix:///run/legacy.sock")
	if _, err := loadProduction(environment); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("legacy v1 configuration was accepted: %v", err)
	}
	environment = canonicalV2Environment()
	environment[0] = "knowvault_dispatcher_root_dir=/run/knowvault/sandbox"
	if _, err := loadProduction(environment); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("case-folded non-canonical variable was accepted: %v", err)
	}
}

func TestLoadProductionRejectsNonCanonicalRolePaths(t *testing.T) {
	for index, value := range map[int]string{
		0: rootDirEnvironment + "=/run/knowvault/sandbox/",
		1: submitSocketEnvironment + "=unix:///run/knowvault/sandbox/submit/../dispatcher.sock",
		2: handoffSocketEnvironment + "=unix://relative/handoff.sock",
		3: officeSocketEnvironment + "=unix:///run//knowvault/sandbox/office/register.sock",
		4: pdfSocketEnvironment + "=unix:///run/knowvault/sandbox/pdf/register.sock\n",
	} {
		environment := canonicalV2Environment()
		// Keep the complete allowlist while replacing exactly one value.
		environment[index] = value
		if _, err := loadProduction(environment); CodeOf(err) != CodeConfigInvalid {
			t.Fatalf("non-canonical path %q was accepted: %v", value, err)
		}
	}
}

func TestLoadProductionRejectsManifestTupleDrift(t *testing.T) {
	mutations := map[string]struct {
		index int
		value string
	}{
		"root":              {0, rootDirEnvironment + "=/run/knowvault/other"},
		"submit socket":     {1, submitSocketEnvironment + "=unix:///run/knowvault/sandbox/submit/other.sock"},
		"handoff socket":    {2, handoffSocketEnvironment + "=unix:///run/knowvault/sandbox/supervisor/other.sock"},
		"office socket":     {3, officeSocketEnvironment + "=unix:///run/knowvault/sandbox/office/other.sock"},
		"pdf socket":        {4, pdfSocketEnvironment + "=unix:///run/knowvault/sandbox/pdf/other.sock"},
		"supervisor uid":    {5, supervisorUIDEnvironment + "=1"},
		"supervisor gid":    {6, supervisorGIDEnvironment + "=1"},
		"submitter uid":     {7, submitterUIDEnvironment + "=65531"},
		"submitter gid":     {8, submitterGIDEnvironment + "=65531"},
		"office worker uid": {9, officeWorkerUIDEnvironment + "=65534"},
		"office worker gid": {10, officeWorkerGIDEnvironment + "=65534"},
		"pdf worker uid":    {11, pdfWorkerUIDEnvironment + "=65535"},
		"pdf worker gid":    {12, pdfWorkerGIDEnvironment + "=65535"},
		"payload":           {13, maxPayloadEnvironment + "=1048576"},
		"frame timeout":     {14, frameTimeoutEnvironment + "=6000"},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			environment := canonicalV2Environment()
			environment[mutation.index] = mutation.value
			if _, err := loadProduction(environment); CodeOf(err) != CodeConfigInvalid {
				t.Fatalf("manifest tuple drift was accepted: %v", err)
			}
		})
	}
}

func TestManifestStartupTupleMatchesCompositionContract(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/manifests/sandbox-dispatcher.yaml")
	if err != nil {
		t.Fatalf("read dispatcher manifest: %v", err)
	}
	manifest := strings.ReplaceAll(string(raw), "\r\n", "\n")
	fragments := []string{
		"KNOWVAULT_DISPATCHER_ROOT_DIR: " + canonicalRootDir,
		"KNOWVAULT_DISPATCHER_SUBMIT_SOCKET: unix://" + canonicalSubmitSocket,
		"KNOWVAULT_DISPATCHER_HANDOFF_SOCKET: unix://" + canonicalHandoffSocket,
		"KNOWVAULT_DISPATCHER_OFFICE_REGISTER_SOCKET: unix://" + canonicalOfficeSocket,
		"KNOWVAULT_DISPATCHER_PDF_REGISTER_SOCKET: unix://" + canonicalPDFSocket,
		"KNOWVAULT_DISPATCHER_SUPERVISOR_UID: \"0\"",
		"KNOWVAULT_DISPATCHER_SUPERVISOR_GID: \"0\"",
		"KNOWVAULT_DISPATCHER_SUBMITTER_UID: \"65530\"",
		"KNOWVAULT_DISPATCHER_SUBMITTER_GID: \"65530\"",
		"KNOWVAULT_DISPATCHER_OFFICE_WORKER_UID: \"65532\"",
		"KNOWVAULT_DISPATCHER_OFFICE_WORKER_GID: \"65532\"",
		"KNOWVAULT_DISPATCHER_PDF_WORKER_UID: \"65533\"",
		"KNOWVAULT_DISPATCHER_PDF_WORKER_GID: \"65533\"",
		"KNOWVAULT_DISPATCHER_MAX_PAYLOAD_BYTES: \"67108864\"",
		"KNOWVAULT_DISPATCHER_FRAME_TIMEOUT_MS: \"5000\"",
	}
	for _, fragment := range fragments {
		if strings.Count(manifest, fragment) != 1 {
			t.Fatalf("manifest/config tuple drift for %q", fragment)
		}
	}
}

func TestNewProductionRejectsManifestTupleDriftBeforeOpeningSockets(t *testing.T) {
	config, err := loadProduction(canonicalV2Environment())
	if err != nil {
		t.Fatalf("load baseline configuration: %v", err)
	}
	config.submitterUID++
	if _, err := NewProduction(config); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("constructor accepted a drifted submitter identity: %v", err)
	}
}
