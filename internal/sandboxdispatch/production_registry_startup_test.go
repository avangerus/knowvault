package sandboxdispatch

import (
	"testing"
	"time"
)

func TestProductionRegistryPinsV3StartupProfileWithoutChangingCapabilities(t *testing.T) {
	if ProductionSandboxProfileRevision != "document-parser-sandbox-v3" {
		t.Fatalf("production startup profile = %q, want document-parser-sandbox-v3", ProductionSandboxProfileRevision)
	}

	wantLimits := Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: 120_000}
	if got := ProductionV2Limits(); got != wantLimits {
		t.Fatalf("resource profile changed: got %#v, want %#v", got, wantLimits)
	}

	registry := ProductionV2Registry(65532, 65532, 65533, 65533)
	wantEntries := []struct {
		parserType, operation, mediaFamily, mediaType, observation, output string
		maxDecodedPixels                                                   int64
		workerUID, workerGID                                               int
	}{
		{ParserTypeOffice, OperationObserveStructure, "DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ProductionOfficeObservationRev, ProductionOfficeOutputContract, ProductionMaxDecodedPixels, 65532, 65532},
		{ParserTypeOffice, OperationObserveStructure, "PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation", ProductionOfficeObservationRev, ProductionOfficeOutputContract, ProductionMaxDecodedPixels, 65532, 65532},
		{ParserTypeOffice, OperationObserveStructure, "XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ProductionOfficeObservationRev, ProductionOfficeOutputContract, ProductionMaxDecodedPixels, 65532, 65532},
		{ParserTypePDF, OperationObservePDFText, "PDF", "application/pdf", ProductionPDFObservationRevision, ProductionPDFOutputContract, ProductionMaxDecodedPixels, 65533, 65533},
		{ParserTypePDF, OperationRenderPDFPages, "PDF", "application/pdf", ProductionPDFObservationRevision, ProductionPDFRenderOutputContract, ProductionRenderMaxDecodedPixels, 65533, 65533},
	}
	if len(registry) != len(wantEntries) {
		t.Fatalf("registry entries = %d, want %d", len(registry), len(wantEntries))
	}

	for i, want := range wantEntries {
		got := registry[i]
		request := got.ParserRequest
		if request.SchemaVersion != ParserRequestVersionV1 || request.ParserType != want.parserType ||
			request.Operation != want.operation || request.MediaFamily != want.mediaFamily ||
			request.SandboxProfileRevision != ProductionSandboxProfileRevision ||
			request.ObservationProfileRevision != want.observation || request.OutputContract != want.output ||
			request.MaxInputBytes != ProductionMaxInputBytes || request.MaxOutputBytes != ProductionMaxOutputBytes ||
			request.MaxUnits != ProductionMaxUnits || request.MaxPages != ProductionMaxPages ||
			request.MaxDecodedPixels != want.maxDecodedPixels {
			t.Errorf("registry[%d] parser capability changed beyond startup profile: %#v", i, request)
		}
		if got.MediaType != want.mediaType || got.ExpectedLimits != wantLimits ||
			got.MaxLeaseDuration != time.Duration(ProductionParserWallClockMS)*time.Millisecond ||
			got.ExpectedWorkerUID != want.workerUID || got.ExpectedWorkerGID != want.workerGID {
			t.Errorf("registry[%d] resource/media/identity tuple changed: %#v", i, got)
		}
		if got.ArtifactHash != ProductionParserArtifactHash {
			t.Errorf("registry[%d] artifact hash drifted before a measured candidate hash was supplied", i)
		}
		if request.OCRProfileRevision != "" {
			t.Errorf("registry[%d] unexpectedly acquired an OCR profile: %q", i, request.OCRProfileRevision)
		}
		if want.operation != OperationRenderPDFPages && request.RendererProfileRevision != "" {
			t.Errorf("registry[%d] unexpectedly acquired a renderer profile: %q", i, request.RendererProfileRevision)
		}
		if wantHash := RuntimeProfileHash(want.parserType, "document-parser-sandbox-v3", wantLimits); got.RuntimeProfileHash != wantHash {
			t.Errorf("registry[%d] runtime profile hash = %q, want v3 hash %q", i, got.RuntimeProfileHash, wantHash)
		}
		if got.RuntimeProfileHash == RuntimeProfileHash(want.parserType, "document-parser-sandbox-v2", wantLimits) {
			t.Errorf("registry[%d] startup profile revision did not re-key runtime identity", i)
		}
		if want.mediaFamily == "PDF" && want.operation == OperationRenderPDFPages && request.RendererProfileRevision != ProductionPDFRendererRevision {
			t.Errorf("registry[%d] renderer profile changed: %q", i, request.RendererProfileRevision)
		}
	}
}
