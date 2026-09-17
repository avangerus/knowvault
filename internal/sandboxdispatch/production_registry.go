package sandboxdispatch

import "time"

// The DispatcherV2 production registry is the single immutable owner of the
// parser capability tuple. The submitter facade and the deployment composition
// both consume these values; neither is allowed to copy a profile, bound or
// artifact identity independently.
const (
	ProductionParserArtifactHash            = "sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414"
	ProductionSandboxProfileRevision        = "document-parser-sandbox-v3"
	ProductionOfficeObservationRev          = "office-obs-v1"
	ProductionPDFObservationRevision        = "pdf-obs-v1"
	ProductionPDFRendererRevision           = "pdf-render-v1"
	ProductionOfficeOutputContract          = "document-parser-result-v1"
	ProductionPDFOutputContract             = "pdf-parser-result-v1"
	ProductionPDFRenderOutputContract       = "pdf-render-result-v1"
	ProductionMaxInputBytes           int64 = 64 << 20
	ProductionMaxOutputBytes          int64 = 16 << 20
	ProductionMaxUnits                int64 = 100000
	ProductionMaxPages                int64 = 10000
	ProductionMaxDecodedPixels        int64 = 1
	ProductionRenderMaxDecodedPixels  int64 = 50_000_000
	ProductionOCRMaxInputBytes        int64 = 32 << 20
	ProductionOCRMaxOutputBytes       int64 = 8 << 20
	ProductionOCRMaxUnits             int64 = 100000
	ProductionOCRMaxDecodedPixels     int64 = 100_000_000
	ProductionParserWallClockMS       int64 = 120000
)

// ProductionV2Limits is the unchanged finite cgroup profile for DispatcherV2
// parser roles.
func ProductionV2Limits() Limits {
	return Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: ProductionParserWallClockMS}
}

// ProductionV2Registry returns a fresh registry slice with the immutable
// Office (DOCX/PPTX/XLSX) and text-PDF capabilities. UID/GID values are the
// deployment-owned socket principals supplied by the composition snapshot;
// all parser/profile/artifact/limit values come from this package.
func ProductionV2Registry(officeUID, officeGID, pdfUID, pdfGID int) []V2RegistryEntry {
	limits := ProductionV2Limits()
	entry := func(parserType, mediaFamily, mediaType, observationRevision, outputContract string, workerUID, workerGID int) V2RegistryEntry {
		operation := OperationObserveStructure
		if parserType == ParserTypePDF {
			operation = OperationObservePDFText
		}
		request := ParserRequestV1{
			SchemaVersion: ParserRequestVersionV1, ParserType: parserType,
			Operation: operation, MediaFamily: mediaFamily,
			SandboxProfileRevision: ProductionSandboxProfileRevision, ObservationProfileRevision: observationRevision,
			MaxInputBytes: ProductionMaxInputBytes, MaxOutputBytes: ProductionMaxOutputBytes,
			MaxUnits: ProductionMaxUnits, MaxPages: ProductionMaxPages,
			MaxDecodedPixels: ProductionMaxDecodedPixels, OutputContract: outputContract,
		}
		return V2RegistryEntry{
			ParserRequest: request, ArtifactHash: ProductionParserArtifactHash, MediaType: mediaType,
			MaxLeaseDuration: time.Duration(ProductionParserWallClockMS) * time.Millisecond,
			ExpectedLimits:   limits, RuntimeProfileHash: RuntimeProfileHash(parserType, ProductionSandboxProfileRevision, limits),
			ExpectedWorkerUID: workerUID, ExpectedWorkerGID: workerGID,
		}
	}
	registry := []V2RegistryEntry{
		entry(ParserTypeOffice, "DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ProductionOfficeObservationRev, ProductionOfficeOutputContract, officeUID, officeGID),
		entry(ParserTypeOffice, "PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation", ProductionOfficeObservationRev, ProductionOfficeOutputContract, officeUID, officeGID),
		entry(ParserTypeOffice, "XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ProductionOfficeObservationRev, ProductionOfficeOutputContract, officeUID, officeGID),
		entry(ParserTypePDF, "PDF", "application/pdf", ProductionPDFObservationRevision, ProductionPDFOutputContract, pdfUID, pdfGID),
	}
	render := entry(ParserTypePDF, "PDF", "application/pdf", ProductionPDFObservationRevision, ProductionPDFRenderOutputContract, pdfUID, pdfGID)
	render.ParserRequest.Operation = OperationRenderPDFPages
	render.ParserRequest.RendererProfileRevision = ProductionPDFRendererRevision
	render.ParserRequest.MaxDecodedPixels = ProductionRenderMaxDecodedPixels
	registry = append(registry, render)
	return registry
}
