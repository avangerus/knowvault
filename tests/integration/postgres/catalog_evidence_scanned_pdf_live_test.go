//go:build linux

package postgres_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"image"
	"os"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/dispatchparser"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/ocrparser"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
	"knowvault.local/verified-workspace/tests/integration/parserv2harness"
)

// liveScannedPDF embeds the deterministic OCR canary as a real PDF image
// XObject. The source bytes therefore cross PDFBox's actual image safety walk
// and renderer before they reach the separately supervised Tesseract worker.
// The image stream is raw RGB compressed with FlateDecode (PDF, not a PNG
// wrapper), so a fixture or a parser shortcut cannot satisfy this proof.
func liveScannedPDF(t *testing.T) []byte {
	t.Helper()
	pngBytes, err := liveOCRPNG()
	if err != nil {
		t.Fatalf("encode OCR canary: %v", err)
	}
	source, _, err := image.Decode(bytes.NewReader(pngBytes))
	if err != nil {
		t.Fatalf("decode OCR canary: %v", err)
	}
	bounds := source.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	raw := make([]byte, 0, width*height*3)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := source.At(x, y).RGBA()
			raw = append(raw, byte(r>>8), byte(g>>8), byte(b>>8))
		}
	}
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(raw); err != nil {
		t.Fatalf("compress PDF image: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close PDF image stream: %v", err)
	}
	// Preserve the source aspect ratio while leaving a white margin around the
	// page. The renderer's fixed 2x scale restores the original 40px glyph
	// height, which is the calibrated envelope of the pinned Tesseract image.
	content := []byte("q 1120 0 0 180 40 60 cm /Im1 Do Q")
	objects := [][]byte{
		[]byte("<< /Type /Catalog /Pages 2 0 R >>"),
		[]byte("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
		[]byte("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1200 300] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>"),
		append([]byte(fmt.Sprintf("<< /Length %d >>\nstream\n", len(content))), append(content, []byte("\nendstream")...)...),
		append([]byte(fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n", width, height, compressed.Len())), append(compressed.Bytes(), []byte("\nendstream")...)...),
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", i+1)
		out.Write(object)
		out.WriteString("\nendobj\n")
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i < len(offsets); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

// liveQualificationOCRExtractor is only a qualification composition adapter.
// It submits the transient renderer page through the same public DispatcherV2
// protocol as production, while the OCR image remains EVIDENCE_ONLY until its
// offline and vulnerability gates close; no synthetic OCR result is possible.
type liveQualificationOCRExtractor struct{ socketPath string }

func (e liveQualificationOCRExtractor) Extract(ctx context.Context, mediaFamily string, document []byte) (*ocrparser.Result, error) {
	if mediaFamily != ocrparser.FormatPNG {
		return nil, errQualificationOCR
	}
	return submitQualificationOCR(ctx, e.socketPath, document)
}

// productionPDFRenderExtractor adapts the typed Render method to the narrow
// ingestion capability. Go has no method overloading, so the PDF text and
// renderer operations remain two explicit interfaces while sharing one facade.
type productionPDFRenderExtractor struct{ pdf *dispatchparser.PDF }

func (e productionPDFRenderExtractor) Extract(ctx context.Context, format string, document []byte) (*pdfrenderparser.Result, error) {
	return e.pdf.Render(ctx, format, document)
}

// TestS2dScannedPDFRenderOCRAndEvidenceReal proves the complete engineering
// contour: the real PDF observer classifies an embedded-image PDF, the real
// PDFBox renderer emits a transient PNG, real Tesseract recovers its text, and
// the ingestion transaction persists only Go-owned OCR Evidence and identities.
// It is intentionally opt-in under KNOWVAULT_REQUIRE_REAL_V2=1 because the
// supervisor requires Linux namespaces/cgroups and the two pinned images.
func TestS2dScannedPDFRenderOCRAndEvidenceReal(t *testing.T) {
	pdfHarness := parserv2harness.New(t, officeWorkerImage(t))
	_, pdf, err := dispatchparser.NewProduction(pdfHarness.SubmitSocketPath())
	if err != nil {
		t.Fatalf("construct PDF production facade: %v", err)
	}
	ocrImage := strings.TrimSpace(os.Getenv(ocrWorkerImageEnv))
	if ocrImage == "" {
		ocrImage = "knowvault-tesseract-ocr:gauntlet-20260829-v3"
	}
	ocrHarness := parserv2harness.New(t, ocrImage)
	pdfBytes := liveScannedPDF(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	if _, err := pdf.Extract(ctx, pdfparser.FormatPDF, pdfBytes); !errors.Is(err, pdfparser.ErrScannedOrMixedPDF) {
		t.Fatalf("image PDF was not explicitly classified for OCR: %v", err)
	}
	rendered, err := pdf.Render(ctx, pdfparser.FormatPDF, pdfBytes)
	if err != nil {
		t.Fatalf("real PDFBox render: %v", err)
	}
	if len(rendered.Pages) != 1 || len(rendered.Pages[0].PNGBytes) == 0 || rendered.Pages[0].Page != 1 {
		t.Fatalf("unexpected renderer pages: %+v", rendered.Pages)
	}
	if _, _, err := image.Decode(bytes.NewReader(rendered.Pages[0].PNGBytes)); err != nil {
		t.Fatalf("renderer did not return a valid PNG: %v", err)
	}
	ocrResult, err := submitQualificationOCR(ctx, ocrHarness.SubmitSocketPath(), rendered.Pages[0].PNGBytes)
	if err != nil {
		t.Fatalf("real Tesseract OCR of rendered page: %v", err)
	}
	if ocrResult.Parser.ArtifactHash != parserv2harness.QualifiedOCRArtifactHash {
		t.Fatalf("OCR artifact identity was not preserved: %s", ocrResult.Parser.ArtifactHash)
	}
	repaged, err := ocrparser.Repage(ocrResult, rendered.Pages[0].Page)
	if err != nil {
		t.Fatalf("repage OCR to renderer identity: %v", err)
	}
	var joined strings.Builder
	for _, token := range repaged.Pages[0].Tokens {
		joined.WriteString(token.CanonicalTokenText)
	}
	if !strings.Contains(joined.String(), "125") {
		t.Fatalf("real OCR did not recover scanned evidence: %q", joined.String())
	}

	// The same real boundaries now run through the PostgreSQL ingestion path.
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := root + string(os.PathSeparator) + "projects" + string(os.PathSeparator) + "alpha"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+string(os.PathSeparator)+"scanned.pdf", pdfBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	repo := mustRepo(t)
	handler := ingestion.NewHandler(workerStore, queue, repo, codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
		WithPDFExtractor(pdf).WithPDFRenderExtractor(productionPDFRenderExtractor{pdf: pdf}).
		WithOCRExtractor(liveQualificationOCRExtractor{socketPath: ocrHarness.SubmitSocketPath()})
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "scanned-pdf-live")
	if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/scanned.pdf"); got != "pdf-v1" {
		t.Fatalf("scanned PDF active parser revision = %q, want pdf-v1", got)
	}
	_, versionID, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/scanned.pdf")
	var canonical string
	var ocrUsed bool
	var modelID, modelRevision, modelHash, profileRevision *string
	if err := admin.QueryRow(ctx, `SELECT e.canonical_format, e.ocr_used, e.ocr_model_id,
		e.ocr_model_revision, e.ocr_artifact_hash, e.ocr_profile_revision
		FROM public.source_extraction e WHERE e.organization_id=$1 AND e.source_version_id=$2 AND e.id=$3`,
		s1dOrg, versionID, extractionID).Scan(&canonical, &ocrUsed, &modelID, &modelRevision, &modelHash, &profileRevision); err != nil {
		t.Fatal(err)
	}
	if canonical != "OCR" || !ocrUsed || modelID == nil || modelRevision == nil || modelHash == nil || profileRevision == nil ||
		*modelID != "eng" || *modelRevision != "tessdata-v1" || *profileRevision != "tessdata-v1" {
		t.Fatalf("scanned PDF OCR identity not persisted: canonical=%q used=%v model=%v/%v hash=%v profile=%v", canonical, ocrUsed, modelID, modelRevision, modelHash, profileRevision)
	}
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("scanned PDF produced no durable Evidence fragments")
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatalf("construct evidence viewer: %v", err)
	}
	fragment, err := viewer.Read(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_scanned_pdf"}, s1dWorkspace, fragments[0].id)
	if err != nil {
		t.Fatalf("authorized scanned PDF evidence read: %v", err)
	}
	anchor := fragment.Anchor
	if !bytes.Contains(anchor, []byte(`"kind":"OCR"`)) || !bytes.Contains(anchor, []byte(`"page":1`)) || bytes.Contains(anchor, []byte("text_start")) {
		t.Fatalf("durable anchor is not a repaged OCR token range: %s", anchor)
	}
}
