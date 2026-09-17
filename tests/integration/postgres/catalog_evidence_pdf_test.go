package postgres_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/dispatchparser"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
)

const pdfEvidenceCanary = "KNOWVAULT_PDF_CANARY_20260828"

// buildPDF emits a real, xref-correct PDF without adding a PDF library to the Go
// product. The bytes cross the actual Docker/PDFBox boundary in this test.
func buildPDF(t *testing.T, content []byte, catalogExtra string, extraObjects ...[]byte) []byte {
	t.Helper()
	objects := [][]byte{
		[]byte("<< /Type /Catalog /Pages 2 0 R " + catalogExtra + " >>"),
		[]byte("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
		[]byte("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"),
		[]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
		append([]byte(fmt.Sprintf("<< /Length %d >>\nstream\n", len(content))), append(content, []byte("\nendstream")...)...),
	}
	objects = append(objects, extraObjects...)
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

func validTextPDF(t *testing.T) []byte {
	return buildPDF(t, []byte("BT /F1 12 Tf 72 720 Td (Waste hauled today: 42 tonnes. "+pdfEvidenceCanary+") Tj ET"), "")
}

func scannedPDF(t *testing.T) []byte {
	return buildPDF(t, []byte("0 0 100 100 re f"), "")
}

func mixedInlineImagePDF(t *testing.T) []byte {
	content := append([]byte("BT /F1 12 Tf 72 720 Td (visible text) Tj ET\nq\nBI /W 1 /H 1 /CS /DeviceGray /BPC 8 ID "), 0xff)
	content = append(content, []byte(" EI\nQ")...)
	return buildPDF(t, content, "")
}

func activePDF(t *testing.T) []byte {
	return buildPDF(t, []byte("BT /F1 12 Tf 72 720 Td (visible text) Tj ET"), "/OpenAction 6 0 R",
		[]byte("<< /S /JavaScript /JS (app.alert\\(1\\)) >>"))
}

// TestS2cPDFFolderExtraction proves the bounded S2c path against real PostgreSQL,
// filesystem bytes and the real PDFBox image through the production dispatcher
// facade. The external test supervisor is the only process-launching component.
func TestS2cPDFFolderExtraction(t *testing.T) {
	runtime := newProductionParserRuntime(t)
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	valid := validTextPDF(t)
	write("waste.pdf", valid)
	write("scanned.pdf", scannedPDF(t))
	write("mixed.pdf", mixedInlineImagePDF(t))
	write("active.pdf", activePDF(t))
	write("fake.pdf", []byte("plain text "+pdfEvidenceCanary))
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "a plain text neighbour")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
		WithPDFExtractor(runtime.pdf)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "pdf-sync")

	if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/waste.pdf"); got != "pdf-v1" {
		t.Fatalf("valid PDF profile = %q, want pdf-v1", got)
	}
	for _, name := range []string{"scanned.pdf", "mixed.pdf", "active.pdf", "fake.pdf"} {
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/"+name); got != "" {
			t.Fatalf("hostile %s published extraction %q", name, got)
		}
	}
	if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/notes.txt"); got != "text-v1" {
		t.Fatalf("neighbouring text did not continue after PDF quarantines: %q", got)
	}

	t.Run("exact PDF anchor replay", func(t *testing.T) {
		result, err := runtime.pdf.Extract(ctx, pdfparser.FormatPDF, valid)
		if err != nil {
			t.Fatal(err)
		}
		_, _, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/waste.pdf")
		stored := officeFragments(t, ctx, admin, extractionID)
		if len(stored) != len(result.Fragments) || len(stored) == 0 {
			t.Fatalf("stored/replayed fragments = %d/%d", len(stored), len(result.Fragments))
		}
		for i, fragment := range result.Fragments {
			if len(fragment.Anchor.BoundingBoxes) == 0 {
				t.Fatalf("fragment %d has no PDF geometry", i+1)
			}
			if stored[i].textHash != canon.HMACDigest(s1dDigestKey, 1, fragment.CanonicalText) ||
				stored[i].anchorHash != canon.HMACDigest(s1dDigestKey, 1, fragment.AnchorBytes) {
				t.Fatalf("fragment %d did not replay hash-for-hash", i+1)
			}
		}
	})

	t.Run("no raw PDF or canary reaches durable control fields", func(t *testing.T) {
		var leaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job
			WHERE organization_id=$1 AND (position($2 in payload_json::text)>0 OR position($2 in coalesce(last_error_code,''))>0)`,
			s1dOrg, pdfEvidenceCanary).Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if leaks != 0 {
			t.Fatal("PDF source content reached a job payload or error code")
		}
		var rawHeaders int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
			WHERE organization_id=$1 AND position('%PDF-' in encode(ciphertext,'escape'))>0`, s1dOrg).Scan(&rawHeaders); err != nil {
			t.Fatal(err)
		}
		if rawHeaders != 0 {
			t.Fatal("raw PDF bytes reached a durable artifact")
		}
	})

	before := s1dCounts(t, ctx, admin)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "pdf-resync")
	if after := s1dCounts(t, ctx, admin); after != before {
		t.Fatalf("repeat PDF sync changed catalog counts: %+v -> %+v", before, after)
	}
}

func TestS2cPDFMissingOrWrongWorkerIdentityQuarantines(t *testing.T) {
	ctx := context.Background()
	t.Run("missing dispatcher boundary", func(t *testing.T) {
		admin := resetStage1Database(t)
		codec := s1dCodec(t, s1dOrg)
		root := t.TempDir()
		dir := filepath.Join(root, "projects", "alpha")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "waste.pdf"), validTextPDF(t), 0o644); err != nil {
			t.Fatal(err)
		}
		writeS1dFile(t, filepath.Join(dir, "notes.txt"), "continues")
		seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
		configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
		seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
			s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
		workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
		queue, _ := jobs.New(workerStore)
		_, missingPDF, err := dispatchparser.NewProduction(filepath.Join(root, "missing-dispatcher.sock"))
		if err != nil {
			t.Fatal(err)
		}
		handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
			WithPDFExtractor(missingPDF)
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "pdf-failure")
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/waste.pdf"); got != "" {
			t.Fatalf("failed PDF worker published %q", got)
		}
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/notes.txt"); got != "text-v1" {
			t.Fatalf("neighbour did not continue: %q", got)
		}
	})

	t.Run("caller timeout is fail closed", func(t *testing.T) {
		runtime := newProductionParserRuntime(t)
		admin := resetStage1Database(t)
		codec := s1dCodec(t, s1dOrg)
		root := t.TempDir()
		dir := filepath.Join(root, "projects", "alpha")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "waste.pdf"), validTextPDF(t), 0o644); err != nil {
			t.Fatal(err)
		}
		writeS1dFile(t, filepath.Join(dir, "notes.txt"), "continues")
		seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
		configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
		seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
			s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
		workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
		queue, _ := jobs.New(workerStore)
		handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
			WithPDFExtractor(pdfWithDeadline{pdf: runtime.pdf, timeout: 50 * time.Millisecond})
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "pdf-timeout")
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/waste.pdf"); got != "" {
			t.Fatalf("expired PDF worker published %q", got)
		}
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/notes.txt"); got != "text-v1" {
			t.Fatalf("neighbour did not continue: %q", got)
		}
	})
}
