package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/dispatchparser"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/tests/integration/parserv2harness"
)

// productionParserRuntime is the PostgreSQL qualification composition root.
// The facade owns the closed Office/PDF request tuples; the test-only harness
// supplies only the external supervisor boundary and its submitter socket.
type productionParserRuntime struct {
	harness *parserv2harness.Harness
	office  *dispatchparser.Office
	pdf     *dispatchparser.PDF
}

// officeWithDeadline is a test-only caller-fence adapter. It still invokes the
// production dispatcher facade and real Java worker; the short context merely
// proves the timeout/atomicity path without reintroducing a direct worker CLI.
type officeWithDeadline struct {
	office  *dispatchparser.Office
	timeout time.Duration
}

func (o officeWithDeadline) Extract(ctx context.Context, format string, document []byte) (*docparser.Result, error) {
	bounded, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	return o.office.Extract(bounded, format, document)
}

type pdfWithDeadline struct {
	pdf     *dispatchparser.PDF
	timeout time.Duration
}

func (p pdfWithDeadline) Extract(ctx context.Context, format string, document []byte) (*pdfparser.Result, error) {
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return p.pdf.Extract(bounded, format, document)
}

func newProductionParserRuntime(t *testing.T) *productionParserRuntime {
	t.Helper()
	harness := parserv2harness.New(t, officeWorkerImage(t))
	office, pdf, err := dispatchparser.NewProduction(harness.SubmitSocketPath())
	if err != nil {
		harness.Close()
		t.Fatalf("construct production parser facade: %v", err)
	}
	return &productionParserRuntime{harness: harness, office: office, pdf: pdf}
}

// TestParserV2ExecHelper is copied into each extracted image rootfs. The
// supervisor holds the process at the gate until the pidfd/SCM_RIGHTS handoff
// has been accepted, then this function execs the image's exact Java entrypoint.
func TestParserV2ExecHelper(t *testing.T) {
	if os.Getenv("KNOWVAULT_P2_EXEC_HELPER") != "1" {
		return
	}
	if err := parserv2harness.ExecImageEntrypoint(); err != nil {
		t.Fatal(err)
	}
}

// TestParserV2SubmitProxyHelper runs as the exact configured non-root
// submitter. It owns the public facade socket and relays opaque v2 frames to
// the root supervisor/DispatcherV2 boundary.
func TestParserV2SubmitProxyHelper(t *testing.T) {
	if os.Getenv("KNOWVAULT_P2_SUBMIT_PROXY_HELPER") != "1" {
		return
	}
	if err := parserv2harness.RunSubmitProxyHelper(); err != nil {
		t.Fatal(err)
	}
}
