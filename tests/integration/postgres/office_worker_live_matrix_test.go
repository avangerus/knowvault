package postgres_test

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/source/docparser"
)

// TestS2bLiveOfficeWorkerFormatMatrix qualifies each Office media family at the
// real image/DispatcherV2 boundary before the broader folder-ingestion proof.
// Keeping this matrix narrow makes a format-specific wire or worker regression
// observable without first processing the hostile-package corpus.
func TestS2bLiveOfficeWorkerFormatMatrix(t *testing.T) {
	runtime := newProductionParserRuntime(t)
	cases := []struct {
		name   string
		format string
		body   func(*testing.T) []byte
	}{
		{name: "docx", format: docparser.FormatDOCX, body: validDOCX},
		{name: "pptx", format: docparser.FormatPPTX, body: validPPTX},
		{name: "xlsx", format: docparser.FormatXLSX, body: validXLSX},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := runtime.office.Extract(context.Background(), tc.format, tc.body(t))
			if err != nil {
				t.Fatalf("real %s extraction failed: %v", tc.format, err)
			}
			if result == nil || result.ObservedFormat != tc.format || len(result.Fragments) == 0 {
				t.Fatalf("real %s result is incomplete: %#v", tc.format, result)
			}
		})
	}
}
