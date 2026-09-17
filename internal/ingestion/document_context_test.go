package ingestion

import (
	"strings"
	"testing"
)

// A retrieval unit alone names no document. The chunk projection therefore
// carries the object's own path from the observation that produced it, so a
// question about where something is implemented can match, rank and cite the
// file rather than an anonymous body of text.
func TestDocumentChunkTextCarriesTheObjectPath(t *testing.T) {
	chunk := string(documentChunkText("internal/workspace/repository/trust_verify.go",
		[]byte("func VerifySourceConnectionTrust(ctx context.Context) error {")))
	if !strings.HasPrefix(chunk, "internal/workspace/repository/trust_verify.go\n") {
		t.Fatalf("chunk %q does not open with the object path", chunk)
	}
	if !strings.Contains(chunk, "VerifySourceConnectionTrust") {
		t.Fatalf("chunk %q lost the unit text", chunk)
	}
}

// The Evidence fragment stays the document's exact bytes; only the retrieval
// projection gains context. A path that could corrupt the projection (empty,
// multi-line, invalid UTF-8) is dropped rather than embedded.
func TestDocumentChunkTextRejectsUnusablePaths(t *testing.T) {
	for name, path := range map[string]string{
		"empty":     "",
		"blank":     "   ",
		"multiline": "a\nb",
		"carriage":  "a\rb",
		"invalid":   string([]byte{0xff, 0xfe}),
	} {
		chunk := string(documentChunkText(path, []byte("body")))
		if chunk != "body" {
			t.Fatalf("%s: chunk=%q want the unmodified unit text", name, chunk)
		}
	}
}
