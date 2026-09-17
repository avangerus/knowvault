package search

import (
	"strings"
	"testing"
)

func TestValidChunkAllowsLexicalOnlyProjection(t *testing.T) {
	chunk := Chunk{
		ID: "chunk_01", OrganizationID: "org_01", SourceVersionID: "version_01",
		ExtractionID: "extract_01", ChunkHash: "sha256:" + strings.Repeat("a", 64), TokenCount: 3,
	}
	if !validChunk(chunk, "org_01") {
		t.Fatal("lexical-only chunk rejected")
	}
}

func TestValidChunkRejectsPartialEmbeddingTuple(t *testing.T) {
	chunk := Chunk{
		ID: "chunk_01", OrganizationID: "org_01", SourceVersionID: "version_01",
		ExtractionID: "extract_01", ChunkHash: "sha256:" + strings.Repeat("a", 64), TokenCount: 3,
		EmbeddingProfileHash: "sha256:" + strings.Repeat("b", 64),
	}
	if validChunk(chunk, "org_01") {
		t.Fatal("partial embedding tuple accepted")
	}
}
