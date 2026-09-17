package canon

import (
	"strings"
	"testing"
)

func TestCanonicalJSONUsesExactJCSAndHash(t *testing.T) {
	type sample struct {
		Z int    `json:"z"`
		A string `json:"a"`
	}
	got, err := canonicalJSON(sample{Z: 1, A: "é"})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	const want = `{"a":"é","z":1}`
	if string(got) != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
	if gotHash := Hash(got); gotHash != "sha256:fb64e573f7cde5b7efeda52ffc4bdd57572055b0b7e64a70172606c82c6c7eac" {
		t.Fatalf("canonical JSON hash = %s", gotHash)
	}
}

// The extraction profile is golden-locked for the same reason the anchors are: its
// JCS form is the input to profile_hash, which identifies an immutable Extraction.
// Drift in the key set, the ordering or a const value re-identifies historical
// Extractions, so it must break this test rather than pass silently.

const (
	goldenExtractorHash = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	goldenObserverHash  = "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
)

func goldenObserver() ObserverIdentity {
	return ObserverIdentity{
		Name:                       "knowvault-document-parser",
		Version:                    "1.0",
		ArtifactHash:               goldenObserverHash,
		ObservationProfileRevision: "docx-obs-v1",
	}
}

func TestProfileBytesGoldenWithoutObserver(t *testing.T) {
	got, err := ExtractionProfile{
		CanonicalFormat: "TEXT", ExtractorName: "knowvault-text-line-parser", ExtractorVer: "1.0",
		ArtifactHash: goldenExtractorHash, ParserRevision: "text-v1",
	}.ProfileBytes()
	if err != nil {
		t.Fatalf("ProfileBytes: %v", err)
	}
	want := `{"canonical_format":"TEXT","extractor":{"artifact_hash":"` + goldenExtractorHash +
		`","name":"knowvault-text-line-parser","parser_profile_revision":"text-v1","version":"1.0"},` +
		`"normalization_version":"text-v1","ocr":null}`
	if string(got) != want {
		t.Fatalf("in-process profile drifted:\n got %s\nwant %s", got, want)
	}
}

// TestProfileBytesShapeIsUnchangedByAnObserver is the load-bearing assertion behind
// composing the observer into extractor.artifact_hash rather than adding a member:
// CANONICALIZATION.md §7 freezes this shape, and worker-backed Extractions must fit
// inside it.
func TestProfileBytesShapeIsUnchangedByAnObserver(t *testing.T) {
	observer := goldenObserver()
	got, err := ExtractionProfile{
		CanonicalFormat: "DOCX", ExtractorName: "knowvault-text-line-parser", ExtractorVer: "1.0",
		ArtifactHash: goldenExtractorHash, ParserRevision: "docx-v1", Observer: &observer,
	}.ProfileBytes()
	if err != nil {
		t.Fatalf("ProfileBytes: %v", err)
	}
	composite, err := CompositeArtifactHash(goldenExtractorHash, observer)
	if err != nil {
		t.Fatalf("CompositeArtifactHash: %v", err)
	}
	want := `{"canonical_format":"DOCX","extractor":{"artifact_hash":"` + composite +
		`","name":"knowvault-text-line-parser","parser_profile_revision":"docx-v1","version":"1.0"},` +
		`"normalization_version":"text-v1","ocr":null}`
	if string(got) != want {
		t.Fatalf("worker-backed profile drifted:\n got %s\nwant %s", got, want)
	}
	for _, forbidden := range []string{"observer", "observation_profile_revision", goldenObserverHash} {
		if strings.Contains(string(got), forbidden) {
			t.Fatalf("the frozen profile shape gained %q: %s", forbidden, got)
		}
	}
}

// TestObserverIdentityChangesTheProfileHash is the defect this slice closes: without
// it, swapping the worker image under an unchanged parser_profile_revision leaves
// profile_hash equal, the "already extracted" short-circuit fires, and the platform
// keeps serving Evidence attributed to a build that no longer exists.
func TestObserverIdentityChangesTheProfileHash(t *testing.T) {
	base := goldenObserver()
	profileOf := func(observer *ObserverIdentity) string {
		t.Helper()
		raw, err := ExtractionProfile{
			CanonicalFormat: "DOCX", ExtractorName: "knowvault-text-line-parser", ExtractorVer: "1.0",
			ArtifactHash: goldenExtractorHash, ParserRevision: "docx-v1", Observer: observer,
		}.ProfileBytes()
		if err != nil {
			t.Fatalf("ProfileBytes: %v", err)
		}
		return Hash(raw)
	}

	pinned := profileOf(&base)
	same := goldenObserver()
	if profileOf(&same) != pinned {
		t.Fatal("the same observer produced a different profile hash")
	}
	if profileOf(nil) == pinned {
		t.Fatal("dropping the observer left the profile hash unchanged")
	}

	drifts := map[string]func(ObserverIdentity) ObserverIdentity{
		"a rebuilt image": func(o ObserverIdentity) ObserverIdentity {
			o.ArtifactHash = "sha256:" + strings.Repeat("3", 64)
			return o
		},
		"a new observation profile": func(o ObserverIdentity) ObserverIdentity {
			o.ObservationProfileRevision = "docx-obs-v2"
			return o
		},
		"a different worker":   func(o ObserverIdentity) ObserverIdentity { o.Name = "other-parser"; return o },
		"a new worker version": func(o ObserverIdentity) ObserverIdentity { o.Version = "2.0"; return o },
		"a different kernel runtime profile": func(o ObserverIdentity) ObserverIdentity {
			o.RuntimeProfileHash = "sha256:" + strings.Repeat("5", 64)
			return o
		},
	}
	seen := map[string]string{pinned: "pinned"}
	for name, drift := range drifts {
		t.Run(name, func(t *testing.T) {
			mutated := drift(goldenObserver())
			hash := profileOf(&mutated)
			if hash == pinned {
				t.Fatalf("%s did not change the extraction identity", name)
			}
			if previous, collided := seen[hash]; collided {
				t.Fatalf("%s collided with %s", name, previous)
			}
			seen[hash] = name
		})
	}
}

func TestCompositeArtifactHashRejectsMalformedRuntimeProfileIdentity(t *testing.T) {
	observer := goldenObserver()
	observer.RuntimeProfileHash = "worker-self-report"
	if _, err := CompositeArtifactHash(goldenExtractorHash, observer); err == nil {
		t.Fatal("malformed runtime profile hash entered extraction identity")
	}
}

// TestOCRProfileCarriesTheFrozenMemberShape proves the ocr member is emitted with
// exactly the four keys CANONICALIZATION.md §7 names, so the renderer and engine
// identity reach the extraction identity without the shape gaining a field.
func TestOCRProfileCarriesTheFrozenMemberShape(t *testing.T) {
	observer := goldenObserver()
	got, err := ExtractionProfile{
		CanonicalFormat: "OCR", ExtractorName: "knowvault-text-line-parser", ExtractorVer: "1.0",
		ArtifactHash: goldenExtractorHash, ParserRevision: "ocr-v1", Observer: &observer,
		OCR: &OCRProfile{
			ModelID: "ocr-model", ModelRevision: "4.1.0",
			ArtifactHash: goldenObserverHash, ProfileRevision: "ocr-obs-v1",
		},
	}.ProfileBytes()
	if err != nil {
		t.Fatalf("ProfileBytes: %v", err)
	}
	want := `"ocr":{"artifact_hash":"` + goldenObserverHash +
		`","model_id":"ocr-model","model_revision":"4.1.0","profile_revision":"ocr-obs-v1"}`
	if !strings.Contains(string(got), want) {
		t.Fatalf("ocr member drifted:\n got %s\nwant substring %s", got, want)
	}
}

func TestCompositeArtifactHashIsDeterministicAndSensitive(t *testing.T) {
	observer := goldenObserver()
	first, err := CompositeArtifactHash(goldenExtractorHash, observer)
	if err != nil {
		t.Fatalf("CompositeArtifactHash: %v", err)
	}
	second, err := CompositeArtifactHash(goldenExtractorHash, goldenObserver())
	if err != nil {
		t.Fatalf("CompositeArtifactHash: %v", err)
	}
	if first != second {
		t.Fatal("the composite identity is not deterministic")
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("the composite identity is not an exact sha256: %q", first)
	}
	// Either side changing changes the result, so either side changing changes the
	// extraction identity.
	other, err := CompositeArtifactHash("sha256:"+strings.Repeat("4", 64), observer)
	if err != nil {
		t.Fatalf("CompositeArtifactHash: %v", err)
	}
	if other == first {
		t.Fatal("a different Go extractor produced the same composite identity")
	}
}
