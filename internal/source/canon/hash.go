package canon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"sort"
)

// ErrCanonical is returned when a value cannot be rendered to canonical JSON.
var ErrCanonical = errors.New("canon: cannot canonicalize value")

// canonicalJSON renders value to RFC 8785 JCS bytes using the pinned jsonv2
// canonicalizer (the same reference implementation the rest of the codebase and
// the contract validators use).
func canonicalJSON(value any) ([]byte, error) {
	raw, err := jsonv2.Marshal(value)
	if err != nil {
		return nil, ErrCanonical
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return nil, ErrCanonical
	}
	return []byte(canonical), nil
}

// CanonicalJSON exposes the single RFC 8785/JCS implementation to other
// source owners. Keeping this helper here prevents each connector from
// inventing a subtly different hash projection.
func CanonicalJSON(value any) ([]byte, error) {
	return canonicalJSON(value)
}

// FileLocatorBytes returns the canonical JCS of the folder FILE locator of
// CANONICALIZATION.md s3.1: {"connection_id","kind":"FILE","relative_path"}.
// relativePath must already be the connector's canonical (slash, NFC, relative)
// path.
func FileLocatorBytes(connectionID, relativePath string) ([]byte, error) {
	return canonicalJSON(struct {
		ConnectionID string `json:"connection_id"`
		Kind         string `json:"kind"`
		RelativePath string `json:"relative_path"`
	}{ConnectionID: connectionID, Kind: "FILE", RelativePath: relativePath})
}

// ObservationExternalIDBytes returns the canonical source-agnostic identity
// projection for one observed object.  It is deliberately separate from the
// locator projection: a mail attachment, for example, has one stable external
// identity and a locator that also carries its parent MIME part.  Both values
// are transient canonical bytes and are keyed by the caller before persistence.
func ObservationExternalIDBytes(connectionID, kind, externalID string) ([]byte, error) {
	return canonicalJSON(struct {
		ConnectionID string `json:"connection_id"`
		Kind         string `json:"kind"`
		ExternalID   string `json:"external_id"`
	}{ConnectionID: connectionID, Kind: kind, ExternalID: externalID})
}

// ObservationLocatorBytes returns the canonical source-agnostic locator for a
// connector observation.  ParentExternalID and PartPath are retained in the
// identity even when empty, so a provider cannot silently reinterpret a flat
// object as a nested one (or vice versa) without changing its digest.
func ObservationLocatorBytes(connectionID, kind, externalID, parentExternalID, partPath string) ([]byte, error) {
	return canonicalJSON(struct {
		ConnectionID     string `json:"connection_id"`
		Kind             string `json:"kind"`
		ExternalID       string `json:"external_id"`
		ParentExternalID string `json:"parent_external_id"`
		PartPath         string `json:"part_path"`
	}{ConnectionID: connectionID, Kind: kind, ExternalID: externalID,
		ParentExternalID: parentExternalID, PartPath: partPath})
}

// HMACDigest formats an organization-scoped keyed digest as
// hmac-sha256:k<version>:<lowercase hex>, the form the schema and DB validators
// accept. The key is supplied by the caller's trusted digester; canon never
// holds key material.
func HMACDigest(key []byte, keyVersion int, message []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return fmt.Sprintf("hmac-sha256:k%d:%s", keyVersion, hex.EncodeToString(mac.Sum(nil)))
}

// TextAnchorBytes returns the canonical JCS of a TEXT anchor
// {"kind":"TEXT","line_start","line_end"} per source-anchor.schema.json. The
// resolver maps this line range back to the exact UTF-8 byte range.
func TextAnchorBytes(lineStart, lineEnd int) ([]byte, error) {
	return canonicalJSON(struct {
		Kind      string `json:"kind"`
		LineStart int    `json:"line_start"`
		LineEnd   int    `json:"line_end"`
	}{Kind: "TEXT", LineStart: lineStart, LineEnd: lineEnd})
}

// EmailAnchorBytes returns the canonical JCS of an EMAIL anchor per
// source-anchor.schema.json: a message id, a MIME part path and a half-open
// UTF-8 byte range into that part's text-v1 canonical text. messageID is the
// deterministic file-EML identity ("source-object:<id>"), never the RFC
// Message-ID header (PARSER_CONTRACTS.md s5). The offsets are byte offsets into
// the exact MIME part's canonical text, so the resolver re-derives the part and
// slices [textStart,textEnd).
func EmailAnchorBytes(messageID, mimePart string, textStart, textEnd int) ([]byte, error) {
	return canonicalJSON(struct {
		Kind                 string `json:"kind"`
		MessageID            string `json:"message_id"`
		MIMEPart             string `json:"mime_part"`
		TextStart            int    `json:"text_start"`
		TextEnd              int    `json:"text_end"`
		OffsetUnit           string `json:"offset_unit"`
		RangeSemantics       string `json:"range_semantics"`
		NormalizationVersion string `json:"normalization_version"`
	}{
		Kind: "EMAIL", MessageID: messageID, MIMEPart: mimePart,
		TextStart: textStart, TextEnd: textEnd,
		OffsetUnit: "UTF8_BYTE", RangeSemantics: "START_INCLUSIVE_END_EXCLUSIVE",
		NormalizationVersion: NormalizationVersion,
	})
}

// ObserverIdentity is the exact identity of an isolated parser sandbox that observed
// a document. It is not authority — the observer supplies no hash, offset or anchor —
// but it is part of what produced the Evidence, so it belongs in the extraction
// identity (ADR-0062 §2f, PARSER_CONTRACTS.md §6).
type ObserverIdentity struct {
	Name                       string
	Version                    string
	ArtifactHash               string
	ObservationProfileRevision string
	RuntimeProfileHash         string
}

// OCRProfile is the exact `ocr` member CANONICALIZATION.md s7 freezes. Its
// ArtifactHash is itself a composite over the OCR engine and the deterministic
// renderer, so the renderer profile is part of the extraction identity without the
// frozen shape gaining a field (ADR-0063 s4).
type OCRProfile struct {
	ModelID         string
	ModelRevision   string
	ArtifactHash    string
	ProfileRevision string
}

// ExtractionProfile is the exact profile-hash shape of CANONICALIZATION.md s7.
//
// Observer is set exactly when the canonical text was observed by an isolated parser
// sandbox. It has no member of its own in the frozen shape: instead it composes into
// extractor.artifact_hash. That is deliberate — the shape stays byte-identical to the
// one the contract froze, while swapping a worker image necessarily changes the
// profile hash. Without it, a new image under an unchanged parser_profile_revision
// would leave profile_hash equal, the "already extracted" short-circuit would fire,
// and the platform would keep serving Evidence attributed to a build that no longer
// exists.
type ExtractionProfile struct {
	CanonicalFormat string
	ExtractorName   string
	ExtractorVer    string
	ArtifactHash    string
	ParserRevision  string
	Observer        *ObserverIdentity
	OCR             *OCRProfile
}

// CompositeArtifactHash binds the Go extractor's identity to the identity of the
// isolated observer that produced the text it canonicalized. Either one changing
// changes the result, so either one changing must change the extraction identity.
func CompositeArtifactHash(extractorHash string, observer ObserverIdentity) (string, error) {
	if observer.RuntimeProfileHash != "" && !validSHA256(observer.RuntimeProfileHash) {
		return "", ErrCanonical
	}
	raw, err := canonicalJSON(struct {
		ExtractorArtifactHash      string `json:"extractor_artifact_hash"`
		ObserverArtifactHash       string `json:"observer_artifact_hash"`
		ObserverName               string `json:"observer_name"`
		ObserverVersion            string `json:"observer_version"`
		ObservationProfileRevision string `json:"observation_profile_revision"`
		RuntimeProfileHash         string `json:"runtime_profile_hash,omitempty"`
	}{
		ExtractorArtifactHash:      extractorHash,
		ObserverArtifactHash:       observer.ArtifactHash,
		ObserverName:               observer.Name,
		ObserverVersion:            observer.Version,
		ObservationProfileRevision: observer.ObservationProfileRevision,
		RuntimeProfileHash:         observer.RuntimeProfileHash,
	})
	if err != nil {
		return "", err
	}
	return Hash(raw), nil
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size
}

type profileOCR struct {
	ModelID         string `json:"model_id"`
	ModelRevision   string `json:"model_revision"`
	ArtifactHash    string `json:"artifact_hash"`
	ProfileRevision string `json:"profile_revision"`
}

type profileExtractor struct {
	Name                  string `json:"name"`
	Version               string `json:"version"`
	ArtifactHash          string `json:"artifact_hash"`
	ParserProfileRevision string `json:"parser_profile_revision"`
}

// ProfileBytes returns the canonical JCS of the extraction profile. ocr is null
// unless OCR produced the text.
func (p ExtractionProfile) ProfileBytes() ([]byte, error) {
	artifactHash := p.ArtifactHash
	if p.Observer != nil {
		composite, err := CompositeArtifactHash(p.ArtifactHash, *p.Observer)
		if err != nil {
			return nil, err
		}
		artifactHash = composite
	}
	var ocr *profileOCR
	if p.OCR != nil {
		ocr = &profileOCR{
			ModelID:         p.OCR.ModelID,
			ModelRevision:   p.OCR.ModelRevision,
			ArtifactHash:    p.OCR.ArtifactHash,
			ProfileRevision: p.OCR.ProfileRevision,
		}
	}
	return canonicalJSON(struct {
		CanonicalFormat      string           `json:"canonical_format"`
		Extractor            profileExtractor `json:"extractor"`
		NormalizationVersion string           `json:"normalization_version"`
		OCR                  *profileOCR      `json:"ocr"`
	}{
		CanonicalFormat: p.CanonicalFormat,
		Extractor: profileExtractor{
			Name:                  p.ExtractorName,
			Version:               p.ExtractorVer,
			ArtifactHash:          artifactHash,
			ParserProfileRevision: p.ParserRevision,
		},
		NormalizationVersion: NormalizationVersion,
		OCR:                  ocr,
	})
}

// EvidenceDescriptor is one entry of the ordered evidence-set hash input.
type EvidenceDescriptor struct {
	FragmentID string
	Ordinal    int
	TextHash   string
	AnchorHash string
}

// EvidenceSetHash returns the SHA-256 of the JCS array of descriptors sorted by
// ordinal, in the exact object shape of CANONICALIZATION.md s7.
func EvidenceSetHash(descriptors []EvidenceDescriptor) (string, error) {
	sorted := make([]EvidenceDescriptor, len(descriptors))
	copy(sorted, descriptors)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Ordinal < sorted[j].Ordinal })
	entries := make([]struct {
		AnchorHash       string `json:"anchor_hash"`
		EvidenceFragment string `json:"evidence_fragment_id"`
		EvidenceTextHash string `json:"evidence_text_hash"`
		Ordinal          int    `json:"ordinal"`
	}, len(sorted))
	for i, d := range sorted {
		entries[i].AnchorHash = d.AnchorHash
		entries[i].EvidenceFragment = d.FragmentID
		entries[i].EvidenceTextHash = d.TextHash
		entries[i].Ordinal = d.Ordinal
	}
	raw, err := canonicalJSON(entries)
	if err != nil {
		return "", err
	}
	return Hash(raw), nil
}
