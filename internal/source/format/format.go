// Package format is the typed owner of text/structured format determination and
// structural validation for the S2a extractor. It maps an object's canonical
// relative path to the immutable parser-profile revision of its format, enforcing
// the scope's format allowlist, and structurally validates the canonical bytes so
// a malformed input or an extension whose bytes do not match its format is
// quarantined rather than silently coerced. The extension is only a candidate; the
// structural parse is the proof (SOURCE_CONTRACTS.md), and there is no fallback to
// plain text (PARSER_CONTRACTS.md §2).
//
// Every format here resolves to the TEXT line-range anchor and carries a distinct
// parser-profile revision, so a format is an independently revisable immutable
// Extraction. Formats needing a gated non-stdlib HTML adapter, or a gated
// office/PDF/OCR image, are deliberately absent until their dependency lock is
// accepted (ADR-0060 §1).
package format

import (
	"bytes"
	"encoding/csv"
	jsonv2 "encoding/json/v2"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// Parser-profile revisions. TEXT-anchor formats that need no structural
// validation share text-v1; each structured format has its own revision so a
// format change forces a new immutable Extraction (PARSER_CONTRACTS.md §6).
const (
	RevisionText = "text-v1"
	// RevisionSourceCode keeps source-code identity distinct from ordinary
	// prose while reusing the same text-v1 canonical bytes and line anchors.
	// The parser profile is part of immutable SourceExtraction provenance, so
	// downstream authorities can distinguish code Evidence without trusting a
	// filename at query time.
	RevisionSourceCode = "source-code-v1"
	RevisionCSV        = "csv-v1"
	RevisionJSON       = "json-v1"
	RevisionXML        = "xml-v1"
	// RevisionHTML is the folder-HTML profile. Like EML it resolves through a
	// dedicated parser (internal/source/html) rather than the byte-level Validate
	// here, but unlike EML it emits the TEXT line-range anchor (PARSER_CONTRACTS.md
	// §1); its normalized visible text is the canonical text those lines index.
	RevisionHTML = "html-v1"
	// RevisionEML is the file-EML profile. Unlike the TEXT-anchor revisions above,
	// EML resolves to the EMAIL canonical format and its MIME message/part anchor,
	// and its structural validation is the MIME parse owned by internal/source/eml,
	// not the byte-level Validate here.
	RevisionEML = "eml-v1"
	// The Office profiles. Each resolves to its own canonical format and structural
	// anchor, and its structural proof is the isolated parser sandbox's observation
	// re-validated by internal/source/docparser — never the byte-level Validate here.
	//
	// These are the Go runtime's EXTRACTION profile revisions and belong to the
	// immutable SourceExtraction. They are deliberately not the sandbox's observation
	// profile revision (which is versioned separately, in its own namespace): the
	// runtime owns what an Extraction means, the sandbox owns only how it looked at
	// the document (ADR-0062 §2b1).
	RevisionDOCX = "docx-v1"
	RevisionPPTX = "pptx-v1"
	RevisionXLSX = "xlsx-v1"
	// RevisionPDF is the Go-owned immutable extraction profile for text PDFs.
	// The sandbox observation profile remains separately versioned and is bound
	// into the Extraction observer identity.
	RevisionPDF = "pdf-v1"
	// RevisionPNG and RevisionJPEG are isolated OCR extraction profiles. Their
	// bytes are admitted by the connector signature gate and never fall back to
	// an in-process text parser.
	RevisionPNG  = "png-ocr-v1"
	RevisionJPEG = "jpeg-ocr-v1"
)

// OfficeRevision reports whether a revision resolves through the isolated office
// parser sandbox, and the canonical format it yields.
func OfficeRevision(revision string) (canonicalFormat string, ok bool) {
	switch revision {
	case RevisionDOCX:
		return "DOCX", true
	case RevisionPPTX:
		return "PPTX", true
	case RevisionXLSX:
		return "XLSX", true
	default:
		return "", false
	}
}

// PDFRevision reports whether a revision must resolve through the isolated
// text-PDF observer. It is deliberately disjoint from Office and OCR.
func PDFRevision(revision string) (canonicalFormat string, ok bool) {
	if revision == RevisionPDF {
		return "PDF", true
	}
	return "", false
}

// OCRRevision reports whether a revision resolves through the isolated OCR
// worker and returns the canonical OCR format.
func OCRRevision(revision string) (canonicalFormat string, ok bool) {
	switch revision {
	case RevisionPNG, RevisionJPEG:
		return "OCR", true
	default:
		return "", false
	}
}

// ErrInvalid means the canonical bytes are malformed for their format or the
// object's format could not be admitted; the caller quarantines.
var ErrInvalid = errors.New("format: invalid or inadmissible object")

// spec maps a Product-Constitution format name to its parser-profile revision.
type spec struct {
	name     string
	revision string
}

// extensionFormat maps a lowercase file extension (without the dot) to its
// candidate format. Source-code extensions all resolve to SOURCE_CODE with a
// dedicated text-v1 parser profile; the canonical bytes and line anchors stay
// identical to ordinary text, but provenance retains the trusted source class.
var extensionFormat = func() map[string]spec {
	m := map[string]spec{
		"txt":      {"TXT", RevisionText},
		"text":     {"TXT", RevisionText},
		"md":       {"MARKDOWN", RevisionText},
		"markdown": {"MARKDOWN", RevisionText},
		"csv":      {"CSV", RevisionCSV},
		"json":     {"JSON", RevisionJSON},
		"xml":      {"XML", RevisionXML},
		"html":     {"HTML", RevisionHTML},
		"htm":      {"HTML", RevisionHTML},
		"eml":      {"EML", RevisionEML},
		"docx":     {"DOCX", RevisionDOCX},
		"pptx":     {"PPTX", RevisionPPTX},
		"xlsx":     {"XLSX", RevisionXLSX},
		"pdf":      {"PDF", RevisionPDF},
		"png":      {"PNG", RevisionPNG},
		"jpg":      {"JPEG", RevisionJPEG},
		"jpeg":     {"JPEG", RevisionJPEG},
	}
	for _, ext := range []string{
		"go", "py", "js", "ts", "jsx", "tsx", "java", "c", "h", "cc", "cpp", "hpp",
		"cs", "rb", "rs", "sh", "bash", "sql", "yaml", "yml", "toml", "ini", "php",
		"kt", "swift", "scala", "pl", "pm", "lua", "r", "m", "mm", "gradle", "dockerfile",
	} {
		m[ext] = spec{"SOURCE_CODE", RevisionSourceCode}
	}
	return m
}()

// Determine resolves the object's format from its canonical (slash, lowercase-safe)
// relative path and requires that format to be in the scope's allowlist. It
// returns the Product-Constitution format name, the parser-profile revision, and
// ok=false (quarantine) for an unknown extension or a format the scope does not
// allow. The extension is a candidate only; Validate proves the bytes match.
func Determine(relativePath string, allowed map[string]bool) (formatName, revision string, ok bool) {
	base := relativePath
	if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
		base = base[idx+1:]
	}
	dot := strings.LastIndexByte(base, '.')
	if dot < 0 || dot == len(base)-1 {
		return "", "", false
	}
	ext := strings.ToLower(base[dot+1:])
	s, known := extensionFormat[ext]
	if !known || !allowed[s.name] {
		return "", "", false
	}
	return s.name, s.revision, true
}

// DetermineObservation resolves a format for a source-agnostic byte
// observation.  Flat sources (folder and Git) retain the extension candidate;
// mail messages and attachments may have no filename, so their trusted media
// type is the only admissible candidate.  The caller still performs the
// structural parse and coarse media-family check after this decision.  No
// unknown media type is coerced to text.
func DetermineObservation(objectType, externalID, mediaType string, allowed map[string]bool) (formatName, revision string, ok bool) {
	if objectType == "EMAIL" {
		if allowed["EML"] {
			return "EML", RevisionEML, true
		}
		return "", "", false
	}
	if objectType == "EMAIL_ATTACHMENT" {
		name, rev, mapped := mediaTypeFormat(mediaType)
		if !mapped || !allowed[name] {
			return "", "", false
		}
		return name, rev, true
	}
	return Determine(externalID, allowed)
}

func mediaTypeFormat(mediaType string) (formatName, revision string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(strings.SplitN(mediaType, ";", 2)[0])) {
	case "text/plain":
		return "TXT", RevisionText, true
	case "text/markdown":
		return "MARKDOWN", RevisionText, true
	case "text/csv", "application/csv":
		return "CSV", RevisionCSV, true
	case "application/json", "text/json":
		return "JSON", RevisionJSON, true
	case "application/xml", "text/xml":
		return "XML", RevisionXML, true
	case "text/html":
		return "HTML", RevisionHTML, true
	case "application/pdf":
		return "PDF", RevisionPDF, true
	case "image/png":
		return "PNG", RevisionPNG, true
	case "image/jpeg":
		return "JPEG", RevisionJPEG, true
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return "DOCX", RevisionDOCX, true
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return "PPTX", RevisionPPTX, true
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return "XLSX", RevisionXLSX, true
	default:
		return "", "", false
	}
}

// Validate structurally validates the canonical bytes for a parser-profile
// revision. text-v1 objects are already canonical UTF-8 and need no further
// parse; the structured revisions must parse cleanly or the object is quarantined.
func Validate(revision string, canonical []byte) error {
	switch revision {
	case RevisionText, RevisionSourceCode:
		return nil
	case RevisionCSV:
		return validateCSV(canonical)
	case RevisionJSON:
		return validateJSON(canonical)
	case RevisionXML:
		return validateXML(canonical)
	case RevisionPNG, RevisionJPEG:
		// Image structure is checked by the connector signature gate and the
		// isolated OCR worker; this package intentionally does not decode images.
		return nil
	default:
		return ErrInvalid
	}
}

// validateJSON strictly parses the whole document: encoding/json/v2 rejects
// trailing data and duplicate object names, so a malformed or ambiguous document
// is quarantined.
func validateJSON(canonical []byte) error {
	if len(bytes.TrimSpace(canonical)) == 0 {
		return ErrInvalid
	}
	var v any
	if err := jsonv2.Unmarshal(canonical, &v); err != nil {
		return ErrInvalid
	}
	return nil
}

// validateXML streams the whole document with entity/DTD resolution denied. A DTD
// directive is rejected outright (closing entity-expansion and XXE), the decoder
// resolves no external or undefined entity and fetches no network/file resource,
// and any well-formedness error quarantines.
func validateXML(canonical []byte) error {
	if len(bytes.TrimSpace(canonical)) == 0 {
		return ErrInvalid
	}
	decoder := xml.NewDecoder(bytes.NewReader(canonical))
	decoder.Strict = true
	// Entity stays nil: undefined entities are an error, so an entity-expansion
	// payload cannot resolve.
	decoder.Entity = nil
	sawElement := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrInvalid
		}
		switch t := token.(type) {
		case xml.Directive:
			// <!DOCTYPE …> and any other directive (the DTD carrier) is denied.
			return ErrInvalid
		case xml.StartElement:
			sawElement = true
		case xml.ProcInst:
			// Only the XML declaration is tolerated; any other processing
			// instruction is a directive-like escape hatch and is denied.
			if t.Target != "xml" {
				return ErrInvalid
			}
		}
	}
	if !sawElement {
		return ErrInvalid
	}
	return nil
}

// validateCSV parses the whole document with a fixed field count (the first
// record sets the shape), so a ragged record is quarantined rather than coerced;
// headers are preserved as the first record.
func validateCSV(canonical []byte) error {
	if len(bytes.TrimSpace(canonical)) == 0 {
		return ErrInvalid
	}
	reader := csv.NewReader(bytes.NewReader(canonical))
	// FieldsPerRecord defaults to setting the count from the first record and then
	// requiring every record to match, so a ragged row is a parse error.
	rows := 0
	for {
		_, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrInvalid
		}
		rows++
	}
	if rows == 0 {
		return ErrInvalid
	}
	return nil
}
