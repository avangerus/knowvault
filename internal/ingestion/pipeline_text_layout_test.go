package ingestion

import (
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/format"
)

func TestExtractionParserRevisionSelectsFormatLayout(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		override string
		want     string
		valid    bool
	}{
		{name: "plain text", format: format.RevisionText, override: defaultParserRevision, want: "text-v1-layout-v2", valid: true},
		{name: "source code", format: format.RevisionSourceCode, override: defaultParserRevision, want: "source-code-v1-layout-v2", valid: true},
		{name: "csv", format: format.RevisionCSV, override: defaultParserRevision, want: "csv-v1-layout-v2", valid: true},
		{name: "json", format: format.RevisionJSON, override: defaultParserRevision, want: "json-v1-layout-v2", valid: true},
		{name: "xml", format: format.RevisionXML, override: defaultParserRevision, want: "xml-v1-layout-v2", valid: true},
		{name: "html visible text", format: format.RevisionHTML, override: defaultParserRevision, want: "html-v1-layout-v2", valid: true},
		{name: "text override", format: format.RevisionText, override: "fixture-parser-v4", want: "fixture-parser-v4-layout-v2", valid: true},
		{name: "office structural layout", format: format.RevisionDOCX, override: defaultParserRevision, want: format.RevisionDOCX + "-struct-layout-v1", valid: true},
		{name: "pdf structural layout", format: format.RevisionPDF, override: "fixture-pdf-parser", want: "fixture-pdf-parser-struct-layout-v1", valid: true},
		{name: "email remains legacy", format: format.RevisionEML, override: defaultParserRevision, want: format.RevisionEML, valid: true},
		{name: "text override exceeds profile bound", format: format.RevisionText, override: strings.Repeat("x", 64), valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, valid := extractionParserRevision(test.format, test.override)
			if got != test.want || valid != test.valid {
				t.Fatalf("extractionParserRevision() = (%q, %t), want (%q, %t)", got, valid, test.want, test.valid)
			}
			if usesTextFragmentLayout(test.format) && valid != canon.IsTextLayoutParserRevision(got) {
				t.Fatalf("text format profile %q does not select layout metadata", got)
			}
		})
	}
}

func TestPlannedTextUnitsCarryWholeCanonicalLayoutMetadata(t *testing.T) {
	canonical := []byte(strings.Repeat("a", maxFragmentBytes) + "\n" + "β🙂\n")
	parserRevision := "text-v1-layout-v2"
	planned, ok := plannedTextUnits(canonical, parserRevision)
	if !ok {
		t.Fatal("plannedTextUnits rejected canonical text")
	}
	if len(planned) != 2 {
		t.Fatalf("plannedTextUnits returned %d fragments, want 2", len(planned))
	}
	for i, unit := range planned {
		var layout canon.TextFragmentLayout
		if err := jsonv2.Unmarshal(unit.textLayoutMetadata, &layout); err != nil {
			t.Fatalf("fragment %d metadata did not decode: %v", i, err)
		}
		if layout.Ordinal != i+1 || layout.ParserProfileRevision != parserRevision ||
			layout.CanonicalTotalBytes != len(canonical) || layout.CanonicalSHA256 != canon.Hash(canonical) {
			t.Fatalf("fragment %d metadata does not bind the full canonical source: %+v", i, layout)
		}
	}
	units, err := buildUnits("TEXT", parserRevision, "object", planned)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != len(planned) || string(units[0].metadata) != string(planned[0].textLayoutMetadata) {
		t.Fatal("buildUnits did not preserve the planned layout metadata")
	}
}

func TestBuildUnitsRequiresLayoutMetadataForLayoutProfile(t *testing.T) {
	planned := []plannedUnit{{text: []byte("line"), lineStart: 1, lineEnd: 1}}
	if _, err := buildUnits("TEXT", "text-v1-layout-v2", "object", planned); err == nil {
		t.Fatal("buildUnits accepted a layout profile without layout metadata")
	}

	legacy, err := buildUnits("TEXT", "legacy-text-profile", "object", planned)
	if err != nil {
		t.Fatal(err)
	}
	var legacyMetadata struct {
		ParserProfileRevision string `json:"parser_profile_revision"`
		LineStart             int    `json:"line_start"`
		LineEnd               int    `json:"line_end"`
	}
	if err := jsonv2.Unmarshal(legacy[0].metadata, &legacyMetadata); err != nil {
		t.Fatal(err)
	}
	if legacyMetadata.ParserProfileRevision != "legacy-text-profile" || legacyMetadata.LineStart != 1 || legacyMetadata.LineEnd != 1 {
		t.Fatalf("legacy text metadata changed: %+v", legacyMetadata)
	}
}
