package ingestion

import (
	jsonv2 "encoding/json/v2"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestNativePlanningRetainsWholeTextAndObserverMetadata(t *testing.T) {
	for _, format := range []string{"DOCX", "PPTX", "XLSX", "PDF"} {
		profile := canon.StructuralLayoutParserRevision("parser-v1")
		metadata, _ := jsonv2.Marshal(map[string]any{"parser_profile_revision": profile, "observer_name": "qualified-native", "page_width": 612})
		planned := []plannedUnit{{text: []byte("10")}, {text: []byte("30")}}
		for i := range planned {
			if format == "PDF" {
				planned[i].pdfAnchor = []byte{byte(i + 1)}
				planned[i].pdfMetadata = metadata
			} else {
				planned[i].officeAnchor = []byte{byte(i + 1)}
				planned[i].officeMetadata = metadata
			}
		}
		whole := []byte("10\n30")
		if err := bindStructuralLayout(format, profile, whole, canon.Hash(whole), planned); err != nil {
			t.Fatal(err)
		}
		units, err := buildUnits(format, profile, "object", planned)
		if err != nil {
			t.Fatal(err)
		}
		for i, unit := range units {
			var meta struct {
				ObserverName string                         `json:"observer_name"`
				PageWidth    int                            `json:"page_width"`
				Layout       canon.StructuralFragmentLayout `json:"canonical_text_layout"`
			}
			if err := jsonv2.Unmarshal(unit.metadata, &meta); err != nil {
				t.Fatal(err)
			}
			if meta.ObserverName != "qualified-native" || meta.PageWidth != 612 || meta.Layout.CanonicalSHA256 != canon.Hash(whole) || meta.Layout.Ordinal != i+1 || meta.Layout.AnchorSHA256 != canon.Hash(unit.anchorBytes) {
				t.Fatal("native metadata lost observer or layout binding")
			}
		}
		if err := bindStructuralLayout(format, profile, whole, "sha256:wrong", planned); err == nil {
			t.Fatal("wrong parser whole hash accepted")
		}
	}
}
