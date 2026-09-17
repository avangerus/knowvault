package ingestion

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// bindStructuralLayout retains observer metadata and adds an encrypted complete
// object layout. Legacy callers keep their previous metadata and byte contract.
func bindStructuralLayout(format, profile string, canonical []byte, expectedHash string, planned []plannedUnit) error {
	if !canon.IsStructuralLayoutParserRevision(profile) {
		return nil
	}
	if canon.Hash(canonical) != expectedHash {
		return canon.ErrStructuralFragmentLayout
	}
	units := make([]canon.StructuralTextUnit, 0, len(planned))
	for i, p := range planned {
		anchor := p.officeAnchor
		if format == "PDF" {
			anchor = p.pdfAnchor
		}
		units = append(units, canon.StructuralTextUnit{Ordinal: i + 1, Text: p.text, Anchor: anchor})
	}
	layouts, err := canon.NewStructuralFragmentLayouts(canonical, units, format, profile)
	if err != nil {
		return err
	}
	for i := range planned {
		metadata := planned[i].officeMetadata
		if format == "PDF" {
			metadata = planned[i].pdfMetadata
		}
		var fields map[string]jsontext.Value
		if err := jsonv2.Unmarshal(metadata, &fields); err != nil {
			return err
		}
		if _, present := fields["canonical_text_layout"]; present {
			return canon.ErrStructuralFragmentLayout
		}
		layout, err := jsonv2.Marshal(layouts[i])
		if err != nil {
			return err
		}
		fields["canonical_text_layout"] = layout
		updated, err := jsonv2.Marshal(fields)
		if err != nil {
			return err
		}
		if format == "PDF" {
			planned[i].pdfMetadata = updated
		} else {
			planned[i].officeMetadata = updated
		}
	}
	return nil
}
