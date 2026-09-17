package workspaceapi

import (
	"fmt"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// Only the fragments intersecting this returned page are disclosed. Offsets
// are relative to the exact page text, never to a separately truncated excerpt.
type readPageFragment struct {
	Address       string `json:"canonical_address"`
	FragmentID    string `json:"fragment_id"`
	SourcePageURL string `json:"source_page_url,omitempty"`
	PageOffset    int    `json:"page_offset"`
	Length        int    `json:"length"`
}

func (handler *Handler) readPageFragments(workspaceID string, object evidence.WholeObject, page address.Page) ([]readPageFragment, error) {
	fragments := make([]readPageFragment, 0)
	for _, span := range object.Fragments {
		if span.Offset < 0 || span.Length < 0 || span.Offset > len(object.Text)-span.Length || span.FragmentID == "" {
			return nil, fmt.Errorf("invalid canonical fragment span")
		}
		start := max(span.Offset, page.Offset)
		end := min(span.Offset+span.Length, page.Offset+len(page.Data))
		if start >= end {
			continue
		}
		fragment := object.Fragment
		fragment.FragmentID = span.FragmentID
		fragment.Ordinal = span.Ordinal
		fragment.Text = object.Text[span.Offset : span.Offset+span.Length]
		canonical, err := handler.canonicalEvidenceAddress(fragment)
		if err != nil {
			return nil, err
		}
		fragments = append(fragments, readPageFragment{
			Address: canonical.String(), FragmentID: span.FragmentID,
			SourcePageURL: handler.evidenceSourcePageURL(workspaceID, span.FragmentID, canonical.String()),
			PageOffset:    start - page.Offset, Length: end - start,
		})
	}
	return fragments, nil
}
