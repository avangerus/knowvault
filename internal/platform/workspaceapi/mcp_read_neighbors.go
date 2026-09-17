package workspaceapi

import (
	"context"
	"encoding/json"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// EvidenceFragmentNeighbors is an optional additive capability. Keeping it
// separate from EvidenceService lets fragment-only fakes and mounted services
// retain the existing read contract; unsupported services simply omit optional
// neighbor metadata from a successful direct page.
type EvidenceFragmentNeighbors interface {
	ReadNeighbors(context.Context, database.AccessContext, string, evidence.Fragment) (evidence.FragmentNeighbors, error)
}

type readNeighborProjection struct {
	FragmentID string `json:"fragment_id"`
	Ordinal    int64  `json:"ordinal"`
	Address    string `json:"canonical_address"`
}

type readNeighborsProjection struct {
	Previous *readNeighborProjection `json:"previous"`
	Next     *readNeighborProjection `json:"next"`
}

func (handler *Handler) evidenceFragmentNeighborsCapability() (EvidenceFragmentNeighbors, bool) {
	if handler == nil || handler.evidence == nil {
		return nil, false
	}
	capability, ok := handler.evidence.(EvidenceFragmentNeighbors)
	return capability, ok
}

// readNeighborsProjection asks the optional capability only after the primary
// fragment has passed the ordinary authorized Read path. It projects no text;
// an unavailable or structurally inconsistent neighbor is omitted without
// changing the successful primary page.
func (handler *Handler) readNeighborsProjection(ctx context.Context, access database.AccessContext, workspaceID string, current evidence.Fragment) *readNeighborsProjection {
	capability, ok := handler.evidenceFragmentNeighborsCapability()
	if !ok {
		return nil
	}
	neighbors, err := capability.ReadNeighbors(ctx, access, workspaceID, current)
	if err != nil {
		return nil
	}
	return &readNeighborsProjection{
		Previous: handler.readNeighborProjection(current, neighbors.Previous, true),
		Next:     handler.readNeighborProjection(current, neighbors.Next, false),
	}
}

func (handler *Handler) readNeighborProjection(current evidence.Fragment, neighbor *evidence.Fragment, previous bool) *readNeighborProjection {
	if neighbor == nil || neighbor.FragmentID == "" || neighbor.FragmentID == current.FragmentID || len(neighbor.Text) == 0 ||
		neighbor.ExtractionID == "" || neighbor.ExtractionID != current.ExtractionID ||
		neighbor.SourceObjectID == "" || neighbor.SourceObjectID != current.SourceObjectID ||
		neighbor.SourceVersionID == "" || neighbor.SourceVersionID != current.SourceVersionID {
		return nil
	}
	if previous && neighbor.Ordinal >= current.Ordinal {
		return nil
	}
	if !previous && neighbor.Ordinal <= current.Ordinal {
		return nil
	}
	canonical, err := handler.canonicalEvidenceAddress(*neighbor)
	if err != nil {
		return nil
	}
	return &readNeighborProjection{FragmentID: neighbor.FragmentID, Ordinal: neighbor.Ordinal, Address: canonical.String()}
}

// mcpEvidenceReadNeighborsMetadata keeps the content-only MCP channel in sync
// with structuredContent. It carries identifiers and full-fragment addresses,
// never neighboring source text; the JSON is compact so the trailing metadata
// line remains unambiguous to clients that do not parse structuredContent.
func mcpEvidenceReadNeighborsMetadata(neighbors *readNeighborsProjection) string {
	if neighbors == nil {
		return ""
	}
	raw, err := json.Marshal(neighbors)
	if err != nil {
		return ""
	}
	return " neighbors=" + string(raw)
}
