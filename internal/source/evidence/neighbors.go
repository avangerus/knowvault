package evidence

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// FragmentNeighbors contains at most the adjacent fragments in the active
// extraction of one source version. The Fragment values are obtained through
// the normal authorized Read path; callers must project only their immutable
// identifiers and addresses, never the returned text.
type FragmentNeighbors struct {
	Previous *Fragment
	Next     *Fragment
}

type fragmentNeighborRef struct {
	id     string
	before bool
}

// ReadNeighbors resolves the immediate predecessor and successor of an
// already authorized fragment. The metadata query is bounded to the same
// source version and active extraction. Each candidate is then opened through
// Read so the ordinary workspace authorization, access-point recheck and
// citation audit happen before the caller can project an address. A neighbor
// that becomes unreadable is silently omitted, preserving the content-free
// denial boundary of the optional metadata.
func (v *Viewer) ReadNeighbors(ctx context.Context, access database.AccessContext, workspaceID string, current Fragment) (FragmentNeighbors, error) {
	if v == nil || v.db == nil || workspaceID == "" || current.FragmentID == "" ||
		current.ExtractionID == "" || current.SourceVersionID == "" || current.SourceObjectID == "" {
		return FragmentNeighbors{}, ErrNotFound
	}

	refs, err := v.readNeighborRefs(ctx, access, workspaceID, current)
	if err != nil {
		return FragmentNeighbors{}, ErrNotFound
	}
	var result FragmentNeighbors
	for _, ref := range refs {
		fragment, readErr := v.Read(ctx, access, workspaceID, ref.id)
		if readErr != nil || fragment.FragmentID != ref.id || len(fragment.Text) == 0 ||
			fragment.ExtractionID != current.ExtractionID ||
			fragment.SourceVersionID != current.SourceVersionID ||
			fragment.SourceObjectID != current.SourceObjectID {
			continue
		}
		if ref.before {
			if fragment.Ordinal >= current.Ordinal {
				continue
			}
			result.Previous = &fragment
			continue
		}
		if fragment.Ordinal <= current.Ordinal {
			continue
		}
		result.Next = &fragment
	}
	return result, nil
}

func (v *Viewer) readNeighborRefs(ctx context.Context, access database.AccessContext, workspaceID string, current Fragment) ([]fragmentNeighborRef, error) {
	refs := make([]fragmentNeighborRef, 0, 2)
	err := v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var (
			storedVersionID    string
			storedExtractionID string
			storedObjectID     string
			storedOrdinal      int64
		)
		if err := tx.QueryRow(ctx, `
			SELECT f.source_version_id, f.extraction_id, v.source_object_id, f.ordinal
			FROM public.evidence_fragment f
			JOIN public.source_version v
			  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
			JOIN public.source_version_active_extraction ae
			  ON ae.organization_id = f.organization_id
			 AND ae.source_version_id = f.source_version_id
			 AND ae.extraction_id = f.extraction_id
			WHERE f.organization_id = $1
			  AND f.id = $2
			  AND app.evidence_fragment_readable(f.id, $3)`,
			access.OrganizationID, current.FragmentID, workspaceID).Scan(
			&storedVersionID, &storedExtractionID, &storedObjectID, &storedOrdinal); err != nil {
			if database.IsNotFound(err) {
				return ErrNotFound
			}
			return err
		}
		if storedVersionID != current.SourceVersionID || storedExtractionID != current.ExtractionID ||
			storedObjectID != current.SourceObjectID || storedOrdinal != current.Ordinal {
			return ErrNotFound
		}

		readNeighbor := func(before bool) error {
			comparison, order := ">", "ASC"
			if before {
				comparison, order = "<", "DESC"
			}
			// evidence_fragment enforces UNIQUE (organization_id, extraction_id,
			// ordinal), so ordinal order is unambiguous within this extraction;
			// id remains a defensive stable tie-breaker in the ordered query.
			query := `SELECT f.id
				FROM public.evidence_fragment f
				JOIN public.source_version_active_extraction ae
				  ON ae.organization_id = f.organization_id
				 AND ae.source_version_id = f.source_version_id
				 AND ae.extraction_id = f.extraction_id
				JOIN public.source_version v
				  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
				WHERE f.organization_id = $1
				  AND f.source_version_id = $2
				  AND f.extraction_id = $3
				  AND v.source_object_id = $4
				  AND f.ordinal ` + comparison + ` $5
				ORDER BY f.ordinal ` + order + `, f.id ` + order + `
				LIMIT 1`
			var ref fragmentNeighborRef
			ref.before = before
			if err := tx.QueryRow(ctx, query, access.OrganizationID, current.SourceVersionID, current.ExtractionID, current.SourceObjectID, current.Ordinal).Scan(&ref.id); err != nil {
				if database.IsNotFound(err) {
					return nil
				}
				return err
			}
			refs = append(refs, ref)
			return nil
		}
		if err := readNeighbor(true); err != nil {
			return err
		}
		return readNeighbor(false)
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}
