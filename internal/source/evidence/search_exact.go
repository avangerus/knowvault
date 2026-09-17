package evidence

import (
	"context"
	"errors"
	"sort"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// FragmentVersionRef binds a search survivor to the immutable version that
// produced it. A fragment from another version cannot satisfy this reference.
type FragmentVersionRef struct {
	FragmentID      string
	SourceVersionID string
}

// AuthorizeFragmentVersions is the final live authorization of an all_versions
// search. It uses the existing exact-read repository and returns freshly read
// text, anchors and provenance; previously returned search bytes are not reused.
// As with AuthorizeFragments, search admission must already have been journalled.
// An unreadable tuple is omitted without revealing why it was refused.
func (v *Viewer) AuthorizeFragmentVersions(ctx context.Context, access database.AccessContext,
	workspaceID string, references []FragmentVersionRef) ([]Fragment, error) {
	if v == nil || v.db == nil || v.codec == nil || ctx == nil || access.Validate() != nil ||
		workspaceID == "" || len(references) > maximumAuthorizedFragments {
		return nil, ErrNotFound
	}
	if len(references) == 0 {
		return nil, nil
	}
	ordered := make([]FragmentVersionRef, 0, len(references))
	seen := make(map[string]string, len(references))
	for _, reference := range references {
		if reference.FragmentID == "" || reference.SourceVersionID == "" {
			return nil, ErrNotFound
		}
		if versionID, duplicate := seen[reference.FragmentID]; duplicate {
			if versionID != reference.SourceVersionID {
				return nil, ErrNotFound
			}
			continue
		}
		seen[reference.FragmentID] = reference.SourceVersionID
		ordered = append(ordered, reference)
	}
	versionRepos := make(map[string]*repository.Repository)
	authorized := make([]Fragment, 0, len(ordered))
	err := v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		for _, reference := range ordered {
			repo := versionRepos[reference.SourceVersionID]
			if repo == nil {
				var err error
				repo, err = repositoryForWorkspaceVersion(workspaceID, reference.SourceVersionID)
				if err != nil {
					return err
				}
				versionRepos[reference.SourceVersionID] = repo
			}
			fragment, _, err := v.readExactFragmentInTransaction(ctx, tx, repo, access,
				workspaceID, reference.FragmentID, reference.SourceVersionID)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			authorized = append(authorized, fragment)
		}
		return nil
	})
	if err != nil {
		return nil, ErrNotFound
	}
	sort.SliceStable(authorized, func(i, j int) bool { return authorized[i].FragmentID < authorized[j].FragmentID })
	return authorized, nil
}
