package observation

import (
	"context"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/connector/git"
)

// GitAdapter binds the read-only HTTPS Git connector to the source-agnostic
// observation contract. The connector owns provider authentication and tree
// consistency; this adapter only adds the server-owned organization/scope
// identity and converts native blobs to transient document payloads.
type GitAdapter struct {
	connector           *git.Connector
	organizationID      string
	sourceScopeID       string
	sourceScopeRevision int64
}

func NewGitAdapter(connector *git.Connector, organizationID, sourceScopeID string, sourceScopeRevision int64) (*GitAdapter, error) {
	if connector == nil || !validOpaque(organizationID) || !validOpaque(sourceScopeID) ||
		sourceScopeRevision < 1 || sourceScopeRevision > 9007199254740991 {
		return nil, &Error{code: CodeInvalidRequest}
	}
	return &GitAdapter{connector: connector, organizationID: organizationID, sourceScopeID: sourceScopeID,
		sourceScopeRevision: sourceScopeRevision}, nil
}

func (adapter *GitAdapter) Kind() Kind {
	if adapter == nil {
		return ""
	}
	return KindGit
}

// Close retires the connector transport and clears its private token state.
func (adapter *GitAdapter) Close() error {
	if adapter == nil || adapter.connector == nil {
		return nil
	}
	return adapter.connector.Close()
}

func (adapter *GitAdapter) Observe(ctx context.Context, request Request) (Page, error) {
	if adapter == nil || ctx == nil || !validRequest(request) || request.OrganizationID != adapter.organizationID ||
		request.SourceScopeID != adapter.sourceScopeID || request.SourceScopeRevision != adapter.sourceScopeRevision || request.Cursor != "" {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	native, err := adapter.connector.Observe(ctx, git.ObserveRequest{MaxObjects: request.MaxObjects, MaxBytes: request.MaxBytes})
	if err != nil {
		return Page{}, &Error{code: CodeAdapterRejected, cause: err}
	}
	page := Page{OrganizationID: adapter.organizationID, Kind: KindGit, CoverageComplete: native.CoverageComplete,
		SnapshotHash: native.SnapshotHash}
	for _, quarantine := range native.Quarantined {
		page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: quarantine.Path, Code: string(quarantine.Code)})
	}
	for _, object := range native.Objects {
		page.Objects = append(page.Objects, Object{
			Kind: KindGit, ExternalID: object.Path,
			// The catalog's immutable version contract distinguishes connector-native
			// versions from folder content-hash surrogates.  Keep the provider token
			// opaque but typed at this boundary so it can enter source_version without
			// a downstream string guess.
			VersionKey: "native:" + object.NativeVersionKey, ObjectType: "GIT_FILE",
			ContentHash: object.ContentHash, ObservedAt: time.Now().UTC(), PayloadKind: PayloadBytes,
			Document: &DocumentPayload{MediaType: object.MediaType, MediaFamily: gitMediaFamily(object.MediaType), Bytes: object.Content},
		})
	}
	if err := page.Validate(request); err != nil {
		return Page{}, err
	}
	return page, nil
}

func gitMediaFamily(mediaType string) string {
	mediaType = strings.ToLower(mediaType)
	switch mediaType {
	case "application/pdf":
		return "PDF"
	case "image/png":
		return "PNG"
	case "image/jpeg":
		return "JPEG"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return "OOXML"
	default:
		return "TEXT"
	}
}
