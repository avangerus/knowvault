package observation

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/connector/folder"
)

// FolderAdapter is the real bounded filesystem adapter for document, mail and
// Git scopes.  The same implementation is selected by the admitted source
// kind; only the trusted scope configuration decides what media reaches it.
// It has no database, workspace-write or credential authority.
type FolderAdapter struct {
	connector           *folder.Connector
	scope               *folder.Scope
	organizationID      string
	sourceScopeID       string
	sourceScopeRevision int64
	kind                Kind
	now                 func() time.Time
}

func NewFolderAdapter(connector *folder.Connector, scope *folder.Scope, organizationID, sourceScopeID string, sourceScopeRevision int64, kind Kind) (*FolderAdapter, error) {
	if connector == nil || scope == nil || !validKind(kind) || kind == KindSQLBusinessData ||
		!validOpaque(organizationID) || !validOpaque(sourceScopeID) || sourceScopeRevision < 1 || sourceScopeRevision > 9007199254740991 {
		return nil, &Error{code: CodeInvalidRequest}
	}
	return &FolderAdapter{
		connector: connector, scope: scope, organizationID: organizationID,
		sourceScopeID: sourceScopeID, sourceScopeRevision: sourceScopeRevision,
		kind: kind, now: time.Now,
	}, nil
}

func (adapter *FolderAdapter) Kind() Kind {
	if adapter == nil {
		return ""
	}
	return adapter.kind
}

func (adapter *FolderAdapter) Observe(ctx context.Context, request Request) (Page, error) {
	if adapter == nil || ctx == nil || !validRequest(request) ||
		request.OrganizationID != adapter.organizationID || request.SourceScopeID != adapter.sourceScopeID || request.SourceScopeRevision != adapter.sourceScopeRevision {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	discovery, err := adapter.connector.Discover(ctx, adapter.scope)
	if err != nil {
		return Page{}, &Error{code: CodeAdapterRejected, cause: err}
	}
	if len(discovery.Objects) > request.MaxObjects {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	page := Page{OrganizationID: adapter.organizationID, Kind: adapter.kind, CoverageComplete: discovery.Complete}
	for _, quarantine := range discovery.Quarantined {
		page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: quarantine.RelativePath, Code: string(quarantine.Code)})
	}
	for _, discovered := range discovery.Objects {
		read, quarantine, readErr := adapter.connector.Read(ctx, adapter.scope, discovered.RelativePath)
		if readErr != nil {
			return Page{}, &Error{code: CodeAdapterRejected, cause: readErr}
		}
		if quarantine != nil {
			// Per-object quarantine is not a fabricated observation.  The source
			// catalog records the diagnostic; preserve it on the page so the
			// reconciliation owner can count and persist the quarantine exactly as
			// it did before the source-agnostic seam was introduced.
			page.Quarantined = append(page.Quarantined, Quarantine{
				ExternalID: quarantine.RelativePath, Code: string(quarantine.Code),
			})
			continue
		}
		observedAt := adapter.now().UTC()
		if discovered.ModTimeUnixNano > 0 {
			observedAt = time.Unix(0, discovered.ModTimeUnixNano).UTC()
		}
		page.Objects = append(page.Objects, Object{
			Kind: adapter.kind, ExternalID: discovered.RelativePath,
			VersionKey: read.NativeVersionToken, ObjectType: "DOCUMENT",
			ContentHash: read.ContentSHA256, ObservedAt: observedAt,
			PayloadKind: PayloadBytes,
			Document:    &DocumentPayload{MediaType: read.MediaType, MediaFamily: string(read.MediaFamily), Bytes: read.Content},
		})
	}
	if err := page.Validate(request); err != nil {
		return Page{}, err
	}
	return page, nil
}
