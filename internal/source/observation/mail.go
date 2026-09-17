package observation

import (
	"context"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/connector/mail"
)

// MailAdapter binds a real source-native mail connector to the common
// observation contract. Authentication, IMAP read-only command policy and
// UIDVALIDITY/UID identity remain inside the connector; this type only adds
// server-owned organization/scope binding and transient document payloads.
type MailAdapter struct {
	connector           *mail.Connector
	organizationID      string
	sourceScopeID       string
	sourceScopeRevision int64
}

func NewMailAdapter(connector *mail.Connector, organizationID, sourceScopeID string, sourceScopeRevision int64) (*MailAdapter, error) {
	if connector == nil || !validOpaque(organizationID) || !validOpaque(sourceScopeID) ||
		sourceScopeRevision < 1 || sourceScopeRevision > 9007199254740991 {
		return nil, &Error{code: CodeInvalidRequest}
	}
	return &MailAdapter{connector: connector, organizationID: organizationID, sourceScopeID: sourceScopeID,
		sourceScopeRevision: sourceScopeRevision}, nil
}

func (adapter *MailAdapter) Kind() Kind {
	if adapter == nil {
		return ""
	}
	return KindMail
}

// Close retires the connector and clears its private password state.
func (adapter *MailAdapter) Close() error {
	if adapter == nil || adapter.connector == nil {
		return nil
	}
	return adapter.connector.Close()
}

func (adapter *MailAdapter) Observe(ctx context.Context, request Request) (Page, error) {
	if adapter == nil || ctx == nil || !validRequest(request) || request.OrganizationID != adapter.organizationID ||
		request.SourceScopeID != adapter.sourceScopeID || request.SourceScopeRevision != adapter.sourceScopeRevision || request.Cursor != "" {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	native, err := adapter.connector.Observe(ctx, mail.ObserveRequest{MaxObjects: request.MaxObjects, MaxBytes: request.MaxBytes})
	if err != nil {
		return Page{}, &Error{code: CodeAdapterRejected, cause: err}
	}
	page := Page{OrganizationID: adapter.organizationID, Kind: KindMail, CoverageComplete: native.CoverageComplete,
		SnapshotHash: native.SnapshotHash}
	for _, quarantine := range native.Quarantined {
		page.Quarantined = append(page.Quarantined, Quarantine{ExternalID: quarantine.ExternalID, Code: string(quarantine.Code)})
	}
	for _, object := range native.Objects {
		page.Objects = append(page.Objects, Object{
			Kind: KindMail, ExternalID: object.ExternalID, VersionKey: "native:" + object.VersionKey,
			ObjectType: object.ObjectType, ParentExternalID: object.ParentExternalID, PartPath: object.MIMEPart,
			ContentHash: object.ContentHash, ObservedAt: time.Now().UTC(),
			PayloadKind: PayloadBytes, Document: &DocumentPayload{MediaType: object.MediaType,
				MediaFamily: mailMediaFamily(object.MediaType), Bytes: object.Content},
		})
	}
	if err := page.Validate(request); err != nil {
		return Page{}, err
	}
	return page, nil
}

func mailMediaFamily(mediaType string) string {
	switch strings.ToLower(mediaType) {
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
