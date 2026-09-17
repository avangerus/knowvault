// Package observation defines the source-agnostic hand-off from connectors to
// the ingestion/catalog owner.  A connector may read documents, mail, Git or
// SQL business objects, but it can only return this bounded typed observation;
// it cannot write catalog rows, choose a workspace, execute user SQL or emit a
// citation.
package observation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/pathcanon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

type Kind string

const (
	KindDocument        Kind = "DOCUMENT"
	KindMail            Kind = "MAIL"
	KindGit             Kind = "GIT"
	KindSQLBusinessData Kind = "SQL_BUSINESS_DATA"
)

type PayloadKind string

const (
	PayloadBytes    PayloadKind = "BYTES"
	PayloadTypedRow PayloadKind = "TYPED_ROW"
)

type ErrorCode string

const (
	CodeInvalidRequest  ErrorCode = "OBSERVATION_REQUEST_INVALID"
	CodeAdapterMissing  ErrorCode = "OBSERVATION_ADAPTER_MISSING"
	CodeAdapterRejected ErrorCode = "OBSERVATION_ADAPTER_REJECTED"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeAdapterRejected
}

// Request is server-owned scope context.  It contains no DSN, credentials,
// SQL text or caller-controlled workspace selector beyond the already admitted
// source scope revision.
type Request struct {
	OrganizationID      string
	SourceScopeID       string
	SourceScopeRevision int64
	Cursor              string
	MaxObjects          int
	MaxBytes            int64
}

// DocumentPayload is the transient byte observation for a document, mail
// message, Git commit/file, or other source object represented as bytes.
type DocumentPayload struct {
	MediaType   string
	MediaFamily string
	Bytes       []byte
}

// PayloadFormat is the interoperable business-object payload contract. SQL
// rows currently use JSON (the canonical typed row array), while other
// source-owned business projections may use structural TEXT or MARKDOWN.
type PayloadFormat string

const (
	PayloadFormatJSON     PayloadFormat = "JSON"
	PayloadFormatText     PayloadFormat = "TEXT"
	PayloadFormatMarkdown PayloadFormat = "MARKDOWN"
)

// BusinessObjectContract is the minimum source-neutral envelope required for
// a business object. The ingestion owner binds these fields to the immutable
// SourceObject/SourceVersion/Evidence lineage; no model or caller can supply
// them. Payload bytes are canonical and never executable.
type BusinessObjectContract struct {
	EntityID      string                   `json:"entity_id"`
	EntityVersion string                   `json:"entity_version"`
	LastUpdatedAt time.Time                `json:"last_updated_at"`
	Payload       []byte                   `json:"payload"`
	PayloadFormat PayloadFormat            `json:"payload_format"`
	Provenance    BusinessObjectProvenance `json:"provenance"`
}

type BusinessObjectProvenance struct {
	SourceKind             string `json:"source_kind"`
	OrganizationID         string `json:"organization_id"`
	SourceScopeID          string `json:"source_scope_id"`
	SourceScopeRevision    int64  `json:"source_scope_revision"`
	ConnectionID           string `json:"connection_id"`
	DatabaseIdentity       string `json:"database_identity"`
	ProjectionLineageID    string `json:"projection_lineage_id"`
	ProjectionRevision     int64  `json:"projection_revision"`
	ProjectionContractHash string `json:"projection_contract_hash"`
	RowVersionHash         string `json:"row_version_hash"`
}

// BusinessRowPayload is the only SQL representation admitted at this seam. A
// projection and a canonical typed row have already been attested by the SQL
// connector; executable SQL and driver values are intentionally absent. The
// Contract envelope is the interoperable entity_id/entity_version/
// last_updated_at/payload/payload_format/provenance shape consumed by the
// source-agnostic graph pipeline.
type BusinessRowPayload struct {
	Projection postgresqlquery.Projection
	Row        postgresqlquery.Row
	Contract   BusinessObjectContract
}

type Object struct {
	Kind       Kind
	ExternalID string
	VersionKey string
	ObjectType string
	// ParentExternalID and PartPath preserve source-native containment (for
	// example an email attachment's message and MIME part). They are optional
	// for flat sources such as Git files and folders, but when present they are
	// validated and carried into provenance projection rather than inferred
	// later from display text.
	ParentExternalID string
	PartPath         string
	ContentHash      string
	ObservedAt       time.Time
	SourceUpdatedAt  *time.Time
	PayloadKind      PayloadKind
	Document         *DocumentPayload
	BusinessRow      *BusinessRowPayload
}

// Quarantine is a per-object, content-free diagnostic. It is carried beside
// the admitted objects so a partial/unsupported object can never be mistaken
// for an authoritative deletion during reconciliation.
type Quarantine struct {
	ExternalID string
	Code       string
}

type Page struct {
	OrganizationID   string
	Kind             Kind
	Objects          []Object
	Quarantined      []Quarantine
	NextCursor       string
	CoverageComplete bool
	SnapshotHash     string
}

// Adapter is implemented by a real connector.  Observe is read-only and
// bounded; persistence, provenance binding, lifecycle and Evidence publication
// remain the ingestion/catalog owner's responsibility.
type Adapter interface {
	Kind() Kind
	Observe(context.Context, Request) (Page, error)
}

// Registry owns the closed set of adapters configured by deployment.  There is
// no default/mock adapter: asking for a source kind without a real registered
// implementation fails closed.
type Registry struct {
	byKind map[Kind]Adapter
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{byKind: make(map[Kind]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil || !validKind(adapter.Kind()) {
			return nil, &Error{code: CodeInvalidRequest}
		}
		if _, exists := registry.byKind[adapter.Kind()]; exists {
			return nil, &Error{code: CodeInvalidRequest}
		}
		registry.byKind[adapter.Kind()] = adapter
	}
	return registry, nil
}

func (registry *Registry) Observe(ctx context.Context, kind Kind, request Request) (Page, error) {
	if registry == nil || ctx == nil || !validKind(kind) || !validRequest(request) {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	adapter, ok := registry.byKind[kind]
	if !ok {
		return Page{}, &Error{code: CodeAdapterMissing}
	}
	page, err := adapter.Observe(ctx, request)
	if err != nil {
		return Page{}, &Error{code: CodeAdapterRejected, cause: err}
	}
	if err := page.Validate(request); err != nil {
		return Page{}, err
	}
	return page, nil
}

func (page Page) Validate(request Request) error {
	if !validRequest(request) || page.OrganizationID != request.OrganizationID || page.Kind == "" || !validKind(page.Kind) || len(page.Objects) > request.MaxObjects {
		return &Error{code: CodeInvalidRequest}
	}
	if page.Kind == KindSQLBusinessData && !page.CoverageComplete {
		// A partial SQL snapshot is not a business fact. The SQL adapter must
		// report complete coverage or the planner will return UNKNOWN.
		return &Error{code: CodeAdapterRejected}
	}
	var totalBytes int64
	seen := make(map[string]struct{}, len(page.Objects))
	for _, quarantine := range page.Quarantined {
		if !validSourceIdentity(quarantine.ExternalID) || !validOpaque(quarantine.Code) {
			return &Error{code: CodeInvalidRequest}
		}
	}
	for _, object := range page.Objects {
		if err := object.Validate(page.Kind); err != nil {
			return err
		}
		if page.Kind == KindSQLBusinessData && object.BusinessRow != nil {
			provenance := object.BusinessRow.Contract.Provenance
			if provenance.OrganizationID != request.OrganizationID || provenance.SourceScopeID != request.SourceScopeID || provenance.SourceScopeRevision != request.SourceScopeRevision {
				return &Error{code: CodeInvalidRequest}
			}
		}
		if _, duplicate := seen[object.ExternalID+"\x00"+object.VersionKey]; duplicate {
			return &Error{code: CodeInvalidRequest}
		}
		seen[object.ExternalID+"\x00"+object.VersionKey] = struct{}{}
		objectBytes := int64(0)
		if object.Document != nil {
			objectBytes = int64(len(object.Document.Bytes))
		}
		if object.BusinessRow != nil {
			objectBytes = int64(len(object.BusinessRow.Row.Canonical))
		}
		// Compare before adding so an adversarial page cannot wrap the running
		// total and pass the aggregate byte budget.
		if objectBytes < 0 || objectBytes > request.MaxBytes-totalBytes {
			return &Error{code: CodeInvalidRequest}
		}
		totalBytes += objectBytes
	}
	if page.NextCursor != "" && !validOpaque(page.NextCursor) {
		return &Error{code: CodeInvalidRequest}
	}
	// A continuation must make progress and a page marked complete cannot also
	// advertise more work. Without these checks a faulty provider could make a
	// source sync loop forever or reconcile an incomplete tail as authoritative.
	if page.NextCursor != "" && page.NextCursor == request.Cursor {
		return &Error{code: CodeInvalidRequest}
	}
	if page.CoverageComplete && page.NextCursor != "" {
		return &Error{code: CodeInvalidRequest}
	}
	if page.Kind == KindSQLBusinessData && !validSHA256(page.SnapshotHash) {
		return &Error{code: CodeAdapterRejected}
	}
	return nil
}

func (object Object) Validate(kind Kind) error {
	if object.Kind != kind || !validSourceIdentity(object.ExternalID) || !validOpaque(object.VersionKey) ||
		!validVersionKey(object.VersionKey) || !validOpaque(object.ObjectType) || !validSHA256(object.ContentHash) || object.ObservedAt.IsZero() {
		return &Error{code: CodeInvalidRequest}
	}
	if object.ParentExternalID != "" && (!validSourceIdentity(object.ParentExternalID) || object.ParentExternalID == object.ExternalID) {
		return &Error{code: CodeInvalidRequest}
	}
	if object.PartPath != "" && !validOpaque(object.PartPath) {
		return &Error{code: CodeInvalidRequest}
	}
	if object.SourceUpdatedAt != nil && object.SourceUpdatedAt.IsZero() {
		return &Error{code: CodeInvalidRequest}
	}
	switch object.PayloadKind {
	case PayloadBytes:
		if object.Document == nil || object.BusinessRow != nil || len(object.Document.Bytes) == 0 || !validOpaque(object.Document.MediaType) || !validMediaFamily(object.Document.MediaFamily) {
			return &Error{code: CodeInvalidRequest}
		}
		if hashBytes(object.Document.Bytes) != object.ContentHash {
			return &Error{code: CodeInvalidRequest}
		}
	case PayloadTypedRow:
		if kind != KindSQLBusinessData || object.BusinessRow == nil || object.Document != nil || object.BusinessRow.Projection.Validate() != nil || len(object.BusinessRow.Row.Canonical) == 0 || object.BusinessRow.Row.Hash != object.ContentHash || !validBusinessObjectContract(object.BusinessRow.Contract, object.BusinessRow.Projection, object.BusinessRow.Row, object) {
			return &Error{code: CodeInvalidRequest}
		}
	default:
		return &Error{code: CodeInvalidRequest}
	}
	return nil
}

func validBusinessObjectContract(contract BusinessObjectContract, projection postgresqlquery.Projection, row postgresqlquery.Row, object Object) bool {
	if contract.EntityID == "" || contract.EntityID != object.ExternalID || contract.EntityVersion == "" || contract.EntityVersion != object.VersionKey ||
		contract.LastUpdatedAt.IsZero() || !validPayloadFormat(contract.PayloadFormat) || len(contract.Payload) == 0 || !bytes.Equal(contract.Payload, row.Canonical) || hashBytes(contract.Payload) != object.ContentHash {
		return false
	}
	canonical := jsontext.Value(append([]byte(nil), contract.Payload...))
	if err := canonical.Canonicalize(); err != nil || !bytes.Equal([]byte(canonical), contract.Payload) {
		return false
	}
	if object.SourceUpdatedAt != nil && !contract.LastUpdatedAt.Equal(object.SourceUpdatedAt.UTC()) {
		return false
	}
	p := contract.Provenance
	return p.SourceKind == string(KindSQLBusinessData) && p.OrganizationID != "" && p.SourceScopeID != "" && p.SourceScopeRevision >= 1 &&
		p.ConnectionID == projection.ConnectionID && p.DatabaseIdentity == projection.DatabaseIdentity && p.ProjectionLineageID == projection.LineageID &&
		p.ProjectionRevision == projection.Revision && p.ProjectionContractHash == projection.ContractHash && p.RowVersionHash == row.Hash
}

func validPayloadFormat(value PayloadFormat) bool {
	switch value {
	case PayloadFormatJSON, PayloadFormatText, PayloadFormatMarkdown:
		return true
	default:
		return false
	}
}

func validVersionKey(value string) bool {
	if strings.HasPrefix(value, "hash:") {
		return validSHA256(strings.TrimPrefix(value, "hash:"))
	}
	if !strings.HasPrefix(value, "native:") {
		return false
	}
	tail := strings.TrimPrefix(value, "native:")
	if len(tail) < 1 || len(tail) > 248 {
		return false
	}
	for _, r := range tail {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}

func validRequest(request Request) bool {
	return validOpaque(request.OrganizationID) && validOpaque(request.SourceScopeID) && request.SourceScopeRevision >= 1 && request.SourceScopeRevision <= 9007199254740991 &&
		(request.Cursor == "" || validOpaque(request.Cursor)) && request.MaxObjects >= 1 && request.MaxObjects <= 10_000_000 && request.MaxBytes >= 1 && request.MaxBytes <= 1<<40
}

func validKind(kind Kind) bool {
	switch kind {
	case KindDocument, KindMail, KindGit, KindSQLBusinessData:
		return true
	default:
		return false
	}
}

func validMediaFamily(value string) bool {
	switch value {
	case "TEXT", "PDF", "PNG", "JPEG", "OOXML":
		return true
	default:
		return false
	}
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

// Source-native identities include canonical folder and Git paths. Their
// accepted byte limit matches pathcanon rather than the smaller control-plane
// identifier limit; connector-specific validation has already enforced the
// source identity syntax before this source-agnostic observation is built.
func validSourceIdentity(value string) bool {
	if value == "" || len(value) > pathcanon.MaxBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
