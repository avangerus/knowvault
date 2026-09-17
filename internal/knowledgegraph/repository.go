// Package knowledgegraph is the typed persistence boundary for the semantic
// layer above the source catalog.  It accepts only canonical identifiers,
// hashes and an exact Evidence-backed provenance tuple; source text, SQL and
// connector credentials never cross this boundary.
package knowledgegraph

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const maximumGeneration = int64(9007199254740991)

var (
	generatedIDPattern = regexp.MustCompile(`^[a-z]+_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	predicatePattern   = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{1,127}$`)
	languagePattern    = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$`)
)

// ErrorCode is safe for API/metrics exposure.  Causes are retained only for
// trusted diagnostics and never contain source text or SQL.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "KNOWLEDGE_GRAPH_REQUEST_INVALID"
	CodePersistence ErrorCode = "KNOWLEDGE_GRAPH_PERSISTENCE_FAILED"
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
	return CodePersistence
}

// SourceProvenance is the immutable source/workspace tuple every graph object
// carries.  EvidenceFragmentID is mandatory: a graph assertion without a
// concrete Evidence row is not accepted by this package or the database.
type SourceProvenance struct {
	WorkspaceID         string
	WorkspaceRevision   int64
	SourceScopeID       string
	SourceScopeRevision int64
	SourceObjectID      string
	SourceVersionID     string
	EvidenceFragmentID  string
	ObservedAt          time.Time
	FreshnessAt         time.Time
}

// Entity is a canonical business/object identity.  CanonicalKeyHash and
// DisplayNameHash are SHA-256 hashes of normalized values; the values remain
// in encrypted Evidence/artifact storage and are never persisted as plaintext
// catalog columns.
type Entity struct {
	OrganizationID   string
	ID               string
	EntityType       string
	CanonicalKeyHash string
	DisplayNameHash  string
	AttributesJSON   []byte
	SourceProvenance
}

// Relation is a directed ontology edge between two canonical entities.  It is
// versioned by the source version and is always tied to one Evidence fragment.
type Relation struct {
	OrganizationID  string
	ID              string
	SubjectEntityID string
	Predicate       string
	ObjectEntityID  string
	Confidence      float64
	AttributesJSON  []byte
	SourceProvenance
}

// SemanticTerm is one catalog/ontology term, synonym, abbreviation or context
// alias for a canonical entity.  The term itself is represented by term_hash;
// a future encrypted-term owner can expose it to the lexical/vector index
// without widening this persistence contract.
type SemanticTerm struct {
	OrganizationID    string
	ID                string
	CanonicalEntityID string
	TermKind          string
	Language          string
	TermHash          string
	ContextHash       string
	Confidence        float64
	AttributesJSON    []byte
	SourceProvenance
}

// Validate exposes the same fail-closed checks used by the persistence methods
// for adapters that stage graph rows before opening a database transaction.
func (provenance SourceProvenance) Validate() error {
	if !validProvenance(provenance) {
		return &Error{code: CodeInvalid}
	}
	return nil
}

func (entity Entity) Validate(organizationID string) error {
	if !validEntity(entity, organizationID) {
		return &Error{code: CodeInvalid}
	}
	return nil
}

func (relation Relation) Validate(organizationID string) error {
	if !validRelation(relation, organizationID) {
		return &Error{code: CodeInvalid}
	}
	return nil
}

func (term SemanticTerm) Validate(organizationID string) error {
	if !validSemanticTerm(term, organizationID) {
		return &Error{code: CodeInvalid}
	}
	return nil
}

// Repository has no mutable state and is safe to share between workers.
// Database transactions remain owned by the caller so graph writes can be
// committed atomically with a source publication and its audit event.
type Repository struct{}

func NewRepository() *Repository { return &Repository{} }

func (repository *Repository) CreateEntity(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, entity Entity) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validEntity(entity, access.OrganizationID) {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.canonical_entity
			(organization_id, workspace_id, workspace_revision, source_scope_id,
			 source_scope_revision, id, entity_type, canonical_key_hash,
			 display_name_hash, source_object_id, source_version_id,
			 evidence_fragment_id, observed_at, freshness_at, attributes_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)`,
		entity.OrganizationID, entity.WorkspaceID, entity.WorkspaceRevision,
		entity.SourceScopeID, entity.SourceScopeRevision, entity.ID, entity.EntityType,
		entity.CanonicalKeyHash, nullableHash(entity.DisplayNameHash), entity.SourceObjectID,
		entity.SourceVersionID, entity.EvidenceFragmentID, entity.ObservedAt,
		entity.FreshnessAt, string(entity.AttributesJSON)); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// UpsertEntity performs the worker-only, tenant-bound canonical identity
// upsert. The database function hides graph rows from the worker's ordinary
// SELECT path and returns the durable winner for crash-replayed projections.
func (repository *Repository) UpsertEntity(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, entity Entity) (string, bool, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validEntity(entity, access.OrganizationID) {
		return "", false, &Error{code: CodeInvalid}
	}
	var entityID string
	var inserted bool
	if err := transaction.QueryRow(ctx, `
		SELECT entity_id, inserted
		  FROM app.knowledge_graph_entity_upsert(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		entity.WorkspaceID, entity.WorkspaceRevision, entity.SourceScopeID,
		entity.SourceScopeRevision, entity.ID, entity.EntityType,
		entity.CanonicalKeyHash, entity.DisplayNameHash, entity.SourceObjectID,
		entity.SourceVersionID, entity.EvidenceFragmentID, entity.ObservedAt,
		entity.FreshnessAt, string(entity.AttributesJSON)).Scan(&entityID, &inserted); err != nil {
		return "", false, &Error{code: CodePersistence, cause: err}
	}
	if !validGeneratedID(entityID, "entity") {
		return "", false, &Error{code: CodePersistence}
	}
	return entityID, inserted, nil
}

func (repository *Repository) CreateRelation(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, relation Relation) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validRelation(relation, access.OrganizationID) {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.entity_relation
			(organization_id, workspace_id, workspace_revision, source_scope_id,
			 source_scope_revision, id, subject_entity_id, predicate, object_entity_id,
			 source_object_id, source_version_id, evidence_fragment_id, confidence,
			 observed_at, freshness_at, attributes_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb)`,
		relation.OrganizationID, relation.WorkspaceID, relation.WorkspaceRevision,
		relation.SourceScopeID, relation.SourceScopeRevision, relation.ID,
		relation.SubjectEntityID, relation.Predicate, relation.ObjectEntityID,
		relation.SourceObjectID, relation.SourceVersionID, relation.EvidenceFragmentID,
		relation.Confidence, relation.ObservedAt, relation.FreshnessAt,
		string(relation.AttributesJSON)); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func (repository *Repository) CreateSemanticTerm(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, term SemanticTerm) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validSemanticTerm(term, access.OrganizationID) {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.semantic_term
			(organization_id, workspace_id, workspace_revision, source_scope_id,
			 source_scope_revision, id, canonical_entity_id, term_kind, language,
			 term_hash, context_hash, source_object_id, source_version_id,
			 evidence_fragment_id, confidence, observed_at, freshness_at, attributes_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb)`,
		term.OrganizationID, term.WorkspaceID, term.WorkspaceRevision, term.SourceScopeID,
		term.SourceScopeRevision, term.ID, term.CanonicalEntityID, term.TermKind,
		term.Language, term.TermHash, nullableHash(term.ContextHash), term.SourceObjectID,
		term.SourceVersionID, term.EvidenceFragmentID, term.Confidence, term.ObservedAt,
		term.FreshnessAt, string(term.AttributesJSON)); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func validEntity(entity Entity, organizationID string) bool {
	return entity.OrganizationID == organizationID && validGeneratedID(entity.ID, "entity") &&
		validEntityType(entity.EntityType) && validHash(entity.CanonicalKeyHash) &&
		(entity.DisplayNameHash == "" || validHash(entity.DisplayNameHash)) &&
		validProvenance(entity.SourceProvenance) && validAttributes(entity.AttributesJSON)
}

func validRelation(relation Relation, organizationID string) bool {
	return relation.OrganizationID == organizationID && validGeneratedID(relation.ID, "relation") &&
		validGeneratedID(relation.SubjectEntityID, "entity") && validGeneratedID(relation.ObjectEntityID, "entity") &&
		validPredicate(relation.Predicate) && (relation.SubjectEntityID != relation.ObjectEntityID || strings.HasPrefix(relation.Predicate, "self.")) &&
		relation.Confidence >= 0 && relation.Confidence <= 1 &&
		validProvenance(relation.SourceProvenance) && validAttributes(relation.AttributesJSON)
}

func validSemanticTerm(term SemanticTerm, organizationID string) bool {
	return term.OrganizationID == organizationID && validGeneratedID(term.ID, "term") &&
		validGeneratedID(term.CanonicalEntityID, "entity") &&
		(term.TermKind == "CANONICAL" || term.TermKind == "SYNONYM" || term.TermKind == "ABBREVIATION" || term.TermKind == "CONTEXT") &&
		languagePattern.MatchString(term.Language) && validHash(term.TermHash) &&
		(term.ContextHash == "" || validHash(term.ContextHash)) && term.Confidence >= 0 && term.Confidence <= 1 &&
		validProvenance(term.SourceProvenance) && validAttributes(term.AttributesJSON)
}

func validProvenance(provenance SourceProvenance) bool {
	return validOpaque(provenance.WorkspaceID) && provenance.WorkspaceRevision >= 1 && provenance.WorkspaceRevision <= maximumGeneration &&
		validOpaque(provenance.SourceScopeID) && provenance.SourceScopeRevision >= 1 && provenance.SourceScopeRevision <= maximumGeneration &&
		validOpaque(provenance.SourceObjectID) && validOpaque(provenance.SourceVersionID) && validOpaque(provenance.EvidenceFragmentID) &&
		!provenance.ObservedAt.IsZero() && !provenance.FreshnessAt.IsZero()
}

func validEntityType(value string) bool {
	switch value {
	case "DOCUMENT", "EMAIL", "GIT_COMMIT", "CODE_SYMBOL", "SQL_BUSINESS_OBJECT", "PERSON", "PROCESS", "CONTROL", "TERM", "OTHER":
		return true
	default:
		return false
	}
}

func validGeneratedID(value, prefix string) bool {
	return generatedIDPattern.MatchString(value) && strings.HasPrefix(value, prefix+"_")
}

func validPredicate(value string) bool { return predicatePattern.MatchString(value) }

func validHash(value string) bool {
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

func validAttributes(value []byte) bool {
	if len(value) == 0 || len(value) > 65536 || !utf8.Valid(value) {
		return false
	}
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return false
	}
	_, object := decoded.(map[string]any)
	return object
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

func nullableHash(value string) any {
	if value == "" {
		return nil
	}
	return value
}
