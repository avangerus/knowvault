package artifactcrypto

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// AADSchemaVersion is the only accepted encrypted-artifact AAD schema version.
// It matches architecture/contracts/encrypted-artifact-aad.schema.json and the
// accepted artifact AAD schema default enforced by the persistence boundary.
const AADSchemaVersion = "encrypted-artifact-aad-v1"

// OwnerField is the closed, typed selector for an encrypted-artifact owner. A
// caller chooses exactly one of the accepted selectors; it can never pass an
// arbitrary owner_table, owner_column, resource_type or field string. The zero
// value is deliberately invalid so an unset selector fails closed.
type OwnerField uint8

const (
	ownerFieldInvalid OwnerField = iota
	ExternalIdentitySubject
	SourceConnectionTrustConfig
	SourceDiscoveryResultMetadata
	SourceScopeIdentity
	SourceScopeDisplayMetadata
	SourceScopeConfig
	SourceObjectExternalID
	SourceObjectCanonicalLocator
	SourceObjectTitle
	ACLPrincipalTokens
	EvidenceNormalizedText
	EvidenceAnchor
	EvidenceMetadata
	SearchChunkText
	QuestionText
	AnswerMarkdown
	AnswerStructured
	QuestionManifestContent
	AuthorizedCandidateSet
	ModelExecutionPlan
	ClaimText
	DeterministicValidationOutput
	CitationCitedExcerpt
	CitationAnchor
	CitationDeepLink
	ModelRunInput
	ModelRunOutput
	QuestionFeedbackComment
	ownerFieldSentinel
)

// ownerDefinition binds one typed selector to its exact database owner tuple.
// The four string fields are the third machine-checked source of the closed
// owner inventory; the architecture parity gate proves this slice is set-equal
// to the AAD schema, the SQL owner-validation function and the documentation.
type ownerDefinition struct {
	field        OwnerField
	ownerTable   string
	ownerColumn  string
	resourceType string
	aadField     string
}

// ownerInventory is the closed 27-branch owner map. Each row is one exact
// (owner_table, owner_column, resource_type, field) tuple. Adding, removing or
// editing a row without the matching schema, SQL and documentation change is a
// parity-gate failure.
var ownerInventory = []ownerDefinition{
	{field: ExternalIdentitySubject, ownerTable: "external_identity", ownerColumn: "external_subject_artifact_id", resourceType: "EXTERNAL_IDENTITY", aadField: "SUBJECT"},
	{field: SourceConnectionTrustConfig, ownerTable: "source_connection_revision", ownerColumn: "trust_profile_artifact_id", resourceType: "SOURCE_TRUST_CONFIG", aadField: "TRUST_CONFIG"},
	{field: SourceDiscoveryResultMetadata, ownerTable: "source_discovery_result", ownerColumn: "metadata_artifact_id", resourceType: "SOURCE_DISCOVERY_RESULT", aadField: "DISCOVERY_METADATA"},
	{field: SourceScopeIdentity, ownerTable: "source_discovered_scope", ownerColumn: "identity_artifact_id", resourceType: "SOURCE_SCOPE_IDENTITY", aadField: "EXTERNAL_SCOPE_IDENTITY"},
	{field: SourceScopeDisplayMetadata, ownerTable: "source_discovered_scope", ownerColumn: "display_metadata_artifact_id", resourceType: "SOURCE_SCOPE_METADATA", aadField: "DISPLAY_METADATA"},
	{field: SourceScopeConfig, ownerTable: "source_scope_revision", ownerColumn: "scope_config_artifact_id", resourceType: "SOURCE_SCOPE_CONFIG", aadField: "SCOPE_CONFIG"},
	{field: SourceObjectExternalID, ownerTable: "source_object", ownerColumn: "external_object_id_artifact_id", resourceType: "SOURCE_OBJECT_ID", aadField: "EXTERNAL_OBJECT_ID"},
	{field: SourceObjectCanonicalLocator, ownerTable: "source_object", ownerColumn: "canonical_locator_artifact_id", resourceType: "SOURCE_LOCATOR", aadField: "CANONICAL_LOCATOR"},
	{field: SourceObjectTitle, ownerTable: "source_object", ownerColumn: "title_artifact_id", resourceType: "SOURCE_TITLE", aadField: "DISPLAY_TITLE"},
	{field: ACLPrincipalTokens, ownerTable: "acl_snapshot", ownerColumn: "principal_tokens_artifact_id", resourceType: "ACL_PRINCIPAL_SET", aadField: "PRINCIPAL_TOKENS"},
	{field: EvidenceNormalizedText, ownerTable: "evidence_fragment", ownerColumn: "normalized_text_artifact_id", resourceType: "EVIDENCE_TEXT", aadField: "NORMALIZED_TEXT"},
	{field: EvidenceAnchor, ownerTable: "evidence_fragment", ownerColumn: "anchor_artifact_id", resourceType: "EVIDENCE_ANCHOR", aadField: "CANONICAL_ANCHOR"},
	{field: EvidenceMetadata, ownerTable: "evidence_fragment", ownerColumn: "metadata_artifact_id", resourceType: "EVIDENCE_METADATA", aadField: "METADATA"},
	{field: SearchChunkText, ownerTable: "search_chunk", ownerColumn: "search_text_artifact_id", resourceType: "SEARCH_CHUNK_TEXT", aadField: "NORMALIZED_TEXT"},
	{field: QuestionText, ownerTable: "question_run", ownerColumn: "question_text_artifact_id", resourceType: "QUESTION_RUN", aadField: "QUESTION_TEXT"},
	{field: AnswerMarkdown, ownerTable: "question_run", ownerColumn: "answer_markdown_artifact_id", resourceType: "QUESTION_RUN", aadField: "ANSWER_MARKDOWN"},
	{field: AnswerStructured, ownerTable: "question_run", ownerColumn: "answer_structured_artifact_id", resourceType: "QUESTION_RUN", aadField: "ANSWER_STRUCTURED"},
	{field: QuestionManifestContent, ownerTable: "question_run", ownerColumn: "manifest_content_artifact_id", resourceType: "MANIFEST_CONTENT", aadField: "CANONICAL_BYTES"},
	{field: AuthorizedCandidateSet, ownerTable: "question_authorized_candidate_set", ownerColumn: "canonical_artifact_id", resourceType: "AUTHORIZED_CANDIDATE_SET", aadField: "CANONICAL_BYTES"},
	{field: ModelExecutionPlan, ownerTable: "question_model_execution_plan", ownerColumn: "canonical_artifact_id", resourceType: "MODEL_EXECUTION_PLAN", aadField: "CANONICAL_BYTES"},
	{field: ClaimText, ownerTable: "question_claim", ownerColumn: "text_artifact_id", resourceType: "CLAIM_TEXT", aadField: "CLAIM_TEXT"},
	{field: DeterministicValidationOutput, ownerTable: "claim_deterministic_validation_artifact", ownerColumn: "output_artifact_id", resourceType: "DETERMINISTIC_VALIDATION", aadField: "VALIDATION_OUTPUT"},
	{field: CitationCitedExcerpt, ownerTable: "question_citation", ownerColumn: "cited_excerpt_artifact_id", resourceType: "CITED_EXCERPT", aadField: "EXACT_TEXT"},
	{field: CitationAnchor, ownerTable: "question_citation", ownerColumn: "anchor_artifact_id", resourceType: "CITATION_ANCHOR", aadField: "CANONICAL_ANCHOR"},
	{field: CitationDeepLink, ownerTable: "question_citation", ownerColumn: "deep_link_artifact_id", resourceType: "SOURCE_DEEPLINK", aadField: "DEEPLINK"},
	{field: ModelRunInput, ownerTable: "model_run_artifact", ownerColumn: "input_artifact_id", resourceType: "MODEL_ARTIFACT", aadField: "CANONICAL_INPUT"},
	{field: ModelRunOutput, ownerTable: "model_run_artifact", ownerColumn: "output_artifact_id", resourceType: "MODEL_ARTIFACT", aadField: "CANONICAL_OUTPUT"},
	{field: QuestionFeedbackComment, ownerTable: "question_feedback", ownerColumn: "comment_artifact_id", resourceType: "QUESTION_FEEDBACK", aadField: "COMMENT_TEXT"},
}

type ownerTuple struct {
	ownerTable   string
	ownerColumn  string
	resourceType string
	field        string
}

// ownerByField and registryByTuple are the runtime lookups built once from
// ownerInventory. init fails closed (panics at package load) if the inventory
// drifts from the closed set of 27 typed selectors, so no deployment can start
// with a partial registry.
var (
	ownerByField    = buildOwnerRegistry()
	registryByTuple = buildTupleRegistry()
)

func buildTupleRegistry() map[ownerTuple]ownerDefinition {
	registry := make(map[ownerTuple]ownerDefinition, len(ownerInventory))
	for _, definition := range ownerInventory {
		tuple := ownerTuple{definition.ownerTable, definition.ownerColumn, definition.resourceType, definition.aadField}
		if _, exists := registry[tuple]; exists {
			panic("artifactcrypto: owner inventory has a duplicate tuple")
		}
		registry[tuple] = definition
	}
	return registry
}

func buildOwnerRegistry() map[OwnerField]ownerDefinition {
	expected := int(ownerFieldSentinel) - int(ownerFieldInvalid) - 1
	if len(ownerInventory) != expected {
		panic(fmt.Sprintf("artifactcrypto: owner inventory has %d rows, expected %d typed selectors", len(ownerInventory), expected))
	}
	registry := make(map[OwnerField]ownerDefinition, len(ownerInventory))
	for _, definition := range ownerInventory {
		if definition.field <= ownerFieldInvalid || definition.field >= ownerFieldSentinel {
			panic("artifactcrypto: owner inventory row has an out-of-range selector")
		}
		if _, exists := registry[definition.field]; exists {
			panic("artifactcrypto: owner inventory has a duplicate selector")
		}
		if definition.ownerTable == "" || definition.ownerColumn == "" || definition.resourceType == "" || definition.aadField == "" {
			panic("artifactcrypto: owner inventory row has an empty tuple component")
		}
		registry[definition.field] = definition
	}
	for selector := ownerFieldInvalid + 1; selector < ownerFieldSentinel; selector++ {
		if _, exists := registry[selector]; !exists {
			panic("artifactcrypto: owner inventory is missing a typed selector")
		}
	}
	return registry
}

// OwnerIdentity is the exact, trusted owner tuple for one encrypted artifact.
// It is constructed only from a typed selector plus the trusted tenant and
// owning-row resource id; owner_table, owner_column, resource_type and field
// are never caller-supplied strings.
type OwnerIdentity struct {
	organizationID string
	ownerTable     string
	ownerColumn    string
	resourceType   string
	resourceID     string
	field          string
}

func (OwnerIdentity) String() string   { return "artifactcrypto.OwnerIdentity{…}" }
func (OwnerIdentity) GoString() string { return "artifactcrypto.OwnerIdentity{…}" }

func (owner OwnerIdentity) OrganizationID() string { return owner.organizationID }
func (owner OwnerIdentity) OwnerTable() string     { return owner.ownerTable }
func (owner OwnerIdentity) OwnerColumn() string    { return owner.ownerColumn }
func (owner OwnerIdentity) ResourceType() string   { return owner.resourceType }
func (owner OwnerIdentity) ResourceID() string     { return owner.resourceID }
func (owner OwnerIdentity) Field() string          { return owner.field }

// IsOwnerField reports whether a selector is one of the closed accepted owner
// branches. The repository uses it to reject an unknown or zero selector.
func IsOwnerField(field OwnerField) bool {
	_, ok := ownerByField[field]
	return ok
}

// NewOwnerIdentity resolves a typed selector into the exact owner tuple. The
// only caller-provided values are the trusted tenant and the owning-row
// resource id; both are shape-validated. An unknown selector or malformed id
// fails closed.
func NewOwnerIdentity(field OwnerField, organizationID, resourceID string) (OwnerIdentity, error) {
	definition, ok := ownerByField[field]
	if !ok {
		return OwnerIdentity{}, ErrUnknownOwner
	}
	if !validIdentifier(organizationID, 128) || !validIdentifier(resourceID, 256) {
		return OwnerIdentity{}, ErrInvalidOwnerIdentity
	}
	return OwnerIdentity{
		organizationID: organizationID,
		ownerTable:     definition.ownerTable,
		ownerColumn:    definition.ownerColumn,
		resourceType:   definition.resourceType,
		resourceID:     resourceID,
		field:          definition.aadField,
	}, nil
}

// NewOwnerIdentityFromTuple resolves a database owner tuple — the exact
// (owner_table, owner_column, resource_type, field_name) columns returned by a
// persistence read — into a trusted OwnerIdentity. It is the inverse of
// NewOwnerIdentity for callers that only ever see stored columns, such as the
// rotation re-wrap handlers. The tuple must be one of the closed accepted owner
// definitions; an unregistered tuple or a malformed identity fails closed.
func NewOwnerIdentityFromTuple(ownerTable, ownerColumn, resourceType, field, organizationID, resourceID string) (OwnerIdentity, error) {
	definition, ok := registryByTuple[ownerTuple{ownerTable, ownerColumn, resourceType, field}]
	if !ok {
		return OwnerIdentity{}, ErrUnknownOwner
	}
	if !validIdentifier(organizationID, 128) || !validIdentifier(resourceID, 256) {
		return OwnerIdentity{}, ErrInvalidOwnerIdentity
	}
	return OwnerIdentity{
		organizationID: organizationID,
		ownerTable:     definition.ownerTable,
		ownerColumn:    definition.ownerColumn,
		resourceType:   definition.resourceType,
		resourceID:     resourceID,
		field:          definition.aadField,
	}, nil
}

// Valid reports whether the owner identity is well formed. The repository uses
// it to fail closed before touching the database.
func (owner OwnerIdentity) Valid() bool { return owner.valid() }

func (owner OwnerIdentity) valid() bool {
	if !validIdentifier(owner.organizationID, 128) || !validIdentifier(owner.resourceID, 256) ||
		owner.ownerTable == "" || owner.ownerColumn == "" || owner.resourceType == "" || owner.field == "" {
		return false
	}
	// The tuple must be one of the closed accepted owner definitions: a
	// hand-built OwnerIdentity with a plausible but unregistered tuple fails.
	definition, ok := registryByTuple[ownerTuple{owner.ownerTable, owner.ownerColumn, owner.resourceType, owner.field}]
	return ok && definition.field != ownerFieldInvalid
}

// validIdentifier mirrors the AAD schema pattern for organization_id and
// resource_id: bounded length, valid UTF-8, no leading/trailing whitespace and
// no control characters.
func validIdentifier(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}
