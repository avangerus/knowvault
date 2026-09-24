// Package workspacecontext models the workspace-model-context-v1 document
// (ADR-0098, S2-MODEL-CONTEXT-DESIGN.md): a workspace's explicit description,
// answer rules, glossary and source/table/column notes.
//
// This package is deliberately pure: it opens no PostgreSQL connection and
// serves no HTTP route. Validation, canonical hashing, model-facing
// rendering and question-text term matching are all testable without a
// database or a network call. Persistence and REST (workspacecontext/store.go,
// workspaceapi), chat delivery (question/tool_loop.go), MCP delivery
// (workspacetools) and the deterministic proposer all build on the types and
// pure functions declared here; the Reader, RunObserver and ProposalService
// interfaces fix the shape those boundaries agree on without this package
// importing any of them.
//
// The document itself is never evidence and never changes the tool catalog,
// read-only transactions or authorization (ADR-0098 decision 3); this
// package only shapes and bounds its content, in line with the security
// invariants in S2-MODEL-CONTEXT-DESIGN.md.
package workspacecontext

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const documentSchemaVersion = "workspace-model-context-v1"

// Bounds from S2-MODEL-CONTEXT-DESIGN.md "Document `workspace-model-context-v1`".
const (
	maxDescriptionChars       = 4000
	maxRules                  = 30
	maxRuleTextChars          = 500
	maxGlossaryTerms          = 500
	maxTermChars              = 80
	maxSynonyms               = 20
	maxDefinitionChars        = 1000
	maxDataLocations          = 5
	maxHintChars              = 200
	maxSourceDescriptionChars = 2000
	maxTableNoteChars         = 1000
	maxColumnNoteChars        = 500

	// maxDocumentBytes is migration 000112's document jsonb bound: "at most
	// 256 KiB". It is measured on the canonical JSON bytes Hash also hashes.
	maxDocumentBytes = 256 * 1024

	// The following bounds are not individually stated by the design. They
	// are defensive caps only, sized well above any plausible workspace, so
	// that Validate always terminates in bounded memory before the 256 KiB
	// whole-document cap (which is the real, product-specified limit) is
	// reached. Being registered relations/columns known to the caller, the
	// effective limit on sources/tables/columns is the workspace's own
	// registered projection count, not these numbers.
	maxSynonymChars    = maxTermChars
	maxSources         = maxGlossaryTerms
	maxTablesPerSource = 2000
	maxColumnsPerTable = 2000

	// maxIdentifierChars bounds a source_connection_id, relation or column
	// name. These are references to server-registered identifiers, not free
	// text; the design gives no explicit bound, so this mirrors the general
	// identifier bound used elsewhere in the codebase (e.g.
	// internal/workspace.validID's sibling constants).
	maxIdentifierChars = 256

	// rulePrefix and termPrefix are the internal/source/ids.New prefixes the
	// store (card A) mints rule and glossary-term ids with. Validate checks
	// an id already carries the matching prefix and ULID shape; it never
	// mints one itself.
	rulePrefix = "rule"
	termPrefix = "term"
)

// assignedIDPattern is internal/source/ids.New's exact output shape
// (typed-prefix Crockford-base32 ULID: `^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$`).
// It is duplicated here, rather than imported, so this package stays free of
// any dependency beyond validating the shape it must enforce.
var assignedIDPattern = regexp.MustCompile(`^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// ErrorCode is content-free and safe for HTTP/MCP mapping, logs and audit
// metadata: workspace context text may itself be sensitive workspace
// configuration, so no cause is ever exposed through it.
type ErrorCode string

const (
	// CodeInvalidDocument covers every bound, NFC, control-character, id
	// format or duplicate-id violation.
	CodeInvalidDocument ErrorCode = "WORKSPACE_CONTEXT_DOCUMENT_INVALID"
	// CodeUnknownLocation is returned when a data_locations entry, source,
	// table or column note references a relation or column that is not in
	// the caller-supplied known projections (S1 invariant 4: notes refer
	// only to enabled sources and non-excluded columns).
	CodeUnknownLocation ErrorCode = "WORKSPACE_CONTEXT_LOCATION_UNKNOWN"
	// CodeHashFailed marks a canonicalization failure, which should be
	// unreachable for a document that already passed Validate.
	CodeHashFailed ErrorCode = "WORKSPACE_CONTEXT_HASH_FAILED"
)

// Error preserves a stable, content-free code. Callers use CodeOf.
type Error struct {
	code  ErrorCode
	cause error
}

func (err *Error) Error() string { return string(err.code) }
func (err *Error) Unwrap() error { return err.cause }

// CodeOf maps any error to a safe, stable workspacecontext code.
func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeInvalidDocument
}

// Rule is one answer-shaping rule. Its id is server-assigned
// (internal/source/ids.New("rule")).
type Rule struct {
	ID   string
	Text string
}

// DataLocation points a glossary term at where it lives in a source. Column
// is optional: empty means the whole relation, per S2-MODEL-CONTEXT-DESIGN.md.
type DataLocation struct {
	SourceConnectionID string
	Relation           string
	Column             string
	Hint               string
}

// Term is one glossary entry. Its id is server-assigned
// (internal/source/ids.New("term")).
type Term struct {
	ID            string
	Term          string
	Synonyms      []string
	Definition    string
	DataLocations []DataLocation
}

// Column is one column note within a Table.
type Column struct {
	Name string
	Note string
}

// Table is one relation's notes within a Source, plus its column notes.
type Table struct {
	Relation string
	Note     string
	Columns  []Column
}

// Source is one enabled source connection's description and table/column
// notes.
type Source struct {
	SourceConnectionID string
	Description        string
	Tables             []Table
}

// Document is the full workspace-model-context-v1 content. It carries no
// version, content hash or workspace identity of its own: those are
// version-row metadata the store (card A) owns, projected here as Version.
type Document struct {
	Description string
	Rules       []Rule
	Glossary    []Term
	Sources     []Source
}

// KnownProjection is one relation Validate accepts as a data_locations or
// source-note target: an enabled source's registered projection in this
// workspace, already narrowed by any S1 column exclusion (an excluded
// column is simply absent from Columns). The caller (the store) resolves
// these from the same source-registration authority the rest of the product
// reads; Validate itself never queries a source.
type KnownProjection struct {
	SourceConnectionID string
	Relation           string
	Columns            []string
}

// Validate normalizes doc to NFC and enforces every bound, control-character
// and server-assigned-id rule in S2-MODEL-CONTEXT-DESIGN.md, plus the
// invariant that every data_locations entry, source, table and column
// references a relation/column present in knownProjections (an enabled,
// non-excluded relation or column). It returns a private normalized copy;
// the supplied doc and its slices are never mutated or retained.
func Validate(doc Document, knownProjections []KnownProjection) (Document, error) {
	normalized := normalizeForHash(doc)
	if err := validateDocument(normalized, knownProjections); err != nil {
		return Document{}, err
	}
	return normalized, nil
}

func validateDocument(doc Document, knownProjections []KnownProjection) error {
	if !validText(doc.Description, 0, maxDescriptionChars) {
		return &Error{code: CodeInvalidDocument}
	}

	if len(doc.Rules) > maxRules {
		return &Error{code: CodeInvalidDocument}
	}
	ruleIDs := make(map[string]bool, len(doc.Rules))
	for _, rule := range doc.Rules {
		if !validAssignedID(rulePrefix, rule.ID) || ruleIDs[rule.ID] {
			return &Error{code: CodeInvalidDocument}
		}
		ruleIDs[rule.ID] = true
		if !validText(rule.Text, 1, maxRuleTextChars) {
			return &Error{code: CodeInvalidDocument}
		}
	}

	if len(doc.Glossary) > maxGlossaryTerms {
		return &Error{code: CodeInvalidDocument}
	}
	index := newProjectionIndex(knownProjections)
	termIDs := make(map[string]bool, len(doc.Glossary))
	for _, term := range doc.Glossary {
		if err := validateTerm(term, index, termIDs); err != nil {
			return err
		}
	}

	if len(doc.Sources) > maxSources {
		return &Error{code: CodeInvalidDocument}
	}
	sourceIDs := make(map[string]bool, len(doc.Sources))
	for _, source := range doc.Sources {
		if err := validateSource(source, index, sourceIDs); err != nil {
			return err
		}
	}

	canonical, err := canonicalBytesOf(doc)
	if err != nil {
		return &Error{code: CodeHashFailed, cause: err}
	}
	if len(canonical) > maxDocumentBytes {
		return &Error{code: CodeInvalidDocument}
	}
	return nil
}

func validateTerm(term Term, index projectionIndex, termIDs map[string]bool) error {
	if !validAssignedID(termPrefix, term.ID) || termIDs[term.ID] {
		return &Error{code: CodeInvalidDocument}
	}
	termIDs[term.ID] = true
	if !validText(term.Term, 1, maxTermChars) {
		return &Error{code: CodeInvalidDocument}
	}
	if len(term.Synonyms) > maxSynonyms {
		return &Error{code: CodeInvalidDocument}
	}
	for _, synonym := range term.Synonyms {
		if !validText(synonym, 1, maxSynonymChars) {
			return &Error{code: CodeInvalidDocument}
		}
	}
	if !validText(term.Definition, 0, maxDefinitionChars) {
		return &Error{code: CodeInvalidDocument}
	}
	if len(term.DataLocations) > maxDataLocations {
		return &Error{code: CodeInvalidDocument}
	}
	for _, location := range term.DataLocations {
		if err := validateLocation(location, index); err != nil {
			return err
		}
	}
	return nil
}

func validateLocation(location DataLocation, index projectionIndex) error {
	if !validIdentifier(location.SourceConnectionID, maxIdentifierChars) ||
		!validIdentifier(location.Relation, maxIdentifierChars) {
		return &Error{code: CodeInvalidDocument}
	}
	if location.Column != "" && !validIdentifier(location.Column, maxIdentifierChars) {
		return &Error{code: CodeInvalidDocument}
	}
	if !validText(location.Hint, 0, maxHintChars) {
		return &Error{code: CodeInvalidDocument}
	}
	if location.Column == "" {
		if !index.hasRelation(location.SourceConnectionID, location.Relation) {
			return &Error{code: CodeUnknownLocation}
		}
		return nil
	}
	if !index.hasColumn(location.SourceConnectionID, location.Relation, location.Column) {
		return &Error{code: CodeUnknownLocation}
	}
	return nil
}

func validateSource(source Source, index projectionIndex, sourceIDs map[string]bool) error {
	if !validIdentifier(source.SourceConnectionID, maxIdentifierChars) || sourceIDs[source.SourceConnectionID] {
		return &Error{code: CodeInvalidDocument}
	}
	sourceIDs[source.SourceConnectionID] = true
	if !index.hasSource(source.SourceConnectionID) {
		return &Error{code: CodeUnknownLocation}
	}
	if !validText(source.Description, 0, maxSourceDescriptionChars) {
		return &Error{code: CodeInvalidDocument}
	}
	if len(source.Tables) > maxTablesPerSource {
		return &Error{code: CodeInvalidDocument}
	}
	tableRelations := make(map[string]bool, len(source.Tables))
	for _, table := range source.Tables {
		if !validIdentifier(table.Relation, maxIdentifierChars) || tableRelations[table.Relation] {
			return &Error{code: CodeInvalidDocument}
		}
		tableRelations[table.Relation] = true
		if !index.hasRelation(source.SourceConnectionID, table.Relation) {
			return &Error{code: CodeUnknownLocation}
		}
		if !validText(table.Note, 0, maxTableNoteChars) {
			return &Error{code: CodeInvalidDocument}
		}
		if len(table.Columns) > maxColumnsPerTable {
			return &Error{code: CodeInvalidDocument}
		}
		columnNames := make(map[string]bool, len(table.Columns))
		for _, column := range table.Columns {
			if !validIdentifier(column.Name, maxIdentifierChars) || columnNames[column.Name] {
				return &Error{code: CodeInvalidDocument}
			}
			columnNames[column.Name] = true
			if !index.hasColumn(source.SourceConnectionID, table.Relation, column.Name) {
				return &Error{code: CodeUnknownLocation}
			}
			if !validText(column.Note, 0, maxColumnNoteChars) {
				return &Error{code: CodeInvalidDocument}
			}
		}
	}
	return nil
}

// projectionIndex is knownProjections reshaped for O(1) membership checks.
type projectionIndex struct {
	relations map[string]map[string]map[string]bool // connection -> relation -> column -> present
}

func newProjectionIndex(known []KnownProjection) projectionIndex {
	index := projectionIndex{relations: make(map[string]map[string]map[string]bool, len(known))}
	for _, projection := range known {
		connection := norm.NFC.String(projection.SourceConnectionID)
		relation := norm.NFC.String(projection.Relation)
		if connection == "" || relation == "" {
			continue
		}
		byRelation, ok := index.relations[connection]
		if !ok {
			byRelation = make(map[string]map[string]bool)
			index.relations[connection] = byRelation
		}
		columns, ok := byRelation[relation]
		if !ok {
			columns = make(map[string]bool, len(projection.Columns))
			byRelation[relation] = columns
		}
		for _, column := range projection.Columns {
			columns[norm.NFC.String(column)] = true
		}
	}
	return index
}

func (index projectionIndex) hasSource(connectionID string) bool {
	_, ok := index.relations[connectionID]
	return ok
}

func (index projectionIndex) hasRelation(connectionID, relation string) bool {
	byRelation, ok := index.relations[connectionID]
	if !ok {
		return false
	}
	_, ok = byRelation[relation]
	return ok
}

func (index projectionIndex) hasColumn(connectionID, relation, column string) bool {
	byRelation, ok := index.relations[connectionID]
	if !ok {
		return false
	}
	columns, ok := byRelation[relation]
	if !ok {
		return false
	}
	return columns[column]
}

// normalizeForHash returns a private copy of doc with every string field NFC
// normalized. It performs no bounds checking: Validate layers that on top,
// and Hash/Render use it directly so a document that only differs in
// Unicode normalization form hashes and renders identically.
func normalizeForHash(doc Document) Document {
	normalized := Document{Description: norm.NFC.String(doc.Description)}

	normalized.Rules = make([]Rule, len(doc.Rules))
	for i, rule := range doc.Rules {
		normalized.Rules[i] = Rule{ID: rule.ID, Text: norm.NFC.String(rule.Text)}
	}

	normalized.Glossary = make([]Term, len(doc.Glossary))
	for i, term := range doc.Glossary {
		synonyms := make([]string, len(term.Synonyms))
		for j, synonym := range term.Synonyms {
			synonyms[j] = norm.NFC.String(synonym)
		}
		locations := make([]DataLocation, len(term.DataLocations))
		for j, location := range term.DataLocations {
			locations[j] = DataLocation{
				SourceConnectionID: norm.NFC.String(location.SourceConnectionID),
				Relation:           norm.NFC.String(location.Relation),
				Column:             norm.NFC.String(location.Column),
				Hint:               norm.NFC.String(location.Hint),
			}
		}
		normalized.Glossary[i] = Term{
			ID: term.ID, Term: norm.NFC.String(term.Term), Synonyms: synonyms,
			Definition: norm.NFC.String(term.Definition), DataLocations: locations,
		}
	}

	normalized.Sources = make([]Source, len(doc.Sources))
	for i, source := range doc.Sources {
		tables := make([]Table, len(source.Tables))
		for j, table := range source.Tables {
			columns := make([]Column, len(table.Columns))
			for k, column := range table.Columns {
				columns[k] = Column{Name: norm.NFC.String(column.Name), Note: norm.NFC.String(column.Note)}
			}
			tables[j] = Table{Relation: norm.NFC.String(table.Relation), Note: norm.NFC.String(table.Note), Columns: columns}
		}
		normalized.Sources[i] = Source{
			SourceConnectionID: norm.NFC.String(source.SourceConnectionID),
			Description:        norm.NFC.String(source.Description),
			Tables:             tables,
		}
	}
	return normalized
}

func validAssignedID(prefix, id string) bool {
	return strings.HasPrefix(id, prefix+"_") && assignedIDPattern.MatchString(id)
}

// validText bounds free-form content (description, rule text, definitions,
// notes, hints, term names and synonyms): a rune-count range, valid UTF-8
// and no control character (matching internal/workspace's own hasControl
// range, C0 plus C1).
func validText(value string, minChars, maxChars int) bool {
	count := utf8.RuneCountInString(value)
	if count < minChars || count > maxChars {
		return false
	}
	return utf8.ValidString(value) && !hasControl(value)
}

// validIdentifier additionally requires no leading/trailing whitespace, for
// values that must equal an exact registered identifier
// (source_connection_id, relation, column name).
func validIdentifier(value string, maxChars int) bool {
	return validText(value, 1, maxChars) && strings.TrimSpace(value) == value
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}
