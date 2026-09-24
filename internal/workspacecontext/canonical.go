package workspacecontext

import (
	"knowvault.local/verified-workspace/internal/source/canon"
)

// canonicalDataLocation, canonicalTerm, ... mirror Document's exported types
// with explicit json tags for the pinned RFC 8785/JCS canonicalizer
// (internal/source/canon, docs/CANONICALIZATION.md json-v1). Field order here
// is irrelevant to the resulting hash: JCS sorts object member names.
type canonicalDataLocation struct {
	SourceConnectionID string `json:"source_connection_id"`
	Relation           string `json:"relation"`
	Column             string `json:"column"`
	Hint               string `json:"hint"`
}

type canonicalTerm struct {
	ID            string                  `json:"id"`
	Term          string                  `json:"term"`
	Synonyms      []string                `json:"synonyms"`
	Definition    string                  `json:"definition"`
	DataLocations []canonicalDataLocation `json:"data_locations"`
}

type canonicalRule struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type canonicalColumn struct {
	Name string `json:"name"`
	Note string `json:"note"`
}

type canonicalTable struct {
	Relation string            `json:"relation"`
	Note     string            `json:"note"`
	Columns  []canonicalColumn `json:"columns"`
}

type canonicalSource struct {
	SourceConnectionID string           `json:"source_connection_id"`
	Description        string           `json:"description"`
	Tables             []canonicalTable `json:"tables"`
}

type canonicalDocument struct {
	SchemaVersion string            `json:"schema_version"`
	Description   string            `json:"description"`
	Rules         []canonicalRule   `json:"rules"`
	Glossary      []canonicalTerm   `json:"glossary"`
	Sources       []canonicalSource `json:"sources"`
}

// canonicalBytesOf projects doc (already NFC-normalized; see
// normalizeForHash) into workspace-model-context-v1's canonical JCS bytes.
// Array order is preserved, never sorted: rules, glossary and sources are
// ordered content, not sets.
func canonicalBytesOf(doc Document) ([]byte, error) {
	rules := make([]canonicalRule, len(doc.Rules))
	for i, rule := range doc.Rules {
		rules[i] = canonicalRule{ID: rule.ID, Text: rule.Text}
	}

	glossary := make([]canonicalTerm, len(doc.Glossary))
	for i, term := range doc.Glossary {
		synonyms := make([]string, len(term.Synonyms))
		copy(synonyms, term.Synonyms)
		locations := make([]canonicalDataLocation, len(term.DataLocations))
		for j, location := range term.DataLocations {
			locations[j] = canonicalDataLocation{
				SourceConnectionID: location.SourceConnectionID, Relation: location.Relation,
				Column: location.Column, Hint: location.Hint,
			}
		}
		glossary[i] = canonicalTerm{
			ID: term.ID, Term: term.Term, Synonyms: synonyms,
			Definition: term.Definition, DataLocations: locations,
		}
	}

	sources := make([]canonicalSource, len(doc.Sources))
	for i, source := range doc.Sources {
		tables := make([]canonicalTable, len(source.Tables))
		for j, table := range source.Tables {
			columns := make([]canonicalColumn, len(table.Columns))
			for k, column := range table.Columns {
				columns[k] = canonicalColumn{Name: column.Name, Note: column.Note}
			}
			tables[j] = canonicalTable{Relation: table.Relation, Note: table.Note, Columns: columns}
		}
		sources[i] = canonicalSource{
			SourceConnectionID: source.SourceConnectionID, Description: source.Description, Tables: tables,
		}
	}

	projection := canonicalDocument{
		SchemaVersion: documentSchemaVersion, Description: doc.Description,
		Rules: rules, Glossary: glossary, Sources: sources,
	}
	return canon.CanonicalJSON(projection)
}

// Hash returns workspace-model-context-v1's deterministic sha256 content
// hash: "sha256:" followed by lowercase hex, exactly canon.Hash's shape
// (docs/CANONICALIZATION.md json-v1). It NFC-normalizes doc internally
// (normalizeForHash), so two documents differing only in Unicode
// normalization form hash identically; it does not otherwise validate doc,
// so callers that need bounds/reference enforcement call Validate first.
func Hash(doc Document) (string, error) {
	canonical, err := canonicalBytesOf(normalizeForHash(doc))
	if err != nil {
		return "", &Error{code: CodeHashFailed, cause: err}
	}
	return canon.Hash(canonical), nil
}
