package knowledgegraph

import (
	"context"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	maximumResolveTerms = 32
	maximumGraphHits    = 128
)

// ResolveQuery is a server-owned semantic lookup. Terms are normalized and
// hashed before they reach SQL; the database returns only canonical IDs and
// provenance, never the source text or a caller-provided predicate.
type ResolveQuery struct {
	WorkspaceID string
	Terms       []string
	Limit       int
}

type EntityMatch struct {
	EntityID           string
	EntityType         string
	TermKind           string
	Language           string
	TermHash           string
	Confidence         float64
	SourceObjectID     string
	EvidenceFragmentID string
	ExtractionID       string
	SourceVersionID    string
	ContentHash        string
	EvidenceTextHash   string
	AnchorHash         string
}

type RelationMatch struct {
	RelationID                string
	SubjectEntityID           string
	Predicate                 string
	ObjectEntityID            string
	Confidence                float64
	SourceObjectID            string
	EvidenceFragmentID        string
	ExtractionID              string
	SourceVersionID           string
	ContentHash               string
	EvidenceTextHash          string
	AnchorHash                string
	SubjectSourceObjectID     string
	SubjectSourceVersionID    string
	SubjectEvidenceFragmentID string
	ObjectSourceObjectID      string
	ObjectSourceVersionID     string
	ObjectEvidenceFragmentID  string
}

// TermResolution is the server-owned result of resolving a bounded set of
// opaque semantic terms. The hashes are safe to return to callers; plaintext
// catalog terms never leave the query boundary.
type TermResolution struct {
	Matches             []EntityMatch
	AmbiguousTermHashes []string
	TruncatedTermHashes []string
}

func (resolution TermResolution) Incomplete() bool {
	return len(resolution.AmbiguousTermHashes) > 0 || len(resolution.TruncatedTermHashes) > 0
}

// ResolveTerms performs an app-authorized semantic catalog lookup. The caller
// must execute it inside a transaction whose app.current_* context is already
// bound by database.Store; forced RLS then applies workspace membership,
// source-binding, membership revocation and retention checks.
func (repository *Repository) ResolveTerms(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, query ResolveQuery) ([]EntityMatch, error) {
	resolution, err := repository.ResolveTermsDetailed(ctx, transaction, access, query)
	if err != nil {
		return nil, err
	}
	return resolution.Matches, nil
}

// ResolveTermsDetailed performs the same bounded lookup as ResolveTerms and
// additionally records authorization-filtered ambiguity and page truncation.
// The count query intentionally runs before the page query: a second visible
// entity must not be hidden merely because the caller requested a one-row
// page. Only term hashes cross this boundary; plaintext catalog terms never
// leave the server-owned query layer.
func (repository *Repository) ResolveTermsDetailed(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, query ResolveQuery) (TermResolution, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		query.WorkspaceID == "" || !validOpaque(query.WorkspaceID) || len(query.Terms) == 0 || len(query.Terms) > maximumResolveTerms {
		return TermResolution{}, &Error{code: CodeInvalid}
	}
	limit := query.Limit
	if limit == 0 {
		limit = maximumGraphHits
	}
	if limit < 1 || limit > maximumGraphHits {
		return TermResolution{}, &Error{code: CodeInvalid}
	}
	hashes := make([]string, 0, len(query.Terms))
	seen := make(map[string]struct{}, len(query.Terms))
	for _, term := range query.Terms {
		hash, err := SemanticTermHash(term)
		if err != nil {
			return TermResolution{}, &Error{code: CodeInvalid}
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		return TermResolution{}, &Error{code: CodeInvalid}
	}

	type termCounts struct {
		matches        int64
		strongEntities int64
	}
	counts := make(map[string]termCounts, len(hashes))
	countRows, err := transaction.Query(ctx, `
		SELECT term.term_hash,
		       count(*) AS match_count,
		       count(DISTINCT term.canonical_entity_id) FILTER
		         (WHERE term.term_kind IN ('CANONICAL', 'SYNONYM', 'ABBREVIATION')) AS strong_entity_count
		  FROM public.semantic_term term
		  JOIN public.canonical_entity entity
		    ON entity.organization_id = term.organization_id
		   AND entity.id = term.canonical_entity_id
		  JOIN public.source_version version
		    ON version.organization_id = term.organization_id
		   AND version.id = term.source_version_id
		   AND version.source_object_id = term.source_object_id
		  JOIN public.evidence_fragment fragment
		    ON fragment.organization_id = term.organization_id
		   AND fragment.id = term.evidence_fragment_id
		   AND fragment.source_version_id = term.source_version_id
		 WHERE term.organization_id = $1
		   AND term.workspace_id = $2
		   AND term.term_hash = ANY($3::text[])
		 GROUP BY term.term_hash
		 ORDER BY term.term_hash`, access.OrganizationID, query.WorkspaceID, hashes)
	if err != nil {
		return TermResolution{}, &Error{code: CodePersistence, cause: err}
	}
	for countRows.Next() {
		var hash string
		var count termCounts
		if err := countRows.Scan(&hash, &count.matches, &count.strongEntities); err != nil {
			countRows.Close()
			return TermResolution{}, &Error{code: CodePersistence, cause: err}
		}
		counts[hash] = count
	}
	if err := countRows.Err(); err != nil {
		countRows.Close()
		return TermResolution{}, &Error{code: CodePersistence, cause: err}
	}
	countRows.Close()
	resolution := TermResolution{}
	for _, hash := range hashes {
		count := counts[hash]
		if count.strongEntities > 1 {
			resolution.AmbiguousTermHashes = append(resolution.AmbiguousTermHashes, hash)
		}
	}

	rows, err := transaction.Query(ctx, `
		SELECT term.canonical_entity_id, entity.entity_type, term.term_kind,
		       term.language, term.term_hash, term.confidence, entity.source_object_id,
		       term.evidence_fragment_id, fragment.extraction_id, term.source_version_id,
		       version.content_hash, fragment.text_hash, fragment.anchor_hash
		  FROM public.semantic_term term
		  JOIN public.canonical_entity entity
		    ON entity.organization_id = term.organization_id
		   AND entity.id = term.canonical_entity_id
		  JOIN public.source_version version
		    ON version.organization_id = term.organization_id
		   AND version.id = term.source_version_id
		   AND version.source_object_id = term.source_object_id
		  JOIN public.evidence_fragment fragment
		    ON fragment.organization_id = term.organization_id
		   AND fragment.id = term.evidence_fragment_id
		   AND fragment.source_version_id = term.source_version_id
		 WHERE term.organization_id = $1
		   AND term.workspace_id = $2
		   AND term.term_hash = ANY($3::text[])
		 ORDER BY term.confidence DESC, term.id
		 LIMIT $4`, access.OrganizationID, query.WorkspaceID, hashes, limit)
	if err != nil {
		return TermResolution{}, &Error{code: CodePersistence, cause: err}
	}
	defer rows.Close()
	resolution.Matches = make([]EntityMatch, 0, limit)
	returnedByHash := make(map[string]int64, len(hashes))
	for rows.Next() {
		var match EntityMatch
		if err := rows.Scan(&match.EntityID, &match.EntityType, &match.TermKind,
			&match.Language, &match.TermHash, &match.Confidence, &match.SourceObjectID,
			&match.EvidenceFragmentID, &match.ExtractionID, &match.SourceVersionID, &match.ContentHash,
			&match.EvidenceTextHash, &match.AnchorHash); err != nil {
			return TermResolution{}, &Error{code: CodePersistence, cause: err}
		}
		resolution.Matches = append(resolution.Matches, match)
		returnedByHash[match.TermHash]++
	}
	if err := rows.Err(); err != nil {
		return TermResolution{}, &Error{code: CodePersistence, cause: err}
	}
	for _, hash := range hashes {
		count := counts[hash]
		if count.matches > returnedByHash[hash] {
			resolution.TruncatedTermHashes = append(resolution.TruncatedTermHashes, hash)
		}
	}
	return resolution, nil
}

// TraverseRelations returns visible edges touching one of the resolved entity
// IDs. It is intentionally a separate typed call: relationship expansion is
// bounded and post-authorized by the same graph row policy, so a caller cannot
// smuggle an arbitrary graph query or cross-workspace traversal.
func (repository *Repository) TraverseRelations(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, workspaceID string, entityIDs []string, limit int) ([]RelationMatch, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(workspaceID) || len(entityIDs) == 0 || len(entityIDs) > maximumGraphHits {
		return nil, &Error{code: CodeInvalid}
	}
	if limit == 0 {
		limit = maximumGraphHits
	}
	if limit < 1 || limit > maximumGraphHits {
		return nil, &Error{code: CodeInvalid}
	}
	seen := make(map[string]struct{}, len(entityIDs))
	for _, entityID := range entityIDs {
		if !validGeneratedID(entityID, "entity") {
			return nil, &Error{code: CodeInvalid}
		}
		seen[entityID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for entityID := range seen {
		ids = append(ids, entityID)
	}
	rows, err := transaction.Query(ctx, `
		SELECT relation.id, relation.subject_entity_id, relation.predicate, relation.object_entity_id,
		       relation.confidence, relation.source_object_id, relation.evidence_fragment_id,
		       fragment.extraction_id, relation.source_version_id, version.content_hash, fragment.text_hash,
		       fragment.anchor_hash, subject_entity.source_object_id,
		       subject_entity.source_version_id, subject_entity.evidence_fragment_id,
		       object_entity.source_object_id, object_entity.source_version_id,
		       object_entity.evidence_fragment_id
		  FROM public.entity_relation AS relation
		  JOIN public.canonical_entity AS subject_entity
		    ON subject_entity.organization_id = relation.organization_id
		   AND subject_entity.workspace_id = relation.workspace_id
		   AND subject_entity.id = relation.subject_entity_id
		  JOIN public.canonical_entity AS object_entity
		    ON object_entity.organization_id = relation.organization_id
		   AND object_entity.workspace_id = relation.workspace_id
		   AND object_entity.id = relation.object_entity_id
		  JOIN public.source_version version
		    ON version.organization_id = relation.organization_id
		   AND version.id = relation.source_version_id
		   AND version.source_object_id = relation.source_object_id
		  JOIN public.evidence_fragment fragment
		    ON fragment.organization_id = relation.organization_id
		   AND fragment.id = relation.evidence_fragment_id
		   AND fragment.source_version_id = relation.source_version_id
		 WHERE relation.organization_id = $1
		   AND relation.workspace_id = $2
		   AND (relation.subject_entity_id = ANY($3::text[]) OR relation.object_entity_id = ANY($3::text[]))
		 ORDER BY relation.confidence DESC, relation.id
		 LIMIT $4`, access.OrganizationID, workspaceID, ids, limit)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	defer rows.Close()
	result := make([]RelationMatch, 0, limit)
	for rows.Next() {
		var match RelationMatch
		if err := rows.Scan(&match.RelationID, &match.SubjectEntityID, &match.Predicate,
			&match.ObjectEntityID, &match.Confidence, &match.SourceObjectID,
			&match.EvidenceFragmentID, &match.ExtractionID, &match.SourceVersionID, &match.ContentHash,
			&match.EvidenceTextHash, &match.AnchorHash, &match.SubjectSourceObjectID,
			&match.SubjectSourceVersionID, &match.SubjectEvidenceFragmentID,
			&match.ObjectSourceObjectID, &match.ObjectSourceVersionID,
			&match.ObjectEvidenceFragmentID); err != nil {
			return nil, &Error{code: CodePersistence, cause: err}
		}
		result = append(result, match)
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	return result, nil
}

// SemanticTermHash is the one catalog key normalization. It is deliberately
// a public helper so ingestion and query planners cannot silently disagree on
// Unicode/newline normalization; no plaintext term is persisted by this
// package.
func SemanticTermHash(term string) (string, error) {
	term = strings.ToLower(strings.TrimSpace(term))
	if term == "" || !validOpaque(term) {
		return "", &Error{code: CodeInvalid}
	}
	canonical, err := canon.Canonicalize([]byte(term))
	if err != nil || len(canonical) == 0 {
		return "", &Error{code: CodeInvalid, cause: err}
	}
	return canon.Hash(canonical), nil
}
