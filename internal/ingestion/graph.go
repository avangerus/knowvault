package ingestion

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

type graphTermInput struct {
	Label              string
	EvidenceFragmentID string
	TermKind           string
	ContextHash        string
}

type semanticAliasObservation struct {
	Label    string
	TermKind string
}

// Semantic markers are deliberately explicit. They recognise a bounded
// relation in trusted Evidence text, but never infer aliases from arbitrary
// co-occurrence. The parser resolves only the lexical segment immediately
// adjacent to a marker, requires both sides to be valid terms, and keeps the
// result tied to the caller's Evidence fragment. The captured values are
// later normalized and hashed by the same semantic-term boundary as all other
// catalog inputs.
var (
	semanticDefinitionMarkerPattern   = regexp.MustCompile("(?i)(?:means|is\\s+called|\u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442|\u043e\u0437\u043d\u0430\u0447\u0430\u044e\u0442|\u043d\u0430\u0437\u044b\u0432\u0430\u0435\u0442\u0441\u044f|\u043d\u0430\u0437\u044b\u0432\u0430\u044e\u0442\u0441\u044f|\u2014|\u2013)")
	semanticKnownAsMarkerPattern      = regexp.MustCompile("(?i)(?:is\\s+also\\s+known\\s+as|also\\s+known\\s+as|is\\s+also\\s+called|also\\s+called|aka|alias(?:ed)?\\s+as|\u0442\u0430\u043a\u0436\u0435\\s+\u0438\u0437\u0432\u0435\u0441\u0442\\p{L}*\\s+\u043a\u0430\u043a|\u0442\u0430\u043a\u0436\u0435\\s+\u043d\u0430\u0437\u044b\u0432\u0430\\p{L}*)")
	semanticAbbreviationSuffixPattern = regexp.MustCompile("(?i)(?:abbreviation|abbr\\.?|\u0430\u0431\u0431\u0440\u0435\u0432\u0438\u0430\u0442\u0443\u0440\\p{L}*|\u0441\u043e\u043a\u0440\\.?)\\s*[:=-]\\s*")
	semanticAbbreviationForPattern    = regexp.MustCompile("(?i)(?:(?:is|\u044d\u0442\u043e)\\s+(?:an?\\s+)?(?:abbreviation|abbr\\.?|\u0430\u0431\u0431\u0440\u0435\u0432\u0438\u0430\u0442\u0443\u0440\\p{L}*|\u0441\u043e\u043a\u0440\\.?)\\s+(?:for|\u0434\u043b\u044f)|(?:\u0430\u0431\u0431\u0440\u0435\u0432\u0438\u0430\u0442\u0443\u0440\u0430|\u0441\u043e\u043a\u0440\u0430\u0449\u0435\u043d\u0438\u0435)\\s+\u0434\u043b\u044f)")
	semanticTermTokenPattern          = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}_-]{1,63}$`)
)

// projectGraphForVersion materializes the minimum canonical graph projection
// for one newly published source version. The source catalog remains the
// authority for content; this projector stores only hashes, IDs and the exact
// Evidence provenance tuple. Workspace rows are derived from the current
// enabled source bindings, so one source can safely appear in several isolated
// workspaces without sharing an authorization edge.
//
// The projector is deliberately conservative: it creates one source entity
// and one canonical term for the trusted source title/lineage label. Semantic
// extraction and cross-source relation discovery are later bounded projectors;
// they must use the same Evidence-backed API rather than bypassing this path.
func (h *Handler) projectGraphForVersion(ctx context.Context, tx database.Transaction,
	access database.AccessContext, scope resolvedScope, objectID, versionID,
	extractionID, evidenceFragmentID, label, entityType string, termInputs ...graphTermInput) error {
	if h == nil || h.graph == nil || ctx == nil || !tx.Valid() || access.Validate() != nil ||
		objectID == "" || versionID == "" || extractionID == "" || evidenceFragmentID == "" ||
		strings.TrimSpace(label) == "" {
		return nil
	}
	if entityType == "" {
		entityType = "OTHER"
	}
	var observedAt, freshnessAt time.Time
	if err := tx.QueryRow(ctx, `
		SELECT observed_at
		  FROM public.source_version
		 WHERE organization_id=$1 AND id=$2 AND source_object_id=$3`,
		access.OrganizationID, versionID, objectID).Scan(&observedAt); err != nil {
		return err
	}
	if observedAt.IsZero() {
		observedAt = h.now().UTC()
	}
	freshnessAt = h.now().UTC()
	if freshnessAt.Before(observedAt) {
		freshnessAt = observedAt
	}
	attributes, err := json.Marshal(map[string]string{
		"projection":    "source-object-v1",
		"extraction_id": extractionID,
	})
	if err != nil {
		return err
	}
	canonicalKeyHash := canon.Hash([]byte(objectID))
	displayNameHash := canon.Hash([]byte(label))
	// A graph row is workspace-scoped. Only the current workspace revision that
	// enables this exact source revision receives a projection. The query is
	// server-owned and cannot be widened by a source payload.
	rows, err := tx.Query(ctx, `
		SELECT workspace_id, workspace_revision
		  FROM app.knowledge_graph_projection_targets($1,$2)`, scope.scopeID, scope.revision)
	if err != nil {
		return err
	}
	bindings := make([]struct {
		workspaceID       string
		workspaceRevision int64
	}, 0)
	for rows.Next() {
		var workspaceID string
		var workspaceRevision int64
		if err := rows.Scan(&workspaceID, &workspaceRevision); err != nil {
			rows.Close()
			return err
		}
		bindings = append(bindings, struct {
			workspaceID       string
			workspaceRevision int64
		}{workspaceID: workspaceID, workspaceRevision: workspaceRevision})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(termInputs) == 0 {
		termInputs = []graphTermInput{{Label: label, EvidenceFragmentID: evidenceFragmentID}}
	}
	// Normalize and bound term observations before opening any graph write. A
	// malformed transient label is an ingestion failure, never an opportunity
	// to persist an unvalidated catalog key.
	normalizedTerms := make([]graphTermInput, 0, len(termInputs))
	seenTerms := make(map[string]struct{}, len(termInputs))
	for _, input := range termInputs {
		input.Label = strings.ToLower(strings.TrimSpace(input.Label))
		if input.Label == "" || input.EvidenceFragmentID == "" || len([]rune(input.Label)) < 2 {
			continue
		}
		if input.TermKind == "" {
			input.TermKind = "CANONICAL"
		}
		switch input.TermKind {
		case "CANONICAL", "SYNONYM", "ABBREVIATION", "CONTEXT":
		default:
			continue
		}
		if input.ContextHash != "" && !strings.HasPrefix(input.ContextHash, "sha256:") {
			continue
		}
		if _, exists := seenTerms[input.Label+"\x00"+input.EvidenceFragmentID+"\x00"+input.TermKind]; exists {
			continue
		}
		if _, err := knowledgegraph.SemanticTermHash(input.Label); err != nil {
			continue
		}
		seenTerms[input.Label+"\x00"+input.EvidenceFragmentID+"\x00"+input.TermKind] = struct{}{}
		normalizedTerms = append(normalizedTerms, input)
		if len(normalizedTerms) >= 64 {
			break
		}
	}
	for _, binding := range bindings {
		workspaceID := binding.workspaceID
		workspaceRevision := binding.workspaceRevision
		candidateID, err := h.newID("entity")
		if err != nil {
			return err
		}
		provenance := knowledgegraph.SourceProvenance{
			WorkspaceID: workspaceID, WorkspaceRevision: workspaceRevision,
			SourceScopeID: scope.scopeID, SourceScopeRevision: scope.revision,
			SourceObjectID: objectID, SourceVersionID: versionID,
			EvidenceFragmentID: evidenceFragmentID, ObservedAt: observedAt,
			FreshnessAt: freshnessAt,
		}
		entityID, inserted, err := h.graph.UpsertEntity(ctx, tx, access, knowledgegraph.Entity{
			OrganizationID: access.OrganizationID, ID: candidateID, EntityType: entityType,
			CanonicalKeyHash: canonicalKeyHash, DisplayNameHash: displayNameHash,
			AttributesJSON: attributes, SourceProvenance: provenance,
		})
		if err != nil {
			return err
		}
		// A previously committed entity implies its dependent terms/relations
		// were committed in the same source transaction. Nothing is rewritten on
		// replay, and lifecycle visibility remains owned by the graph guards.
		if !inserted {
			continue
		}
		for _, input := range normalizedTerms {
			inputHash, err := knowledgegraph.SemanticTermHash(input.Label)
			if err != nil {
				return err
			}
			termID, err := h.newID("term")
			if err != nil {
				return err
			}
			termProvenance := provenance
			termProvenance.EvidenceFragmentID = input.EvidenceFragmentID
			if err := h.graph.CreateSemanticTerm(ctx, tx, access, knowledgegraph.SemanticTerm{
				OrganizationID: access.OrganizationID, ID: termID, CanonicalEntityID: entityID,
				TermKind: input.TermKind, Language: "und", TermHash: inputHash, ContextHash: input.ContextHash,
				Confidence: 1, AttributesJSON: attributes, SourceProvenance: termProvenance,
			}); err != nil {
				return err
			}
		}
		if err := h.projectSharedTermRelations(ctx, tx, access, workspaceID, entityID, provenance, normalizedTerms); err != nil {
			return err
		}
	}
	return nil
}

// projectSharedTermRelations links one source entity to already projected
// entities in the same workspace when an explicit canonical/synonym term is
// shared. Ordinary CONTEXT tokens are intentionally excluded: co-occurrence
// must not become an asserted business relationship. The relation itself is
// still grounded in the current source Evidence fragment and contains only
// hashes/opaque IDs.
func (h *Handler) projectSharedTermRelations(ctx context.Context, tx database.Transaction,
	access database.AccessContext, workspaceID, entityID string,
	provenance knowledgegraph.SourceProvenance, terms []graphTermInput) error {
	if h == nil || h.graph == nil || ctx == nil || !tx.Valid() || access.Validate() != nil ||
		workspaceID == "" || entityID == "" || len(terms) == 0 {
		return nil
	}
	targets := make(map[string]string, 32)
	for _, input := range terms {
		if input.TermKind != "CANONICAL" && input.TermKind != "SYNONYM" && input.TermKind != "ABBREVIATION" {
			continue
		}
		termHash, err := knowledgegraph.SemanticTermHash(input.Label)
		if err != nil {
			continue
		}
		// The worker deliberately has no broad SELECT policy on graph tables.
		// Resolve only this bounded, same-workspace target set through the
		// tenant-bound SECURITY DEFINER read surface.
		rows, err := tx.Query(ctx, `
			SELECT canonical_entity_id
			  FROM app.knowledge_graph_shared_term_targets($1,$2,$3)`, workspaceID, entityID, termHash)
		if err != nil {
			return err
		}
		for rows.Next() {
			var targetID string
			if err := rows.Scan(&targetID); err != nil {
				rows.Close()
				return err
			}
			if targetID != "" {
				if _, exists := targets[targetID]; !exists {
					targets[targetID] = termHash
				}
			}
			if len(targets) >= 32 {
				break
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(targets) >= 32 {
			break
		}
	}
	if len(targets) == 0 {
		return nil
	}
	targetIDs := make([]string, 0, len(targets))
	for targetID := range targets {
		targetIDs = append(targetIDs, targetID)
	}
	sort.Strings(targetIDs)
	for _, targetID := range targetIDs {
		termHash := targets[targetID]
		attributes, err := json.Marshal(struct {
			Projection string `json:"projection"`
			TermHash   string `json:"term_hash"`
		}{Projection: "shared-semantic-term-v1", TermHash: termHash})
		if err != nil {
			return err
		}
		relationID, err := h.newID("relation")
		if err != nil {
			return err
		}
		relationProvenance := provenance
		for _, input := range terms {
			if input.TermKind == "CANONICAL" || input.TermKind == "SYNONYM" || input.TermKind == "ABBREVIATION" {
				if hash, hashErr := knowledgegraph.SemanticTermHash(input.Label); hashErr == nil && hash == termHash {
					if input.EvidenceFragmentID != "" {
						relationProvenance.EvidenceFragmentID = input.EvidenceFragmentID
					}
					break
				}
			}
		}
		if err := h.graph.CreateRelation(ctx, tx, access, knowledgegraph.Relation{
			OrganizationID: access.OrganizationID, ID: relationID,
			SubjectEntityID: entityID, Predicate: "context.mentions", ObjectEntityID: targetID,
			Confidence: 0.75, AttributesJSON: attributes, SourceProvenance: relationProvenance,
		}); err != nil {
			return err
		}
	}
	return nil
}

func graphTermInputs(label string, planned []plannedUnit, fragmentIDs []string) []graphTermInput {
	result := make([]graphTermInput, 0, 32)
	if len(fragmentIDs) == 0 {
		return result
	}
	appendTokens := func(text string, evidenceID, termKind, contextHash string) {
		var builder strings.Builder
		flush := func() {
			value := strings.ToLower(strings.TrimSpace(builder.String()))
			builder.Reset()
			if value == "" || len([]rune(value)) < 2 {
				return
			}
			result = append(result, graphTermInput{Label: value, EvidenceFragmentID: evidenceID, TermKind: termKind, ContextHash: contextHash})
		}
		for _, r := range text {
			if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-' {
				builder.WriteRune(r)
				continue
			}
			flush()
			if len(result) >= 64 {
				return
			}
		}
		flush()
	}
	// Keep the source title as the canonical label and use tokenized words only
	// as context terms. This prevents ordinary prose words from being mislabeled
	// as canonical entities while still allowing a query for "Kafka" to resolve
	// through the Evidence-backed semantic catalog.
	canonicalLabel := strings.ToLower(strings.TrimSpace(label))
	if canonicalLabel != "" {
		result = append(result, graphTermInput{Label: canonicalLabel, EvidenceFragmentID: fragmentIDs[0], TermKind: "CANONICAL"})
	}
	appendTokens(label, fragmentIDs[0], "CONTEXT", canon.Hash([]byte(label)))
	for index, unit := range planned {
		if index >= len(fragmentIDs) || len(result) >= 64 {
			break
		}
		// An explicit definition is stronger than a generic context token. Keep
		// the alias tied to this exact fragment and retain the whole unit as its
		// context hash; no plaintext is persisted by the graph repository.
		for _, alias := range semanticAliasObservations(string(unit.text)) {
			if len(result) >= 64 {
				break
			}
			result = append(result, graphTermInput{
				Label: alias.Label, EvidenceFragmentID: fragmentIDs[index], TermKind: alias.TermKind,
				ContextHash: canon.Hash(unit.text),
			})
		}
		appendTokens(string(unit.text), fragmentIDs[index], "CONTEXT", canon.Hash(unit.text))
	}
	return result
}

// semanticAliasObservations returns only explicit, locally bounded catalog
// assertions. A definition/known-as marker promotes the left term to SYNONYM;
// an abbreviation marker promotes the explicitly marked short form to
// ABBREVIATION. The opposite side is validated as a lexical witness but is
// not promoted, preventing a single sentence from silently asserting
// bidirectional synonymy.
func semanticAliasObservations(text string) []semanticAliasObservation {
	result := make([]semanticAliasObservation, 0, 8)
	seen := make(map[string]struct{}, 8)
	appendObservation := func(label, termKind string) {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" || termKind == "" {
			return
		}
		key := termKind + "\x00" + label
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, semanticAliasObservation{Label: label, TermKind: termKind})
	}
	appendPair := func(pattern *regexp.Regexp, termKind string, aliasOnLeft bool) {
		for _, bounds := range pattern.FindAllStringIndex(text, 8) {
			if len(bounds) != 2 || !semanticMarkerBoundary(text, bounds[0], bounds[1]) {
				continue
			}
			left, leftOK := semanticExplicitTerm(text[:bounds[0]], true)
			marker := strings.TrimSpace(text[bounds[0]:bounds[1]])
			// A dash definition commonly carries a grammatical connector on the
			// right (for example, "The bus is Kafka"). It is still an explicit
			// assertion, so only this marker permits a leading stop word. Other
			// markers reject a leading article/preposition; accepting one would
			// promote vague prose such as "Kafka also known as the platform ...".
			right, rightOK := semanticExplicitTermPolicy(text[bounds[1]:], false, marker == "—" || marker == "–")
			if !leftOK || !rightOK {
				continue
			}
			if aliasOnLeft {
				appendObservation(left, termKind)
			} else {
				appendObservation(right, termKind)
			}
		}
	}
	// Keep the historical definition/dash semantics while allowing bounded
	// multi-token terms. A dash is an explicit marker even when adjacent to a
	// term, so it intentionally bypasses the word-boundary check below.
	appendPair(semanticDefinitionMarkerPattern, "SYNONYM", true)
	appendPair(semanticKnownAsMarkerPattern, "SYNONYM", true)
	// "Message Bus (abbr: MB)" marks the right side; "MB is an abbreviation
	// for Message Bus" marks the left side. Both forms require a valid witness
	// on the opposite side and never treat an unmarked parenthesis as semantic.
	appendPair(semanticAbbreviationSuffixPattern, "ABBREVIATION", false)
	appendPair(semanticAbbreviationForPattern, "ABBREVIATION", true)
	return result
}

// semanticAliasMatches is retained as a compatibility helper for bounded
// callers that only need labels. The graph projector uses the typed
// observations above so abbreviations cannot be collapsed into synonyms.
func semanticAliasMatches(text string) []string {
	seen := make(map[string]struct{}, 4)
	result := make([]string, 0, 4)
	for _, observation := range semanticAliasObservations(text) {
		if _, exists := seen[observation.Label]; exists {
			continue
		}
		seen[observation.Label] = struct{}{}
		result = append(result, observation.Label)
	}
	return result
}

func semanticMarkerBoundary(text string, start, end int) bool {
	if start < 0 || end < start || end > len(text) {
		return false
	}
	marker := strings.TrimSpace(text[start:end])
	if marker == "—" || marker == "–" {
		return true
	}
	left := text[:start]
	if left != "" {
		r, _ := utf8.DecodeLastRuneInString(left)
		if semanticTermRune(r) {
			return false
		}
	}
	right := text[end:]
	if right != "" {
		r, _ := utf8.DecodeRuneInString(right)
		markerLast, _ := utf8.DecodeLastRuneInString(marker)
		// A lexical marker must be separated from an adjacent word. Explicit
		// abbreviation forms are different: the marker ends in ':'/'='/'-',
		// so `abbr:MB` remains valid without an extra space.
		if semanticTermRune(r) && semanticTermRune(markerLast) {
			return false
		}
	}
	return true
}

func semanticExplicitTerm(value string, fromLeft bool) (string, bool) {
	return semanticExplicitTermPolicy(value, fromLeft, false)
}

func semanticExplicitTermPolicy(value string, fromLeft, allowLeadingStopWords bool) (string, bool) {
	segments := semanticLexicalSegments(value)
	if len(segments) == 0 {
		return "", false
	}
	segment := segments[0]
	if fromLeft {
		segment = segments[len(segments)-1]
	}
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(segment)))
	if !fromLeft && !allowLeadingStopWords && len(parts) > 0 && semanticStopWord(parts[0]) {
		return "", false
	}
	if fromLeft || allowLeadingStopWords {
		for len(parts) > 0 && semanticStopWord(parts[0]) {
			parts = parts[1:]
		}
	}
	for len(parts) > 0 && semanticStopWord(parts[len(parts)-1]) {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 || len(parts) > 4 {
		return "", false
	}
	hasLetter := false
	for _, part := range parts {
		if !semanticTermTokenPattern.MatchString(part) {
			return "", false
		}
		if strings.IndexFunc(part, unicode.IsLetter) >= 0 {
			hasLetter = true
		}
	}
	term := strings.Join(parts, " ")
	if len([]rune(term)) < 2 || !hasLetter {
		return "", false
	}
	return term, true
}

func semanticLexicalSegments(value string) []string {
	segments := make([]string, 0, 4)
	var builder strings.Builder
	spacePending := false
	flush := func() {
		segment := strings.TrimSpace(builder.String())
		builder.Reset()
		spacePending = false
		if segment != "" {
			segments = append(segments, segment)
		}
	}
	for _, r := range value {
		switch {
		case semanticTermRune(r):
			if spacePending && builder.Len() > 0 {
				builder.WriteByte(' ')
			}
			spacePending = false
			builder.WriteRune(r)
		case unicode.IsSpace(r):
			if builder.Len() > 0 {
				spacePending = true
			}
		default:
			flush()
		}
	}
	flush()
	return segments
}

func semanticTermRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-'
}

func semanticStopWord(value string) bool {
	switch value {
	case "\u044d\u0442\u043e", "means", "is", "called", "the", "a", "an", "also", "known", "as", "or", "and", "of", "for", "used", "by", "with", "from", "in", "on", "to", "which", "that", "this", "our", "\u0442\u0430\u043a\u0436\u0435", "\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043d", "\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u0430", "\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u043e", "\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u044b", "\u043a\u0430\u043a", "\u043d\u0430\u0437\u044b\u0432\u0430\u0435\u0442\u0441\u044f", "\u043d\u0430\u0437\u044b\u0432\u0430\u044e\u0442\u0441\u044f", "\u0430\u0431\u0431\u0440\u0435\u0432\u0438\u0430\u0442\u0443\u0440\u0430", "\u0441\u043e\u043a\u0440\u0430\u0449\u0435\u043d\u0438\u0435", "\u0441\u043e\u043a\u0440", "abbreviation", "abbr", "\u0438", "\u0438\u043b\u0438", "\u0434\u043b\u044f", "\u0438\u0437", "\u0432", "\u043d\u0430", "\u043a":
		return true
	default:
		return false
	}
}

func (h *Handler) graphPublication(ctx context.Context, tx database.Transaction,
	access database.AccessContext, versionID, profileHash string) (string, []string, error) {
	var extractionID string
	rows, err := tx.Query(ctx, `
		SELECT extraction.id, fragment.id
		  FROM public.source_extraction extraction
		  JOIN public.evidence_fragment fragment
		    ON fragment.organization_id=extraction.organization_id
		   AND fragment.extraction_id=extraction.id
		 WHERE extraction.organization_id=$1
		   AND extraction.source_version_id=$2
		   AND extraction.profile_hash=$3
		   AND extraction.status='SUCCEEDED'
		 ORDER BY fragment.ordinal`, access.OrganizationID, versionID, profileHash)
	if err != nil {
		return "", nil, err
	}
	fragmentIDs := make([]string, 0)
	for rows.Next() {
		var currentExtraction, fragmentID string
		if err := rows.Scan(&currentExtraction, &fragmentID); err != nil {
			rows.Close()
			return "", nil, err
		}
		if extractionID == "" {
			extractionID = currentExtraction
		} else if extractionID != currentExtraction {
			rows.Close()
			return "", nil, &errPipeline{code: "INGEST_GRAPH_EXTRACTION_DRIFT"}
		}
		fragmentIDs = append(fragmentIDs, fragmentID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", nil, err
	}
	rows.Close()
	if extractionID == "" || len(fragmentIDs) == 0 {
		return "", nil, &errPipeline{code: "INGEST_GRAPH_EVIDENCE_MISSING"}
	}
	return extractionID, fragmentIDs, nil
}

func (h *Handler) projectGraphForPostgreSQLRow(ctx context.Context, tx database.Transaction,
	access database.AccessContext, request PostgreSQLSnapshotRequest, objectID, versionID string, row postgresqlquery.Row, profileHash string) error {
	if h == nil || h.graph == nil {
		return nil
	}
	extractionID, fragmentIDs, err := h.graphPublication(ctx, tx, access, versionID, profileHash)
	if err != nil {
		return err
	}
	identity, err := postgresqlquery.IdentityDigest(h.digester.Key, h.digester.KeyVersion, request.Projection, row)
	if err != nil {
		return err
	}
	terms, err := postgresqlGraphTermInputs(request, row, fragmentIDs, identity)
	if err != nil {
		return err
	}
	return h.projectGraphForVersion(ctx, tx, access,
		resolvedScope{scopeID: request.ScopeID, revision: request.ScopeRevision},
		objectID, versionID, extractionID, fragmentIDs[0],
		request.Projection.LineageID, "SQL_BUSINESS_OBJECT",
		terms...)
}

// postgresqlGraphTermInputs keeps the SQL projection source-agnostic while
// making its server-declared column vocabulary discoverable to the semantic
// catalog. Only columns that produced an Evidence cell are projected, so a
// term can never point at a fabricated or unrelated fragment. The helper is
// intentionally pure: publication still performs all authorization and
// persistence through projectGraphForVersion.
func postgresqlGraphTermInputs(request PostgreSQLSnapshotRequest, row postgresqlquery.Row, fragmentIDs []string, identity string) ([]graphTermInput, error) {
	if request.Projection.Validate() != nil || len(fragmentIDs) == 0 || identity == "" {
		return nil, &errPipeline{code: "INGEST_GRAPH_EVIDENCE_MAPPING"}
	}
	terms := []graphTermInput{{
		Label: request.Projection.LineageID, EvidenceFragmentID: fragmentIDs[0], TermKind: "CANONICAL",
	}}
	rendered, err := postgresqlRenderedEvidenceCells(request, identity, row)
	if err != nil {
		return nil, &errPipeline{code: "INGEST_GRAPH_EVIDENCE_MAPPING"}
	}
	if len(rendered) != len(fragmentIDs) {
		return nil, &errPipeline{code: "INGEST_GRAPH_EVIDENCE_MAPPING"}
	}
	for index, rendered := range rendered {
		label := rendered.column.Name
		if rendered.cell.Path != "" {
			label += rendered.cell.Path
		}
		terms = append(terms, graphTermInput{
			Label: label, EvidenceFragmentID: fragmentIDs[index], TermKind: "CONTEXT",
			ContextHash: canon.Hash([]byte(request.Projection.LineageID + "\x00" + label)),
		})
	}
	return terms, nil
}
