package retrieval

import (
	"context"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

const (
	maximumQueryBytes       = 32 << 10
	maximumSearchHits       = 64
	maximumEvidencePerChunk = 256
	maximumGraphMatches     = 128
	maximumExpandedTerms    = 32
	maximumPhraseTokens     = 3
)

// lexicalProfileID mirrors search.LexicalProfileID: the server-owned profile
// descriptor a deployment installs when no embedding channel is mounted. It is
// an identity, not a model artifact, and never carries a vector space.
const lexicalProfileID = search.LexicalProfileID

// ErrorCode values used by the live executor. The package already exposes a
// snapshot persistence vocabulary in repository.go; these names keep runtime
// dependency failures distinguishable without changing that contract.
const (
	CodeExecutorInvalid ErrorCode = "RETRIEVAL_REQUEST_INVALID"
	CodeExecutorDenied  ErrorCode = "RETRIEVAL_REQUEST_DENIED"
	CodeExecutorFailed  ErrorCode = "RETRIEVAL_DEPENDENCY_FAILED"
)

// Channel failure sentinels. Fusion inputs come from independent channels,
// and "a dependency failed" is not actionable on its own: an operator needs
// to know whether the embedding channel, the index, or the corpus lineage
// itself is the problem. These names carry no tenant, workspace or content.
var (
	errLexicalLineageConflict = errors.New("RETRIEVAL_LEXICAL_LINEAGE_CONFLICT")
	errVectorLineageConflict  = errors.New("RETRIEVAL_VECTOR_LINEAGE_CONFLICT")
	errVectorChannelMismatch  = errors.New("RETRIEVAL_VECTOR_CHANNEL_MISMATCH")
	// errWorkspaceChannelsUnavailable means every channel the requested
	// retrieval profile declared failed to answer. It is distinct from an empty
	// corpus on purpose: a vector-only ablation whose endpoint is down must
	// report a dependency failure, not "this workspace knows nothing".
	errWorkspaceChannelsUnavailable = errors.New("RETRIEVAL_WORKSPACE_CHANNELS_UNAVAILABLE")
)

// DiagnosticClass names the dependency behind a retrieval failure for worker
// and server logs. It is content-free by construction: every value is one of
// the closed error-code vocabularies of the packages this one composes.
func DiagnosticClass(err error) string {
	if err == nil {
		return ""
	}
	for _, sentinel := range []error{errLexicalLineageConflict, errVectorLineageConflict, errVectorChannelMismatch, errWorkspaceChannelsUnavailable} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	var embeddingError *embedding.Error
	if errors.As(err, &embeddingError) {
		return string(embedding.CodeOf(err))
	}
	var searchError *search.Error
	if errors.As(err, &searchError) {
		return string(search.CodeOf(err))
	}
	return ""
}

// AuthorizedCandidate is a post-authorized Evidence projection. Text and Anchor are
// obtained from PostgreSQL's gated encrypted-artifact viewer, never from an
// OpenSearch _source field.
type AuthorizedCandidate struct {
	ID                    string
	SourceObjectID        string
	SourceVersionID       string
	ExtractionID          string
	ObjectType            string
	CanonicalFormat       string
	ParserProfileRevision string
	TextHash              string
	AnchorHash            string
	ContentHash           string
	Ordinal               int64
	Score                 float64
	Channels              []Channel
	Text                  []byte
	Anchor                []byte
}

// Result is deliberately explicit about incompleteness. A bounded or
// post-authorization-partial result must not be rendered as a complete answer.
type Result struct {
	Total      int
	Candidates []AuthorizedCandidate
	Partial    bool
}

// Executor composes the immutable search capability with the current
// workspace/Evidence authorization gate. It has no raw SQL or OpenSearch DSL
// surface and is safe for concurrent use.
type Executor struct {
	client   *search.Client
	viewer   *evidence.Viewer
	db       *database.Store
	graph    *knowledgegraph.Repository
	vector   VectorProvider
	reranker RerankProvider
}

func NewExecutor(client *search.Client, viewer *evidence.Viewer) (*Executor, error) {
	if client == nil || viewer == nil {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	return &Executor{client: client, viewer: viewer}, nil
}

// NewExecutorWithGraph composes the lexical index with the live semantic
// catalog. Vector providers are deliberately a separate capability: until a
// qualified model/index is mounted, RetrievePlan returns a partial fusion and
// the Question authority must not publish a complete answer.
func NewExecutorWithGraph(client *search.Client, viewer *evidence.Viewer, db *database.Store, graph *knowledgegraph.Repository) (*Executor, error) {
	if client == nil || viewer == nil || db == nil || graph == nil {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	return &Executor{client: client, viewer: viewer, db: db, graph: graph}, nil
}

// NewExecutorWithGraphAndVector mounts a qualified vector capability beside
// the existing lexical/entity graph channels. The capability is explicit and
// immutable; omitting it keeps the vector channel partial rather than silently
// substituting a fake or in-memory embedding.
func NewExecutorWithGraphAndVector(client *search.Client, viewer *evidence.Viewer, db *database.Store,
	graph *knowledgegraph.Repository, vector VectorProvider) (*Executor, error) {
	if client == nil || viewer == nil || db == nil || graph == nil || vector == nil {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	return &Executor{client: client, viewer: viewer, db: db, graph: graph, vector: vector}, nil
}

// NewExecutorWithProviders mounts optional vector and neural ranking providers.
// Ranking receives only text obtained through the live Evidence gate.
func NewExecutorWithProviders(client *search.Client, viewer *evidence.Viewer, db *database.Store,
	graph *knowledgegraph.Repository, vector VectorProvider, reranker RerankProvider) (*Executor, error) {
	if client == nil || viewer == nil || db == nil || graph == nil {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	return &Executor{client: client, viewer: viewer, db: db, graph: graph, vector: vector, reranker: reranker}, nil
}

// HybridReady reports whether the graph-aware execution boundary is mounted.
// It does not claim vector/model qualification; callers should inspect the
// returned FusionResult.Partial as the authoritative completeness signal.
func (executor *Executor) HybridReady() bool {
	return executor != nil && executor.client != nil && executor.viewer != nil && executor.db != nil && executor.graph != nil
}

// VectorReady reports whether a qualified vector capability is mounted. It
// does not assert that the external provider is healthy for a particular run.
func (executor *Executor) VectorReady() bool {
	return executor != nil && executor.vector != nil
}

// RetrievePlan executes the server-owned lexical + entity/relationship
// channels for one validated plan and fuses them with the explicit vector
// channel placeholder. No provider can supply plaintext, SQL or citations;
// every fused reference is post-authorized through PostgreSQL Evidence.
func (executor *Executor) RetrievePlan(ctx context.Context, access database.AccessContext,
	workspaceID string, planned planner.Plan) (Result, error) {
	return executor.RetrievePlanWithQuestion(ctx, access, workspaceID, planned.PlanHash, VectorQuestionText(expandPhraseTerms(planned.SubjectTerms)), planned)
}

// RetrievePlanWithQuestion is the question-aware entry point used by Question
// Run. It keeps the original natural-language context for a real embedding
// provider while retaining the same immutable planner and authorization path.
func (executor *Executor) RetrievePlanWithQuestion(ctx context.Context, access database.AccessContext,
	workspaceID, operationID, question string, planned planner.Plan) (Result, error) {
	if executor == nil || executor.client == nil || executor.viewer == nil || executor.db == nil || executor.graph == nil ||
		ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(operationID) || question == "" || planned.Validate() != nil {
		return Result{}, &Error{code: CodeExecutorInvalid}
	}
	if executor.client.OrganizationID() != access.OrganizationID {
		return Result{}, &Error{code: CodeExecutorDenied}
	}
	// The tenant's ACTIVE profile revision — not the presence of an embedding
	// mount — decides which channels may answer. A deployment can mount the
	// embedding channel for the GENERATIVE claim verifier long before (or
	// without ever) activating a vector revision for this tenant, and a STAGING
	// revision whose re-index pass has not been activated must never be read
	// from (SRCH-010: query and corpus vectors belong to one exact profile).
	// A drifted or absent profile stays fail-closed exactly as before.
	// The embedding pair is nullable by design (migration 000046): a lexical
	// deployment has a profile identity but no model artifact.
	active, profileActive, profileErr := executor.activeSearchProfile(ctx, access)
	if profileErr != nil {
		return Result{}, &Error{code: CodeExecutorFailed, cause: profileErr}
	}
	provider := executor.vectorForProfile(active, profileActive)
	useVector := provider != nil
	lexicalOnly := !useVector && profileActive
	queryTerms := searchTermsForPlan(planned)
	if len(queryTerms) == 0 {
		return Result{}, &Error{code: CodeExecutorInvalid}
	}
	searchResult, err := executor.client.Search(ctx, search.Query{Text: strings.Join(queryTerms, " "), Size: maximumSearchHits + 1, Operator: search.MatchAny, ProfileRevision: active.revision, ProfileHash: active.hash})
	if err != nil {
		return Result{}, &Error{code: CodeExecutorFailed, cause: err}
	}
	lexical := ChannelResult{Channel: ChannelLexical, CoverageComplete: searchResult.TotalExact && searchResult.Total <= maximumSearchHits}
	lexicalByEvidence := make(map[string]ChannelHit)
	for _, hit := range searchResult.Hits {
		fragmentIDs := hit.Document.EvidenceFragmentIDs
		textHashes := hit.Document.EvidenceTextHashes
		anchorHashes := hit.Document.EvidenceAnchorHashes
		if len(fragmentIDs) == 0 {
			fragmentIDs = []string{hit.Document.EvidenceFragmentID}
			textHashes = []string{hit.Document.TextHash}
			anchorHashes = []string{hit.Document.AnchorHash}
		}
		if len(fragmentIDs) != len(textHashes) || len(fragmentIDs) != len(anchorHashes) {
			lexical.CoverageComplete = false
			continue
		}
		for index, fragmentID := range fragmentIDs {
			candidate := ChannelHit{Channel: ChannelLexical,
				EvidenceFragmentID: fragmentID, SourceObjectID: hit.Document.SourceObjectID,
				SourceVersionID: hit.Document.SourceVersionID, ExtractionID: hit.Document.ExtractionID,
				ContentHash: hit.Document.ContentHash, TextHash: textHashes[index],
				AnchorHash: anchorHashes[index], Score: hit.Score}
			if previous, exists := lexicalByEvidence[candidate.EvidenceFragmentID]; exists {
				if previous.SourceObjectID != candidate.SourceObjectID || previous.SourceVersionID != candidate.SourceVersionID ||
					previous.ExtractionID != candidate.ExtractionID || previous.ContentHash != candidate.ContentHash ||
					previous.TextHash != candidate.TextHash || previous.AnchorHash != candidate.AnchorHash {
					return Result{}, &Error{code: CodeExecutorFailed, cause: errLexicalLineageConflict}
				}
				if candidate.Score > previous.Score {
					lexicalByEvidence[candidate.EvidenceFragmentID] = candidate
				}
				continue
			}
			lexicalByEvidence[candidate.EvidenceFragmentID] = candidate
		}
	}
	for _, candidate := range lexicalByEvidence {
		lexical.Hits = append(lexical.Hits, candidate)
	}
	sort.SliceStable(lexical.Hits, func(i, j int) bool {
		if lexical.Hits[i].Score != lexical.Hits[j].Score {
			return lexical.Hits[i].Score > lexical.Hits[j].Score
		}
		return lexical.Hits[i].EvidenceFragmentID < lexical.Hits[j].EvidenceFragmentID
	})
	if len(lexical.Hits) > maximumHybridHits {
		lexical.Hits = lexical.Hits[:maximumHybridHits]
		lexical.CoverageComplete = false
	}
	entity := ChannelResult{Channel: ChannelEntity, CoverageComplete: true}
	if len(planned.EntityHints) == 0 {
		entity.CoverageComplete = false
	} else {
		var termResolution knowledgegraph.TermResolution
		var relations []knowledgegraph.RelationMatch
		if err := executor.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
			var err error
			termResolution, err = executor.graph.ResolveTermsDetailed(txCtx, tx, access,
				knowledgegraph.ResolveQuery{WorkspaceID: workspaceID, Terms: expandPhraseTerms(planned.EntityHints), Limit: maximumGraphMatches})
			if err != nil {
				return err
			}
			ids := make([]string, 0, len(termResolution.Matches))
			for _, match := range termResolution.Matches {
				ids = append(ids, match.EntityID)
			}
			if len(ids) == 0 {
				return nil
			}
			relations, err = executor.graph.TraverseRelations(txCtx, tx, access, workspaceID, ids, maximumGraphMatches)
			return err
		}); err != nil {
			return Result{}, &Error{code: CodeExecutorFailed, cause: err}
		}
		terms := termResolution.Matches
		entityByEvidence := make(map[string]ChannelHit, len(terms)+len(relations))
		if termResolution.Incomplete() {
			// A catalog term that resolves to multiple canonical entities is not
			// a ranking problem. The server-owned count result also covers
			// entities hidden beyond the page limit; any truncation is incomplete
			// so the Question authority cannot choose one meaning by score.
			entity.CoverageComplete = false
		}
		for _, match := range terms {
			candidate := ChannelHit{Channel: ChannelEntity,
				EvidenceFragmentID: match.EvidenceFragmentID, SourceObjectID: match.SourceObjectID,
				SourceVersionID: match.SourceVersionID, ExtractionID: match.ExtractionID,
				ContentHash: match.ContentHash, TextHash: match.EvidenceTextHash,
				AnchorHash: match.AnchorHash, Score: match.Confidence}
			if previous, exists := entityByEvidence[candidate.EvidenceFragmentID]; !exists || candidate.Score > previous.Score {
				entityByEvidence[candidate.EvidenceFragmentID] = candidate
			}
		}
		for _, match := range relations {
			candidate := ChannelHit{Channel: ChannelEntity,
				EvidenceFragmentID: match.EvidenceFragmentID, SourceObjectID: match.SourceObjectID,
				SourceVersionID: match.SourceVersionID, ExtractionID: match.ExtractionID,
				ContentHash: match.ContentHash, TextHash: match.EvidenceTextHash,
				AnchorHash: match.AnchorHash, Score: match.Confidence}
			if previous, exists := entityByEvidence[candidate.EvidenceFragmentID]; !exists || candidate.Score > previous.Score {
				entityByEvidence[candidate.EvidenceFragmentID] = candidate
			}
		}
		for _, candidate := range entityByEvidence {
			entity.Hits = append(entity.Hits, candidate)
		}
		sort.SliceStable(entity.Hits, func(i, j int) bool {
			if entity.Hits[i].Score != entity.Hits[j].Score {
				return entity.Hits[i].Score > entity.Hits[j].Score
			}
			return entity.Hits[i].EvidenceFragmentID < entity.Hits[j].EvidenceFragmentID
		})
		// An empty semantic catalog match is a valid negative signal for a
		// lexical question. Only ambiguity/truncation makes this channel
		// incomplete; treating every miss as a partial corpus would make the
		// explicit lexical-only deployment unable to answer ordinary lookups.
	}
	if planned.Operation == planner.Compare || planned.Operation == planner.Audit || planned.Operation == planner.CodeTrace {
		// Explicit-fact operations render only bounded equality lines, not a
		// catalog entity ranking. A broad field label such as "status" can
		// resolve to hundreds of row entities and otherwise flood the bounded
		// fusion page, turning a valid comparison/audit/code trace into a false
		// CORPUS_PARTIAL result. The entity lookup above still executes for
		// auditability, but its ambiguous/truncated hits are not admitted to
		// explicit-fact contexts.
		entity.Hits = nil
		entity.CoverageComplete = true
	}
	// No vector signal is invented. A missing qualified embedding provider is
	// represented explicitly so fusion remains fail-closed and observable.
	vector := ChannelResult{Channel: ChannelVector, CoverageComplete: false}
	channels := []ChannelResult{lexical}
	if useVector {
		vectorResult, vectorErr := provider.RetrieveVector(ctx, access, workspaceID, operationID, question)
		if vectorErr != nil {
			return Result{}, &Error{code: CodeExecutorFailed, cause: vectorErr}
		}
		if vectorResult.Channel != ChannelVector {
			return Result{}, &Error{code: CodeExecutorFailed, cause: errVectorChannelMismatch}
		}
		vector = vectorResult
		channels = append(channels, vector)
	} else if !lexicalOnly {
		// Keep the strict missing-vector signal when no durable lexical profile
		// is active. This preserves the fail-closed behavior for a drifted or
		// incomplete deployment.
		channels = append(channels, vector)
	}
	channels = append(channels, entity)
	options := FuseOptions{}
	if lexicalOnly {
		options.OptionalChannels = []Channel{ChannelVector}
	}
	// Explicit-fact renderers admit only line-oriented equality assertions from
	// authorized Evidence, so a generic field label resolving to multiple
	// catalog entities must not turn a complete lexical result into a
	// fabricated/empty answer. Unsupported requests still fail closed when no
	// bounded facts/citations are available.
	if planned.Operation == planner.Compare || planned.Operation == planner.Audit || planned.Operation == planner.CodeTrace {
		options.OptionalChannels = append(options.OptionalChannels, ChannelEntity)
	}
	fused, err := FuseWithOptions(channels, maximumSearchHits, options)
	if err != nil {
		return Result{}, err
	}
	return executor.AuthorizeFused(ctx, access, workspaceID, fused)
}

// searchTermsForPlan compiles a bounded lexical hint from the immutable plan.
// Aggregate plans use only their declared metric/group fields plus the
// server-owned temporal column hints. This avoids broad interrogative terms
// ("entity", "records", dates, etc.) returning the whole corpus and tripping
// the 64-hit completeness fence, while selection and the typed reducer still
// enforce the full plan against authorized Evidence cells.
func searchTermsForPlan(planned planner.Plan) []string {
	if planned.Operation == planner.Compare || planned.Operation == planner.Audit || planned.Operation == planner.CodeTrace {
		// Structured Evidence cells are rendered as `payload[/field] = value`.
		// Searching the structural `payload` token alone, or generic operation
		// words such as "audit"/"code", matches the whole corpus and can make
		// the bounded lexical channel incomplete before an explicit-fact renderer
		// inspects the requested key. Preserve field/value/source terms while
		// dropping only structural and operation-envelope noise; all returned
		// candidates still pass the Evidence gate.
		terms := make([]string, 0, len(planned.SubjectTerms))
		for _, term := range planned.SubjectTerms {
			switch strings.ToLower(strings.TrimSpace(term)) {
			case "payload", "entity", "entities", "record", "records",
				"audit", "code", "\u043a\u043e\u0434", "\u043a\u043e\u0434\u0430", "\u043a\u043e\u0434\u043e\u043c", "\u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442", "\u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b", "\u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u043c\u0438",
				"\u043f\u0440\u043e\u0432\u0435\u0440\u044c", "\u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c", "\u043a\u043e\u043d\u0442\u0440\u043e\u043b", "\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c", "\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u0438",
				"\u0441\u0440\u0430\u0432\u043d\u0438", "\u0441\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u0435", "compare", "difference", "versus", "\u043c\u0435\u0436\u0434\u0443", "between",
				"\u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u0435", "\u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f", "\u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a", "\u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0438", "source", "sources":
				continue
			default:
				terms = append(terms, term)
			}
		}
		if len(terms) > 0 {
			return expandPhraseTerms(terms)
		}
	}
	if planned.Operation != planner.Aggregate || planned.Aggregate == nil {
		return expandPhraseTerms(planned.SubjectTerms)
	}
	terms := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	appendTerm := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len([]rune(value)) < 2 {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		terms = append(terms, value)
	}
	appendField := func(field string) {
		field = strings.TrimSpace(field)
		if open := strings.IndexByte(field, '['); open >= 0 && strings.HasSuffix(field, "]") {
			path := strings.TrimSuffix(field[open+1:], "]")
			if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
				path = path[slash+1:]
			}
			path = strings.ReplaceAll(strings.ReplaceAll(path, "~1", "/"), "~0", "~")
			appendTerm(path)
			return
		}
		appendTerm(field)
	}
	appendField(planned.Aggregate.Metric)
	for _, field := range planned.Aggregate.GroupBy {
		appendField(field)
	}
	for _, filter := range planned.Filters {
		switch filter.Name {
		case "time_range", "time_window", "time_period":
			// SQL business-object projections use these stable provenance/date
			// fields. They are only hints for retrieval; range enforcement stays
			// in candidate selection and the typed reducer.
			appendTerm("last_updated_at")
			appendTerm("observed_at")
		}
	}
	if len(terms) == 0 {
		return expandPhraseTerms(planned.SubjectTerms)
	}
	return terms
}

// expandPhraseTerms adds only bounded contiguous n-grams to planner-owned
// terms. It is a retrieval hint, not a new plan field or authority: the
// original single-token terms are retained first, then stable 2- and 3-token
// phrases are appended and deduplicated. The graph resolver still hashes every
// term and the lexical hits still pass the existing Evidence post-authorization
// gate, so a phrase can improve recall but cannot grant access or invent a
// citation.
func expandPhraseTerms(terms []string) []string {
	if len(terms) == 0 {
		return nil
	}
	base := make([]string, 0, len(terms))
	seen := make(map[string]struct{}, maximumExpandedTerms)
	appendTerm := func(value string) (string, bool, bool) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") || len([]rune(value)) > 256 {
			return "", false, false
		}
		if _, exists := seen[value]; exists {
			return value, true, true
		}
		if len(base) >= maximumExpandedTerms {
			return value, false, false
		}
		seen[value] = struct{}{}
		base = append(base, value)
		return value, true, false
	}
	phraseSegments := make([][]string, 0, 4)
	currentSegment := make([]string, 0, maximumPhraseTokens)
	flushSegment := func() {
		if len(currentSegment) > 0 {
			phraseSegments = append(phraseSegments, currentSegment)
			currentSegment = nil
		}
	}
	for _, term := range terms {
		value, accepted, duplicate := appendTerm(term)
		if !accepted {
			// Invalid/empty/oversized input is a hard phrase boundary. A caller
			// cannot smuggle two otherwise valid terms across a rejected token.
			flushSegment()
			continue
		}
		if duplicate {
			// Repeated planner hints are not a new lexical adjacency. Keep the
			// first occurrence deterministic and close the current segment so a
			// duplicate cannot bridge unrelated terms.
			flushSegment()
			continue
		}
		if len(strings.Fields(value)) != 1 {
			// Preserve a supplied phrase, but do not concatenate it with a
			// neighboring token; future catalog resolvers may already provide
			// canonical multi-token terms here.
			flushSegment()
			continue
		}
		currentSegment = append(currentSegment, value)
	}
	flushSegment()
	if len(base) == 0 {
		return nil
	}
	result := append([]string(nil), base...)
	for _, lexical := range phraseSegments {
		for width := 2; width <= maximumPhraseTokens && len(result) < maximumExpandedTerms; width++ {
			for start := 0; start+width <= len(lexical) && len(result) < maximumExpandedTerms; start++ {
				phrase := strings.Join(lexical[start:start+width], " ")
				if len([]rune(phrase)) > 256 {
					continue
				}
				if _, exists := seen[phrase]; exists {
					continue
				}
				seen[phrase] = struct{}{}
				result = append(result, phrase)
			}
		}
	}
	return result
}

// Retrieve gets a bounded candidate page from OpenSearch and re-resolves each
// Evidence fragment through PostgreSQL before returning any plaintext. A
// stale, revoked, cross-workspace or metadata-drifting hit is omitted and
// marks the result partial, causing the Question authority to fail closed.
func (executor *Executor) Retrieve(ctx context.Context, access database.AccessContext, workspaceID, query string) (Result, error) {
	if executor == nil || executor.client == nil || executor.viewer == nil || ctx == nil ||
		access.Validate() != nil || !validOpaque(workspaceID) || !validQuery(query) {
		return Result{}, &Error{code: CodeExecutorInvalid}
	}
	if executor.client.OrganizationID() != access.OrganizationID {
		return Result{}, &Error{code: CodeExecutorDenied}
	}
	active, _, err := executor.activeSearchProfile(ctx, access)
	if err != nil {
		return Result{}, &Error{code: CodeExecutorFailed, cause: err}
	}
	searchResult, err := executor.client.Search(ctx, search.Query{Text: query, Size: maximumSearchHits + 1, Operator: search.MatchAny, ProfileRevision: active.revision, ProfileHash: active.hash})
	if err != nil {
		return Result{}, &Error{code: CodeExecutorFailed, cause: err}
	}
	result := Result{Total: searchResult.Total, Candidates: make([]AuthorizedCandidate, 0, len(searchResult.Hits))}
	if !searchResult.TotalExact || searchResult.Total > len(searchResult.Hits) || searchResult.Total > maximumSearchHits {
		result.Partial = true
	}
	seen := make(map[string]struct{}, len(searchResult.Hits))
	for _, hit := range searchResult.Hits {
		fragmentIDs := hit.Document.EvidenceFragmentIDs
		if len(fragmentIDs) == 0 {
			fragmentIDs = []string{hit.Document.EvidenceFragmentID}
		}
		if len(fragmentIDs) > maximumEvidencePerChunk {
			result.Partial = true
			fragmentIDs = fragmentIDs[:maximumEvidencePerChunk]
		}
		for _, fragmentID := range fragmentIDs {
			if _, duplicate := seen[fragmentID]; duplicate {
				continue
			}
			seen[fragmentID] = struct{}{}
			fragment, readErr := executor.viewer.Read(ctx, access, workspaceID, fragmentID)
			// Same separation as AuthorizeFused: evidence.ErrNotFound is the ACL
			// filter refusing a hit from the shared organization index, which is
			// this gate working, not a hole in the corpus (POKA_YOKE SRCH-008).
			// A different read error, or a lineage/hash mismatch, still degrades
			// coverage fail-closed.
			if errors.Is(readErr, evidence.ErrNotFound) {
				clearBytes(fragment.Text)
				clearBytes(fragment.Anchor)
				continue
			}
			if readErr != nil || !matches(hit.Document, fragment, fragmentID, access.OrganizationID) {
				clearBytes(fragment.Text)
				clearBytes(fragment.Anchor)
				result.Partial = true
				continue
			}
			result.Candidates = append(result.Candidates, AuthorizedCandidate{
				ID: fragment.FragmentID, SourceObjectID: fragment.SourceObjectID,
				SourceVersionID: fragment.SourceVersionID, ExtractionID: fragment.ExtractionID,
				ObjectType: fragment.ObjectType, CanonicalFormat: fragment.CanonicalFormat,
				ParserProfileRevision: fragment.ParserProfileRevision,
				TextHash:              fragment.EvidenceTextHash, AnchorHash: fragment.AnchorHash,
				ContentHash: fragment.ContentHash, Ordinal: fragment.Ordinal,
				Text: append([]byte(nil), fragment.Text...), Anchor: append([]byte(nil), fragment.Anchor...),
			})
			clearBytes(fragment.Text)
			clearBytes(fragment.Anchor)
			if len(result.Candidates) >= maximumSearchHits {
				result.Partial = true
				return result, nil
			}
		}
	}
	return result, nil
}

// AuthorizeFused resolves a fused lexical/vector/entity candidate set through
// the same Evidence viewer used by Retrieve. Providers may contribute only
// metadata references; this method is the sole place where plaintext can enter
// the answer pipeline, and every returned item is checked against its exact
// source lineage and hashes.
func (executor *Executor) AuthorizeFused(ctx context.Context, access database.AccessContext,
	workspaceID string, fused FusionResult) (Result, error) {
	if executor == nil || executor.viewer == nil || ctx == nil || access.Validate() != nil ||
		!validOpaque(workspaceID) || len(fused.Hits) > maximumSearchHits {
		return Result{}, &Error{code: CodeExecutorInvalid}
	}
	unauthorized := 0
	result := Result{Total: len(fused.Hits), Partial: fused.Partial,
		Candidates: make([]AuthorizedCandidate, 0, len(fused.Hits))}
	seen := make(map[string]struct{}, len(fused.Hits))
	for _, hit := range fused.Hits {
		if _, duplicate := seen[hit.EvidenceFragmentID]; duplicate {
			return Result{}, &Error{code: CodeExecutorInvalid}
		}
		seen[hit.EvidenceFragmentID] = struct{}{}
		fragment, readErr := executor.viewer.Read(ctx, access, workspaceID, hit.EvidenceFragmentID)
		// POKA_YOKE SRCH-008: "coverage status is not authorization" —
		// and the converse holds too. evidence.ErrNotFound is the viewer's one
		// answer for every denial: not this principal's, not this workspace's
		// current binding, not the current version. That is the ACL filter doing
		// its job on a hit the shared organization index legitimately returned,
		// not a gap in the corpus this run was supposed to cover. Counting it as
		// coverage damage made ONE unauthorized neighbour in the ranked window
		// degrade every answer in the workspace to a partial corpus. Only a real
		// read failure or a lineage/hash mismatch — evidence that does not match
		// the index entry it came from — is a fail-closed coverage signal.
		if errors.Is(readErr, evidence.ErrNotFound) {
			clearBytes(fragment.Text)
			clearBytes(fragment.Anchor)
			unauthorized++
			continue
		}
		if readErr != nil || fragment.FragmentID != hit.EvidenceFragmentID ||
			fragment.SourceObjectID != hit.SourceObjectID || fragment.SourceVersionID != hit.SourceVersionID ||
			fragment.ExtractionID != hit.ExtractionID || fragment.ContentHash != hit.ContentHash ||
			fragment.EvidenceTextHash != hit.TextHash || fragment.AnchorHash != hit.AnchorHash {
			clearBytes(fragment.Text)
			clearBytes(fragment.Anchor)
			result.Partial = true
			continue
		}
		result.Candidates = append(result.Candidates, AuthorizedCandidate{
			ID: fragment.FragmentID, SourceObjectID: fragment.SourceObjectID,
			SourceVersionID: fragment.SourceVersionID, ExtractionID: fragment.ExtractionID,
			ObjectType: fragment.ObjectType, CanonicalFormat: fragment.CanonicalFormat,
			ParserProfileRevision: fragment.ParserProfileRevision,
			TextHash:              fragment.EvidenceTextHash, AnchorHash: fragment.AnchorHash,
			ContentHash: fragment.ContentHash, Ordinal: fragment.Ordinal,
			Score: hit.Score, Channels: append([]Channel(nil), hit.Channels...),
			Text: append([]byte(nil), fragment.Text...), Anchor: append([]byte(nil), fragment.Anchor...),
		})
		clearBytes(fragment.Text)
		clearBytes(fragment.Anchor)
	}
	if len(result.Candidates)+unauthorized < len(fused.Hits) {
		result.Partial = true
	}
	return result, nil
}

func matches(document search.IndexDocument, fragment evidence.Fragment, fragmentID, organizationID string) bool {
	textHash, anchorHash := document.TextHash, document.AnchorHash
	if len(document.EvidenceFragmentIDs) > 0 {
		if len(document.EvidenceTextHashes) != len(document.EvidenceFragmentIDs) ||
			len(document.EvidenceAnchorHashes) != len(document.EvidenceFragmentIDs) {
			return false
		}
		found := false
		for index, candidateID := range document.EvidenceFragmentIDs {
			if candidateID == fragmentID {
				textHash, anchorHash = document.EvidenceTextHashes[index], document.EvidenceAnchorHashes[index]
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return fragment.FragmentID == fragmentID && document.OrganizationID == organizationID &&
		document.SourceObjectID == fragment.SourceObjectID &&
		document.SourceVersionID == fragment.SourceVersionID &&
		document.ExtractionID == fragment.ExtractionID &&
		document.ContentHash == fragment.ContentHash &&
		textHash == fragment.EvidenceTextHash &&
		anchorHash == fragment.AnchorHash
}

func validQuery(value string) bool {
	return value != "" && utf8.ValidString(value) && len([]byte(value)) <= maximumQueryBytes && strings.TrimSpace(value) != ""
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// activeSearchProfile is the single durable selector for all retrieval paths.
// A mounted embedding profile is a capability, never an activation signal.
type activeSearchProfile struct {
	id       string
	hash     string
	revision int64
}

func (executor *Executor) activeSearchProfile(ctx context.Context, access database.AccessContext) (activeSearchProfile, bool, error) {
	if executor == nil || executor.db == nil {
		return activeSearchProfile{}, false, nil
	}
	var id, hash *string
	var revision int64
	err := executor.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
            SELECT embedding_profile_id, embedding_profile_hash, activation_revision
              FROM public.organization_search_profile
             WHERE organization_id = $1 AND status = 'ACTIVE'`, access.OrganizationID).Scan(&id, &hash, &revision)
	})
	if database.IsNotFound(err) {
		return activeSearchProfile{}, false, nil
	}
	if err != nil {
		return activeSearchProfile{}, false, err
	}
	active := activeSearchProfile{revision: revision}
	if id != nil {
		active.id = *id
	}
	if hash != nil {
		active.hash = *hash
	}
	return active, true, nil
}

func (executor *Executor) vectorForProfile(active activeSearchProfile, found bool) VectorProvider {
	if executor == nil || executor.vector == nil || !found || active.id == "" || active.id == lexicalProfileID || active.hash == "" || active.hash != executor.vector.ProfileHash() {
		return nil
	}
	if revisioned, ok := executor.vector.(RevisionedVectorProvider); ok {
		return revisioned.ForRevision(active.revision)
	}
	if active.revision > 1 {
		return nil
	}
	return executor.vector
}
