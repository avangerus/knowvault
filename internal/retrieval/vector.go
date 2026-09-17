package retrieval

import (
	"context"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
)

// VectorProvider is the only capability RetrievePlan may use for a vector
// channel. It is deliberately a server-owned operation: the provider receives
// an authenticated workspace context and a question, never raw OpenSearch DSL
// or a caller-selected model/index.
type VectorProvider interface {
	RetrieveVector(context.Context, database.AccessContext, string, string, string) (ChannelResult, error)
	// ProfileHash is the immutable vector-space identity this provider embeds
	// and searches under. The executor compares it with the tenant's ACTIVE
	// profile revision so a mounted-but-not-yet-activated vector space can
	// never answer a question (SRCH-010).
	ProfileHash() string
}

// OpenSearchVectorProvider composes the qualified embedding gateway with the
// profile-bound OpenSearch adapter. Both clients are immutable deployment
// capabilities; there is no in-memory vector fallback.
type OpenSearchVectorProvider struct {
	embedding       *embedding.Client
	search          *search.Client
	profileRevision int64
}

// RevisionedVectorProvider selects a physical corpus only after the executor
// has read its ACTIVE revision. It returns a copy so concurrent calls cannot
// change one another's index selection.
type RevisionedVectorProvider interface {
	VectorProvider
	ForRevision(int64) VectorProvider
}

func (provider *OpenSearchVectorProvider) ForRevision(revision int64) VectorProvider {
	if provider == nil {
		return nil
	}
	qualified := *provider
	qualified.profileRevision = revision
	return &qualified
}

func NewOpenSearchVectorProvider(embedClient *embedding.Client, searchClient *search.Client) (*OpenSearchVectorProvider, error) {
	if embedClient == nil || searchClient == nil || embedClient.Profile().ProfileHash == "" {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	if searchClient.OrganizationID() == "" {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	profile := embedClient.Profile()
	profileHash, dimension := searchClient.VectorProfile()
	if profileHash != profile.ProfileHash || dimension != profile.Dimension {
		return nil, &Error{code: CodeExecutorInvalid}
	}
	return &OpenSearchVectorProvider{embedding: embedClient, search: searchClient}, nil
}

// ProfileHash reports the qualified embedding profile this provider is bound
// to. It is a deployment capability value, never a request value.
func (provider *OpenSearchVectorProvider) ProfileHash() string {
	if provider == nil || provider.embedding == nil {
		return ""
	}
	return provider.embedding.Profile().ProfileHash
}

// ScopedVectorProvider is a vector capability that accepts the caller's live
// authorized scope set and the version-lifecycle state as predicates of the
// ranking itself. A deployment that mounts only the unscoped VectorProvider
// keeps the vector channel out of the workspace search rather than ranking a
// tenant's whole corpus and pruning the foreign part afterwards: an unscoped
// k-NN returns k tenant-wide neighbours, so on a large tenant a workspace's
// own best passages can be crowded out by passages it may not read, and post
// authorization then turns that into an empty answer rather than a wrong one.
type ScopedVectorProvider interface {
	VectorProvider
	RetrieveScopedVector(ctx context.Context, access database.AccessContext,
		workspaceID, operationID, question string, scopeIDs []string, versionState string) (ChannelResult, error)
}

// groupedScopedVectorProvider is the workspace-only companion used by the
// indexed search path. Legacy plan callers continue to use
// ScopedVectorProvider and indexedChannel; a provider that has not adopted the
// grouped contract remains visibly degraded for workspace search.
type groupedScopedVectorProvider interface {
	RetrieveScopedVectorGroups(ctx context.Context, access database.AccessContext,
		workspaceID, operationID, question string, scopeIDs []string, versionState string) (workspaceGroupedChannelResult, error)
}

var _ ScopedVectorProvider = (*OpenSearchVectorProvider)(nil)
var _ groupedScopedVectorProvider = (*OpenSearchVectorProvider)(nil)

func (provider *OpenSearchVectorProvider) RetrieveVector(ctx context.Context, access database.AccessContext,
	workspaceID, operationID, question string) (ChannelResult, error) {
	return provider.RetrieveScopedVector(ctx, access, workspaceID, operationID, question, nil, "")
}

// RetrieveScopedVector runs the k-NN channel with the caller's own authorized
// scope set and version state applied inside the query. The scope identifiers
// are server-owned authorization state, never request input, and they only
// ever narrow: PostgreSQL post-authorization still gates every hit.
func (provider *OpenSearchVectorProvider) RetrieveScopedVector(ctx context.Context, access database.AccessContext,
	workspaceID, operationID, question string, scopeIDs []string, versionState string) (ChannelResult, error) {
	if provider == nil || provider.embedding == nil || provider.search == nil || ctx == nil ||
		access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(operationID) || question == "" ||
		provider.search.OrganizationID() != access.OrganizationID {
		return ChannelResult{}, &Error{code: CodeExecutorInvalid}
	}
	profile := provider.embedding.Profile()
	bound := embedding.Binding{OrganizationID: access.OrganizationID, WorkspaceID: workspaceID,
		OperationID: operationID, ProfileHash: profile.ProfileHash}
	// The question is projected exactly as a passage is at index time, so a
	// query and the corpus it is compared against are normalised the same way.
	projected, ok := search.EmbeddableText(question, profile.MaxInputBytes)
	if !ok {
		return ChannelResult{}, &Error{code: CodeExecutorInvalid}
	}
	vector, err := provider.embedding.Embed(ctx, bound, projected)
	if err != nil {
		return ChannelResult{}, err
	}
	result, err := provider.search.VectorSearch(ctx, search.VectorQuery{
		ProfileRevision: provider.profileRevision,
		Vector:          vector.Vector, ProfileHash: vector.ProfileHash, Dimension: vector.Dimension,
		Size: maximumSearchHits + 1, SourceScopeIDs: scopeIDs, VersionState: versionState,
	})
	if err != nil {
		return ChannelResult{}, err
	}
	return indexedChannel(result, ChannelVector)
}

// RetrieveScopedVectorGroups runs the same qualified vector query as
// RetrieveScopedVector but preserves each IndexDocument as one workspace
// retrieval group. The ordinary method above deliberately keeps its historical
// fragment-channel shape for planned/legacy callers.
func (provider *OpenSearchVectorProvider) RetrieveScopedVectorGroups(ctx context.Context, access database.AccessContext,
	workspaceID, operationID, question string, scopeIDs []string, versionState string) (workspaceGroupedChannelResult, error) {
	if provider == nil || provider.embedding == nil || provider.search == nil || ctx == nil ||
		access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(operationID) || question == "" ||
		provider.search.OrganizationID() != access.OrganizationID {
		return workspaceGroupedChannelResult{}, &Error{code: CodeExecutorInvalid}
	}
	profile := provider.embedding.Profile()
	bound := embedding.Binding{OrganizationID: access.OrganizationID, WorkspaceID: workspaceID,
		OperationID: operationID, ProfileHash: profile.ProfileHash}
	projected, ok := search.EmbeddableText(question, profile.MaxInputBytes)
	if !ok {
		return workspaceGroupedChannelResult{}, &Error{code: CodeExecutorInvalid}
	}
	vector, err := provider.embedding.Embed(ctx, bound, projected)
	if err != nil {
		return workspaceGroupedChannelResult{}, err
	}
	result, err := provider.search.VectorSearch(ctx, search.VectorQuery{
		ProfileRevision: provider.profileRevision,
		Vector:          vector.Vector, ProfileHash: vector.ProfileHash, Dimension: vector.Dimension,
		Size: maximumSearchHits + 1, SourceScopeIDs: scopeIDs, VersionState: versionState,
	})
	if err != nil {
		return workspaceGroupedChannelResult{}, err
	}
	channel, err := indexedGroupedChannel(result, ChannelVector)
	if err != nil {
		return workspaceGroupedChannelResult{}, &workspaceGroupedIntegrityError{cause: err}
	}
	return channel, nil
}

func indexedChannel(result search.Result, kind Channel) (ChannelResult, error) {
	channel := ChannelResult{Channel: kind,
		CoverageComplete: result.TotalExact && result.Total <= maximumSearchHits && result.Total <= len(result.Hits)}
	byEvidence := make(map[string]ChannelHit, len(result.Hits))
	for _, hit := range result.Hits {
		fragmentIDs := hit.Document.EvidenceFragmentIDs
		textHashes := hit.Document.EvidenceTextHashes
		anchorHashes := hit.Document.EvidenceAnchorHashes
		if len(fragmentIDs) == 0 {
			fragmentIDs = []string{hit.Document.EvidenceFragmentID}
			textHashes = []string{hit.Document.TextHash}
			anchorHashes = []string{hit.Document.AnchorHash}
		}
		if len(fragmentIDs) == 0 || len(fragmentIDs) != len(textHashes) || len(fragmentIDs) != len(anchorHashes) {
			channel.CoverageComplete = false
			continue
		}
		for index, fragmentID := range fragmentIDs {
			if fragmentID == "" || textHashes[index] == "" || anchorHashes[index] == "" {
				channel.CoverageComplete = false
				continue
			}
			candidate := ChannelHit{Channel: kind,
				EvidenceFragmentID: fragmentID, SourceObjectID: hit.Document.SourceObjectID,
				SourceVersionID: hit.Document.SourceVersionID, ExtractionID: hit.Document.ExtractionID,
				ContentHash: hit.Document.ContentHash, TextHash: textHashes[index],
				AnchorHash: anchorHashes[index], Score: hit.Score}
			if previous, exists := byEvidence[candidate.EvidenceFragmentID]; exists {
				if previous.SourceObjectID != candidate.SourceObjectID || previous.SourceVersionID != candidate.SourceVersionID ||
					previous.ExtractionID != candidate.ExtractionID || previous.ContentHash != candidate.ContentHash ||
					previous.TextHash != candidate.TextHash || previous.AnchorHash != candidate.AnchorHash {
					return ChannelResult{}, &Error{code: CodeExecutorFailed, cause: errVectorLineageConflict}
				}
				if candidate.Score > previous.Score {
					byEvidence[candidate.EvidenceFragmentID] = candidate
				}
				continue
			}
			byEvidence[candidate.EvidenceFragmentID] = candidate
		}
	}
	channel.Hits = make([]ChannelHit, 0, len(byEvidence))
	for _, candidate := range byEvidence {
		channel.Hits = append(channel.Hits, candidate)
	}
	sort.SliceStable(channel.Hits, func(i, j int) bool {
		if channel.Hits[i].Score != channel.Hits[j].Score {
			return channel.Hits[i].Score > channel.Hits[j].Score
		}
		return channel.Hits[i].EvidenceFragmentID < channel.Hits[j].EvidenceFragmentID
	})
	if len(channel.Hits) > maximumHybridHits {
		channel.Hits = channel.Hits[:maximumHybridHits]
		channel.CoverageComplete = false
	}
	return channel, nil
}

// VectorQuestionText is the server-owned fallback input used by the legacy
// plan-only method when a caller has not retained the original question. The
// question-aware path is preferred because it preserves all natural-language
// context for a real embedding model.
func VectorQuestionText(planTerms []string) string {
	return strings.Join(planTerms, " ")
}
