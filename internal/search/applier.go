package search

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// Applier error codes are content-free and safe for worker metrics.  A
// pending non-search event is deliberately distinguishable from an empty
// queue: strict outbox order means the search projection cannot skip it.
const (
	CodeNoWork             ErrorCode = "SEARCH_APPLIER_NO_WORK"
	CodeBlocked            ErrorCode = "SEARCH_APPLIER_ORDER_BLOCKED"
	CodeEventInvalid       ErrorCode = "SEARCH_APPLIER_EVENT_INVALID"
	CodeProfileUnavailable ErrorCode = "SEARCH_APPLIER_PROFILE_UNAVAILABLE"
	CodeIndexFailed        ErrorCode = "SEARCH_APPLIER_INDEX_FAILED"
	CodePublishFailed      ErrorCode = "SEARCH_APPLIER_PUBLISH_FAILED"
)

// reindexPageSize bounds one database page of the re-index pass. It is a
// server-owned constant, never a request or payload value.
const reindexPageSize = 200

// reindexConcurrency bounds how many chunks of one page are rebuilt at once.
// Each is an independent idempotent PUT; the bound keeps the pass from
// saturating the embedding runtime or the index while the rest of the worker
// loop keeps running. Server-owned constant, never a request value.
const reindexConcurrency = 2

var reobservationEventID = regexp.MustCompile(`^searchupd_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// DiagnosticClass names the nested dependency an applier failure came from,
// so an operator reading worker logs can tell an embedding-channel outage
// apart from an index transport failure without the log ever naming a
// tenant, chunk, profile or any corpus content. It mirrors
// governedask.DiagnosticClass.
func DiagnosticClass(err error) string {
	if err == nil {
		return ""
	}
	var embeddingError *embedding.Error
	if errors.As(err, &embeddingError) {
		return string(embedding.CodeOf(err))
	}
	return ""
}

// Applier is the worker-side bridge from the tenant-scoped durable outbox to
// one generation-bound OpenSearch alias.  The database remains authoritative:
// an event is marked published only after the idempotent OpenSearch PUT has
// succeeded, and a retry of a committed PUT is safe.
type Applier struct {
	db         *database.Store
	repository *Repository
	codec      *artifactcrypto.Codec
	client     *Client
	embedding  *embedding.Client
}

func NewApplier(db *database.Store, repository *Repository, codec *artifactcrypto.Codec, client *Client) (*Applier, error) {
	return newApplier(db, repository, codec, client, nil)
}

// NewApplierWithEmbedding enables vector indexing only when the same
// administrator-owned profile is configured on the embedding gateway and
// OpenSearch client. A lexical client can never be upgraded by request data or
// by an outbox payload.
func NewApplierWithEmbedding(db *database.Store, repository *Repository, codec *artifactcrypto.Codec, client *Client, embeddingClient *embedding.Client) (*Applier, error) {
	if embeddingClient == nil {
		return nil, &Error{code: CodeProfileUnavailable}
	}
	return newApplier(db, repository, codec, client, embeddingClient)
}

func newApplier(db *database.Store, repository *Repository, codec *artifactcrypto.Codec, client *Client, embeddingClient *embedding.Client) (*Applier, error) {
	if db == nil || repository == nil || codec == nil || client == nil {
		return nil, &Error{code: CodeInvalid}
	}
	if embeddingClient != nil {
		profile := embeddingClient.Profile()
		profileHash, dimension := client.VectorProfile()
		if profileHash != profile.ProfileHash || dimension != profile.Dimension {
			return nil, &Error{code: CodeProfileUnavailable}
		}
	}
	return &Applier{db: db, repository: repository, codec: codec, client: client, embedding: embeddingClient}, nil
}

type pendingOutboxEvent struct {
	ID            string
	Sequence      int64
	AggregateType string
	AggregateID   string
	EventType     string
	Payload       []byte
}

type searchChunkEvent struct {
	Operation                  string `json:"operation"`
	SearchChunkID              string `json:"search_chunk_id"`
	SourceVersionID            string `json:"source_version_id"`
	ExtractionID               string `json:"extraction_id"`
	ArtifactID                 string `json:"artifact_id"`
	TextHash                   string `json:"text_hash"`
	EmbeddingProfileHash       string `json:"embedding_profile_hash"`
	EmbeddingModelArtifactHash string `json:"embedding_model_artifact_hash"`
	Dimension                  int    `json:"dimension"`
}

type searchChunkMetadata struct {
	ProfileRevision      int64
	SourceObjectID       string
	SourceVersionID      string
	ExtractionID         string
	ChunkHash            string
	ArtifactID           string
	EmbeddingProfileHash string
	ContentHash          string
	EvidenceFragmentIDs  []string
	EvidenceTextHashes   []string
	EvidenceAnchorHashes []string
	EvidenceFragmentID   string
	EvidenceTextHash     string
	AnchorHash           string
	SourceScopeIDs       []string
	VersionState         string
	Generation           int64
	GenerationFence      int64
	ProfileStatus        string
}

// ApplyOnce processes at most one event.  It returns false,nil for an empty
// queue.  The method intentionally performs the network PUT outside the
// database transaction, then executes a narrow publication function; a crash
// between those operations is convergent on retry.
func (applier *Applier) ApplyOnce(ctx context.Context, access database.AccessContext) (bool, error) {
	if applier == nil || applier.db == nil || applier.repository == nil || applier.codec == nil || applier.client == nil || ctx == nil || access.Validate() != nil {
		return false, &Error{code: CodeInvalid}
	}
	event, found, err := applier.readNext(ctx, access)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	if event.AggregateType != "SEARCH_CHUNK" ||
		(event.EventType != "search.chunk.upsert" && event.EventType != "search.chunk.delete") {
		return false, &Error{code: CodeBlocked}
	}
	payload, err := parseSearchChunkEvent(event, access.OrganizationID)
	if err != nil {
		return false, err
	}
	if payload.Operation == "DELETE" {
		if err := applier.client.DeleteProfileCopies(ctx, payload.SearchChunkID); err != nil {
			return false, &Error{code: CodeIndexFailed, cause: err}
		}
		if err := applier.publish(ctx, access, event); err != nil {
			return false, err
		}
		return true, nil
	}
	document, err := applier.loadDocument(ctx, access, event, payload)
	if err != nil {
		// A purge can race an unpublished UPSERT.  The retention transition is
		// authoritative and the encrypted text has already been erased, so the
		// only safe convergence is an idempotent external DELETE followed by
		// publication of that original event.  Without this branch a stale
		// UPSERT would permanently block the later durable DELETE event.
		if CodeOf(err) == CodeProfileUnavailable {
			purged, purgeErr := applier.versionPurged(ctx, access, payload.SourceVersionID)
			if purgeErr != nil {
				return false, purgeErr
			}
			if purged {
				if deleteErr := applier.client.DeleteProfileCopies(ctx, payload.SearchChunkID); deleteErr != nil {
					return false, &Error{code: CodeIndexFailed, cause: deleteErr}
				}
				if publishErr := applier.publish(ctx, access, event); publishErr != nil {
					return false, publishErr
				}
				return true, nil
			}
			if applied, missingErr := applier.publishMissing(ctx, access, event, payload); missingErr != nil || applied {
				return applied, missingErr
			}
			if applied, obsoleteErr := applier.publishSuperseded(ctx, access, event, payload); obsoleteErr != nil || applied {
				return applied, obsoleteErr
			}
		}
		return false, err
	}
	if err := applier.client.Index(ctx, document); err != nil {
		clearVector(document.Embedding)
		return false, &Error{code: CodeIndexFailed, cause: err}
	}
	clearVector(document.Embedding)
	if err := applier.publish(ctx, access, event); err != nil {
		return false, err
	}
	return true, nil
}

// Drain applies a bounded number of events and stops at the first empty queue.
// A non-search event or a failed dependency is returned immediately; no
// best-effort skip can weaken tenant sequence or generation fencing.
func (applier *Applier) Drain(ctx context.Context, access database.AccessContext, maximum int) (int, error) {
	if maximum < 1 || maximum > 10000 {
		return 0, &Error{code: CodeInvalid}
	}
	count := 0
	for count < maximum {
		applied, err := applier.ApplyOnce(ctx, access)
		if err != nil {
			return count, err
		}
		if !applied {
			return count, nil
		}
		count++
	}
	return count, nil
}

// Reindex rebuilds alias documents for the tenant under this worker's mounted
// vector space. It is the durable, resumable half of an operator's
// profile-revision command (migration 000072): every currently indexable chunk
// is re-loaded through the same document loader an outbox event uses and
// re-written with an idempotent PUT keyed by chunk id, so the document's vector
// belongs to the staged embedding profile. The pass never invents lineage — a
// chunk whose version/extraction/retention state no longer admits indexing is
// left to the ordinary outbox path — and it never carries plaintext or a vector
// across a batch boundary.
//
// The pass is resumable: it starts after afterChunkID and returns the chunk id
// to continue from, or an empty cursor once the corpus is exhausted. A caller
// drives it in lease-sized slices so a long re-index heartbeats instead of
// losing its job lease.
func (applier *Applier) Reindex(ctx context.Context, access database.AccessContext,
	afterChunkID string, budget int) (int, string, error) {
	if applier == nil || applier.db == nil || applier.repository == nil || applier.codec == nil ||
		applier.client == nil || ctx == nil || access.Validate() != nil {
		return 0, "", &Error{code: CodeInvalid}
	}
	if budget < 1 || budget > 100000 || (afterChunkID != "" && !validOpaque(afterChunkID)) {
		return 0, "", &Error{code: CodeInvalid}
	}
	cursor := afterChunkID
	indexed := 0
	for indexed < budget {
		var references []ChunkReference
		if err := applier.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
			var readErr error
			references, readErr = applier.repository.ChunksForReindex(txCtx, tx, access, cursor, reindexPageSize)
			return readErr
		}); err != nil {
			return indexed, cursor, err
		}
		if len(references) == 0 {
			return indexed, "", nil
		}
		// One page is rebuilt by a small, fixed pool. Each chunk is an
		// independent, idempotent PUT keyed by its own id, re-validated through
		// the same document loader, so the only thing concurrency changes is how
		// long a tenant waits for its corpus: a sequential pass spends almost all
		// of its time waiting on three network round trips per chunk (database,
		// embedding, index) and takes long enough that the rest of the worker
		// loop is visibly starved. The pool is server-owned and fixed; no request
		// or payload can widen it.
		remaining := budget - indexed
		page := references
		if len(page) > remaining {
			page = page[:remaining]
		}
		cursor = page[len(page)-1].ChunkID
		var (
			mutex     sync.Mutex
			written   int
			failure   error
			workGroup sync.WaitGroup
			slots     = make(chan struct{}, reindexConcurrency)
		)
		for _, reference := range page {
			slots <- struct{}{}
			workGroup.Add(1)
			go func(reference ChunkReference) {
				defer workGroup.Done()
				defer func() { <-slots }()
				mutex.Lock()
				stop := failure != nil
				mutex.Unlock()
				if stop || ctx.Err() != nil {
					return
				}
				event := pendingOutboxEvent{ID: reference.ChunkID, Sequence: 1, AggregateType: "SEARCH_CHUNK",
					AggregateID: reference.ChunkID, EventType: "search.chunk.upsert"}
				payload := searchChunkEvent{Operation: "UPSERT", SearchChunkID: reference.ChunkID,
					EmbeddingProfileHash: reference.EmbeddingProfileHash,
					SourceVersionID:      reference.SourceVersionID, ExtractionID: reference.ExtractionID,
					ArtifactID: reference.ArtifactID, TextHash: reference.TextHash}
				document, err := applier.loadDocument(ctx, access, event, payload)
				if err != nil {
					// Not indexable right now (purged, superseded extraction, an
					// alias generation this worker does not own). The durable
					// outbox remains the authority for that chunk.
					if CodeOf(err) == CodeProfileUnavailable {
						return
					}
					mutex.Lock()
					if failure == nil {
						failure = err
					}
					mutex.Unlock()
					return
				}
				indexErr := applier.client.Index(ctx, document)
				clearVector(document.Embedding)
				mutex.Lock()
				if indexErr != nil {
					if failure == nil {
						failure = &Error{code: CodeIndexFailed, cause: indexErr}
					}
				} else {
					written++
				}
				mutex.Unlock()
			}(reference)
		}
		workGroup.Wait()
		indexed += written
		if failure != nil {
			return indexed, cursor, failure
		}
		if ctx.Err() != nil {
			return indexed, cursor, ctx.Err()
		}
		if len(references) < reindexPageSize {
			return indexed, "", nil
		}
	}
	return indexed, cursor, nil
}

func (applier *Applier) readNext(ctx context.Context, access database.AccessContext) (pendingOutboxEvent, bool, error) {
	var event pendingOutboxEvent
	err := applier.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var payload string
		query := `
			SELECT event_id, event_sequence, aggregate_type, aggregate_id,
			       event_type, payload_json::text
			  FROM app.search_chunk_outbox_next()`
		err := tx.QueryRow(txCtx, query).Scan(&event.ID, &event.Sequence, &event.AggregateType, &event.AggregateID, &event.EventType, &payload)
		if err != nil {
			return err
		}
		event.Payload = []byte(payload)
		return nil
	})
	if database.IsNotFound(err) {
		return pendingOutboxEvent{}, false, nil
	}
	if err != nil {
		return pendingOutboxEvent{}, false, &Error{code: CodePersistence, cause: err}
	}
	if event.Sequence < 1 || event.Sequence > maximumGeneration || !validOpaque(event.ID) || !validOpaque(event.AggregateID) || !validOpaque(event.AggregateType) || !validOpaque(event.EventType) || len(event.Payload) == 0 || len(event.Payload) > 64<<10 {
		return pendingOutboxEvent{}, false, &Error{code: CodeEventInvalid}
	}
	return event, true, nil
}

func parseSearchChunkEvent(event pendingOutboxEvent, organizationID string) (searchChunkEvent, error) {
	if event.AggregateType != "SEARCH_CHUNK" ||
		(event.EventType != "search.chunk.upsert" && event.EventType != "search.chunk.delete") ||
		event.AggregateID == "" || organizationID == "" {
		return searchChunkEvent{}, &Error{code: CodeEventInvalid}
	}
	var payload searchChunkEvent
	if err := jsonv2.Unmarshal(event.Payload, &payload, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return searchChunkEvent{}, &Error{code: CodeEventInvalid, cause: err}
	}
	if payload.SearchChunkID != event.AggregateID || !validOpaque(payload.SearchChunkID) ||
		!validOpaque(payload.SourceVersionID) {
		return searchChunkEvent{}, &Error{code: CodeEventInvalid}
	}
	if event.EventType == "search.chunk.delete" {
		if payload.Operation != "DELETE" || payload.ExtractionID != "" || payload.ArtifactID != "" ||
			payload.TextHash != "" || payload.EmbeddingProfileHash != "" ||
			payload.EmbeddingModelArtifactHash != "" || payload.Dimension != 0 {
			return searchChunkEvent{}, &Error{code: CodeEventInvalid}
		}
		return payload, nil
	}
	if (event.AggregateID != event.ID && !reobservationEventID.MatchString(event.ID)) || payload.Operation != "UPSERT" ||
		!validOpaque(payload.ExtractionID) || !validOpaque(payload.ArtifactID) ||
		!validSHA256(payload.TextHash) {
		return searchChunkEvent{}, &Error{code: CodeEventInvalid}
	}
	profileEmpty := payload.EmbeddingProfileHash == ""
	modelEmpty := payload.EmbeddingModelArtifactHash == ""
	dimensionEmpty := payload.Dimension == 0
	if profileEmpty || modelEmpty || dimensionEmpty {
		if !(profileEmpty && modelEmpty && dimensionEmpty) {
			return searchChunkEvent{}, &Error{code: CodeEventInvalid}
		}
	} else if !validSHA256(payload.EmbeddingProfileHash) ||
		!validSHA256(payload.EmbeddingModelArtifactHash) || payload.Dimension < 1 || payload.Dimension > 65536 {
		return searchChunkEvent{}, &Error{code: CodeEventInvalid}
	}
	return payload, nil
}

func (applier *Applier) loadDocument(ctx context.Context, access database.AccessContext, event pendingOutboxEvent, payload searchChunkEvent) (IndexDocument, error) {
	var document IndexDocument
	err := applier.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var metadata searchChunkMetadata
		var embeddingProfileHash *string
		var targetProfileHash *string
		if err := tx.QueryRow(txCtx, `
			SELECT version.source_object_id, chunk.source_version_id, chunk.extraction_id,
			       chunk.chunk_hash, chunk.search_text_artifact_id,
			       chunk.embedding_profile_hash, version.content_hash,
			       (SELECT array_agg(all_fragment.evidence_fragment_id ORDER BY all_fragment.ordinal)
			          FROM public.search_chunk_fragment AS all_fragment
			         WHERE all_fragment.organization_id = chunk.organization_id
			           AND all_fragment.search_chunk_id = chunk.id),
			       (SELECT array_agg(all_evidence.text_hash ORDER BY all_fragment.ordinal)
			          FROM public.search_chunk_fragment AS all_fragment
			          JOIN public.evidence_fragment AS all_evidence
			            ON all_evidence.organization_id = all_fragment.organization_id
			           AND all_evidence.id = all_fragment.evidence_fragment_id
			         WHERE all_fragment.organization_id = chunk.organization_id
			           AND all_fragment.search_chunk_id = chunk.id),
			       (SELECT array_agg(all_evidence.anchor_hash ORDER BY all_fragment.ordinal)
			          FROM public.search_chunk_fragment AS all_fragment
			          JOIN public.evidence_fragment AS all_evidence
			            ON all_evidence.organization_id = all_fragment.organization_id
			           AND all_evidence.id = all_fragment.evidence_fragment_id
			         WHERE all_fragment.organization_id = chunk.organization_id
			           AND all_fragment.search_chunk_id = chunk.id),
			       fragment.evidence_fragment_id, evidence.text_hash, evidence.anchor_hash,
			       -- The scope memberships of the object carry into the index so
			       -- a workspace's retrieval query can narrow candidates to the
			       -- scopes it binds before ranking them. They are a narrowing
			       -- hint only: app.evidence_fragment_readable remains the
			       -- authority on every hit that comes back.
			       (SELECT array_agg(DISTINCT membership.source_scope_id)
			          FROM public.source_object_scope AS membership
			         WHERE membership.organization_id = object.organization_id
			           AND membership.source_object_id = object.id
			           AND membership.membership_state = 'ACTIVE'),
			       version.state,
			       profile.index_generation, profile.generation_fence, profile.status, profile.activation_revision, profile.embedding_profile_hash
			  FROM public.search_chunk AS chunk
			  JOIN public.source_version AS version
			    ON version.organization_id = chunk.organization_id
			   AND version.id = chunk.source_version_id
			  JOIN public.source_object AS object
			    ON object.organization_id = version.organization_id
			   AND object.id = version.source_object_id
			  JOIN public.source_extraction AS extraction
			    ON extraction.organization_id = chunk.organization_id
			   AND extraction.id = chunk.extraction_id
			   AND extraction.source_version_id = chunk.source_version_id
			  JOIN public.source_version_retention AS version_retention
			    ON version_retention.organization_id = chunk.organization_id
			   AND version_retention.source_version_id = chunk.source_version_id
			  JOIN public.source_extraction_retention AS extraction_retention
			    ON extraction_retention.organization_id = chunk.organization_id
			   AND extraction_retention.extraction_id = chunk.extraction_id
			  JOIN public.source_version_active_extraction AS active_extraction
			    ON active_extraction.organization_id = chunk.organization_id
			   AND active_extraction.source_version_id = chunk.source_version_id
			   AND active_extraction.extraction_id = chunk.extraction_id
			  JOIN public.search_chunk_fragment AS fragment
			    ON fragment.organization_id = chunk.organization_id
			   AND fragment.search_chunk_id = chunk.id
			  JOIN public.evidence_fragment AS evidence
			    ON evidence.organization_id = fragment.organization_id
			   AND evidence.id = fragment.evidence_fragment_id
			  JOIN LATERAL (
			        -- Migration 000072 makes the retrieval profile an
			        -- append-only revision sequence. An index write belongs to
			        -- the revision currently being built when one is staged and
			        -- otherwise to the active revision; superseded and failed
			        -- revisions never accept a write.
			        SELECT candidate.index_generation, candidate.generation_fence, candidate.status, candidate.activation_revision, candidate.embedding_profile_hash
			          FROM public.organization_search_profile AS candidate
			         WHERE candidate.organization_id = chunk.organization_id
			           AND candidate.status IN ('STAGING', 'ACTIVE')
			         ORDER BY candidate.activation_revision DESC
			         LIMIT 1
			       ) AS profile ON TRUE
			 WHERE chunk.organization_id = $1
			   AND chunk.id = $2
			   AND object.lifecycle_state = 'ACTIVE'
			   AND object.current_version_id = version.id
			   AND version.state = 'CURRENT'
			   AND extraction.status = 'SUCCEEDED'
			   AND version_retention.state = 'ACTIVE'
			   AND version_retention.queryable
			   AND extraction_retention.state = 'ACTIVE'
			   AND extraction_retention.queryable
			 ORDER BY fragment.ordinal
			 LIMIT 1`, access.OrganizationID, payload.SearchChunkID).Scan(
			&metadata.SourceObjectID, &metadata.SourceVersionID, &metadata.ExtractionID,
			&metadata.ChunkHash, &metadata.ArtifactID, &embeddingProfileHash,
			&metadata.ContentHash, &metadata.EvidenceFragmentIDs, &metadata.EvidenceTextHashes,
			&metadata.EvidenceAnchorHashes, &metadata.EvidenceFragmentID, &metadata.EvidenceTextHash,
			&metadata.AnchorHash, &metadata.SourceScopeIDs, &metadata.VersionState,
			&metadata.Generation, &metadata.GenerationFence,
			&metadata.ProfileStatus, &metadata.ProfileRevision, &targetProfileHash); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeProfileUnavailable}
			}
			return &Error{code: CodePersistence, cause: err}
		}
		if embeddingProfileHash != nil {
			metadata.EmbeddingProfileHash = *embeddingProfileHash
		}
		if metadata.ProfileRevision > 1 && (targetProfileHash == nil || *targetProfileHash != applier.client.vectorProfileHash) {
			return &Error{code: CodeConflict}
		}
		if metadata.VersionState != VersionStateCurrent ||
			len(metadata.SourceScopeIDs) == 0 || len(metadata.SourceScopeIDs) > maximumDocumentScopeIDs {
			// A passage with no active scope membership is not reachable from
			// any workspace, so indexing it would only add an unauthorizable
			// candidate to every k-NN walk.
			return &Error{code: CodeProfileUnavailable}
		}
		if (metadata.ProfileStatus != RevisionActive && metadata.ProfileStatus != RevisionStaging) ||
			metadata.SourceVersionID != payload.SourceVersionID ||
			metadata.ExtractionID != payload.ExtractionID || metadata.ArtifactID != payload.ArtifactID ||
			metadata.ChunkHash != payload.TextHash || metadata.EmbeddingProfileHash != payload.EmbeddingProfileHash ||
			metadata.Generation != applier.client.generation || metadata.GenerationFence != applier.client.generationFence ||
			metadata.Generation < 1 || metadata.GenerationFence < 1 || !validSHA256(metadata.ContentHash) ||
			!validDigest(metadata.EvidenceTextHash) || !validDigest(metadata.AnchorHash) ||
			len(metadata.EvidenceFragmentIDs) == 0 ||
			len(metadata.EvidenceTextHashes) != len(metadata.EvidenceFragmentIDs) ||
			len(metadata.EvidenceAnchorHashes) != len(metadata.EvidenceFragmentIDs) {
			return &Error{code: CodeProfileUnavailable}
		}
		for index := range metadata.EvidenceFragmentIDs {
			if !validOpaque(metadata.EvidenceFragmentIDs[index]) ||
				!validDigest(metadata.EvidenceTextHashes[index]) ||
				!validDigest(metadata.EvidenceAnchorHashes[index]) {
				return &Error{code: CodeProfileUnavailable}
			}
		}
		plaintext, err := applier.repository.ReadText(txCtx, tx, access, applier.codec, payload.SearchChunkID)
		if err != nil {
			return &Error{code: CodePersistence, cause: err}
		}
		defer clearBytes(plaintext)
		if len(plaintext) == 0 || len(plaintext) > maximumTextBytes || !utf8.Valid(plaintext) || string(plaintext) == "" {
			return &Error{code: CodeEventInvalid}
		}
		document = IndexDocument{
			ProfileRevision: metadata.ProfileRevision,
			ID:              payload.SearchChunkID, OrganizationID: access.OrganizationID,
			SourceObjectID: metadata.SourceObjectID, SourceVersionID: metadata.SourceVersionID,
			ExtractionID: metadata.ExtractionID, EvidenceFragmentID: metadata.EvidenceFragmentID,
			EvidenceFragmentIDs:  append([]string(nil), metadata.EvidenceFragmentIDs...),
			EvidenceTextHashes:   append([]string(nil), metadata.EvidenceTextHashes...),
			EvidenceAnchorHashes: append([]string(nil), metadata.EvidenceAnchorHashes...),
			Text:                 string(plaintext), ContentHash: metadata.ContentHash, TextHash: metadata.EvidenceTextHash,
			AnchorHash:     metadata.AnchorHash,
			SourceScopeIDs: append([]string(nil), metadata.SourceScopeIDs...),
			// The loader admits a chunk only while its version is the object's
			// CURRENT one, so the indexed lifecycle value is that state and
			// never a guess.
			VersionState: metadata.VersionState,
			Generation:   metadata.Generation, GenerationFence: metadata.GenerationFence,
		}
		if applier.embedding != nil && metadata.EmbeddingProfileHash != "" {
			document.EmbeddingProfileHash = metadata.EmbeddingProfileHash
		}
		return nil
	})
	if err != nil {
		return IndexDocument{}, err
	}
	if document.ID != event.AggregateID || document.OrganizationID != access.OrganizationID {
		return IndexDocument{}, &Error{code: CodeEventInvalid}
	}
	if applier.embedding != nil {
		profile := applier.embedding.Profile()
		// The chunk's original embedding identity was validated against its
		// durable payload above. A profile revision deliberately recomputes it
		// in the newly mounted space, preserving the text and lineage.
		// Indexing is tenant-scoped rather than user/workspace-scoped: the
		// source object may belong to several workspaces. The purpose and chunk
		// ID are server-owned binding values; neither is sent to the provider.
		// A corpus is not a prompt. Real passages — source files, exports,
		// office documents — carry form feeds, escape sequences and bidi
		// controls that the embedding channel's input contract rejects, and a
		// single such passage would otherwise stop the whole projection. The
		// passage itself is untouched: this is only the projection sent to the
		// model, and every citation, disclosure and lexical match still comes
		// from the stored text.
		embeddable, ok := EmbeddableText(document.Text, profile.MaxInputBytes)
		if !ok {
			return IndexDocument{}, &Error{code: CodeEventInvalid}
		}
		vector, embedErr := applier.embedding.Embed(ctx, embedding.Binding{
			OrganizationID: access.OrganizationID,
			WorkspaceID:    "search-index",
			OperationID:    payload.SearchChunkID,
			ProfileHash:    profile.ProfileHash,
		}, embeddable)
		if embedErr != nil {
			return IndexDocument{}, &Error{code: CodeIndexFailed, cause: embedErr}
		}
		document.EmbeddingProfileHash = vector.ProfileHash
		document.EmbeddingDimension = vector.Dimension
		document.Embedding = vector.Vector
	}
	return document, nil
}

func (applier *Applier) publish(ctx context.Context, access database.AccessContext, event pendingOutboxEvent) error {
	var published bool
	err := applier.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `SELECT app.publish_search_chunk_outbox($1, $2)`, event.ID, event.Sequence).Scan(&published)
	})
	if err != nil || !published {
		return &Error{code: CodePublishFailed, cause: err}
	}
	return nil
}

// EmbeddableText projects one passage into the canonical, control-free,
// budget-bounded input the embedding profile accepts. It never changes what is
// stored, cited or disclosed — only what is handed to the model to derive a
// vector from — and it reports false rather than sending something empty.
//
// Both consumers of the one embedding channel use it, and must: real corpora
// carry form feeds, escape sequences and bidi controls that the channel's input
// contract rejects outright, so without this a single such passage silently
// removes itself from semantic retrieval (indexing side) or fails a claim that
// its own evidence supports (GENERATIVE verification side).
func EmbeddableText(raw string, maximumBytes int) (string, bool) {
	if raw == "" || maximumBytes < 1 {
		return "", false
	}
	canonical, err := canon.Canonicalize([]byte(raw))
	if err != nil {
		return "", false
	}
	var builder strings.Builder
	builder.Grow(len(canonical))
	for _, character := range string(canonical) {
		if character == '\n' || character == '\t' {
			builder.WriteRune(character)
			continue
		}
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) ||
			(character >= 0x202A && character <= 0x202E) ||
			(character >= 0x2066 && character <= 0x2069) {
			builder.WriteRune(' ')
			continue
		}
		builder.WriteRune(character)
	}
	value := builder.String()
	if len(value) > maximumBytes {
		cut := maximumBytes
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut]
	}
	// Re-canonicalize so the value the channel receives is byte-identical to
	// its own canonical form (the channel refuses anything else).
	final, err := canon.Canonicalize([]byte(value))
	if err != nil || len(final) == 0 || len(final) > maximumBytes || strings.TrimSpace(string(final)) == "" {
		return "", false
	}
	return string(final), true
}

func (applier *Applier) versionPurged(ctx context.Context, access database.AccessContext, versionID string) (bool, error) {
	if applier == nil || applier.db == nil || ctx == nil || access.Validate() != nil || !validOpaque(versionID) {
		return false, &Error{code: CodeInvalid}
	}
	var purged bool
	err := applier.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT state IN ('PURGING', 'PURGED')
			  FROM public.source_version_retention
			 WHERE organization_id=$1 AND source_version_id=$2`, access.OrganizationID, versionID).Scan(&purged)
	})
	if database.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, &Error{code: CodePersistence, cause: err}
	}
	return purged, nil
}

// Observed absence is a temporary database disclosure gate, not physical
// erasure. Skip an exact pending UPSERT while no scope can read the object.
// Restoration emits a fresh event. In particular, issue no reversible DELETE:
// a timed-out remote DELETE could otherwise overtake the later restoration PUT.
func (applier *Applier) publishMissing(ctx context.Context, access database.AccessContext,
	event pendingOutboxEvent, payload searchChunkEvent) (bool, error) {
	var applied bool
	err := applier.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var state string
		if err := tx.QueryRow(txCtx, `SELECT object.lifecycle_state
			FROM public.source_object AS object
			JOIN public.source_version AS version ON version.organization_id=object.organization_id AND version.source_object_id=object.id
			JOIN public.search_chunk AS chunk ON chunk.organization_id=version.organization_id AND chunk.source_version_id=version.id
			WHERE object.organization_id=$1 AND chunk.id=$2 AND version.id=$3
			AND chunk.extraction_id=$4 AND chunk.search_text_artifact_id=$5 AND chunk.chunk_hash=$6
            AND COALESCE(chunk.embedding_profile_hash,'')=$7 AND COALESCE(chunk.embedding_model_artifact_hash,'')=$8 AND COALESCE(chunk.embedding_dimension,0)=$9
			FOR SHARE OF object`, access.OrganizationID, payload.SearchChunkID, payload.SourceVersionID,
			payload.ExtractionID, payload.ArtifactID, payload.TextHash, payload.EmbeddingProfileHash, payload.EmbeddingModelArtifactHash, payload.Dimension).Scan(&state); err != nil {
			if database.IsNotFound(err) {
				return nil
			}
			return err
		}
		if state != "MISSING" {
			return nil
		}
		// This second statement observes memberships after obtaining the object
		// lock. Presence publication always takes that same lock first.
		var eligible bool
		if err := tx.QueryRow(txCtx, `SELECT NOT EXISTS (
			SELECT 1 FROM public.source_object_scope AS membership
			JOIN public.source_version AS version ON version.organization_id=membership.organization_id AND version.source_object_id=membership.source_object_id
			WHERE version.organization_id=$1 AND version.id=$2 AND membership.membership_state='ACTIVE')
			AND EXISTS (SELECT 1 FROM (
			SELECT index_generation, generation_fence FROM public.organization_search_profile
			WHERE organization_id=$1 AND status IN ('STAGING','ACTIVE') ORDER BY activation_revision DESC LIMIT 1
			) AS profile WHERE index_generation=$3 AND generation_fence=$4)`,
			access.OrganizationID, payload.SourceVersionID, applier.client.generation, applier.client.generationFence).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return nil
		}
		if err := tx.QueryRow(txCtx, `SELECT app.publish_search_chunk_outbox($1,$2)`, event.ID, event.Sequence).Scan(&applied); err != nil || !applied {
			return &Error{code: CodePublishFailed, cause: err}
		}
		return nil
	})
	if err != nil {
		return false, &Error{code: CodePersistence, cause: err}
	}
	return applied, nil
}

// A changed observation can supersede an immutable version before its first
// UPSERT drains. That version can never become CURRENT again, and its chunk ID
// cannot identify the replacement version's projection. Delete only this exact
// obsolete chunk, then acknowledge its original event. Retained Evidence and
// historical reads remain intact; an arbitrary profile failure is not absence.
func (applier *Applier) publishSuperseded(ctx context.Context, access database.AccessContext,
	event pendingOutboxEvent, payload searchChunkEvent) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var applied bool
	err := applier.db.Write(bounded, access, func(txCtx context.Context, tx database.Transaction) error {
		var obsolete bool
		if err := tx.QueryRow(txCtx, `SELECT true
			FROM public.search_chunk AS chunk
			JOIN public.source_version AS version ON version.organization_id=chunk.organization_id AND version.id=chunk.source_version_id
			JOIN public.source_object AS object ON object.organization_id=version.organization_id AND object.id=version.source_object_id
			JOIN public.source_extraction AS extraction ON extraction.organization_id=chunk.organization_id AND extraction.id=chunk.extraction_id AND extraction.source_version_id=version.id
			JOIN public.source_version_retention AS vr ON vr.organization_id=version.organization_id AND vr.source_version_id=version.id
			JOIN public.source_extraction_retention AS er ON er.organization_id=extraction.organization_id AND er.extraction_id=extraction.id
			JOIN LATERAL (SELECT index_generation,generation_fence,activation_revision,embedding_profile_hash
				FROM public.organization_search_profile WHERE organization_id=chunk.organization_id AND status IN ('STAGING','ACTIVE')
				ORDER BY activation_revision DESC LIMIT 1 FOR SHARE) AS profile ON true
			WHERE chunk.organization_id=$1 AND chunk.id=$2 AND version.id=$3
			AND extraction.id=$4 AND chunk.search_text_artifact_id=$5 AND chunk.chunk_hash=$6
			AND COALESCE(chunk.embedding_profile_hash,'')=$7 AND COALESCE(chunk.embedding_model_artifact_hash,'')=$8 AND COALESCE(chunk.embedding_dimension,0)=$9
			AND version.state='SUPERSEDED' AND object.current_version_id IS NOT NULL AND object.current_version_id<>version.id
			AND extraction.status='SUCCEEDED' AND vr.state='ACTIVE' AND vr.queryable AND vr.extraction_allowed
			AND er.state='ACTIVE' AND er.queryable AND extraction.retention_fence_at_start=vr.retention_fence
			AND profile.index_generation=$10 AND profile.generation_fence=$11
			AND (profile.activation_revision=1 OR profile.embedding_profile_hash=$12)
			FOR SHARE OF vr,er`, access.OrganizationID, payload.SearchChunkID, payload.SourceVersionID,
			payload.ExtractionID, payload.ArtifactID, payload.TextHash, payload.EmbeddingProfileHash,
			payload.EmbeddingModelArtifactHash, payload.Dimension, applier.client.generation,
			applier.client.generationFence, applier.client.vectorProfileHash).Scan(&obsolete); err != nil {
			if database.IsNotFound(err) {
				return nil
			}
			return err
		}
		if !obsolete {
			return nil
		}
		if err := applier.client.DeleteProfileCopies(txCtx, payload.SearchChunkID); err != nil {
			return &Error{code: CodeIndexFailed, cause: err}
		}
		if err := tx.QueryRow(txCtx, `SELECT app.publish_search_chunk_outbox($1,$2)`, event.ID, event.Sequence).Scan(&applied); err != nil || !applied {
			return &Error{code: CodePublishFailed, cause: err}
		}
		return nil
	})
	if err != nil {
		var classified *Error
		if errors.As(err, &classified) {
			return false, classified
		}
		return false, &Error{code: CodePersistence, cause: err}
	}
	return applied, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clearVector(value []float32) {
	for index := range value {
		value[index] = 0
	}
}
