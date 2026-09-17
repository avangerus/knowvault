package search

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	artifactrepository "knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// Repository is the worker-side durable projection boundary. It owns the
// typed SQL needed to create a SearchChunk, bind its encrypted text and attach
// exact Evidence fragments. It intentionally has no OpenSearch handle: the
// database row and ordered outbox are the source of truth for a later applier.
type Repository struct {
	artifacts *artifactrepository.Repository
}

// NewRepository activates only the SearchChunk text owner branch. A nil or
// incomplete repository is never usable by a worker.
func NewRepository() (*Repository, error) {
	binding, err := artifactrepository.NewBinding(
		artifactcrypto.SearchChunkText,
		"app.search_chunk_bind_text",
		"app.search_chunk_read_text",
		workerAuthorize,
	)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	store, err := artifactrepository.New(binding)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	return &Repository{artifacts: store}, nil
}

// Chunk is the immutable, tenant-bound search projection metadata. Text is
// never carried here; it is sealed through the SearchChunkText owner branch.
// Embedding fields are an optional all-or-nothing tuple. A lexical chunk is
// valid without them; a vector chunk must carry the deployment-qualified
// profile, model artifact and dimension together. This keeps lexical
// ingestion live while refusing to invent vector provenance before a real
// embedding provider is qualified.
type Chunk struct {
	ID                         string
	OrganizationID             string
	SourceVersionID            string
	ExtractionID               string
	ChunkHash                  string
	TokenCount                 int64
	EmbeddingProfileHash       string
	EmbeddingModelArtifactHash string
	EmbeddingDimension         int
}

// CreateChunk inserts the immutable row and binds its encrypted text in one
// caller transaction. The database trigger verifies extraction retention and
// the deferred owner trigger verifies exact artifact/hash ownership.
func (repository *Repository) CreateChunk(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, chunk Chunk, artifactID string, envelope artifactcrypto.Envelope) error {
	if repository == nil || repository.artifacts == nil || ctx == nil || !transaction.Valid() ||
		access.Validate() != nil || !validChunk(chunk, access.OrganizationID) ||
		!validOpaque(artifactID) || !envelope.Valid() || envelope.OrganizationID() != access.OrganizationID ||
		envelope.ResourceID() != chunk.ID || envelope.PlaintextHash() != chunk.ChunkHash {
		return &Error{code: CodeInvalid}
	}
	embeddingProfileHash, embeddingModelArtifactHash, embeddingDimension := any(nil), any(nil), any(nil)
	if chunk.EmbeddingProfileHash != "" {
		embeddingProfileHash = chunk.EmbeddingProfileHash
		embeddingModelArtifactHash = chunk.EmbeddingModelArtifactHash
		embeddingDimension = chunk.EmbeddingDimension
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.search_chunk
			(organization_id, id, source_version_id, extraction_id, chunk_hash,
			 search_text_artifact_id, token_count, embedding_profile_hash,
			 embedding_model_artifact_hash, embedding_dimension)
		VALUES ($1,$2,$3,$4,$5,NULL,$6,$7,$8,$9)`,
		chunk.OrganizationID, chunk.ID, chunk.SourceVersionID, chunk.ExtractionID,
		chunk.ChunkHash, chunk.TokenCount, embeddingProfileHash,
		embeddingModelArtifactHash, embeddingDimension); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if err := repository.artifacts.Store(ctx, transaction, access, artifactcrypto.SearchChunkText,
		chunk.ID, artifactID, envelope); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	// Publication is part of the same transaction as the durable row and its
	// encrypted text owner. The narrow worker-only function emits references and
	// hashes only; it never places searchable plaintext in the outbox payload.
	var sequence int64
	if err := transaction.QueryRow(ctx,
		`SELECT app.enqueue_search_chunk_upsert($1)`, chunk.ID).Scan(&sequence); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// AddFragment records one exact chunk-to-Evidence relationship. The database
// trigger rejects cross-version or cross-extraction joins and duplicate order.
func (repository *Repository) AddFragment(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, chunkID, evidenceFragmentID string, ordinal int64) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(chunkID) || !validOpaque(evidenceFragmentID) || ordinal < 1 || ordinal > maximumGeneration {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.search_chunk_fragment
			(organization_id, search_chunk_id, evidence_fragment_id, ordinal)
		VALUES ($1,$2,$3,$4)`, access.OrganizationID, chunkID, evidenceFragmentID, ordinal); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// CreateStagingProfile persists one immutable index-generation profile. It is
// separate from activation so an applier can reconcile every chunk/outbox
// event before an alias cutover is attempted.
func (repository *Repository) CreateStagingProfile(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, profileID, profileHash string, generation, activationRevision, generationFence,
	catalogWatermark, outboxSequence int64) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(profileID) || !validSHA256(profileHash) || generation < 1 || generation > maximumGeneration ||
		activationRevision < 1 || activationRevision > maximumGeneration || generationFence < 0 || generationFence > maximumGeneration ||
		catalogWatermark < 0 || catalogWatermark > maximumGeneration || outboxSequence < 0 || outboxSequence > maximumGeneration {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.organization_search_profile
			(organization_id, embedding_profile_id, embedding_profile_hash,
			 index_generation, activation_revision, generation_fence,
			 catalog_snapshot_watermark, outbox_applied_sequence, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'STAGING')`,
		access.OrganizationID, profileID, profileHash, generation, activationRevision,
		generationFence, catalogWatermark, outboxSequence); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// Revision statuses of the durable, append-only retrieval profile
// (migration 000072). A tenant has at most one ACTIVE revision (the one every
// query and every index write is bound to) and at most one STAGING revision
// (the vector space currently being built).
const (
	RevisionStaging    = "STAGING"
	RevisionActive     = "ACTIVE"
	RevisionSuperseded = "SUPERSEDED"
)

// LexicalProfileID is the server-owned descriptor used when no embedding
// channel is mounted. It is a profile identity, never a model artifact.
const LexicalProfileID = "lexical-only-v1"

// Revision is one durable retrieval profile revision. Identity
// (profile/hash/generation) is immutable inside a revision; changing the
// vector space appends a new revision instead of mutating this one.
type Revision struct {
	ProfileID          string
	ProfileHash        string
	Generation         int64
	GenerationFence    int64
	ActivationRevision int64
	Status             string
}

// Vector reports whether the revision is bound to a real embedding profile
// rather than the server-owned lexical descriptor.
func (revision Revision) Vector() bool {
	return revision.ProfileID != "" && revision.ProfileID != LexicalProfileID
}

// ReadRevision returns the newest revision with the requested status.
func (repository *Repository) ReadRevision(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, status string) (Revision, bool, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		(status != RevisionStaging && status != RevisionActive && status != RevisionSuperseded) {
		return Revision{}, false, &Error{code: CodeInvalid}
	}
	var revision Revision
	// The embedding pair is nullable by design (migration 000046): a lexical
	// deployment has a profile identity but no model artifact.
	var profileID, profileHash *string
	err := transaction.QueryRow(ctx, `
		SELECT embedding_profile_id, embedding_profile_hash, index_generation,
		       generation_fence, activation_revision, status
		  FROM public.organization_search_profile
		 WHERE organization_id = $1
		   AND status = $2
		 ORDER BY activation_revision DESC
		 LIMIT 1`, access.OrganizationID, status).Scan(
		&profileID, &profileHash, &revision.Generation,
		&revision.GenerationFence, &revision.ActivationRevision, &revision.Status)
	if err != nil {
		if database.IsNotFound(err) {
			return Revision{}, false, nil
		}
		return Revision{}, false, &Error{code: CodePersistence, cause: err}
	}
	if profileID != nil {
		revision.ProfileID = *profileID
	}
	if profileHash != nil {
		revision.ProfileHash = *profileHash
	}
	if revision.Status != status || revision.ActivationRevision < 1 {
		return Revision{}, false, &Error{code: CodePersistence}
	}
	return revision, true, nil
}

// EnsureMountedProfile provisions the tenant's first revision from the
// administrator-owned embedding mount and then verifies that the ACTIVE
// revision still belongs to this deployment's alias generation.
//
// It deliberately does NOT require the ACTIVE revision to name the mounted
// embedding profile. A tenant whose corpus was indexed under an earlier vector
// space (or lexically) keeps serving that revision until an operator stages
// and activates a successor; treating that as a startup failure is what made
// the embedding mount unmountable on an existing tenant.
func (repository *Repository) EnsureMountedProfile(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, profileID, profileHash string, generation, generationFence int64) error {
	if !validOpaque(profileID) || !validSHA256(profileHash) {
		return &Error{code: CodeInvalid}
	}
	return repository.ensureBootstrapRevision(ctx, transaction, access, profileID, profileHash, generation, generationFence)
}

// EnsureMountedLexicalProfile provisions the tenant's first revision without
// fabricating embedding provenance. The lexical descriptor is a server-owned
// profile, not a model artifact.
func (repository *Repository) EnsureMountedLexicalProfile(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, generation, generationFence int64) error {
	return repository.ensureBootstrapRevision(ctx, transaction, access,
		LexicalProfileID, mountedLexicalProfileHash(), generation, generationFence)
}

func (repository *Repository) ensureBootstrapRevision(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, profileID, profileHash string, generation, generationFence int64) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(profileID) || !validSHA256(profileHash) ||
		generation < 1 || generation > maximumGeneration || generationFence < 1 || generationFence > maximumGeneration {
		return &Error{code: CodeInvalid}
	}
	// Revision 1 is born ACTIVE because there is no earlier corpus to
	// re-index. The guard in migration 000072 rejects this shape for every
	// later revision, so a second vector space can never skip staging.
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.organization_search_profile
			(organization_id, embedding_profile_id, embedding_profile_hash,
			 index_generation, activation_revision, generation_fence,
			 catalog_snapshot_watermark, outbox_applied_sequence, status,
			 activated_at)
		SELECT $1, $2, $3, $4, 1, $5, 0, 0, 'ACTIVE', transaction_timestamp()
		 WHERE NOT EXISTS (
			SELECT 1 FROM public.organization_search_profile WHERE organization_id = $1
		 )`, access.OrganizationID, profileID, profileHash, generation, generationFence); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	active, found, err := repository.ReadRevision(ctx, transaction, access, RevisionActive)
	if err != nil {
		return err
	}
	if !found || active.Generation != generation || active.GenerationFence != generationFence ||
		!validOpaque(active.ProfileID) || !validSHA256(active.ProfileHash) {
		return &Error{code: CodeProfileUnavailable}
	}
	return nil
}

// RequestRevision records an operator's profile-revision command: it appends
// (or returns) the STAGING revision for the deployment-mounted embedding
// profile. It is the only path by which the runtime role touches the revision
// sequence, and it can only ever produce a revision nothing reads yet — the
// re-index and the cutover remain worker work.
func (repository *Repository) RequestRevision(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, profileID, profileHash string, generation, generationFence int64) (int64, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(profileID) || !validSHA256(profileHash) ||
		generation < 1 || generation > maximumGeneration || generationFence < 1 || generationFence > maximumGeneration {
		return 0, &Error{code: CodeInvalid}
	}
	var revision int64
	if err := transaction.QueryRow(ctx,
		`SELECT app.stage_search_profile_revision($1, $2, $3, $4)`,
		profileID, profileHash, generation, generationFence).Scan(&revision); err != nil {
		return 0, &Error{code: CodePersistence, cause: err}
	}
	if revision < 1 || revision > maximumGeneration {
		return 0, &Error{code: CodePersistence}
	}
	return revision, nil
}

// StageRevision appends the STAGING revision an operator's profile-revision
// command asks for, bound to the deployment's mounted embedding profile. It is
// idempotent: an identical staged revision, or an ACTIVE revision that already
// names this profile, is returned unchanged instead of appending a second one.
func (repository *Repository) StageRevision(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, profileID, profileHash string, generation, generationFence int64) (Revision, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaque(profileID) || !validSHA256(profileHash) ||
		generation < 1 || generation > maximumGeneration || generationFence < 1 || generationFence > maximumGeneration {
		return Revision{}, &Error{code: CodeInvalid}
	}
	staged, stagedFound, err := repository.ReadRevision(ctx, transaction, access, RevisionStaging)
	if err != nil {
		return Revision{}, err
	}
	if stagedFound {
		if staged.ProfileID != profileID || staged.ProfileHash != profileHash ||
			staged.Generation != generation || staged.GenerationFence != generationFence {
			return Revision{}, &Error{code: CodeProfileUnavailable}
		}
		return staged, nil
	}
	active, activeFound, err := repository.ReadRevision(ctx, transaction, access, RevisionActive)
	if err != nil {
		return Revision{}, err
	}
	if !activeFound || active.Generation != generation || active.GenerationFence != generationFence {
		return Revision{}, &Error{code: CodeProfileUnavailable}
	}
	if active.ProfileID == profileID && active.ProfileHash == profileHash {
		return active, nil
	}
	var next int64
	if err := transaction.QueryRow(ctx, `
		SELECT coalesce(max(activation_revision), 0) + 1
		  FROM public.organization_search_profile
		 WHERE organization_id = $1`, access.OrganizationID).Scan(&next); err != nil {
		return Revision{}, &Error{code: CodePersistence, cause: err}
	}
	if next < 2 || next > maximumGeneration {
		return Revision{}, &Error{code: CodePersistence}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.organization_search_profile
			(organization_id, embedding_profile_id, embedding_profile_hash,
			 index_generation, activation_revision, generation_fence,
			 catalog_snapshot_watermark, outbox_applied_sequence, status)
		VALUES ($1,$2,$3,$4,$5,$6,0,0,'STAGING')`,
		access.OrganizationID, profileID, profileHash, generation, next, generationFence); err != nil {
		return Revision{}, &Error{code: CodePersistence, cause: err}
	}
	return Revision{ProfileID: profileID, ProfileHash: profileHash, Generation: generation,
		GenerationFence: generationFence, ActivationRevision: next, Status: RevisionStaging}, nil
}

// ActivateRevision performs the one-way cutover once the re-index pass has
// rebuilt every indexable chunk under the staged vector space: the previous
// ACTIVE revision becomes SUPERSEDED and the staged revision becomes ACTIVE.
// The SQL guard remains the final authority for both transitions.
func (repository *Repository) ActivateRevision(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, activationRevision int64, activatedAt time.Time) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		activationRevision < 2 || activationRevision > maximumGeneration || activatedAt.IsZero() {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE public.organization_search_profile
		   SET status = 'SUPERSEDED'
		 WHERE organization_id = $1
		   AND status = 'ACTIVE'
		   AND activation_revision < $2`, access.OrganizationID, activationRevision); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	commandTag, err := transaction.Exec(ctx, `
		UPDATE public.organization_search_profile
		   SET status = 'ACTIVE',
		       activated_at = $3
		 WHERE organization_id = $1
		   AND activation_revision = $2
		   AND status = 'STAGING'`, access.OrganizationID, activationRevision, activatedAt)
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if commandTag.RowsAffected() != 1 {
		return &Error{code: CodePersistence}
	}
	return nil
}

// ChunkReference is the durable identity of one indexable search chunk. It
// carries no text: the re-index pass re-reads plaintext through the same owner
// branch an outbox-driven index write uses.
type ChunkReference struct {
	EmbeddingProfileHash string
	ChunkID              string
	SourceVersionID      string
	ExtractionID         string
	ArtifactID           string
	TextHash             string
}

// ChunksForReindex pages through the tenant's currently indexable chunks in a
// stable identity order. Lifecycle filtering here is an efficiency bound only;
// the document loader re-validates every retention, extraction and Evidence
// constraint before a document is written to the alias.
func (repository *Repository) ChunksForReindex(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, afterChunkID string, limit int) ([]ChunkReference, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		limit < 1 || limit > 1000 || (afterChunkID != "" && !validOpaque(afterChunkID)) {
		return nil, &Error{code: CodeInvalid}
	}
	rows, err := transaction.Query(ctx, `
		SELECT chunk.id, chunk.source_version_id, chunk.extraction_id,
		       chunk.search_text_artifact_id, chunk.chunk_hash, COALESCE(chunk.embedding_profile_hash, '')
		  FROM public.search_chunk AS chunk
		  JOIN public.source_version AS version
		    ON version.organization_id = chunk.organization_id
		   AND version.id = chunk.source_version_id
		  JOIN public.source_object AS object
		    ON object.organization_id = version.organization_id
		   AND object.id = version.source_object_id
		  JOIN public.source_version_active_extraction AS active_extraction
		    ON active_extraction.organization_id = chunk.organization_id
		   AND active_extraction.source_version_id = chunk.source_version_id
		   AND active_extraction.extraction_id = chunk.extraction_id
		 WHERE chunk.organization_id = $1
		   AND chunk.search_text_artifact_id IS NOT NULL
		   AND object.lifecycle_state = 'ACTIVE'
		   AND object.current_version_id = version.id
		   AND version.state = 'CURRENT'
		   AND ($2 = '' OR chunk.id > $2)
		 ORDER BY chunk.id
		 LIMIT $3`, access.OrganizationID, afterChunkID, limit)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	defer rows.Close()
	references := make([]ChunkReference, 0, limit)
	for rows.Next() {
		var reference ChunkReference
		if err := rows.Scan(&reference.ChunkID, &reference.SourceVersionID, &reference.ExtractionID,
			&reference.ArtifactID, &reference.TextHash, &reference.EmbeddingProfileHash); err != nil {
			return nil, &Error{code: CodePersistence, cause: err}
		}
		if !validOpaque(reference.ChunkID) || !validOpaque(reference.SourceVersionID) ||
			!validOpaque(reference.ExtractionID) || !validOpaque(reference.ArtifactID) ||
			!validSHA256(reference.TextHash) {
			return nil, &Error{code: CodePersistence}
		}
		references = append(references, reference)
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	return references, nil
}

func mountedLexicalProfileHash() string {
	digest := sha256.Sum256([]byte("knowvault-search-lexical-profile-v1"))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ActivateProfile performs the one-way generation cutover after an applier has
// caught up through the requested outbox sequence.  The SQL trigger remains the
// final authority for monotonic watermarks and status transitions; this method
// only exposes the typed worker operation.
func (repository *Repository) ActivateProfile(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, generation, generationFence, catalogWatermark, outboxSequence int64,
	activatedAt time.Time) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		generation < 1 || generation > maximumGeneration || generationFence < 0 || generationFence > maximumGeneration ||
		catalogWatermark < 0 || catalogWatermark > maximumGeneration || outboxSequence < 0 || outboxSequence > maximumGeneration ||
		activatedAt.IsZero() {
		return &Error{code: CodeInvalid}
	}
	commandTag, err := transaction.Exec(ctx, `
		UPDATE public.organization_search_profile
		   SET generation_fence = $3,
		       catalog_snapshot_watermark = $4,
		       outbox_applied_sequence = $5,
		       status = 'ACTIVE',
		       activated_at = $6
		 WHERE organization_id = $1
		   AND index_generation = $2
		   AND status = 'STAGING'`,
		access.OrganizationID, generation, generationFence, catalogWatermark, outboxSequence, activatedAt)
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if commandTag.RowsAffected() != 1 {
		return &Error{code: CodePersistence}
	}
	return nil
}

// ReadText retrieves and decrypts the one search-text owner branch for a
// chunk. Plaintext is returned only to the bounded applier and must be cleared
// by the caller after the OpenSearch request completes.
func (repository *Repository) ReadText(ctx context.Context, transaction database.Transaction,
	access database.AccessContext, codec *artifactcrypto.Codec, chunkID string) ([]byte, error) {
	if repository == nil || repository.artifacts == nil || codec == nil || ctx == nil ||
		!transaction.Valid() || access.Validate() != nil || !validOpaque(chunkID) {
		return nil, &Error{code: CodeInvalid}
	}
	owner, envelope, err := repository.artifacts.Fetch(ctx, transaction, access, artifactcrypto.SearchChunkText, chunkID)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	plaintext, err := codec.Open(owner, envelope)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	return plaintext, nil
}

func workerAuthorize(ctx context.Context, transaction database.Transaction, _ database.AccessContext, _ string) error {
	var allowed bool
	if err := transaction.QueryRow(ctx,
		`SELECT session_user = 'knowvault_worker' AND app.current_organization_id() IS NOT NULL`).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return errors.New("search worker role gate denied")
	}
	return nil
}

func validChunk(chunk Chunk, organizationID string) bool {
	if chunk.OrganizationID != organizationID || !validOpaque(chunk.ID) || !validOpaque(chunk.SourceVersionID) ||
		!validOpaque(chunk.ExtractionID) || !validSHA256(chunk.ChunkHash) || chunk.TokenCount < 0 ||
		chunk.TokenCount > maximumGeneration {
		return false
	}
	profileEmpty := chunk.EmbeddingProfileHash == ""
	modelEmpty := chunk.EmbeddingModelArtifactHash == ""
	dimensionEmpty := chunk.EmbeddingDimension == 0
	if profileEmpty || modelEmpty || dimensionEmpty {
		return profileEmpty && modelEmpty && dimensionEmpty
	}
	return validSHA256(chunk.EmbeddingProfileHash) && validSHA256(chunk.EmbeddingModelArtifactHash) &&
		chunk.EmbeddingDimension >= 1 && chunk.EmbeddingDimension <= 65536
}
