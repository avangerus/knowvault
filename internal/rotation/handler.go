package rotation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// Digester is the active organization-scoped keyed HMAC material that the
// digest recompute pass re-projects with. It is owned by composition and must
// be cleared by the caller after the runtime closes.
type Digester struct {
	Key        []byte
	KeyVersion int
}

// Handler processes the rotation-domain jobs on the S1b substrate: one
// KEK_REWRAP or DIGEST_RECOMPUTE pass per lease, each a bounded batch in one
// fenced transaction, re-enqueuing itself while a full batch means more
// candidates and closing the rotation when the batch comes back short. Every
// write is CAS'd by the SECURITY DEFINER functions against the previous
// pair/version and the live lease, so a crash or a duplicate pass is
// idempotently resumable.
type Handler struct {
	db       *database.Store
	queue    *jobs.Queue
	audit    *audit.Store
	provider *artifactcrypto.MountedProvider
	codec    *artifactcrypto.Codec
	digester Digester
	workerID string
	now      func() time.Time
	newID    func(string) (string, error)
}

// NewHandler wires a rotation handler over the worker-role store. The provider
// carries the active plus optional previous KEK pair (reads accept both,
// writes seal under the active pair only); the codec opens anchor artifacts for
// digest re-projection; the digester is the active source digest key.
func NewHandler(db *database.Store, queue *jobs.Queue, provider *artifactcrypto.MountedProvider,
	codec *artifactcrypto.Codec, digester Digester, workerID string, now func() time.Time,
	newID func(string) (string, error)) (*Handler, error) {
	if db == nil || queue == nil || provider == nil || codec == nil || workerID == "" || now == nil || newID == nil {
		return nil, &Error{code: CodeInvalid}
	}
	auditStore, err := audit.NewStore(db)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	return &Handler{db: db, queue: queue, audit: auditStore, provider: provider, codec: codec,
		digester: digester, workerID: workerID, now: now, newID: newID}, nil
}

// HandleKEKRewrap performs one fenced re-wrap pass (ADR-0070 §1.3): every
// candidate still sealed under the previous pair is unwrapped, re-sealed under
// the active pair and written back with the envelope nonce and AAD hash
// untouched. A full batch re-enqueues the next pass in the same transaction; a
// short batch means nothing remains, so the rotation completes atomically.
func (h *Handler) HandleKEKRewrap(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if claimed.Type != jobs.TypeKEKRewrap {
		return h.fail(ctx, access, claimed, "ROTATION_WRONG_JOB_TYPE", nil)
	}
	err := h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		state, err := readRotationState(ctx, tx, DomainKEK)
		if err != nil {
			return err
		}
		if state.phase == "COMPLETE" {
			return nil // idempotent duplicate pass of a closed rotation
		}
		if state.phase != "REWRAPPING" || state.previousRef == "" || state.previousVersion < 1 {
			return &Error{code: CodeFailed}
		}
		batch, err := rewrapCandidates(ctx, tx, state.previousRef, state.previousVersion)
		if err != nil {
			return err
		}
		for _, candidate := range batch {
			if err := h.rewrapOne(ctx, tx, access, claimed, state, candidate); err != nil {
				return err
			}
		}
		if len(batch) == rotationBatchSize {
			return h.enqueueNext(ctx, access, tx, jobs.TypeKEKRewrap, claimed.ID)
		}
		if _, err := tx.Exec(ctx, `SELECT app.kek_rotation_complete($1, $2)`,
			state.activeRef, state.activeVersion); err != nil {
			return err
		}
		// The rotation just closed: the complete event lands in the same
		// transaction, so a closed window can never exist without its audit
		// event (ADR-0070 §1.3: the audit trail makes the window observable).
		eventID, err := h.newID("audit")
		if err != nil {
			return err
		}
		return appendRotationSuccessAudit(ctx, h.audit, access, tx, audit.ActionKeyRotationComplete,
			eventID, DomainKEK, state.activeRef, state.activeVersion, h.now())
	})
	if err != nil {
		return h.fail(ctx, access, claimed, "ROTATION_KEK_REWRAP", err)
	}
	return h.complete(ctx, access, claimed)
}

// HandleDigestRecompute performs one fenced digest re-projection pass
// (ADR-0070 §1.4, ADR-0077 §1.3): every fragment still projected under the
// previous digest version has its anchor and text artifacts opened and its
// keyed anchor and text digests re-keyed under the active version in one
// fenced rewrite. The projection rows are updated before the fragment row by
// the database function, so citations never observe a torn projection.
func (h *Handler) HandleDigestRecompute(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if claimed.Type != jobs.TypeDigestRecompute {
		return h.fail(ctx, access, claimed, "ROTATION_WRONG_JOB_TYPE", nil)
	}
	err := h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		state, err := readRotationState(ctx, tx, DomainDigest)
		if err != nil {
			return err
		}
		if state.phase == "COMPLETE" {
			return nil // idempotent duplicate pass of a closed rotation
		}
		if state.phase != "REWRAPPING" || state.previousVersion < 1 {
			return &Error{code: CodeFailed}
		}
		batch, err := digestCandidates(ctx, tx, state.previousVersion)
		if err != nil {
			return err
		}
		for _, candidate := range batch {
			if err := h.reprojectOne(ctx, tx, access, claimed, candidate); err != nil {
				return err
			}
		}
		if len(batch) == rotationBatchSize {
			return h.enqueueNext(ctx, access, tx, jobs.TypeDigestRecompute, claimed.ID)
		}
		if _, err := tx.Exec(ctx, `SELECT app.digest_rotation_complete($1)`,
			state.previousVersion); err != nil {
			return err
		}
		eventID, err := h.newID("audit")
		if err != nil {
			return err
		}
		return appendRotationSuccessAudit(ctx, h.audit, access, tx, audit.ActionKeyRotationComplete,
			eventID, DomainDigest, state.activeRef, state.activeVersion, h.now())
	})
	if err != nil {
		return h.fail(ctx, access, claimed, "ROTATION_DIGEST_RECOMPUTE", err)
	}
	return h.complete(ctx, access, claimed)
}

// rewrapOne re-seals one candidate's DEK under the active pair and rewrites
// the wrapper columns with the envelope nonce and AAD hash untouched.
func (h *Handler) rewrapOne(ctx context.Context, tx database.Transaction, access database.AccessContext,
	claimed jobs.ClaimedJob, state rotationState, candidate rewrapCandidate) error {
	if !candidate.valid() {
		return &Error{code: CodeFailed}
	}
	owner, err := artifactcrypto.NewOwnerIdentityFromTuple(
		candidate.ownerTable, candidate.ownerColumn, candidate.resourceType, candidate.fieldName,
		access.OrganizationID, candidate.resourceID)
	if err != nil {
		return err
	}
	wrapped := artifactcrypto.NewWrappedDEK(candidate.kekReference, candidate.kekVersion, candidate.wrappedDEK)
	dek, err := h.provider.UnwrapDEK(wrapped, owner)
	if err != nil {
		return err
	}
	newWrapped, err := h.provider.WrapDEK(dek, owner)
	clear(dek)
	if err != nil {
		return err
	}
	wrappedBytes := newWrapped.Bytes()
	defer clear(wrappedBytes)
	_, err = tx.Exec(ctx, `SELECT app.artifact_rewrap($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		candidate.id, state.previousRef, state.previousVersion, state.activeRef, state.activeVersion,
		candidate.nonce, wrappedBytes, sha256Digest(wrappedBytes), candidate.aadHash,
		claimed.ID, h.workerID, claimed.LeaseEpoch)
	return err
}

// reprojectOne opens the anchor and text artifacts of one fragment and
// rewrites both keyed digests under the active digest version in one fenced
// database call.
func (h *Handler) reprojectOne(ctx context.Context, tx database.Transaction, access database.AccessContext,
	claimed jobs.ClaimedJob, candidate digestCandidate) error {
	if !candidate.valid() {
		return &Error{code: CodeFailed}
	}
	// Both artifacts are owned by the fragment row: the AAD binds to the
	// fragment id, not to the artifact row ids.
	anchorOwner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.EvidenceAnchor, access.OrganizationID, candidate.fragmentID)
	if err != nil {
		return err
	}
	anchorEnvelope := artifactcrypto.NewEnvelopeFromStorage(anchorOwner, artifactcrypto.CipherAES256GCM,
		candidate.ciphertext, candidate.sizeBytes, candidate.nonce, candidate.wrappedDEK,
		candidate.wrappedDEKHash, candidate.kekReference, candidate.kekVersion,
		candidate.aadHash, candidate.plaintextHash)
	anchorBytes, err := h.codec.Open(anchorOwner, anchorEnvelope)
	if err != nil {
		return err
	}
	newAnchorHash := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, anchorBytes)
	clear(anchorBytes)

	textOwner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.EvidenceNormalizedText, access.OrganizationID, candidate.fragmentID)
	if err != nil {
		return err
	}
	textEnvelope := artifactcrypto.NewEnvelopeFromStorage(textOwner, artifactcrypto.CipherAES256GCM,
		candidate.textCiphertext, candidate.textSizeBytes, candidate.textNonce, candidate.textWrappedDEK,
		candidate.textWrappedDEKHash, candidate.textKEKReference, candidate.textKEKVersion,
		candidate.textAADHash, candidate.textPlaintextHash)
	textBytes, err := h.codec.Open(textOwner, textEnvelope)
	if err != nil {
		return err
	}
	newTextHash := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, textBytes)
	clear(textBytes)

	_, err = tx.Exec(ctx, `SELECT app.evidence_digest_rewrite($1, $2, $3, $4, $5, $6, $7)`,
		candidate.fragmentID, newAnchorHash, newTextHash, int64(h.digester.KeyVersion),
		claimed.ID, h.workerID, claimed.LeaseEpoch)
	return err
}

// enqueueNext places the next pass of the same domain. The idempotency key is
// the current job id, so a crashed pass that re-runs reuses the already placed
// follow-on job instead of duplicating it.
func (h *Handler) enqueueNext(ctx context.Context, access database.AccessContext, tx database.Transaction,
	jobType jobs.Type, previousJobID string) error {
	jobID, err := ids.New("job")
	if err != nil {
		return err
	}
	_, err = h.queue.EnqueueInTransaction(ctx, access, tx, jobs.Spec{
		JobID: jobID, Type: jobType, Payload: jobs.Payload{},
		IdempotencyKey: "rotation:continue:" + previousJobID, Priority: 0, MaxAttempts: 5,
	})
	return err
}

// complete acknowledges a finished pass. A lease lost here (a reclaimed,
// superseded pass) is a normal fence outcome, not a worker failure.
func (h *Handler) complete(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if err := h.queue.Complete(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
		if jobs.CodeOf(err) == jobs.CodeLeaseLost {
			return nil
		}
		return failure("ROTATION_COMPLETE", err)
	}
	return nil
}

func (h *Handler) fail(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob, code string, cause error) error {
	_ = h.queue.Fail(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch, jobs.ErrorCode(code), 60)
	return failure(code, cause)
}

// failure builds the content-free error the poll loop logs.
func failure(code string, cause error) error {
	return &Error{code: ErrorCode(code), cause: cause}
}

// sha256Digest renders the stored wrapper hash format (sha256:<hex>).
func sha256Digest(bytes []byte) string {
	digest := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// rewrapCandidate is one row of app.artifact_rewrap_candidate_batch.
type rewrapCandidate struct {
	id             string
	ownerTable     string
	ownerColumn    string
	resourceType   string
	resourceID     string
	fieldName      string
	ciphertext     []byte
	sizeBytes      int
	nonce          []byte
	wrappedDEK     []byte
	wrappedDEKHash string
	kekReference   string
	kekVersion     int64
	aadHash        string
	plaintextHash  string
}

func (c rewrapCandidate) valid() bool {
	return c.id != "" && c.ownerTable != "" && c.ownerColumn != "" && c.resourceType != "" &&
		c.resourceID != "" && c.fieldName != "" && len(c.ciphertext) > 0 && c.sizeBytes > 0 &&
		len(c.nonce) == 12 && len(c.wrappedDEK) >= 62 && c.kekReference != "" && c.kekVersion >= 1
}

// rewrapCandidates reads one bounded batch of wrappers still sealed under the
// previous pair, oldest first.
func rewrapCandidates(ctx context.Context, tx database.Transaction, previousRef string, previousVersion int64) ([]rewrapCandidate, error) {
	rows, err := tx.Query(ctx, `SELECT id, owner_table, owner_column, resource_type, resource_id, field_name,
		ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
		FROM app.artifact_rewrap_candidate_batch($1, $2, $3)`,
		previousRef, previousVersion, rotationBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batch []rewrapCandidate
	for rows.Next() {
		var candidate rewrapCandidate
		if err := rows.Scan(&candidate.id, &candidate.ownerTable, &candidate.ownerColumn, &candidate.resourceType,
			&candidate.resourceID, &candidate.fieldName, &candidate.ciphertext, &candidate.sizeBytes,
			&candidate.nonce, &candidate.wrappedDEK, &candidate.wrappedDEKHash, &candidate.kekReference,
			&candidate.kekVersion, &candidate.aadHash, &candidate.plaintextHash); err != nil {
			return nil, err
		}
		batch = append(batch, candidate)
	}
	return batch, rows.Err()
}

// digestCandidate is one row of app.evidence_digest_candidate_batch: the
// fragment's current projection pairs plus the envelope material of both its
// anchor and text artifacts.
type digestCandidate struct {
	fragmentID          string
	anchorArtifactID    string
	anchorHash          string
	anchorDigestVersion int64
	ciphertext          []byte
	sizeBytes           int
	nonce               []byte
	wrappedDEK          []byte
	wrappedDEKHash      string
	kekReference        string
	kekVersion          int64
	aadHash             string
	plaintextHash       string
	textArtifactID      string
	textHash            string
	textDigestVersion   int64
	textCiphertext      []byte
	textSizeBytes       int
	textNonce           []byte
	textWrappedDEK      []byte
	textWrappedDEKHash  string
	textKEKReference    string
	textKEKVersion      int64
	textAADHash         string
	textPlaintextHash   string
}

func (c digestCandidate) valid() bool {
	return c.fragmentID != "" && c.anchorArtifactID != "" && len(c.ciphertext) > 0 && c.sizeBytes > 0 &&
		len(c.nonce) == 12 && len(c.wrappedDEK) >= 62 && c.kekReference != "" && c.kekVersion >= 1 &&
		c.textArtifactID != "" && len(c.textCiphertext) > 0 && c.textSizeBytes > 0 &&
		len(c.textNonce) == 12 && len(c.textWrappedDEK) >= 62 && c.textKEKReference != "" && c.textKEKVersion >= 1
}

// digestCandidates reads one bounded batch of fragments still projected under
// the previous digest version, joined with the envelope material of both their
// anchor and text artifacts.
func digestCandidates(ctx context.Context, tx database.Transaction, previousVersion int64) ([]digestCandidate, error) {
	rows, err := tx.Query(ctx, `SELECT fragment_id, anchor_artifact_id, anchor_hash, anchor_digest_key_version,
		text_hash, text_digest_key_version,
		ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash,
		text_artifact_id, text_ciphertext, text_size_bytes, text_nonce, text_wrapped_dek, text_wrapped_dek_hash,
		text_kek_reference, text_kek_version, text_aad_hash, text_plaintext_hash
		FROM app.evidence_digest_candidate_batch($1, $2)`,
		previousVersion, rotationBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batch []digestCandidate
	for rows.Next() {
		var candidate digestCandidate
		if err := rows.Scan(&candidate.fragmentID, &candidate.anchorArtifactID, &candidate.anchorHash,
			&candidate.anchorDigestVersion, &candidate.textHash, &candidate.textDigestVersion,
			&candidate.ciphertext, &candidate.sizeBytes, &candidate.nonce,
			&candidate.wrappedDEK, &candidate.wrappedDEKHash, &candidate.kekReference, &candidate.kekVersion,
			&candidate.aadHash, &candidate.plaintextHash,
			&candidate.textArtifactID, &candidate.textCiphertext, &candidate.textSizeBytes, &candidate.textNonce,
			&candidate.textWrappedDEK, &candidate.textWrappedDEKHash, &candidate.textKEKReference, &candidate.textKEKVersion,
			&candidate.textAADHash, &candidate.textPlaintextHash); err != nil {
			return nil, err
		}
		batch = append(batch, candidate)
	}
	return batch, rows.Err()
}
