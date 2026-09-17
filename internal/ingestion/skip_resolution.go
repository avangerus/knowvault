package ingestion

import (
	"context"
	"crypto/subtle"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

type pendingObjectSkip struct {
	runID, digest, artifactID string
	keyVersion                int64
}

// Read only outstanding skipped identities, once per scope sync. Healthy
// objects cost no resolution row or per-object lookup. Decrypting this bounded
// problem set also matches a retry under a rotated digest key to older skips.
func (h *Handler) unresolvedObjectSkips(ctx context.Context, access database.AccessContext, scopeID string, revision int64) (map[string][]pendingObjectSkip, error) {
	pending := map[string][]pendingObjectSkip{}
	err := h.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (s.external_id_digest)
			s.sync_run_id, s.external_id_digest, s.digest_key_version, s.external_id_artifact_id
			FROM app.source_object_current_skips() s
			JOIN public.sync_run run ON run.organization_id=s.organization_id AND run.id=s.sync_run_id
			WHERE s.organization_id=$1 AND s.source_scope_id=$2 AND s.source_scope_revision=$3
			ORDER BY s.external_id_digest, run.completed_at DESC, run.id DESC`, access.OrganizationID, scopeID, revision)
		if err != nil {
			return err
		}
		var skips []pendingObjectSkip
		for rows.Next() {
			var skip pendingObjectSkip
			if err := rows.Scan(&skip.runID, &skip.digest, &skip.keyVersion, &skip.artifactID); err != nil {
				rows.Close()
				return err
			}
			skips = append(skips, skip)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, skip := range skips {
			identity, ok, err := h.pendingSkipIdentity(ctx, tx, access, skip)
			if err != nil {
				return err
			}
			if ok {
				pending[identity] = append(pending[identity], skip)
			}
		}
		return nil
	})
	return pending, err
}

func (h *Handler) pendingSkipIdentity(ctx context.Context, tx database.Transaction, access database.AccessContext, skip pendingObjectSkip) (string, bool, error) {
	var resourceID, wrappedHash, kekReference, aadHash, plaintextHash string
	var ciphertext, nonce, wrappedKey []byte
	var size int
	var kekVersion int64
	err := tx.QueryRow(ctx, `SELECT resource_id, ciphertext, size_bytes, nonce, wrapped_dek,
		wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
		FROM app.source_object_skip_read_external_id($1)`, skip.artifactID).Scan(
		&resourceID, &ciphertext, &size, &nonce, &wrappedKey, &wrappedHash, &kekReference, &kekVersion, &aadHash, &plaintextHash)
	if database.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceObjectExternalID, access.OrganizationID, resourceID)
	if err != nil {
		return "", false, nil
	}
	envelope := artifactcrypto.NewEnvelopeFromStorage(owner, artifactcrypto.CipherAES256GCM, ciphertext,
		size, nonce, wrappedKey, wrappedHash, kekReference, kekVersion, aadHash, plaintextHash)
	if !envelope.Valid() {
		return "", false, nil
	}
	plaintext, err := h.codec.Open(owner, envelope)
	if err != nil {
		return "", false, nil
	}
	var identity skipIdentityArtifact
	if jsonv2.Unmarshal(plaintext, &identity) != nil || identity.ExternalID == "" ||
		subtle.ConstantTimeCompare([]byte(identity.Digest), []byte(skip.digest)) != 1 {
		return "", false, nil
	}
	return identity.ExternalID, true, nil
}

// Called only at the successful end of the same transaction that publishes or
// re-observes the object. Its fact remains inactive until the whole sync reaches
// SUCCEEDED; a FAILED run does not prevent a later retry from recording success.
func (h *Handler) resolveObjectSkips(ctx context.Context, tx database.Transaction, access database.AccessContext,
	resolved resolvedScope, syncRunID, objectID, externalID string) error {
	for _, skip := range resolved.pendingSkips[externalID] {
		if _, err := tx.Exec(ctx, `INSERT INTO public.source_object_skip_resolution
			(organization_id, source_scope_id, source_scope_revision, external_id_digest,
			 digest_key_version, skipped_sync_run_id, resolving_sync_run_id, source_object_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			access.OrganizationID, resolved.scopeID, resolved.revision, skip.digest, skip.keyVersion,
			skip.runID, syncRunID, objectID); err != nil {
			return err
		}
	}
	return nil
}
