package evidence

import (
	"context"
	"errors"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// ReadExactVersion returns one fragment only when the requested immutable
// source version is readable in the workspace. This separate entrypoint keeps
// Read's active-version semantics unchanged.
func (v *Viewer) ReadExactVersion(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (Fragment, error) {
	if v == nil || workspaceID == "" || fragmentID == "" || expectedVersionID == "" {
		return Fragment{}, ErrNotFound
	}
	authorize := v.authorizeExactFn
	if authorize == nil {
		authorize = v.authorizeAuthorizedExact
	}
	read := v.readExactFn
	if read == nil {
		read = v.readAuthorizedExactVersion
	}

	authorized, err := authorize(ctx, access, workspaceID, fragmentID, expectedVersionID)
	if err != nil || !authorized {
		return Fragment{}, ErrNotFound
	}
	if err := v.emitAdmission(ctx, access, workspaceID, fragmentID); err != nil {
		return Fragment{}, ErrNotFound
	}
	result, err := read(ctx, access, workspaceID, fragmentID, expectedVersionID)
	if err != nil || result.FragmentID != fragmentID || result.SourceVersionID != expectedVersionID {
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return Fragment{}, ErrNotFound
	}
	if err := v.emitOpened(ctx, access, workspaceID, result); err != nil {
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return Fragment{}, ErrNotFound
	}
	return result, nil
}

// ReadObjectExactVersion returns the immutable extraction that owns the
// addressed fragment in expectedVersionID. It never consults the version's
// mutable active-extraction pointer.
func (v *Viewer) ReadObjectExactVersion(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (WholeObject, error) {
	if v == nil || workspaceID == "" || fragmentID == "" || expectedVersionID == "" {
		return WholeObject{}, ErrNotFound
	}
	authorize := v.authorizeExactFn
	if authorize == nil {
		authorize = v.authorizeAuthorizedExact
	}
	read := v.readObjectExactFn
	if read == nil {
		read = v.readAuthorizedObjectExactVersion
	}

	authorized, err := authorize(ctx, access, workspaceID, fragmentID, expectedVersionID)
	if err != nil || !authorized {
		if denyErr := v.emitObjectDenied(ctx, access, workspaceID); denyErr != nil {
			return WholeObject{}, errors.Join(ErrNotFound, denyErr)
		}
		return WholeObject{}, ErrNotFound
	}
	if err := v.emitAdmission(ctx, access, workspaceID, fragmentID); err != nil {
		return WholeObject{}, ErrNotFound
	}
	result, err := read(ctx, access, workspaceID, fragmentID, expectedVersionID)
	if err != nil || result.Fragment.FragmentID != fragmentID || result.Fragment.SourceVersionID != expectedVersionID {
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return WholeObject{}, ErrNotFound
	}
	if err := v.emitOpened(ctx, access, workspaceID, result.Fragment); err != nil {
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return WholeObject{}, ErrNotFound
	}
	return result, nil
}

func (v *Viewer) authorizeAuthorizedExact(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (bool, error) {
	if v == nil || v.db == nil || workspaceID == "" || fragmentID == "" || expectedVersionID == "" {
		return false, ErrNotFound
	}
	authorized := false
	err := v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var readable bool
		if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_exact_readable($1, $2, $3)`,
			fragmentID, workspaceID, expectedVersionID).Scan(&readable); err != nil {
			return err
		}
		authorized = readable
		return nil
	})
	if err != nil {
		return false, err
	}
	return authorized, nil
}

// repositoryForWorkspaceVersion binds the evidence artifact branches to the
// exact-version gate. Source-object identity branches keep their existing read
// functions, but their callback proves that this object has a fragment in the
// requested version that passes the same exact gate.
func repositoryForWorkspaceVersion(workspaceID, expectedVersionID string) (*repository.Repository, error) {
	if workspaceID == "" || expectedVersionID == "" {
		return nil, ErrNotFound
	}
	authorizeFragment := func(ctx context.Context, transaction database.Transaction, _ database.AccessContext, fragmentID string) error {
		var readable bool
		if err := transaction.QueryRow(ctx, `SELECT app.evidence_fragment_exact_readable($1, $2, $3)`,
			fragmentID, workspaceID, expectedVersionID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return ErrNotFound
		}
		return nil
	}
	authorizeObjectIdentity := func(ctx context.Context, transaction database.Transaction, access database.AccessContext, sourceObjectID string) error {
		var readable bool
		if err := transaction.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM public.source_version v
				JOIN public.evidence_fragment f
				  ON f.organization_id = v.organization_id AND f.source_version_id = v.id
				WHERE v.organization_id = $1 AND v.source_object_id = $2 AND v.id = $3
				  AND app.evidence_fragment_exact_readable(f.id, $4, $3)
			)`, access.OrganizationID, sourceObjectID, expectedVersionID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return ErrNotFound
		}
		return nil
	}
	text, err := repository.NewBinding(artifactcrypto.EvidenceNormalizedText,
		"app.evidence_fragment_bind_normalized_text", "app.evidence_fragment_read_exact_normalized_text", authorizeFragment)
	if err != nil {
		return nil, err
	}
	anchor, err := repository.NewBinding(artifactcrypto.EvidenceAnchor,
		"app.evidence_fragment_bind_anchor", "app.evidence_fragment_read_exact_anchor", authorizeFragment)
	if err != nil {
		return nil, err
	}
	metadata, err := repository.NewBinding(artifactcrypto.EvidenceMetadata,
		"app.evidence_fragment_bind_metadata", "app.evidence_fragment_read_exact_metadata", authorizeFragment)
	if err != nil {
		return nil, err
	}
	externalID, err := repository.NewBinding(artifactcrypto.SourceObjectExternalID,
		"app.source_object_bind_external_object_id", "app.source_object_read_external_object_id", authorizeObjectIdentity)
	if err != nil {
		return nil, err
	}
	locator, err := repository.NewBinding(artifactcrypto.SourceObjectCanonicalLocator,
		"app.source_object_bind_canonical_locator", "app.source_object_read_canonical_locator", authorizeObjectIdentity)
	if err != nil {
		return nil, err
	}
	return repository.New(text, anchor, metadata, externalID, locator)
}

func setExactReadGUCs(ctx context.Context, tx database.Transaction, workspaceID, expectedVersionID string) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.evidence_source_version_id', $1, true)`, expectedVersionID); err != nil {
		return err
	}
	return nil
}

func (v *Viewer) readAuthorizedExactVersion(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (Fragment, error) {
	if v == nil || v.db == nil || v.codec == nil {
		return Fragment{}, ErrNotFound
	}
	repo, err := repositoryForWorkspaceVersion(workspaceID, expectedVersionID)
	if err != nil {
		return Fragment{}, ErrNotFound
	}
	var result Fragment
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		fragment, _, err := v.readExactFragmentInTransaction(ctx, tx, repo, access, workspaceID, fragmentID, expectedVersionID)
		if err != nil {
			return err
		}
		result = fragment
		return nil
	})
	if err != nil {
		return Fragment{}, ErrNotFound
	}
	return result, nil
}

func (v *Viewer) readAuthorizedObjectExactVersion(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (WholeObject, error) {
	if v == nil || v.db == nil || v.codec == nil {
		return WholeObject{}, ErrNotFound
	}
	repo, err := repositoryForWorkspaceVersion(workspaceID, expectedVersionID)
	if err != nil {
		return WholeObject{}, ErrNotFound
	}
	var result WholeObject
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		anchor, provenance, err := v.readExactFragmentInTransaction(ctx, tx, repo, access, workspaceID, fragmentID, expectedVersionID)
		if err != nil {
			return err
		}
		result.Fragment = anchor

		// Resolve only the addressed anchor's immutable extraction. The active
		// pointer intentionally does not participate in an exact-version read.
		rows, err := tx.Query(ctx, `
			SELECT f.id, f.ordinal
			FROM public.evidence_fragment f
			WHERE f.organization_id = $1 AND f.source_version_id = $2 AND f.extraction_id = $3
			ORDER BY f.ordinal, f.id`, access.OrganizationID, expectedVersionID, provenance.ExtractionID)
		if err != nil {
			return err
		}
		ordered := make([]orderedObjectFragment, 0, 64)
		for rows.Next() {
			var item orderedObjectFragment
			if err := rows.Scan(&item.id, &item.ordinal); err != nil {
				rows.Close()
				return err
			}
			ordered = append(ordered, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		return v.readWholeFragmentsInTransaction(ctx, tx, repo, access, workspaceID, expectedVersionID, &result, ordered)
	})
	if err != nil {
		return WholeObject{}, ErrNotFound
	}
	return result, nil
}

func (v *Viewer) readExactFragmentInTransaction(ctx context.Context, tx database.Transaction, repo *repository.Repository,
	access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (Fragment, fragmentProvenance, error) {
	var readable bool
	if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_exact_readable($1, $2, $3)`,
		fragmentID, workspaceID, expectedVersionID).Scan(&readable); err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	if !readable {
		return Fragment{}, fragmentProvenance{}, ErrNotFound
	}
	var provenance fragmentProvenance
	if err := tx.QueryRow(ctx, `
		SELECT f.extraction_id, f.source_version_id, f.ordinal,
		       v.external_version_key, v.content_hash, v.observed_at,
		       v.source_object_id, o.connection_id, o.object_type,
		       extraction.canonical_format, extraction.parser_profile_revision,
		       f.text_hash, f.anchor_hash, o.external_object_id_artifact_id IS NOT NULL,
		       o.external_object_id_digest, COALESCE(o.current_version_id = v.id, false)
		FROM public.evidence_fragment f
		JOIN public.source_version v
		  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
		JOIN public.source_object o
		  ON o.organization_id = v.organization_id AND o.id = v.source_object_id
		JOIN public.source_extraction extraction
		  ON extraction.organization_id = f.organization_id AND extraction.id = f.extraction_id
		 AND extraction.source_version_id = f.source_version_id
		WHERE f.organization_id = $1 AND f.id = $2 AND f.source_version_id = $3
	`, access.OrganizationID, fragmentID, expectedVersionID).Scan(
		&provenance.ExtractionID, &provenance.SourceVersionID, &provenance.Ordinal,
		&provenance.ExternalVersionKey, &provenance.ContentHash, &provenance.ObservedAt,
		&provenance.SourceObjectID, &provenance.ConnectionID, &provenance.ObjectType,
		&provenance.CanonicalFormat, &provenance.ParserProfileRevision,
		&provenance.EvidenceTextHash, &provenance.AnchorHash, &provenance.HasExternalID,
		&provenance.ExternalIDDigest, &provenance.IsCurrentVersion,
	); err != nil {
		return Fragment{}, fragmentProvenance{}, ErrNotFound
	}

	if err := setExactReadGUCs(ctx, tx, workspaceID, expectedVersionID); err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	textOwner, textEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, fragmentID)
	if err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	text, err := v.codec.Open(textOwner, textEnvelope)
	if err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	if err := setExactReadGUCs(ctx, tx, workspaceID, expectedVersionID); err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	anchorOwner, anchorEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceAnchor, fragmentID)
	if err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	anchor, err := v.codec.Open(anchorOwner, anchorEnvelope)
	if err != nil {
		return Fragment{}, fragmentProvenance{}, err
	}
	var sourcePath string
	if provenance.HasExternalID {
		sourcePath, err = v.readObjectExternalIDExact(ctx, tx, repo, access, workspaceID, expectedVersionID,
			provenance.SourceObjectID, provenance.ObjectType, provenance.ConnectionID, provenance.ExternalIDDigest)
		if err != nil {
			return Fragment{}, fragmentProvenance{}, err
		}
	}
	fragment := Fragment{
		FragmentID: fragmentID, Text: text, Anchor: anchor, SourcePath: sourcePath,
		IsCurrentVersion: provenance.IsCurrentVersion,
		ExtractionID:     provenance.ExtractionID, SourceVersionID: provenance.SourceVersionID,
		Ordinal: provenance.Ordinal, ExternalVersionKey: provenance.ExternalVersionKey,
		ContentHash: provenance.ContentHash, ObservedAt: provenance.ObservedAt,
		SourceObjectID: provenance.SourceObjectID, ConnectionID: provenance.ConnectionID,
		ObjectType: provenance.ObjectType, CanonicalFormat: provenance.CanonicalFormat,
		ParserProfileRevision: provenance.ParserProfileRevision,
		EvidenceTextHash:      provenance.EvidenceTextHash, AnchorHash: provenance.AnchorHash,
	}
	return fragment, provenance, nil
}

func (v *Viewer) readObjectExternalIDExact(ctx context.Context, tx database.Transaction, repo *repository.Repository,
	access database.AccessContext, workspaceID, expectedVersionID, sourceObjectID, objectType, connectionID, opaqueID string) (string, error) {
	if repo == nil || sourceObjectID == "" || objectType == "" {
		return "", ErrNotFound
	}
	if err := setExactReadGUCs(ctx, tx, workspaceID, expectedVersionID); err != nil {
		return "", err
	}
	owner, envelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.SourceObjectExternalID, sourceObjectID)
	if err != nil {
		return "", err
	}
	plaintext, err := v.codec.Open(owner, envelope)
	if err != nil {
		return "", err
	}
	if objectType == "POSTGRESQL_QUERY_ROW" {
		identity, err := parsePostgreSQLQueryIdentity(string(plaintext))
		if err != nil {
			return "", ErrNotFound
		}
		if err := setExactReadGUCs(ctx, tx, workspaceID, expectedVersionID); err != nil {
			return "", err
		}
		locatorOwner, locatorEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.SourceObjectCanonicalLocator, sourceObjectID)
		if err != nil {
			return "", err
		}
		locatorPlaintext, err := v.codec.Open(locatorOwner, locatorEnvelope)
		if err != nil {
			return "", err
		}
		if err := validatePostgreSQLQueryCanonicalLocator(string(locatorPlaintext), connectionID, identity.LineageID, opaqueID); err != nil {
			return "", err
		}
		return sourcePostgreSQLQueryDisplayFromIdentity(identity, opaqueID)
	}
	if objectType != "FILE" && objectType != "GIT_FILE" && objectType != "EMAIL" && objectType != "EMAIL_ATTACHMENT" {
		return "", ErrNotFound
	}
	return sourceExternalPath(string(plaintext))
}
