package evidence

// This file adds the two live-state reads the S3 hybrid retrieval path needs
// on top of the existing authorized viewer. Neither of them is a second
// access-control path: AuthorizedScopeIDs projects exactly the grant path
// app.evidence_fragment_readable already walks, and AuthorizeFragments IS that
// predicate, applied per fragment at the access point. They exist so a
// retrieval channel that ranks outside PostgreSQL can be narrowed by live
// rights before it ranks, and re-checked against live rights after it ranks.

import (
	"context"
	"sort"

	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// maximumAuthorizedScopes bounds the scope projection. A workspace binds
// sources, not objects, so the live set is small by construction; the bound
// keeps a pathological binding from turning one question into an unbounded
// filter clause, and an over-long set is a refusal rather than a truncation
// that would silently narrow an answer.
const maximumAuthorizedScopes = 256

// maximumAuthorizedFragments bounds one post-authorization batch. It is the
// fused candidate ceiling, not a page size: a caller that fuses more than this
// is refused rather than served a silently shortened result.
const maximumAuthorizedFragments = 512

// AuthorizedScopeIDs returns the source scopes the caller may currently read
// through workspaceID: the workspace's CURRENT revision bindings that are
// enabled and WORKSPACE_MANAGED, each covered by an unrevoked grant
// confirmation for that exact source tuple, with live membership of the
// calling principal. It is the same grant path app.evidence_fragment_readable
// walks per fragment, projected once per question so an external ranking
// channel can be restricted to it before it ranks.
//
// It discloses no content and no object identity -- only the scope identifiers
// of sources the caller already sees through knowvault_sources. A caller with
// no live membership receives an empty set, so it is not an existence oracle.
func (v *Viewer) AuthorizedScopeIDs(ctx context.Context, access database.AccessContext, workspaceID string) ([]string, error) {
	if v == nil || v.db == nil || ctx == nil || access.Validate() != nil || workspaceID == "" {
		return nil, ErrNotFound
	}
	scopes := make([]string, 0, 16)
	err := v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT wrs.source_scope_id
			  FROM public.workspace w
			  JOIN public.workspace_member wm
			    ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
			   AND wm.principal_id = app.current_principal_id()
			   AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
			  JOIN public.workspace_revision_source wrs
			    ON wrs.organization_id = w.organization_id AND wrs.workspace_id = w.id
			   AND wrs.workspace_revision = w.current_revision
			   AND wrs.enabled
			   AND wrs.access_mode = 'WORKSPACE_MANAGED'
			  JOIN public.workspace_managed_grant_confirmation c
			    ON c.organization_id = w.organization_id AND c.workspace_id = w.id
			   AND c.workspace_source_id = wrs.workspace_source_id
			   AND c.source_scope_id = wrs.source_scope_id
			   AND c.source_scope_revision = wrs.source_scope_revision
			   AND c.scope_config_hash = wrs.scope_config_hash
			   AND c.access_mode = 'WORKSPACE_MANAGED'
			 WHERE w.organization_id = $1
			   AND w.id = $2
			   AND NOT EXISTS (
			       SELECT 1 FROM public.workspace_managed_grant_revocation gr
			       WHERE gr.organization_id = c.organization_id
			         AND gr.confirmation_id = c.confirmation_id
			   )
			   AND NOT EXISTS (
			       SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
			       WHERE ar.organization_id = c.organization_id
			         AND ar.grant_id = c.confirmation_actor_grant_id
			   )
			 ORDER BY 1`, access.OrganizationID, workspaceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var scopeID string
			if err := rows.Scan(&scopeID); err != nil {
				return err
			}
			scopes = append(scopes, scopeID)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, ErrNotFound
	}
	if len(scopes) > maximumAuthorizedScopes {
		return nil, ErrNotFound
	}
	return scopes, nil
}

// AuthorizeFragments re-resolves a fused candidate set against live state and
// returns only the fragments the caller may read right now, each with its
// decrypted canonical text, anchor and provenance. It is deliberately the same
// access-point predicate (app.evidence_fragment_readable) and the same
// workspace-scoped artifact repository the single-fragment read uses, so a
// candidate produced by an external index cannot enter an answer on the
// strength of what the index believed when it was written: a right revoked
// after indexing, a version superseded after indexing and a scope unbound
// after indexing all drop out here.
//
// It emits no admission event of its own: the caller has already journalled
// one admission for the search that produced these candidates, and one
// admission per candidate would make the journal a function of corpus size
// rather than of what a principal asked for. Unreadable candidates are simply
// absent; the result never reveals which candidate was denied.
func (v *Viewer) AuthorizeFragments(ctx context.Context, access database.AccessContext,
	workspaceID string, fragmentIDs []string) ([]Fragment, error) {
	if v == nil || v.db == nil || ctx == nil || access.Validate() != nil ||
		workspaceID == "" || len(fragmentIDs) > maximumAuthorizedFragments {
		return nil, ErrNotFound
	}
	if len(fragmentIDs) == 0 {
		return nil, nil
	}
	repo, err := repositoryForWorkspace(workspaceID)
	if err != nil {
		return nil, ErrNotFound
	}
	ordered := make([]string, 0, len(fragmentIDs))
	seen := make(map[string]struct{}, len(fragmentIDs))
	for _, fragmentID := range fragmentIDs {
		if fragmentID == "" {
			return nil, ErrNotFound
		}
		if _, duplicate := seen[fragmentID]; duplicate {
			continue
		}
		seen[fragmentID] = struct{}{}
		ordered = append(ordered, fragmentID)
	}
	paths := make(map[string]string)
	authorized := make([]Fragment, 0, len(ordered))
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		for _, fragmentID := range ordered {
			var readable bool
			if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&readable); err != nil {
				return err
			}
			if !readable {
				continue
			}
			textOwner, textEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, fragmentID)
			if err != nil {
				return err
			}
			text, err := v.codec.Open(textOwner, textEnvelope)
			if err != nil {
				return err
			}
			anchorOwner, anchorEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceAnchor, fragmentID)
			if err != nil {
				return err
			}
			anchor, err := v.codec.Open(anchorOwner, anchorEnvelope)
			if err != nil {
				return err
			}
			var provenance fragmentProvenance
			if err := tx.QueryRow(ctx, `
				SELECT f.extraction_id, f.source_version_id, f.ordinal,
				       v.external_version_key, v.content_hash, v.observed_at,
				       v.source_object_id, o.connection_id, o.object_type,
				       extraction.canonical_format, extraction.parser_profile_revision,
				       f.text_hash, f.anchor_hash, o.external_object_id_artifact_id IS NOT NULL,
				       o.external_object_id_digest
				FROM public.evidence_fragment f
				JOIN public.source_version v
				  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
				JOIN public.source_object o
				  ON o.organization_id = v.organization_id AND o.id = v.source_object_id
				JOIN public.source_extraction extraction
				  ON extraction.organization_id = f.organization_id AND extraction.id = f.extraction_id
				WHERE f.organization_id = $1 AND f.id = $2
			`, access.OrganizationID, fragmentID).Scan(
				&provenance.ExtractionID, &provenance.SourceVersionID, &provenance.Ordinal,
				&provenance.ExternalVersionKey, &provenance.ContentHash, &provenance.ObservedAt,
				&provenance.SourceObjectID, &provenance.ConnectionID, &provenance.ObjectType,
				&provenance.CanonicalFormat, &provenance.ParserProfileRevision,
				&provenance.EvidenceTextHash, &provenance.AnchorHash, &provenance.HasExternalID,
				&provenance.ExternalIDDigest,
			); err != nil {
				// The gate above already passed, so a missing or drifting row is
				// a denial of this candidate, not a distinguishable error.
				continue
			}
			sourcePath, cached := paths[provenance.SourceObjectID]
			if provenance.HasExternalID && !cached {
				sourcePath, err = v.readObjectExternalID(ctx, tx, repo, access, provenance.SourceObjectID,
					provenance.ObjectType, provenance.ConnectionID, provenance.ExternalIDDigest)
				if err != nil {
					return err
				}
				paths[provenance.SourceObjectID] = sourcePath
			}
			authorized = append(authorized, Fragment{
				FragmentID: fragmentID, Text: text, Anchor: anchor, SourcePath: sourcePath,
				ExtractionID: provenance.ExtractionID, SourceVersionID: provenance.SourceVersionID,
				Ordinal: provenance.Ordinal, ExternalVersionKey: provenance.ExternalVersionKey,
				ContentHash: provenance.ContentHash, ObservedAt: provenance.ObservedAt,
				SourceObjectID: provenance.SourceObjectID, ConnectionID: provenance.ConnectionID,
				ObjectType: provenance.ObjectType, CanonicalFormat: provenance.CanonicalFormat,
				ParserProfileRevision: provenance.ParserProfileRevision,
				EvidenceTextHash:      provenance.EvidenceTextHash, AnchorHash: provenance.AnchorHash,
			})
		}
		return nil
	})
	if err != nil {
		return nil, ErrNotFound
	}
	sort.SliceStable(authorized, func(i, j int) bool { return authorized[i].FragmentID < authorized[j].FragmentID })
	return authorized, nil
}

// Excerpt renders the bounded ranking excerpt of an authorized fragment around
// the first occurrence of one of the query's terms, and the head of the
// fragment when the match was made by a channel that does not match on words.
// It is the same bounded window the lexical search returns, so a hit's excerpt
// does not depend on which channel found it. The full text is always read back
// by address; an excerpt is for ranking, never for the answer.
func Excerpt(text []byte, query string) string {
	if len(text) == 0 {
		return ""
	}
	value := string(text)
	if terms := viewerSearchTerms(LexicalSearchQuery(query)); len(terms) > 0 {
		if _, excerpt, ok := viewerLexicalMatch(text, terms); ok {
			return excerpt
		}
	}
	return viewerExcerpt(value, value, 0)
}
