package composition

// This file wires the additive R3a-1 KV-A03 `knowvault_related` MCP surface to a
// production relation source. The workspaceapi handler only serves a relation
// tool when the mounted EvidenceService also implements
// workspaceapi.EvidenceRelated; before this file existed no production type did,
// so the tool compiled, was documented and was never advertised. relationEvidence
// is the production implementer: it embeds the authorized *evidence.Viewer (so
// Read, ReadObject, ListObjects and SearchFragments keep their single production
// implementation) and adds RelatedObjects, which composes the existing
// knowledgegraph.Repository.TraverseRelations cross-source relation read behind
// the workspaceapi seam.
//
// It introduces no new store, index, migration, REST route or source capability.
// Authorization is the viewer's own fail-closed gate re-used twice: once for the
// addressed anchor fragment (which also emits admission-before-data and
// citation.opened), and once per related fragment through the same
// workspace-scoped, access-point-re-checked artifact repository. The relation
// call itself appends one content-free admitted event before it reads any
// relation row and a matching failed/denied outcome otherwise, through the same
// R1 audit journal the viewer, inventory and search surfaces use.
//
// The wiki-rag names are not advertised or dispatched by the product (owner
// decision 12.09.2026): a session configured for wiki-rag reconfigures to
// `knowvault_related`, documented in docs/MCP-TOOLS.md.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// relationGraphExpansionLimit mirrors knowledgegraph.maximumGraphHits, the
// package-owned cap on one relation expansion. The production adapter asks the
// existing relation read for exactly that many edges; when the request lands on
// the cap the page is reported as truncated rather than silently dropped.
const relationGraphExpansionLimit = 128

// relationExcerptRunes bounds a relation excerpt, exactly like the search
// surface bounds a hit: a relation never returns the whole related fragment by
// accident.
const relationExcerptRunes = 240

// relationAuditSink is the minimal R1 audit writer the relation source appends
// its admission/outcome events to. The real sink is an *audit.Store; the narrow
// interface keeps the adapter testable without a database.
type relationAuditSink interface {
	Append(ctx context.Context, access database.AccessContext, input audit.EventInput) (audit.Event, error)
}

// relationEvidence is the production relation source. It is the *evidence.Viewer
// plus the cross-source relation read, so mounting it satisfies EvidenceService,
// EvidenceSearch and EvidenceRelated with one value and the relation tool can no
// longer silently unadvertise.
type relationEvidence struct {
	*evidence.Viewer
	db      *database.Store
	graph   *knowledgegraph.Repository
	journal relationAuditSink
}

// The compile-time assertions are the wiring proof: removing the production
// implementer (or dropping the relation method) fails the build, so the tool
// cannot silently regress to unadvertised/unavailable in the deployed product.
var (
	_ workspaceapi.EvidenceService = (*relationEvidence)(nil)
	_ workspaceapi.EvidenceSearch  = (*relationEvidence)(nil)
	_ workspaceapi.EvidenceRelated = (*relationEvidence)(nil)
	_ relationAuditSink            = (*audit.Store)(nil)
)

// newRelationEvidence composes the relation read behind the mounted viewer. All
// three dependencies are required: a missing one is a startup failure rather
// than a silently unwired relation surface.
func newRelationEvidence(viewer *evidence.Viewer, db *database.Store, journal *audit.Store) (*relationEvidence, error) {
	if viewer == nil || db == nil || journal == nil {
		return nil, errors.New("composition: relation evidence dependencies are required")
	}
	return &relationEvidence{
		Viewer:  viewer,
		db:      db,
		graph:   knowledgegraph.NewRepository(),
		journal: journal,
	}, nil
}

// RelatedObjects returns one explicit page of the canonical cross-source
// relations touching the object addressed by fragmentID in workspaceID. It
// reuses the viewer's fail-closed authorization and R1 audit for the anchor and
// for every related fragment it projects, and the persisted entity relation read
// for the edges themselves. Every failure mode collapses into the viewer's single
// content-free ErrNotFound, so an unknown, non-member or cross-workspace call
// leaks no relation, excerpt or address.
func (r *relationEvidence) RelatedObjects(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, direction string, offset, limit int64) (workspaceapi.RelatedPage, error) {
	if r == nil || r.Viewer == nil || r.db == nil || r.journal == nil || ctx == nil ||
		workspaceID == "" || fragmentID == "" || offset < 0 || limit < 1 {
		return workspaceapi.RelatedPage{}, evidence.ErrNotFound
	}
	// The anchor read is the authorization decision for the addressed object;
	// it emits admission-before-data and citation.opened on success, and nothing
	// on the content-free denial.
	if _, err := r.Viewer.Read(ctx, access, workspaceID, fragmentID); err != nil {
		// The relation denial is journalled content-free with its class and a
		// NULL workspace, exactly like the inventory/whole-object denials, so it
		// is neither an existence oracle nor an FK failure.
		if denyErr := r.emitRelationsDenied(ctx, access, workspaceID); denyErr != nil {
			return workspaceapi.RelatedPage{}, fmt.Errorf("%w: %w", evidence.ErrNotFound, denyErr)
		}
		return workspaceapi.RelatedPage{}, evidence.ErrNotFound
	}
	// Admission before the relation rows: once the anchor is authorized the
	// relation call records its own admitted event and only then reads edges. A
	// failed admission is the same content-free refusal with no page.
	if err := r.emitRelationsEvent(ctx, access, workspaceID, fragmentID, audit.OutcomeSuccess, audit.ActionEvidenceReadAdmitted, ""); err != nil {
		return workspaceapi.RelatedPage{}, evidence.ErrNotFound
	}
	refs, truncated, err := r.relationRefs(ctx, access, workspaceID, fragmentID, direction)
	if err != nil {
		_ = r.emitRelationsEvent(ctx, access, workspaceID, fragmentID, audit.OutcomeFailed, audit.ActionEvidenceReadFailed, auditRelationsReadFailedCode)
		return workspaceapi.RelatedPage{}, evidence.ErrNotFound
	}
	start := offset
	if start > int64(len(refs)) {
		start = int64(len(refs))
	}
	end := start + limit
	if end > int64(len(refs)) {
		end = int64(len(refs))
	}
	page := workspaceapi.RelatedPage{Hits: make([]workspaceapi.RelatedHit, 0, end-start)}
	for _, ref := range refs[start:end] {
		related, err := r.Viewer.Read(ctx, access, workspaceID, ref.fragmentID)
		if err != nil {
			// A related fragment that is not readable (revoked, cross-workspace
			// or missing) closes the whole page with no partial relation.
			_ = r.emitRelationsEvent(ctx, access, workspaceID, fragmentID, audit.OutcomeFailed, audit.ActionEvidenceReadFailed, auditRelationsReadFailedCode)
			return workspaceapi.RelatedPage{}, evidence.ErrNotFound
		}
		page.Hits = append(page.Hits, workspaceapi.RelatedHit{
			Fragment:     related,
			RelationKind: ref.kind,
			Excerpt:      relationExcerpt(related.Text),
		})
	}
	if end < int64(len(refs)) {
		page.HasMore = true
		page.NextOffset = end
	}
	page.Truncated = truncated && !page.HasMore
	return page, nil
}

// relationRef is one relation edge projected to the related endpoint: the related
// object's fragment id and the relation predicate that connects it.
type relationRef struct {
	fragmentID string
	kind       string
}

// relationRefs resolves the addressed fragment to its canonical entities,
// traverses the persisted cross-source relations over exactly those entities and
// projects the requested direction to the related endpoint. It reuses
// knowledgegraph.Repository.TraverseRelations so the boundary set (entity ids,
// workspace, graph cap and post-authorized row policy) is the existing one.
//
// truncated reports that the relation read landed on the package expansion cap,
// where more edges may exist than the bounded read can return; the caller
// discloses it instead of silently dropping them.
func (r *relationEvidence) relationRefs(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, direction string) ([]relationRef, bool, error) {
	refs := []relationRef{}
	truncated := false
	err := r.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, err := tx.Query(txCtx, `
			SELECT id
			  FROM public.canonical_entity
			 WHERE organization_id = $1
			   AND workspace_id = $2
			   AND evidence_fragment_id = $3
			 ORDER BY id`, access.OrganizationID, workspaceID, fragmentID)
		if err != nil {
			return err
		}
		entityIDs := make([]string, 0, 8)
		seen := make(map[string]struct{}, 8)
		for rows.Next() {
			var entityID string
			if err := rows.Scan(&entityID); err != nil {
				rows.Close()
				return err
			}
			if _, ok := seen[entityID]; ok {
				continue
			}
			seen[entityID] = struct{}{}
			entityIDs = append(entityIDs, entityID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(entityIDs) == 0 {
			return nil
		}
		if len(entityIDs) > relationGraphExpansionLimit {
			// The traversal cap is the package's own bound; an anchor bound to
			// more entities than the graph read can expand is disclosed rather
			// than silently narrowed.
			entityIDs = entityIDs[:relationGraphExpansionLimit]
			truncated = true
		}
		matches, err := r.graph.TraverseRelations(txCtx, tx, access, workspaceID, entityIDs, relationGraphExpansionLimit)
		if err != nil {
			return err
		}
		addresses := make(map[string]struct{}, len(entityIDs))
		for _, entityID := range entityIDs {
			addresses[entityID] = struct{}{}
		}
		if len(matches) >= relationGraphExpansionLimit {
			truncated = true
		}
		refSeen := make(map[string]struct{}, len(matches))
		for _, match := range matches {
			relatedFragmentID, kind, ok := relationRelatedEndpoint(match, addresses, direction)
			if !ok || relatedFragmentID == "" {
				continue
			}
			key := relatedFragmentID + "\x00" + kind
			if _, ok := refSeen[key]; ok {
				continue
			}
			refSeen[key] = struct{}{}
			refs = append(refs, relationRef{fragmentID: relatedFragmentID, kind: kind})
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return refs, truncated, nil
}

// relationRelatedEndpoint selects the related side of one relation for the
// closed direction vocabulary. referencing keeps the relations whose object is
// the addressed entity (the subject references it); references keeps the
// relations whose subject is the addressed entity (it references the object);
// both keeps either. A self-relation whose two endpoints are both addressed is
// projected once, deterministically to the object endpoint.
func relationRelatedEndpoint(match knowledgegraph.RelationMatch, addressed map[string]struct{}, direction string) (string, string, bool) {
	_, subjectAddressed := addressed[match.SubjectEntityID]
	_, objectAddressed := addressed[match.ObjectEntityID]
	switch direction {
	case workspaceapi.RelatedDirectionReferencing:
		if objectAddressed {
			return match.SubjectEvidenceFragmentID, match.Predicate, true
		}
	case workspaceapi.RelatedDirectionReferences:
		if subjectAddressed {
			return match.ObjectEvidenceFragmentID, match.Predicate, true
		}
	default: // both
		if objectAddressed {
			return match.SubjectEvidenceFragmentID, match.Predicate, true
		}
		if subjectAddressed {
			return match.ObjectEvidenceFragmentID, match.Predicate, true
		}
	}
	return "", "", false
}

// The closed, content-free relation denial/failure classes. Each names no
// fragment, tenant or infrastructure cause, exactly like the inventory and
// search classes they sit beside.
const (
	auditRelationsDeniedCode     = "WORKSPACE_RELATIONS_DENIED"
	auditRelationsReadFailedCode = "WORKSPACE_RELATIONS_READ_FAILED"
)

// emitRelationsEvent appends one content-free relation admission/outcome event
// through the same R1 audit journal the viewer uses. It names the workspace and
// the addressed fragment, never any relation, excerpt or content. An empty
// errorCode is the successful admission; a denial or failure supplies the closed
// class. A failure to append is returned so the caller fails closed.
func (r *relationEvidence) emitRelationsEvent(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string, outcome audit.Outcome, action audit.Action, errorCode string) error {
	if r == nil || r.journal == nil {
		return errors.New("composition: relation audit requires the audit journal")
	}
	eventID, err := relationEventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	resourceID := fragmentID
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      &workspaceID,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           action,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       resourceID,
		RequestID:        access.RequestID,
		Outcome:          outcome,
		OccurredAt:       time.Now().UTC(),
	}
	if errorCode != "" {
		input.ErrorCode = &errorCode
	}
	_, err = r.journal.Append(ctx, access, input)
	return err
}

// emitRelationsDenied appends the content-free denied admission event for a
// relation request the caller may not serve. Like every denial it records a NULL
// workspace so the denial can neither fail the workspace foreign key nor let a
// journal reader distinguish an unknown workspace from a forbidden one.
func (r *relationEvidence) emitRelationsDenied(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if r == nil || r.journal == nil {
		return errors.New("composition: relation audit requires the audit journal")
	}
	eventID, err := relationEventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	errorCode := auditRelationsDeniedCode
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      nil,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           audit.ActionEvidenceReadAdmitted,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       workspaceID,
		RequestID:        access.RequestID,
		Outcome:          audit.OutcomeDenied,
		ErrorCode:        &errorCode,
		OccurredAt:       time.Now().UTC(),
	}
	_, err = r.journal.Append(ctx, access, input)
	return err
}

// relationEventID produces a unique, printable journal event identifier.
func relationEventID() (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("composition: relation audit event id: %w", err)
	}
	return "aud_" + hex.EncodeToString(random[:]), nil
}

// relationExcerpt returns a bounded, rune-safe prefix of the related fragment
// text, mirroring the search surface's excerpt bound so a relation never returns
// the whole fragment by accident.
func relationExcerpt(text []byte) string {
	if len(text) == 0 {
		return ""
	}
	if utf8.RuneCount(text) <= relationExcerptRunes {
		return string(text)
	}
	runes := []rune(string(text))
	return strings.TrimSpace(string(runes[:relationExcerptRunes])) + "…"
}
