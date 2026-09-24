package workspacecontext

// Store is S2 card A's PostgreSQL persistence boundary for the
// workspace-model-context-v1 document (ADR-0098, S2-MODEL-CONTEXT-DESIGN.md,
// migration 000112). It is the sole implementation of the Reader interface
// A0 fixed (interfaces.go), and additionally exposes the write surface
// (Save, Restore) and the read-catalog surface (Versions, VersionAt) the REST
// transport (internal/platform/workspaceapi/model_context.go) calls.
//
// Every method re-checks the caller's workspace access through the existing
// workspace.Snapshot authority, exactly like internal/metricdef.Store: a
// successful Get already proves a readable member (RLS on workspace_member
// itself already makes another organization's or another workspace's rows
// invisible), and OWNER/MANAGER standing is resolved from that same live
// snapshot. Postgres RLS on the two tables this file owns
// (workspace_model_context, workspace_model_context_version) is a second,
// independent enforcement layer: SELECT is open to any active member, INSERT
// and the pointer UPDATE are restricted to an active OWNER/MANAGER row, and
// neither table grants DELETE. A caller who is denied by the Go-level check
// never even reaches a query that RLS would also have refused.
//
// A version row is immutable (workspace_model_context_version_immutable
// trigger) and the pointer only ever advances (workspace_model_context_immutable
// trigger): Save and Restore both insert a new version row and move the
// pointer forward inside one write transaction, atomically with exactly one
// audit.workspace.model_context_revised event
// (ActionWorkspaceModelContextRevised). A read that the REST transport serves
// (GET current, GET a historical version) is additionally recorded as exactly
// one audit.workspace.model_context_read event; the pure Reader methods
// (Current, SourceNotes) that chat (card B) and MCP (card C) call directly
// stay unaudited here by design, since those callers own their own read
// provenance (ToolLoopRecord.WorkspaceContext for chat; an MCP-side admission
// journal for card C), and auditing every per-turn chat read at this layer
// would multiply one conversation turn into many audit_event rows for a
// single logical read.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
)

// emptyContextSentinel is the If-Match value S2-CONTRACT.md requires for a
// workspace that has no context yet (version 0): a literal, not a real
// digest, so it can never collide with an issued content hash (every real
// hash is exactly "sha256:" + 64 lowercase hex characters, per
// workspace.IsConfigurationHash / app.workspace_command_hash_is_valid).
const emptyContextSentinel = "sha256:empty"

// Additional, store-specific error codes layered onto the ErrorCode type
// workspacecontext.go already declares (CodeInvalidDocument,
// CodeUnknownLocation, CodeHashFailed remain Validate's own).
const (
	// CodeAccessDenied is returned when the caller holds no readable
	// membership in the named workspace at all (or it does not exist / is in
	// a different organization). The transport collapses it with NOT_FOUND so
	// a stranger learns nothing about whether a workspace exists.
	CodeAccessDenied ErrorCode = "WORKSPACE_CONTEXT_ACCESS_DENIED"
	// CodeNotEditor is returned when the caller IS a readable member but is
	// not a current OWNER/MANAGER attempting a write. Unlike CodeAccessDenied
	// it maps to 403 FORBIDDEN (S2-CONTRACT.md "403 for members"): a member
	// already knows the workspace exists, so refusing their write is not an
	// existence oracle.
	CodeNotEditor ErrorCode = "WORKSPACE_CONTEXT_NOT_EDITOR"
	// CodeVersionNotFound is returned for a requested historical version, or
	// a restore target, the workspace does not hold.
	CodeVersionNotFound ErrorCode = "WORKSPACE_CONTEXT_VERSION_NOT_FOUND"
	// CodeRevisionConflict is the 412 precondition-failed outcome: the
	// caller's If-Match hash no longer names the current version.
	CodeRevisionConflict ErrorCode = "WORKSPACE_CONTEXT_REVISION_CONFLICT"
	// CodeIdempotencyConflict is the 409 outcome: the same Idempotency-Key
	// was already used, by the same actor on the same workspace, for a
	// materially different request.
	CodeIdempotencyConflict ErrorCode = "WORKSPACE_CONTEXT_IDEMPOTENCY_CONFLICT"
	// CodeStoreUnavailable marks a construction or persistence failure that
	// carries no other content-free code.
	CodeStoreUnavailable ErrorCode = "WORKSPACE_CONTEXT_STORE_UNAVAILABLE"
)

// WorkspaceAuthority is the existing workspace/membership snapshot authority.
// Store invents no second access-control path, mirroring
// internal/metricdef.Store's WorkspaceAuthority exactly.
type WorkspaceAuthority interface {
	Get(ctx context.Context, access database.AccessContext, workspaceID string) (workspace.Snapshot, error)
}

// Store is safe for concurrent use once constructed.
type Store struct {
	database   *database.Store
	workspaces WorkspaceAuthority
	audit      *audit.Store
	now        func() time.Time
}

// NewStore binds the versioned document catalog to the reviewed database, the
// existing workspace authority and the audit journal. Every argument is
// mandatory: a nil audit boundary would let a revision or a read persist
// without its required event, which S2-CONTRACT.md never allows.
func NewStore(databaseStore *database.Store, workspaces WorkspaceAuthority, auditStore *audit.Store) (*Store, error) {
	if databaseStore == nil || workspaces == nil || auditStore == nil {
		return nil, &Error{code: CodeStoreUnavailable}
	}
	return &Store{database: databaseStore, workspaces: workspaces, audit: auditStore, now: time.Now}, nil
}

// authorize re-checks the caller's workspace access through the existing
// snapshot authority. A read needs only a readable membership (Get success is
// that proof); a write additionally needs the caller to currently hold OWNER
// or MANAGER in that same live snapshot.
func (store *Store) authorize(ctx context.Context, access database.AccessContext,
	workspaceID string, requireEditor bool) (workspace.Snapshot, bool, error) {
	if store == nil || store.database == nil || store.workspaces == nil || store.audit == nil || ctx == nil ||
		access.Validate() != nil || !validWorkspaceID(workspaceID) {
		return workspace.Snapshot{}, false, &Error{code: CodeInvalidDocument}
	}
	snapshot, err := store.workspaces.Get(ctx, access, workspaceID)
	if err != nil || snapshot.ID != workspaceID || snapshot.OrganizationID != access.OrganizationID {
		return workspace.Snapshot{}, false, &Error{code: CodeAccessDenied}
	}
	editable := isEditor(snapshot, access.PrincipalID)
	if requireEditor && !editable {
		return workspace.Snapshot{}, false, &Error{code: CodeNotEditor}
	}
	return snapshot, editable, nil
}

func isEditor(snapshot workspace.Snapshot, principalID string) bool {
	for _, member := range snapshot.Members {
		if member.PrincipalID == principalID && (member.Role == workspace.RoleOwner || member.Role == workspace.RoleManager) {
			return true
		}
	}
	return false
}

func validWorkspaceID(value string) bool {
	return len(value) >= 3 && len(value) <= 128
}

func toDatabaseAccess(access Access) database.AccessContext {
	return database.AccessContext{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID}
}

func actorType(access database.AccessContext) audit.ActorType {
	if access.ActorKind == database.ActorKindService {
		return audit.ActorService
	}
	return audit.ActorHuman
}

// Current satisfies Reader.Current: it returns workspaceID's pinned current
// version, unaudited (see the package-level doc above). A workspace with no
// saved context yet returns Version{Number: 0} with an empty Document, per
// S2-CONTRACT.md "A workspace without a context returns version 0 and an
// empty document."
func (store *Store) Current(ctx context.Context, access Access, workspaceID string) (Version, error) {
	return store.currentVersion(ctx, toDatabaseAccess(access), workspaceID)
}

// SourceNotes satisfies Reader.SourceNotes: one enabled source's own notes
// from the current context, for S3's knowvault_source_schema. A source the
// current document does not mention yet (including when the workspace has no
// context at all) is not an error: it returns empty notes at the current
// version, so a caller merges live schema with "no notes recorded" rather
// than failing.
func (store *Store) SourceNotes(ctx context.Context, access Access, workspaceID, sourceConnectionID string) (SourceNotes, error) {
	version, err := store.currentVersion(ctx, toDatabaseAccess(access), workspaceID)
	if err != nil {
		return SourceNotes{}, err
	}
	for _, source := range version.Document.Sources {
		if source.SourceConnectionID == sourceConnectionID {
			return SourceNotes{ContextVersion: version.Number, Source: source}, nil
		}
	}
	return SourceNotes{ContextVersion: version.Number, Source: Source{SourceConnectionID: sourceConnectionID}}, nil
}

// VersionRecord is Version plus its own row's provenance (who created it and
// when). REST's GET/PUT/restore response needs updated_at/updated_by
// (S2-CONTRACT.md); Reader.Current's callers (chat, MCP) do not, so this
// stays a REST-only wrapper rather than widening A0's frozen Version shape.
type VersionRecord struct {
	Version
	CreatedAt time.Time
	CreatedBy string
}

// CurrentForREST is the audited read the REST transport calls for
// GET .../model-context: the same Current projection, plus its provenance and
// exactly one audit.workspace.model_context_read event on success.
func (store *Store) CurrentForREST(ctx context.Context, access database.AccessContext, workspaceID string) (VersionRecord, error) {
	record, err := store.currentVersionRecord(ctx, access, workspaceID)
	if err != nil {
		return VersionRecord{}, err
	}
	if err := store.recordRead(ctx, access, workspaceID); err != nil {
		return VersionRecord{}, err
	}
	return record, nil
}

// VersionAtForREST is the audited read for
// GET .../model-context/versions/{version}: VersionAt plus exactly one
// audit.workspace.model_context_read event on success. Its Editable is
// always false (S2-CONTRACT.md: "the GET shape for that version, with
// editable: false"): a historical version is never itself editable, only
// restorable.
func (store *Store) VersionAtForREST(ctx context.Context, access database.AccessContext, workspaceID string, versionNumber int64) (VersionRecord, error) {
	record, err := store.VersionAt(ctx, access, workspaceID, versionNumber)
	if err != nil {
		return VersionRecord{}, err
	}
	if err := store.recordRead(ctx, access, workspaceID); err != nil {
		return VersionRecord{}, err
	}
	return record, nil
}

// VersionAt returns exactly one historical version of workspaceID, unaudited.
func (store *Store) VersionAt(ctx context.Context, access database.AccessContext, workspaceID string, versionNumber int64) (VersionRecord, error) {
	if _, _, err := store.authorize(ctx, access, workspaceID, false); err != nil {
		return VersionRecord{}, err
	}
	if versionNumber < 1 {
		return VersionRecord{}, &Error{code: CodeVersionNotFound}
	}
	var record VersionRecord
	found := false
	err := store.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		loaded, _, ok, loadErr := loadVersionRowRaw(ctx, tx, access.OrganizationID, workspaceID, versionNumber)
		if loadErr != nil {
			return loadErr
		}
		record, found = loaded, ok
		return nil
	})
	if err != nil {
		return VersionRecord{}, storeFailure(err)
	}
	if !found {
		return VersionRecord{}, &Error{code: CodeVersionNotFound}
	}
	// A historical version is never itself editable, only restorable.
	record.Editable = false
	return record, nil
}

// VersionSummary is one workspace_model_context_version row's history
// metadata, the shape GET .../model-context/versions publishes: the document
// content itself is not included (only the exact-version read carries it).
type VersionSummary struct {
	Version     int64
	ContentHash string
	ChangeKind  string
	CreatedAt   time.Time
	CreatedBy   string
	ProposalID  string
}

const (
	defaultVersionPageLimit = 20
	maxVersionPageLimit     = 100
)

// Versions returns a descending page of workspaceID's version history.
// cursor is the version number to page strictly before (0 means "from the
// most recent"); the returned nextCursor is 0 when there is no further page.
func (store *Store) Versions(ctx context.Context, access database.AccessContext, workspaceID string, limit int, cursor int64) ([]VersionSummary, int64, error) {
	if _, _, err := store.authorize(ctx, access, workspaceID, false); err != nil {
		return nil, 0, err
	}
	if limit < 1 {
		limit = defaultVersionPageLimit
	}
	if limit > maxVersionPageLimit {
		limit = maxVersionPageLimit
	}
	var cursorParam any
	if cursor > 0 {
		cursorParam = cursor
	}
	summaries := []VersionSummary{}
	err := store.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		rows, queryErr := tx.Query(ctx, `
			SELECT version, content_hash, change_kind, created_at, created_by, proposal_id
			FROM public.workspace_model_context_version
			WHERE organization_id = $1 AND workspace_id = $2 AND ($3::bigint IS NULL OR version < $3)
			ORDER BY version DESC
			LIMIT $4
		`, access.OrganizationID, workspaceID, cursorParam, limit+1)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var summary VersionSummary
			var proposalID *string
			if scanErr := rows.Scan(&summary.Version, &summary.ContentHash, &summary.ChangeKind,
				&summary.CreatedAt, &summary.CreatedBy, &proposalID); scanErr != nil {
				return scanErr
			}
			if proposalID != nil {
				summary.ProposalID = *proposalID
			}
			summaries = append(summaries, summary)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, storeFailure(err)
	}
	var nextCursor int64
	if len(summaries) > limit {
		nextCursor = summaries[limit-1].Version
		summaries = summaries[:limit]
	}
	return summaries, nextCursor, nil
}

// currentVersion is the shared, unaudited read both Current and the REST
// wrappers build on.
func (store *Store) currentVersion(ctx context.Context, access database.AccessContext, workspaceID string) (Version, error) {
	record, err := store.currentVersionRecord(ctx, access, workspaceID)
	if err != nil {
		return Version{}, err
	}
	return record.Version, nil
}

// currentVersionRecord is the shared, unaudited read Current, SourceNotes and
// CurrentForREST all build on.
func (store *Store) currentVersionRecord(ctx context.Context, access database.AccessContext, workspaceID string) (VersionRecord, error) {
	_, editable, err := store.authorize(ctx, access, workspaceID, false)
	if err != nil {
		return VersionRecord{}, err
	}
	var record VersionRecord
	found := false
	err = store.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		loaded, ok, loadErr := loadCurrentVersion(ctx, tx, access.OrganizationID, workspaceID)
		if loadErr != nil {
			return loadErr
		}
		record, found = loaded, ok
		return nil
	})
	if err != nil {
		return VersionRecord{}, storeFailure(err)
	}
	if !found {
		return VersionRecord{Version: Version{Number: 0, ContentHash: "", Document: Document{}, Editable: editable}}, nil
	}
	record.Editable = editable
	return record, nil
}

func loadCurrentVersion(ctx context.Context, tx database.Transaction, organizationID, workspaceID string) (VersionRecord, bool, error) {
	var versionNumber int64
	var contentHash string
	var documentRaw []byte
	var createdAt time.Time
	var createdBy string
	scanErr := tx.ScanRow(ctx, `
		SELECT v.version, v.content_hash, v.document, v.created_at, v.created_by
		FROM public.workspace_model_context AS pointer
		JOIN public.workspace_model_context_version AS v
		  ON v.organization_id = pointer.organization_id AND v.workspace_id = pointer.workspace_id
		 AND v.version = pointer.current_version
		WHERE pointer.organization_id = $1 AND pointer.workspace_id = $2
	`, []any{organizationID, workspaceID}, &versionNumber, &contentHash, &documentRaw, &createdAt, &createdBy)
	if database.IsNotFound(scanErr) {
		return VersionRecord{}, false, nil
	}
	if scanErr != nil {
		return VersionRecord{}, false, scanErr
	}
	document, decodeErr := decodeDocument(documentRaw)
	if decodeErr != nil {
		return VersionRecord{}, false, decodeErr
	}
	return VersionRecord{
		Version:   Version{Number: versionNumber, ContentHash: contentHash, Document: document},
		CreatedAt: createdAt, CreatedBy: createdBy,
	}, true, nil
}

// Save validates document (minting any missing Rule/Term id first) and
// persists it as workspaceID's next version, atomically moving the pointer
// forward and appending exactly one audit.workspace.model_context_revised
// event. ifMatchHash must equal the current pointer's hash, or
// emptyContextSentinel when the workspace has no context yet; any other
// value is CodeRevisionConflict (mapped to HTTP 412 by the transport).
// idempotencyKey scopes a replay: the same key with the same document
// returns the version that call already created instead of minting a new
// one, and the same key with a different document is
// CodeIdempotencyConflict.
func (store *Store) Save(ctx context.Context, access database.AccessContext, workspaceID string,
	document Document, ifMatchHash, idempotencyKey string) (VersionRecord, error) {
	snapshot, editable, err := store.authorize(ctx, access, workspaceID, true)
	if err != nil {
		return VersionRecord{}, err
	}
	if idempotencyKey == "" || !validIfMatch(ifMatchHash) {
		return VersionRecord{}, &Error{code: CodeInvalidDocument}
	}
	// The idempotency request hash is computed on the caller's raw, pre-mint
	// document (empty ids and all): a byte-identical retry hashes identically
	// even though minting fresh ids on the eventual write path is otherwise
	// nondeterministic. It is scoped to the SAVE operation so the same raw key
	// can never be replayed against a different command.
	rawHash, err := Hash(document)
	if err != nil {
		return VersionRecord{}, err
	}
	requestHash := scopedHash("SAVE", rawHash)
	keyHash := scopedHash("KEY", idempotencyKey)

	projections, err := store.loadKnownProjections(ctx, access, snapshot)
	if err != nil {
		return VersionRecord{}, err
	}

	var result VersionRecord
	err = store.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if cachedVersion, ok, cacheErr := reconcileIdempotency(ctx, tx, access, workspaceID, keyHash, requestHash); cacheErr != nil {
			return cacheErr
		} else if ok {
			cached, found, loadErr := loadVersionRow(ctx, tx, access.OrganizationID, workspaceID, cachedVersion)
			if loadErr != nil {
				return loadErr
			}
			if !found {
				return &Error{code: CodeStoreUnavailable}
			}
			cached.Editable = editable
			result = cached
			return nil
		}

		current, found, loadErr := loadCurrentVersion(ctx, tx, access.OrganizationID, workspaceID)
		if loadErr != nil {
			return loadErr
		}
		expectedHash := emptyContextSentinel
		if found {
			expectedHash = current.ContentHash
		}
		if ifMatchHash != expectedHash {
			return &Error{code: CodeRevisionConflict}
		}

		minted, mintErr := mintMissingIDs(document)
		if mintErr != nil {
			return mintErr
		}
		normalized, validateErr := Validate(minted, projections)
		if validateErr != nil {
			return validateErr
		}
		documentBytes, contentHash, hashErr := canonicalDocumentBytesAndHash(normalized)
		if hashErr != nil {
			return hashErr
		}

		nextVersion := int64(1)
		if found {
			nextVersion = current.Number + 1
		}
		if err := insertVersionRow(ctx, tx, access, workspaceID, nextVersion, documentBytes, contentHash,
			"EDIT", nil, nil); err != nil {
			return err
		}
		if err := upsertPointer(ctx, tx, access, workspaceID, nextVersion, contentHash, found); err != nil {
			return err
		}
		if err := recordIdempotency(ctx, tx, access, workspaceID, keyHash, requestHash, nextVersion); err != nil {
			return err
		}
		if err := store.appendRevised(ctx, tx, access, workspaceID); err != nil {
			return err
		}
		result = VersionRecord{
			Version:   Version{Number: nextVersion, ContentHash: contentHash, Document: normalized, Editable: editable},
			CreatedAt: store.now().UTC(), CreatedBy: access.PrincipalID,
		}
		return nil
	})
	if err != nil {
		return VersionRecord{}, storeFailure(err)
	}
	return result, nil
}

// Restore mints a new version whose document is byte-identical to
// targetVersion's, atomically moving the pointer forward and appending
// exactly one audit.workspace.model_context_revised event. Preconditions and
// idempotency behave exactly like Save.
func (store *Store) Restore(ctx context.Context, access database.AccessContext, workspaceID string,
	targetVersion int64, ifMatchHash, idempotencyKey string) (VersionRecord, error) {
	_, editable, err := store.authorize(ctx, access, workspaceID, true)
	if err != nil {
		return VersionRecord{}, err
	}
	if idempotencyKey == "" || !validIfMatch(ifMatchHash) || targetVersion < 1 {
		return VersionRecord{}, &Error{code: CodeInvalidDocument}
	}
	requestHash := scopedHash("RESTORE", versionToken(targetVersion))
	keyHash := scopedHash("KEY", idempotencyKey)

	var result VersionRecord
	err = store.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if cachedVersion, ok, cacheErr := reconcileIdempotency(ctx, tx, access, workspaceID, keyHash, requestHash); cacheErr != nil {
			return cacheErr
		} else if ok {
			cached, found, loadErr := loadVersionRow(ctx, tx, access.OrganizationID, workspaceID, cachedVersion)
			if loadErr != nil {
				return loadErr
			}
			if !found {
				return &Error{code: CodeStoreUnavailable}
			}
			cached.Editable = editable
			result = cached
			return nil
		}

		current, found, loadErr := loadCurrentVersion(ctx, tx, access.OrganizationID, workspaceID)
		if loadErr != nil {
			return loadErr
		}
		expectedHash := emptyContextSentinel
		if found {
			expectedHash = current.ContentHash
		}
		if ifMatchHash != expectedHash {
			return &Error{code: CodeRevisionConflict}
		}

		target, documentBytes, targetFound, loadErr := loadVersionRowRaw(ctx, tx, access.OrganizationID, workspaceID, targetVersion)
		if loadErr != nil {
			return loadErr
		}
		if !targetFound {
			return &Error{code: CodeVersionNotFound}
		}

		nextVersion := int64(1)
		if found {
			nextVersion = current.Number + 1
		}
		restoredFrom := targetVersion
		if err := insertVersionRow(ctx, tx, access, workspaceID, nextVersion, documentBytes, target.ContentHash,
			"RESTORE", nil, &restoredFrom); err != nil {
			return err
		}
		if err := upsertPointer(ctx, tx, access, workspaceID, nextVersion, target.ContentHash, found); err != nil {
			return err
		}
		if err := recordIdempotency(ctx, tx, access, workspaceID, keyHash, requestHash, nextVersion); err != nil {
			return err
		}
		if err := store.appendRevised(ctx, tx, access, workspaceID); err != nil {
			return err
		}
		result = VersionRecord{
			Version:   Version{Number: nextVersion, ContentHash: target.ContentHash, Document: target.Document, Editable: editable},
			CreatedAt: store.now().UTC(), CreatedBy: access.PrincipalID,
		}
		return nil
	})
	if err != nil {
		return VersionRecord{}, storeFailure(err)
	}
	return result, nil
}

func validIfMatch(value string) bool {
	return value == emptyContextSentinel || workspace.IsConfigurationHash(value)
}

func loadVersionRow(ctx context.Context, tx database.Transaction, organizationID, workspaceID string, versionNumber int64) (VersionRecord, bool, error) {
	record, _, found, err := loadVersionRowRaw(ctx, tx, organizationID, workspaceID, versionNumber)
	return record, found, err
}

func loadVersionRowRaw(ctx context.Context, tx database.Transaction, organizationID, workspaceID string, versionNumber int64) (VersionRecord, []byte, bool, error) {
	var contentHash string
	var documentRaw []byte
	var createdAt time.Time
	var createdBy string
	scanErr := tx.ScanRow(ctx, `
		SELECT content_hash, document, created_at, created_by
		FROM public.workspace_model_context_version
		WHERE organization_id = $1 AND workspace_id = $2 AND version = $3
	`, []any{organizationID, workspaceID, versionNumber}, &contentHash, &documentRaw, &createdAt, &createdBy)
	if database.IsNotFound(scanErr) {
		return VersionRecord{}, nil, false, nil
	}
	if scanErr != nil {
		return VersionRecord{}, nil, false, scanErr
	}
	document, decodeErr := decodeDocument(documentRaw)
	if decodeErr != nil {
		return VersionRecord{}, nil, false, decodeErr
	}
	return VersionRecord{
		Version:   Version{Number: versionNumber, ContentHash: contentHash, Document: document},
		CreatedAt: createdAt, CreatedBy: createdBy,
	}, documentRaw, true, nil
}

func insertVersionRow(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID string,
	versionNumber int64, documentBytes []byte, contentHash, changeKind string, proposalID *string, restoredFromVersion *int64) error {
	var parentVersion any
	if versionNumber > 1 {
		parentVersion = versionNumber - 1
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_model_context_version (
			organization_id, workspace_id, version, document, content_hash,
			parent_version, change_kind, proposal_id, restored_from_version, created_by
		) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10)
	`, access.OrganizationID, workspaceID, versionNumber, documentBytes, contentHash,
		parentVersion, changeKind, proposalID, restoredFromVersion, access.PrincipalID)
	return err
}

func upsertPointer(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID string,
	versionNumber int64, contentHash string, exists bool) error {
	if !exists {
		_, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_model_context (organization_id, workspace_id, current_version, current_hash, updated_by)
			VALUES ($1, $2, $3, $4, $5)
		`, access.OrganizationID, workspaceID, versionNumber, contentHash, access.PrincipalID)
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.workspace_model_context
		SET current_version = $3, current_hash = $4, updated_by = $5, updated_at = transaction_timestamp()
		WHERE organization_id = $1 AND workspace_id = $2
	`, access.OrganizationID, workspaceID, versionNumber, contentHash, access.PrincipalID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return &Error{code: CodeRevisionConflict}
	}
	return nil
}

// reconcileIdempotency looks up a previously recorded command under keyHash.
// It returns (version, true, nil) on an exact replay (same request), (0,
// false, nil) when the key is unused, and a CodeIdempotencyConflict error
// when the key was already used for a materially different request.
func reconcileIdempotency(ctx context.Context, tx database.Transaction, access database.AccessContext,
	workspaceID, keyHash, requestHash string) (int64, bool, error) {
	var resultVersion int64
	var storedRequestHash string
	scanErr := tx.ScanRow(ctx, `
		SELECT result_version, request_hash
		FROM public.workspace_model_context_command
		WHERE organization_id = $1 AND workspace_id = $2 AND actor_principal_id = $3 AND idempotency_key_hash = $4
	`, []any{access.OrganizationID, workspaceID, access.PrincipalID, keyHash}, &resultVersion, &storedRequestHash)
	if database.IsNotFound(scanErr) {
		return 0, false, nil
	}
	if scanErr != nil {
		return 0, false, scanErr
	}
	if storedRequestHash != requestHash {
		return 0, false, &Error{code: CodeIdempotencyConflict}
	}
	return resultVersion, true, nil
}

func recordIdempotency(ctx context.Context, tx database.Transaction, access database.AccessContext,
	workspaceID, keyHash, requestHash string, versionNumber int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_model_context_command (
			organization_id, workspace_id, actor_principal_id, idempotency_key_hash, request_hash, result_version
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, access.OrganizationID, workspaceID, access.PrincipalID, keyHash, requestHash, versionNumber)
	return err
}

// appendRevised appends exactly one audit.workspace.model_context_revised
// event inside the same write transaction as the version insert and pointer
// move, so the event and the state change commit or roll back together.
func (store *Store) appendRevised(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID string) error {
	return store.appendDocumentEvent(ctx, tx, access, workspaceID, audit.ActionWorkspaceModelContextRevised)
}

// recordRead appends exactly one audit.workspace.model_context_read event in
// its own transaction, for the two audited REST read wrappers.
func (store *Store) recordRead(ctx context.Context, access database.AccessContext, workspaceID string) error {
	eventID, err := ids.New("aev")
	if err != nil {
		return &Error{code: CodeStoreUnavailable, cause: err}
	}
	actorID := access.PrincipalID
	workspaceValue := workspaceID
	_, appendErr := store.audit.Append(ctx, access, audit.EventInput{
		EventID: eventID, ActorType: actorType(access), ActorPrincipalID: &actorID,
		Action: audit.ActionWorkspaceModelContextRead, ResourceType: audit.ResourceWorkspaceModelContext,
		ResourceID: workspaceID, RequestID: access.RequestID, WorkspaceID: &workspaceValue,
		Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
	})
	if appendErr != nil {
		return &Error{code: CodeStoreUnavailable, cause: appendErr}
	}
	return nil
}

func (store *Store) appendDocumentEvent(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID string, action audit.Action) error {
	eventID, err := ids.New("aev")
	if err != nil {
		return &Error{code: CodeStoreUnavailable, cause: err}
	}
	actorID := access.PrincipalID
	workspaceValue := workspaceID
	_, appendErr := store.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID: eventID, ActorType: actorType(access), ActorPrincipalID: &actorID,
		Action: action, ResourceType: audit.ResourceWorkspaceModelContext,
		ResourceID: workspaceID, RequestID: access.RequestID, WorkspaceID: &workspaceValue,
		Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
	})
	if appendErr != nil {
		return &Error{code: CodeStoreUnavailable, cause: appendErr}
	}
	return nil
}

// mintMissingIDs returns a copy of document in which every Rule and Term
// whose ID is empty ("new item" per S2-CONTRACT.md "New items are sent with
// \"id\": \"\"; the server assigns ids") receives a fresh server-assigned id
// (internal/source/ids.New with this package's own rule_/term_ prefixes).
// An already-assigned id is left untouched: Validate is the sole judge of
// whether it is well-formed.
func mintMissingIDs(document Document) (Document, error) {
	minted := Document{
		Description: document.Description,
		Rules:       make([]Rule, len(document.Rules)),
		Glossary:    make([]Term, len(document.Glossary)),
		Sources:     document.Sources,
	}
	for index, rule := range document.Rules {
		if rule.ID == "" {
			freshID, err := ids.New(rulePrefix)
			if err != nil {
				return Document{}, &Error{code: CodeStoreUnavailable, cause: err}
			}
			rule.ID = freshID
		}
		minted.Rules[index] = rule
	}
	for index, term := range document.Glossary {
		if term.ID == "" {
			freshID, err := ids.New(termPrefix)
			if err != nil {
				return Document{}, &Error{code: CodeStoreUnavailable, cause: err}
			}
			term.ID = freshID
		}
		minted.Glossary[index] = term
	}
	return minted, nil
}

// canonicalDocumentBytesAndHash projects doc into its stored jsonb bytes and
// content hash in one pass, so the two can never drift: what Hash commits to
// is byte-for-byte what document_bytes stores.
func canonicalDocumentBytesAndHash(doc Document) ([]byte, string, error) {
	canonicalBytes, err := canonicalBytesOf(doc)
	if err != nil {
		return nil, "", &Error{code: CodeHashFailed, cause: err}
	}
	return canonicalBytes, canon.Hash(canonicalBytes), nil
}

// decodeDocument is canonicalBytesOf's inverse: it reads a stored
// workspace_model_context_version.document value back into a Document. The
// stored bytes are exactly what canonicalDocumentBytesAndHash wrote, so a
// plain JSON unmarshal into the same canonicalDocument shape round-trips
// without re-deriving a second serializer.
func decodeDocument(raw []byte) (Document, error) {
	var stored canonicalDocument
	if err := json.Unmarshal(raw, &stored); err != nil {
		return Document{}, &Error{code: CodeStoreUnavailable, cause: err}
	}
	document := Document{Description: stored.Description}
	document.Rules = make([]Rule, len(stored.Rules))
	for index, rule := range stored.Rules {
		document.Rules[index] = Rule{ID: rule.ID, Text: rule.Text}
	}
	document.Glossary = make([]Term, len(stored.Glossary))
	for index, term := range stored.Glossary {
		locations := make([]DataLocation, len(term.DataLocations))
		for locationIndex, location := range term.DataLocations {
			locations[locationIndex] = DataLocation{
				SourceConnectionID: location.SourceConnectionID, Relation: location.Relation,
				Column: location.Column, Hint: location.Hint,
			}
		}
		document.Glossary[index] = Term{
			ID: term.ID, Term: term.Term, Synonyms: append([]string(nil), term.Synonyms...),
			Definition: term.Definition, DataLocations: locations,
		}
	}
	document.Sources = make([]Source, len(stored.Sources))
	for index, source := range stored.Sources {
		tables := make([]Table, len(source.Tables))
		for tableIndex, table := range source.Tables {
			columns := make([]Column, len(table.Columns))
			for columnIndex, column := range table.Columns {
				columns[columnIndex] = Column{Name: column.Name, Note: column.Note}
			}
			tables[tableIndex] = Table{Relation: table.Relation, Note: table.Note, Columns: columns}
		}
		document.Sources[index] = Source{
			SourceConnectionID: source.SourceConnectionID, Description: source.Description, Tables: tables,
		}
	}
	return document, nil
}

// KnownProjections resolves workspaceID's current KnownProjection set (every
// enabled source binding's registered, exclusion-narrowed relation/column
// projection), for a caller that needs to run Validate itself outside Save --
// concretely, card E's workspacecontext.ProposalService.Accept implementation,
// which must merge a proposal's change into the current document and validate
// the result before calling AcceptProposalVersion.
func (store *Store) KnownProjections(ctx context.Context, access database.AccessContext, workspaceID string) ([]KnownProjection, error) {
	snapshot, _, err := store.authorize(ctx, access, workspaceID, false)
	if err != nil {
		return nil, err
	}
	return store.loadKnownProjections(ctx, access, snapshot)
}

// AcceptProposalVersion is the version half of accepting a context proposal
// (ADR-0098 decision 4, S2-CONTRACT.md "POST .../proposals/{proposal_id}:accept").
// Card E's workspacecontext.ProposalService.Accept implementation is expected
// to: re-authorize the caller as an OWNER/MANAGER, load the current document
// (Reader.Current) and KnownProjections, merge the proposal's candidate term
// or edits into that document per its own Kind-specific rules, open one write
// transaction (database.Store.Write), call this method inside it to validate,
// mint ids, insert the new PROPOSAL_ACCEPTED version and move the pointer,
// then -- in the SAME transaction -- transition its own workspace_context_proposal
// row to ACCEPTED and append exactly one audit.workspace.context_proposal_decided
// event (internal/audit's ActionWorkspaceContextProposalDecided,
// ResourceWorkspaceContextProposal). This method itself performs no
// authorization and appends no audit event of its own: the contract's audit
// vocabulary has no separate model_context_revised event for an acceptance,
// so the caller's single decided event is the whole story.
func (store *Store) AcceptProposalVersion(ctx context.Context, tx database.Transaction, access database.AccessContext,
	workspaceID string, document Document, knownProjections []KnownProjection, ifMatchHash, proposalID string) (Version, error) {
	if store == nil || !tx.Valid() || !validAssignedID(proposalPrefix, proposalID) {
		return Version{}, &Error{code: CodeInvalidDocument}
	}
	current, found, err := loadCurrentVersion(ctx, tx, access.OrganizationID, workspaceID)
	if err != nil {
		return Version{}, storeFailure(err)
	}
	expectedHash := emptyContextSentinel
	if found {
		expectedHash = current.ContentHash
	}
	if ifMatchHash != expectedHash {
		return Version{}, &Error{code: CodeRevisionConflict}
	}
	minted, err := mintMissingIDs(document)
	if err != nil {
		return Version{}, err
	}
	normalized, err := Validate(minted, knownProjections)
	if err != nil {
		return Version{}, err
	}
	documentBytes, contentHash, err := canonicalDocumentBytesAndHash(normalized)
	if err != nil {
		return Version{}, err
	}
	nextVersion := int64(1)
	if found {
		nextVersion = current.Number + 1
	}
	if err := insertVersionRow(ctx, tx, access, workspaceID, nextVersion, documentBytes, contentHash,
		"PROPOSAL_ACCEPTED", &proposalID, nil); err != nil {
		return Version{}, storeFailure(err)
	}
	if err := upsertPointer(ctx, tx, access, workspaceID, nextVersion, contentHash, found); err != nil {
		return Version{}, storeFailure(err)
	}
	return Version{Number: nextVersion, ContentHash: contentHash, Document: normalized, Editable: true}, nil
}

// loadKnownProjections resolves the KnownProjection set Validate checks every
// data_locations/source/table/column reference against: every enabled source
// binding's registered PostgreSQL projection (public.postgresql_query_projection,
// migration 000025), already narrowed by any S1 column exclusion -- an
// excluded column was never written into that table's columns_json in the
// first place (internal/source/registration.RegisterDiscoveredView). Only an
// ACTIVE projection counts as "enabled": a DRAFT registration is not yet
// live, and a REVOKED one must not be citable in the glossary any more.
func (store *Store) loadKnownProjections(ctx context.Context, access database.AccessContext, snapshot workspace.Snapshot) ([]KnownProjection, error) {
	projections := []KnownProjection{}
	err := store.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		for _, binding := range snapshot.SourceBindings {
			if !binding.Enabled {
				continue
			}
			rows, queryErr := tx.Query(ctx, `
				SELECT connection_id, schema_name, relation_name, columns_json
				FROM public.postgresql_query_projection
				WHERE organization_id = $1 AND source_scope_id = $2 AND source_scope_revision = $3 AND status = 'ACTIVE'
			`, access.OrganizationID, binding.SourceScopeID, binding.SourceScopeRevision)
			if queryErr != nil {
				return queryErr
			}
			scanErr := func() error {
				defer rows.Close()
				for rows.Next() {
					var connectionID, schemaName, relationName string
					var columnsRaw []byte
					if err := rows.Scan(&connectionID, &schemaName, &relationName, &columnsRaw); err != nil {
						return err
					}
					columnNames, decodeErr := decodeProjectionColumnNames(columnsRaw)
					if decodeErr != nil {
						return decodeErr
					}
					projections = append(projections, KnownProjection{
						SourceConnectionID: connectionID,
						Relation:           schemaName + "." + relationName,
						Columns:            columnNames,
					})
				}
				return rows.Err()
			}()
			if scanErr != nil {
				return scanErr
			}
		}
		return nil
	})
	if err != nil {
		return nil, storeFailure(err)
	}
	return projections, nil
}

func decodeProjectionColumnNames(raw []byte) ([]string, error) {
	var columns []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &columns); err != nil {
		return nil, &Error{code: CodeStoreUnavailable, cause: err}
	}
	names := make([]string, len(columns))
	for index, column := range columns {
		names[index] = column.Name
	}
	return names, nil
}

func scopedHash(scope, value string) string {
	sum := sha256.Sum256([]byte(scope + ":" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func versionToken(versionNumber int64) string {
	digits := make([]byte, 0, 20)
	if versionNumber == 0 {
		return "0"
	}
	for versionNumber > 0 {
		digits = append([]byte{byte('0' + versionNumber%10)}, digits...)
		versionNumber /= 10
	}
	return string(digits)
}

// storeFailure wraps an error surfaced from a database.Store.Read/Write
// closure that is not already one of this package's own typed errors, so
// every path CodeOf inspects returns a stable, content-free code.
func storeFailure(err error) error {
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	return &Error{code: CodeStoreUnavailable, cause: err}
}

// NewErrorForTest constructs an error CodeOf recognises as carrying exactly
// code. Error's own constructor is unexported by design (only this package
// decides which code a real failure carries); this seam exists solely so a
// fake ModelContextService/ProposalService in another package's tests (for
// example internal/platform/workspaceapi's) can drive
// writeModelContextError/writeModelContextProposalError's switch without a
// real database. It has no other use and no behavior beyond wrapping code.
func NewErrorForTest(code ErrorCode) error { return &Error{code: code} }
