// Package conversation owns the server-side lifecycle and read projection for
// workspace-scoped conversations.  It stores only opaque metadata and links to
// Question Runs; question/answer bytes remain behind the Question authority's
// encrypted artifact disclosure gate.
package conversation

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

const (
	maxConversations                       = 100
	maxTurns                               = 500
	maxSafeInt64                           = int64(9007199254740991)
	conversationRetentionArchiveGuardQuery = `
		SELECT app.conversation_retention_archive_guard($1, $2, $3)
	`
)

// maxConversationPage bounds the additive keyset page (N3). It is deliberately
// smaller than maxConversations: the legacy List first-screen cap is unchanged,
// while ListPage reads at most limit+1 rows and never returns more than
// maxConversationPage conversations.
const maxConversationPage = 50

// ErrorCode is the content-free transport vocabulary for conversation
// lifecycle operations.
type ErrorCode string

const (
	CodeInvalid             ErrorCode = "CONVERSATION_REQUEST_INVALID"
	CodeDenied              ErrorCode = "CONVERSATION_DENIED"
	CodeNotFound            ErrorCode = "CONVERSATION_NOT_FOUND"
	CodeIdempotencyConflict ErrorCode = "CONVERSATION_IDEMPOTENCY_CONFLICT"
	CodeUnavailable         ErrorCode = "CONVERSATION_UNAVAILABLE"
)

// Error never carries a locator, title, source content or database message.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// NewError returns a typed content-free conversation error. It mirrors the
// workspace/registration repositories' own constructors so transport layers
// and their tests can map or simulate the closed error vocabulary without
// reaching into the unexported representation.
func NewError(code ErrorCode, cause error) *Error {
	return &Error{code: code, cause: cause}
}

// CodeOf maps unknown internal errors to a safe unavailable result.
func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// Turn is an opaque, append-only link.  It deliberately has no question,
// answer, prompt or model-memory field.
type Turn struct {
	ID            string    `json:"turn_id"`
	QuestionRunID string    `json:"question_run_id"`
	TurnIndex     int64     `json:"turn_index"`
	CreatedAt     time.Time `json:"created_at"`
}

// View is the server-owned conversation metadata projection.  The API layer
// may enrich each Turn with a Question Run obtained through QuestionService;
// this package itself never reads encrypted question/answer artifacts.
type View struct {
	ID                string     `json:"conversation_id"`
	WorkspaceID       string     `json:"workspace_id"`
	WorkspaceRevision int64      `json:"workspace_revision"`
	CreatedBy         string     `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	ArchivedAt        *time.Time `json:"archived_at,omitempty"`
	Turns             []Turn     `json:"turns"`
}

// Page is one bounded keyset page of the conversation read projection. It is
// additive to View/List and never replaces them: legacy callers keep List,
// while the paginated read path uses ListPage. NextCursor is the opaque ID of
// the last returned conversation and is set only when the server proved a
// further page exists (it read limit+1 rows). It is never a client-supplied
// value and never a JSON number.
type Page struct {
	Conversations []View
	NextCursor    string
}

// ArchiveRequest is a server-owned idempotent lifecycle command.
type ArchiveRequest struct {
	WorkspaceID    string
	ConversationID string
	IdempotencyKey string
}

// Service is the single conversation lifecycle authority used by REST and
// MCP.  It receives only the private database boundary and audit store.
type Service struct {
	db    *database.Store
	audit *audit.Store
	now   func() time.Time
	newID func(string) (string, error)
}

// New constructs a production service with OS-backed opaque IDs and a wall
// clock used only for the audit event timestamp.
func New(db *database.Store, auditStore *audit.Store) (*Service, error) {
	if db == nil || auditStore == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return &Service{db: db, audit: auditStore, now: time.Now, newID: ids.New}, nil
}

// List returns only rows visible under the caller's transaction-local RLS
// identity.  Archived metadata remains readable while retention is ACTIVE;
// PURGING/PURGED rows disappear at the database policy boundary.
func (service *Service) List(ctx context.Context, access database.AccessContext, workspaceID string) ([]View, error) {
	if service == nil || service.db == nil || service.audit == nil || access.Validate() != nil || !validOpaque(workspaceID) {
		return nil, &Error{code: CodeInvalid}
	}
	var result []View
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, err := tx.Query(txCtx, `
			SELECT id, workspace_id, workspace_revision, created_by, created_at, archived_at
			  FROM public.conversation
			 WHERE organization_id = $1 AND workspace_id = $2
			 ORDER BY created_at DESC, id DESC
			 LIMIT $3
		`, access.OrganizationID, workspaceID, maxConversations)
		if err != nil {
			return err
		}
		views := make([]View, 0, maxConversations)
		for rows.Next() {
			var view View
			var archivedAt sql.NullTime
			if err := rows.Scan(&view.ID, &view.WorkspaceID, &view.WorkspaceRevision, &view.CreatedBy, &view.CreatedAt, &archivedAt); err != nil {
				return err
			}
			if archivedAt.Valid {
				value := archivedAt.Time
				view.ArchivedAt = &value
			}
			views = append(views, view)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		// FIX-4 #2: this used to call loadTurns once PER conversation here --
		// an N+1 query pattern that turned "list the recent conversations"
		// into up to maxConversations sequential round trips to Postgres. At
		// scale (900+ conversations already bound in tko-operations, the
		// live accumulation of an autonomous acceptance suite) that alone
		// measured ~2.4s for GET conversations: not because more ROWS were
		// returned (this query is always capped at maxConversations by the
		// LIMIT above, index-backed by conversation_workspace_created
		// regardless of table size), but because the number of ROUND TRIPS
		// scaled with how many conversations existed, up to that same cap.
		// loadTurnsBatch below is the fix: every returned conversation's
		// turns in the same single query, keyed by conversation_id.
		ids := make([]string, len(views))
		for index, view := range views {
			ids[index] = view.ID
		}
		turnsByConversation, err := loadTurnsBatch(txCtx, tx, access.OrganizationID, workspaceID, ids)
		if err != nil {
			return err
		}
		result = make([]View, 0, len(views))
		for _, view := range views {
			if turns, ok := turnsByConversation[view.ID]; ok {
				view.Turns = turns
			} else {
				view.Turns = []Turn{}
			}
			result = append(result, view)
		}
		return nil
	})
	if err != nil {
		return nil, mapDatabaseError(err)
	}
	if result == nil {
		result = []View{}
	}
	return result, nil
}

// ListPage is the additive bounded keyset read (N3). It returns one page of
// at most limit conversations ordered by (created_at DESC, id DESC) inside the
// caller's transaction-local RLS identity and the requested workspace, plus
// NextCursor when a further page exists. limit is clamped to
// [1, maxConversationPage]; an absent cursor starts at the newest row.
//
// cursor is an opaque conversation ID. It is resolved only inside the same
// authorized organization/workspace inside the same transaction that carries
// the policy gate; a nonexistent, foreign-organization or foreign-workspace
// cursor collapses to the same content-free CONVERSATION_REQUEST_INVALID and
// never discloses the cursor's owner. Before resolving an issued cursor the
// current tenant/workspace visibility is checked in that same transaction
// (R1): if the workspace is gone or the caller's membership was revoked, the
// call returns the content-free CONVERSATION_DENIED instead of a
// REQUEST_INVALID that would misreport an access revocation as a malformed
// cursor. The row-wise predicate (created_at, id)
// < (cursor.created_at, cursor.id) is the exact keyset continuation of the
// ORDER BY, so equal created_at values page deterministically by id.
//
// Archived conversations remain visible exactly as List's own query leaves
// them (no archived predicate), and only the returned page's turns are loaded
// through loadTurnsBatch's single capped query. Legacy List and its callers are
// unchanged.
func (service *Service) ListPage(ctx context.Context, access database.AccessContext, workspaceID string, limit int, cursor string) (Page, error) {
	if service == nil || service.db == nil || service.audit == nil || access.Validate() != nil || !validOpaque(workspaceID) {
		return Page{}, &Error{code: CodeInvalid}
	}
	if limit <= 0 || limit > maxConversationPage {
		limit = maxConversationPage
	}
	if cursor != "" && !validOpaque(cursor) {
		return Page{}, &Error{code: CodeInvalid}
	}
	var page Page
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var cursorCreatedAt time.Time
		hasCursor := cursor != ""
		if hasCursor {
			// R1: an issued cursor must not turn into REQUEST_INVALID merely
			// because the caller's workspace membership was revoked. Resolve the
			// CURRENT tenant/workspace visibility first, inside this same
			// transaction-local RLS identity. A workspace the caller can no
			// longer see collapses to the same content-free DENIED the rest of
			// the conversation surface uses (mapped to 404 by the HTTP layer),
			// never to a 400 that would read as a malformed cursor. Only after
			// the workspace itself is confirmed visible does a missing or
			// foreign cursor stay indistinguishable from a syntactically
			// invalid one.
			visible, err := workspaceVisible(txCtx, tx, access.OrganizationID, workspaceID)
			if err != nil {
				return err
			}
			if !visible {
				return &Error{code: CodeDenied}
			}
			if err := tx.QueryRow(txCtx, `
				SELECT created_at
				  FROM public.conversation
				 WHERE organization_id = $1 AND workspace_id = $2 AND id = $3
			`, access.OrganizationID, workspaceID, cursor).Scan(&cursorCreatedAt); err != nil {
				if database.IsNotFound(err) {
					return &Error{code: CodeInvalid}
				}
				return err
			}
		}
		query := `
			SELECT id, workspace_id, workspace_revision, created_by, created_at, archived_at
			  FROM public.conversation
			 WHERE organization_id = $1 AND workspace_id = $2
			 ORDER BY created_at DESC, id DESC
			 LIMIT $3
		`
		args := []any{access.OrganizationID, workspaceID, limit + 1}
		if hasCursor {
			query = `
				SELECT id, workspace_id, workspace_revision, created_by, created_at, archived_at
				  FROM public.conversation
				 WHERE organization_id = $1 AND workspace_id = $2
				   AND (created_at, id) < ($3, $4)
				 ORDER BY created_at DESC, id DESC
				 LIMIT $5
			`
			args = []any{access.OrganizationID, workspaceID, cursorCreatedAt, cursor, limit + 1}
		}
		rows, err := tx.Query(txCtx, query, args...)
		if err != nil {
			return err
		}
		views := make([]View, 0, limit+1)
		for rows.Next() {
			var view View
			var archivedAt sql.NullTime
			if err := rows.Scan(&view.ID, &view.WorkspaceID, &view.WorkspaceRevision, &view.CreatedBy, &view.CreatedAt, &archivedAt); err != nil {
				rows.Close()
				return err
			}
			if archivedAt.Valid {
				value := archivedAt.Time
				view.ArchivedAt = &value
			}
			views = append(views, view)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(views) > limit {
			// The limit+1'th row proves a continuation; the cursor is the ID of
			// the last row actually returned, so the next read resumes exactly
			// after it without gaps or duplicates.
			page.NextCursor = views[limit-1].ID
			views = views[:limit]
		}
		ids := make([]string, len(views))
		for index, view := range views {
			ids[index] = view.ID
		}
		turnsByConversation, err := loadTurnsBatch(txCtx, tx, access.OrganizationID, workspaceID, ids)
		if err != nil {
			return err
		}
		page.Conversations = make([]View, 0, len(views))
		for _, view := range views {
			if turns, ok := turnsByConversation[view.ID]; ok {
				view.Turns = turns
			} else {
				view.Turns = []Turn{}
			}
			page.Conversations = append(page.Conversations, view)
		}
		return nil
	})
	if err != nil {
		return Page{}, mapDatabaseError(err)
	}
	if page.Conversations == nil {
		page.Conversations = []View{}
	}
	return page, nil
}

// Get returns one current-access-checked conversation.  Absence, foreign
// workspace and revoked retention deliberately collapse to NOT_FOUND.
func (service *Service) Get(ctx context.Context, access database.AccessContext, workspaceID, conversationID string) (View, error) {
	if service == nil || service.db == nil || service.audit == nil || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(conversationID) {
		return View{}, &Error{code: CodeInvalid}
	}
	var result View
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var err error
		result, err = loadView(txCtx, tx, access.OrganizationID, workspaceID, conversationID)
		return err
	})
	if err != nil {
		return View{}, mapDatabaseError(err)
	}
	return result, nil
}

// Archive atomically marks one conversation archived, appends its audit event
// and seals an actor-scoped receipt.  The operation is a no-op success when a
// prior request already archived the same conversation; archived_at can never
// be cleared by this authority or by the database trigger.
func (service *Service) Archive(ctx context.Context, access database.AccessContext, request ArchiveRequest) (View, error) {
	if service == nil || service.db == nil || service.audit == nil || service.now == nil || service.newID == nil ||
		access.Validate() != nil || !validOpaque(request.WorkspaceID) || !validOpaque(request.ConversationID) || !validIdempotencyKey(request.IdempotencyKey) {
		return View{}, &Error{code: CodeInvalid}
	}
	keyHash := canon.Hash([]byte(request.IdempotencyKey))
	requestHash := canon.Hash([]byte("conversation-command-v1\x00ARCHIVE\x00" + request.WorkspaceID + "\x00" + request.ConversationID))
	var result View
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var retentionAllowed bool
		if err := tx.QueryRow(txCtx, conversationRetentionArchiveGuardQuery,
			access.OrganizationID, request.WorkspaceID, request.ConversationID).Scan(&retentionAllowed); err != nil {
			return err
		}
		if !retentionAllowed {
			return &Error{code: CodeNotFound}
		}
		view, err := loadView(txCtx, tx, access.OrganizationID, request.WorkspaceID, request.ConversationID)
		if err != nil {
			return err
		}
		created, status, err := reserveReceipt(txCtx, tx, access.OrganizationID, access.PrincipalID, keyHash,
			requestHash, request.WorkspaceID, request.ConversationID, view.WorkspaceRevision)
		if err != nil {
			return err
		}
		if !created {
			switch status {
			case "SUCCESS":
				result = view
				return nil
			case "NOT_FOUND":
				return &Error{code: CodeNotFound}
			case "DENIED":
				return &Error{code: CodeDenied}
			default:
				return &Error{code: CodeUnavailable}
			}
		}

		// The initial read establishes visibility.  The conditional UPDATE is
		// also the concurrency winner election: exactly one command changes an
		// active row and therefore emits the archive audit event.  A concurrent
		// command waits on that row, observes zero affected rows, and reuses the
		// first event instead of appending a duplicate audit entry.
		changed := false
		if view.ArchivedAt == nil {
			tag, updateErr := tx.Exec(txCtx, `
				UPDATE public.conversation
				   SET archived_at = clock_timestamp()
				 WHERE organization_id = $1 AND id = $2 AND workspace_id = $3 AND archived_at IS NULL
			`, access.OrganizationID, request.ConversationID, request.WorkspaceID)
			if updateErr != nil {
				return updateErr
			}
			changed = tag.RowsAffected() == 1
		}
		if !changed {
			var existingAuditID string
			err := tx.QueryRow(txCtx, `
				SELECT id
				  FROM public.audit_event
				 WHERE organization_id = $1 AND workspace_id = $2
				   AND resource_type = 'CONVERSATION' AND resource_id = $3
				   AND action = 'conversation.archived' AND outcome = 'SUCCESS'
				 ORDER BY sequence ASC
				 LIMIT 1
			`, access.OrganizationID, request.WorkspaceID, request.ConversationID).Scan(&existingAuditID)
			if err == nil {
				if err := completeReceipt(txCtx, tx, access.OrganizationID, access.PrincipalID, keyHash, existingAuditID); err != nil {
					return err
				}
				result, err = loadView(txCtx, tx, access.OrganizationID, request.WorkspaceID, request.ConversationID)
				return err
			}
			if !database.IsNotFound(err) {
				return err
			}
			// An archived row without its audit event is an invariant breach.  Do
			// not silently turn it into a successful, unaudited command; the
			// enclosing transaction is rolled back and the caller gets a typed
			// unavailable result.
			return &Error{code: CodeUnavailable}
		}

		eventID, err := service.newID("aud")
		if err != nil {
			return err
		}
		workspaceID := request.WorkspaceID
		if _, err := service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorHuman,
			ActorPrincipalID: &access.PrincipalID, Action: audit.ActionConversationArchived,
			ResourceType: audit.ResourceConversation, ResourceID: request.ConversationID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess,
			ReferencedEvidenceIDs: []string{}, OccurredAt: service.now().UTC(),
		}); err != nil {
			return err
		}
		if err := completeReceipt(txCtx, tx, access.OrganizationID, access.PrincipalID, keyHash, eventID); err != nil {
			return err
		}
		result, err = loadView(txCtx, tx, access.OrganizationID, request.WorkspaceID, request.ConversationID)
		return err
	})
	if err != nil {
		return View{}, mapDatabaseError(err)
	}
	return result, nil
}

// workspaceVisible reports whether the current transaction-local principal can
// still see the named workspace: the workspace is live and the principal holds
// an active membership. It mirrors the membership half of the conversation
// read policy (conversation_member_read) and is deliberately evaluated inside
// the caller's own transaction, so RLS identity and any revocation committed
// before this read are honoured. ListPage uses it only to tell a cursor whose
// workspace became unauthorized apart from a cursor that never existed.
func workspaceVisible(ctx context.Context, tx database.Transaction, organizationID, workspaceID string) (bool, error) {
	var visible bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM public.workspace AS workspace
			  JOIN public.workspace_member AS member
			    ON member.organization_id = workspace.organization_id
			   AND member.workspace_id = workspace.id
			 WHERE workspace.organization_id = $1
			   AND workspace.id = $2
			   AND workspace.status NOT IN ('ARCHIVED', 'DELETING', 'DELETED')
			   AND member.principal_id = app.current_principal_id()
			   AND member.removed_at IS NULL
		)
	`, organizationID, workspaceID).Scan(&visible); err != nil {
		return false, err
	}
	return visible, nil
}

func loadView(ctx context.Context, tx database.Transaction, organizationID, workspaceID, conversationID string) (View, error) {
	var view View
	var archivedAt sql.NullTime
	if err := tx.QueryRow(ctx, `
		SELECT id, workspace_id, workspace_revision, created_by, created_at, archived_at
		  FROM public.conversation
		 WHERE organization_id = $1 AND workspace_id = $2 AND id = $3
	`, organizationID, workspaceID, conversationID).Scan(&view.ID, &view.WorkspaceID, &view.WorkspaceRevision, &view.CreatedBy, &view.CreatedAt, &archivedAt); err != nil {
		if database.IsNotFound(err) {
			return View{}, &Error{code: CodeNotFound}
		}
		return View{}, err
	}
	if archivedAt.Valid {
		value := archivedAt.Time
		view.ArchivedAt = &value
	}
	turns, err := loadTurns(ctx, tx, organizationID, view)
	if err != nil {
		return View{}, err
	}
	view.Turns = turns
	return view, nil
}

func loadTurns(ctx context.Context, tx database.Transaction, organizationID string, view View) ([]Turn, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, question_run_id, turn_index, created_at
		  FROM public.conversation_turn
		 WHERE organization_id = $1 AND conversation_id = $2
		   AND workspace_id = $3
		 ORDER BY turn_index ASC
		 LIMIT $4
	`, organizationID, view.ID, view.WorkspaceID, maxTurns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	turns := make([]Turn, 0)
	for rows.Next() {
		var turn Turn
		if err := rows.Scan(&turn.ID, &turn.QuestionRunID, &turn.TurnIndex, &turn.CreatedAt); err != nil {
			return nil, err
		}
		if turn.TurnIndex < 1 || turn.TurnIndex > maxSafeInt64 {
			return nil, &Error{code: CodeUnavailable}
		}
		turns = append(turns, turn)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return turns, nil
}

// loadTurnsBatch is FIX-4 #2's batched counterpart to loadTurns: the same
// per-conversation "earliest maxTurns turns, ordered by turn_index ASC"
// projection, computed for every given conversation ID in one query instead
// of one query per conversation (List's own N+1). The per-row cap is
// expressed with row_number() PARTITION BY conversation_id rather than a
// per-query LIMIT, which is the set-based equivalent of calling loadTurns
// once per ID.
//
// Neither this query nor loadTurns filters by workspace_revision: since 000080
// (conversation_turn_conversation_fk loosened to (organization_id,
// conversation_id, workspace_id)), two turns of the very same conversation
// can legitimately carry two different workspace_revision values (a
// continuation across an unrelated workspace mutation), so there is no
// longer one single revision value a conversation can be filtered by.
// conversation_id + workspace_id alone is the
// same live-lookup key 000080's own RLS joins already moved to.
func loadTurnsBatch(ctx context.Context, tx database.Transaction, organizationID, workspaceID string, conversationIDs []string) (map[string][]Turn, error) {
	result := make(map[string][]Turn, len(conversationIDs))
	if len(conversationIDs) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT conversation_id, id, question_run_id, turn_index, created_at
		  FROM (
			SELECT conversation_id, id, question_run_id, turn_index, created_at,
			       row_number() OVER (PARTITION BY conversation_id ORDER BY turn_index ASC) AS turn_rank
			  FROM public.conversation_turn
			 WHERE organization_id = $1 AND workspace_id = $2 AND conversation_id = ANY($3)
		  ) AS ranked
		 WHERE turn_rank <= $4
		 ORDER BY conversation_id, turn_index ASC
	`, organizationID, workspaceID, conversationIDs, maxTurns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var conversationID string
		var turn Turn
		if err := rows.Scan(&conversationID, &turn.ID, &turn.QuestionRunID, &turn.TurnIndex, &turn.CreatedAt); err != nil {
			return nil, err
		}
		if turn.TurnIndex < 1 || turn.TurnIndex > maxSafeInt64 {
			return nil, &Error{code: CodeUnavailable}
		}
		result[conversationID] = append(result[conversationID], turn)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func reserveReceipt(ctx context.Context, tx database.Transaction, organizationID, actorID, keyHash, requestHash, workspaceID, conversationID string, revision int64) (bool, string, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO public.conversation_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash,
			conversation_id, workspace_id, workspace_revision, operation,
			canonical_request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,'ARCHIVE',$7)
		ON CONFLICT (organization_id, actor_principal_id, idempotency_key_hash) DO NOTHING
	`, organizationID, actorID, keyHash, conversationID, workspaceID, revision, requestHash)
	if err != nil {
		return false, "", err
	}
	if tag.RowsAffected() == 1 {
		return true, "PENDING", nil
	}
	var storedRequestHash, storedConversationID, storedWorkspaceID, storedOperation, status string
	var storedRevision int64
	if err := tx.QueryRow(ctx, `
		SELECT canonical_request_hash, conversation_id, workspace_id, workspace_revision, operation, status
		  FROM public.conversation_command_receipt
		 WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		 FOR UPDATE
	`, organizationID, actorID, keyHash).Scan(&storedRequestHash, &storedConversationID, &storedWorkspaceID, &storedRevision, &storedOperation, &status); err != nil {
		return false, "", err
	}
	if storedRequestHash != requestHash || storedConversationID != conversationID || storedWorkspaceID != workspaceID || storedRevision != revision || storedOperation != "ARCHIVE" {
		return false, "", &Error{code: CodeIdempotencyConflict}
	}
	return false, status, nil
}

func completeReceipt(ctx context.Context, tx database.Transaction, organizationID, actorID, keyHash, auditEventID string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE public.conversation_command_receipt
		   SET status = 'SUCCESS', audit_event_id = $4, terminal_at = transaction_timestamp()
		 WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3 AND status = 'PENDING'
	`, organizationID, actorID, keyHash, auditEventID)
	if err != nil || tag.RowsAffected() != 1 {
		return &Error{code: CodeUnavailable, cause: err}
	}
	return nil
}

func mapDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if code := CodeOf(err); code != CodeUnavailable {
		return err
	}
	return &Error{code: CodeUnavailable, cause: err}
}

func validIdempotencyKey(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validOpaque(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}
