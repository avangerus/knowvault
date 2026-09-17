// Package serviceprincipal issues and authenticates workspace-scoped agent
// access codes (ADR-0079 §3, ADR-0086 §2, V1-C). A workspace OWNER creates a
// named SERVICE principal bound to one or more workspaces it owns and a
// bounded TTL; the raw code is returned exactly once and MCP authenticates it
// as `Authorization: Bearer <code>` (internal/platform/workspaceapi).
//
// The raw code is never persisted. Only its SHA-256 digest is stored: the
// code itself is a 256-bit CSPRNG value, so an unkeyed digest already has
// negligible reversal risk — the same reasoning that lets a high-entropy API
// key be stored as a bare hash elsewhere in the industry — which keeps
// issuance free of a new KMS-mounted purpose key.
//
// Every workspace a code reaches is granted through the existing, unmodified
// workspace_member/AddMember authority: the resulting SERVICE principal is
// simply another non-owner workspace member (Role=MEMBER), so every
// membership-gated read path (question.ask, evidence disclosure) already
// authorizes and scopes it correctly with no change to that code. Revoking
// or letting a code expire removes exactly that membership; there is no
// second, parallel access-control path to keep in sync.
package serviceprincipal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	// CodePrefix distinguishes a service access code from a browser/API
	// session bearer token at the HTTP boundary (workspaceapi never attempts
	// human session resolution for a value carrying this prefix, and never
	// accepts this prefix outside the MCP endpoint).
	CodePrefix        = "kva_"
	rawCodeBytes      = 32
	minTTL            = time.Hour
	maxTTL            = 180 * 24 * time.Hour
	maxWorkspaces     = 20
	maxNameBytes      = 256
	principalIDPrefix = "svcp"
	credentialPrefix  = "spc"
)

// ErrorCode is content-free and safe for HTTP/MCP mapping and logs.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "SERVICE_PRINCIPAL_REQUEST_INVALID"
	CodeDenied      ErrorCode = "SERVICE_PRINCIPAL_DENIED"
	CodeNotFound    ErrorCode = "SERVICE_PRINCIPAL_NOT_FOUND"
	CodeUnavailable ErrorCode = "SERVICE_PRINCIPAL_UNAVAILABLE"
	// CodeAlreadyIssued is returned for a retry that reuses the idempotency
	// key of an already-created request with the identical body (FIX-1 #2).
	// The raw code can never be shown a second time (it is never persisted),
	// so the caller gets this typed outcome instead of either a fabricated
	// secret or a silently duplicated principal.
	CodeAlreadyIssued ErrorCode = "SERVICE_PRINCIPAL_ALREADY_ISSUED"
	// CodeIdempotencyConflict is returned when the same idempotency key is
	// reused with a different request body.
	CodeIdempotencyConflict ErrorCode = "SERVICE_PRINCIPAL_IDEMPOTENCY_CONFLICT"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (err *Error) Error() string { return string(err.code) }
func (err *Error) Unwrap() error { return err.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// WorkspaceAuthority is the subset of workspacerepository.Store this package
// needs. Membership is granted/revoked through the exact same commands the
// REST "add member"/"remove member" actions use; this package invents no
// second authorization path.
type WorkspaceAuthority interface {
	Get(context.Context, database.AccessContext, string) (workspace.Snapshot, error)
	AddMember(context.Context, database.AccessContext, workspacerepository.AddMemberRequest) (workspace.Snapshot, error)
	RemoveMember(context.Context, database.AccessContext, workspacerepository.RemoveMemberRequest) (workspace.Snapshot, error)
}

// Service is safe for concurrent use once constructed.
type Service struct {
	db         *database.Store
	audit      *audit.Store
	workspaces WorkspaceAuthority
	now        func() time.Time
	newID      func(string) (string, error)
}

func New(db *database.Store, auditStore *audit.Store, workspaces WorkspaceAuthority) (*Service, error) {
	if db == nil || auditStore == nil || workspaces == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return &Service{db: db, audit: auditStore, workspaces: workspaces, now: time.Now, newID: ids.New}, nil
}

// IssueRequest is the closed operator input. WorkspaceIDs must be non-empty,
// deduplicated by the caller-visible set and bounded; every one of them must
// currently have the calling human as OWNER (checked before anything is
// created — a request that is only partially authorized creates nothing).
//
// IdempotencyKey makes a client-facing retry of the exact same request safe
// (FIX-1 #2): it is scoped per issuing principal, single-use, and a replay
// with the identical body never creates a second principal/credential.
type IssueRequest struct {
	Name           string
	WorkspaceIDs   []string
	TTLSeconds     int64
	IdempotencyKey string
}

// IssueResult carries the raw code exactly once. Nothing in this package
// persists it; the caller (the REST/UI layer) must render it once and never
// log or store it.
type IssueResult struct {
	PrincipalID  string
	CredentialID string
	Name         string
	Code         string
	WorkspaceIDs []string
	ExpiresAt    time.Time
}

// Issue authorizes, creates the SERVICE principal and its credential, and
// adds it as a MEMBER of every requested workspace. Every workspace add uses
// the calling human's own AccessContext, so the existing OWNER/MANAGER
// workspace.manage_sources-equivalent policy gate on AddMember is the one and
// only authority checked — this package repeats only the OWNER precondition
// once, up front, so a partially-authorized request fails before creating a
// principal or a credential.
//
// FIX-1 #2: the credential is created inactive (`activated_at` NULL, which
// Authenticate now requires non-null) and is flipped to active in one final
// statement only after every requested workspace's AddMember and scope row
// has committed. A failure anywhere in that per-workspace loop revokes the
// still-inactive credential immediately and unwinds every membership already
// granted, so no caller ever observes a credential holding a proper subset of
// the workspaces it asked for. IdempotencyKey is checked before anything is
// created: a retry with the same key and the same body returns
// CodeAlreadyIssued (never a second principal); the same key with a different
// body returns CodeIdempotencyConflict.
func (service *Service) Issue(ctx context.Context, access database.AccessContext, request IssueRequest) (IssueResult, error) {
	if service == nil || service.db == nil || service.audit == nil || service.workspaces == nil ||
		service.now == nil || service.newID == nil || ctx == nil || access.Validate() != nil {
		return IssueResult{}, &Error{code: CodeUnavailable}
	}
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > maxNameBytes || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
		return IssueResult{}, &Error{code: CodeInvalid}
	}
	workspaceIDs, err := dedupeWorkspaceIDs(request.WorkspaceIDs)
	if err != nil {
		return IssueResult{}, err
	}
	if request.TTLSeconds < int64(minTTL/time.Second) || request.TTLSeconds > int64(maxTTL/time.Second) {
		return IssueResult{}, &Error{code: CodeInvalid}
	}
	if !validIdempotencyKey(request.IdempotencyKey) {
		return IssueResult{}, &Error{code: CodeInvalid}
	}
	ttl := time.Duration(request.TTLSeconds) * time.Second

	// Fail closed before creating anything: the caller must currently be
	// OWNER of every requested workspace.
	snapshots := make(map[string]workspace.Snapshot, len(workspaceIDs))
	for _, workspaceID := range workspaceIDs {
		snapshot, getErr := service.workspaces.Get(ctx, access, workspaceID)
		if getErr != nil {
			return IssueResult{}, &Error{code: CodeDenied, cause: getErr}
		}
		if !isOwner(snapshot, access.PrincipalID) {
			return IssueResult{}, &Error{code: CodeDenied}
		}
		snapshots[workspaceID] = snapshot
	}

	requestHash, err := issueRequestHash(name, workspaceIDs, request.TTLSeconds)
	if err != nil {
		return IssueResult{}, &Error{code: CodeUnavailable, cause: err}
	}
	if replayCode, replayErr := service.checkIssueReplay(ctx, access, request.IdempotencyKey, requestHash); replayErr != nil {
		return IssueResult{}, replayErr
	} else if replayCode != "" {
		return IssueResult{}, &Error{code: replayCode}
	}

	principalID, err := service.newID(principalIDPrefix)
	if err != nil {
		return IssueResult{}, &Error{code: CodeUnavailable, cause: err}
	}
	credentialID, err := service.newID(credentialPrefix)
	if err != nil {
		return IssueResult{}, &Error{code: CodeUnavailable, cause: err}
	}
	rawCode, digest, err := generateCode()
	if err != nil {
		return IssueResult{}, &Error{code: CodeUnavailable, cause: err}
	}
	expiresAt := service.now().UTC().Add(ttl)

	err = service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, execErr := tx.Exec(txCtx, `
			INSERT INTO public.principal (id, organization_id, type, display_name, status, session_revision)
			VALUES ($1, $2, 'SERVICE', $3, 'ACTIVE', 1)
		`, principalID, access.OrganizationID, name); execErr != nil {
			return execErr
		}
		if _, execErr := tx.Exec(txCtx, `
			INSERT INTO public.service_principal_credential
				(id, organization_id, principal_id, name, code_digest, created_by, expires_at,
				 idempotency_key, request_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, credentialID, access.OrganizationID, principalID, name, digest, access.PrincipalID, expiresAt,
			request.IdempotencyKey, requestHash); execErr != nil {
			return execErr
		}
		return nil
	})
	if err != nil {
		// A concurrent request can win the unique idempotency race between our
		// check above and this insert; resolve it the same way a sequential
		// retry would rather than surface a raw constraint violation.
		if database.SQLStateCode(err) == "23505" {
			if replayCode, replayErr := service.checkIssueReplay(ctx, access, request.IdempotencyKey, requestHash); replayErr == nil && replayCode != "" {
				return IssueResult{}, &Error{code: replayCode}
			}
		}
		return IssueResult{}, &Error{code: CodeUnavailable, cause: err}
	}

	granted := make([]string, 0, len(workspaceIDs))
	for _, workspaceID := range workspaceIDs {
		if addErr := service.addWorkspaceScope(ctx, access, principalID, credentialID, workspaceID, snapshots[workspaceID]); addErr != nil {
			// Never leave a partially-scoped credential authenticatable: unwind
			// every membership already granted and permanently revoke the
			// still-inactive credential before returning the failure.
			service.unwindPartialIssue(ctx, access, principalID, credentialID, granted)
			return IssueResult{}, &Error{code: CodeUnavailable, cause: addErr}
		}
		granted = append(granted, workspaceID)
	}

	if err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		tag, execErr := tx.Exec(txCtx, `
			UPDATE public.service_principal_credential
			SET activated_at = transaction_timestamp()
			WHERE organization_id = $1 AND id = $2 AND activated_at IS NULL AND revoked_at IS NULL
		`, access.OrganizationID, credentialID)
		if execErr != nil {
			return execErr
		}
		if tag.RowsAffected() != 1 {
			return errors.New("serviceprincipal: credential activation did not affect exactly one row")
		}
		return nil
	}); err != nil {
		service.unwindPartialIssue(ctx, access, principalID, credentialID, granted)
		return IssueResult{}, &Error{code: CodeUnavailable, cause: err}
	}

	return IssueResult{
		PrincipalID: principalID, CredentialID: credentialID, Name: name,
		Code: rawCode, WorkspaceIDs: workspaceIDs, ExpiresAt: expiresAt,
	}, nil
}

// checkIssueReplay looks up an existing credential for this issuing
// principal's idempotency key. It returns CodeAlreadyIssued when the earlier
// request had the identical canonical body, CodeIdempotencyConflict when the
// body differs, and an empty code (no error) when the key is unused.
func (service *Service) checkIssueReplay(ctx context.Context, access database.AccessContext, idempotencyKey, requestHash string) (ErrorCode, error) {
	var existingHash string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT request_hash FROM public.service_principal_credential
			WHERE organization_id = $1 AND created_by = $2 AND idempotency_key = $3
		`, access.OrganizationID, access.PrincipalID, idempotencyKey).Scan(&existingHash)
	})
	if database.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", &Error{code: CodeUnavailable, cause: err}
	}
	if existingHash == requestHash {
		return CodeAlreadyIssued, nil
	}
	return CodeIdempotencyConflict, nil
}

// addWorkspaceScope grants one requested workspace's membership and records
// its scope row. It is the unit of work that may fail partway through Issue.
func (service *Service) addWorkspaceScope(ctx context.Context, access database.AccessContext, principalID, credentialID, workspaceID string, snapshot workspace.Snapshot) error {
	hash, hashErr := workspace.ConfigurationHash(snapshot)
	if hashErr != nil {
		return hashErr
	}
	key, keyErr := freshIdempotencyKey()
	if keyErr != nil {
		return keyErr
	}
	if _, addErr := service.workspaces.AddMember(ctx, access, workspacerepository.AddMemberRequest{
		IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: hash,
		PrincipalID: principalID, Role: workspace.RoleMember,
	}); addErr != nil {
		return addErr
	}
	return service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(txCtx, `
			INSERT INTO public.service_principal_workspace_scope (organization_id, credential_id, workspace_id)
			VALUES ($1, $2, $3)
		`, access.OrganizationID, credentialID, workspaceID)
		return execErr
	})
}

// unwindPartialIssue is the compensating rollback for a mid-loop failure: it
// permanently revokes the never-activated credential (best-effort; the
// credential is already unauthenticatable because activated_at is still
// NULL, so this only removes the row from future List/Revoke ambiguity) and
// removes every membership already granted, so the net effect of a failed
// Issue is exactly zero standing access.
func (service *Service) unwindPartialIssue(ctx context.Context, access database.AccessContext, principalID, credentialID string, grantedWorkspaceIDs []string) {
	_ = service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(txCtx, `
			UPDATE public.service_principal_credential
			SET revoked_at = transaction_timestamp(), revoked_by = $3
			WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
		`, access.OrganizationID, credentialID, access.PrincipalID)
		return execErr
	})
	for _, workspaceID := range grantedWorkspaceIDs {
		snapshot, getErr := service.workspaces.Get(ctx, access, workspaceID)
		if getErr != nil {
			continue
		}
		hash, hashErr := workspace.ConfigurationHash(snapshot)
		if hashErr != nil {
			continue
		}
		key, keyErr := freshIdempotencyKey()
		if keyErr != nil {
			continue
		}
		_, _ = service.workspaces.RemoveMember(ctx, access, workspacerepository.RemoveMemberRequest{
			IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: hash, PrincipalID: principalID,
		})
	}
}

// issueRequestHash is the canonical digest of the parts of an Issue request
// that must match for a retried idempotency key to be an honest replay rather
// than a different request wearing the same key.
func issueRequestHash(name string, workspaceIDs []string, ttlSeconds int64) (string, error) {
	sorted := append([]string(nil), workspaceIDs...)
	sort.Strings(sorted)
	payload := struct {
		Name         string   `json:"name"`
		WorkspaceIDs []string `json:"workspace_ids"`
		TTLSeconds   int64    `json:"ttl_seconds"`
	}{Name: name, WorkspaceIDs: sorted, TTLSeconds: ttlSeconds}
	canonicalJSON, err := canon.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return canon.Hash(canonicalJSON), nil
}

// validIdempotencyKey mirrors the shape workspaceapi already requires of the
// Idempotency-Key header (32 raw bytes, RawURLEncoding, no padding/whitespace)
// so this package validates its own opaque input rather than trusting the
// transport layer's check alone.
func validIdempotencyKey(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// Credential is the content-free listing/UI projection: never the raw code
// or its digest.
type Credential struct {
	CredentialID string
	PrincipalID  string
	Name         string
	WorkspaceIDs []string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
}

// List returns every access code scoped to workspaceID that the caller (a
// current OWNER of that workspace) may see.
func (service *Service) List(ctx context.Context, access database.AccessContext, workspaceID string) ([]Credential, error) {
	if service == nil || service.db == nil || service.workspaces == nil || ctx == nil || access.Validate() != nil || workspaceID == "" {
		return nil, &Error{code: CodeInvalid}
	}
	snapshot, err := service.workspaces.Get(ctx, access, workspaceID)
	if err != nil {
		return nil, &Error{code: CodeDenied, cause: err}
	}
	if !isOwner(snapshot, access.PrincipalID) {
		return nil, &Error{code: CodeDenied}
	}
	var results []Credential
	err = service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, queryErr := tx.Query(txCtx, `
			SELECT credential.id, credential.principal_id, credential.name,
			       credential.created_at, credential.expires_at, credential.revoked_at
			FROM public.service_principal_credential credential
			JOIN public.service_principal_workspace_scope scope
			  ON scope.organization_id = credential.organization_id AND scope.credential_id = credential.id
			WHERE credential.organization_id = $1 AND scope.workspace_id = $2
			ORDER BY credential.created_at DESC
		`, access.OrganizationID, workspaceID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		byID := map[string]*Credential{}
		var order []string
		for rows.Next() {
			var (
				credentialID, principalID, name string
				createdAt, expiresAt            time.Time
				revokedAt                       *time.Time
			)
			if scanErr := rows.Scan(&credentialID, &principalID, &name, &createdAt, &expiresAt, &revokedAt); scanErr != nil {
				return scanErr
			}
			if _, ok := byID[credentialID]; !ok {
				byID[credentialID] = &Credential{
					CredentialID: credentialID, PrincipalID: principalID, Name: name,
					CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), RevokedAt: revokedAt,
				}
				order = append(order, credentialID)
			}
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		// Second pass: attach the complete workspace-id set per credential
		// (the join above only proves this one workspace's membership).
		for _, credentialID := range order {
			scopeRows, scopeErr := tx.Query(txCtx, `
				SELECT workspace_id FROM public.service_principal_workspace_scope
				WHERE organization_id = $1 AND credential_id = $2 ORDER BY workspace_id
			`, access.OrganizationID, credentialID)
			if scopeErr != nil {
				return scopeErr
			}
			var ids []string
			for scopeRows.Next() {
				var id string
				if scanErr := scopeRows.Scan(&id); scanErr != nil {
					scopeRows.Close()
					return scanErr
				}
				ids = append(ids, id)
			}
			scopeRows.Close()
			byID[credentialID].WorkspaceIDs = ids
			results = append(results, *byID[credentialID])
		}
		return nil
	})
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	return results, nil
}

// Revoke marks the credential permanently revoked and removes the SERVICE
// principal's membership from every workspace it was scoped to. The caller
// must currently be OWNER of every one of those workspaces (symmetric with
// Issue); a partial-authority caller is denied entirely rather than allowed
// to revoke only what it owns, so a code's blast radius never quietly
// shrinks in a way its own audit trail cannot explain. `revoked_at` is set
// first and independently makes the credential unauthenticatable regardless
// of whether the membership cleanup below fully succeeds.
func (service *Service) Revoke(ctx context.Context, access database.AccessContext, credentialID string) error {
	if service == nil || service.db == nil || service.workspaces == nil || ctx == nil || access.Validate() != nil || credentialID == "" {
		return &Error{code: CodeInvalid}
	}
	var workspaceIDs []string
	var principalID string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var revokedAt *time.Time
		if err := tx.QueryRow(txCtx, `
			SELECT principal_id, revoked_at FROM public.service_principal_credential
			WHERE organization_id = $1 AND id = $2
		`, access.OrganizationID, credentialID).Scan(&principalID, &revokedAt); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeNotFound}
			}
			return err
		}
		if revokedAt != nil {
			return &Error{code: CodeNotFound}
		}
		rows, err := tx.Query(txCtx, `
			SELECT workspace_id FROM public.service_principal_workspace_scope
			WHERE organization_id = $1 AND credential_id = $2
		`, access.OrganizationID, credentialID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			workspaceIDs = append(workspaceIDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		if CodeOf(err) == CodeNotFound {
			return err
		}
		return &Error{code: CodeUnavailable, cause: err}
	}
	for _, workspaceID := range workspaceIDs {
		snapshot, getErr := service.workspaces.Get(ctx, access, workspaceID)
		if getErr != nil || !isOwner(snapshot, access.PrincipalID) {
			return &Error{code: CodeDenied}
		}
	}

	err = service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		tag, execErr := tx.Exec(txCtx, `
			UPDATE public.service_principal_credential
			SET revoked_at = transaction_timestamp(), revoked_by = $3
			WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
		`, access.OrganizationID, credentialID, access.PrincipalID)
		if execErr != nil {
			return execErr
		}
		if tag.RowsAffected() != 1 {
			return &Error{code: CodeNotFound}
		}
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodeNotFound {
			return err
		}
		return &Error{code: CodeUnavailable, cause: err}
	}

	// Best effort: the credential is already unauthenticatable (revoked_at set
	// above), so a membership-cleanup failure here never re-opens access; it
	// only leaves a stale workspace_member row an operator can remove by hand.
	for _, workspaceID := range workspaceIDs {
		snapshot, getErr := service.workspaces.Get(ctx, access, workspaceID)
		if getErr != nil {
			continue
		}
		hash, hashErr := workspace.ConfigurationHash(snapshot)
		if hashErr != nil {
			continue
		}
		key, keyErr := freshIdempotencyKey()
		if keyErr != nil {
			continue
		}
		_, _ = service.workspaces.RemoveMember(ctx, access, workspacerepository.RemoveMemberRequest{
			IdempotencyKey: key, WorkspaceID: workspaceID, ExpectedConfigurationHash: hash, PrincipalID: principalID,
		})
	}
	return nil
}

// Authenticate resolves a raw Bearer access code within one known
// organization (the deployment's single tenant, exactly as the browser
// session authenticator resolves its tenant before validating a cookie) into
// an AccessContext for the SERVICE principal it names. Every failure —
// malformed code, unknown digest, expired, revoked or an inactive principal —
// is the identical CodeDenied so the MCP endpoint discloses no oracle.
func (service *Service) Authenticate(ctx context.Context, organizationID, rawCode, requestID string) (database.AccessContext, error) {
	if service == nil || service.db == nil || ctx == nil || !ValidCodeShape(rawCode) {
		return database.AccessContext{}, &Error{code: CodeDenied}
	}
	digest := codeDigest(rawCode)
	preAuth, err := database.NewServicePrincipalPreAuthAccess(organizationID, requestID)
	if err != nil {
		return database.AccessContext{}, &Error{code: CodeDenied}
	}
	var principalID, principalStatus string
	err = service.db.Read(ctx, preAuth, func(txCtx context.Context, tx database.Transaction) error {
		var expiresAt time.Time
		var revokedAt, activatedAt *time.Time
		if scanErr := tx.QueryRow(txCtx, `
			SELECT credential.principal_id, credential.expires_at, credential.revoked_at,
			       credential.activated_at, principal.status
			FROM public.service_principal_credential credential
			JOIN public.principal ON principal.organization_id = credential.organization_id AND principal.id = credential.principal_id
			WHERE credential.organization_id = $1 AND credential.code_digest = $2
		`, organizationID, digest).Scan(&principalID, &expiresAt, &revokedAt, &activatedAt, &principalStatus); scanErr != nil {
			return &Error{code: CodeDenied}
		}
		// FIX-1 #2: activated_at is set only after every requested workspace's
		// membership has committed. A credential still mid-provisioning (or
		// permanently unwound after a failed Issue) is denied exactly like a
		// revoked one -- there is no window where a partially-granted
		// credential authenticates.
		if revokedAt != nil || activatedAt == nil || !expiresAt.After(time.Now().UTC()) || principalStatus != "ACTIVE" {
			return &Error{code: CodeDenied}
		}
		return nil
	})
	if err != nil {
		return database.AccessContext{}, &Error{code: CodeDenied}
	}
	access := database.AccessContext{
		OrganizationID: organizationID, PrincipalID: principalID, RequestID: requestID,
		ActorKind: database.ActorKindService,
	}
	if access.Validate() != nil {
		return database.AccessContext{}, &Error{code: CodeDenied}
	}
	return access, nil
}

// ValidCodeShape is the cheap, content-free prefix/length check the HTTP
// boundary uses to decide whether a Bearer value should even be tried against
// this authenticator, before any database round trip.
func ValidCodeShape(value string) bool {
	if !strings.HasPrefix(value, CodePrefix) {
		return false
	}
	encoded := value[len(CodePrefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == rawCodeBytes && base64.RawURLEncoding.EncodeToString(decoded) == encoded
}

func generateCode() (string, string, error) {
	raw := make([]byte, rawCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	code := CodePrefix + base64.RawURLEncoding.EncodeToString(raw)
	return code, codeDigest(code), nil
}

func codeDigest(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func freshIdempotencyKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func isOwner(snapshot workspace.Snapshot, principalID string) bool {
	if snapshot.Status != workspace.StatusActive {
		return false
	}
	for _, member := range snapshot.Members {
		if member.PrincipalID == principalID && member.Role == workspace.RoleOwner {
			return true
		}
	}
	return false
}

func dedupeWorkspaceIDs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > maxWorkspaces {
		return nil, &Error{code: CodeInvalid}
	}
	seen := make(map[string]bool, len(values))
	var result []string
	for _, value := range values {
		if value == "" || len(value) > 128 {
			return nil, &Error{code: CodeInvalid}
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result, nil
}

// AuditDeniedAgentCall records that a SERVICE principal's MCP tool call was
// refused. It is deliberately content-free: the closed policy.decision action,
// the SERVICE actor kind, the calling principal, the workspace the call named
// and one closed reason code -- never the question, the tool arguments, the
// access code or any evidence.
//
// Without this, an agent's refusals were invisible: the acceptance stand can
// see that a code scoped to one workspace is denied in another, but the
// workspace owner reading the journal saw only the successful calls, so
// "who tried to reach what" -- the first thing an operator asks after issuing
// a credential to an agent -- had no answer. Failure to journal never changes
// the refusal itself; the caller has already been refused when this runs.
func (service *Service) AuditDeniedAgentCall(ctx context.Context, access database.AccessContext, workspaceID, reasonCode string) {
	if service == nil || service.audit == nil || ctx == nil ||
		access.EffectiveActorKind() != database.ActorKindService || access.Validate() != nil {
		return
	}
	if !validReasonCode(reasonCode) {
		return
	}
	eventID, idErr := service.newID("aud")
	if idErr != nil {
		return
	}
	principalID := access.PrincipalID
	deniedCode := reasonCode
	event := audit.EventInput{
		EventID: eventID, ActorType: audit.ActorService, ActorPrincipalID: &principalID,
		Action: audit.ActionPolicyDecision, ResourceType: audit.ResourcePolicy, ResourceID: principalID,
		RequestID: access.RequestID, Outcome: audit.OutcomeDenied, ErrorCode: &deniedCode,
		Metadata:   audit.Metadata{ReasonCodes: []string{reasonCode}},
		OccurredAt: service.now().UTC(),
	}
	if validOpaqueScope(workspaceID) {
		scoped := workspaceID
		event.WorkspaceID = &scoped
	}
	if _, appendErr := service.audit.Append(ctx, access, event); appendErr != nil {
		slog.Warn("denied agent tool call not audited", "component", "knowvault-server",
			"request_id", access.RequestID, "error_code", audit.CodeOf(appendErr))
	}
}

// validReasonCode keeps the journal's reason vocabulary closed: uppercase
// ASCII, digits and underscore only, bounded, so no caller-supplied text can
// ever reach the audit metadata through this path.
func validReasonCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validOpaqueScope(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}
