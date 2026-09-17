// Package repository persists the narrow, pre-authentication OIDC state
// machine. It accepts only opaque IDs and validated keyed digests; raw tokens,
// OIDC subjects, authorization codes, browser secrets and email claims never
// cross this boundary.
package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	maxCommitAttempts  = 3
	maxLoginLifetime   = 15 * time.Minute
	maxSessionLifetime = 24 * time.Hour

	// sessionRenewalWindow is FIX-7 #3's sliding renewal: ResolveSession, on
	// every successful authenticated request, pushes a session that is
	// entering its second half of life (less than sessionRenewalWindow/2
	// remaining) back out to sessionRenewalWindow from now, never past the
	// hard sessionsLifetime ceiling from issuance. A session with no activity
	// for a full sessionRenewalWindow still expires exactly as before this
	// change (fail-closed is unchanged: identity.Validate still rejects any
	// expired, revoked, disabled-principal or disabled-provider session on
	// every request); an actively used session now lives the whole work
	// shift instead of dying on the OIDC provider's own short-lived ID token
	// (root cause: internal/platform/oidcweb/handler.go used to set the
	// session's expiry directly to that token's own `exp`, with nothing ever
	// extending it).
	sessionRenewalWindow = 30 * time.Minute
)

// ErrorCode is content-free and is the only repository result suitable for a
// transport response or regular log.
type ErrorCode string

const (
	CodeRequestInvalid ErrorCode = "IDENTITY_REPOSITORY_REQUEST_INVALID"
	CodeDenied         ErrorCode = "IDENTITY_REPOSITORY_DENIED"
	CodeUnavailable    ErrorCode = "IDENTITY_REPOSITORY_UNAVAILABLE"
	CodeContended      ErrorCode = "IDENTITY_REPOSITORY_CONTENDED"

	// CodeSessionTerminationFailed is the single closed failure code for every
	// session termination failure branch (ADR-0075 §5): the HTTP boundary and
	// the audit event share it so no branch reveals whether another session
	// exists.
	CodeSessionTerminationFailed ErrorCode = "SESSION_TERMINATION_FAILED"

	// SessionTerminationRevocationCode is the only revocation_code written by
	// logout; the identity_session schema check accepts exactly this shape.
	SessionTerminationRevocationCode = "SESSION_TERMINATED"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (errorValue *Error) Error() string { return string(errorValue.code) }
func (errorValue *Error) Unwrap() error { return errorValue.cause }

func CodeOf(err error) ErrorCode {
	var repositoryError *Error
	if errors.As(err, &repositoryError) {
		return repositoryError.code
	}
	return CodeUnavailable
}

// Store is the only identity persistence adapter. It owns the database and
// audit stores together so a login outcome cannot commit without its event.
type Store struct {
	database *database.Store
	audit    *audit.Store
	now      func() time.Time
}

func New(databaseStore *database.Store, auditStore *audit.Store) (*Store, error) {
	if databaseStore == nil || auditStore == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return &Store{database: databaseStore, audit: auditStore, now: time.Now}, nil
}

// BeginLoginRequest is created by the future OIDC transport adapter after it
// generated raw state/nonce/PKCE/browser values and converted each to a
// KeyedDigest. The raw values are intentionally absent from this contract.
type BeginLoginRequest struct {
	OrganizationID       identity.OrganizationID
	ProviderID           identity.ProviderID
	ProviderRevision     int64
	LoginAttemptID       string
	RequestID            string
	StateDigest          identity.KeyedDigest
	BrowserBindingDigest identity.KeyedDigest
	NonceDigest          identity.KeyedDigest
	PKCEVerifierDigest   identity.KeyedDigest
	ExpiresAt            time.Time
}

type LoginAttempt struct {
	ID               string
	OrganizationID   identity.OrganizationID
	ProviderID       identity.ProviderID
	ProviderRevision int64
	ExpiresAt        time.Time
}

// PendingLoginRequest binds a browser callback to the one exact durable OIDC
// attempt it is permitted to continue. Every digest is mandatory; raw OIDC
// material remains outside this repository.
type PendingLoginRequest struct {
	OrganizationID       identity.OrganizationID
	ProviderID           identity.ProviderID
	ProviderRevision     int64
	LoginAttemptID       string
	RequestID            string
	StateDigest          identity.KeyedDigest
	BrowserBindingDigest identity.KeyedDigest
	NonceDigest          identity.KeyedDigest
	PKCEVerifierDigest   identity.KeyedDigest
}

// ProviderConfiguration is the internal, revision-bound OIDC projection. The
// secret reference is opaque metadata for a later secret resolver; it is never
// a secret itself and must not cross a transport response.
type ProviderConfiguration struct {
	OrganizationID        identity.OrganizationID
	ProviderID            identity.ProviderID
	Revision              int64
	IssuerURL             string
	ClientID              string
	ClientSecretReference string
	RedirectURL           string
	SigningAlgorithms     []string
}

// CompleteLoginRequest contains the callback proofs after the future OIDC
// adapter verified issuer, audience, signature, nonce and PKCE. It contains
// neither the ID token nor the raw OIDC subject or session secret.
type CompleteLoginRequest struct {
	OrganizationID        identity.OrganizationID
	ProviderID            identity.ProviderID
	ProviderRevision      int64
	LoginAttemptID        string
	RequestID             string
	AuditEventID          string
	StateDigest           identity.KeyedDigest
	BrowserBindingDigest  identity.KeyedDigest
	NonceDigest           identity.KeyedDigest
	PKCEVerifierDigest    identity.KeyedDigest
	ExternalSubjectDigest identity.KeyedDigest
	SessionID             string
	SessionTokenDigest    identity.KeyedDigest
	SessionExpiresAt      time.Time
}

// IssuedSession is the non-secret result of a successful callback. The OIDC
// adapter retains the raw cookie value it generated; the repository never sees
// it, and returns only its server-side identity metadata.
type IssuedSession struct {
	ID             string
	OrganizationID identity.OrganizationID
	PrincipalID    identity.PrincipalID
	ProviderID     identity.ProviderID
	ExpiresAt      time.Time
}

type ResolveSessionRequest struct {
	OrganizationID     identity.OrganizationID
	RequestID          string
	SessionTokenDigest identity.KeyedDigest
}

// AuthenticatedSession exists only after a current principal/provider check
// passed. Access is therefore safe to pass to policy and workspace layers.
type AuthenticatedSession struct {
	SessionID string
	Claims    identity.Claims
	Access    database.AccessContext
	// Renewed is FIX-7 #3: true when this exact call extended the session's
	// server-side expires_at (sliding renewal, capped at issuance +
	// maxSessionLifetime). Claims.ExpiresAt() already reflects the extended
	// value either way; a caller that also fronts the session with a browser
	// cookie (ADR-0030: cookie Max-Age must never exceed the server-side
	// session expiry) uses this flag to decide whether that cookie's Max-Age
	// needs reissuing this request, rather than rewriting it on every request.
	Renewed bool
}

// RevokeSessionRequest asks for the one-shot transition of an exact session
// row into the revoked shape (ADR-0075 §1.2). The repository never learns the
// raw session token.
type RevokeSessionRequest struct {
	OrganizationID identity.OrganizationID
	SessionID      string
	PrincipalID    identity.PrincipalID
	RequestID      string
	AuditEventID   string
}

// RevocationOutcome reports whether the session row actually transitioned.
// Revoked=false means the row was already revoked: the call was a no-op and
// wrote no event, so a repeated logout never duplicates the success record.
type RevocationOutcome struct {
	Revoked bool
}

// RecordSessionTerminationFailureRequest records one closed failure event for
// a termination attempt that never reached a session transition. SessionID
// and PrincipalID stay nil when the presented session could not be resolved;
// the event then carries no identity detail beyond the server-generated
// request id (ADR-0075 §5, no oracle).
type RecordSessionTerminationFailureRequest struct {
	OrganizationID identity.OrganizationID
	SessionID      *string
	PrincipalID    *identity.PrincipalID
	RequestID      string
	AuditEventID   string
}

func (store *Store) BeginLogin(ctx context.Context, request BeginLoginRequest) (LoginAttempt, error) {
	if err := store.validateBegin(request); err != nil {
		return LoginAttempt{}, err
	}
	now := store.now().UTC()
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(maxLoginLifetime)) {
		return LoginAttempt{}, &Error{code: CodeRequestInvalid}
	}
	access, err := database.NewOIDCServiceAccess(string(request.OrganizationID), request.RequestID)
	if err != nil {
		return LoginAttempt{}, &Error{code: CodeRequestInvalid}
	}

	var result LoginAttempt
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		var providerRevision int64
		if queryErr := transaction.QueryRow(transactionContext, `
			SELECT COALESCE((
				SELECT current_revision
				FROM public.oidc_provider
				WHERE organization_id = $1 AND id = $2 AND status = 'ACTIVE' AND current_revision = $3
			), 0)
		`, string(request.OrganizationID), string(request.ProviderID), request.ProviderRevision).Scan(&providerRevision); queryErr != nil {
			return queryErr
		}
		if providerRevision == 0 {
			return &Error{code: CodeDenied}
		}
		if _, execErr := transaction.Exec(transactionContext, `
			INSERT INTO public.oidc_login_attempt (
				id, organization_id, provider_id, provider_revision, state_digest,
				browser_binding_digest, nonce_digest, pkce_verifier_digest, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, request.LoginAttemptID, string(request.OrganizationID), string(request.ProviderID), providerRevision,
			request.StateDigest.Value(), request.BrowserBindingDigest.Value(), request.NonceDigest.Value(), request.PKCEVerifierDigest.Value(), request.ExpiresAt.UTC()); execErr != nil {
			return execErr
		}
		result = LoginAttempt{
			ID: request.LoginAttemptID, OrganizationID: request.OrganizationID, ProviderID: request.ProviderID,
			ProviderRevision: providerRevision, ExpiresAt: request.ExpiresAt.UTC(),
		}
		return nil
	})
	if err != nil {
		return LoginAttempt{}, normalizeError(err)
	}
	return result, nil
}

// LoadProviderConfiguration resolves one active current provider revision for
// an OIDC adapter before it starts discovery. A later BeginLogin request must
// present this exact revision, preventing a configuration race from mixing a
// newly discovered endpoint with an older stored provider revision.
func (store *Store) LoadProviderConfiguration(ctx context.Context, organizationID identity.OrganizationID, providerID identity.ProviderID, requestID string) (ProviderConfiguration, error) {
	if store == nil || store.database == nil || !validID(string(organizationID)) || !validID(string(providerID)) || !validID(requestID) {
		return ProviderConfiguration{}, &Error{code: CodeRequestInvalid}
	}
	access, err := database.NewOIDCServiceAccess(string(organizationID), requestID)
	if err != nil {
		return ProviderConfiguration{}, &Error{code: CodeRequestInvalid}
	}
	var configuration ProviderConfiguration
	var algorithmsJSON string
	err = store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		return transaction.QueryRow(transactionContext, `
			SELECT COALESCE(max(provider.current_revision), 0),
			       COALESCE(max(provider.issuer_url), ''),
			       COALESCE(max(revision.client_id), ''),
			       COALESCE(max(revision.client_secret_reference), ''),
			       COALESCE(max(revision.redirect_uri), ''),
			       COALESCE(max(revision.allowed_id_token_algorithms_json::text), '')
			FROM public.oidc_provider AS provider
			JOIN public.oidc_provider_revision AS revision
			  ON revision.organization_id = provider.organization_id
			 AND revision.provider_id = provider.id
			 AND revision.revision = provider.current_revision
			WHERE provider.organization_id = $1 AND provider.id = $2 AND provider.status = 'ACTIVE'
		`, string(organizationID), string(providerID)).Scan(
			&configuration.Revision, &configuration.IssuerURL, &configuration.ClientID,
			&configuration.ClientSecretReference, &configuration.RedirectURL, &algorithmsJSON,
		)
	})
	if err != nil {
		return ProviderConfiguration{}, normalizeError(err)
	}
	if configuration.Revision < 1 || configuration.IssuerURL == "" || configuration.ClientID == "" || configuration.ClientSecretReference == "" || configuration.RedirectURL == "" || algorithmsJSON == "" ||
		json.Unmarshal([]byte(algorithmsJSON), &configuration.SigningAlgorithms) != nil || len(configuration.SigningAlgorithms) == 0 {
		return ProviderConfiguration{}, &Error{code: CodeDenied}
	}
	configuration.OrganizationID = organizationID
	configuration.ProviderID = providerID
	configuration.SigningAlgorithms = append([]string(nil), configuration.SigningAlgorithms...)
	return configuration, nil
}

// LoadPendingLoginConfiguration reads the active provider configuration only
// when one still-pending, unexpired login attempt exact-matches every browser
// proof and the provider's current revision. It is deliberately one
// tenant-scoped read so a callback cannot combine an attempt with a newer or
// different provider configuration.
func (store *Store) LoadPendingLoginConfiguration(ctx context.Context, request PendingLoginRequest) (ProviderConfiguration, error) {
	if err := store.validatePending(request); err != nil {
		return ProviderConfiguration{}, err
	}
	access, err := database.NewOIDCServiceAccess(string(request.OrganizationID), request.RequestID)
	if err != nil {
		return ProviderConfiguration{}, &Error{code: CodeRequestInvalid}
	}
	var configuration ProviderConfiguration
	var algorithmsJSON string
	err = store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		queryErr := transaction.QueryRow(transactionContext, `
			SELECT revision.client_id,
			       revision.client_secret_reference,
			       revision.redirect_uri,
			       revision.allowed_id_token_algorithms_json::text,
			       provider.issuer_url
			FROM public.oidc_login_attempt AS attempt
			JOIN public.oidc_provider AS provider
			  ON provider.organization_id = attempt.organization_id
			 AND provider.id = attempt.provider_id
			JOIN public.oidc_provider_revision AS revision
			  ON revision.organization_id = attempt.organization_id
			 AND revision.provider_id = attempt.provider_id
			 AND revision.revision = attempt.provider_revision
			WHERE attempt.organization_id = $1
			  AND attempt.id = $2
			  AND attempt.provider_id = $3
			  AND attempt.provider_revision = $4
			  AND attempt.state_digest = $5
			  AND attempt.browser_binding_digest = $6
			  AND attempt.nonce_digest = $7
			  AND attempt.pkce_verifier_digest = $8
			  AND attempt.status = 'PENDING'
			  AND attempt.expires_at > transaction_timestamp()
			  AND provider.status = 'ACTIVE'
			  AND provider.current_revision = attempt.provider_revision
			  AND provider.current_revision = $4
		`, string(request.OrganizationID), request.LoginAttemptID, string(request.ProviderID), request.ProviderRevision,
			request.StateDigest.Value(), request.BrowserBindingDigest.Value(), request.NonceDigest.Value(), request.PKCEVerifierDigest.Value()).Scan(
			&configuration.ClientID, &configuration.ClientSecretReference, &configuration.RedirectURL, &algorithmsJSON, &configuration.IssuerURL,
		)
		if database.IsNotFound(queryErr) {
			return &Error{code: CodeDenied}
		}
		return queryErr
	})
	if err != nil {
		return ProviderConfiguration{}, normalizeError(err)
	}
	if configuration.IssuerURL == "" || configuration.ClientID == "" || configuration.ClientSecretReference == "" || configuration.RedirectURL == "" || algorithmsJSON == "" ||
		json.Unmarshal([]byte(algorithmsJSON), &configuration.SigningAlgorithms) != nil || len(configuration.SigningAlgorithms) == 0 {
		return ProviderConfiguration{}, &Error{code: CodeDenied}
	}
	configuration.OrganizationID = request.OrganizationID
	configuration.ProviderID = request.ProviderID
	configuration.Revision = request.ProviderRevision
	configuration.SigningAlgorithms = append([]string(nil), configuration.SigningAlgorithms...)
	return configuration, nil
}

// CompleteLogin claims a one-time attempt, resolves an existing digest-only
// identity mapping, creates one opaque session, consumes the attempt and
// appends the outcome audit event in a single transaction.
func (store *Store) CompleteLogin(ctx context.Context, request CompleteLoginRequest) (IssuedSession, error) {
	if err := store.validateComplete(request); err != nil {
		return IssuedSession{}, err
	}
	now := store.now().UTC()
	if !request.SessionExpiresAt.After(now) || request.SessionExpiresAt.After(now.Add(maxSessionLifetime)) {
		return IssuedSession{}, &Error{code: CodeRequestInvalid}
	}
	access, err := database.NewOIDCServiceAccess(string(request.OrganizationID), request.RequestID)
	if err != nil {
		return IssuedSession{}, &Error{code: CodeRequestInvalid}
	}

	for attempt := 0; attempt < maxCommitAttempts; attempt++ {
		var result IssuedSession
		denied := false
		err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
			claimTag, claimErr := transaction.Exec(transactionContext, `
				UPDATE public.oidc_login_attempt
				SET status = 'CLAIMED', claimed_at = transaction_timestamp()
				WHERE organization_id = $1
				  AND id = $2
				  AND provider_id = $3
				  AND provider_revision = $4
				  AND state_digest = $5
				  AND browser_binding_digest = $6
				  AND nonce_digest = $7
				  AND pkce_verifier_digest = $8
				  AND status = 'PENDING'
				  AND expires_at > transaction_timestamp()
				  AND EXISTS (
					SELECT 1
					FROM public.oidc_provider AS provider
					WHERE provider.organization_id = oidc_login_attempt.organization_id
					  AND provider.id = oidc_login_attempt.provider_id
					  AND provider.status = 'ACTIVE'
					  AND provider.current_revision = oidc_login_attempt.provider_revision
				  )
			`, string(request.OrganizationID), request.LoginAttemptID, string(request.ProviderID), request.ProviderRevision,
				request.StateDigest.Value(), request.BrowserBindingDigest.Value(), request.NonceDigest.Value(), request.PKCEVerifierDigest.Value())
			if claimErr != nil {
				return claimErr
			}
			if claimTag.RowsAffected() != 1 {
				return &Error{code: CodeDenied}
			}
			var externalIdentityID, principalID string
			var principalRevision int64
			if queryErr := transaction.QueryRow(transactionContext, `
				SELECT COALESCE(max(external_identity.id), ''),
				       COALESCE(max(external_identity.principal_id), ''),
				       COALESCE(max(principal.session_revision), 0)
				FROM public.external_identity AS external_identity
				JOIN public.principal AS principal
				  ON principal.organization_id = external_identity.organization_id
				 AND principal.id = external_identity.principal_id
				JOIN public.oidc_provider AS provider
				  ON provider.organization_id = external_identity.organization_id
				 AND provider.id = external_identity.provider_id
				WHERE external_identity.organization_id = $1
				  AND external_identity.provider_id = $2
				  AND external_identity.external_subject_digest = $3
				  AND external_identity.status = 'ACTIVE'
				  AND principal.status = 'ACTIVE'
				  AND provider.status = 'ACTIVE'
				  AND provider.current_revision = $4
			`, string(request.OrganizationID), string(request.ProviderID), request.ExternalSubjectDigest.Value(), request.ProviderRevision).Scan(&externalIdentityID, &principalID, &principalRevision); queryErr != nil {
				return queryErr
			}
			if externalIdentityID == "" || principalID == "" || principalRevision < 1 {
				if failureErr := store.failAttempt(transactionContext, access, transaction, request); failureErr != nil {
					return failureErr
				}
				denied = true
				return nil
			}

			if _, insertErr := transaction.Exec(transactionContext, `
				INSERT INTO public.identity_session (
					id, organization_id, principal_id, provider_id, external_identity_id, login_attempt_id,
					session_token_digest, principal_session_revision, provider_revision, expires_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			`, request.SessionID, string(request.OrganizationID), principalID, string(request.ProviderID), externalIdentityID,
				request.LoginAttemptID, request.SessionTokenDigest.Value(), principalRevision, request.ProviderRevision, request.SessionExpiresAt.UTC()); insertErr != nil {
				return insertErr
			}
			completionTag, completionErr := transaction.Exec(transactionContext, `
				UPDATE public.oidc_login_attempt
				SET status = 'CONSUMED', completed_at = transaction_timestamp()
				WHERE organization_id = $1 AND id = $2 AND status = 'CLAIMED'
			`, string(request.OrganizationID), request.LoginAttemptID)
			if completionErr != nil {
				return completionErr
			}
			if completionTag.RowsAffected() != 1 {
				return &Error{code: CodeUnavailable}
			}
			if _, auditErr := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
				EventID: request.AuditEventID, ActorType: audit.ActorSystem, OnBehalfOfPrincipalID: pointer(principalID),
				Action: audit.ActionIdentityLogin, ResourceType: audit.ResourceIdentity, ResourceID: request.SessionID,
				RequestID: request.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
			}); auditErr != nil {
				return auditErr
			}
			result = IssuedSession{ID: request.SessionID, OrganizationID: request.OrganizationID, PrincipalID: identity.PrincipalID(principalID), ProviderID: request.ProviderID, ExpiresAt: request.SessionExpiresAt.UTC()}
			return nil
		})
		if err == nil {
			if denied {
				return IssuedSession{}, &Error{code: CodeDenied}
			}
			return result, nil
		}
		if CodeOf(err) == CodeDenied {
			return IssuedSession{}, err
		}
		if !database.IsSerializationFailure(err) {
			return IssuedSession{}, normalizeError(err)
		}
	}
	return IssuedSession{}, &Error{code: CodeContended}
}

// ResolveSession is the sole path from an opaque session digest to a normal
// user AccessContext. It reads under the fixed pre-auth service context, then
// asks the pure validator to exact-match current principal and provider state.
func (store *Store) ResolveSession(ctx context.Context, request ResolveSessionRequest) (AuthenticatedSession, error) {
	if store == nil || store.database == nil || !validID(string(request.OrganizationID)) || !validID(request.RequestID) || !validDigest(request.SessionTokenDigest) {
		return AuthenticatedSession{}, &Error{code: CodeRequestInvalid}
	}
	access, err := database.NewOIDCServiceAccess(string(request.OrganizationID), request.RequestID)
	if err != nil {
		return AuthenticatedSession{}, &Error{code: CodeRequestInvalid}
	}

	type sessionRecord struct {
		id, principalID, providerID, principalStatus, providerStatus                                 string
		issuedPrincipalRevision, providerRevision, currentPrincipalRevision, currentProviderRevision int64
		expiresAt                                                                                    time.Time
		// databaseNow is the transaction's own clock, read in the SAME
		// statement as the session snapshot. A session must never be treated as
		// live past the instant the database itself considers it expired, so
		// validation uses the later of this and the app clock.
		databaseNow time.Time
	}
	var record sessionRecord
	var renewed bool
	// FIX-7 #3: this is now a Write (not a Read) because a session entering
	// its second half of life is extended in the SAME transaction as the
	// validating read below -- one round trip, and the renewal can never be
	// observed separately from the read it is based on.
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		if scanErr := transaction.QueryRow(transactionContext, `
			SELECT COALESCE(max(session.id), ''),
			       COALESCE(max(session.principal_id), ''),
			       COALESCE(max(session.provider_id), ''),
			       COALESCE(max(session.principal_session_revision), 0),
			       COALESCE(max(session.provider_revision), 0),
			       COALESCE(max(session.expires_at), transaction_timestamp()),
			       transaction_timestamp(),
			       COALESCE(max(principal.status), ''),
			       COALESCE(max(principal.session_revision), 0),
			       COALESCE(max(provider.status), ''),
			       COALESCE(max(provider.current_revision), 0)
			FROM public.identity_session AS session
			JOIN public.principal AS principal
			  ON principal.organization_id = session.organization_id
			 AND principal.id = session.principal_id
			JOIN public.oidc_provider AS provider
			  ON provider.organization_id = session.organization_id
			 AND provider.id = session.provider_id
			JOIN public.external_identity AS external_identity
			  ON external_identity.organization_id = session.organization_id
			 AND external_identity.id = session.external_identity_id
			WHERE session.organization_id = $1
			  AND session.session_token_digest = $2
			  AND session.revoked_at IS NULL
			  AND external_identity.status = 'ACTIVE'
		`, string(request.OrganizationID), request.SessionTokenDigest.Value()).Scan(
			&record.id, &record.principalID, &record.providerID,
			&record.issuedPrincipalRevision, &record.providerRevision, &record.expiresAt,
			&record.databaseNow,
			&record.principalStatus, &record.currentPrincipalRevision, &record.providerStatus, &record.currentProviderRevision,
		); scanErr != nil {
			return scanErr
		}
		if record.id == "" {
			return nil
		}
		// Sliding renewal (FIX-7 #3): only a session that is still valid right
		// now (revoked_at IS NULL, expires_at in the future -- the exact same
		// gate identity.Validate enforces below) and has burned through more
		// than half of sessionRenewalWindow is pushed back out, to
		// now+sessionRenewalWindow, never past issued_at+maxSessionLifetime
		// (the existing identity_session CHECK constraint's own ceiling). A
		// session outside that window (freshly renewed, already expired, or
		// already at the 24h ceiling) is left untouched -- this never
		// resurrects an expired or revoked session, and never extends one
		// past its absolute 24h issuance ceiling.
		renewRow := transaction.QueryRow(transactionContext, `
			UPDATE public.identity_session
			   SET expires_at = LEAST(transaction_timestamp() + make_interval(secs => $3), issued_at + make_interval(secs => $4))
			 WHERE organization_id = $1
			   AND id = $2
			   AND revoked_at IS NULL
			   AND expires_at > transaction_timestamp()
			   AND expires_at < transaction_timestamp() + make_interval(secs => $3) / 2
			   AND expires_at < issued_at + make_interval(secs => $4)
			RETURNING expires_at
		`, string(request.OrganizationID), record.id, sessionRenewalWindow.Seconds(), maxSessionLifetime.Seconds())
		var renewedExpiresAt time.Time
		if scanErr := renewRow.Scan(&renewedExpiresAt); scanErr == nil {
			record.expiresAt = renewedExpiresAt
			renewed = true
		} else if !database.IsNotFound(scanErr) {
			return scanErr
		}
		return nil
	})
	if err != nil {
		return AuthenticatedSession{}, normalizeError(err)
	}
	if record.id == "" {
		return AuthenticatedSession{}, &Error{code: CodeDenied}
	}
	claims, claimErr := identity.NewClaims(request.OrganizationID, identity.PrincipalID(record.principalID), record.issuedPrincipalRevision, identity.ProviderID(record.providerID), record.providerRevision, record.expiresAt)
	if claimErr != nil {
		return AuthenticatedSession{}, claimErr
	}
	principal, principalErr := identity.NewCurrentPrincipal(request.OrganizationID, identity.PrincipalID(record.principalID), identity.PrincipalStatus(record.principalStatus), record.currentPrincipalRevision)
	if principalErr != nil {
		return AuthenticatedSession{}, principalErr
	}
	provider, providerErr := identity.NewCurrentProvider(request.OrganizationID, identity.ProviderID(record.providerID), identity.ProviderStatus(record.providerStatus), record.currentProviderRevision)
	if providerErr != nil {
		return AuthenticatedSession{}, providerErr
	}
	if validationErr := store.validateSession(claims, principal, provider, record.databaseNow); validationErr != nil {
		return AuthenticatedSession{}, validationErr
	}
	return AuthenticatedSession{
		SessionID: record.id,
		Claims:    claims,
		Access:    database.AccessContext{OrganizationID: string(request.OrganizationID), PrincipalID: record.principalID, RequestID: request.RequestID},
		Renewed:   renewed,
	}, nil
}

// validateSession uses the later application or database instant for final
// validation, so a lagging app clock cannot accept a database-expired session.
// The shared validator retains its existing typed errors and their ordering.
func (store *Store) validateSession(claims identity.Claims, principal identity.CurrentPrincipal, provider identity.CurrentProvider, databaseNow time.Time) error {
	validationNow := store.now().UTC()
	if databaseNow.After(validationNow) {
		validationNow = databaseNow
	}
	return identity.Validate(validationNow, claims, principal, provider)
}

// RevokeSession transitions the exact session row into the revoked shape in
// one transaction together with its success audit event. The guard on
// identity_session accepts only the NULL→revoked transition, so the event
// cannot commit without the revocation and vice versa.
func (store *Store) RevokeSession(ctx context.Context, request RevokeSessionRequest) (RevocationOutcome, error) {
	if err := store.validateRevoke(request); err != nil {
		return RevocationOutcome{}, err
	}
	access := database.AccessContext{OrganizationID: string(request.OrganizationID), PrincipalID: string(request.PrincipalID), RequestID: request.RequestID}
	result := RevocationOutcome{}
	err := store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		var principalID string
		if err := transaction.QueryRow(transactionContext, `
			WITH revoked AS (
				UPDATE public.identity_session
				SET revoked_at = transaction_timestamp(), revocation_code = $3
				WHERE organization_id = $1 AND id = $2 AND revoked_at IS NULL
				RETURNING principal_id
			)
			SELECT COALESCE((SELECT principal_id FROM revoked), '')
		`, string(request.OrganizationID), request.SessionID, SessionTerminationRevocationCode).Scan(&principalID); err != nil {
			return err
		}
		if principalID == "" {
			return nil // already revoked: idempotent no-op without an event
		}
		if principalID != string(request.PrincipalID) {
			return &Error{code: CodeDenied} // defensive; rolls back the transition
		}
		if _, err := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
			EventID: request.AuditEventID, ActorType: audit.ActorHuman, ActorPrincipalID: pointer(string(request.PrincipalID)),
			Action:       audit.ActionSessionTerminated,
			ResourceType: audit.ResourceIdentity, ResourceID: request.SessionID, RequestID: request.RequestID,
			Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
		}); err != nil {
			return err
		}
		result.Revoked = true
		return nil
	})
	if err != nil {
		return RevocationOutcome{}, normalizeError(err)
	}
	return result, nil
}

// RecordSessionTerminationFailure appends the single closed failure event for
// a termination attempt that never reached a session transition. When the
// presented session could not be resolved the actor is the system and the
// resource is the request id; otherwise the actor is the authenticated
// principal and the resource is the session id. Both branches share the same
// error code, so the audit trail cannot serve as a session-validity oracle.
func (store *Store) RecordSessionTerminationFailure(ctx context.Context, request RecordSessionTerminationFailureRequest) error {
	if err := store.validateTerminationFailure(request); err != nil {
		return err
	}
	event := audit.EventInput{
		EventID: request.AuditEventID, Action: audit.ActionSessionTerminated,
		ResourceType: audit.ResourceIdentity, RequestID: request.RequestID,
		Outcome: audit.OutcomeFailed, ErrorCode: pointer(string(CodeSessionTerminationFailed)), OccurredAt: store.now().UTC(),
	}
	if request.PrincipalID == nil {
		access, err := database.NewOIDCServiceAccess(string(request.OrganizationID), request.RequestID)
		if err != nil {
			return &Error{code: CodeRequestInvalid}
		}
		event.ActorType = audit.ActorSystem
		event.ResourceID = request.RequestID
		return normalizeError(store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
			_, err := store.audit.AppendInTransaction(transactionContext, access, transaction, event)
			return err
		}))
	}
	access := database.AccessContext{OrganizationID: string(request.OrganizationID), PrincipalID: string(*request.PrincipalID), RequestID: request.RequestID}
	event.ActorType = audit.ActorHuman
	event.ActorPrincipalID = pointer(string(*request.PrincipalID))
	event.ResourceID = *request.SessionID
	return normalizeError(store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		_, err := store.audit.AppendInTransaction(transactionContext, access, transaction, event)
		return err
	}))
}

func (store *Store) validateRevoke(request RevokeSessionRequest) error {
	if store == nil || store.database == nil || store.audit == nil || !validID(string(request.OrganizationID)) ||
		!validID(request.SessionID) || !validID(request.RequestID) || !validID(request.AuditEventID) || !validID(string(request.PrincipalID)) {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func (store *Store) validateTerminationFailure(request RecordSessionTerminationFailureRequest) error {
	if store == nil || store.database == nil || store.audit == nil || !validID(string(request.OrganizationID)) ||
		!validID(request.RequestID) || !validID(request.AuditEventID) {
		return &Error{code: CodeRequestInvalid}
	}
	if request.SessionID == nil {
		if request.PrincipalID != nil {
			return &Error{code: CodeRequestInvalid}
		}
	} else if !validID(*request.SessionID) || request.PrincipalID == nil || !validID(string(*request.PrincipalID)) {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func (store *Store) failAttempt(ctx context.Context, access database.AccessContext, transaction database.Transaction, request CompleteLoginRequest) error {
	tag, err := transaction.Exec(ctx, `
		UPDATE public.oidc_login_attempt
		SET status = 'FAILED', completed_at = transaction_timestamp()
		WHERE organization_id = $1 AND id = $2 AND status = 'CLAIMED'
	`, string(request.OrganizationID), request.LoginAttemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return &Error{code: CodeUnavailable}
	}
	_, err = store.audit.AppendInTransaction(ctx, access, transaction, audit.EventInput{
		EventID: request.AuditEventID, ActorType: audit.ActorSystem, Action: audit.ActionIdentityLoginFailed,
		ResourceType: audit.ResourceIdentity, ResourceID: request.LoginAttemptID, RequestID: request.RequestID,
		Outcome: audit.OutcomeDenied, ErrorCode: pointer(string(CodeDenied)), OccurredAt: store.now().UTC(),
	})
	return err
}

func (store *Store) validateBegin(request BeginLoginRequest) error {
	if store == nil || store.database == nil || store.audit == nil || !validID(string(request.OrganizationID)) || !validID(string(request.ProviderID)) ||
		request.ProviderRevision < 1 || !validID(request.LoginAttemptID) || !validID(request.RequestID) || request.ExpiresAt.IsZero() ||
		!validDigest(request.StateDigest) || !validDigest(request.BrowserBindingDigest) || !validDigest(request.NonceDigest) || !validDigest(request.PKCEVerifierDigest) {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func (store *Store) validatePending(request PendingLoginRequest) error {
	if store == nil || store.database == nil || !validID(string(request.OrganizationID)) || !validID(string(request.ProviderID)) ||
		request.ProviderRevision < 1 || !validID(request.LoginAttemptID) || !validID(request.RequestID) ||
		!validDigest(request.StateDigest) || !validDigest(request.BrowserBindingDigest) || !validDigest(request.NonceDigest) || !validDigest(request.PKCEVerifierDigest) {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func (store *Store) validateComplete(request CompleteLoginRequest) error {
	if store == nil || store.database == nil || store.audit == nil || !validID(string(request.OrganizationID)) || !validID(string(request.ProviderID)) ||
		request.ProviderRevision < 1 || !validID(request.LoginAttemptID) || !validID(request.RequestID) || !validID(request.AuditEventID) || !validID(request.SessionID) || request.SessionExpiresAt.IsZero() ||
		!validDigest(request.StateDigest) || !validDigest(request.BrowserBindingDigest) || !validDigest(request.NonceDigest) || !validDigest(request.PKCEVerifierDigest) || !validDigest(request.ExternalSubjectDigest) || !validDigest(request.SessionTokenDigest) {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func validDigest(digest identity.KeyedDigest) bool {
	_, err := identity.NewKeyedDigest(digest.Value())
	return err == nil
}

func normalizeError(err error) error {
	if err == nil {
		return nil
	}
	var repositoryError *Error
	if errors.As(err, &repositoryError) {
		return err
	}
	return &Error{code: CodeUnavailable, cause: err}
}

func validID(value string) bool {
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

func pointer(value string) *string { return &value }
