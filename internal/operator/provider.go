package operator

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
)

// ProviderRegistration is the closed configuration the operator records for
// one OIDC provider revision. OrganizationID, ProviderID and
// ClientSecretReference become mount material and must satisfy the shared
// manifest-id shape the product loader enforces (secretmount.ValidID);
// CreatedBy must satisfy the database's audit_opaque_id_is_valid shape. The
// registration SQL itself re-checks every constraint.
type ProviderRegistration struct {
	OrganizationID        string
	ProviderID            string
	IssuerURL             string
	ClientID              string
	ClientSecretReference string
	RedirectURI           string
	CreatedBy             string
}

// RegisterProvider inserts the provider and its revision 1 when absent and
// verifies the recorded configuration on repeat runs. A recorded
// configuration that conflicts with the requested one is an incompatible
// deployment state and is never silently overwritten.
func RegisterProvider(ctx context.Context, pool *pgxpool.Pool, registration ProviderRegistration) (created bool, err error) {
	if ctx == nil || pool == nil {
		return false, DependencyUnavailable("nil context or pool")
	}
	if !secretmount.ValidID(registration.OrganizationID) || !secretmount.ValidID(registration.ProviderID) ||
		!secretmount.ValidID(registration.ClientSecretReference) || !validOpaqueID(registration.CreatedBy) {
		return false, MigrationIncompatible("registration input fails the shared identifier shape")
	}
	if !validHTTPSURL(registration.IssuerURL) || !validHTTPSURL(registration.RedirectURI) {
		return false, MigrationIncompatible("issuer and redirect URI must be https URLs")
	}
	if strings.TrimSpace(registration.ClientID) == "" || len(registration.ClientID) > 512 || strings.ContainsAny(registration.ClientID, "\x00\r\n") {
		return false, MigrationIncompatible("client id fails the provider revision shape")
	}
	configurationHash := providerConfigurationHash(registration)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, DependencyUnavailable("begin registration transaction failed: " + err.Error())
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM public.oidc_provider WHERE organization_id = $1 AND id = $2)`,
		registration.OrganizationID, registration.ProviderID).Scan(&exists); err != nil {
		return false, DependencyUnavailable("provider lookup failed: " + err.Error())
	}
	if !exists {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.oidc_provider (id, organization_id, issuer_url, status, current_revision, created_by)
			VALUES ($1, $2, $3, 'ACTIVE', 1, $4)`,
			registration.ProviderID, registration.OrganizationID, registration.IssuerURL, registration.CreatedBy); err != nil {
			if isUniqueViolation(err) {
				// A concurrent operator inserted the provider between the
				// lookup and the INSERT; re-verify the recorded configuration
				// instead of failing the deployment.
				_ = tx.Rollback(ctx)
				return verifyRegisteredProvider(ctx, pool, registration, configurationHash)
			}
			return false, MigrationIncompatible("provider insert failed: " + err.Error())
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.oidc_provider_revision (
				organization_id, provider_id, revision, client_id, client_secret_reference,
				redirect_uri, allowed_id_token_algorithms_json, configuration_hash, created_by
			) VALUES ($1, $2, 1, $3, $4, $5, '["RS256"]'::jsonb, $6, $7)`,
			registration.OrganizationID, registration.ProviderID, registration.ClientID,
			registration.ClientSecretReference, registration.RedirectURI, configurationHash, registration.CreatedBy); err != nil {
			if isUniqueViolation(err) {
				_ = tx.Rollback(ctx)
				return verifyRegisteredProvider(ctx, pool, registration, configurationHash)
			}
			return false, MigrationIncompatible("provider revision insert failed: " + err.Error())
		}
		if err := tx.Commit(ctx); err != nil {
			return false, DependencyUnavailable("registration commit failed: " + err.Error())
		}
		return true, nil
	}
	created, err = verifyProviderInTransaction(ctx, tx, registration, configurationHash)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, DependencyUnavailable("registration verification commit failed: " + err.Error())
	}
	return created, nil
}

// verifyRegisteredProvider re-opens a fresh transaction after a unique
// violation and applies the same recorded-configuration verification as the
// ordinary repeat path. A unique violation on the issuer index with a
// different provider id is a permanent configuration conflict, not a
// transient race: the issuer is already registered under another id and no
// retry can resolve it, so it is classified MIGRATION_INCOMPATIBLE.
func verifyRegisteredProvider(ctx context.Context, pool *pgxpool.Pool, registration ProviderRegistration, configurationHash string) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, DependencyUnavailable("begin registration verification failed: " + err.Error())
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var existingID string
	if err := tx.QueryRow(ctx, `
		SELECT id FROM public.oidc_provider
		WHERE organization_id = $1 AND issuer_url = $2`,
		registration.OrganizationID, registration.IssuerURL).Scan(&existingID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, DependencyUnavailable("provider row vanished during concurrent registration")
		}
		return false, DependencyUnavailable("provider issuer lookup failed: " + err.Error())
	}
	if existingID != registration.ProviderID {
		return false, MigrationIncompatible("issuer is already registered under provider id " + existingID)
	}
	created, err := verifyProviderInTransaction(ctx, tx, registration, configurationHash)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, DependencyUnavailable("registration verification commit failed: " + err.Error())
	}
	return created, nil
}

// verifyProviderInTransaction locks the provider row and verifies that the
// recorded revision 1 configuration matches the requested payload exactly.
// A conflicting recorded configuration is an incompatible deployment state
// and is never silently overwritten.
//
// Lock contract: the oidc_provider row is locked FOR UPDATE before the
// revision row is read. Today no code path in this package updates a
// revision row after creation, so the revision read is safe unlocked; any
// future writer of oidc_provider_revision must take the provider-row lock
// first and keep this read inside that transaction.
func verifyProviderInTransaction(ctx context.Context, tx pgx.Tx, registration ProviderRegistration, configurationHash string) (bool, error) {
	var issuer string
	var status string
	var revision int64
	err := tx.QueryRow(ctx, `
		SELECT issuer_url, status, current_revision
		FROM public.oidc_provider
		WHERE organization_id = $1 AND id = $2
		FOR UPDATE`, registration.OrganizationID, registration.ProviderID).Scan(&issuer, &status, &revision)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The row that caused the unique violation vanished before
		// verification; treat it as a transient registration race.
		return false, DependencyUnavailable("provider row vanished during concurrent registration")
	case err != nil:
		return false, DependencyUnavailable("provider lookup failed: " + err.Error())
	}
	if status != "ACTIVE" || revision < 1 {
		return false, MigrationIncompatible("provider is not in an active registered state")
	}
	var clientID, secretReference, redirectURI, recordedHash string
	if err := tx.QueryRow(ctx, `
		SELECT client_id, client_secret_reference, redirect_uri, configuration_hash
		FROM public.oidc_provider_revision
		WHERE organization_id = $1 AND provider_id = $2 AND revision = $3`,
		registration.OrganizationID, registration.ProviderID, revision).Scan(&clientID, &secretReference, &redirectURI, &recordedHash); err != nil {
		return false, DependencyUnavailable("provider revision lookup failed: " + err.Error())
	}
	if clientID != registration.ClientID || secretReference != registration.ClientSecretReference ||
		redirectURI != registration.RedirectURI || recordedHash != configurationHash {
		return false, MigrationIncompatible("provider registration conflicts with the recorded configuration")
	}
	return false, nil
}

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}

// providerConfigurationHash is the deterministic drift fingerprint of one
// registration payload. Every field is preceded by its 4-byte big-endian
// length prefix, so no field value can be confused with a separator or a
// concatenation boundary (a | -joined hash would collide on "a","b|c" and
// "a|b","c"). It is deployment configuration, not tenant data: the operator
// compares it on repeat registrations and stores it for the revision's audit
// trail.
func providerConfigurationHash(registration ProviderRegistration) string {
	fields := []string{
		registration.IssuerURL, registration.ClientID, registration.ClientSecretReference,
		registration.RedirectURI, "RS256",
	}
	var builder strings.Builder
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		builder.Write(length[:])
		builder.WriteString(field)
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validOpaqueID mirrors the database shape rule app.audit_opaque_id_is_valid:
// 1..256 characters, trimmed, no control characters. It applies to the
// audit-only created_by field; every identifier that becomes mount material
// (organization, provider, client secret reference) uses the shared
// secretmount.ValidID shape instead. The database constraint remains
// authoritative.
func validOpaqueID(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// validHTTPSURL is the shared shape of issuer_url and redirect_uri enforced by
// the provider DDL: https with no whitespace, 9..2048 characters, no query,
// fragment or userinfo, and a canonical hostname validated by the same rule
// the server composition applies (netcanon.ValidCanonicalHost). The operator
// never maintains a second implementation of the hostname rule.
func validHTTPSURL(value string) bool {
	if len(value) < 9 || len(value) > 2048 || !strings.HasPrefix(value, "https://") {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return false
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || !netcanon.ValidCanonicalHost(hostname) {
		return false
	}
	port := parsed.Port()
	if port == "" {
		return true
	}
	if strings.Contains(hostname, ":") {
		// A canonical IPv6 literal is accepted by the hostname rule, but an
		// issuer or redirect URI with an explicit port on an IPv6 literal is
		// outside the deployment shape and fails closed.
		return false
	}
	if parsed.Host != net.JoinHostPort(hostname, port) {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535 && strconv.Itoa(portNumber) == port
}

// ProviderState is the readiness-checked registered state of one provider.
type ProviderState struct {
	IssuerURL         string
	Status            string
	Revision          int64
	ClientID          string
	SecretRef         string
	RedirectURI       string
	ConfigurationHash string
}

// LookupProvider reads the registered provider state for readiness. A missing
// provider is a deployment gap, reported as a typed migration-state conflict
// (run provider-register), not a transient outage.
func LookupProvider(ctx context.Context, pool *pgxpool.Pool, organizationID, providerID string) (*ProviderState, error) {
	if ctx == nil || pool == nil {
		return nil, DependencyUnavailable("nil context or pool")
	}
	state := &ProviderState{}
	var revision int64
	err := pool.QueryRow(ctx, `
		SELECT issuer_url, status, current_revision
		FROM public.oidc_provider
		WHERE organization_id = $1 AND id = $2`, organizationID, providerID).Scan(&state.IssuerURL, &state.Status, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, MigrationIncompatible("provider is not registered")
	}
	if err != nil {
		return nil, DependencyUnavailable("provider lookup failed: " + err.Error())
	}
	state.Revision = revision
	if err := pool.QueryRow(ctx, `
		SELECT client_id, client_secret_reference, redirect_uri, configuration_hash
		FROM public.oidc_provider_revision
		WHERE organization_id = $1 AND provider_id = $2 AND revision = $3`,
		organizationID, providerID, revision).Scan(&state.ClientID, &state.SecretRef, &state.RedirectURI, &state.ConfigurationHash); err != nil {
		return nil, DependencyUnavailable(fmt.Sprintf("provider revision %d lookup failed: %v", revision, err))
	}
	return state, nil
}
