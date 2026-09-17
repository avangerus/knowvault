//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
)

// The e2e owner subject is a fixed constant of the harness: the static IdP
// issues the id_token with this sub, and the seeded external identity must
// carry the digest of the same subject computed with the mount identity key.
const ownerSubject = "e2e-owner-subject"

// ownerPrincipalID is the operator-provisioned tenant owner the product surface, the
// authority chain and the operator created-by references all name.
const ownerPrincipalID = "e2e-owner"

// seedWorkerPrincipal installs only the fixed service identity required by the
// current worker composition. The owner organization/workspace is created by
// the built operator's tenant-provision command; keeping owner provisioning out
// of this SQL helper makes the documented empty-database boot order executable.
func seedWorkerPrincipal(ctx context.Context, cfg config) error {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	statements := []struct {
		sql  string
		args []any
	}{
		{
			// The worker composition claims under this fixed service principal;
			// the audit events it appends require a principal string, so it must
			// exist before the first poll.
			sql:  "INSERT INTO public.principal (id, organization_id, type, display_name, status) VALUES ('knowvault_worker', $1, 'SERVICE', 'knowvault_worker', 'ACTIVE') ON CONFLICT (id) DO NOTHING",
			args: []any{cfg.organizationID},
		},
	}
	if err := execInTransaction(ctx, admin, statements); err != nil {
		return fmt.Errorf("seed worker principal: %w", err)
	}
	return nil
}

// seedExternalIdentity links the owner principal to the static IdP subject
// through the keyed external-subject digest. It must run after
// provider-register (the row references the provider) and after the
// operator-generated mount exists (the digest is computed with the mount
// identity HMAC key, the same key the server uses to verify the subject at
// login).
func seedExternalIdentity(ctx context.Context, cfg config) error {
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return fmt.Errorf("admin pool: %w", err)
	}
	defer admin.Close()
	digest, version, err := subjectDigest(ownerSubject, cfg.organizationID, cfg.providerID)
	if err != nil {
		return err
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{
			sql: "INSERT INTO public.external_identity (" +
				"id, organization_id, principal_id, provider_id, external_subject_digest," +
				"digest_key_version, attributes_hash, status" +
				") VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE') ON CONFLICT (id) DO NOTHING",
			args: []any{
				"ext-e2e-owner", cfg.organizationID, ownerPrincipalID, cfg.providerID,
				digest, version, "sha256:" + hex.EncodeToString(sha256.New().Sum(nil)),
			},
		},
	}
	if err := execInTransaction(ctx, admin, statements); err != nil {
		return fmt.Errorf("seed external identity: %w", err)
	}
	return nil
}

func execInTransaction(ctx context.Context, admin *pgxpool.Pool, statements []struct {
	sql  string
	args []any
}) error {
	tx, err := admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// subjectDigest computes the external-subject keyed digest with the identity
// HMAC key of the generated mount through the production secretmount loader,
// so the key material (base64 decoding included) and the digest format can
// never drift from what the server verifies at login.
func subjectDigest(subject, organizationID, providerID string) (string, uint32, error) {
	mounted, err := secretmount.LoadMounted("/run/knowvault/secrets",
		identity.OrganizationID(organizationID), identity.ProviderID(providerID))
	if err != nil {
		return "", 0, fmt.Errorf("load mounted: %w", err)
	}
	defer mounted.Close()
	key, err := mounted.IdentityKey()
	if err != nil {
		return "", 0, fmt.Errorf("identity key: %w", err)
	}
	defer key.Clear()
	digestor, err := oidc.NewHMACDigestor(key.Version(), key.Bytes())
	if err != nil {
		return "", 0, fmt.Errorf("identity digestor: %w", err)
	}
	defer digestor.Close()
	digest, err := digestor.Digest("subject", subject)
	if err != nil {
		return "", 0, fmt.Errorf("subject digest: %w", err)
	}
	return digest.Value(), key.Version(), nil
}
