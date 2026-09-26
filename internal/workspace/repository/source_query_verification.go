package repository

// source_query_verification.go is S3 card 2c's storage for the least-privilege
// proof behind ADR-0097's knowvault_source_sql tool. The proof itself runs in
// internal/source/postgresqlquery/governedquery against the customer database;
// this boundary only records the content-free outcome bound to the exact
// (connection revision, query credential revision, projection hash) pair, so
// the next call with the same pair can reuse it and any change to either side
// forces a fresh proof.
//
// It stores no secret, no DSN, no relation name and no row: only the two
// revision counters, the projection hash and the role digest the server proved.

import (
	"context"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// RecordSourceQueryVerification upserts the content-free least-privilege proof
// for one connection. It is called by composition only after the tool boundary
// already authorized the caller against this exact source, and the table's RLS
// policy plus its connection foreign key keep a foreign organization from
// writing any row.
func (store *Store) RecordSourceQueryVerification(ctx context.Context, access database.AccessContext, workspaceID, sourceID string,
	connectionRevision, credentialRevision int64, scopeHash, roleDigest string) error {
	if store == nil || store.database == nil || access.Validate() != nil ||
		!validID(workspaceID) || !validID(sourceID) ||
		connectionRevision < 1 || credentialRevision < 1 ||
		!validSourceQueryDigest(scopeHash) || !validSourceQueryDigest(roleDigest) {
		return &Error{code: CodeRequestInvalid}
	}
	err := store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		_, writeErr := transaction.Exec(transactionContext, `
			INSERT INTO public.source_query_credential_verification (
				organization_id, connection_id, connection_revision, credential_revision,
				scope_hash, role_digest, verified_at
			) VALUES ($1, $2, $3, $4, $5, $6, transaction_timestamp())
			ON CONFLICT (organization_id, connection_id) DO UPDATE SET
				connection_revision = EXCLUDED.connection_revision,
				credential_revision = EXCLUDED.credential_revision,
				scope_hash = EXCLUDED.scope_hash,
				role_digest = EXCLUDED.role_digest,
				verified_at = transaction_timestamp()`,
			access.OrganizationID, sourceID, connectionRevision, credentialRevision, scopeHash, roleDigest)
		return writeErr
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return err
		}
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func validSourceQueryDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
