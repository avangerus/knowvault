package registration

import (
	"context"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// PostgreSQLConnectionBootstrapRequest contains only the non-secret identity
// needed to configure a DRAFT connection revision before any scope exists.
// CredentialReference names a worker-mounted secret; it never contains a DSN
// or credential bytes.
type PostgreSQLConnectionBootstrapRequest struct {
	Name                string
	DatabaseIdentity    string
	LineageID           string
	CredentialReference string
}

// PostgreSQLConnectionBootstrapResult identifies the immutable DRAFT revision
// that can be trust-verified and probed. No scope or activation is created.
type PostgreSQLConnectionBootstrapResult struct {
	ConnectionID        string
	ConnectionRevision  int64
	CredentialReference string
	TrustProfileHash    string
	Created             bool
}

// BootstrapPostgreSQLConnection creates only a DRAFT connection revision and
// its sealed trust configuration. Exact replay returns the same revision and
// does not write another artifact or audit event.
func (s *Service) BootstrapPostgreSQLConnection(ctx context.Context, access database.AccessContext,
	request PostgreSQLConnectionBootstrapRequest) (PostgreSQLConnectionBootstrapResult, error) {
	if s == nil || s.database == nil || s.audit == nil || s.codec == nil || access.Validate() != nil ||
		!validName(request.Name) || !validSchemaID(request.DatabaseIdentity) || !validSchemaID(request.LineageID) ||
		(request.CredentialReference != "" && !validGeneratedID(request.CredentialReference, "cred_")) {
		return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodeRequestInvalid}
	}
	connectionID := postgresqlConnectionID(access.OrganizationID, request.DatabaseIdentity, request.LineageID)
	credentialRef := request.CredentialReference
	if credentialRef == "" {
		credentialRef = credentialReference(access.OrganizationID, connectionID)
	}
	trustID := trustRecordID(access.OrganizationID, connectionID)
	trustBytes, err := canon.PostgreSQLQueryTrustBytes(connectionID, request.DatabaseIdentity, request.LineageID)
	if err != nil {
		return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	result := PostgreSQLConnectionBootstrapResult{
		ConnectionID: connectionID, ConnectionRevision: 1,
		CredentialReference: credentialRef, TrustProfileHash: canon.Hash(trustBytes),
	}
	denied, unavailable := false, false
	err = s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		profile, profileErr := readPostgreSQLProfile(ctx, tx)
		if profileErr != nil {
			if database.IsNotFound(profileErr) {
				unavailable = true
				return nil
			}
			return profileErr
		}
		var connectionResourceID string
		if err := tx.QueryRow(ctx, `SELECT app.registration_connection_resource_id($1,$2,1)`,
			access.OrganizationID, connectionID).Scan(&connectionResourceID); err != nil {
			return err
		}
		trustArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		owner, err := artifactcrypto.NewOwnerIdentity(
			artifactcrypto.SourceConnectionTrustConfig, access.OrganizationID, connectionResourceID)
		if err != nil {
			return err
		}
		trustEnvelope, err := s.codec.Seal(owner, trustBytes)
		if err != nil {
			return err
		}
		if trustEnvelope.PlaintextHash() != result.TrustProfileHash {
			return &Error{code: CodePersistence}
		}
		if err := tx.QueryRow(ctx, `SELECT connection_id, revision, created
			FROM app.source_postgresql_connection_bootstrap_begin(
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			connectionID, request.Name, trustID, credentialRef, trustArtifactID,
			trustEnvelope.PlaintextHash(), profile.ID, profile.ProfileHash,
			profile.ConnectorBuildID, profile.ConnectorVersion, profile.ConnectorArtifactHash,
			profile.ContractSuiteHash, profile.VerifiedAt, int64(maximumScopeObjects),
			int64(maximumScopeBytes), int64(maximumObjectBytes)).Scan(
			&result.ConnectionID, &result.ConnectionRevision, &result.Created); err != nil {
			return err
		}
		if !result.Created {
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT app.source_trust_config_bind(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			access.OrganizationID, connectionID, int64(1), trustArtifactID, connectionResourceID,
			trustEnvelope.Ciphertext(), trustEnvelope.SizeBytes(), trustEnvelope.Nonce(),
			trustEnvelope.WrappedDEK(), trustEnvelope.WrappedDEKHash(), trustEnvelope.KEKReference(),
			trustEnvelope.KEKVersion(), trustEnvelope.AADHash(), trustEnvelope.PlaintextHash()); err != nil {
			return err
		}
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceRegistrationCreated, ResourceType: audit.ResourceSourceConnection,
			ResourceID: connectionID, RequestID: access.RequestID, Outcome: audit.OutcomeSuccess,
			OccurredAt: s.now().UTC(), Metadata: audit.Metadata{SourceConnectionID: &connectionID},
		})
		return err
	})
	if err != nil {
		switch database.SQLStateCode(err) {
		case "42501":
			return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodeDenied, cause: err}
		case "23505":
			return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodeConflict, cause: err}
		default:
			return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodePersistence, cause: err}
		}
	}
	if denied {
		return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodeDenied}
	}
	if unavailable {
		return PostgreSQLConnectionBootstrapResult{}, &Error{code: CodeUnavailable}
	}
	return result, nil
}
