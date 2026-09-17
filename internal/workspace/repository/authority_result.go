package repository

// Canonical result documents for the four authority operations. Each is the
// exact closed JCS object migration 000011's receipt guard re-parses and
// projects onto its relational columns, so the field set and every value must
// match the row inserted beside it. The bytes are built by the same shared JCS
// engine as the request envelope (authorityCanonicalHash); PostgreSQL only
// proves the stored hash is SHA-256 of exactly these bytes and that every field
// projects onto its column.

import "time"

const (
	grantSchemaVersion               = "workspace-source-confirmation-grant-v1"
	grantRevocationSchemaVersion     = "workspace-source-confirmation-grant-revocation-v1"
	confirmationSchemaVersion        = "workspace-managed-confirmation-v1"
	confirmationRevocationSchemaVers = "workspace-managed-confirmation-revocation-v1"
)

type grantDocument struct {
	SchemaVersion  string `json:"schema_version"`
	GrantID        string `json:"grant_id"`
	Revision       int64  `json:"revision"`
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	PrincipalID    string `json:"principal_id"`
	Permission     string `json:"permission"`
	ValidFrom      string `json:"valid_from"`
	ValidUntil     string `json:"valid_until"`
	PolicyRevision string `json:"policy_revision"`
	GrantedBy      string `json:"granted_by"`
	GrantedAt      string `json:"granted_at"`
}

type grantRevocationDocument struct {
	SchemaVersion  string `json:"schema_version"`
	RevocationID   string `json:"revocation_id"`
	OrganizationID string `json:"organization_id"`
	GrantID        string `json:"grant_id"`
	GrantRevision  int64  `json:"grant_revision"`
	GrantHash      string `json:"grant_hash"`
	RevokedBy      string `json:"revoked_by"`
	RevokedAt      string `json:"revoked_at"`
	ReasonCode     string `json:"reason_code"`
	PolicyRevision string `json:"policy_revision"`
}

type confirmationDocument struct {
	SchemaVersion                  string `json:"schema_version"`
	ConfirmationID                 string `json:"confirmation_id"`
	OrganizationID                 string `json:"organization_id"`
	WorkspaceID                    string `json:"workspace_id"`
	WorkspaceRevision              int64  `json:"workspace_revision"`
	WorkspaceConfigurationHash     string `json:"workspace_configuration_hash"`
	WorkspaceSourceID              string `json:"workspace_source_id"`
	SourceScopeID                  string `json:"source_scope_id"`
	SourceScopeRevision            int64  `json:"source_scope_revision"`
	ScopeConfigHash                string `json:"scope_config_hash"`
	AccessMode                     string `json:"access_mode"`
	ConfirmationActorGrantID       string `json:"confirmation_actor_grant_id"`
	ConfirmationActorGrantRevision int64  `json:"confirmation_actor_grant_revision"`
	ConfirmationActorGrantHash     string `json:"confirmation_actor_grant_hash"`
	WarningVersion                 string `json:"warning_version"`
	WarningContractHash            string `json:"warning_contract_hash"`
	AcknowledgementCode            string `json:"acknowledgement_code"`
	ConfirmedBy                    string `json:"confirmed_by"`
	ConfirmedAt                    string `json:"confirmed_at"`
	PolicyRevision                 string `json:"policy_revision"`
}

type confirmationRevocationDocument struct {
	SchemaVersion    string `json:"schema_version"`
	RevocationID     string `json:"revocation_id"`
	OrganizationID   string `json:"organization_id"`
	ConfirmationID   string `json:"confirmation_id"`
	ConfirmationHash string `json:"confirmation_hash"`
	RevokedBy        string `json:"revoked_by"`
	RevokedAt        string `json:"revoked_at"`
	ReasonCode       string `json:"reason_code"`
	PolicyRevision   string `json:"policy_revision"`
}

// authorityTimestamp formats one epoch second as the authority-timestamp-v1
// form YYYY-MM-DDTHH:MM:SSZ: UTC, mandatory seconds, no fraction, literal Z.
// It is the exact string app.authority_timestamp_v1_to_epoch round-trips, so a
// value produced here equals the transaction-second the database re-derives.
func authorityTimestamp(epoch int64) string {
	return time.Unix(epoch, 0).UTC().Format("2006-01-02T15:04:05Z")
}
