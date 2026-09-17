// This file is the registry-owned source-connector catalog for the read-only
// onboarding surface. The catalog is static, content-free metadata drawn from
// the real registration request paths in this package (service.go's
// RegisterRequest and the transport's own required-field projection). It never
// reflects a configured source, a credential, a raw DSN, per-source table or
// column names, a database type fingerprint or a hidden mount, so a caller can
// never learn anything about the tenant's existing registrations from it, and
// the same fresh value is returned on every call so no request mutates a shared
// registry.
package registration

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// ConnectorCatalogSchemaVersion is the deterministic, versioned envelope the
// onboarding surface returns so a future schema change is a new major/minor
// that clients can branch on instead of silently re-parsing the same path.
const ConnectorCatalogSchemaVersion = "1.0"

// RegistrationField is one field a registration form for this connector type
// accepts. Names match the exact request path the transport uses, so a client
// can build a register body from the catalog without guessing identifiers.
// Required mirrors what the registration surface actually demands for the
// type; every other accepted field is optional. No field here carries a value,
// only its identifier, presence rule and intent.
type RegistrationField struct {
	Name        string `json:"name"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// ConnectorCapabilities is the truthful capability snapshot for one connector
// type. Booleans are deliberately conservative: a value is true only when the
// code behind it actually exists today, never because a supporting column or
// interval is merely stored.
type ConnectorCapabilities struct {
	// AutonomousRecurringSync reports whether this type has an autonomous,
	// schedule-driven worker sync. FOLDER and POSTGRESQL_QUERY use the durable
	// worker schedule; GIT requires an explicitly refreshed checkout/provider.
	AutonomousRecurringSync bool `json:"autonomous_recurring_sync"`
	// GeneralDiscovery reports whether the server can autonomously discover
	// new sources or schemas for this type. Not implemented for any connector
	// in this slice: schema/relation and folder roots are always supplied by
	// the registering operator, never discovered by a probe.
	GeneralDiscovery bool `json:"general_discovery"`
}

// Connector is one entry of the deterministic catalog.
type Connector struct {
	// Type is the exact source_type token the register surface accepts.
	Type string `json:"type"`
	// Label is a short, human-facing name for the onboarding UI.
	Label string `json:"label"`
	// Description states what registering this type means. A supported type is
	// never a claim that an actual connection is configured or healthy.
	Description        string                `json:"description"`
	RegistrationFields []RegistrationField   `json:"registration_fields"`
	Capabilities       ConnectorCapabilities `json:"capabilities"`
}

// ConnectorCatalogDeclarations carries the cross-type facts the onboarding
// surface must state once instead of repeating per connector.
type ConnectorCatalogDeclarations struct {
	// GeneralDiscoveryImplemented is false: no general source/schema discovery
	// exists anywhere in this release.
	GeneralDiscoveryImplemented bool `json:"general_discovery_implemented"`
	// AutonomousRecurringSyncImplemented is true: at least one connector type
	// has a schedule-driven worker sync.
	AutonomousRecurringSyncImplemented bool `json:"autonomous_recurring_sync_implemented"`
	// AutonomousRecurringSyncSourceTypes names exactly the types that have that
	// worker sync.
	AutonomousRecurringSyncSourceTypes []string `json:"autonomous_recurring_sync_source_types"`
}

// ConnectorCatalog is the deterministic, versioned GET /api/v1/source-connectors
// response body.
type ConnectorCatalog struct {
	SchemaVersion string                       `json:"schema_version"`
	Declarations  ConnectorCatalogDeclarations `json:"declarations"`
	Connectors    []Connector                  `json:"connectors"`
}

// ConnectorCatalogData returns a fresh, immutable copy of the registry-owned
// catalog. It performs no I/O, no authorization and no mutation: it is the
// single content source that both the gated Service method below and tests use,
// and every call builds new slices so no caller can corrupt a shared registry.
func ConnectorCatalogData() ConnectorCatalog {
	return ConnectorCatalog{
		SchemaVersion: ConnectorCatalogSchemaVersion,
		Declarations: ConnectorCatalogDeclarations{
			GeneralDiscoveryImplemented:        false,
			AutonomousRecurringSyncImplemented: true,
			AutonomousRecurringSyncSourceTypes: []string{"FOLDER", "POSTGRESQL_QUERY"},
		},
		Connectors: []Connector{
			{
				Type:        "FOLDER",
				Label:       "Mounted folder",
				Description: "Registers an already-mounted filesystem folder. The worker refreshes authorized active scopes on their configured schedule. Folder discovery is not available. A supported type does not mean a connection is configured or healthy.",
				RegistrationFields: []RegistrationField{
					regField("name", true, "Display name of the source connection."),
					regField("root_alias", true, "Alias naming the mounted root identity."),
					regField("root_identity", true, "Opaque identity of the mounted filesystem share."),
					regField("relative_root", true, "Path of the scope below the mounted root."),
					regField("kind", true, "Business-object kind the contents are indexed as."),
					regField("recursive", true, "Whether descendant folders are traversed."),
					regField("include_globs", true, "Glob patterns that include objects."),
					regField("exclude_globs", true, "Glob patterns that exclude objects."),
					regField("max_file_bytes", true, "Per-object byte ceiling for ingestion."),
					regField("ocr_mode", true, "OCR policy for scanned content."),
					regField("formats", true, "Accepted document/office formats."),
					regField("credential_reference", false, "Opaque reference to a worker-mounted source credential; never a secret value."),
				},
				Capabilities: ConnectorCapabilities{AutonomousRecurringSync: true, GeneralDiscovery: false},
			},
			{
				Type:        "POSTGRESQL_QUERY",
				Label:       "PostgreSQL query projection",
				Description: "Registers an immutable projection over a PostgreSQL relation. The worker refreshes authorized active scopes on their configured schedule. General schema discovery is not available. A supported type does not mean a connection is configured or healthy.",
				RegistrationFields: []RegistrationField{
					regField("name", true, "Display name of the source connection."),
					regField("kind", true, "Business-object kind the projection is indexed as."),
					regField("database_identity", true, "Identity of the target database (never a raw DSN)."),
					regField("lineage_id", true, "Immutable lineage label of the projection."),
					regField("projection_revision", true, "Immutable revision number of the projection contract."),
					regField("contract_hash", true, "Hash of the projection contract this registration commits to."),
					regField("schema_name", true, "Name of the target schema in the database."),
					regField("relation_name", true, "Name of the target relation in that schema."),
					regField("relation_kind", true, "Kind of the target relation (e.g. TABLE, VIEW)."),
					regField("columns", true, "Declared projection column list with their roles and logical types."),
					regField("empty_snapshot_policy", true, "Policy applied when the projection returns no rows."),
					regField("max_rows", false, "Row ceiling for one snapshot."),
					regField("max_columns", false, "Column ceiling for the projection."),
					regField("max_field_bytes", false, "Per-field byte ceiling."),
					regField("max_row_bytes", false, "Per-row byte ceiling."),
					regField("max_total_bytes", false, "Snapshot-wide byte ceiling."),
					regField("statement_timeout_ms", false, "Statement timeout for one query."),
					regField("sync_interval_seconds", false, "Autonomous recurring-sync interval chosen at registration."),
					regField("credential_reference", false, "Opaque reference to a worker-mounted source credential; never a secret value."),
				},
				Capabilities: ConnectorCapabilities{AutonomousRecurringSync: true, GeneralDiscovery: false},
			},
			{
				Type:        "GIT",
				Label:       "Git repository",
				Description: "Registers a remote Git repository by provider, endpoint and repository identity. Registration is declarative: it does not autonomously discover repositories and does not claim an automatic clone or pull loop at registration (no remote is fetched merely because a MOUNT/endpoint reference is supplied). A supported type does not mean a connection is configured or healthy.",
				RegistrationFields: []RegistrationField{
					regField("name", true, "Display name of the source connection."),
					regField("kind", true, "Business-object kind the code is indexed as."),
					regField("provider", true, "Hosting provider of the remote repository."),
					regField("endpoint", true, "API/transport endpoint of the provider."),
					regField("repository_id", true, "Identity of the repository at the provider."),
					regField("branch_name", true, "Branch this scope tracks."),
					regField("include_globs", true, "Glob patterns that include blobs."),
					regField("exclude_globs", true, "Glob patterns that exclude blobs."),
					regField("text_media_types", true, "Media types indexed as text."),
					regField("max_blob_bytes", true, "Per-blob byte ceiling for ingestion."),
					regField("web_base_url", false, "Human web base URL for browsing the repository."),
					regField("credential_reference", false, "Opaque reference to a worker-mounted source credential; never a secret value."),
				},
				Capabilities: ConnectorCapabilities{AutonomousRecurringSync: false, GeneralDiscovery: false},
			},
		},
	}
}

// regField is a small constructor that keeps ConnectorCatalogData readable.
func regField(name string, required bool, description string) RegistrationField {
	return RegistrationField{Name: name, Required: required, Description: description}
}

// NewRegistrationError builds a typed registration error with a safe,
// content-free code and an optional cause retained only for trusted
// in-process diagnostics. It mirrors workspacerepository.NewError so callers
// and tests can construct the typed errors the source surface returns without
// opening their unexported code field.
func NewRegistrationError(code ErrorCode, cause error) *Error {
	return &Error{code: code, cause: cause}
}

// ConnectorCatalog is the authorization-gated read of the registry-owned
// connector catalog. Authorization is this package's own source-management gate
// (the same organization OWNER policy every source registration action uses),
// so the onboarding route never re-decides eligibility and never sees a
// configured source. The returned catalog is the same static, content-free
// value on every successful call.
func (s *Service) ConnectorCatalog(ctx context.Context, access database.AccessContext) (ConnectorCatalog, error) {
	if s == nil || s.database == nil || access.Validate() != nil {
		return ConnectorCatalog{}, &Error{code: CodeRequestInvalid}
	}
	denied := false
	readErr := s.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
		}
		return nil
	})
	if readErr != nil {
		return ConnectorCatalog{}, &Error{code: CodePersistence, cause: readErr}
	}
	if denied {
		return ConnectorCatalog{}, &Error{code: CodeDenied}
	}
	return ConnectorCatalogData(), nil
}
