package registration

import (
	"context"
	"sort"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// tableDiscoveredDefaultMaxRows is ADR-0097's default per-table row limit. A
// base/partitioned-table registration coming through discovery has no
// administrator-reviewed view standing between it and a possibly very large
// table, so it defaults far below the general POSTGRESQL_QUERY default
// (postgreSQLLimits' 1,000,000); an operator who needs more raises MaxRows
// explicitly through the general registration surface.
const tableDiscoveredDefaultMaxRows = 50_000

// RegisterDiscoveredView creates a DRAFT PostgreSQL scope from one prepared
// server-owned discovery projection. It accepts no browser-authored schema,
// relation, column, role, hash, SQL or connection metadata.
//
// excludedColumnOrdinals are ordinals from the same sealed discovery result
// (never a caller-chosen name or index) and are accepted only for a base or
// partitioned table: the five-column view contract has no excludable field.
// Each ordinal must name a real EVIDENCE column of that exact projection;
// naming a primary-key column, or any ordinal the discovery result never
// reported, is refused. Excluding narrows the projection and therefore mints
// a new ContractHash/LineageID (ADR-0097): a table registered with different
// exclusions is a distinct immutable lineage, not a mutation of an existing
// one.
func (s *Service) RegisterDiscoveredView(ctx context.Context, access database.AccessContext,
	selected discovery.SelectedView, excludedColumnOrdinals []int) (RegisterResult, error) {
	projection := selected.Projection
	if s == nil || s.database == nil || s.audit == nil || s.codec == nil || access.Validate() != nil ||
		selected.RequestID == "" || selected.ResultID == "" || selected.Selector == "" ||
		selected.ConnectionRevision < 1 || selected.ConnectionID != projection.ConnectionID ||
		projection.Validate() != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	if len(excludedColumnOrdinals) > 0 {
		if projection.RelationKind != "TABLE" && projection.RelationKind != "PARTITIONED_TABLE" {
			return RegisterResult{}, &Error{code: CodeRequestInvalid}
		}
		excludedSet, ok := excludedColumnOrdinalSet(excludedColumnOrdinals, len(projection.Columns))
		if !ok {
			return RegisterResult{}, &Error{code: CodeRequestInvalid}
		}
		narrowed, err := postgresqlquery.NarrowProjection(projection, excludedSet)
		if err != nil {
			return RegisterResult{}, &Error{code: CodeRequestInvalid, cause: err}
		}
		projection = narrowed
	}
	columnsJSON, err := postgresqlColumnsJSON(projection.Columns)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	discoveredID := postgresqlDiscoveredScopeID(access.OrganizationID, projection.ConnectionID,
		projection.DatabaseIdentity, projection.LineageID, projection.Revision)
	scopeID := scopeID(access.OrganizationID, discoveredID)
	identityBytes, err := canon.PostgreSQLQueryScopeIdentityBytes(projection.ConnectionID,
		projection.DatabaseIdentity, projection.LineageID, projection.Revision)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	displayBytes, err := canon.ScopeDisplayBytes(projection.RelationName, "business-objects")
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	limits := (RegisterRequest{}).postgreSQLLimits()
	if projection.RelationKind == "TABLE" || projection.RelationKind == "PARTITIONED_TABLE" {
		limits.maxRows = tableDiscoveredDefaultMaxRows
	}
	configBytes, err := canon.PostgreSQLQueryScopeConfigBytes(
		projection.DatabaseIdentity, projection.LineageID, projection.Revision,
		projection.SchemaName, projection.RelationName, projection.RelationKind,
		projection.ContractHash, string(columnsJSON), projection.EmptySnapshotPolicy,
		limits.maxRows, limits.maxColumns, limits.maxFieldBytes, limits.maxRowBytes,
		limits.maxTotalBytes, limits.statementTimeoutMS)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	identityDigest := canon.HMACDigest(s.digestKey, s.digestKeyVersion, identityBytes)
	result := RegisterResult{ConnectionID: projection.ConnectionID, SourceScopeID: scopeID,
		DiscoveredScopeID: discoveredID, Revision: 1, AccessMode: accessModeManaged}
	denied := false
	err = s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		var scopeResourceID string
		if err := tx.QueryRow(ctx, `SELECT app.registration_scope_resource_id($1,$2,1)`,
			access.OrganizationID, scopeID).Scan(&scopeResourceID); err != nil {
			return err
		}
		identityArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		displayArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		configArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		seal := func(field artifactcrypto.OwnerField, resourceID string, plaintext []byte) (artifactcrypto.Envelope, error) {
			owner, ownerErr := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, resourceID)
			if ownerErr != nil {
				return artifactcrypto.Envelope{}, ownerErr
			}
			return s.codec.Seal(owner, plaintext)
		}
		identityEnvelope, err := seal(artifactcrypto.SourceScopeIdentity, discoveredID, identityBytes)
		if err != nil {
			return err
		}
		displayEnvelope, err := seal(artifactcrypto.SourceScopeDisplayMetadata, discoveredID, displayBytes)
		if err != nil {
			return err
		}
		configEnvelope, err := seal(artifactcrypto.SourceScopeConfig, scopeResourceID, configBytes)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT connection_id, source_scope_id,
			discovered_scope_id, revision, created
			FROM app.source_discovery_view_registration_begin(
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
				$17,$18,$19,$20,$21,$22)`,
			selected.RequestID, selected.ResultID, selected.Selector,
			projection.ConnectionID, selected.ConnectionRevision, discoveredID,
			identityDigest, int64(s.digestKeyVersion), identityArtifactID,
			identityEnvelope.PlaintextHash(), displayArtifactID,
			displayEnvelope.PlaintextHash(), scopeID, configArtifactID,
			configEnvelope.PlaintextHash(), projection.ContractHash,
			syncIntervalSeconds, freshnessSLA, int64(objectLimit), int64(byteLimit),
			int64(scopeMaxObjectBytes), accessModeManaged).Scan(
			&result.ConnectionID, &result.SourceScopeID, &result.DiscoveredScopeID,
			&result.Revision, &result.Created); err != nil {
			return err
		}
		result.ScopeConfigHash = configEnvelope.PlaintextHash()
		if !result.Created {
			return nil
		}
		envelopeArgs := func(envelope artifactcrypto.Envelope) []any {
			return []any{envelope.Ciphertext(), envelope.SizeBytes(), envelope.Nonce(),
				envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(),
				envelope.KEKVersion(), envelope.AADHash(), envelope.PlaintextHash()}
		}
		bind := func(statement string, args ...any) error {
			_, bindErr := tx.Exec(ctx, statement, args...)
			return bindErr
		}
		if err := bind(`SELECT app.source_scope_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			append([]any{access.OrganizationID, scopeID, int64(1), configArtifactID, scopeResourceID},
				envelopeArgs(configEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_identity_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			append([]any{access.OrganizationID, discoveredID, identityArtifactID, discoveredID},
				envelopeArgs(identityEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_display_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			append([]any{access.OrganizationID, discoveredID, displayArtifactID, discoveredID},
				envelopeArgs(displayEnvelope)...)...); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_register(
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18)`,
			scopeID, int64(1), projection.ConnectionID, projection.DatabaseIdentity,
			projection.LineageID, projection.Revision, projection.ContractHash,
			projection.SchemaName, projection.RelationName, projection.RelationKind,
			string(columnsJSON), projection.EmptySnapshotPolicy, limits.maxRows,
			limits.maxColumns, limits.maxFieldBytes, limits.maxRowBytes,
			limits.maxTotalBytes, limits.statementTimeoutMS); err != nil {
			return err
		}
		catalogJSON, err := postgresqlCatalogJSON(projection, selected.CatalogColumns)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_relation_catalog_record($1,$2,$3,$4,$5,$6::jsonb)`,
			scopeID, int64(1), projection.ConnectionID, truncateCatalogComment(selected.RelationComment),
			selected.ApproxRowCount, string(catalogJSON)); err != nil {
			return err
		}
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceRegistrationCreated, ResourceType: audit.ResourceSourceScope,
			ResourceID: scopeID, RequestID: access.RequestID, Outcome: audit.OutcomeSuccess,
			OccurredAt: s.now().UTC(), Metadata: audit.Metadata{
				SourceConnectionID: &projection.ConnectionID, SourceScopeID: &scopeID,
				SourceScopeRevision: &result.Revision,
			},
		})
		return err
	})
	if err != nil {
		switch database.SQLStateCode(err) {
		case "42501":
			return RegisterResult{}, &Error{code: CodeDenied, cause: err}
		case "23505":
			return RegisterResult{}, &Error{code: CodeConflict, cause: err}
		case "55000":
			return RegisterResult{}, &Error{code: CodeUnavailable, cause: err}
		default:
			return RegisterResult{}, &Error{code: CodePersistence, cause: err}
		}
	}
	if denied {
		return RegisterResult{}, &Error{code: CodeDenied}
	}
	return result, nil
}

// postgresqlCatalogJSON builds the bounded, display-only catalog column array
// migration 000114 persists next to the projection: exactly the projected
// columns, in projection order, each carrying the discovery-time native type
// name, comment and primary-key membership when the sealed discovery result
// reported that column and the projection's own logical type as the fallback
// label otherwise. Because it is built from projection.Columns -- already
// narrowed by any registration-time exclusion -- an excluded column can never
// be named here, which the recording command re-checks in the database.
type catalogColumnJSON struct {
	Name       string `json:"name"`
	TypeName   string `json:"type_name"`
	Comment    string `json:"comment"`
	PrimaryKey bool   `json:"primary_key"`
}

// maxCatalogCommentBytes mirrors migration 000114's per-comment bound on
// postgresql_query_relation_catalog. Discovery's own comment bound is the
// request profile's MaxCommentBytes, which may be larger; a longer catalog
// comment is truncated on a UTF-8 boundary rather than allowed to fail the
// whole registration, because a comment is display metadata only.
const maxCatalogCommentBytes = 4096

func truncateCatalogComment(value string) string {
	if len(value) <= maxCatalogCommentBytes {
		return value
	}
	truncated := value[:maxCatalogCommentBytes]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

func postgresqlCatalogJSON(projection postgresqlquery.Projection, discovered []discovery.Column) ([]byte, error) {
	byName := make(map[string]discovery.Column, len(discovered))
	for _, column := range discovered {
		byName[column.Name] = column
	}
	columns := append([]postgresqlquery.Column(nil), projection.Columns...)
	sort.Slice(columns, func(i, j int) bool { return columns[i].Ordinal < columns[j].Ordinal })
	items := make([]catalogColumnJSON, 0, len(columns))
	for _, column := range columns {
		item := catalogColumnJSON{Name: column.Name, TypeName: string(column.LogicalType)}
		for _, role := range column.Roles {
			if role == postgresqlquery.RoleIdentity {
				item.PrimaryKey = true
				break
			}
		}
		if found, ok := byName[column.Name]; ok {
			if found.TypeName != "" {
				item.TypeName = found.TypeName
			}
			item.Comment = truncateCatalogComment(found.Comment)
			if found.PrimaryKey {
				item.PrimaryKey = true
			}
		}
		items = append(items, item)
	}
	return canon.CanonicalJSON(items)
}

// excludedColumnOrdinalSet bounds-checks the browser-chosen exclusion
// ordinals against the sealed discovery projection's own column count before
// they ever reach postgresqlquery.NarrowProjection. Every entry must be a
// distinct, in-range positive ordinal, and at least one column must survive;
// ADR-0097 permits only narrowing an already-discovered table, never naming a
// column the server never reported.
func excludedColumnOrdinalSet(ordinals []int, columnCount int) (map[int]bool, bool) {
	if len(ordinals) == 0 || len(ordinals) >= columnCount {
		return nil, false
	}
	set := make(map[int]bool, len(ordinals))
	for _, ordinal := range ordinals {
		if ordinal < 1 || ordinal > columnCount || set[ordinal] {
			return nil, false
		}
		set[ordinal] = true
	}
	return set, true
}
