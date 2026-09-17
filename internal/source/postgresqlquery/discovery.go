package postgresqlquery

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// DiscoveryStatus describes whether a visible PostgreSQL view has the
// explicit source-neutral business-object envelope. A view that is visible
// but not prepared is returned as metadata with NeedsInterpretation; it is
// never assigned identity, date, status or title semantics by this package.
type DiscoveryStatus string

const (
	DiscoveryPrepared            DiscoveryStatus = "PREPARED"
	DiscoveryNeedsInterpretation DiscoveryStatus = "NEEDS_INTERPRETATION"
)

// These names are the JSON field names of observation.BusinessObjectContract.
// They stay local to this package to avoid an import cycle; no business or
// source-specific names are accepted as preparation evidence.
const (
	preparedEntityIDColumn      = "entity_id"
	preparedEntityVersionColumn = "entity_version"
	preparedUpdatedAtColumn     = "last_updated_at"
	preparedPayloadColumn       = "payload"
	preparedPayloadFormatColumn = "payload_format"
)

// InterpretationReason is a bounded reason for a visible view that cannot
// yet receive a server-owned Projection. It intentionally has no free-form
// database text, query text or row content.
type InterpretationReason string

const (
	InterpretationUnrecognizedFormat InterpretationReason = "UNRECOGNIZED_FORMAT"
	InterpretationIncompleteContract InterpretationReason = "INCOMPLETE_BUSINESS_OBJECT_CONTRACT"
	InterpretationMalformedContract  InterpretationReason = "MALFORMED_BUSINESS_OBJECT_CONTRACT"
	InterpretationUnsupportedType    InterpretationReason = "UNSUPPORTED_TYPE"
	InterpretationInvalidIdentifier  InterpretationReason = "INVALID_IDENTIFIER"
)

// DiscoveryLimits are server-owned bounds for PostgreSQL catalog discovery.
// They cap only metadata acquisition; no application rows are selected.
type DiscoveryLimits struct {
	MaxViews           int
	MaxColumns         int
	MaxCommentBytes    int
	StatementTimeout   time.Duration
	TransactionTimeout time.Duration
}

// Validate checks the bounded catalog-discovery limits before any external
// connection is opened.
func (limits DiscoveryLimits) Validate() error {
	if limits.MaxViews < 1 || limits.MaxViews > 1024 ||
		limits.MaxColumns < 1 || limits.MaxColumns > 256 ||
		limits.MaxCommentBytes < 1 || limits.MaxCommentBytes > 64<<10 ||
		limits.StatementTimeout < time.Second || limits.StatementTimeout > 24*time.Hour ||
		limits.TransactionTimeout < limits.StatementTimeout || limits.TransactionTimeout > 24*time.Hour {
		return &Error{code: CodeDiscoveryInvalid}
	}
	return nil
}

// ValidateDurable checks the narrower bounds persisted by the source
// discovery request. The durable command and this connector must reject the
// same profile before a worker opens an external connection.
func (limits DiscoveryLimits) ValidateDurable() error {
	if limits.Validate() != nil || limits.MaxViews > 64 ||
		limits.StatementTimeout > 5*time.Minute || limits.TransactionTimeout > 10*time.Minute {
		return &Error{code: CodeDiscoveryInvalid}
	}
	return nil
}

// DefaultDiscoveryLimits returns the fixed bounded profile used by the source
// owner when a server has not selected a narrower profile.
func DefaultDiscoveryLimits() DiscoveryLimits {
	return DiscoveryLimits{
		MaxViews: 64, MaxColumns: 256, MaxCommentBytes: 4096,
		StatementTimeout: 2 * time.Minute, TransactionTimeout: 5 * time.Minute,
	}
}

// DiscoveryRequest identifies a protected source connection and, for a
// selected-view request, one catalog relation. It carries an opaque
// credential reference, never a DSN or credential bytes.
type DiscoveryRequest struct {
	ConnectionID        string
	CredentialReference string
	SchemaName          string
	RelationName        string
	Limits              DiscoveryLimits
}

// DiscoveredColumn is server-returned PostgreSQL catalog metadata. OIDs,
// ordinals, nullability, type fingerprints, precision and scale come from the
// external server; comments are native pg_description values bounded by the
// request profile.
type DiscoveredColumn struct {
	Ordinal         int         `json:"ordinal"`
	Name            string      `json:"name"`
	TypeOID         uint32      `json:"type_oid"`
	TypeName        string      `json:"type_name"`
	TypeFingerprint string      `json:"type_fingerprint"`
	LogicalType     LogicalType `json:"logical_type"`
	Nullable        bool        `json:"nullable"`
	Precision       int         `json:"precision,omitempty"`
	Scale           int         `json:"scale,omitempty"`
	MaxBytes        int         `json:"max_bytes,omitempty"`
	Comment         string      `json:"comment,omitempty"`
}

// ViewDiscovery is one visible VIEW or MATERIALIZED_VIEW and its bounded
// catalog metadata. Projection is present only for the exact prepared
// BusinessObjectContract envelope; no source rows or view definition are
// returned.
type ViewDiscovery struct {
	ConnectionID   string               `json:"connection_id"`
	DatabaseOID    uint32               `json:"database_oid"`
	DatabaseName   string               `json:"database_name"`
	RelationOID    uint32               `json:"relation_oid"`
	SchemaName     string               `json:"schema_name"`
	RelationName   string               `json:"relation_name"`
	RelationKind   string               `json:"relation_kind"`
	Comment        string               `json:"comment,omitempty"`
	Columns        []DiscoveredColumn   `json:"columns"`
	Status         DiscoveryStatus      `json:"status"`
	Interpretation InterpretationReason `json:"interpretation,omitempty"`
	Projection     *Projection          `json:"projection,omitempty"`
}

// CatalogSnapshot is one bounded, read-only catalog observation. Database
// identity is retained even when the source has no visible views, so the
// caller can bind an empty discovery result to the server it actually probed.
// PrivilegeDigest summarizes the effective catalog visibility of this
// observation; it contains no ACL text, row values or executable SQL.
type CatalogSnapshot struct {
	DatabaseOID     uint32
	DatabaseName    string
	Views           []ViewDiscovery
	PrivilegeDigest string
}

// DiscoverViews lists visible user-schema views and materialized views through
// the same resolver, TLS and trust-root path as ReadProjection. The method is
// read-only and catalog-only; it never executes a view or retains row data.
func (connector *LiveConnector) DiscoverViews(ctx context.Context, request DiscoveryRequest) ([]ViewDiscovery, error) {
	snapshot, err := connector.DiscoverCatalog(ctx, request)
	if err != nil {
		return nil, err
	}
	return snapshot.Views, nil
}

// DiscoverCatalog opens one trusted source connection and returns a bounded
// catalog snapshot. The transaction is catalog-only and read-only; the
// credential reference is resolved by the connector and never appears in the
// snapshot or its digest.
func (connector *LiveConnector) DiscoverCatalog(ctx context.Context, request DiscoveryRequest) (CatalogSnapshot, error) {
	if err := request.validate(false); err != nil {
		return CatalogSnapshot{}, err
	}
	connection, err := connector.openConnection(ctx, request.CredentialReference, discoveryApplicationName)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	defer closeDiscoveryConnection(connection)
	return discoverCatalogSnapshot(ctx, connection, request.ConnectionID, "", "", request.Limits)
}

// DiscoverView inspects one visible user-schema view or materialized view
// through the source owner's trusted connection path. A non-prepared view is
// a successful metadata result with Status=NEEDS_INTERPRETATION; a hidden or
// absent view returns one content-free discovery-unavailable error.
func (connector *LiveConnector) DiscoverView(ctx context.Context, request DiscoveryRequest) (ViewDiscovery, error) {
	if err := request.validate(true); err != nil {
		return ViewDiscovery{}, err
	}
	connection, err := connector.openConnection(ctx, request.CredentialReference, discoveryApplicationName)
	if err != nil {
		return ViewDiscovery{}, err
	}
	defer closeDiscoveryConnection(connection)
	return discoverViewForConnection(ctx, connection, request.ConnectionID, request.SchemaName, request.RelationName, request.Limits)
}

func (request DiscoveryRequest) validate(selected bool) error {
	if !validOpaque(request.ConnectionID) || request.CredentialReference == "" || len(request.CredentialReference) > 128 || !utf8.ValidString(request.CredentialReference) || request.Limits.Validate() != nil {
		return &Error{code: CodeDiscoveryInvalid}
	}
	if selected {
		if !identifierPattern.MatchString(request.SchemaName) || !identifierPattern.MatchString(request.RelationName) || !discoverySchemaAllowed(request.SchemaName) {
			return &Error{code: CodeDiscoveryInvalid}
		}
		return nil
	}
	if request.SchemaName != "" || request.RelationName != "" {
		return &Error{code: CodeDiscoveryInvalid}
	}
	return nil
}

func discoverViews(ctx context.Context, connection *pgx.Conn, limits DiscoveryLimits) ([]ViewDiscovery, error) {
	return discoverViewsForConnection(ctx, connection, "discovery", limits)
}

func discoverView(ctx context.Context, connection *pgx.Conn, schemaName, relationName string, limits DiscoveryLimits) (ViewDiscovery, error) {
	return discoverViewForConnection(ctx, connection, "discovery", schemaName, relationName, limits)
}

func discoverViewsForConnection(ctx context.Context, connection *pgx.Conn, connectionID string, limits DiscoveryLimits) ([]ViewDiscovery, error) {
	return discoverCatalog(ctx, connection, connectionID, "", "", limits)
}

func discoverViewForConnection(ctx context.Context, connection *pgx.Conn, connectionID, schemaName, relationName string, limits DiscoveryLimits) (ViewDiscovery, error) {
	views, err := discoverCatalog(ctx, connection, connectionID, schemaName, relationName, limits)
	if err != nil {
		return ViewDiscovery{}, err
	}
	if len(views) != 1 {
		return ViewDiscovery{}, &Error{code: CodeDiscoveryUnavailable}
	}
	return views[0], nil
}

func discoverCatalog(ctx context.Context, connection *pgx.Conn, connectionID, schemaName, relationName string, limits DiscoveryLimits) ([]ViewDiscovery, error) {
	snapshot, err := discoverCatalogSnapshot(ctx, connection, connectionID, schemaName, relationName, limits)
	if err != nil {
		return nil, err
	}
	return snapshot.Views, nil
}

func discoverCatalogSnapshot(ctx context.Context, connection *pgx.Conn, connectionID, schemaName, relationName string, limits DiscoveryLimits) (CatalogSnapshot, error) {
	if ctx == nil || connection == nil || limits.Validate() != nil {
		return CatalogSnapshot{}, &Error{code: CodeDiscoveryInvalid}
	}
	if relationName != "" && (!identifierPattern.MatchString(schemaName) || !identifierPattern.MatchString(relationName) || !discoverySchemaAllowed(schemaName)) {
		return CatalogSnapshot{}, &Error{code: CodeDiscoveryInvalid}
	}
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly, DeferrableMode: pgx.Deferrable,
	})
	if err != nil {
		return CatalogSnapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	defer rollbackDiscoveryTransaction(tx)
	if err := prepareDiscoveryTransaction(ctx, tx, limits); err != nil {
		return CatalogSnapshot{}, err
	}
	databaseOID, databaseName, err := discoveryDatabase(ctx, tx)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	relations, err := discoveryRelations(ctx, tx, schemaName, relationName, limits)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	if relationName != "" && len(relations) == 0 {
		return CatalogSnapshot{}, &Error{code: CodeDiscoveryUnavailable}
	}
	views := make([]ViewDiscovery, 0, len(relations))
	for _, relation := range relations {
		columns, err := discoveryColumns(ctx, tx, relation.relationOID, limits)
		if err != nil {
			return CatalogSnapshot{}, err
		}
		view, err := newViewDiscovery(connectionID, databaseOID, databaseName, relation, columns)
		if err != nil {
			return CatalogSnapshot{}, err
		}
		views = append(views, view)
	}
	privilegeDigest, err := catalogPrivilegeDigest(databaseOID, databaseName, views)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CatalogSnapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	return CatalogSnapshot{DatabaseOID: databaseOID, DatabaseName: databaseName, Views: views, PrivilegeDigest: privilegeDigest}, nil
}

type privilegeDigestRelation struct {
	RelationOID  uint32                  `json:"relation_oid"`
	SchemaName   string                  `json:"schema_name"`
	RelationName string                  `json:"relation_name"`
	RelationKind string                  `json:"relation_kind"`
	Columns      []privilegeDigestColumn `json:"columns"`
}

type privilegeDigestColumn struct {
	Ordinal int    `json:"ordinal"`
	Name    string `json:"name"`
	TypeOID uint32 `json:"type_oid"`
}

// catalogPrivilegeDigest hashes only the bounded set of catalog objects and
// columns visible to the source role. The role's effective visibility is the
// result of PostgreSQL's has_schema/table/column_privilege predicates in the
// catalog query; hashing that projection lets the worker detect privilege
// changes without retaining an ACL graph or role name.
func catalogPrivilegeDigest(databaseOID uint32, databaseName string, views []ViewDiscovery) (string, error) {
	entries := make([]privilegeDigestRelation, 0, len(views))
	for _, view := range views {
		columns := make([]privilegeDigestColumn, 0, len(view.Columns))
		for _, column := range view.Columns {
			columns = append(columns, privilegeDigestColumn{Ordinal: column.Ordinal, Name: column.Name, TypeOID: column.TypeOID})
		}
		entries = append(entries, privilegeDigestRelation{
			RelationOID: view.RelationOID, SchemaName: view.SchemaName, RelationName: view.RelationName,
			RelationKind: view.RelationKind, Columns: columns,
		})
	}
	raw, err := canon.CanonicalJSON(struct {
		DatabaseOID  uint32                    `json:"database_oid"`
		DatabaseName string                    `json:"database_name"`
		Relations    []privilegeDigestRelation `json:"relations"`
	}{DatabaseOID: databaseOID, DatabaseName: databaseName, Relations: entries})
	if err != nil {
		return "", &Error{code: CodeDiscoveryInvalid, cause: err}
	}
	return canon.Hash(raw), nil
}

func prepareDiscoveryTransaction(ctx context.Context, tx pgx.Tx, limits DiscoveryLimits) error {
	if tx == nil {
		return &Error{code: CodeExternalFailure}
	}
	for _, setting := range []string{
		"SET LOCAL search_path = pg_catalog",
		"SET LOCAL row_security = on",
		"SET LOCAL max_parallel_workers_per_gather = 0",
		"SET LOCAL jit = off",
		"SET LOCAL work_mem = '16MB'",
	} {
		if _, err := tx.Exec(ctx, setting); err != nil {
			return &Error{code: CodeExternalFailure, cause: err}
		}
	}
	if err := enforceTempFileLimit(ctx, tx); err != nil {
		return &Error{code: CodeExternalFailure, cause: err}
	}
	for name, duration := range map[string]time.Duration{
		"statement_timeout":                   limits.StatementTimeout,
		"idle_in_transaction_session_timeout": limits.TransactionTimeout,
		"lock_timeout":                        limits.StatementTimeout,
		"transaction_timeout":                 limits.TransactionTimeout,
	} {
		if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", name, strconv.FormatInt(duration.Milliseconds(), 10)+"ms"); err != nil {
			return &Error{code: CodeExternalFailure, cause: err}
		}
	}
	var readOnly string
	if err := tx.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		return &Error{code: CodeExternalFailure, cause: err}
	}
	return nil
}

func discoveryDatabase(ctx context.Context, tx pgx.Tx) (uint32, string, error) {
	const statement = `
		SELECT d.oid::bigint, d.datname
		FROM pg_catalog.pg_database AS d
		WHERE d.datname = current_database()`
	var rawOID int64
	var databaseName string
	if err := tx.QueryRow(ctx, statement).Scan(&rawOID, &databaseName); err != nil {
		return 0, "", &Error{code: CodeExternalFailure, cause: err}
	}
	databaseOID, ok := boundedOID(rawOID)
	if !ok || !validCatalogText(databaseName, 128) {
		return 0, "", &Error{code: CodeDiscoveryInvalid}
	}
	return databaseOID, databaseName, nil
}

type catalogRelation struct {
	relationOID  uint32
	schemaName   string
	relationName string
	relationKind string
	comment      string
}

// PostgreSQL's obj_description catalog_name argument is the unqualified
// catalog identifier "pg_class"; the function itself is catalog-qualified.
const discoverRelationsSQL = `
WITH candidates AS (
	SELECT c.oid::bigint AS relation_oid, n.nspname AS schema_name, c.relname AS relation_name,
		CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED_VIEW' END AS relation_kind,
		pg_catalog.obj_description(c.oid, 'pg_class') AS relation_comment
	FROM pg_catalog.pg_class AS c
	JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
	WHERE c.relkind IN ('v', 'm')
		AND n.nspname <> 'pg_catalog'
		AND n.nspname <> 'information_schema'
		AND pg_catalog.left(n.nspname, 3) <> 'pg_'
		AND pg_catalog.has_schema_privilege(current_user, n.oid, 'USAGE')
		AND pg_catalog.has_table_privilege(current_user, c.oid, 'SELECT')
		AND NOT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_attribute AS restricted_attribute
			WHERE restricted_attribute.attrelid = c.oid
				AND restricted_attribute.attnum > 0
				AND NOT restricted_attribute.attisdropped
				AND NOT pg_catalog.has_column_privilege(current_user, restricted_attribute.attrelid, restricted_attribute.attnum, 'SELECT')
		)
)
SELECT relation_oid, schema_name, relation_name, relation_kind,
	COALESCE(pg_catalog.octet_length(relation_comment), 0)::bigint AS comment_bytes,
	CASE WHEN relation_comment IS NULL OR pg_catalog.octet_length(relation_comment) > $1
		THEN '' ELSE relation_comment END AS relation_comment
FROM candidates
ORDER BY schema_name, relation_name
LIMIT $2`

const discoverSelectedRelationSQL = `
WITH candidates AS (
	SELECT c.oid::bigint AS relation_oid, n.nspname AS schema_name, c.relname AS relation_name,
		CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED_VIEW' END AS relation_kind,
		pg_catalog.obj_description(c.oid, 'pg_class') AS relation_comment
	FROM pg_catalog.pg_class AS c
	JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
	WHERE c.relkind IN ('v', 'm')
		AND n.nspname = $2
		AND c.relname = $3
		AND pg_catalog.has_schema_privilege(current_user, n.oid, 'USAGE')
		AND pg_catalog.has_table_privilege(current_user, c.oid, 'SELECT')
		AND NOT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_attribute AS restricted_attribute
			WHERE restricted_attribute.attrelid = c.oid
				AND restricted_attribute.attnum > 0
				AND NOT restricted_attribute.attisdropped
				AND NOT pg_catalog.has_column_privilege(current_user, restricted_attribute.attrelid, restricted_attribute.attnum, 'SELECT')
		)
)
SELECT relation_oid, schema_name, relation_name, relation_kind,
	COALESCE(pg_catalog.octet_length(relation_comment), 0)::bigint AS comment_bytes,
	CASE WHEN relation_comment IS NULL OR pg_catalog.octet_length(relation_comment) > $1
		THEN '' ELSE relation_comment END AS relation_comment
FROM candidates`

func discoveryRelations(ctx context.Context, tx pgx.Tx, schemaName, relationName string, limits DiscoveryLimits) ([]catalogRelation, error) {
	statement := discoverRelationsSQL
	args := []any{limits.MaxCommentBytes, limits.MaxViews + 1}
	if relationName != "" {
		statement = discoverSelectedRelationSQL
		args = []any{limits.MaxCommentBytes, schemaName, relationName}
	}
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, &Error{code: CodeExternalFailure, cause: err}
	}
	defer rows.Close()
	relations := make([]catalogRelation, 0, limits.MaxViews)
	for rows.Next() {
		var rawOID, commentBytes int64
		var relation catalogRelation
		if err := rows.Scan(&rawOID, &relation.schemaName, &relation.relationName, &relation.relationKind, &commentBytes, &relation.comment); err != nil {
			return nil, &Error{code: CodeExternalFailure, cause: err}
		}
		if commentBytes < 0 || commentBytes > int64(limits.MaxCommentBytes) {
			return nil, &Error{code: CodeLimitExceeded}
		}
		relation.relationOID, _ = boundedOID(rawOID)
		if relation.relationOID == 0 || relation.relationKind == "" || !validCatalogText(relation.schemaName, 128) || !validCatalogText(relation.relationName, 128) || !validCatalogComment(relation.comment, limits.MaxCommentBytes) {
			return nil, &Error{code: CodeDiscoveryInvalid}
		}
		relations = append(relations, relation)
		if len(relations) > limits.MaxViews {
			return nil, &Error{code: CodeLimitExceeded}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{code: CodeExternalFailure, cause: err}
	}
	return relations, nil
}

type catalogColumn struct {
	ordinal  int
	name     string
	typeOID  uint32
	typeName string
	typmod   int64
	nullable bool
	comment  string
}

const discoverColumnsSQL = `
WITH candidates AS (
	SELECT a.attnum::int AS ordinal, a.attname, a.atttypid::bigint AS type_oid,
		t.typname, a.atttypmod::bigint AS typmod, NOT a.attnotnull AS nullable,
		pg_catalog.col_description(a.attrelid, a.attnum) AS column_comment
	FROM pg_catalog.pg_attribute AS a
	JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid
	WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped
	ORDER BY a.attnum
	LIMIT $3
)
SELECT ordinal, attname, type_oid, typname, typmod, nullable,
	COALESCE(pg_catalog.octet_length(column_comment), 0)::bigint AS comment_bytes,
	CASE WHEN column_comment IS NULL OR pg_catalog.octet_length(column_comment) > $2
		THEN '' ELSE column_comment END AS column_comment
FROM candidates
ORDER BY ordinal`

func discoveryColumns(ctx context.Context, tx pgx.Tx, relationOID uint32, limits DiscoveryLimits) ([]catalogColumn, error) {
	rows, err := tx.Query(ctx, discoverColumnsSQL, relationOID, limits.MaxCommentBytes, limits.MaxColumns+1)
	if err != nil {
		return nil, &Error{code: CodeExternalFailure, cause: err}
	}
	defer rows.Close()
	columns := make([]catalogColumn, 0, limits.MaxColumns)
	for rows.Next() {
		var rawTypeOID, commentBytes int64
		var column catalogColumn
		if err := rows.Scan(&column.ordinal, &column.name, &rawTypeOID, &column.typeName, &column.typmod, &column.nullable, &commentBytes, &column.comment); err != nil {
			return nil, &Error{code: CodeExternalFailure, cause: err}
		}
		if commentBytes < 0 || commentBytes > int64(limits.MaxCommentBytes) {
			return nil, &Error{code: CodeLimitExceeded}
		}
		column.typeOID, _ = boundedOID(rawTypeOID)
		if column.ordinal < 1 || column.typeOID == 0 || !validCatalogText(column.name, 128) || !validCatalogText(column.typeName, 128) || !validCatalogComment(column.comment, limits.MaxCommentBytes) {
			return nil, &Error{code: CodeDiscoveryInvalid}
		}
		columns = append(columns, column)
		if len(columns) > limits.MaxColumns {
			return nil, &Error{code: CodeLimitExceeded}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, &Error{code: CodeExternalFailure, cause: err}
	}
	if len(columns) == 0 {
		return nil, &Error{code: CodeDiscoveryInvalid}
	}
	return columns, nil
}

func newViewDiscovery(connectionID string, databaseOID uint32, databaseName string, relation catalogRelation, columns []catalogColumn) (ViewDiscovery, error) {
	view := ViewDiscovery{
		ConnectionID: connectionID, DatabaseOID: databaseOID, DatabaseName: databaseName, RelationOID: relation.relationOID,
		SchemaName: relation.schemaName, RelationName: relation.relationName,
		RelationKind: relation.relationKind, Comment: relation.comment,
		Columns: make([]DiscoveredColumn, 0, len(columns)), Status: DiscoveryNeedsInterpretation,
	}
	for _, column := range columns {
		discovered, err := newDiscoveredColumn(column)
		if err != nil {
			return ViewDiscovery{}, err
		}
		view.Columns = append(view.Columns, discovered)
	}
	status, reason, projection := classifyDiscoveredView(view)
	view.Status, view.Interpretation, view.Projection = status, reason, projection
	return view, nil
}

func newDiscoveredColumn(column catalogColumn) (DiscoveredColumn, error) {
	if column.ordinal < 1 || column.typeOID == 0 || !validCatalogText(column.name, 128) || !validCatalogComment(column.comment, 64<<10) {
		return DiscoveredColumn{}, &Error{code: CodeDiscoveryInvalid}
	}
	logicalType, precision, scale, maxBytes, typeFingerprint := catalogType(column.typeOID, column.typmod)
	return DiscoveredColumn{
		Ordinal: column.ordinal, Name: column.name, TypeOID: column.typeOID,
		TypeName: column.typeName, TypeFingerprint: typeFingerprint,
		LogicalType: logicalType, Nullable: column.nullable, Precision: precision,
		Scale: scale, MaxBytes: maxBytes, Comment: column.comment,
	}, nil
}

func classifyDiscoveredView(view ViewDiscovery) (DiscoveryStatus, InterpretationReason, *Projection) {
	for _, column := range view.Columns {
		if !identifierPattern.MatchString(column.Name) {
			return DiscoveryNeedsInterpretation, InterpretationInvalidIdentifier, nil
		}
	}
	fieldNames := map[string]struct{}{
		preparedEntityIDColumn: {}, preparedEntityVersionColumn: {}, preparedUpdatedAtColumn: {}, preparedPayloadColumn: {}, preparedPayloadFormatColumn: {},
	}
	seen := 0
	for _, column := range view.Columns {
		if _, required := fieldNames[column.Name]; required {
			seen++
		}
	}
	if seen == 0 {
		return DiscoveryNeedsInterpretation, InterpretationUnrecognizedFormat, nil
	}
	if seen != len(fieldNames) {
		return DiscoveryNeedsInterpretation, InterpretationIncompleteContract, nil
	}
	byName := make(map[string]DiscoveredColumn, len(view.Columns))
	for _, column := range view.Columns {
		byName[column.Name] = column
	}
	if !preparedColumnTypes(byName) {
		return DiscoveryNeedsInterpretation, InterpretationMalformedContract, nil
	}
	for _, column := range view.Columns {
		if column.LogicalType == "" || (column.LogicalType == TypeNumeric && (column.Precision < 1 || column.Scale < 0 || column.Scale > column.Precision)) || column.MaxBytes < 1 {
			return DiscoveryNeedsInterpretation, InterpretationUnsupportedType, nil
		}
	}
	projection, err := buildDiscoveredProjection(view)
	if err != nil {
		if CodeOf(err) == CodeDiscoveryInvalid {
			return DiscoveryNeedsInterpretation, InterpretationInvalidIdentifier, nil
		}
		return DiscoveryNeedsInterpretation, InterpretationUnsupportedType, nil
	}
	return DiscoveryPrepared, "", &projection
}

func preparedColumnTypes(columns map[string]DiscoveredColumn) bool {
	entityID := columns[preparedEntityIDColumn]
	entityVersion := columns[preparedEntityVersionColumn]
	lastUpdated := columns[preparedUpdatedAtColumn]
	payload := columns[preparedPayloadColumn]
	payloadFormat := columns[preparedPayloadFormatColumn]
	return (entityID.LogicalType == TypeUUID || entityID.LogicalType == TypeInt || entityID.LogicalType == TypeText) &&
		entityVersion.LogicalType == TypeText &&
		(lastUpdated.LogicalType == TypeDate || lastUpdated.LogicalType == TypeTimestamp || lastUpdated.LogicalType == TypeTimestamptz) &&
		(payload.LogicalType == TypeJSON || payload.LogicalType == TypeJSONB || payload.LogicalType == TypeText) &&
		payloadFormat.LogicalType == TypeText
}

func buildDiscoveredProjection(view ViewDiscovery) (Projection, error) {
	if !validCatalogText(view.DatabaseName, 128) || !discoverySchemaAllowed(view.SchemaName) || !identifierPattern.MatchString(view.SchemaName) || !identifierPattern.MatchString(view.RelationName) {
		return Projection{}, &Error{code: CodeDiscoveryInvalid}
	}
	databaseBytes, err := canon.CanonicalJSON(struct {
		OID  uint32 `json:"oid"`
		Name string `json:"name"`
	}{OID: view.DatabaseOID, Name: view.DatabaseName})
	if err != nil {
		return Projection{}, &Error{code: CodeDiscoveryInvalid, cause: err}
	}
	databaseIdentity := "pgdb:" + strings.TrimPrefix(canon.Hash(databaseBytes), "sha256:")
	columns := make([]Column, 0, len(view.Columns))
	for _, discovered := range view.Columns {
		if discovered.Ordinal < 1 || !identifierPattern.MatchString(discovered.Name) || !validOpaque(discovered.TypeFingerprint) || discovered.LogicalType == "" || discovered.MaxBytes < 1 {
			return Projection{}, &Error{code: CodeDiscoveryInvalid}
		}
		roles := []Role{RoleEvidence}
		nullable := discovered.Nullable
		switch discovered.Name {
		case preparedEntityIDColumn:
			roles = []Role{RoleIdentity}
			nullable = false
		case preparedEntityVersionColumn:
			roles = []Role{RoleVersionHint}
			nullable = false
		case preparedUpdatedAtColumn:
			roles = []Role{RoleVersionHint, RoleEvidence}
			nullable = false
		case preparedPayloadColumn, preparedPayloadFormatColumn:
			nullable = false
		}
		columns = append(columns, Column{
			Ordinal: discovered.Ordinal, Name: discovered.Name, TypeFingerprint: discovered.TypeFingerprint,
			LogicalType: discovered.LogicalType, Roles: roles, Nullable: nullable,
			Precision: discovered.Precision, Scale: discovered.Scale, MaxBytes: discovered.MaxBytes,
		})
	}
	hashBytes, err := canon.CanonicalJSON(struct {
		ValueFormat  string                 `json:"value_format"`
		DatabaseOID  uint32                 `json:"database_oid"`
		DatabaseName string                 `json:"database_name"`
		RelationOID  uint32                 `json:"relation_oid"`
		SchemaName   string                 `json:"schema_name"`
		RelationName string                 `json:"relation_name"`
		RelationKind string                 `json:"relation_kind"`
		ViewComment  string                 `json:"view_comment"`
		Columns      []projectionHashColumn `json:"columns"`
	}{
		ValueFormat: ValueContractVersion, DatabaseOID: view.DatabaseOID, DatabaseName: view.DatabaseName,
		RelationOID: view.RelationOID, SchemaName: view.SchemaName, RelationName: view.RelationName,
		RelationKind: view.RelationKind, ViewComment: view.Comment, Columns: projectionHashColumns(view, columns),
	})
	if err != nil {
		return Projection{}, &Error{code: CodeDiscoveryInvalid, cause: err}
	}
	contractHash := canon.Hash(hashBytes)
	lineageBytes, err := canon.CanonicalJSON(struct {
		ConnectionID string `json:"connection_id"`
		DatabaseID   string `json:"database_id"`
		RelationOID  uint32 `json:"relation_oid"`
		ContractHash string `json:"contract_hash"`
	}{ConnectionID: view.ConnectionID, DatabaseID: databaseIdentity, RelationOID: view.RelationOID, ContractHash: contractHash})
	if err != nil {
		return Projection{}, &Error{code: CodeDiscoveryInvalid, cause: err}
	}
	lineageID := "projection-lineage:" + strings.TrimPrefix(canon.Hash(lineageBytes), "sha256:")
	projection := Projection{
		ConnectionID: view.ConnectionID, DatabaseIdentity: databaseIdentity, LineageID: lineageID,
		Revision: 1, ContractHash: contractHash, SchemaName: view.SchemaName,
		RelationName: view.RelationName, RelationKind: view.RelationKind, Columns: columns,
		EmptySnapshotPolicy: "HELD",
	}
	if err := projection.Validate(); err != nil {
		return Projection{}, &Error{code: CodeDiscoveryInvalid, cause: err}
	}
	return projection, nil
}

type projectionHashColumn struct {
	Ordinal         int         `json:"ordinal"`
	Name            string      `json:"name"`
	TypeOID         uint32      `json:"type_oid"`
	TypeFingerprint string      `json:"type_fingerprint"`
	LogicalType     LogicalType `json:"logical_type"`
	Roles           []Role      `json:"roles"`
	Nullable        bool        `json:"nullable"`
	Precision       int         `json:"precision"`
	Scale           int         `json:"scale"`
	MaxBytes        int         `json:"max_bytes"`
	Comment         string      `json:"comment"`
}

func projectionHashColumns(view ViewDiscovery, columns []Column) []projectionHashColumn {
	byOrdinal := make(map[int]DiscoveredColumn, len(view.Columns))
	for _, discovered := range view.Columns {
		byOrdinal[discovered.Ordinal] = discovered
	}
	result := make([]projectionHashColumn, 0, len(columns))
	for _, column := range columns {
		discovered := byOrdinal[column.Ordinal]
		result = append(result, projectionHashColumn{
			Ordinal: column.Ordinal, Name: column.Name, TypeOID: discovered.TypeOID, TypeFingerprint: column.TypeFingerprint,
			LogicalType: column.LogicalType, Roles: append([]Role(nil), column.Roles...), Nullable: column.Nullable,
			Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes, Comment: discovered.Comment,
		})
	}
	return result
}

func catalogType(typeOID uint32, typmod int64) (LogicalType, int, int, int, string) {
	fingerprint := "oid:" + strconv.FormatUint(uint64(typeOID), 10)
	switch typeOID {
	case 16:
		return TypeBool, 0, 0, 8, fingerprint
	case 20:
		return TypeInt, 0, 0, 32, fingerprint
	case 21:
		return TypeInt, 0, 0, 16, fingerprint
	case 23:
		return TypeInt, 0, 0, 24, fingerprint
	case 1700:
		precision, scale, ok := numericTypmod(typmod)
		if ok {
			fingerprint += ":p:" + strconv.Itoa(precision) + ":s:" + strconv.Itoa(scale)
			return TypeNumeric, precision, scale, precision + 32, fingerprint
		}
		return TypeNumeric, 0, 0, 0, fingerprint
	case 2950:
		return TypeUUID, 0, 0, 64, fingerprint
	case 1082:
		return TypeDate, 0, 0, 32, fingerprint
	case 1114:
		precision, ok := temporalTypmod(typmod)
		if !ok {
			return TypeTimestamp, precision, 0, 0, fingerprint
		}
		return TypeTimestamp, precision, 0, 64, fingerprint + ":p:" + strconv.Itoa(precision)
	case 1184:
		precision, ok := temporalTypmod(typmod)
		if !ok {
			return TypeTimestamptz, precision, 0, 0, fingerprint
		}
		return TypeTimestamptz, precision, 0, 64, fingerprint + ":p:" + strconv.Itoa(precision)
	case 25, 1042, 1043:
		maxBytes := 16 << 20
		if typmod > 4 {
			maxBytes = boundedTextBytes(typmod - 4)
			fingerprint += ":len:" + strconv.FormatInt(typmod-4, 10)
		}
		return TypeText, 0, 0, maxBytes, fingerprint
	case 114:
		return TypeJSON, 0, 0, 16 << 20, fingerprint
	case 3802:
		return TypeJSONB, 0, 0, 16 << 20, fingerprint
	default:
		return "", 0, 0, 0, fingerprint
	}
}

func numericTypmod(typmod int64) (int, int, bool) {
	if typmod < 4 {
		return 0, 0, false
	}
	raw := typmod - 4
	precision := int((raw >> 16) & 0xffff)
	// PostgreSQL stores NUMERIC's scale as a signed 11-bit value.  The
	// remaining five bits are reserved; decoding all 16 bits turns a valid
	// negative scale such as -2 into 2046 and loses the server metadata.
	scale := int(raw & 0x7ff)
	if scale&0x400 != 0 {
		scale -= 0x800
	}
	return precision, scale, precision >= 1
}

func temporalTypmod(typmod int64) (int, bool) {
	if typmod < 0 {
		return 6, true
	}
	precision := int(typmod)
	return precision, precision <= 6
}

func boundedTextBytes(characters int64) int {
	if characters < 1 {
		return 1
	}
	if characters > int64((64<<20)/4) {
		return 64 << 20
	}
	return int(characters * 4)
}

func boundedOID(value int64) (uint32, bool) {
	if value < 1 || value > int64(^uint32(0)) {
		return 0, false
	}
	return uint32(value), true
}

func validCatalogText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 && character != '\n' && character != '\t' {
			return false
		}
	}
	return true
}

func validCatalogComment(value string, maxBytes int) bool {
	if value == "" {
		return true
	}
	return validCatalogText(value, maxBytes)
}

func discoverySchemaAllowed(schemaName string) bool {
	return schemaName != "" && schemaName != "pg_catalog" && schemaName != "information_schema" && !strings.HasPrefix(schemaName, "pg_")
}

func rollbackDiscoveryTransaction(tx pgx.Tx) {
	if tx == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func closeDiscoveryConnection(connection *pgx.Conn) {
	if connection == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = connection.Close(ctx)
}
