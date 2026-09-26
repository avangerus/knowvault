// Package postgresqlquery owns the bounded PostgreSQL business-object source
// boundary. It accepts only a server-generated projection, never SQL supplied
// by a user or a model, and turns streamed rows into the same immutable typed
// value bytes used by the catalog/Evidence path.
package postgresqlquery

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const ValueContractVersion = "postgresql-query-value-v1"

type ErrorCode string

const (
	CodeInvalidProjection    ErrorCode = "PG_QUERY_PROJECTION_INVALID"
	CodeInvalidValue         ErrorCode = "PG_QUERY_VALUE_INVALID"
	CodeUnsupportedType      ErrorCode = "PG_QUERY_UNSUPPORTED_TYPE"
	CodeLimitExceeded        ErrorCode = "PG_QUERY_LIMIT_EXCEEDED"
	CodeIncomplete           ErrorCode = "PG_QUERY_INCOMPLETE_SNAPSHOT"
	CodeExternalFailure      ErrorCode = "PG_QUERY_EXTERNAL_FAILURE"
	CodeDiscoveryInvalid     ErrorCode = "PG_QUERY_DISCOVERY_INVALID"
	CodeDiscoveryUnavailable ErrorCode = "PG_QUERY_DISCOVERY_UNAVAILABLE"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeExternalFailure
}

type Role string

const (
	RoleIdentity    Role = "IDENTITY"
	RoleTitle       Role = "TITLE"
	RoleVersionHint Role = "VERSION_HINT"
	RoleEvidence    Role = "EVIDENCE"
	// RolePeriod is the owner's own declaration, at registration, of which
	// temporal column is the row's PERIOD -- the date "today"/"yesterday"/"for
	// the week" means for this projection (FIX-3 #1). It is optional (a
	// single-temporal-column projection needs no declaration, exactly as
	// before), but when a projection has more than one temporal column, the
	// reducer requires exactly this declared column rather than guessing the
	// lowest-ordinal one.
	RolePeriod Role = "PERIOD"
	// RoleStatus is the owner's own declaration of which column carries the
	// row's lifecycle status (SEED-3 #1). It is what lets the reducer's
	// "overdue" condition tell a genuinely overdue row from one
	// whose PERIOD (due) date has passed but that is already closed. It is
	// optional: a projection with no declared STATUS column still answers
	// "overdue" questions, but purely by PERIOD < now(), with a note that
	// status was not considered (nothing here silently invents a closed set).
	RoleStatus Role = "STATUS"
)

type LogicalType string

const (
	TypeBool        LogicalType = "BOOL"
	TypeInt         LogicalType = "INT"
	TypeNumeric     LogicalType = "NUMERIC"
	TypeUUID        LogicalType = "UUID"
	TypeDate        LogicalType = "DATE"
	TypeTimestamp   LogicalType = "TIMESTAMP"
	TypeTimestamptz LogicalType = "TIMESTAMPTZ"
	TypeText        LogicalType = "TEXT"
	TypeJSON        LogicalType = "JSON"
	TypeJSONB       LogicalType = "JSONB"
)

// Column is the immutable ordered projection contract. TypeFingerprint is the
// external PostgreSQL OID/domain/collation fingerprint, not a caller-display
// label; it is persisted in every row-value entry so type drift cannot be
// mistaken for content equality.
type Column struct {
	Ordinal         int
	Name            string
	TypeFingerprint string
	LogicalType     LogicalType
	Roles           []Role
	Nullable        bool
	Precision       int
	Scale           int
	MaxBytes        int
}

// Projection is the trusted, immutable server-side projection. RelationKind
// is VIEW, MATERIALIZED_VIEW, TABLE or PARTITIONED_TABLE (ADR-0097) and
// SelectSQL is generated from these fields; no SQL text is stored or
// accepted.
//
// QueryOnly (S3 card 4) is the registration mode: a query-only relation is a
// registered, SQL-addressable contract whose rows are never copied into the
// search index. It is part of the immutable contract, not a per-call flag: a
// query-only projection carries its own ContractHash and LineageID (see
// WithQueryOnly), so switching a relation between indexed and query-only is a
// distinct immutable lineage exactly like a column exclusion.
type Projection struct {
	ConnectionID        string
	DatabaseIdentity    string
	LineageID           string
	Revision            int64
	ContractHash        string
	SchemaName          string
	RelationName        string
	RelationKind        string
	Columns             []Column
	EmptySnapshotPolicy string
	QueryOnly           bool
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (p Projection) Validate() error {
	if !validOpaque(p.ConnectionID) || !validOpaque(p.DatabaseIdentity) ||
		!validOpaque(p.LineageID) || p.Revision < 1 || !digestPattern.MatchString(p.ContractHash) ||
		!identifierPattern.MatchString(p.SchemaName) || !identifierPattern.MatchString(p.RelationName) ||
		!validRelationKind(p.RelationKind) || len(p.Columns) == 0 ||
		(p.EmptySnapshotPolicy != "HELD" && p.EmptySnapshotPolicy != "AUTHORITATIVE") {
		return &Error{code: CodeInvalidProjection}
	}
	columns := append([]Column(nil), p.Columns...)
	sort.Slice(columns, func(i, j int) bool { return columns[i].Ordinal < columns[j].Ordinal })
	hasIdentity, hasEvidence := false, false
	periodCount := 0
	statusCount := 0
	seenNames := make(map[string]struct{}, len(columns))
	for index, column := range columns {
		if column.Ordinal != index+1 || !identifierPattern.MatchString(column.Name) ||
			!validOpaque(column.TypeFingerprint) || !validLogicalType(column.LogicalType) ||
			len(column.Roles) == 0 || column.MaxBytes < 1 || column.MaxBytes > 64<<20 ||
			column.Precision < 0 || column.Precision > 1000 || column.Scale < 0 || column.Scale > column.Precision {
			return &Error{code: CodeInvalidProjection}
		}
		if _, duplicate := seenNames[column.Name]; duplicate {
			return &Error{code: CodeInvalidProjection}
		}
		seenNames[column.Name] = struct{}{}
		if column.LogicalType == TypeNumeric && column.Precision < 1 {
			return &Error{code: CodeInvalidProjection}
		}
		if (column.LogicalType == TypeTimestamp || column.LogicalType == TypeTimestamptz) && column.Precision > 6 {
			return &Error{code: CodeInvalidProjection}
		}
		seenRoles := make(map[Role]struct{}, len(column.Roles))
		for _, role := range column.Roles {
			if _, duplicate := seenRoles[role]; duplicate || !validRole(role) {
				return &Error{code: CodeInvalidProjection}
			}
			seenRoles[role] = struct{}{}
			if role == RoleIdentity {
				if column.Nullable {
					return &Error{code: CodeInvalidProjection}
				}
				hasIdentity = true
			}
			if role == RoleEvidence {
				hasEvidence = true
			}
			if role == RolePeriod {
				if column.LogicalType != TypeDate && column.LogicalType != TypeTimestamp && column.LogicalType != TypeTimestamptz {
					// PERIOD names "the date this row counts under" -- a role
					// only a temporal column can carry.
					return &Error{code: CodeInvalidProjection}
				}
				periodCount++
			}
			if role == RoleStatus {
				statusCount++
			}
		}
		if !column.Nullable && column.LogicalType == TypeText && column.MaxBytes < 1 {
			return &Error{code: CodeInvalidProjection}
		}
	}
	if !hasIdentity || !hasEvidence {
		return &Error{code: CodeInvalidProjection}
	}
	if periodCount > 1 {
		// FIX-3 #1: PERIOD is the owner's statement of exactly one column, not
		// a hint several columns may share -- more than one declared PERIOD
		// column is as unresolvable as none at all.
		return &Error{code: CodeInvalidProjection}
	}
	if statusCount > 1 {
		// SEED-3 #1: same reasoning as PERIOD -- STATUS names exactly one
		// column's lifecycle state, never several to disambiguate later.
		return &Error{code: CodeInvalidProjection}
	}
	return nil
}

func (p Projection) SelectSQL() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	columns := append([]Column(nil), p.Columns...)
	sort.Slice(columns, func(i, j int) bool { return columns[i].Ordinal < columns[j].Ordinal })
	names := make([]string, len(columns))
	identityNames := make([]string, 0, len(columns))
	for i, column := range columns {
		names[i] = quoteIdentifier(column.Name)
		for _, role := range column.Roles {
			if role == RoleIdentity {
				identityNames = append(identityNames, quoteIdentifier(column.Name))
				break
			}
		}
	}
	// This is deliberately the only SQL statement emitted by this package. It
	// has no predicates, parameters, joins, function calls or caller-controlled
	// fragments; identifiers come from the validated immutable contract. The
	// identity ordering makes a streamed snapshot reproducible even when the
	// external view has no physical ordering guarantee.
	return fmt.Sprintf("SELECT %s FROM %s.%s ORDER BY %s", strings.Join(names, ","), quoteIdentifier(p.SchemaName), quoteIdentifier(p.RelationName), strings.Join(identityNames, ",")), nil
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

// validRelationKind is the ADR-0097 closed set: the original DBA-reviewed
// VIEW/MATERIALIZED_VIEW contract plus an ordinary or partitioned base table
// admitted only through its primary key.
func validRelationKind(value string) bool {
	switch value {
	case "VIEW", "MATERIALIZED_VIEW", "TABLE", "PARTITIONED_TABLE":
		return true
	default:
		return false
	}
}

func validRole(value Role) bool {
	switch value {
	case RoleIdentity, RoleTitle, RoleVersionHint, RoleEvidence, RolePeriod, RoleStatus:
		return true
	default:
		return false
	}
}

func validLogicalType(value LogicalType) bool {
	switch value {
	case TypeBool, TypeInt, TypeNumeric, TypeUUID, TypeDate, TypeTimestamp, TypeTimestamptz, TypeText, TypeJSON, TypeJSONB:
		return true
	default:
		return false
	}
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_-.:", r) {
			continue
		}
		return false
	}
	return true
}
