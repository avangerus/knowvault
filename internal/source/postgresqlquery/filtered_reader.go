package postgresqlquery

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ScalarArgument is one closed, server-owned typed comparison value. Only the
// field matching LogicalType carries the value; the caller can never supply an
// identifier or SQL fragment. Canonicalization reuses the same rules as
// CanonicalizeRow so a predicate value cannot smuggle a representation the
// value owner would reject.
type ScalarArgument struct {
	LogicalType LogicalType
	Text        string
	Int         int64
	Bool        bool
}

// EqualityPredicate is one typed `column = value` filter over an approved
// projection column, named only by its positive ordinal.
type EqualityPredicate struct {
	Ordinal int
	Value   ScalarArgument
}

// HalfOpenPeriod is one `column >= Start AND column < EndExclusive` filter over
// the selected PERIOD column, named only by its positive ordinal.
type HalfOpenPeriod struct {
	Ordinal      int
	LogicalType  LogicalType
	Start        string
	EndExclusive string
}

// ScalarReadSelection names the approved projection columns retained in the
// returned Snapshot. Filter ordinals must already be members of this set, so
// every predicate is self-evidenced by a selected column.
type ScalarReadSelection struct {
	OutputOrdinals   []int
	IdentityOrdinals []int
	MeasureOrdinal   int
}

// FilteredProjectionRequest is the complete closed request for one bounded
// parameterized projection read. It carries no SQL, schema, relation,
// identifier, connection target or execution mode.
type FilteredProjectionRequest struct {
	Projection Projection
	Selection  ScalarReadSelection
	Equalities []EqualityPredicate
	Period     *HalfOpenPeriod
}

// ReadFilteredProjection executes one server-generated, parameterized
// projection SELECT inside the shared SERIALIZABLE READ ONLY DEFERRABLE
// transaction. It validates the closed request before touching the connection,
// streams rows, and refuses cap+1 before publication can consume the result. It
// never aggregates, persists, authorizes or creates a receipt.
func ReadFilteredProjection(ctx context.Context, connection *pgx.Conn, request FilteredProjectionRequest, limits Limits) (Snapshot, error) {
	query, err := buildFilteredProjectionQuery(request, limits)
	if err != nil {
		return Snapshot{}, err
	}
	if ctx == nil || connection == nil {
		return Snapshot{}, &Error{code: CodeExternalFailure}
	}
	return readBoundedProjection(ctx, connection, query.statement, query.args, query.columns, limits)
}

// filteredProjectionQuery is the validated, ready-to-run result of a closed
// request: the statement, the canonicalized pgx arguments and the ordered
// 1..N renumbered selected columns handed to CanonicalizeRow.
type filteredProjectionQuery struct {
	statement string
	args      []any
	columns   []Column
}

// buildFilteredProjectionQuery validates the closed request and compiles the
// only parameterized SELECT this package emits. Identifiers come exclusively
// from the validated Projection; every comparison value becomes a pgx argument
// and every caller ordinal is resolved against Projection.Columns.
func buildFilteredProjectionQuery(request FilteredProjectionRequest, limits Limits) (filteredProjectionQuery, error) {
	if err := request.Projection.Validate(); err != nil {
		return filteredProjectionQuery{}, err
	}
	if err := limits.Validate(); err != nil {
		return filteredProjectionQuery{}, err
	}

	// The selected column set is the source-order union of output, identity and
	// measure ordinals. Filter ordinals must be selected too: a predicate the
	// returned Snapshot cannot evidence is refused.
	selected := make(map[int]struct{}, len(request.Selection.OutputOrdinals)+len(request.Selection.IdentityOrdinals)+1)
	outputSeen := make(map[int]struct{}, len(request.Selection.OutputOrdinals))
	for _, ordinal := range request.Selection.OutputOrdinals {
		column, ok := columnByOrdinal(request.Projection, ordinal)
		if !ok {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		if _, duplicate := outputSeen[column.Ordinal]; duplicate {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		outputSeen[column.Ordinal] = struct{}{}
		selected[column.Ordinal] = struct{}{}
	}

	identitySeen := make(map[int]struct{}, len(request.Selection.IdentityOrdinals))
	for _, ordinal := range request.Selection.IdentityOrdinals {
		column, ok := columnByOrdinal(request.Projection, ordinal)
		if !ok || column.Nullable || !columnHasRole(column, RoleIdentity) {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		if _, duplicate := identitySeen[column.Ordinal]; duplicate {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		identitySeen[column.Ordinal] = struct{}{}
		selected[column.Ordinal] = struct{}{}
	}
	if len(identitySeen) == 0 {
		return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
	}

	measure, ok := columnByOrdinal(request.Projection, request.Selection.MeasureOrdinal)
	if !ok || !columnHasRole(measure, RoleEvidence) {
		return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
	}
	selected[measure.Ordinal] = struct{}{}

	var args []any
	conditions := make([]string, 0, len(request.Equalities)+1)

	equalitySeen := make(map[int]struct{}, len(request.Equalities))
	for _, predicate := range request.Equalities {
		column, ok := columnByOrdinal(request.Projection, predicate.Ordinal)
		if !ok {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		if _, duplicate := equalitySeen[column.Ordinal]; duplicate {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		equalitySeen[column.Ordinal] = struct{}{}
		if _, isSelected := selected[column.Ordinal]; !isSelected {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		if predicate.Value.LogicalType != column.LogicalType || !predicateTypeSupported(column.LogicalType) {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		argument, err := canonicalScalarArgument(column, predicate.Value)
		if err != nil {
			return filteredProjectionQuery{}, err
		}
		conditions = append(conditions, quoteIdentifier(column.Name)+" = $"+strconv.Itoa(len(args)+1))
		args = append(args, argument)
	}

	if request.Period != nil {
		column, ok := columnByOrdinal(request.Projection, request.Period.Ordinal)
		if !ok || !columnHasRole(column, RolePeriod) || !periodTypeSupported(column.LogicalType) ||
			request.Period.LogicalType != column.LogicalType {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		if _, isSelected := selected[column.Ordinal]; !isSelected {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		start, err := canonicalPeriodBound(column, request.Period.Start)
		if err != nil {
			return filteredProjectionQuery{}, err
		}
		end, err := canonicalPeriodBound(column, request.Period.EndExclusive)
		if err != nil {
			return filteredProjectionQuery{}, err
		}
		// Canonical bounds share one fixed-width ISO representation per
		// selected column, so the string comparison is chronological.
		if start >= end {
			return filteredProjectionQuery{}, &Error{code: CodeInvalidProjection}
		}
		conditions = append(conditions, quoteIdentifier(column.Name)+" >= $"+strconv.Itoa(len(args)+1))
		args = append(args, start)
		conditions = append(conditions, quoteIdentifier(column.Name)+" < $"+strconv.Itoa(len(args)+1))
		args = append(args, end)
	}

	selectedOrdinals := make([]int, 0, len(selected))
	for ordinal := range selected {
		selectedOrdinals = append(selectedOrdinals, ordinal)
	}
	sort.Ints(selectedOrdinals)
	selectedNames := make([]string, len(selectedOrdinals))
	columns := make([]Column, len(selectedOrdinals))
	for index, ordinal := range selectedOrdinals {
		column, _ := columnByOrdinal(request.Projection, ordinal)
		selectedNames[index] = quoteIdentifier(column.Name)
		// Selected columns stay in source order; only the canonical copy handed
		// to CanonicalizeRow is renumbered 1..N.
		copied := column
		copied.Ordinal = index + 1
		columns[index] = copied
	}

	identityOrdinals := make([]int, 0, len(identitySeen))
	for ordinal := range identitySeen {
		identityOrdinals = append(identityOrdinals, ordinal)
	}
	sort.Ints(identityOrdinals)
	identityNames := make([]string, len(identityOrdinals))
	for index, ordinal := range identityOrdinals {
		column, _ := columnByOrdinal(request.Projection, ordinal)
		identityNames[index] = quoteIdentifier(column.Name)
	}

	statement := "SELECT " + strings.Join(selectedNames, ",") +
		" FROM " + quoteIdentifier(request.Projection.SchemaName) + "." + quoteIdentifier(request.Projection.RelationName)
	if len(conditions) > 0 {
		statement += " WHERE " + strings.Join(conditions, " AND ")
	}
	// LIMIT is the server-owned cap+1 probe bound; no caller value reaches it.
	statement += " ORDER BY " + strings.Join(identityNames, ",") + " LIMIT " + strconv.Itoa(limits.MaxRows+1)

	return filteredProjectionQuery{statement: statement, args: args, columns: columns}, nil
}

func columnByOrdinal(projection Projection, ordinal int) (Column, bool) {
	if ordinal < 1 {
		return Column{}, false
	}
	for _, column := range projection.Columns {
		if column.Ordinal == ordinal {
			return column, true
		}
	}
	return Column{}, false
}

func columnHasRole(column Column, role Role) bool {
	for _, candidate := range column.Roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func predicateTypeSupported(logicalType LogicalType) bool {
	switch logicalType {
	case TypeBool, TypeInt, TypeNumeric, TypeUUID, TypeDate, TypeTimestamp, TypeTimestamptz, TypeText:
		return true
	default:
		// JSON, JSONB and any unsupported predicate type are refused.
		return false
	}
}

func periodTypeSupported(logicalType LogicalType) bool {
	return logicalType == TypeDate || logicalType == TypeTimestamp || logicalType == TypeTimestamptz
}

// canonicalScalarArgument reuses the package's existing value rules to validate
// and canonicalize one equality argument. The returned value is always a pgx
// argument, never SQL text.
func canonicalScalarArgument(column Column, argument ScalarArgument) (any, error) {
	switch column.LogicalType {
	case TypeBool:
		value, err := boolValue(argument.Bool)
		if err != nil {
			return nil, err
		}
		return value, nil
	case TypeInt:
		value, err := integerValue(argument.Int)
		if err != nil {
			return nil, err
		}
		if err := validateIntegerRange(column.TypeFingerprint, value); err != nil {
			return nil, err
		}
		return argument.Int, nil
	case TypeNumeric:
		return numericValue(argument.Text, column.Precision, column.Scale)
	case TypeUUID:
		return uuidValue(argument.Text)
	case TypeDate:
		return dateValue(argument.Text)
	case TypeTimestamp:
		return timestampValue(argument.Text, column.Precision, false)
	case TypeTimestamptz:
		return timestampValue(argument.Text, column.Precision, true)
	case TypeText:
		return textValue(argument.Text, column.MaxBytes)
	default:
		return nil, &Error{code: CodeInvalidProjection}
	}
}

func canonicalPeriodBound(column Column, raw string) (string, error) {
	switch column.LogicalType {
	case TypeDate:
		return dateValue(raw)
	case TypeTimestamp:
		return timestampValue(raw, column.Precision, false)
	case TypeTimestamptz:
		return timestampValue(raw, column.Precision, true)
	default:
		return "", &Error{code: CodeInvalidProjection}
	}
}
