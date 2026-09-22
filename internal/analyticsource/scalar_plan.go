package analyticsource

import (
	"sort"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/queryintent"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// scalarReadPlan is the pure, server-owned description of exactly one bounded
// ungrouped scalar read. It carries the semantic filtered read naming only
// approved projection ordinals and closed typed values, plus the selected
// Snapshot positions of the measure and grain columns. It performs no I/O,
// reads no resolver or repository, holds no execution handle, and grants
// nothing: compiling a plan is not executing it.
//
// read.Selection ordinals are source ordinals as the approved sealed profile
// names them. measureOrdinal and identityOrdinals are the 1..N positions of
// those columns inside the Snapshot the bounded read returns, because the
// filtered reader selects the source-order union of the requested columns and
// renumbers them. A result reducer must therefore read measureOrdinal and
// identityOrdinals, never the source ordinals.
type scalarReadPlan struct {
	read             repository.PostgreSQLFilteredRead
	measureOrdinal   int
	identityOrdinals []int
}

// compileScalarReadPlan compiles one ungrouped scalar SUM read plan from one
// valid sealed profile and the exact intent that profile authorized. It is pure:
// it performs no I/O, calls no resolver or repository, and derives every source
// ordinal from the sealed profile alone.
//
// It accepts only the closed shape this card serves: an AGGREGATE proposal with
// the VALUE output, zero dimensions, limit 1, zero sort keys, the exact dataset
// identity the profile carries, the profile's own limits and coverage, a named
// measure whose reducer is SUM, a non-NONE profile time policy with a valid
// resolved period that has bounds and the matching time kind, and 0..4 EQ
// filters that each carry exactly one scalar and resolve to distinct approved
// source ordinals. Every refusal returns the exact
// zero scalarReadPlan and the exact unwrapped errMismatch, so the plan is
// neither an existence nor an authorization oracle.
func compileScalarReadPlan(profile analytic.DatasetProfile, intent queryintent.ValidatedIntentV2) (scalarReadPlan, error) {
	if !profile.Valid() || !intent.Valid() {
		return scalarReadPlan{}, errMismatch
	}

	operation, ok := intent.Operation()
	if !ok || operation != queryintent.OperationAGGREGATE {
		return scalarReadPlan{}, errMismatch
	}
	output, ok := intent.Output()
	if !ok || output != queryintent.OutputValue {
		return scalarReadPlan{}, errMismatch
	}
	dimensions, ok := intent.Dimensions()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	dimensionFields, ok := dimensions.Fields()
	if !ok || len(dimensionFields) != 0 {
		return scalarReadPlan{}, errMismatch
	}
	sortKeys, ok := intent.Sort()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	keys, ok := sortKeys.Values()
	if !ok || len(keys) != 0 {
		return scalarReadPlan{}, errMismatch
	}
	limit, ok := intent.Limit()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	limitValue, ok := limit.Value()
	if !ok || limitValue != 1 {
		return scalarReadPlan{}, errMismatch
	}

	dataset, ok := intent.Dataset()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	datasetID, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, hashOK := dataset.ExpectedProfileHash()
	key := profile.Key()
	if !idOK || !versionOK || !hashOK || datasetID != key.DatasetID() ||
		version != key.Version() || profileHash != profile.Hash() {
		return scalarReadPlan{}, errMismatch
	}
	limits, ok := intent.Limits()
	if !ok || limits != profile.Limits() {
		return scalarReadPlan{}, errMismatch
	}
	coverage, ok := intent.Coverage()
	if !ok || coverage != profile.Coverage() {
		return scalarReadPlan{}, errMismatch
	}

	measure, ok := intent.Measure()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	measureID, idOK := measure.MeasureID()
	measureSpec, found := profile.Measure(measureID)
	measureValues := measureSpec.Values()
	if !idOK || !found || measureValues.Reducer != analytic.ReducerSum {
		return scalarReadPlan{}, errMismatch
	}
	numerator, found := profile.Field(measureValues.NumeratorField)
	if !found {
		return scalarReadPlan{}, errMismatch
	}
	measureSource := numerator.Values().SourceOrdinal

	timePolicy := profile.Time().Values()
	if timePolicy.Kind == analytic.TimeNone {
		return scalarReadPlan{}, errMismatch
	}
	resolved, ok := intent.ResolvedPeriod()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	resolvedKind, kindOK := resolved.TimeKind()
	if !kindOK || resolvedKind != timePolicy.Kind {
		return scalarReadPlan{}, errMismatch
	}
	periodType, ok := periodLogicalType(timePolicy.Kind)
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	timeField, found := profile.Field(timePolicy.FieldToken)
	if !found {
		return scalarReadPlan{}, errMismatch
	}
	periodSource := timeField.Values().SourceOrdinal
	start, end, boundsOK := resolved.Bounds()
	if !boundsOK {
		return scalarReadPlan{}, errMismatch
	}

	filters, ok := intent.Filters()
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	predicates, ok := filters.Values()
	if !ok || len(predicates) > queryintent.MaxPredicates {
		return scalarReadPlan{}, errMismatch
	}
	equalities := make([]postgresqlquery.EqualityPredicate, 0, len(predicates))
	seenFilterSources := make(map[int]struct{}, len(predicates))
	for _, predicate := range predicates {
		if predicate.Op() != queryintent.OpEQ {
			return scalarReadPlan{}, errMismatch
		}
		values := predicate.Values()
		if len(values) != 1 {
			return scalarReadPlan{}, errMismatch
		}
		name, nameOK := predicate.Field().Value()
		field, found := profile.Field(name)
		if !nameOK || !found {
			return scalarReadPlan{}, errMismatch
		}
		source := field.Values().SourceOrdinal
		if _, duplicate := seenFilterSources[source]; duplicate {
			return scalarReadPlan{}, errMismatch
		}
		seenFilterSources[source] = struct{}{}
		argument, ok := scalarArgument(field.Values().LogicalType, values[0])
		if !ok {
			return scalarReadPlan{}, errMismatch
		}
		equalities = append(equalities, postgresqlquery.EqualityPredicate{
			Ordinal: source,
			Value:   argument,
		})
	}

	grain := profile.Grain().Values()
	identitySources := make([]int, 0, len(grain.KeyFields))
	for _, token := range grain.KeyFields {
		field, found := profile.Field(token)
		if !found {
			return scalarReadPlan{}, errMismatch
		}
		identitySources = append(identitySources, field.Values().SourceOrdinal)
	}
	identitySources = sortedUniqueOrdinals(identitySources)

	outputSources := []int{measureSource, periodSource}
	for _, equality := range equalities {
		outputSources = append(outputSources, equality.Ordinal)
	}
	outputSources = sortedUniqueOrdinals(outputSources)

	// The bounded read returns the source-order union of output, identity and
	// measure columns, renumbered 1..N. Map every selected source ordinal onto
	// that Snapshot position so the result-mapping fields never carry a source
	// ordinal.
	selected := make([]int, 0, len(outputSources)+len(identitySources)+1)
	selected = append(selected, outputSources...)
	selected = append(selected, identitySources...)
	selected = append(selected, measureSource)
	selected = sortedUniqueOrdinals(selected)
	snapshot := make(map[int]int, len(selected))
	for index, source := range selected {
		snapshot[source] = index + 1
	}
	measureOrdinal, ok := snapshot[measureSource]
	if !ok {
		return scalarReadPlan{}, errMismatch
	}
	identityOrdinals := make([]int, len(identitySources))
	for index, source := range identitySources {
		ordinal, ok := snapshot[source]
		if !ok {
			return scalarReadPlan{}, errMismatch
		}
		identityOrdinals[index] = ordinal
	}

	return scalarReadPlan{
		read: repository.PostgreSQLFilteredRead{
			Selection: postgresqlquery.ScalarReadSelection{
				OutputOrdinals:   outputSources,
				IdentityOrdinals: identitySources,
				MeasureOrdinal:   measureSource,
			},
			Equalities: equalities,
			Period: &postgresqlquery.HalfOpenPeriod{
				Ordinal:      periodSource,
				LogicalType:  periodType,
				Start:        start,
				EndExclusive: end,
			},
		},
		measureOrdinal:   measureOrdinal,
		identityOrdinals: identityOrdinals,
	}, nil
}

// scalarArgument is the closed scalar mapping from one intent scalar onto the
// typed postgresqlquery argument, given the exact logical type of the approved
// profile field the scalar filters. BOOL carries its flag, INT its integer, and
// NUMERIC, TEXT, DATE, TIMESTAMP and TIMESTAMPTZ their canonical text. Any
// mismatch between the query scalar kind and the profile field logical type, or
// any unsupported kind, refuses.
func scalarArgument(logical analytic.ScalarType, value queryintent.Scalar) (postgresqlquery.ScalarArgument, bool) {
	switch value.Kind() {
	case queryintent.KindBOOL:
		if logical != analytic.ScalarBool {
			return postgresqlquery.ScalarArgument{}, false
		}
		flag, ok := value.Bool()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeBool, Bool: flag}, true
	case queryintent.KindINT:
		if logical != analytic.ScalarInt {
			return postgresqlquery.ScalarArgument{}, false
		}
		number, ok := value.Int()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeInt, Int: number}, true
	case queryintent.KindNUMERIC:
		if logical != analytic.ScalarNumeric {
			return postgresqlquery.ScalarArgument{}, false
		}
		text, ok := value.Numeric()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeNumeric, Text: text}, true
	case queryintent.KindTEXT:
		if logical != analytic.ScalarText {
			return postgresqlquery.ScalarArgument{}, false
		}
		text, ok := value.Text()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeText, Text: text}, true
	case queryintent.KindDATE:
		if logical != analytic.ScalarDate {
			return postgresqlquery.ScalarArgument{}, false
		}
		text, ok := value.Date()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeDate, Text: text}, true
	case queryintent.KindTIMESTAMP:
		if logical != analytic.ScalarTimestamp {
			return postgresqlquery.ScalarArgument{}, false
		}
		text, ok := value.Timestamp()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeTimestamp, Text: text}, true
	case queryintent.KindTIMESTAMPTZ:
		if logical != analytic.ScalarTimestamptz {
			return postgresqlquery.ScalarArgument{}, false
		}
		text, ok := value.Timestamptz()
		if !ok {
			return postgresqlquery.ScalarArgument{}, false
		}
		return postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeTimestamptz, Text: text}, true
	default:
		return postgresqlquery.ScalarArgument{}, false
	}
}

// periodLogicalType maps the profile's closed time kind onto the logical type
// of the one typed half-open period. NONE and every other kind refuse.
func periodLogicalType(kind analytic.TimeKind) (postgresqlquery.LogicalType, bool) {
	switch kind {
	case analytic.TimeBusinessDate:
		return postgresqlquery.TypeDate, true
	case analytic.TimeLocalTimestamp:
		return postgresqlquery.TypeTimestamp, true
	case analytic.TimeZonedTimestamp:
		return postgresqlquery.TypeTimestamptz, true
	default:
		return "", false
	}
}

// sortedUniqueOrdinals returns a freshly allocated ascending copy of values with
// duplicates removed, or nil for an empty input.
func sortedUniqueOrdinals(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	unique := sorted[:1]
	for _, value := range sorted[1:] {
		if value != unique[len(unique)-1] {
			unique = append(unique, value)
		}
	}
	return unique
}
