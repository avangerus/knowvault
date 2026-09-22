package postgres_test

// B2.4g2a2b1 — the fixed typed analytics catalog mount fixture and its one
// database-free constructor, strict-decoder and mount parity proof.
//
// The fixture is one four-source-column analytics dataset profile: a bigint
// operation identity, a business date, a nullable numeric amount and a zoned
// observation instant. Its expected profile is sealed only through the public
// analytic constructors, with one COUNT_ROWS measure, one semantics entry per
// field and measure, the operation identity as grain, a business-date time
// policy over the business day, UNKNOWN coverage and small conservative
// limits; its expected one-entry ACTIVE catalog is sealed only through
// analytic.NewDatasetProfileCatalog.
//
// The mount document is one fixed catalog mount JSON document carrying that
// same profile. Only the source identity values and the pinned timezone rules
// digest are substituted, and every substituted string is rendered by the
// repository's JSON v2 encoder before insertion, so the strict decoder and the
// production mount loader must reproduce the constructed values exactly.
//
// The proof asserts facts and adds no behavior: the expected profile and
// catalog are valid, the loaded catalog is valid with the expected identity and
// hash, it holds exactly one ACTIVE entry for the expected profile key and
// hash, ResolveActive resolves that key and hash, and the resolved profile
// equals the constructed source, four fields, measure, semantics, grain, time,
// coverage and limits.
//
// Deliberately not covered here: PostgreSQL access, source authority and
// governed exposure reads, analyticsource.Resolver, mount provenance at
// runtime, and negative cases.

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/platform/analyticcatalog"
	"knowvault.local/verified-workspace/internal/tzrules"
)

const (
	// typedAnalyticsCatalogMountFilename is the exact file the analytic catalog
	// mount loader reads under its root.
	typedAnalyticsCatalogMountFilename = "dataset-profile-catalog.json"

	// typedAnalyticsCatalogID and typedAnalyticsCatalogRevision are the catalog
	// identity the mount document carries and the expected catalog is sealed
	// with.
	typedAnalyticsCatalogID       = "catalog.typed-analytics"
	typedAnalyticsCatalogRevision = int64(1)

	// typedAnalyticsCatalogDatasetID and typedAnalyticsCatalogDatasetVersion are
	// the active profile key the mount document carries.
	typedAnalyticsCatalogDatasetID      = "dataset.typed-analytics-operations"
	typedAnalyticsCatalogDatasetVersion = int64(1)

	// typedAnalyticsCatalogMeasureID is the fixture's one COUNT_ROWS measure id.
	typedAnalyticsCatalogMeasureID = "operation_rows"
)

// typedAnalyticsCatalogSourceInput is the fixture's fixed synthetic source
// identity: eleven distinct values naming the approved projection of the
// registered typed analytics relation, with sha256-form projection and
// exposed-schema hashes and the VIEW relation kind.
func typedAnalyticsCatalogSourceInput() analytic.SourceProjectionInput {
	return analytic.SourceProjectionInput{
		SourceScopeID:          "scope-typed-analytics-catalog",
		ConnectionID:           "connection-typed-analytics-catalog",
		DatabaseIdentity:       "database-typed-analytics-catalog",
		ProjectionLineageID:    "lineage-typed-analytics-catalog",
		ProjectionRevision:     1,
		ProjectionContractHash: "sha256:" + strings.Repeat("d", 64),
		ExposedSchemaRevision:  1,
		ExposedSchemaHash:      "sha256:" + strings.Repeat("e", 64),
		SchemaName:             typedAnalyticsSchema,
		RelationName:           typedAnalyticsRelation,
		RelationKind:           analytic.RelationView,
	}
}

// typedAnalyticsCatalogColumn is one source-ordered column of the fixture's
// four-column profile. It declares the exact field DTO the constructors must
// seal and the mount document must decode back to, plus the field's complete
// business semantics; capability flags stay false with no allowed predicate
// operator, so both declarations are the whole column.
type typedAnalyticsCatalogColumn struct {
	token         string
	physicalName  string
	logicalType   analytic.ScalarType
	physicalType  analytic.PhysicalType
	nullable      bool
	outputAllowed bool
	label         string
	description   string
	nullMeaning   string
}

// typedAnalyticsCatalogColumns is the fixture's complete column inventory in
// source ordinal order.
func typedAnalyticsCatalogColumns() []typedAnalyticsCatalogColumn {
	return []typedAnalyticsCatalogColumn{
		{
			token: "operation_id", physicalName: "operation_id",
			logicalType: analytic.ScalarInt, physicalType: analytic.PhysicalPGInt8,
			outputAllowed: true, label: "Operation identifier",
			description: "Stable identifier of one typed analytics operation.",
			nullMeaning: "Never null; the operation identity is always present.",
		},
		{
			token: "operation_day", physicalName: "operation_day",
			logicalType: analytic.ScalarDate, physicalType: analytic.PhysicalPGDate,
			outputAllowed: true, label: "Operation day",
			description: "Business day the operation is booked to.",
			nullMeaning: "Never null; every operation has one business day.",
		},
		{
			token: "amount", physicalName: "amount",
			logicalType: analytic.ScalarNumeric, physicalType: analytic.PhysicalPGNumeric,
			nullable: true, outputAllowed: true, label: "Amount",
			description: "Signed amount of the operation.",
			nullMeaning: "The amount was not recorded for this operation.",
		},
		{
			token: "observed_at", physicalName: "observed_at",
			logicalType: analytic.ScalarTimestamptz, physicalType: analytic.PhysicalPGTimestamptz,
			outputAllowed: true, label: "Observed at",
			description: "Instant the operation was observed.",
			nullMeaning: "Never null; the observation instant is always present.",
		},
	}
}

// fieldInput is the exact field DTO of this column at source ordinal.
func (column typedAnalyticsCatalogColumn) fieldInput(sourceOrdinal int) analytic.FieldSpecInput {
	return analytic.FieldSpecInput{
		Token: column.token, SourceOrdinal: sourceOrdinal, PhysicalName: column.physicalName,
		LogicalType: column.logicalType, PhysicalType: column.physicalType,
		Nullable: column.nullable, OutputAllowed: column.outputAllowed,
	}
}

// semantics is this column's business semantics.
func (column typedAnalyticsCatalogColumn) semantics() analytic.FieldSemanticsInput {
	return analytic.FieldSemanticsInput{
		Token: column.token, Label: column.label,
		Description: column.description, NullMeaning: column.nullMeaning,
	}
}

// typedAnalyticsCatalogMeasureInput is the fixture's one COUNT_ROWS measure.
func typedAnalyticsCatalogMeasureInput() analytic.MeasureSpecInput {
	return analytic.MeasureSpecInput{
		ID: typedAnalyticsCatalogMeasureID, Reducer: analytic.ReducerCountRows,
		Unit: "rows", NullPolicy: analytic.NullNotApplicable, Eligibility: analytic.EligibilityAllRows,
	}
}

// typedAnalyticsCatalogSemanticsInput is the fixture's complete business
// semantics: one entry per column in source ordinal order and one entry for the
// measure.
func typedAnalyticsCatalogSemanticsInput(columns []typedAnalyticsCatalogColumn) analytic.ProfileSemanticsInput {
	fields := make([]analytic.FieldSemanticsInput, 0, len(columns))
	for _, column := range columns {
		fields = append(fields, column.semantics())
	}
	return analytic.ProfileSemanticsInput{
		DatasetLabel: "Typed analytics operations",
		DatasetDescription: "One approved row per typed analytics operation, with its business day, " +
			"signed amount and observation instant.",
		Fields: fields,
		Measures: []analytic.MeasureSemanticsInput{{
			ID: typedAnalyticsCatalogMeasureID, Label: "Operation rows",
			Description: "Number of approved operation rows.",
		}},
	}
}

// typedAnalyticsCatalogFixture is the fixed four-column analytics profile, its
// independently sealed one-entry active catalog, and the source identity both
// are constructed from.
type typedAnalyticsCatalogFixture struct {
	source  analytic.SourceProjectionSpec
	columns []typedAnalyticsCatalogColumn
	profile analytic.DatasetProfile
	catalog analytic.DatasetProfileCatalog
}

// newTypedAnalyticsCatalogFixture seals the fixture for one approved source
// projection identity. Every other member — the four columns in source ordinal
// order, the one COUNT_ROWS measure, complete semantics, the grain, the
// business-date time policy, UNKNOWN coverage and the limits — is fixed by this
// file, and the expected profile and catalog come only from the public
// constructors.
func newTypedAnalyticsCatalogFixture(t *testing.T, sourceInput analytic.SourceProjectionInput) typedAnalyticsCatalogFixture {
	t.Helper()
	source, err := analytic.NewSourceProjectionSpec(sourceInput)
	if err != nil {
		t.Fatalf("construct typed analytics catalog source projection: %v", err)
	}
	columns := typedAnalyticsCatalogColumns()
	fields := make([]analytic.FieldSpec, 0, len(columns))
	for index, column := range columns {
		field, err := analytic.NewFieldSpec(column.fieldInput(index + 1))
		if err != nil {
			t.Fatalf("construct typed analytics catalog field %q: %v", column.token, err)
		}
		fields = append(fields, field)
	}
	measure, err := analytic.NewMeasureSpec(typedAnalyticsCatalogMeasureInput())
	if err != nil {
		t.Fatalf("construct typed analytics catalog measure: %v", err)
	}
	key, err := analytic.NewProfileKey(typedAnalyticsCatalogDatasetID, typedAnalyticsCatalogDatasetVersion)
	if err != nil {
		t.Fatalf("construct typed analytics catalog profile key: %v", err)
	}
	semantics, err := analytic.NewProfileSemantics(typedAnalyticsCatalogSemanticsInput(columns))
	if err != nil {
		t.Fatalf("construct typed analytics catalog semantics: %v", err)
	}
	grain, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description:     "One row per operation identifier.",
		KeyFields:       []string{"operation_id"},
		DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatalf("construct typed analytics catalog grain: %v", err)
	}
	timePolicy, err := analytic.NewTimePolicy(analytic.TimePolicyInput{
		Kind:              analytic.TimeBusinessDate,
		FieldToken:        "operation_day",
		ReportingTimezone: "UTC",
		Calendar:          analytic.CalendarGregorian,
	})
	if err != nil {
		t.Fatalf("construct typed analytics catalog time policy: %v", err)
	}
	limits, err := analytic.NewProfileLimits(analytic.ProfileLimitsInput{
		MaxInputRows: 1000, MaxOutputGroups: 20, MaxPeriodDays: 31,
		MaxResultBytes: 1048576, StatementTimeoutMS: 5000,
	})
	if err != nil {
		t.Fatalf("construct typed analytics catalog limits: %v", err)
	}
	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: key, Mode: analytic.ExecutionLive, Source: source, Fields: fields,
		Measures: []analytic.MeasureSpec{measure}, Semantics: semantics, Grain: grain,
		Time: timePolicy, Coverage: analytic.CoverageUnknown, Limits: limits,
	})
	if err != nil {
		t.Fatalf("construct typed analytics catalog profile: %v", err)
	}
	catalog, err := analytic.NewDatasetProfileCatalog(typedAnalyticsCatalogID, typedAnalyticsCatalogRevision,
		[]analytic.CatalogEntryInput{{Profile: profile, State: analytic.ProfileActive}})
	if err != nil {
		t.Fatalf("construct typed analytics catalog: %v", err)
	}
	return typedAnalyticsCatalogFixture{source: source, columns: columns, profile: profile, catalog: catalog}
}

// mountDocument renders the fixture's one fixed catalog mount document. Every
// member is literal except the nine substituted JSON strings — the eight source
// identity strings in document order and the pinned timezone rules digest —
// and each substituted string is encoded by the repository's JSON v2 encoder
// rather than quoted by hand.
func (fixture typedAnalyticsCatalogFixture) mountDocument(t *testing.T) []byte {
	t.Helper()
	source := fixture.source.Values()
	return []byte(fmt.Sprintf(typedAnalyticsCatalogMountTemplate,
		typedAnalyticsCatalogJSONString(t, source.SourceScopeID),
		typedAnalyticsCatalogJSONString(t, source.ConnectionID),
		typedAnalyticsCatalogJSONString(t, source.DatabaseIdentity),
		typedAnalyticsCatalogJSONString(t, source.ProjectionLineageID),
		typedAnalyticsCatalogJSONString(t, source.ProjectionContractHash),
		typedAnalyticsCatalogJSONString(t, source.ExposedSchemaHash),
		typedAnalyticsCatalogJSONString(t, source.SchemaName),
		typedAnalyticsCatalogJSONString(t, source.RelationName),
		typedAnalyticsCatalogJSONString(t, tzrules.BundleSHA256),
	))
}

// mountedCatalog writes the fixture's document as exactly
// dataset-profile-catalog.json under a fresh t.TempDir() and loads it only
// through the production mount loader.
func (fixture typedAnalyticsCatalogFixture) mountedCatalog(t *testing.T) analytic.DatasetProfileCatalog {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, typedAnalyticsCatalogMountFilename),
		fixture.mountDocument(t), 0o600); err != nil {
		t.Fatalf("write typed analytics catalog mount document: %v", err)
	}
	catalog, err := analyticcatalog.LoadMountedAt(root)
	if err != nil {
		t.Fatalf("load typed analytics catalog mount: %v", err)
	}
	return catalog
}

// typedAnalyticsCatalogJSONString renders one substituted mount value as a JSON
// string through the repository's JSON v2 encoder.
func typedAnalyticsCatalogJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := jsonv2.Marshal(value)
	if err != nil {
		t.Fatalf("encode typed analytics catalog mount value with the JSON v2 encoder: %v", err)
	}
	return string(encoded)
}

// typedAnalyticsCatalogMountTemplate is the fixture's complete catalog mount
// document: one ACTIVE entry holding the four-column profile. The indexed
// substitutions are, in order, the source scope, connection, database identity,
// projection lineage, projection contract hash, exposed-schema hash, schema,
// relation and the pinned timezone rules digest.
const typedAnalyticsCatalogMountTemplate = `{
  "schema_version": "knowvault-dataset-profile-catalog-mount-v1",
  "catalog_id": "catalog.typed-analytics",
  "revision": 1,
  "entries": [
    {
      "state": "ACTIVE",
      "profile": {
        "schema_version": "knowvault-dataset-profile-v2",
        "key": {"dataset_id": "dataset.typed-analytics-operations", "version": 1},
        "mode": "LIVE",
        "source": {
          "source_scope_id": %[1]s,
          "connection_id": %[2]s,
          "database_identity": %[3]s,
          "projection_lineage_id": %[4]s,
          "projection_revision": 1,
          "projection_contract_hash": %[5]s,
          "exposed_schema_revision": 1,
          "exposed_schema_hash": %[6]s,
          "schema_name": %[7]s,
          "relation_name": %[8]s,
          "relation_kind": "VIEW"
        },
        "fields": [
          {"token": "operation_id", "source_ordinal": 1, "physical_name": "operation_id", "logical_type": "INT", "physical_type": "PG_INT8", "nullable": false, "filterable": false, "groupable": false, "sortable": false, "output_allowed": true, "allowed_ops": []},
          {"token": "operation_day", "source_ordinal": 2, "physical_name": "operation_day", "logical_type": "DATE", "physical_type": "PG_DATE", "nullable": false, "filterable": false, "groupable": false, "sortable": false, "output_allowed": true, "allowed_ops": []},
          {"token": "amount", "source_ordinal": 3, "physical_name": "amount", "logical_type": "NUMERIC", "physical_type": "PG_NUMERIC", "nullable": true, "filterable": false, "groupable": false, "sortable": false, "output_allowed": true, "allowed_ops": []},
          {"token": "observed_at", "source_ordinal": 4, "physical_name": "observed_at", "logical_type": "TIMESTAMPTZ", "physical_type": "PG_TIMESTAMPTZ", "nullable": false, "filterable": false, "groupable": false, "sortable": false, "output_allowed": true, "allowed_ops": []}
        ],
        "measures": [
          {"id": "operation_rows", "reducer": "COUNT_ROWS", "distinct_field": "", "numerator_field": "", "denominator_field": "", "unit": "rows", "null_policy": "NOT_APPLICABLE", "eligibility": "ALL_ROWS"}
        ],
        "semantics": {
          "dataset_label": "Typed analytics operations",
          "dataset_description": "One approved row per typed analytics operation, with its business day, signed amount and observation instant.",
          "fields": [
            {"token": "operation_id", "label": "Operation identifier", "description": "Stable identifier of one typed analytics operation.", "null_meaning": "Never null; the operation identity is always present.", "aliases": []},
            {"token": "operation_day", "label": "Operation day", "description": "Business day the operation is booked to.", "null_meaning": "Never null; every operation has one business day.", "aliases": []},
            {"token": "amount", "label": "Amount", "description": "Signed amount of the operation.", "null_meaning": "The amount was not recorded for this operation.", "aliases": []},
            {"token": "observed_at", "label": "Observed at", "description": "Instant the operation was observed.", "null_meaning": "Never null; the observation instant is always present.", "aliases": []}
          ],
          "measures": [
            {"id": "operation_rows", "label": "Operation rows", "description": "Number of approved operation rows.", "aliases": []}
          ]
        },
        "grain": {
          "description": "One row per operation identifier.",
          "key_fields": ["operation_id"],
          "duplicate_policy": "REJECT"
        },
        "time": {
          "kind": "BUSINESS_DATE",
          "field_token": "operation_day",
          "reporting_timezone": "UTC",
          "source_timezone": "",
          "calendar": "GREGORIAN",
          "timezone_rules_bundle_sha256": %[9]s
        },
        "coverage": "UNKNOWN",
        "limits": {
          "max_input_rows": 1000,
          "max_output_groups": 20,
          "max_period_days": 31,
          "max_result_bytes": 1048576,
          "statement_timeout_ms": 5000
        }
      }
    }
  ]
}
`

// TestTypedAnalyticsCatalogMountMatchesPublicConstructors proves the fixed
// typed analytics catalog mount document decodes into exactly the profile and
// catalog the public constructors seal. It reads no database: the document is
// written under a fresh t.TempDir() and loaded only through
// analyticcatalog.LoadMountedAt.
func TestTypedAnalyticsCatalogMountMatchesPublicConstructors(t *testing.T) {
	fixture := newTypedAnalyticsCatalogFixture(t, typedAnalyticsCatalogSourceInput())

	if !fixture.profile.Valid() {
		t.Fatal("expected typed analytics catalog profile is not valid")
	}
	if !fixture.catalog.Valid() {
		t.Fatal("expected typed analytics catalog is not valid")
	}

	loaded := fixture.mountedCatalog(t)
	if !loaded.Valid() {
		t.Fatal("loaded typed analytics catalog is not valid")
	}
	if loaded.ID() != fixture.catalog.ID() || loaded.Revision() != fixture.catalog.Revision() ||
		loaded.Hash() != fixture.catalog.Hash() {
		t.Fatalf("loaded catalog = id %q revision %d hash %q, want id %q revision %d hash %q",
			loaded.ID(), loaded.Revision(), loaded.Hash(),
			fixture.catalog.ID(), fixture.catalog.Revision(), fixture.catalog.Hash())
	}

	entries := loaded.Entries()
	if len(entries) != 1 {
		t.Fatalf("loaded catalog holds %d entries, want exactly one", len(entries))
	}
	if entries[0].State != analytic.ProfileActive ||
		entries[0].Profile.Key() != fixture.profile.Key() ||
		entries[0].Profile.Hash() != fixture.profile.Hash() {
		t.Fatalf("loaded catalog entry = state %q key %v hash %q, want state %q key %v hash %q",
			entries[0].State, entries[0].Profile.Key(), entries[0].Profile.Hash(),
			analytic.ProfileActive, fixture.profile.Key(), fixture.profile.Hash())
	}

	active, resolved := loaded.ResolveActive(fixture.profile.Key(), fixture.profile.Hash())
	if !resolved {
		t.Fatalf("ResolveActive(%v, %q) did not resolve the loaded active profile",
			fixture.profile.Key(), fixture.profile.Hash())
	}
	if !active.Valid() || active.Hash() != fixture.profile.Hash() {
		t.Fatalf("resolved active profile valid = %v hash %q, want valid hash %q",
			active.Valid(), active.Hash(), fixture.profile.Hash())
	}

	if got, want := active.Source().Values(), fixture.source.Values(); got != want {
		t.Fatalf("loaded source DTO = %#v, want %#v", got, want)
	}

	fields, wantFields := active.Fields(), fixture.profile.Fields()
	if len(fields) != len(wantFields) || len(wantFields) != len(fixture.columns) {
		t.Fatalf("loaded profile holds %d fields, want %d", len(fields), len(fixture.columns))
	}
	for index, column := range fixture.columns {
		got, want := fields[index].Values(), wantFields[index].Values()
		if got.Token != column.token || got.SourceOrdinal != index+1 ||
			got.PhysicalName != column.physicalName ||
			got.LogicalType != column.logicalType || got.PhysicalType != column.physicalType ||
			got.Nullable != column.nullable || got.OutputAllowed != column.outputAllowed {
			t.Fatalf("loaded field %d identity = %#v, want token %q ordinal %d name %q logical %q physical %q nullable %v output %v",
				index+1, got, column.token, index+1, column.physicalName,
				column.logicalType, column.physicalType, column.nullable, column.outputAllowed)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("loaded field %d DTO = %#v, want %#v", index+1, got, want)
		}
	}

	measures, wantMeasures := active.Measures(), fixture.profile.Measures()
	if len(measures) != 1 || len(wantMeasures) != 1 {
		t.Fatalf("loaded profile holds %d measures, want exactly one", len(measures))
	}
	if got, want := measures[0].Values(), wantMeasures[0].Values(); got != want {
		t.Fatalf("loaded measure DTO = %#v, want %#v", got, want)
	}
	if got, want := active.Semantics().Values(), fixture.profile.Semantics().Values(); !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded semantics = %#v, want %#v", got, want)
	}
	if got, want := active.Grain().Values(), fixture.profile.Grain().Values(); !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded grain = %#v, want %#v", got, want)
	}
	if got, want := active.Time().Values(), fixture.profile.Time().Values(); got != want {
		t.Fatalf("loaded time policy = %#v, want %#v", got, want)
	}
	if got, want := active.Coverage(), fixture.profile.Coverage(); got != want {
		t.Fatalf("loaded coverage = %q, want %q", got, want)
	}
	if got, want := active.Limits().Values(), fixture.profile.Limits().Values(); got != want {
		t.Fatalf("loaded limits = %#v, want %#v", got, want)
	}
}
