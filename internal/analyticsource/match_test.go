package analyticsource

import (
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

type matchFixture struct {
	expected analytic.SourceProjectionSpec
	source   sourceFacts
	exposure exposureFacts
	required []string
}

func validMatchFixture(t *testing.T) matchFixture {
	t.Helper()
	binding := bindingFacts{
		workspaceID: "workspace-1", workspaceRevision: 12,
		workspaceConfigurationHash: validHash("e"), workspaceSourceID: "workspace-source-1",
		sourceScopeID: "scope-1", sourceScopeRevision: 7,
		sourceScopeConfigurationHash: validHash("f"),
		connectionID:                 "connection-1", connectionRevision: 3,
		databaseIdentity: "database-1", schemaName: "analytics$approved",
		relationName: "orders_projection",
	}
	input := analytic.SourceProjectionInput{
		SourceScopeID: binding.sourceScopeID, ConnectionID: binding.connectionID,
		DatabaseIdentity: binding.databaseIdentity, ProjectionLineageID: "lineage-1",
		ProjectionRevision: 4, ProjectionContractHash: validHash("a"),
		ExposedSchemaRevision: 9, ExposedSchemaHash: validHash("b"),
		SchemaName: binding.schemaName, RelationName: binding.relationName,
		RelationKind: analytic.RelationView,
	}
	spec, err := analytic.NewSourceProjectionSpec(input)
	if err != nil {
		t.Fatalf("fixture projection rejected: %v", err)
	}
	return matchFixture{
		expected: spec,
		source: sourceFacts{
			binding: binding, projectionLineageID: input.ProjectionLineageID,
			projectionRevision:     input.ProjectionRevision,
			projectionContractHash: input.ProjectionContractHash,
			relationKind:           input.RelationKind,
			columns:                []string{"order_id", "customer_id", "total_amount"},
		},
		exposure: exposureFacts{
			binding: binding, liveEnabled: true,
			exposedSchemaRevision: input.ExposedSchemaRevision,
			exposedSchemaHash:     input.ExposedSchemaHash,
			columns:               []string{"order_id", "customer_id", "total_amount"},
		},
		required: []string{"order_id", "total_amount"},
	}
}

func validHash(character string) string { return "sha256:" + strings.Repeat(character, 64) }

// bindingKind is the value family one common binding field carries, so mutation
// tables apply the value the field actually accepts.
type bindingKind int

const (
	kindIdentity bindingKind = iota
	kindRevision
	kindHash
	kindIdentifier
)

// bindingFieldCount fences the common binding inventory at twelve fields: a
// dropped field must fail loudly instead of quietly thinning every table.
const bindingFieldCount = 12

// commonBindingField names one common binding field with a fixture-free setter,
// so every drift and malformed-value table is generated from one inventory.
type commonBindingField struct {
	name        string
	kind        bindingKind
	setText     func(*bindingFacts, string)
	setRevision func(*bindingFacts, int64)
}

// commonBindingFields enumerates the twelve common binding fields in fixture
// order.
func commonBindingFields() []commonBindingField {
	return []commonBindingField{
		{name: "workspace id", kind: kindIdentity,
			setText: func(binding *bindingFacts, value string) { binding.workspaceID = value }},
		{name: "workspace revision", kind: kindRevision,
			setRevision: func(binding *bindingFacts, value int64) { binding.workspaceRevision = value }},
		{name: "workspace configuration hash", kind: kindHash,
			setText: func(binding *bindingFacts, value string) { binding.workspaceConfigurationHash = value }},
		{name: "workspace source id", kind: kindIdentity,
			setText: func(binding *bindingFacts, value string) { binding.workspaceSourceID = value }},
		{name: "source scope id", kind: kindIdentity,
			setText: func(binding *bindingFacts, value string) { binding.sourceScopeID = value }},
		{name: "source scope revision", kind: kindRevision,
			setRevision: func(binding *bindingFacts, value int64) { binding.sourceScopeRevision = value }},
		{name: "source scope configuration hash", kind: kindHash,
			setText: func(binding *bindingFacts, value string) { binding.sourceScopeConfigurationHash = value }},
		{name: "connection id", kind: kindIdentity,
			setText: func(binding *bindingFacts, value string) { binding.connectionID = value }},
		{name: "connection revision", kind: kindRevision,
			setRevision: func(binding *bindingFacts, value int64) { binding.connectionRevision = value }},
		{name: "database identity", kind: kindIdentity,
			setText: func(binding *bindingFacts, value string) { binding.databaseIdentity = value }},
		{name: "schema", kind: kindIdentifier,
			setText: func(binding *bindingFacts, value string) { binding.schemaName = value }},
		{name: "relation", kind: kindIdentifier,
			setText: func(binding *bindingFacts, value string) { binding.relationName = value }},
	}
}

// The values below differ from every fixture identity, revision, and hash, so
// an alternate written to either side breaks equality.
const (
	alternateIdentity   = "other-1"
	alternateIdentifier = "other_identifier"
	alternateRevision   = 1
)

// setAlternate writes a different value that is still valid for this field.
func (field commonBindingField) setAlternate(binding *bindingFacts) {
	switch field.kind {
	case kindRevision:
		field.setRevision(binding, alternateRevision)
	case kindHash:
		field.setText(binding, validHash("c"))
	case kindIdentifier:
		field.setText(binding, alternateIdentifier)
	default:
		field.setText(binding, alternateIdentity)
	}
}

// bindingSide names one trusted side and locates its common binding value.
type bindingSide struct {
	name    string
	binding func(*matchFixture) *bindingFacts
}

// bindingSides lists the two trusted sides that report a common binding value.
func bindingSides() []bindingSide {
	return []bindingSide{
		{"source", func(fixture *matchFixture) *bindingFacts { return &fixture.source.binding }},
		{"exposure", func(fixture *matchFixture) *bindingFacts { return &fixture.exposure.binding }},
	}
}

// bindingShapeCase is one malformed value applied to every common binding field
// of its kind.
type bindingShapeCase struct {
	name     string
	kind     bindingKind
	text     string
	revision int64
}

// bindingShapeCases lists representative malformed values per value family.
func bindingShapeCases() []bindingShapeCase {
	return []bindingShapeCase{
		{name: "empty", kind: kindIdentity, text: ""},
		{name: "untrimmed", kind: kindIdentity, text: " identity "},
		{name: "c0 control", kind: kindIdentity, text: "identity\x00"},
		{name: "delete control", kind: kindIdentity, text: "identity\x7f"},
		{name: "c1 control", kind: kindIdentity, text: "identity\u0085"},
		{name: "invalid utf8", kind: kindIdentity, text: string([]byte{0xff, 0xfe})},
		{name: "oversize", kind: kindIdentity, text: strings.Repeat("i", 257)},
		{name: "zero", kind: kindRevision, revision: 0},
		{name: "negative", kind: kindRevision, revision: -1},
		{name: "above max", kind: kindRevision, revision: maxBindingRevision + 1},
		{name: "empty", kind: kindHash, text: ""},
		{name: "wrong prefix", kind: kindHash, text: "sha512:" + strings.Repeat("a", 64)},
		{name: "uppercase", kind: kindHash, text: "sha256:" + strings.Repeat("A", 64)},
		{name: "non hex", kind: kindHash, text: "sha256:" + strings.Repeat("g", 64)},
		{name: "short", kind: kindHash, text: "sha256:" + strings.Repeat("a", 63)},
		{name: "empty", kind: kindIdentifier, text: ""},
		{name: "quoted", kind: kindIdentifier, text: `"schema"`},
		{name: "leading digit", kind: kindIdentifier, text: "1schema"},
		{name: "leading dollar", kind: kindIdentifier, text: "$schema"},
		{name: "embedded space", kind: kindIdentifier, text: "schema name"},
		{name: "oversize", kind: kindIdentifier, text: strings.Repeat("s", 64)},
	}
}

// apply writes the malformed value into one field of binding.
func (shape bindingShapeCase) apply(binding *bindingFacts, field commonBindingField) {
	if field.kind == kindRevision {
		field.setRevision(binding, shape.revision)
		return
	}
	field.setText(binding, shape.text)
}

// The fixture populates all twelve common binding fields, so the exact case
// below exercises a fully populated common binding.
func TestMatchExactFactsSucceed(t *testing.T) {
	fixture := validMatchFixture(t)
	if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("exact facts refused: %v", err)
	}
	if err := match(fixture.expected, fixture.source.columns, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("full-overlap facts refused: %v", err)
	}
}

func TestMatchRefusesCommonBindingDrift(t *testing.T) {
	fields := commonBindingFields()
	if len(fields) != bindingFieldCount {
		t.Fatalf("common binding inventory has %d fields, want %d", len(fields), bindingFieldCount)
	}
	for _, side := range bindingSides() {
		for _, field := range fields {
			t.Run(side.name+"/"+field.name, func(t *testing.T) {
				fixture := validMatchFixture(t)
				field.setAlternate(side.binding(&fixture))
				if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
					t.Fatalf("common binding drift accepted: err=%v", err)
				}
			})
		}
	}
}

// Malformed values are written to both sides, so the two bindings stay equal and
// only the shape validation under test can refuse them.
func TestMatchRefusesMalformedCommonBindingValues(t *testing.T) {
	for _, field := range commonBindingFields() {
		for _, shape := range bindingShapeCases() {
			if shape.kind != field.kind {
				continue
			}
			t.Run(field.name+"/"+shape.name, func(t *testing.T) {
				fixture := validMatchFixture(t)
				for _, side := range bindingSides() {
					shape.apply(side.binding(&fixture), field)
				}
				if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
					t.Fatalf("malformed common binding accepted: err=%v", err)
				}
			})
		}
	}
}

func TestMatchAcceptsBoundaryCommonBindingValues(t *testing.T) {
	fixture := validMatchFixture(t)
	binding := fixture.source.binding
	binding.workspaceID = strings.Repeat("w", 256)
	binding.workspaceSourceID = "w"
	binding.workspaceRevision = maxBindingRevision
	binding.sourceScopeRevision = 1
	binding.connectionRevision = 1
	binding.workspaceConfigurationHash = validHash("c")
	binding.sourceScopeConfigurationHash = validHash("d")
	fixture.source.binding, fixture.exposure.binding = binding, binding
	if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("boundary common binding refused: %v", err)
	}
}

// The approved projection does not name a workspace, so this matcher proves only
// that both sides report one valid equal tuple. A different but internally equal
// workspace binding still matches; current workspace authority belongs to the
// future trusted adapters and resolver.
func TestMatchAcceptsAlternateEqualWorkspaceBinding(t *testing.T) {
	fixture := validMatchFixture(t)
	alternate := fixture.source.binding
	alternate.workspaceID = "workspace-2"
	alternate.workspaceRevision = 42
	alternate.workspaceConfigurationHash = validHash("c")
	alternate.workspaceSourceID = "workspace-source-2"
	fixture.source.binding, fixture.exposure.binding = alternate, alternate
	if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("alternate equal workspace binding refused: %v", err)
	}
}

func TestMatchRefusesZeroExpectedAndZeroOrInactiveFacts(t *testing.T) {
	fixture := validMatchFixture(t)
	if err := match(analytic.SourceProjectionSpec{}, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
		t.Fatalf("zero expected accepted: err=%v", err)
	}
	if err := match(fixture.expected, fixture.required, sourceFacts{}, fixture.exposure); err != errMismatch {
		t.Fatalf("zero source facts accepted: err=%v", err)
	}
	if err := match(fixture.expected, fixture.required, fixture.source, exposureFacts{}); err != errMismatch {
		t.Fatalf("zero exposure facts accepted: err=%v", err)
	}
	fixture.exposure.liveEnabled = false
	if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
		t.Fatalf("inactive exposure accepted: err=%v", err)
	}
}

func TestMatchRefusesSourceIdentityDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*matchFixture)
	}{
		{"lineage", func(f *matchFixture) { f.source.projectionLineageID = "lineage-2" }},
		{"lineage empty", func(f *matchFixture) { f.source.projectionLineageID = "" }},
		{"revision behind", func(f *matchFixture) { f.source.projectionRevision = 3 }},
		{"revision ahead", func(f *matchFixture) { f.source.projectionRevision = 5 }},
		{"revision zero", func(f *matchFixture) { f.source.projectionRevision = 0 }},
		{"revision negative", func(f *matchFixture) { f.source.projectionRevision = -4 }},
		{"contract hash", func(f *matchFixture) { f.source.projectionContractHash = validHash("c") }},
		{"contract hash empty", func(f *matchFixture) { f.source.projectionContractHash = "" }},
		{"relation kind", func(f *matchFixture) { f.source.relationKind = analytic.RelationMaterializedView }},
		{"relation kind unknown", func(f *matchFixture) { f.source.relationKind = "TABLE" }},
		{"relation kind empty", func(f *matchFixture) { f.source.relationKind = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validMatchFixture(t)
			test.mutate(&fixture)
			if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
				t.Fatalf("source drift accepted: err=%v", err)
			}
		})
	}
}

func TestMatchRefusesExposureDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*matchFixture)
	}{
		{"live disabled", func(f *matchFixture) { f.exposure.liveEnabled = false }},
		{"schema revision behind", func(f *matchFixture) { f.exposure.exposedSchemaRevision = 8 }},
		{"schema revision ahead", func(f *matchFixture) { f.exposure.exposedSchemaRevision = 10 }},
		{"schema revision zero", func(f *matchFixture) { f.exposure.exposedSchemaRevision = 0 }},
		{"schema hash", func(f *matchFixture) { f.exposure.exposedSchemaHash = validHash("d") }},
		{"schema hash empty", func(f *matchFixture) { f.exposure.exposedSchemaHash = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validMatchFixture(t)
			test.mutate(&fixture)
			if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
				t.Fatalf("exposure drift accepted: err=%v", err)
			}
		})
	}
}

func TestMatchRefusesMissingRequiredColumn(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*matchFixture)
	}{
		{"absent from source", func(f *matchFixture) { f.source.columns = []string{"order_id", "customer_id"} }},
		{"absent from exposure", func(f *matchFixture) { f.exposure.columns = []string{"customer_id", "total_amount"} }},
		{"absent from both", func(f *matchFixture) { f.required = []string{"order_id", "missing_column"} }},
		{"only case difference", func(f *matchFixture) { f.required = []string{"ORDER_ID"} }},
		{"absent valid name", func(f *matchFixture) { f.required = []string{"order_id", "shipment_id"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validMatchFixture(t)
			test.mutate(&fixture)
			if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
				t.Fatalf("missing required column accepted: err=%v", err)
			}
		})
	}
}

func TestMatchRefusesInvalidRequiredColumns(t *testing.T) {
	tests := []struct {
		name     string
		required []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"empty name", []string{""}},
		{"duplicate", []string{"order_id", "order_id"}},
		{"leading digit", []string{"1order"}},
		{"leading dollar", []string{"$order"}},
		{"embedded space", []string{"order id"}},
		{"double quoted", []string{`"order_id"`}},
		{"sql punctuation", []string{"order_id;drop table orders"}},
		{"non ascii", []string{"order_üd"}},
		{"too long", []string{strings.Repeat("a", 64)}},
		{"nul byte", []string{"order\x00id"}},
		{"newline", []string{"order\nid"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validMatchFixture(t)
			if err := match(fixture.expected, test.required, fixture.source, fixture.exposure); err != errMismatch {
				t.Fatalf("invalid required columns accepted: err=%v", err)
			}
		})
	}
	fixture := validMatchFixture(t)
	bounded := strings.Repeat("a", 63)
	fixture.source.columns = append(fixture.source.columns, bounded)
	fixture.exposure.columns = append(fixture.exposure.columns, bounded)
	if err := match(fixture.expected, []string{bounded}, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("63-byte identifier refused: %v", err)
	}
}

func TestMatchRefusesInvalidFactColumns(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*matchFixture)
	}{
		{"source empty", func(f *matchFixture) { f.source.columns = nil }},
		{"source empty list", func(f *matchFixture) { f.source.columns = []string{} }},
		{"source empty name", func(f *matchFixture) { f.source.columns = []string{"order_id", "total_amount", ""} }},
		{"source duplicate", func(f *matchFixture) { f.source.columns = []string{"order_id", "order_id", "total_amount"} }},
		{"source malformed", func(f *matchFixture) { f.source.columns = []string{"order_id", "total_amount", "9bad"} }},
		{"source too long", func(f *matchFixture) {
			f.source.columns = []string{"order_id", "total_amount", strings.Repeat("a", 64)}
		}},
		{"exposure empty", func(f *matchFixture) { f.exposure.columns = nil }},
		{"exposure empty list", func(f *matchFixture) { f.exposure.columns = []string{} }},
		{"exposure empty name", func(f *matchFixture) { f.exposure.columns = []string{"order_id", "total_amount", ""} }},
		{"exposure duplicate", func(f *matchFixture) { f.exposure.columns = []string{"order_id", "order_id", "total_amount"} }},
		{"exposure malformed", func(f *matchFixture) { f.exposure.columns = []string{"order_id", "total_amount", "order id"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validMatchFixture(t)
			test.mutate(&fixture)
			if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
				t.Fatalf("invalid fact columns accepted: err=%v", err)
			}
		})
	}
}

func TestMatchAllowsExtraValidFactColumns(t *testing.T) {
	fixture := validMatchFixture(t)
	fixture.source.columns = append(fixture.source.columns, "internal_note", "_audit$1", strings.Repeat("z", 63))
	fixture.exposure.columns = append(fixture.exposure.columns, "internal_note", "unapproved_extra")
	if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("extra valid fact columns refused: %v", err)
	}
}

func TestMatchRefusalsAreOneContentFreeSentinel(t *testing.T) {
	fixture := validMatchFixture(t)
	driftedSource := fixture.source
	driftedSource.binding.sourceScopeID = "refusal-scope"
	driftedSource.binding.workspaceConfigurationHash = validHash("c")
	driftedSource.columns = []string{"other_column"}
	driftedExposure := fixture.exposure
	driftedExposure.binding.workspaceID = "refusal-workspace"
	driftedExposure.liveEnabled = false
	malformedSource, malformedExposure := fixture.source, fixture.exposure
	malformedSource.binding.workspaceSourceID = "refusal\x00source"
	malformedExposure.binding.workspaceSourceID = "refusal\x00source"
	refusals := []error{
		match(analytic.SourceProjectionSpec{}, fixture.required, fixture.source, fixture.exposure),
		match(fixture.expected, nil, fixture.source, fixture.exposure),
		match(fixture.expected, fixture.required, sourceFacts{}, fixture.exposure),
		match(fixture.expected, fixture.required, fixture.source, exposureFacts{}),
		match(fixture.expected, fixture.required, driftedSource, fixture.exposure),
		match(fixture.expected, fixture.required, fixture.source, driftedExposure),
		match(fixture.expected, fixture.required, malformedSource, malformedExposure),
		match(fixture.expected, []string{"missing_column"}, fixture.source, fixture.exposure),
	}
	identities := []string{
		fixture.source.binding.workspaceID, fixture.source.binding.workspaceSourceID,
		fixture.source.binding.sourceScopeID, fixture.source.binding.connectionID,
		fixture.source.binding.databaseIdentity, fixture.source.binding.schemaName,
		fixture.source.binding.relationName, fixture.source.binding.workspaceConfigurationHash,
		fixture.source.binding.sourceScopeConfigurationHash,
		fixture.source.projectionLineageID, fixture.source.projectionContractHash,
		fixture.exposure.exposedSchemaHash,
		"refusal-scope", "refusal-workspace", "refusal\x00source", validHash("c"),
		"other_column", "missing_column",
	}
	if errMismatch == nil || errMismatch.Error() == "" {
		t.Fatal("sentinel error is empty")
	}
	for index, err := range refusals {
		if err != errMismatch || !errors.Is(err, errMismatch) {
			t.Fatalf("refusal %d is not the sentinel: %v", index, err)
		}
		if err.Error() != errMismatch.Error() {
			t.Fatalf("refusal %d has a distinct message: %q", index, err.Error())
		}
		for _, identity := range identities {
			if strings.Contains(err.Error(), identity) {
				t.Fatalf("refusal %d discloses identity %q", index, identity)
			}
		}
	}
}
