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
	input := analytic.SourceProjectionInput{
		SourceScopeID: "scope-1", ConnectionID: "connection-1", DatabaseIdentity: "database-1",
		ProjectionLineageID: "lineage-1", ProjectionRevision: 4,
		ProjectionContractHash: validHash("a"), ExposedSchemaRevision: 9,
		ExposedSchemaHash: validHash("b"), SchemaName: "analytics$approved",
		RelationName: "orders_projection", RelationKind: analytic.RelationView,
	}
	spec, err := analytic.NewSourceProjectionSpec(input)
	if err != nil {
		t.Fatalf("fixture projection rejected: %v", err)
	}
	return matchFixture{
		expected: spec,
		source: sourceFacts{
			sourceScopeID: input.SourceScopeID, connectionID: input.ConnectionID,
			databaseIdentity: input.DatabaseIdentity, projectionLineageID: input.ProjectionLineageID,
			projectionRevision: input.ProjectionRevision, projectionContractHash: input.ProjectionContractHash,
			schemaName: input.SchemaName, relationName: input.RelationName,
			relationKind: input.RelationKind,
			columns:      []string{"order_id", "customer_id", "total_amount"},
		},
		exposure: exposureFacts{
			liveEnabled: true, exposedSchemaRevision: input.ExposedSchemaRevision,
			exposedSchemaHash: input.ExposedSchemaHash, schemaName: input.SchemaName,
			relationName: input.RelationName,
			columns:      []string{"order_id", "customer_id", "total_amount"},
		},
		required: []string{"order_id", "total_amount"},
	}
}

func validHash(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func TestMatchExactFactsSucceed(t *testing.T) {
	fixture := validMatchFixture(t)
	if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("exact facts refused: %v", err)
	}
	if err := match(fixture.expected, fixture.source.columns, fixture.source, fixture.exposure); err != nil {
		t.Fatalf("full-overlap facts refused: %v", err)
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
		{"source scope", func(f *matchFixture) { f.source.sourceScopeID = "scope-2" }},
		{"source scope empty", func(f *matchFixture) { f.source.sourceScopeID = "" }},
		{"connection", func(f *matchFixture) { f.source.connectionID = "connection-2" }},
		{"connection empty", func(f *matchFixture) { f.source.connectionID = "" }},
		{"database", func(f *matchFixture) { f.source.databaseIdentity = "database-2" }},
		{"database empty", func(f *matchFixture) { f.source.databaseIdentity = "" }},
		{"lineage", func(f *matchFixture) { f.source.projectionLineageID = "lineage-2" }},
		{"lineage empty", func(f *matchFixture) { f.source.projectionLineageID = "" }},
		{"revision behind", func(f *matchFixture) { f.source.projectionRevision = 3 }},
		{"revision ahead", func(f *matchFixture) { f.source.projectionRevision = 5 }},
		{"revision zero", func(f *matchFixture) { f.source.projectionRevision = 0 }},
		{"revision negative", func(f *matchFixture) { f.source.projectionRevision = -4 }},
		{"contract hash", func(f *matchFixture) { f.source.projectionContractHash = validHash("c") }},
		{"contract hash empty", func(f *matchFixture) { f.source.projectionContractHash = "" }},
		{"schema", func(f *matchFixture) { f.source.schemaName = "analytics_other" }},
		{"schema case", func(f *matchFixture) { f.source.schemaName = "ANALYTICS$APPROVED" }},
		{"relation", func(f *matchFixture) { f.source.relationName = "orders_projection_v2" }},
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
		{"schema", func(f *matchFixture) { f.exposure.schemaName = "analytics_other" }},
		{"schema case", func(f *matchFixture) { f.exposure.schemaName = "ANALYTICS$APPROVED" }},
		{"relation", func(f *matchFixture) { f.exposure.relationName = "orders_projection_v2" }},
		{"relation empty", func(f *matchFixture) { f.exposure.relationName = "" }},
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
	driftedSource.sourceScopeID = "other-scope"
	driftedSource.columns = []string{"other_column"}
	driftedExposure := fixture.exposure
	driftedExposure.liveEnabled = false
	refusals := []error{
		match(analytic.SourceProjectionSpec{}, fixture.required, fixture.source, fixture.exposure),
		match(fixture.expected, nil, fixture.source, fixture.exposure),
		match(fixture.expected, fixture.required, driftedSource, fixture.exposure),
		match(fixture.expected, fixture.required, fixture.source, driftedExposure),
		match(fixture.expected, []string{"missing_column"}, fixture.source, fixture.exposure),
	}
	identities := []string{
		fixture.source.sourceScopeID, fixture.source.connectionID, fixture.source.databaseIdentity,
		fixture.source.projectionLineageID, fixture.source.projectionContractHash,
		fixture.exposure.exposedSchemaHash, fixture.source.schemaName, fixture.source.relationName,
		"order_id", "total_amount", "other-scope", "other_column", "missing_column",
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
