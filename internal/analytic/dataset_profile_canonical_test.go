package analytic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

func TestDatasetProfileCanonicalNormalizesOrderAndIsDeterministic(t *testing.T) {
	left := validDatasetProfileSpec(t)
	right := validDatasetProfileSpec(t)
	reverseFields(right.Fields)
	reverseMeasures(right.Measures)
	leftBytes, leftHash := canonicalProfileForTest(t, left)
	rightBytes, rightHash := canonicalProfileForTest(t, right)
	if !bytes.Equal(leftBytes, rightBytes) || leftHash != rightHash {
		t.Fatal("normalized input order changed canonical identity")
	}
	againBytes, againHash := canonicalProfileForTest(t, left)
	if !bytes.Equal(leftBytes, againBytes) || leftHash != againHash {
		t.Fatal("canonical identity is not deterministic")
	}
	if !bytes.Contains(leftBytes, []byte(`"schema_version":"knowvault-dataset-profile-v1"`)) {
		t.Fatalf("schema version missing: %s", leftBytes)
	}
	if bytes.Contains(leftBytes, []byte(":null")) {
		t.Fatalf("canonical profile contains null: %s", leftBytes)
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(leftHash) {
		t.Fatalf("non-canonical hash %q", leftHash)
	}
	digest := sha256.Sum256(leftBytes)
	if want := "sha256:" + hex.EncodeToString(digest[:]); leftHash != want {
		t.Fatalf("hash = %q, want independently computed %q", leftHash, want)
	}
	for _, member := range []string{
		`"key":{"dataset_id":"operations","version":1}`,
		`"mode":"LIVE"`,
		`"source":{"connection_id":"primary","database_identity":"gm","exposed_schema_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222","exposed_schema_revision":1,"projection_contract_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","projection_lineage_id":"operations","projection_revision":1,"relation_kind":"VIEW","relation_name":"operations","schema_name":"public","source_scope_id":"gm"}`,
		`{"allowed_ops":[],"filterable":false,"groupable":false,"logical_type":"TEXT","nullable":false,"output_allowed":true,"physical_name":"object_id","physical_type":"PG_TEXT","sortable":false,"source_ordinal":1,"token":"object_id"}`,
		`{"denominator_field":"","distinct_field":"","eligibility":"ALL_ROWS","id":"amount","null_policy":"EXCLUDE_AND_REPORT","numerator_field":"amount","reducer":"SUM","unit":"units"}`,
		`"time":{"calendar":"","field_token":"","kind":"NONE","reporting_timezone":"","source_timezone":""}`,
		`"coverage":"UNKNOWN"`,
		`"limits":{"max_input_rows":1000,"max_output_groups":20,"max_period_days":31,"max_result_bytes":1048576,"statement_timeout_ms":5000}`,
	} {
		if !bytes.Contains(leftBytes, []byte(member)) {
			t.Fatalf("canonical profile missing member %s: %s", member, leftBytes)
		}
	}
}

func TestDatasetProfileCanonicalEveryIdentityMemberChangesHash(t *testing.T) {
	cases := map[string]func(*testing.T, *DatasetProfileSpec){
		"dataset id": func(t *testing.T, spec *DatasetProfileSpec) {
			spec.Key = mustProfileKey(t, "operations_alt", spec.Key.Version())
		},
		"source scope": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.SourceScopeID = "gm_alt" })
		},
		"connection id": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.ConnectionID = "secondary" })
		},
		"database identity": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.DatabaseIdentity = "gm_alt" })
		},
		"projection lineage": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.ProjectionLineageID = "operations_alt" })
		},
		"projection revision": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.ProjectionRevision++ })
		},
		"projection contract hash": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.ProjectionContractHash = "sha256:" + strings.Repeat("3", 64) })
		},
		"exposed schema hash": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.ExposedSchemaHash = "sha256:" + strings.Repeat("4", 64) })
		},
		"exposed schema revision": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.ExposedSchemaRevision++ })
		},
		"schema name": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.SchemaName = "reporting" })
		},
		"relation name": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.RelationName = "operations_alt" })
		},
		"relation kind": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateSource(t, spec, func(v *SourceProjectionInput) { v.RelationKind = RelationMaterializedView })
		},
		"field token": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "object_id", func(v *FieldSpecInput) { v.Token = "record_id" })
		},
		"physical field name": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.PhysicalName = "amount_total" })
		},
		"swapped ordinals": func(t *testing.T, spec *DatasetProfileSpec) {
			first, second := spec.Fields[0].Values(), spec.Fields[1].Values()
			first.SourceOrdinal, second.SourceOrdinal = second.SourceOrdinal, first.SourceOrdinal
			spec.Fields[0] = mustField(t, first)
			spec.Fields[1] = mustField(t, second)
		},
		"logical and physical type": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.LogicalType, v.PhysicalType = ScalarInt, PhysicalPGInt8 })
		},
		"permission flag": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.Nullable = !v.Nullable })
		},
		"filter and allowed ops": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.Filterable = true; v.AllowedOps = []PredicateOperator{PredicateEQ} })
		},
		"groupable": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.Groupable = true })
		},
		"sortable": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.Sortable = true })
		},
		"output allowed": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateField(t, spec, "amount", func(v *FieldSpecInput) { v.OutputAllowed = false })
		},
		"measure id": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateMeasure(t, spec, "amount", func(v *MeasureSpecInput) { v.ID = "amount_total" })
		},
		"unit": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateMeasure(t, spec, "amount", func(v *MeasureSpecInput) { v.Unit = "currency" })
		},
		"null policy": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateMeasure(t, spec, "amount", func(v *MeasureSpecInput) { v.NullPolicy = NullRequireComplete })
		},
		"time policy": func(t *testing.T, spec *DatasetProfileSpec) {
			spec.Time = profileTime(t, TimeBusinessDate, "business_day")
		},
		"coverage": func(_ *testing.T, spec *DatasetProfileSpec) { spec.Coverage = CoverageSourceGuaranteed },
		"limit": func(t *testing.T, spec *DatasetProfileSpec) {
			value := spec.Limits.Values()
			value.MaxOutputGroups++
			spec.Limits = mustLimits(t, value)
		},
		"max input rows": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateLimits(t, spec, func(v *ProfileLimitsInput) { v.MaxInputRows++ })
		},
		"max period days": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateLimits(t, spec, func(v *ProfileLimitsInput) { v.MaxPeriodDays-- })
		},
		"max result bytes": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateLimits(t, spec, func(v *ProfileLimitsInput) { v.MaxResultBytes++ })
		},
		"statement timeout": func(t *testing.T, spec *DatasetProfileSpec) {
			mutateLimits(t, spec, func(v *ProfileLimitsInput) { v.StatementTimeoutMS++ })
		},
		"profile version": func(t *testing.T, spec *DatasetProfileSpec) {
			spec.Key = mustProfileKey(t, spec.Key.DatasetID(), spec.Key.Version()+1)
		},
	}
	_, baselineHash := canonicalProfileForTest(t, validDatasetProfileSpec(t))
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			mutate(t, &spec)
			_, changedHash := canonicalProfileForTest(t, spec)
			if changedHash == baselineHash {
				t.Fatal("valid identity mutation did not change hash")
			}
		})
	}
}

func TestDatasetProfileCanonicalMeasureOperandChangesHash(t *testing.T) {
	left := validDatasetProfileSpec(t)
	right := validDatasetProfileSpec(t)
	for _, spec := range []*DatasetProfileSpec{&left, &right} {
		spec.Fields = append(spec.Fields, profileField(t, "amount_net", "amount_net", 6, ScalarNumeric, true))
	}
	mutateMeasure(t, &right, "amount", func(value *MeasureSpecInput) { value.NumeratorField = "amount_net" })
	_, leftHash := canonicalProfileForTest(t, left)
	_, rightHash := canonicalProfileForTest(t, right)
	if leftHash == rightHash {
		t.Fatal("measure operand did not change hash")
	}
}

func canonicalProfileForTest(t *testing.T, spec DatasetProfileSpec) ([]byte, string) {
	t.Helper()
	normalized, err := normalizeDatasetProfileSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	value, hash, err := canonicalDatasetProfile(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return value, hash
}

func reverseFields(values []FieldSpec) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
func reverseMeasures(values []MeasureSpec) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func mutateSource(t *testing.T, spec *DatasetProfileSpec, mutate func(*SourceProjectionInput)) {
	t.Helper()
	value := spec.Source.Values()
	mutate(&value)
	var err error
	spec.Source, err = NewSourceProjectionSpec(value)
	if err != nil {
		t.Fatal(err)
	}
}
func mutateField(t *testing.T, spec *DatasetProfileSpec, token string, mutate func(*FieldSpecInput)) {
	t.Helper()
	for index := range spec.Fields {
		value := spec.Fields[index].Values()
		if value.Token == token {
			mutate(&value)
			spec.Fields[index] = mustField(t, value)
			return
		}
	}
	t.Fatalf("field %q not found", token)
}
func mutateMeasure(t *testing.T, spec *DatasetProfileSpec, id string, mutate func(*MeasureSpecInput)) {
	t.Helper()
	for index := range spec.Measures {
		value := spec.Measures[index].Values()
		if value.ID == id {
			mutate(&value)
			spec.Measures[index] = profileMeasure(t, value)
			return
		}
	}
	t.Fatalf("measure %q not found", id)
}
func mutateLimits(t *testing.T, spec *DatasetProfileSpec, mutate func(*ProfileLimitsInput)) {
	t.Helper()
	value := spec.Limits.Values()
	mutate(&value)
	spec.Limits = mustLimits(t, value)
}
func mustField(t *testing.T, value FieldSpecInput) FieldSpec {
	t.Helper()
	result, err := NewFieldSpec(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func mustLimits(t *testing.T, value ProfileLimitsInput) ProfileLimits {
	t.Helper()
	result, err := NewProfileLimits(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func mustProfileKey(t *testing.T, id string, version int64) ProfileKey {
	t.Helper()
	result, err := NewProfileKey(id, version)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
