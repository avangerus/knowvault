package analytic

import (
	"strings"
	"testing"
)

func TestDatasetProfileIdentityEnumsAreClosed(t *testing.T) {
	if !ExecutionLive.Valid() || ExecutionMode("").Valid() || ExecutionMode("live").Valid() || ExecutionMode("SNAPSHOT").Valid() {
		t.Fatal("execution mode set is not closed")
	}
	if !RelationView.Valid() || !RelationMaterializedView.Valid() || RelationKind("").Valid() || RelationKind("view").Valid() || RelationKind("TABLE").Valid() {
		t.Fatal("relation kind set is not closed")
	}
}

func TestDatasetProfileIdentityKeyValidation(t *testing.T) {
	valid256 := strings.Repeat("a", 256)
	multibyte256 := strings.Repeat("é", 128)
	for _, candidate := range []string{"dataset", valid256, multibyte256} {
		key, err := NewProfileKey(candidate, 1)
		if err != nil || !key.Valid() || key.DatasetID() != candidate || key.Version() != 1 {
			t.Fatalf("valid key rejected: bytes=%d err=%v", len(candidate), err)
		}
	}
	invalid := []struct {
		id      string
		version int64
	}{
		{"", 1}, {" dataset", 1}, {"dataset ", 1}, {"data\nset", 1}, {"data\u0085set", 1},
		{strings.Repeat("a", 257), 1}, {strings.Repeat("é", 129), 1},
		{string([]byte{0xff}), 1}, {"dataset", 0}, {"dataset", -1},
	}
	for _, candidate := range invalid {
		if key, err := NewProfileKey(candidate.id, candidate.version); err == nil || CodeOf(err) != CodeInvalidRequest || key.Valid() {
			t.Fatalf("invalid key accepted: bytes=%d version=%d", len(candidate.id), candidate.version)
		}
	}
	if (ProfileKey{}).Valid() {
		t.Fatal("zero key is valid")
	}
}

func TestDatasetProfileIdentitySourceRoundTripAndCopy(t *testing.T) {
	input := validSourceProjectionInput()
	spec, err := NewSourceProjectionSpec(input)
	if err != nil || !spec.Valid() || spec.Values() != input {
		t.Fatalf("valid source rejected: value=%+v err=%v", spec.Values(), err)
	}
	detached := spec.Values()
	detached.SourceScopeID = "mutated"
	detached.SchemaName = "mutated"
	if spec.Values() != input {
		t.Fatal("mutating returned DTO changed immutable spec")
	}
	if (SourceProjectionSpec{}).Valid() {
		t.Fatal("zero source spec is valid")
	}
}

func TestDatasetProfileIdentityRejectsMissingOrUnknownSourceMembers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SourceProjectionInput)
	}{
		{"source scope", func(v *SourceProjectionInput) { v.SourceScopeID = "" }},
		{"connection", func(v *SourceProjectionInput) { v.ConnectionID = "" }},
		{"database", func(v *SourceProjectionInput) { v.DatabaseIdentity = "" }},
		{"lineage", func(v *SourceProjectionInput) { v.ProjectionLineageID = "" }},
		{"projection revision", func(v *SourceProjectionInput) { v.ProjectionRevision = 0 }},
		{"contract hash", func(v *SourceProjectionInput) { v.ProjectionContractHash = "" }},
		{"schema revision", func(v *SourceProjectionInput) { v.ExposedSchemaRevision = 0 }},
		{"schema hash", func(v *SourceProjectionInput) { v.ExposedSchemaHash = "" }},
		{"schema", func(v *SourceProjectionInput) { v.SchemaName = "" }},
		{"relation", func(v *SourceProjectionInput) { v.RelationName = "" }},
		{"kind", func(v *SourceProjectionInput) { v.RelationKind = "TABLE" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validSourceProjectionInput()
			test.mutate(&input)
			if spec, err := NewSourceProjectionSpec(input); err == nil || CodeOf(err) != CodeInvalidRequest || spec.Valid() {
				t.Fatalf("invalid source accepted: %+v", input)
			}
		})
	}
}

func TestDatasetProfileIdentityRejectsMalformedHashes(t *testing.T) {
	bad := []string{
		"SHA256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("g", 64), "md5:" + strings.Repeat("a", 64),
	}
	for _, candidate := range bad {
		for _, contractHash := range []bool{true, false} {
			input := validSourceProjectionInput()
			if contractHash {
				input.ProjectionContractHash = candidate
			} else {
				input.ExposedSchemaHash = candidate
			}
			if _, err := NewSourceProjectionSpec(input); err == nil || CodeOf(err) != CodeInvalidRequest {
				t.Fatalf("malformed hash accepted: %q", candidate)
			}
		}
	}
}

func TestDatasetProfileIdentityProjectionIdentifiers(t *testing.T) {
	for _, field := range []string{"schema", "relation"} {
		for _, candidate := range []string{"bad.name", "bad;drop", "9bad", strings.Repeat("a", 64), "ümlaut"} {
			input := validSourceProjectionInput()
			if field == "schema" {
				input.SchemaName = candidate
			} else {
				input.RelationName = candidate
			}
			if _, err := NewSourceProjectionSpec(input); err == nil {
				t.Fatalf("invalid %s identifier accepted: %q", field, candidate)
			}
		}
	}
	input := validSourceProjectionInput()
	input.SchemaName = "schema$1"
	input.RelationName = "_relation$2"
	if _, err := NewSourceProjectionSpec(input); err != nil {
		t.Fatalf("valid dollar identifiers rejected: %v", err)
	}
}

func TestDatasetProfileIdentityOpaqueSourceIDsAreBounded(t *testing.T) {
	mutations := []func(*SourceProjectionInput){
		func(v *SourceProjectionInput) { v.SourceScopeID = " scope" },
		func(v *SourceProjectionInput) { v.ConnectionID = "connection\x00id" },
		func(v *SourceProjectionInput) { v.DatabaseIdentity = strings.Repeat("é", 129) },
		func(v *SourceProjectionInput) { v.ProjectionLineageID = string([]byte{0xff}) },
	}
	for _, mutate := range mutations {
		input := validSourceProjectionInput()
		mutate(&input)
		if _, err := NewSourceProjectionSpec(input); err == nil || CodeOf(err) != CodeInvalidRequest {
			t.Fatalf("invalid opaque source ID accepted: %+v", input)
		}
	}
}

func validSourceProjectionInput() SourceProjectionInput {
	return SourceProjectionInput{
		SourceScopeID: "scope-1", ConnectionID: "connection-1", DatabaseIdentity: "database-1",
		ProjectionLineageID: "lineage-1", ProjectionRevision: 1,
		ProjectionContractHash: "sha256:" + strings.Repeat("a", 64), ExposedSchemaRevision: 2,
		ExposedSchemaHash: "sha256:" + strings.Repeat("b", 64), SchemaName: "public$approved",
		RelationName: "facts_view", RelationKind: RelationView,
	}
}
